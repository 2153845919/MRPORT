using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace MRPORT.Services;

/// <summary>
/// WinDivert-assisted transparent proxy.
///
/// 1. Add target IPs to loopback interface (routes traffic locally).
/// 2. WinDivert captures first SYN to each target IP:port → consume it, create listener.
/// 3. Game retransmits SYN → listener accepts → TCP handshake → SOCKS5 forward.
/// 4. 127.0.0.1:80 → WinDivert modifies dst_port to 21539 → listener on 21539.
/// 5. No packet modification for target IPs (they're already on loopback).
/// </summary>
public class DynamicPortListener : IDisposable
{
    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr WinDivertOpen(string filter, int layer, short priority, ulong flags);

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WinDivertRecv(IntPtr handle, byte[] pPacket, int packetLen,
        ref WINDIVERT_ADDRESS pAddr, ref int pRecvLen);

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WinDivertSend(IntPtr handle, byte[] pPacket, int packetLen,
        ref WINDIVERT_ADDRESS pAddr, ref int pSendLen);

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WinDivertClose(IntPtr handle);

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern bool WinDivertHelperCalcChecksums(byte[] pPacket, int packetLen,
        ref WINDIVERT_ADDRESS pAddr, ulong flags);

    [StructLayout(LayoutKind.Sequential)]
    private struct WINDIVERT_ADDRESS { public int IfIdx; public int SubIfIdx; public byte Direction; public byte R1; public byte R2; public byte R3; }

    private const int BufSize = 0xFFFF;
    private const int LoopbackFallbackPort = 21539;

    private readonly Socks5ClientFactory _clientFactory;
    private readonly LogService _log;
    private readonly string _targetDomain;
    private IntPtr _handle;
    private CancellationTokenSource? _cts;
    private volatile byte[][] _targetIps = [];
    private readonly ConcurrentDictionary<int, TcpListener> _listeners = new();
    private Thread? _sniffThread;
    private TcpListener? _fallbackListener;

    // Track first-SYN-consumed per port so we only create each listener once
    private readonly HashSet<int> _createdPorts = new();

    public bool IsRunning { get; private set; }

    public DynamicPortListener(Socks5ClientFactory clientFactory, LogService log, string targetDomain)
    {
        _clientFactory = clientFactory;
        _log = log;
        _targetDomain = targetDomain;
    }

    public Task<bool> StartAsync()
    {
        return Task.Run(() =>
        {
            if (IsRunning) return true;
            _cts = new CancellationTokenSource();

            // Resolve target IPs
            if (!ResolveTargetIps()) return false;

            // Copy WinDivert to TEMP
            CopyToTempIfNeeded();

            // Add target IPs to loopback interface
            foreach (var ipBytes in _targetIps)
            {
                var ip = new IPAddress(ipBytes);
                var psi = new ProcessStartInfo("netsh", $"int ip add address Loopback {ip} 255.255.255.255")
                {
                    CreateNoWindow = true, UseShellExecute = false,
                    RedirectStandardOutput = true, RedirectStandardError = true
                };
                using var p = Process.Start(psi);
                p?.WaitForExit(3000);
            }
            _log.Info($"Added {_targetIps.Length} IPs to loopback");

            // Open WinDivert (negative priority for loopback capture)
            // Filter: all TCP SYNs (no direction to catch both loopback and physical)
            _handle = WinDivertOpen("tcp.Syn and not tcp.Ack", 0, (short)-100, 0);
            if (_handle == IntPtr.Zero) { _log.Error("WinDivertOpen failed"); return false; }
            _log.Info("WinDivert started (loopback mode)");

            // Fallback listener for 127.0.0.1:80 → 21539
            try
            {
                _fallbackListener = new TcpListener(IPAddress.Loopback, LoopbackFallbackPort);
                _fallbackListener.Start();
                _ = AcceptLoopAsync(_fallbackListener, 80, _cts.Token);
            }
            catch (Exception ex) { _log.Warn($"Fallback port: {ex.Message}"); return false; }

            // Sniff thread
            _sniffThread = new Thread(SniffLoop) { IsBackground = true, Name = "WinDivert" };
            _sniffThread.Start();

            // DNS refresh
            _ = Task.Run(DnsRefreshLoop);

            IsRunning = true;
            _log.Info("MRPORT active");
            return true;
        });
    }

    private bool ResolveTargetIps()
    {
        try
        {
            var entry = Dns.GetHostEntry(_targetDomain);
            _targetIps = entry.AddressList
                .Where(a => a.AddressFamily == AddressFamily.InterNetwork)
                .Select(a => a.GetAddressBytes()).Distinct(BytesComparer.Instance).ToArray();
            _log.Info($"Targets: {string.Join(", ", _targetIps.Select(b => new IPAddress(b)))}");
            return _targetIps.Length > 0;
        }
        catch (Exception ex) { _log.Error($"DNS: {ex.Message}"); return false; }
    }

    private static void CopyToTempIfNeeded()
    {
        string local = AppDomain.CurrentDomain.BaseDirectory;
        string temp = Path.Combine(Path.GetTempPath(), "MRPORT");
        Directory.CreateDirectory(temp);
        foreach (var f in new[] { "WinDivert64.sys", "WinDivert.dll" })
        {
            string src = Path.Combine(local, f);
            string dst = Path.Combine(temp, f);
            if (File.Exists(src) && (!File.Exists(dst) || File.GetLastWriteTimeUtc(src) > File.GetLastWriteTimeUtc(dst)))
                File.Copy(src, dst, true);
        }
        Environment.CurrentDirectory = temp;
    }

    private void SniffLoop()
    {
        byte[] buf = new byte[BufSize];
        var addr = new WINDIVERT_ADDRESS();
        int recvLen = 0;

        while (!_cts!.IsCancellationRequested && _handle != IntPtr.Zero)
        {
            try
            {
                if (!WinDivertRecv(_handle, buf, BufSize, ref addr, ref recvLen))
                { Thread.Sleep(10); continue; }
                if (recvLen < 40 || (buf[0] & 0xF0) != 0x40) continue;

                int ipHdrLen = (buf[0] & 0x0F) * 4;
                int tcpOff = ipHdrLen;
                if (tcpOff + 14 > recvLen) continue;

                // TCP flags
                byte flags = buf[tcpOff + 13];
                if ((flags & 0x02) == 0 || (flags & 0x10) != 0) continue;

                // Read IPv4 destination address (network byte order in packet)
                var dstIp = new IPAddress(new[] { buf[16], buf[17], buf[18], buf[19] });
                int dstPort = (buf[tcpOff] << 8) | buf[tcpOff + 1];

                // --- 127.0.0.1:80 → redirect to fallback port ---
                if (dstIp.Equals(IPAddress.Loopback) && dstPort == 80)
                {
                    buf[tcpOff] = (byte)(LoopbackFallbackPort >> 8);
                    buf[tcpOff + 1] = (byte)(LoopbackFallbackPort & 0xFF);
                    WinDivertHelperCalcChecksums(buf, recvLen, ref addr, 0);
                    WinDivertSend(_handle, buf, recvLen, ref addr, ref recvLen);
                    continue;
                }

                // Pass through if not a target IP
                if (!IsTargetIp(dstIp))
                {
                    WinDivertSend(_handle, buf, recvLen, ref addr, ref recvLen);
                    continue;
                }

                // --- Target IP: consume first SYN, create listener ---
                lock (_createdPorts)
                {
                    if (!_createdPorts.Contains(dstPort))
                    {
                        _createdPorts.Add(dstPort);
                        // DON'T send: consume this SYN so game waits/retransmits
                        // Create listener on the target IP (now on loopback)
                        CreateTargetListener(dstIp, dstPort);
                        _log.Info($"First SYN consumed, creating listener for {dstIp}:{dstPort}");
                        continue;
                    }
                }

                // Subsequent SYN: pass through, listener should be ready
                WinDivertSend(_handle, buf, recvLen, ref addr, ref recvLen);
            }
            catch (Exception ex) { _log.Warn($"Sniff: {ex.Message}"); }
        }
    }

    private void CreateTargetListener(IPAddress ip, int port)
    {
        try
        {
            var l = new TcpListener(ip, port);
            l.Start();
            _listeners[port] = l;
            _ = AcceptLoopAsync(l, port, _cts!.Token);
            _log.Info($"Listener {ip}:{port}");
        }
        catch (Exception ex) { _log.Warn($"Create listener {ip}:{port}: {ex.Message}"); }
    }

    private async Task AcceptLoopAsync(TcpListener listener, int realPort, CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var client = await listener.AcceptTcpClientAsync(ct);
                _ = RelayConnectionAsync(client, realPort);
            }
        }
        catch { }
        finally { try { listener.Stop(); } catch { } }
    }

    private async Task RelayConnectionAsync(TcpClient client, int port)
    {
        try
        {
            using var socks = _clientFactory.Create();
            await socks.ConnectAsync();
            await socks.ConnectThroughProxyAsync(_targetDomain, port);

            using var clientStream = client.GetStream();
            var relay = new TcpRelay(clientStream, socks.GetStream());
            await relay.RunAsync(CancellationToken.None);
            _log.Info($"Relay done port {port}");
        }
        catch (Exception ex) { _log.Warn($"Relay port {port}: {ex.Message}"); }
        finally { client.Dispose(); }
    }

    private bool IsTargetIp(IPAddress ip)
    {
        var b = ip.GetAddressBytes();
        return _targetIps.Any(t => b.AsSpan().SequenceEqual(t));
    }

    private void DnsRefreshLoop()
    {
        while (!_cts!.IsCancellationRequested)
        {
            try { Task.Delay(60_000, _cts.Token).Wait(_cts.Token); } catch { break; }
            try
            {
                var entry = Dns.GetHostEntry(_targetDomain);
                _targetIps = entry.AddressList
                    .Where(a => a.AddressFamily == AddressFamily.InterNetwork)
                    .Select(a => a.GetAddressBytes()).Distinct(BytesComparer.Instance).ToArray();
            }
            catch { }
        }
    }

    public void Stop()
    {
        if (!IsRunning) return;
        IsRunning = false;
        _cts?.Cancel();

        // Close WinDivert handle first (unblocks sniff thread)
        var h = _handle;
        _handle = IntPtr.Zero;
        if (h != IntPtr.Zero) WinDivertClose(h);
        _sniffThread?.Join(2000);
        _sniffThread = null;

        // Close listeners
        try { _fallbackListener?.Stop(); } catch { }
        foreach (var (_, l) in _listeners) { try { l.Stop(); } catch { } }
        _listeners.Clear();
        _createdPorts.Clear();

        // Remove target IPs from loopback
        foreach (var ipBytes in _targetIps)
        {
            var ip = new IPAddress(ipBytes);
            var psi = new ProcessStartInfo("netsh", $"int ip delete address Loopback {ip}")
            { CreateNoWindow = true, UseShellExecute = false };
            using var p = Process.Start(psi);
            p?.WaitForExit(1000);
        }
        _log.Info("MRPORT stopped");
    }

    public void Dispose() { Stop(); _cts?.Dispose(); }

    private class BytesComparer : IEqualityComparer<byte[]>
    {
        public static readonly BytesComparer Instance = new();
        public bool Equals(byte[]? a, byte[]? b) => a != null && b != null && a.AsSpan().SequenceEqual(b);
        public int GetHashCode(byte[] a) { int h = 0; for (int i = 0; i < a.Length && i < 4; i++) h = (h << 8) | a[i]; return h; }
    }
}

public class TcpRelay
{
    private readonly NetworkStream _a, _b;
    public TcpRelay(NetworkStream a, NetworkStream b) { _a = a; _b = b; }

    public async Task RunAsync(CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var t1 = CopyAsync(_a, _b, cts.Token);
        var t2 = CopyAsync(_b, _a, cts.Token);
        await Task.WhenAny(t1, t2);
        cts.Cancel();
        try { await Task.WhenAll(t1, t2); } catch { }
    }

    private static async Task CopyAsync(NetworkStream src, NetworkStream dst, CancellationToken ct)
    {
        byte[] buf = new byte[81920];
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var r = await src.ReadAsync(buf, ct);
                if (r == 0) break;
                await dst.WriteAsync(buf.AsMemory(0, r), ct);
            }
        }
        catch { }
    }
}
