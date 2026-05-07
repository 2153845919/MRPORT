using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace MRPORT.Services;

/// <summary>
/// WinDivert SYN redirect + local listener proxy.
///
/// On SYN to target IP:port → change dst_ip to 127.0.0.1, keep port → recalc checksums → send.
/// Game kernel completes TCP handshake with our local listener normally (no packet spoofing).
/// All subsequent packets in the flow pass through unmodified.
/// Listener accepts → SOCKS5 forward to real target.
///
/// 127.0.0.1:80 is handled by a separate pre-created listener (no redirection needed).
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
    private static extern bool WinDivertHelperCalcChecksums(byte[] pPacket, int packetLen, ref WINDIVERT_ADDRESS pAddr, ulong flags);

    [StructLayout(LayoutKind.Sequential)]
    private struct WINDIVERT_ADDRESS { public int IfIdx; public int SubIfIdx; public byte Direction; public byte R1; public byte R2; public byte R3; }

    private const int BufSize = 0xFFFF;
    private const uint TTL_INFINITE = 100_000;

    // Known ports that always get a local listener (no redirection needed)
    private static readonly int[] LoopbackPorts = [80, 443, 10012, 8080, 8443];

    private readonly Socks5ClientFactory _clientFactory;
    private readonly LogService _log;
    private readonly string _targetDomain;
    private IntPtr _handle;
    private CancellationTokenSource? _cts;
    private volatile byte[][] _targetIps = [];
    private readonly ConcurrentDictionary<int, TcpListener> _listeners = new();
    private Thread? _sniffThread;

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

            // Resolve real IPs (do NOT modify hosts file!)
            if (!ResolveTargetIps()) return false;

            // Open WinDivert: capture outbound TCP SYNs (non-loopback)
            string filter = "outbound and tcp.Syn and not tcp.Ack and not ip.DstAddr == 127.0.0.1";
            _handle = WinDivertOpen(filter, 0, (short)1, 0);
            if (_handle == IntPtr.Zero) { _log.Error("WinDivertOpen failed"); return false; }
            _log.Info("WinDivert SYN redirect started");

            // Create loopback listeners for known ports
            foreach (var port in LoopbackPorts)
                TryCreateListener(port);

            // Sniff & modify SYNs on dedicated thread
            _sniffThread = new Thread(SniffLoop) { IsBackground = true, Name = "WinDivertSniff" };
            _sniffThread.Start();

            // Periodic DNS refresh
            _ = Task.Run(DnsRefreshLoop);

            IsRunning = true;
            _log.Info($"MRPORT proxy active on {_targetIps.Length} IPs");
            return true;
        });
    }

    private bool ResolveTargetIps()
    {
        try
        {
            // Bypass hosts file using DNS resolution that doesn't check hosts
            var entry = Dns.GetHostEntry(_targetDomain);
            _targetIps = entry.AddressList
                .Where(a => a.AddressFamily == AddressFamily.InterNetwork)
                .Select(a => a.GetAddressBytes()).Distinct(BytesComparer.Instance).ToArray();
            _log.Info($"Target IPs: {string.Join(", ", _targetIps.Select(b => new IPAddress(b)))}");
            return _targetIps.Length > 0;
        }
        catch (Exception ex)
        {
            _log.Error($"DNS resolve failed: {ex.Message}");
            return false;
        }
    }

    private void TryCreateListener(int port)
    {
        if (_listeners.ContainsKey(port)) return;
        try
        {
            var l = new TcpListener(IPAddress.Loopback, port);
            l.Start();
            _listeners[port] = l;
            _ = AcceptLoopAsync(l, port, _cts!.Token, isDynamic: false);
        }
        catch (Exception ex) { _log.Warn($"Listen {port}: {ex.Message}"); }
    }

    private void SniffLoop()
    {
        byte[] buf = new byte[BufSize];
        var addr = new WINDIVERT_ADDRESS();
        int recvLen = 0;

        while (!_cts!.IsCancellationRequested)
        {
            try
            {
                if (!WinDivertRecv(_handle, buf, BufSize, ref addr, ref recvLen))
                { Thread.Sleep(10); continue; }
                if (recvLen < 40) continue;

                // Parse IP header
                int ipHdrLen = (buf[0] & 0x0F) * 4;
                if (ipHdrLen < 20) continue;

                // Destination IP (bytes 16-19)
                uint dstAddr = (uint)(buf[16] | (buf[17] << 8) | (buf[18] << 16) | (buf[19] << 24));
                var dstIp = new IPAddress(BitConverter.GetBytes(dstAddr).Reverse().ToArray());
                if (dstIp.Equals(IPAddress.Loopback)) continue;

                // Destination port (bytes 22-23 for TCP header after IP header)
                int tcpOffset = ipHdrLen;
                int dstPort = (buf[tcpOffset + 0] << 8) | buf[tcpOffset + 1];

                // Check if this is a target IP
                if (!IsTargetIp(dstIp)) continue;

                // Redirect to loopback: change dst_ip to 127.0.0.1
                buf[16] = 127; buf[17] = 0; buf[18] = 0; buf[19] = 1;

                // Recalculate checksums
                var chkAddr = addr; // copy
                WinDivertHelperCalcChecksums(buf, recvLen, ref chkAddr, 0);

                // Send modified packet
                WinDivertSend(_handle, buf, recvLen, ref addr, ref recvLen);
                _log.Info($"Redirect: {dstIp}:{dstPort} → 127.0.0.1:{dstPort}");

                // Ensure listener exists
                if (!_listeners.ContainsKey(dstPort))
                {
                    try
                    {
                        var l = new TcpListener(IPAddress.Loopback, dstPort);
                        l.Start();
                        _listeners[dstPort] = l;
                        _ = AcceptLoopAsync(l, dstPort, _cts.Token, isDynamic: true);
                        _log.Info($"Dynamic listener port {dstPort}");
                    }
                    catch { }
                }
            }
            catch (Exception ex) { _log.Warn($"Sniff: {ex.Message}"); }
        }
    }

    private async Task AcceptLoopAsync(TcpListener listener, int port, CancellationToken ct, bool isDynamic)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var client = await listener.AcceptTcpClientAsync(ct);
                _ = RelayConnectionAsync(client, port);
            }
        }
        catch { }
        finally
        {
            if (isDynamic)
            {
                try { listener.Stop(); } catch { }
                _listeners.TryRemove(port, out _);
            }
        }
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
                _log.Info($"DNS refresh: {_targetIps.Length} IPs");
            }
            catch { }
        }
    }

    public void Stop()
    {
        if (!IsRunning) return;
        IsRunning = false;
        _cts?.Cancel();
        _sniffThread = null;

        Task.Run(() =>
        {
            foreach (var (_, l) in _listeners) { try { l.Stop(); } catch { } }
            _listeners.Clear();
        });

        var h = _handle;
        _handle = IntPtr.Zero;
        if (h != IntPtr.Zero)
            Task.Run(() => WinDivertClose(h));

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
