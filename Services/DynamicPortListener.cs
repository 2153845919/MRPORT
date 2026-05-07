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
/// Hybrid transparent proxy:
/// 1. netsh portproxy: 127.0.0.1:80 → 127.0.0.1:21539 (kernel-level, no driver needed)
/// 2. Target IPs added to loopback (routes via local)
/// 3. WinDivert (if available) sniffs inbound to target IPs for dynamic port detection
/// 4. TcpListener on 0.0.0.0:21539 accepts redirected :80 traffic → SOCKS5 forward
/// 5. TcpListener on target IP:port (dynamic) accepts → SOCKS5 forward
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
    private static extern bool WinDivertClose(IntPtr handle);

    [StructLayout(LayoutKind.Sequential)]
    private struct WINDIVERT_ADDRESS { public int IfIdx; public int SubIfIdx; public byte Direction; public byte R1; public byte R2; public byte R3; }

    private const int BufSize = 0xFFFF;
    private const int ForwardPort = 21539; // 127.0.0.1:80 → :21539

    private readonly Socks5ClientFactory _clientFactory;
    private readonly LogService _log;
    private readonly string _targetDomain;
    private volatile byte[][] _targetIps = [];
    private TcpListener? _forwardListener;
    private CancellationTokenSource? _cts;
    private IntPtr _windivertHandle;
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

            if (!ResolveTargetIps()) return false;
            CopyToTempIfNeeded();

            // 1. Add target IPs to loopback
            AddIpsToLoopback();

            // 2. Setup portproxy: 127.0.0.1:80 → 127.0.0.1:21539
            RunNetshPortProxy("add", 80, ForwardPort);
            _log.Info($"Portproxy: 127.0.0.1:80 → 127.0.0.1:{ForwardPort}");

            // 3. Listener on 0.0.0.0:21539 accepts redirected :80 traffic
            try
            {
                _forwardListener = new TcpListener(IPAddress.Any, ForwardPort);
                _forwardListener.Start();
                _ = AcceptLoopAsync(_forwardListener, 80, _cts.Token);
                _log.Info($"Forward listener on 0.0.0.0:{ForwardPort}");
            }
            catch (Exception ex)
            {
                _log.Warn($"Forward listener failed: {ex.Message}");
                RunNetshPortProxy("delete", 80, ForwardPort);
                return false;
            }

            // 4. Try WinDivert sniff for dynamic port detection (best-effort)
            TryStartWinDivert();

            IsRunning = true;
            _log.Info("MRPORT active");
            return true;
        });
    }

    private void TryStartWinDivert()
    {
        try
        {
            var filter = "inbound and tcp.Syn and not tcp.Ack";
            _windivertHandle = WinDivertOpen(filter, 0, -100, 0);
            if (_windivertHandle == IntPtr.Zero)
            {
                filter = "tcp.Syn and not tcp.Ack";
                _windivertHandle = WinDivertOpen(filter, 0, -100, 0);
            }
            if (_windivertHandle == IntPtr.Zero)
            {
                _log.Info("WinDivert unavailable - dynamic ports won't be proxied");
                return;
            }
            _log.Info("WinDivert sniff active for dynamic port detection");
            _sniffThread = new Thread(SniffLoop) { IsBackground = true, Name = "WinDivert" };
            _sniffThread.Start();
        }
        catch (Exception ex)
        {
            _log.Info($"WinDivert unavailable: {ex.Message}");
        }
    }

    private void SniffLoop()
    {
        byte[] buf = new byte[BufSize];
        var addr = new WINDIVERT_ADDRESS();
        int recvLen = 0;

        while (!_cts!.IsCancellationRequested && _windivertHandle != IntPtr.Zero)
        {
            try
            {
                if (!WinDivertRecv(_windivertHandle, buf, BufSize, ref addr, ref recvLen))
                { Thread.Sleep(50); continue; }
                if (recvLen < 40 || (buf[0] & 0xF0) != 0x40) continue;

                var dstIp = new IPAddress(new[] { buf[16], buf[17], buf[18], buf[19] });

                // Only care about inbound to target IPs (on loopback)
                if (!IsTargetIp(dstIp)) continue;

                int ipHdrLen = (buf[0] & 0x0F) * 4;
                int tcpOff = ipHdrLen;
                int dstPort = (buf[tcpOff] << 8) | buf[tcpOff + 1];

                _log.Info($"WinDivert sniff: {dstIp}:{dstPort}");
                // We don't consume or modify - just log for now
            }
            catch { }
        }
    }

    private void AddIpsToLoopback()
    {
        foreach (var ipBytes in _targetIps)
        {
            try
            {
                var ip = new IPAddress(ipBytes);
                var psi = new ProcessStartInfo("netsh",
                    $"int ip add address \"Loopback Pseudo-Interface 1\" {ip} 255.255.255.255")
                { CreateNoWindow = true, UseShellExecute = false };
                using var p = Process.Start(psi);
                p?.WaitForExit(2000);
            }
            catch { }
        }
        _log.Info("Added target IPs to loopback");
    }

    private void RunNetshPortProxy(string action, int fromPort, int toPort)
    {
        try
        {
            string args = action == "add"
                ? $"interface portproxy add v4tov4 listenaddress=127.0.0.1 listenport={fromPort} connectaddress=127.0.0.1 connectport={toPort}"
                : $"interface portproxy delete v4tov4 listenaddress=127.0.0.1 listenport={fromPort}";

            using var p = Process.Start(new ProcessStartInfo("netsh", args)
            { CreateNoWindow = true, UseShellExecute = false });
            p?.WaitForExit(2000);
        }
        catch { }
    }

    private async Task AcceptLoopAsync(TcpListener listener, int targetPort, CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var client = await listener.AcceptTcpClientAsync(ct);
                _ = RelayConnectionAsync(client, targetPort);
            }
        }
        catch { }
        finally { try { listener.Stop(); } catch { } }
    }

    private async Task RelayConnectionAsync(TcpClient client, int port)
    {
        try
        {
            _log.Info($"Relay port {port} via SOCKS5...");
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

    private bool ResolveTargetIps()
    {
        try
        {
            var entry = Dns.GetHostEntry(_targetDomain);
            _targetIps = entry.AddressList
                .Where(a => a.AddressFamily == AddressFamily.InterNetwork)
                .Select(a => a.GetAddressBytes()).Distinct(BytesComparer.Instance).ToArray();
            _log.Info($"Target IPs: {string.Join(", ", _targetIps.Select(b => new IPAddress(b)))}");
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

    public void Stop()
    {
        if (!IsRunning) return;
        IsRunning = false;
        _cts?.Cancel();

        // Close WinDivert
        var h = _windivertHandle;
        _windivertHandle = IntPtr.Zero;
        if (h != IntPtr.Zero) WinDivertClose(h);
        _sniffThread?.Join(1000);
        _sniffThread = null;

        // Close listener
        try { _forwardListener?.Stop(); } catch { }

        // Remove portproxy
        RunNetshPortProxy("delete", 80, ForwardPort);

        // Remove loopback IPs
        foreach (var ipBytes in _targetIps)
        {
            try
            {
                var ip = new IPAddress(ipBytes);
                using var p = Process.Start(new ProcessStartInfo("netsh",
                    $"int ip delete address \"Loopback Pseudo-Interface 1\" {ip}")
                { CreateNoWindow = true, UseShellExecute = false });
                p?.WaitForExit(1000);
            }
            catch { }
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
