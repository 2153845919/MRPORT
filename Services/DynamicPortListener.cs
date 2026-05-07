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
/// Outbound TCP SYNs:
///   → target IP: modify dst_ip to 127.0.0.1, same port
///   → 127.0.0.1:80: modify dst_port to loopbackFallbackPort (avoid port conflict)
///   → anything else: pass through unmodified
///
/// Game kernel completes TCP handshake with our listener normally.
/// Accepted connections → SOCKS5 forward to cschannel.anticheatexpert.com:samePort.
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

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WinDivertHelperParsePacket(byte[] pPacket, int packetLen,
        ref IntPtr ppIpHdr, ref IntPtr ppIpv6Hdr,
        ref IntPtr ppIcmpHdr, ref IntPtr ppIcmpv6Hdr,
        ref IntPtr ppTcpHdr, ref IntPtr ppUdpHdr,
        ref IntPtr ppData, ref int pDataLen,
        ref IntPtr ppEnd);

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
    private TcpListener? _loopbackFallbackListener;

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

            // Resolve real IPs (no hosts file modification!)
            if (!ResolveTargetIps()) return false;

            // Open WinDivert: capture ALL outbound TCP SYNs (including loopback)
            string filter = "outbound and tcp.Syn and not tcp.Ack";
            // Negative priority to capture loopback traffic too
            _handle = WinDivertOpen(filter, 0, (short)-100, 0);
            if (_handle == IntPtr.Zero) { _log.Error("WinDivertOpen failed"); return false; }
            _log.Info("WinDivert SYN redirect started");

            // Fallback listener for 127.0.0.1:80 → 127.0.0.1:21539 redirection
            try
            {
                _loopbackFallbackListener = new TcpListener(IPAddress.Loopback, LoopbackFallbackPort);
                _loopbackFallbackListener.Start();
                _ = AcceptLoopAsync(_loopbackFallbackListener, 80, _cts.Token, isDynamic: false);
                _log.Info($"Fallback listener 127.0.0.1:{LoopbackFallbackPort} (for :80)");
            }
            catch (Exception ex) { _log.Warn($"Fallback port {LoopbackFallbackPort}: {ex.Message}"); return false; }

            // Sniff thread
            _sniffThread = new Thread(SniffLoop) { IsBackground = true, Name = "WinDivertSniff" };
            _sniffThread.Start();

            // DNS refresh
            _ = Task.Run(DnsRefreshLoop);

            IsRunning = true;
            _log.Info($"MRPORT active, redirecting {_targetIps.Length} target IPs to SOCKS5");
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
            _log.Info($"Target IPs: {string.Join(", ", _targetIps.Select(b => new IPAddress(b)))}");
            return _targetIps.Length > 0;
        }
        catch (Exception ex) { _log.Error($"DNS: {ex.Message}"); return false; }
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
                if ((buf[0] & 0xF0) != 0x40) continue; // IPv4 only

                int ipHdrLen = (buf[0] & 0x0F) * 4;
                int tcpOff = ipHdrLen;
                if (tcpOff + 14 > recvLen) continue;

                // Parse TCP flags
                byte flags = buf[tcpOff + 13];
                if ((flags & 0x02) == 0 || (flags & 0x10) != 0) continue; // SYN only, not SYN-ACK

                uint dstAddr = (uint)(buf[16] | (buf[17] << 8) | (buf[18] << 16) | (buf[19] << 24));
                int dstPort = (buf[tcpOff] << 8) | buf[tcpOff + 1];
                var dstIp = new IPAddress(BitConverter.GetBytes(dstAddr).Reverse().ToArray());

                if (dstIp.Equals(IPAddress.Loopback))
                {
                    // Loopback traffic: only handle port 80
                    if (dstPort == 80)
                    {
                        // Redirect 127.0.0.1:80 → 127.0.0.1:21539
                        buf[tcpOff] = (byte)(LoopbackFallbackPort >> 8);
                        buf[tcpOff + 1] = (byte)(LoopbackFallbackPort & 0xFF);

                        WinDivertHelperCalcChecksums(buf, recvLen, ref addr, 0);
                        WinDivertSend(_handle, buf, recvLen, ref addr, ref recvLen);
                        _log.Info($"Redirect :80 → :{LoopbackFallbackPort}");
                    }
                    // Other loopback: pass through (WinDivertSend without modifications)
                    else
                    {
                        WinDivertSend(_handle, buf, recvLen, ref addr, ref recvLen);
                    }
                    continue;
                }

                // Non-loopback: check if target IP
                if (!IsTargetIp(dstIp))
                {
                    WinDivertSend(_handle, buf, recvLen, ref addr, ref recvLen);
                    continue;
                }

                // Redirect to loopback
                buf[16] = 127; buf[17] = 0; buf[18] = 0; buf[19] = 1;
                WinDivertHelperCalcChecksums(buf, recvLen, ref addr, 0);
                WinDivertSend(_handle, buf, recvLen, ref addr, ref recvLen);
                _log.Info($"Redirect {dstIp}:{dstPort} → 127.0.0.1:{dstPort}");

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

    private async Task AcceptLoopAsync(TcpListener listener, int realPort, CancellationToken ct, bool isDynamic)
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
        finally
        {
            if (isDynamic)
            {
                try { listener.Stop(); } catch { }
                if (_listeners.TryRemove(realPort, out _)) { }
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
            }
            catch { }
        }
    }

    public void Stop()
    {
        if (!IsRunning) return;
        IsRunning = false;
        _cts?.Cancel();

        // Shutdown everything on bg thread (WinDivertClose may block)
        var h = _handle;
        _handle = IntPtr.Zero;
        var t = _sniffThread;
        _sniffThread = null;

        Task.Run(() =>
        {
            if (h != IntPtr.Zero) WinDivertClose(h); // unblocks sniff thread
            t?.Join(1000);
            try { _loopbackFallbackListener?.Stop(); } catch { }
            foreach (var (_, l) in _listeners) { try { l.Stop(); } catch { } }
            _listeners.Clear();
        });

        _log.Info("MRPORT stopping...");
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
