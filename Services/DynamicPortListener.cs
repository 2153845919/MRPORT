using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace MRPORT.Services;

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
    private static readonly int[] KnownPorts = [80, 443, 10012, 8080, 8443];

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

            try { ModifyHosts(add: true); }
            catch (Exception ex) { _log.Error($"Hosts: {ex.Message}"); return false; }

            string filter = "outbound and tcp.Syn and not tcp.Ack and not ip.DstAddr == 127.0.0.1";
            _handle = WinDivertOpen(filter, 0, 0, 0);
            if (_handle == IntPtr.Zero) { _log.Error("WinDivertOpen failed"); return false; }
            _log.Info("WinDivert opened");

            foreach (var port in KnownPorts)
                TryCreateListener(port);

            // Sniff on a dedicated STA thread so WinDivertRecv has stable context
            _sniffThread = new Thread(SniffLoop) { IsBackground = true, Name = "WinDivertSniff" };
            _sniffThread.Start();

            _ = Task.Run(DnsRefreshLoop);

            IsRunning = true;
            _log.Info("DynamicPortListener started");
            return true;
        });
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

                // Extract dest port from raw packet
                if (recvLen < 40) continue;
                int dstPort = (buf[22] << 8) | buf[23];
                uint dstAddr = (uint)(buf[16] | (buf[17] << 8) | (buf[18] << 16) | (buf[19] << 24));

                byte flags = buf[33];
                bool isSyn = (flags & 0x02) != 0;
                bool isAck = (flags & 0x10) != 0;
                if (!isSyn || isAck) continue;

                var dstIp = new IPAddress(BitConverter.GetBytes(dstAddr).Reverse().ToArray());
                if (dstIp.Equals(IPAddress.Loopback)) continue;
                if (!IsTargetIp(dstIp)) continue;

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
            try
            {
                var entry = Dns.GetHostEntry(_targetDomain);
                _targetIps = entry.AddressList
                    .Where(a => a.AddressFamily == AddressFamily.InterNetwork)
                    .Select(a => a.GetAddressBytes()).ToArray();
                _log.Info($"DNS: {_targetDomain} -> {string.Join(", ", entry.AddressList.Select(a => a))}");
            }
            catch { }
            try { Task.Delay(60_000, _cts.Token).Wait(_cts.Token); } catch { break; }
        }
    }

    private static void ModifyHosts(bool add)
    {
        string hostsPath = @"C:\Windows\System32\drivers\etc\hosts";
        string entry = "127.0.0.1 cschannel.anticheatexpert.com";
        var lines = File.ReadAllLines(hostsPath).ToList();
        bool exists = lines.Any(l => l.Contains("cschannel.anticheatexpert.com"));
        if (add && !exists) { lines.Add(entry); File.WriteAllLines(hostsPath, lines); }
        else if (!add && exists) { lines.RemoveAll(l => l.Contains("cschannel.anticheatexpert.com")); File.WriteAllLines(hostsPath, lines); }
    }

    public void Stop()
    {
        if (!IsRunning) return;
        IsRunning = false;

        // Cancel all loops
        _cts?.Cancel();
        _sniffThread = null;

        // Close all listeners (on bg thread to avoid blocking UI)
        Task.Run(() =>
        {
            foreach (var (_, l) in _listeners) { try { l.Stop(); } catch { } }
            _listeners.Clear();
        });

        // Close WinDivert handle on bg thread (may block)
        var h = _handle;
        _handle = IntPtr.Zero;
        if (h != IntPtr.Zero)
            Task.Run(() => WinDivertClose(h));

        try { ModifyHosts(add: false); } catch { }
        _log.Info("DynamicPortListener stopped");
    }

    public void Dispose() { Stop(); _cts?.Dispose(); }
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
