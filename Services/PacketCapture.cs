using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Linq;

namespace MRPORT.Services;

/// <summary>
/// WinDivert-based packet capture for TCP SYN redirection.
/// Captures outbound TCP SYNs to target destinations, modifies them to
/// point to our local proxy, and reinjects. Only SYN packets are touched;
/// established connections flow naturally through the local proxy.
/// </summary>
public class PacketCapture : IDisposable
{
    private const string WinDivertDll = "WinDivert.dll";

    #region WinDivert P/Invoke

    [DllImport(WinDivertDll, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr WinDivertOpen(string filter, int layer, short priority, ulong flags);

    [DllImport(WinDivertDll, CallingConvention = CallingConvention.Cdecl)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WinDivertRecv(IntPtr handle, byte[] pPacket, int packetLen,
        ref WINDIVERT_ADDRESS pAddr, ref int pRecvLen);

    [DllImport(WinDivertDll, CallingConvention = CallingConvention.Cdecl)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WinDivertSend(IntPtr handle, byte[] pPacket, int packetLen,
        ref WINDIVERT_ADDRESS pAddr, ref int pSendLen);

    [DllImport(WinDivertDll, CallingConvention = CallingConvention.Cdecl)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WinDivertClose(IntPtr handle);

    [DllImport(WinDivertDll, CallingConvention = CallingConvention.Cdecl)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WinDivertHelperCalcChecksums(byte[] pPacket, int packetLen,
        ref WINDIVERT_ADDRESS pAddr, ulong flags);

    [DllImport(WinDivertDll, CallingConvention = CallingConvention.Cdecl)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WinDivertHelperParsePacket(byte[] pPacket, int packetLen,
        ref IntPtr ppIpHdr, ref IntPtr ppIpv6Hdr,
        ref IntPtr ppIcmpHdr, ref IntPtr ppIcmpv6Hdr,
        ref IntPtr ppTcpHdr, ref IntPtr ppUdpHdr,
        ref IntPtr ppData, ref int pDataLen,
        ref IntPtr ppEnd);

    #endregion

    // WinDivert address
    [StructLayout(LayoutKind.Sequential)]
    private struct WINDIVERT_ADDRESS
    {
        public int IfIdx;
        public int SubIfIdx;
        public byte Direction;
        public byte Reserved1;
        public byte Reserved2;
        public byte Reserved3;
    }

    // WinDivert IP header (network byte order)
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct WINDIVERT_IPHDR
    {
        public byte VerLen;      // 4 bits version + 4 bits hdr length
        public byte Tos;
        public ushort Length;    // total length
        public ushort Id;
        public ushort FragOff0;
        public byte Ttl;
        public byte Protocol;
        public ushort Checksum;
        public uint SrcAddr;
        public uint DstAddr;
    }

    // WinDivert TCP header (network byte order)
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct WINDIVERT_TCPHDR
    {
        public ushort SrcPort;
        public ushort DstPort;
        public uint SeqNum;
        public uint AckNum;
        // Flags are bitfields; treat as ushort and mask manually
        // ushort Reserved1:4, HdrLength:4, Fin:1, Syn:1, Rst:1, Psh:1, Ack:1, Urg:1, Reserved2:2
        public ushort FlagsAndOffset;
        public ushort Window;
        public ushort Checksum;
        public ushort UrgPtr;
    }

    private const int BufSize = 0xFFFF;
    private const int SynFlag = 0x02;     // TCP flag: SYN
    private const int AckFlag = 0x10;     // TCP flag: ACK

    // Connection mapping: (clientIP:clientPort) -> (origHost, origPort)
    private static readonly ConcurrentDictionary<string, DstInfo> _pendingDst = new();

    private readonly Socks5ClientFactory _clientFactory;
    private readonly int _localProxyPort;
    private readonly LogService _log;
    private readonly string _targetDomain = "cschannel.anticheatexpert.com";

    private IntPtr _handle;
    private CancellationTokenSource? _cts;
    private Task? _captureTask;
    private Task? _dnsTask;
    private byte[][] _targetIps = [];

    public bool IsRunning { get; private set; }
    public static PacketCapture? Instance { get; private set; }

    public PacketCapture(Socks5ClientFactory clientFactory, int localProxyPort, LogService log)
    {
        _clientFactory = clientFactory;
        _localProxyPort = localProxyPort;
        _log = log;
        Instance = this;
    }

    public static DstInfo? GetOriginalDestination(IPEndPoint clientEP)
    {
        var key = $"{clientEP.Address}:{clientEP.Port}";
        if (_pendingDst.TryRemove(key, out var dst))
            return dst;
        return null;
    }

    public void Start()
    {
        if (IsRunning) return;
        _cts = new CancellationTokenSource();
        Instance = this;

        _log.Info("Starting packet capture...");

        // Open WinDivert
        string filter = "outbound and tcp.Syn and not tcp.Ack";
        _handle = WinDivertOpen(filter, 0, 0, 0);
        if (_handle == IntPtr.Zero)
        {
            _log.Error("WinDivertOpen FAILED. Ensure WinDivert64.sys is installed.");
            return;
        }

        _log.Info("WinDivert opened successfully");

        // Periodic DNS refresh
        _ = DnsRefreshLoopAsync(_cts.Token);

        // Capture loop
        _captureTask = Task.Run(() => CaptureLoop());
        IsRunning = true;
    }

    private void CaptureLoop()
    {
        byte[] packet = new byte[BufSize];
        var addr = new WINDIVERT_ADDRESS();
        int recvLen = 0;

        while (!_cts!.IsCancellationRequested)
        {
            try
            {
                if (!WinDivertRecv(_handle, packet, BufSize, ref addr, ref recvLen))
                    continue;

                // Parse headers
                IntPtr ipHdr = IntPtr.Zero, ipv6Hdr = IntPtr.Zero;
                IntPtr icmpHdr = IntPtr.Zero, icmpv6Hdr = IntPtr.Zero;
                IntPtr tcpHdr = IntPtr.Zero, udpHdr = IntPtr.Zero;
                IntPtr data = IntPtr.Zero;
                int dataLen = 0;
                IntPtr end = IntPtr.Zero;

                WinDivertHelperParsePacket(packet, recvLen,
                    ref ipHdr, ref ipv6Hdr,
                    ref icmpHdr, ref icmpv6Hdr,
                    ref tcpHdr, ref udpHdr,
                    ref data, ref dataLen,
                    ref end);

                if (ipHdr == IntPtr.Zero || tcpHdr == IntPtr.Zero)
                {
                    WinDivertSend(_handle, packet, recvLen, ref addr, ref recvLen);
                    continue;
                }

                var ip = Marshal.PtrToStructure<WINDIVERT_IPHDR>(ipHdr);
                var tcp = Marshal.PtrToStructure<WINDIVERT_TCPHDR>(tcpHdr);

                // Check SYN flag
                bool isSyn = (tcp.FlagsAndOffset & SynFlag) != 0;
                if (!isSyn)
                {
                    WinDivertSend(_handle, packet, recvLen, ref addr, ref recvLen);
                    continue;
                }

                // Parse addresses
                uint srcIp = ip.SrcAddr;
                uint dstIp = ip.DstAddr;
                ushort srcPort = tcp.SrcPort;
                ushort dstPort = tcp.DstPort;

                // Network-to-host byte order
                srcPort = (ushort)IPAddress.NetworkToHostOrder((short)srcPort);
                dstPort = (ushort)IPAddress.NetworkToHostOrder((short)dstPort);

                var dstIpAddr = new IPAddress((long)dstIp);

                // Check if this is a target
                if (IsTarget(dstIpAddr, dstPort))
                {
                    var clientEp = new IPEndPoint(new IPAddress((long)srcIp), srcPort);
                    var dstStr = $"{dstIpAddr}:{dstPort}";

                    _pendingDst[$"{clientEp.Address}:{clientEp.Port}"] = new DstInfo(dstIpAddr.ToString(), dstPort);

                    // Modify: redirect to local proxy
                    ip.DstAddr = BitConverter.ToUInt32(new byte[] { 127, 0, 0, 1 }, 0);
                    Marshal.StructureToPtr(ip, ipHdr, false);

                    tcp.DstPort = IPAddress.HostToNetworkOrder((short)_localProxyPort);
                    Marshal.StructureToPtr(tcp, tcpHdr, false);

                    // Recalculate checksums
                    WinDivertHelperCalcChecksums(packet, recvLen, ref addr, 0);

                    WinDivertSend(_handle, packet, recvLen, ref addr, ref recvLen);
                    Debug.WriteLine($"[Capture] Redirect: {clientEp} -> {dstStr}");
                }
                else
                {
                    // Pass through
                    WinDivertSend(_handle, packet, recvLen, ref addr, ref recvLen);
                }
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                Debug.WriteLine($"[Capture] Error: {ex.Message}");
            }
        }
    }

    private bool IsTarget(IPAddress dstIp, int dstPort)
    {
        // 127.0.0.1:80
        if (dstIp.Equals(IPAddress.Loopback) && dstPort == 80)
            return true;

        // Match against resolved domain IPs
        var bytes = dstIp.GetAddressBytes();
        return _targetIps.Any(t => bytes.Length >= 4 && t.Length >= 4 &&
            bytes[0] == t[0] && bytes[1] == t[1] &&
            bytes[2] == t[2] && bytes[3] == t[3]);
    }

    private async Task DnsRefreshLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var entry = await System.Net.Dns.GetHostEntryAsync(_targetDomain, ct);
                _targetIps = entry.AddressList
                    .Where(a => a.AddressFamily == AddressFamily.InterNetwork)
                    .Select(a => a.GetAddressBytes())
                    .ToArray();
                _log.Info($"DNS: {_targetDomain} -> {string.Join(", ", entry.AddressList.Select(a => a))}");
            }
            catch (Exception ex)
            {
                _log.Warn($"DNS refresh failed: {ex.Message}");
            }

            try { await Task.Delay(60_000, ct); } catch { break; }
        }
    }

    public void Stop()
    {
        IsRunning = false;
        _cts?.Cancel();
        if (_handle != IntPtr.Zero)
        {
            WinDivertClose(_handle);
            _handle = IntPtr.Zero;
        }
    }

    public void Dispose()
    {
        Stop();
        _cts?.Dispose();
    }

    public class DstInfo
    {
        public string Host { get; }
        public int Port { get; }
        public DstInfo(string host, int port) { Host = host; Port = port; }
    }
}
