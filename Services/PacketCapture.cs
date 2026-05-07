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
/// WinDivert-based TCP transparent proxy (MITM).
/// Maintains per-connection TCP state: captures client packets, forwards
/// data through SOCKS5, crafts response packets back to the client.
/// </summary>
public class PacketCapture : IDisposable
{
    #region WinDivert P/Invoke

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
    [return: MarshalAs(UnmanagedType.Bool)]
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

    #endregion

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

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct IPHDR
    {
        public byte VerLen;
        public byte Tos;
        public ushort Length;
        public ushort Id;
        public ushort FragOff0;
        public byte Ttl;
        public byte Protocol;
        public ushort Checksum;
        public uint SrcAddr;
        public uint DstAddr;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct TCPHDR
    {
        public ushort SrcPort;
        public ushort DstPort;
        public uint SeqNum;
        public uint AckNum;
        public ushort FlagsAndOffset;
        public ushort Window;
        public ushort Checksum;
        public ushort UrgPtr;
    }

    private const int BufSize = 0xFFFF;
    private const int SYN = 0x02;
    private const int ACK = 0x10;
    private const int SYN_ACK = 0x12;
    private const int FIN = 0x01;
    private const int RST = 0x04;
    private const int PSH = 0x08;

    // Per-connection TCP state
    private class TcpState : IDisposable
    {
        public uint ClientIp, ServerIp;
        public ushort ClientPort, ServerPort;
        public uint ClientSeq, ServerSeq;
        public uint ClientAck, ServerAck;
        public TcpClient? SocksClient;
        public NetworkStream? SocksStream;
        public CancellationTokenSource? Cts;
        public Task? RelayTask;
        public bool Closed;

        public void Dispose()
        {
            Closed = true;
            Cts?.Cancel();
            SocksStream?.Dispose();
            SocksClient?.Dispose();
            Cts?.Dispose();
        }
    }

    // Connection key = "clientIp:clientPort:serverIp:serverPort"
    private readonly ConcurrentDictionary<string, TcpState> _connections = new();

    private readonly Socks5ClientFactory _clientFactory;
    private readonly LogService _log;
    private readonly string _targetDomain = "cschannel.anticheatexpert.com";
    private readonly int _shutdownTimeoutMs = 30000;

    private IntPtr _handle;
    private CancellationTokenSource? _cts;
    private Task? _captureTask;
    private byte[][] _targetIps = [];

    public bool IsRunning { get; private set; }

    // Inject buffer pool for recycled packet buffers
    private readonly byte[] _injectBuf = new byte[BufSize];

    public PacketCapture(Socks5ClientFactory clientFactory, LogService log)
    {
        _clientFactory = clientFactory;
        _log = log;
    }

    public void Start()
    {
        if (IsRunning) return;
        _cts = new CancellationTokenSource();

        // Open WinDivert - capture outbound TCP to targets
        // Exclude loopback EXCEPT port 80
        string filter = "outbound and tcp and (not (ip.DstAddr == 127.0.0.1) or tcp.DstPort == 80)";
        _handle = WinDivertOpen(filter, 0, 0, 0);
        if (_handle == IntPtr.Zero)
        {
            _log.Error("WinDivertOpen FAILED. Is WinDivert driver installed?");
            return;
        }
        _log.Info("WinDivert opened, starting TCP transparent proxy...");

        // Periodic DNS refresh
        _ = DnsRefreshLoopAsync(_cts.Token);
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
                IntPtr dataPtr = IntPtr.Zero;
                int dataLen = 0;
                IntPtr end = IntPtr.Zero;

                WinDivertHelperParsePacket(packet, recvLen,
                    ref ipHdr, ref ipv6Hdr,
                    ref icmpHdr, ref icmpv6Hdr,
                    ref tcpHdr, ref udpHdr,
                    ref dataPtr, ref dataLen,
                    ref end);

                if (ipHdr == IntPtr.Zero || tcpHdr == IntPtr.Zero)
                    continue;

                var ip = Marshal.PtrToStructure<IPHDR>(ipHdr);
                var tcp = Marshal.PtrToStructure<TCPHDR>(tcpHdr);

                uint srcIp = ip.SrcAddr;
                uint dstIp = ip.DstAddr;
                ushort srcPort = NetworkToHost16(tcp.SrcPort);
                ushort dstPort = NetworkToHost16(tcp.DstPort);

                var dstIpAddr = new IPAddress((long)dstIp);
                byte flags = (byte)(tcp.FlagsAndOffset & 0xFF);

                bool isTarget = IsTarget(dstIpAddr, dstPort);

                // Check if this is a connection we're already tracking
                string key = $"{srcIp}:{srcPort}:{dstIp}:{dstPort}";
                string reverseKey = $"{dstIp}:{dstPort}:{srcIp}:{srcPort}";

                if (isTarget && (flags & SYN) != 0 && (flags & ACK) == 0)
                {
                    // NEW CONNECTION: capture SYN, create tunnel
                    HandleSyn(packet, recvLen, ref addr, ip, tcp, srcIp, dstIp, srcPort, dstPort, key);
                }
                else if (_connections.TryGetValue(key, out var state) && !state.Closed)
                {
                    // EXISTING CONNECTION: forward data or handle close
                    HandleExistingPacket(packet, recvLen, ref addr, ip, tcp, flags, dataPtr, dataLen, state, key);
                }
                else
                {
                    // NOT OUR TRAFFIC: pass through
                    WinDivertSend(_handle, packet, recvLen, ref addr, ref recvLen);
                }
            }
            catch (OperationCanceledException) { break; }
            catch (ObjectDisposedException) { break; }
            catch (Exception ex)
            {
                Debug.WriteLine($"[Capture] Error: {ex.Message}");
            }
        }
    }

    private unsafe void HandleSyn(byte[] packet, int recvLen, ref WINDIVERT_ADDRESS addr,
        IPHDR ip, TCPHDR tcp, uint srcIp, uint dstIp, ushort srcPort, ushort dstPort, string key)
    {
        string dstStr = new IPAddress((long)dstIp).ToString();
        _log.Info($"New connection: {srcIp}:{srcPort} -> {dstStr}:{dstPort}");

        var state = new TcpState
        {
            ClientIp = srcIp,
            ServerIp = dstIp,
            ClientPort = srcPort,
            ServerPort = dstPort,
            ClientSeq = tcp.SeqNum,
            ServerSeq = 0,
            ClientAck = tcp.SeqNum + 1,
            ServerAck = tcp.SeqNum + 1,
            Cts = CancellationTokenSource.CreateLinkedTokenSource(_cts!.Token)
        };

        if (!_connections.TryAdd(key, state))
        {
            // Already tracking this connection, drop duplicate
            return;
        }

        // DROP the SYN (don't let it reach the real server)
        // We'll send a crafted SYN-ACK back to the client

        var dstHost = new IPAddress((long)dstIp).ToString();

        // Fire-and-forget: set up SOCKS5 tunnel and send SYN-ACK
        _ = Task.Run(async () =>
        {
            try
            {
                var socks = _clientFactory.Create();
                await socks.ConnectAsync(state.Cts.Token);
                await socks.ConnectThroughProxyAsync(dstHost, dstPort, state.Cts.Token);

                // Detach - TcpState now owns the client/stream
                state.SocksClient = socks.GetClient();
                state.SocksStream = socks.GetStream();
                // Suppress dispose in Socks5Client (TcpState handles it)
                GC.SuppressFinalize(socks);

                state.ServerSeq = (uint)(new Random().Next() & 0x7FFFFFFF);

                // Send SYN-ACK to client via WinDivert
                SendPacket(srcIp, dstIp, HostToNetwork16(srcPort), HostToNetwork16(dstPort),
                    state.ServerSeq, state.ClientAck, SYN_ACK, 65535, null);

                _log.Info($"Tunnel OK: {dstStr}:{dstPort}");

                // Start relay: SOCKS5 → client (via packet injection)
                state.RelayTask = Task.Run(() => RemoteToClientLoop(state));
            }
            catch (Exception ex)
            {
                _log.Warn($"Tunnel failed for {dstStr}:{dstPort}: {ex.Message}");
                // Send RST to client so it knows connection failed
                SendPacket(srcIp, dstIp, HostToNetwork16(srcPort), HostToNetwork16(dstPort),
                    0, 0, RST, 0, null);
                CleanupState(key, state);
            }
        });
    }

    private void HandleExistingPacket(byte[] packet, int recvLen, ref WINDIVERT_ADDRESS addr,
        IPHDR ip, TCPHDR tcp, byte flags, IntPtr dataPtr, int dataLen, TcpState state, string key)
    {
        // Don't process - let the connection flow through WinDivert or drop
        // For data packets, we DROP them (don't reinject) and forward through SOCKS5
        // For ACKs, just update our tracking

        if ((flags & RST) != 0)
        {
            // Client sent RST - clean up
            CleanupState(key, state);
            return;
        }

        if ((flags & FIN) != 0)
        {
            // Client sent FIN - relay shutdown
            try { state.SocksStream?.Write([0]); } catch { }
            return;
        }

        // For data packets: extract payload, send through SOCKS5
        if (dataPtr != IntPtr.Zero && dataLen > 0 && state.SocksStream != null)
        {
            byte[] data = new byte[dataLen];
            Marshal.Copy(dataPtr, data, 0, dataLen);

            // Update client sequence tracking
            state.ClientSeq = tcp.SeqNum + (uint)dataLen;
            state.ClientAck = tcp.AckNum;

            // Forward data through SOCKS5
            try
            {
                state.SocksStream.Write(data, 0, dataLen);
                state.SocksStream.Flush();

                // Send ACK back to client (to keep TCP flow going)
                SendPacket(state.ClientIp, state.ServerIp,
                    HostToNetwork16(state.ClientPort), HostToNetwork16(state.ServerPort),
                    state.ServerSeq, state.ClientSeq, ACK, 65535, null);
            }
            catch (Exception ex)
            {
                _log.Warn($"Write to SOCKS5 failed: {ex.Message}");
                CleanupState(key, state);
            }
        }
        else
        {
            // Just an ACK or window update - acknowledge to keep flow
            state.ClientAck = tcp.AckNum;
            state.ClientSeq = tcp.SeqNum;
        }

        // Drop the packet (don't reinject to host)
    }

    private void RemoteToClientLoop(TcpState state)
    {
        try
        {
            byte[] buffer = new byte[81920];
            var stream = state.SocksStream;
            if (stream == null) return;

            while (!state.Closed && !state.Cts!.IsCancellationRequested)
            {
                int read = stream.Read(buffer, 0, buffer.Length);
                if (read == 0) break;

                // Send data back to client as TCP data packet
                byte[] data = new byte[read];
                Buffer.BlockCopy(buffer, 0, data, 0, read);

                uint newSeq = state.ServerSeq + (uint)read;
                // Note: this is a simplified approach. Real implementation needs
                // ACK matching and retransmission handling.

                SendPacket(state.ClientIp, state.ServerIp,
                    HostToNetwork16(state.ClientPort), HostToNetwork16(state.ServerPort),
                    state.ServerSeq, state.ClientSeq, PSH | ACK, 65535, data);

                state.ServerSeq = newSeq;
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[Relay] Remote->Client error: {ex.Message}");
        }

        // Connection closed from remote side
        string key = $"{state.ClientIp}:{state.ClientPort}:{state.ServerIp}:{state.ServerPort}";
        CleanupState(key, state);
    }

    private unsafe void SendPacket(uint srcIp, uint dstIp, ushort srcPort, ushort dstPort,
        uint seqNum, uint ackNum, byte flags, ushort window, byte[]? payload)
    {
        int totalLen = Marshal.SizeOf<IPHDR>() + Marshal.SizeOf<TCPHDR>();
        if (payload != null) totalLen += payload.Length;

        if (totalLen > _injectBuf.Length) return;

        // Clear buffer
        Array.Clear(_injectBuf, 0, totalLen);

        // Build IP header
        var ipHdr = new IPHDR
        {
            VerLen = 0x45, // IPv4, 20 bytes header
            Length = HostToNetwork16((ushort)totalLen),
            Id = HostToNetwork16((ushort)(new Random().Next() & 0xFFFF)),
            Ttl = 128,
            Protocol = 6, // TCP
            SrcAddr = dstIp,  // We send AS the server (was original dst)
            DstAddr = srcIp   // To the client (was original src)
        };
        ipHdr.Checksum = 0;

        fixed (byte* ptr = _injectBuf)
        {
            Marshal.StructureToPtr(ipHdr, (IntPtr)ptr, false);

            // Build TCP header
            var tcpHdr = new TCPHDR
            {
                SrcPort = dstPort,  // Our response comes from server port
                DstPort = srcPort,  // To client port
                SeqNum = seqNum,
                AckNum = ackNum,
                FlagsAndOffset = (ushort)(flags | 0x50), // HdrLen=5 (20 bytes)
                Window = HostToNetwork16(window),
                Checksum = 0,
                UrgPtr = 0
            };

            int ipHdrLen = Marshal.SizeOf<IPHDR>();
            Marshal.StructureToPtr(tcpHdr, (IntPtr)(ptr + ipHdrLen), false);

            // Copy payload
            if (payload != null && payload.Length > 0)
            {
                Marshal.Copy(payload, 0, (IntPtr)(ptr + ipHdrLen + Marshal.SizeOf<TCPHDR>()), payload.Length);
            }
        }

        // Calculate checksums (WinDivert helper)
        var addr = new WINDIVERT_ADDRESS { Direction = 0 }; // outbound
        WinDivertHelperCalcChecksums(_injectBuf, totalLen, ref addr, 0);

        // Inject the packet
        int sentLen = 0;
        WinDivertSend(_handle, _injectBuf, totalLen, ref addr, ref sentLen);
    }

    private bool IsTarget(IPAddress dstIp, int dstPort)
    {
        if (dstIp.Equals(IPAddress.Loopback) && dstPort == 80)
            return true;

        var bytes = dstIp.GetAddressBytes();
        return _targetIps.Any(t => bytes[0] == t[0] && bytes[1] == t[1] &&
                                   bytes[2] == t[2] && bytes[3] == t[3]);
    }

    private async Task DnsRefreshLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var entry = await Dns.GetHostEntryAsync(_targetDomain, ct);
                _targetIps = entry.AddressList
                    .Where(a => a.AddressFamily == AddressFamily.InterNetwork)
                    .Select(a => a.GetAddressBytes())
                    .ToArray();
                _log.Info($"DNS: {_targetDomain} -> {string.Join(", ", entry.AddressList.Select(a => a))}");
            }
            catch { }

            try { await Task.Delay(60_000, ct); } catch { break; }
        }
    }

    private void CleanupState(string key, TcpState? state)
    {
        if (state != null)
        {
            state.Closed = true;
            state.Dispose();
            _connections.TryRemove(key, out _);
        }
    }

    private static ushort NetworkToHost16(ushort val) =>
        (ushort)IPAddress.NetworkToHostOrder((short)val);

    private static ushort HostToNetwork16(ushort val) =>
        (ushort)IPAddress.HostToNetworkOrder((short)val);

    public void Stop()
    {
        IsRunning = false;
        _cts?.Cancel();

        // Clean up all connections
        foreach (var kv in _connections)
            kv.Value.Dispose();
        _connections.Clear();

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
}
