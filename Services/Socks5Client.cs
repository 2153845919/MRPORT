using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace MRPORT.Services;

/// <summary>
/// SOCKS5 client with username/password auth (RFC 1929).
/// </summary>
public class Socks5Client : IDisposable
{
    private readonly string _proxyHost;
    private readonly int _proxyPort;
    private readonly string _username;
    private readonly string _password;
    private TcpClient? _client;
    private NetworkStream? _stream;

    public bool IsConnected { get; private set; }

    public Socks5Client(string proxyHost, int proxyPort, string username, string password)
    {
        _proxyHost = proxyHost;
        _proxyPort = proxyPort;
        _username = username;
        _password = password;
    }

    public async Task<bool> ConnectAsync(CancellationToken ct = default)
    {
        try
        {
            _client?.Dispose();
            _client = new TcpClient { NoDelay = true };
            await _client.ConnectAsync(_proxyHost, _proxyPort, ct).ConfigureAwait(false);
            _stream = _client.GetStream();

            // Handshake: method negotiation
            byte[] greeting = [5, 2, 0, 2]; // SOCKS5, 2 methods: no-auth, user/pass
            await _stream.WriteAsync(greeting, ct).ConfigureAwait(false);

            byte[] response = new byte[2];
            await _stream.ReadExactlyAsync(response, 0, 2, ct).ConfigureAwait(false);

            if (response[0] != 5) throw new Exception("SOCKS5 version mismatch");
            if (response[1] == 2)
            {
                // User/Pass auth
                var uBytes = System.Text.Encoding.UTF8.GetBytes(_username);
                var pBytes = System.Text.Encoding.UTF8.GetBytes(_password);
                using var ms = new System.IO.MemoryStream();
                ms.WriteByte(1); // version
                ms.WriteByte((byte)uBytes.Length);
                ms.Write(uBytes);
                ms.WriteByte((byte)pBytes.Length);
                ms.Write(pBytes);

                var authBytes = ms.ToArray();
                await _stream.WriteAsync(authBytes, ct).ConfigureAwait(false);

                byte[] authResp = new byte[2];
                await _stream.ReadExactlyAsync(authResp, 0, 2, ct).ConfigureAwait(false);
                if (authResp[1] != 0) throw new Exception("SOCKS5 auth failed");
            }

            IsConnected = true;
            return true;
        }
        catch
        {
            IsConnected = false;
            throw;
        }
    }

    public TcpClient GetClient() => _client ?? throw new InvalidOperationException("Not connected");
    public NetworkStream GetStream() => _stream ?? throw new InvalidOperationException("Not connected");

    /// <summary>
    /// Send UDP ASSOCIATE request and return the relay endpoint.
    /// </summary>
    public async Task<IPEndPoint?> UdpAssociateAsync(CancellationToken ct = default)
    {
        if (_stream == null) throw new InvalidOperationException("Not connected");

        // UDP ASSOCIATE command
        byte[] request = BuildRequest(3, "0.0.0.0", 0); // 3=UDP ASSOCIATE
        await _stream.WriteAsync(request, ct).ConfigureAwait(false);

        byte[] resp = new byte[10];
        await _stream.ReadExactlyAsync(resp, 0, 10, ct).ConfigureAwait(false);

        if (resp[1] != 0) throw new Exception($"UDP ASSOCIATE failed: {resp[1]}");

        // Parse response
        int port = (resp[8] << 8) | resp[9];
        string ip = $"{resp[4]}.{resp[5]}.{resp[6]}.{resp[7]}";
        return new IPEndPoint(IPAddress.Parse(ip), port);
    }

    /// <summary>
    /// Measure latency to target via SOCKS5 proxy.
    /// </summary>
    public async Task<int> MeasureLatencyAsync(string targetHost, int targetPort, int timeoutMs = 5000)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        using var cts = new CancellationTokenSource(timeoutMs);
        try
        {
            await ConnectAsync(cts.Token).ConfigureAwait(false);
            // Send CONNECT to target
            byte[] connectReq = BuildRequest(1, targetHost, targetPort);
            await _stream!.WriteAsync(connectReq, cts.Token).ConfigureAwait(false);

            byte[] resp = new byte[10];
            await _stream.ReadExactlyAsync(resp, 0, 10, cts.Token).ConfigureAwait(false);

            sw.Stop();
            if (resp[1] != 0) return -1;
            return (int)sw.ElapsedMilliseconds;
        }
        catch
        {
            return -1;
        }
        finally
        {
            Dispose();
        }
    }

    public async Task ConnectThroughProxyAsync(string targetHost, int targetPort, CancellationToken ct = default)
    {
        if (_stream == null) throw new InvalidOperationException("Not connected");
        byte[] req = BuildRequest(1, targetHost, targetPort);
        await _stream.WriteAsync(req, ct).ConfigureAwait(false);

        byte[] resp = new byte[10];
        await _stream.ReadExactlyAsync(resp, 0, 10, ct).ConfigureAwait(false);
        if (resp[1] != 0) throw new Exception($"SOCKS5 connect failed: {resp[1]}");
    }

    public async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct = default)
    {
        if (_stream == null) throw new InvalidOperationException("Not connected");
        return await _stream.ReadAsync(buffer, offset, count, ct).ConfigureAwait(false);
    }

    public async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct = default)
    {
        if (_stream == null) throw new InvalidOperationException("Not connected");
        await _stream.WriteAsync(buffer.AsMemory(offset, count), ct).ConfigureAwait(false);
    }

    private static byte[] BuildRequest(byte cmd, string host, int port)
    {
        using var ms = new System.IO.MemoryStream();
        ms.WriteByte(5); // version
        ms.WriteByte(cmd); // 1=CONNECT, 3=UDP ASSOCIATE
        ms.WriteByte(0); // reserved

        if (IPAddress.TryParse(host, out var addr))
        {
            if (addr.AddressFamily == AddressFamily.InterNetworkV6)
            {
                ms.WriteByte(4); // IPv6
                ms.Write(addr.GetAddressBytes());
            }
            else
            {
                ms.WriteByte(1); // IPv4
                ms.Write(addr.GetAddressBytes());
            }
        }
        else
        {
            ms.WriteByte(3); // DOMAINNAME
            var hostBytes = System.Text.Encoding.UTF8.GetBytes(host);
            ms.WriteByte((byte)hostBytes.Length);
            ms.Write(hostBytes);
        }

        ms.WriteByte((byte)(port >> 8));
        ms.WriteByte((byte)port);
        return ms.ToArray();
    }

    public void Dispose()
    {
        _stream?.Dispose();
        _client?.Dispose();
        IsConnected = false;
    }
}
