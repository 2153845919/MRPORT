using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace MRPORT.Services;

/// <summary>
/// Local TCP proxy. Accepts connections redirected by WFP callout,
/// looks up original destination from shared memory, forwards via SOCKS5.
/// </summary>
public class LocalProxyServer : IDisposable
{
    private readonly int _localPort;
    private readonly Socks5ClientFactory _clientFactory;
    private readonly WfpEngine _wfp;
    private readonly LogService _log;
    private TcpListener? _listener;
    private CancellationTokenSource? _cts;

    public LocalProxyServer(int localPort, Socks5ClientFactory clientFactory, WfpEngine wfp, LogService log)
    {
        _localPort = localPort;
        _clientFactory = clientFactory;
        _wfp = wfp;
        _log = log;
    }

    public void Start()
    {
        _cts = new CancellationTokenSource();
        _listener = new TcpListener(IPAddress.Loopback, _localPort);
        _listener.Start();
        _log.Info($"Local proxy listening on 127.0.0.1:{_localPort}");
        _ = AcceptLoopAsync(_cts.Token);
    }

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var client = await _listener!.AcceptTcpClientAsync(ct);
                _ = RelayConnectionAsync(client, ct);
            }
            catch (ObjectDisposedException) { break; }
            catch (OperationCanceledException) { break; }
            catch { }
        }
    }

    private async Task RelayConnectionAsync(TcpClient client, CancellationToken ct)
    {
        var ep = (IPEndPoint?)client.Client?.LocalEndPoint;
        if (ep == null) { client.Dispose(); return; }

        // Read original destination from shared memory
        ushort localPort = (ushort)ep.Port;
        if (!_wfp.ReadOriginalDestination(localPort, out var origIp, out int origPort))
        {
            _log.Warn($"No original dest found for port {localPort}, dropping");
            client.Dispose();
            return;
        }

        _log.Info($"Proxy: {ep.Address}:{ep.Port} -> {origIp}:{origPort}");

        try
        {
            using var socks = _clientFactory.Create();
            await socks.ConnectAsync(ct);
            await socks.ConnectThroughProxyAsync(origIp!.ToString(), origPort, ct);

            using var clientStream = client.GetStream();
            var relay = new TcpRelay(clientStream, socks.GetStream());
            await relay.RunAsync(ct);
        }
        catch (Exception ex)
        {
            _log.Warn($"Relay failed: {ex.Message}");
        }
        finally
        {
            client.Dispose();
        }
    }

    public void Stop()
    {
        _cts?.Cancel();
        _listener?.Stop();
    }

    public void Dispose()
    {
        Stop();
        _cts?.Dispose();
        _listener?.Dispose();
    }
}

/// <summary>
/// Bidirectional TCP relay.
/// </summary>
public class TcpRelay
{
    private readonly NetworkStream _a;
    private readonly NetworkStream _b;

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
