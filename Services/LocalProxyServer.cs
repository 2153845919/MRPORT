using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace MRPORT.Services;

/// <summary>
/// Local transparent TCP proxy. Accepts connections redirected by the WinDivert
/// capture layer and forwards them through SOCKS5 to the original destination.
/// </summary>
public class LocalProxyServer : IDisposable
{
    private readonly int _localPort;
    private readonly Socks5ClientFactory _clientFactory;
    private TcpListener? _listener;
    private CancellationTokenSource? _cts;
    private Task? _acceptLoop;

    public LocalProxyServer(int localPort, Socks5ClientFactory clientFactory)
    {
        _localPort = localPort;
        _clientFactory = clientFactory;
    }

    public void Start()
    {
        _cts = new CancellationTokenSource();
        _listener = new TcpListener(IPAddress.Loopback, _localPort);
        _listener.Start();
        _acceptLoop = Task.Run(() => AcceptLoopAsync(_cts.Token));
    }

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var client = await _listener!.AcceptTcpClientAsync(ct);
                _ = RelayConnectionAsync(client, ct); // fire-and-forget
            }
            catch (ObjectDisposedException) { break; }
            catch (OperationCanceledException) { break; }
            catch { }
        }
    }

    private async Task RelayConnectionAsync(TcpClient client, CancellationToken ct)
    {
        var remoteEp = (IPEndPoint?)client.Client.RemoteEndPoint;
        if (remoteEp == null) { client.Dispose(); return; }

        var key = remoteEp;
        var origDst = PacketCapture.GetOriginalDestination(key);
        if (origDst == null) { client.Dispose(); return; }

        try
        {
            using var socks = _clientFactory.Create();
            await socks.ConnectAsync(ct);
            await socks.ConnectThroughProxyAsync(origDst.Host, origDst.Port, ct);

            using var clientStream = client.GetStream();
            var relay = new TcpRelay(clientStream, socks.GetStream());
            await relay.RunAsync(ct);
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[Proxy] Relay failed: {ex.Message}");
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
/// Factory for creating new SOCKS5 client connections.
/// </summary>
public class Socks5ClientFactory
{
    private readonly string _host;
    private readonly int _port;
    private readonly string _user;
    private readonly string _pass;

    public Socks5ClientFactory(string host, int port, string user, string pass)
    {
        _host = host; _port = port; _user = user; _pass = pass;
    }

    public Socks5Client Create() => new(_host, _port, _user, _pass);
}

/// <summary>
/// Bidirectional TCP relay: copies data in both directions simultaneously.
/// </summary>
public class TcpRelay
{
    private readonly NetworkStream _local;
    private readonly NetworkStream _remote;

    public TcpRelay(NetworkStream local, NetworkStream remote)
    {
        _local = local; _remote = remote;
    }

    public async Task RunAsync(CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var t1 = RelayAsync(_local, _remote, cts.Token);
        var t2 = RelayAsync(_remote, _local, cts.Token);
        await Task.WhenAny(t1, t2);
        cts.Cancel();
        await Task.WhenAll(t1, t2).ConfigureAwait(false);
    }

    private static async Task RelayAsync(NetworkStream src, NetworkStream dst, CancellationToken ct)
    {
        byte[] buffer = new byte[81920];
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var read = await src.ReadAsync(buffer, ct);
                if (read == 0) break;
                await dst.WriteAsync(buffer.AsMemory(0, read), ct);
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception)
        {
            // Connection broke
        }
    }
}
