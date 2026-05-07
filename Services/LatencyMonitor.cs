using System;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace MRPORT.Services;

/// <summary>
/// Monitors latency to the SOCKS5 proxy server (111.230.193.4:21538) directly.
/// Simple TCP connection timing.
/// </summary>
public class LatencyMonitor : IDisposable
{
    private readonly string _host;
    private readonly int _port;
    private CancellationTokenSource? _cts;
    private Task? _worker;

    public int CurrentLatency { get; private set; } = -1;
    public bool IsRunning { get; private set; }
    public event Action<int>? OnLatencyUpdated;

    public LatencyMonitor(string host, int port)
    {
        _host = host;
        _port = port;
    }

    public void Start()
    {
        if (IsRunning) return;
        IsRunning = true;
        _cts = new CancellationTokenSource();
        _worker = Task.Run(() => LoopAsync(_cts.Token));
    }

    public void Stop()
    {
        IsRunning = false;
        _cts?.Cancel();
        _worker = null;
    }

    private async Task LoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            int latency = -1;
            try
            {
                var sw = System.Diagnostics.Stopwatch.StartNew();
                using var tcp = new TcpClient { NoDelay = true };
                await tcp.ConnectAsync(_host, _port, ct).ConfigureAwait(false);
                sw.Stop();
                latency = (int)sw.ElapsedMilliseconds;
            }
            catch { latency = -1; }

            CurrentLatency = latency;
            OnLatencyUpdated?.Invoke(latency);

            try { await Task.Delay(3000, ct); } catch { break; }
        }
    }

    public void Dispose()
    {
        Stop();
        _cts?.Dispose();
    }
}
