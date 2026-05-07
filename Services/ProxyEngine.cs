using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace MRPORT.Services;

/// <summary>
/// Main engine: WFP redirect + local proxy + SOCKS5 forward.
/// </summary>
public class ProxyEngine : INotifyPropertyChanged, IDisposable
{
    private readonly ConfigManager _config;
    private readonly LogService _log;
    private readonly Socks5ClientFactory _clientFactory;
    private readonly WfpEngine _wfp;
    private LocalProxyServer? _proxy;
    private LatencyMonitor? _latency;
    private ProcessGuard? _guard;

    public const int LocalProxyPort = 21539;

    private bool _isRunning;
    private int _currentLatency = -1;
    private DateTime _runStart;
    private string _runTimeStr = "00:00:00";
    private string _lastRunTime = "";

    public bool IsRunning
    {
        get => _isRunning;
        set { _isRunning = value; OnPropertyChanged(nameof(IsRunning)); }
    }

    public int CurrentLatency
    {
        get => _currentLatency;
        set { _currentLatency = value; OnPropertyChanged(nameof(CurrentLatency)); }
    }

    public string RunTimeStr
    {
        get => _runTimeStr;
        set { _runTimeStr = value; OnPropertyChanged(nameof(RunTimeStr)); }
    }

    public string LastRunTime
    {
        get => _lastRunTime;
        set { _lastRunTime = value; OnPropertyChanged(nameof(LastRunTime)); }
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public ProxyEngine(ConfigManager config, LogService log)
    {
        _config = config;
        _log = log;
        _wfp = new WfpEngine(log);

        var cfg = config.Load();
        _clientFactory = new Socks5ClientFactory(
            cfg.ServerAddress, cfg.ServerPort, cfg.Username, cfg.Password);

        if (!string.IsNullOrEmpty(cfg.LastRunTime))
            LastRunTime = cfg.LastRunTime;
    }

    public async Task<bool> StartAsync()
    {
        if (IsRunning) return true;

        _log.Info("Starting proxy engine...");

        var cfg = _config.Load();
        if (string.IsNullOrEmpty(cfg.Username) || string.IsNullOrEmpty(cfg.Password))
        {
            _log.Error("请先输入账号和密码");
            return false;
        }

        // Test SOCKS5 connection
        try
        {
            _log.Info("Testing SOCKS5 connection...");
            using var testClient = _clientFactory.Create();
            await testClient.ConnectAsync();
            _log.Info("SOCKS5 connection OK");
        }
        catch (Exception ex)
        {
            _log.Error($"SOCKS5 connection failed: {ex.Message}");
            return false;
        }

        // Initialize WFP callout engine
        if (!_wfp.InitializeEngine())
        {
            _log.Error("WFP callout engine init failed (callout.dll missing?)");
            return false;
        }

        // Set target IPs (DNS + loopback 127.0.0.1)
        try
        {
            var entry = await Dns.GetHostEntryAsync("cschannel.anticheatexpert.com");
            var ips = entry.AddressList.Where(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork).ToList();
            ips.Add(IPAddress.Loopback); // For 127.0.0.1:80
            _wfp.SetTargetIps(ips.ToArray());
            _log.Info($"WFP targets set: {string.Join(", ", ips.Select(a => a))}");
        }
        catch (Exception ex)
        {
            _log.Error($"DNS resolve failed: {ex.Message}");
            return false;
        }

        // Start local proxy
        _proxy = new LocalProxyServer(LocalProxyPort, _clientFactory, _wfp, _log);
        _proxy.Start();
        _log.Info($"Local proxy started on 127.0.0.1:{LocalProxyPort}");

        // Start latency monitor
        _latency = new LatencyMonitor(cfg.ServerAddress, cfg.ServerPort);
        _latency.OnLatencyUpdated += OnLatencyUpdated;
        _latency.Start();

        // Run time tracking
        _runStart = DateTime.Now;
        _ = RunTimeTrackerAsync();

        // Process guard
        _guard = new ProcessGuard("MRPORT");
        _guard.StartGuard();
        _log.Info("Process guard started");

        IsRunning = true;
        _log.Info("MRPORT started successfully");
        return true;
    }

    public void Stop()
    {
        if (!IsRunning) return;

        _log.Info("Stopping proxy engine...");
        _proxy?.Stop();
        _latency?.Stop();
        _guard?.Dispose();

        var cfg = _config.Load();
        cfg.LastRunTime = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
        LastRunTime = cfg.LastRunTime;
        _config.Save(cfg);

        IsRunning = false;
        _log.Info("MRPORT stopped");
    }

    public void UpdateCredentials(string username, string password)
    {
        var cfg = _config.Load();
        cfg.Username = username;
        cfg.Password = password;
        _config.Save(cfg);
        _log.Info("Credentials saved");
    }

    private void OnLatencyUpdated(int latencyMs)
    {
        CurrentLatency = latencyMs;
        if (latencyMs < 0)
        {
            _failedChecks++;
            if (_failedChecks >= 3)
            {
                _log.Warn("Proxy lost, killing nrc_launcher.exe");
                ProcessGuard.KillNrcLauncher();
            }
        }
        else
        {
            _failedChecks = 0;
        }
    }

    private int _failedChecks;

    private async Task RunTimeTrackerAsync()
    {
        while (IsRunning)
        {
            var elapsed = DateTime.Now - _runStart;
            RunTimeStr = $"{(int)elapsed.TotalHours:D2}:{elapsed.Minutes:D2}:{elapsed.Seconds:D2}";
            try { await Task.Delay(1000); } catch { break; }
        }
    }

    public void VerifyWebsite()
    {
        try
        {
            Process.Start(new ProcessStartInfo("http://127.0.0.1:80") { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            _log.Error($"Failed to open browser: {ex.Message}");
        }
    }

    protected void OnPropertyChanged(string name) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    public void Dispose()
    {
        Stop();
        _proxy?.Dispose();
        _latency?.Dispose();
        _guard?.Dispose();
        _wfp.Dispose();
    }
}
