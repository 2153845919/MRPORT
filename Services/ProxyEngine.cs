using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace MRPORT.Services;

public class ProxyEngine : INotifyPropertyChanged, IDisposable
{
    private readonly ConfigManager _config;
    private readonly LogService _log;
    private readonly Socks5ClientFactory _clientFactory;
    private const string TargetDomain = "cschannel.anticheatexpert.com";
    private DynamicPortListener? _dynListener;
    private LatencyMonitor? _latency;
    private ProcessGuard? _guard;

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
        var cfg = config.Load();
        _clientFactory = new Socks5ClientFactory(cfg.ServerAddress, cfg.ServerPort, cfg.Username, cfg.Password);
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

        // Test SOCKS5
        try
        {
            using var test = _clientFactory.Create();
            await test.ConnectAsync();
            _log.Info("SOCKS5 OK");
        }
        catch (Exception ex)
        {
            _log.Error($"SOCKS5: {ex.Message}");
            return false;
        }

        // Dynamic port listener (hosts file + WinDivert sniff + known port listeners)
        _dynListener = new DynamicPortListener(_clientFactory, _log, TargetDomain);
        _dynListener.Start();

        // Latency
        _latency = new LatencyMonitor(cfg.ServerAddress, cfg.ServerPort);
        _latency.OnLatencyUpdated += OnLatencyUpdated;
        _latency.Start();

        // Runtime tracker
        _runStart = DateTime.Now;
        _ = RunTimeTrackerAsync();

        // Process guard
        _guard = new ProcessGuard("MRPORT");
        _guard.StartGuard();

        IsRunning = true;
        _log.Info("MRPORT started");
        return true;
    }

    public void Stop()
    {
        if (!IsRunning) return;
        _log.Info("Stopping...");
        _dynListener?.Stop();
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

    private int _failedChecks;
    private void OnLatencyUpdated(int ms)
    {
        CurrentLatency = ms;
        if (ms < 0)
        {
            _failedChecks++;
            if (_failedChecks >= 3)
            {
                _log.Warn("Proxy lost, killing nrc_launcher.exe");
                ProcessGuard.KillNrcLauncher();
            }
        }
        else _failedChecks = 0;
    }

    private async Task RunTimeTrackerAsync()
    {
        while (IsRunning)
        {
            var e = DateTime.Now - _runStart;
            RunTimeStr = $"{(int)e.TotalHours:D2}:{e.Minutes:D2}:{e.Seconds:D2}";
            try { await Task.Delay(1000); } catch { break; }
        }
    }

    public void VerifyWebsite()
    {
        try { Process.Start(new ProcessStartInfo("http://127.0.0.1:80") { UseShellExecute = true }); }
        catch (Exception ex) { _log.Error($"Browser: {ex.Message}"); }
    }

    private void OnPropertyChanged(string n) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(n));

    public void Dispose()
    {
        Stop();
        _dynListener?.Dispose();
        _latency?.Dispose();
        _guard?.Dispose();
    }
}
