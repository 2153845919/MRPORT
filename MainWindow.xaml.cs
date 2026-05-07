using System;
using System.ComponentModel;
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;
using MRPORT.Services;

namespace MRPORT;

public partial class MainWindow : Window
{
    private readonly ConfigManager _config;
    private readonly LogService _log;
    private readonly ProxyEngine _engine;
    private readonly AnnouncementService _announcement;

    public MainWindow()
    {
        InitializeComponent();

        _config = new ConfigManager();
        _log = new LogService();
        _engine = new ProxyEngine(_config, _log);
        _announcement = new AnnouncementService();

        // Wire up log binding
        _log.PropertyChanged += OnLogChanged;
        _engine.PropertyChanged += OnEnginePropertyChanged;

        // Load config
        var cfg = _config.Load();
        UsernameBox.Text = cfg.Username;
        PasswordBox.Password = cfg.Password;
        if (!string.IsNullOrEmpty(cfg.LastRunTime))
            LastRunText.Text = cfg.LastRunTime;

        // Register process-exit cleanup for netsh portproxy
        _engine.RegisterCleanup();

        // Load announcement
        LoadAnnouncementAsync();
    }

    private async void LoadAnnouncementAsync()
    {
        var text = await _announcement.FetchAsync();
        AnnouncementBox.Text = text;
    }

    private void OnLogChanged(object? sender, PropertyChangedEventArgs e)
    {
        // Use BeginInvoke to avoid deadlock when PropertyChanged fires from any thread
        Dispatcher.BeginInvoke(() =>
        {
            LogBox.Text = _log.LogText;
            LogBox.ScrollToEnd();
        });
    }

    private void OnEnginePropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        Dispatcher.BeginInvoke(() =>
        {
            switch (e.PropertyName)
            {
                case nameof(ProxyEngine.CurrentLatency):
                    UpdateLatencyDisplay();
                    break;
                case nameof(ProxyEngine.RunTimeStr):
                    RunTimeText.Text = _engine.RunTimeStr;
                    break;
                case nameof(ProxyEngine.LastRunTime):
                    LastRunText.Text = _engine.LastRunTime;
                    break;
                case nameof(ProxyEngine.IsRunning):
                    StartBtn.IsEnabled = !_engine.IsRunning;
                    StopBtn.IsEnabled = _engine.IsRunning;
                    break;
            }
        });
    }

    private void UpdateLatencyDisplay()
    {
        var ms = _engine.CurrentLatency;
        if (ms < 0)
        {
            LatencyText.Text = "超时";
            LatencyText.Foreground = (Brush)FindResource("RedBrush");
        }
        else
        {
            LatencyText.Text = $"{ms}ms";
            if (ms <= 100)
                LatencyText.Foreground = (Brush)FindResource("GreenBrush");
            else if (ms <= 200)
                LatencyText.Foreground = (Brush)FindResource("YellowBrush");
            else
                LatencyText.Foreground = (Brush)FindResource("RedBrush");
        }
    }

    private async void OnStartClick(object sender, RoutedEventArgs e)
    {
        SaveCredentials();
        var ok = await _engine.StartAsync();
        if (!ok)
            _log.Error("启动失败，请检查配置");
    }

    private void OnStopClick(object sender, RoutedEventArgs e)
    {
        _engine.Stop();
    }

    private void OnSaveClick(object sender, RoutedEventArgs e)
    {
        SaveCredentials();
    }

    private void SaveCredentials()
    {
        _engine.UpdateCredentials(UsernameBox.Text, PasswordBox.Password);
        _log.Info("配置已保存");
    }

    private void OnVerifyClick(object sender, RoutedEventArgs e)
    {
        _engine.VerifyWebsite();
    }

    private void OnEditAnnouncementClick(object sender, RoutedEventArgs e)
    {
        // Re-fetch announcement
        LoadAnnouncementAsync();
    }

    protected override void OnClosed(EventArgs e)
    {
        _engine.Dispose();
        base.OnClosed(e);
    }
}
