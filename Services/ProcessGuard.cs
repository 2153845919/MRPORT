using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace MRPORT.Services;

/// <summary>
/// Dual-process watchdog: ensures main process stays alive.
/// If proxy connection lost → kill nrc_launcher.exe.
/// </summary>
public class ProcessGuard : IDisposable
{
    private readonly string _mainProcessName;
    private CancellationTokenSource? _cts;
    private Task? _watchdog;
    public event Action? OnGuardRestart;

    /// <summary>
    /// Guard mode = child process that monitors main process.
    /// </summary>
    public ProcessGuard(string mainProcessName)
    {
        _mainProcessName = mainProcessName;
    }

    public void StartGuard()
    {
        _cts = new CancellationTokenSource();
        _watchdog = Task.Run(() => GuardLoopAsync(_cts.Token));
    }

    private async Task GuardLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            var procs = Process.GetProcessesByName(_mainProcessName);
            if (procs.Length == 0)
            {
                // Main process died, restart
                try
                {
                    Process.Start(System.Reflection.Assembly.GetEntryAssembly()!.Location);
                    OnGuardRestart?.Invoke();
                }
                catch { }
            }
            else
            {
                foreach (var p in procs) p.Dispose();
            }

            try { await Task.Delay(1000, ct); } catch { break; }
        }
    }

    /// <summary>
    /// Kill nrc_launcher.exe when proxy is down.
    /// </summary>
    public static void KillNrcLauncher()
    {
        try
        {
            foreach (var proc in Process.GetProcessesByName("nrc_launcher"))
            {
                proc.Kill(entireProcessTree: true);
                proc.Dispose();
            }
        }
        catch { }
    }

    public void Dispose()
    {
        _cts?.Cancel();
        _cts?.Dispose();
    }
}
