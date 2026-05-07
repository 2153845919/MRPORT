using System;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace MRPORT.Services;

public class LogService : INotifyPropertyChanged
{
    private readonly ConcurrentQueue<string> _logs = new();
    private const int MaxLines = 500;

    public string LogText
    {
        get
        {
            var sb = new StringBuilder();
            foreach (var line in _logs)
                sb.AppendLine(line);
            return sb.ToString();
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public void Info(string msg) => Append($"[{DateTime.Now:HH:mm:ss}] INFO: {msg}");
    public void Warn(string msg) => Append($"[{DateTime.Now:HH:mm:ss}] WARN: {msg}");
    public void Error(string msg) => Append($"[{DateTime.Now:HH:mm:ss}] ERROR: {msg}");

    private void Append(string line)
    {
        _logs.Enqueue(line);
        while (_logs.Count > MaxLines)
            _logs.TryDequeue(out _);
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(LogText)));
    }
}
