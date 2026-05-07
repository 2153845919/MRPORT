using System;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace MRPORT.Services;

/// <summary>
/// Manages the WFP callout DLL lifecycle.
/// Loads the native DLL, sets target IPs, and reads original destinations.
/// </summary>
public class WfpEngine : IDisposable
{
    private const string DllName = "callout.dll";

    [DllImport(DllName, CallingConvention = CallingConvention.Winapi)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Initialize();

    [DllImport(DllName, CallingConvention = CallingConvention.Winapi)]
    private static extern void Shutdown();

    [DllImport(DllName, CallingConvention = CallingConvention.Winapi)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetTargets(uint[] ips, uint count);

    [DllImport(DllName, CallingConvention = CallingConvention.Winapi)]
    private static extern uint GetTargetCount();

    [DllImport(DllName, CallingConvention = CallingConvention.Winapi)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ReadOrigDst(ushort localPort, out uint outIp, out ushort outPort);

    private readonly LogService _log;
    private bool _initialized;

    public WfpEngine(LogService log)
    {
        _log = log;
    }

    public bool InitializeEngine()
    {
        if (_initialized) return true;

        if (!Initialize())
        {
            _log.Error("Failed to initialize WFP callout (callout.dll missing?)");
            return false;
        }

        _initialized = true;
        _log.Info("WFP callout engine initialized");
        return true;
    }

    public bool SetTargetIps(IPAddress[] ips)
    {
        var v4 = new System.Collections.Generic.List<uint>();
        foreach (var ip in ips)
        {
            if (ip.AddressFamily == AddressFamily.InterNetwork)
            {
                byte[] bytes = ip.GetAddressBytes();
                uint val = (uint)(bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24));
                v4.Add(val);
            }
        }
        return SetTargets(v4.ToArray(), (uint)v4.Count);
    }

    public bool ReadOriginalDestination(ushort localPort, out IPAddress? ip, out int port)
    {
        ip = null;
        port = 0;
        if (!ReadOrigDst(localPort, out uint rawIp, out ushort rawPort))
            return false;

        ip = new IPAddress(new byte[] {
            (byte)(rawIp & 0xFF),
            (byte)((rawIp >> 8) & 0xFF),
            (byte)((rawIp >> 16) & 0xFF),
            (byte)((rawIp >> 24) & 0xFF)
        });
        port = IPAddress.NetworkToHostOrder((short)rawPort);
        return true;
    }

    public void Dispose()
    {
        if (_initialized)
        {
            Shutdown();
            _initialized = false;
        }
    }
}
