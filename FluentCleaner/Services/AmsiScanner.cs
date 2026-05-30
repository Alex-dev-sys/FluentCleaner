using System.Runtime.InteropServices;

namespace FluentCleaner.Services;

public static class AmsiScanner
{
    private static readonly HashSet<string> _scanExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".sys", ".ocx", ".scr",
        ".bat", ".cmd", ".ps1", ".vbs", ".js",
        ".hta", ".jar", ".wsf", ".msi", ".com",
    };

    private const int MaxScanBytes = 16 * 1024 * 1024;

    public static bool IsEnabled => AppSettings.Instance.AmsiScanEnabled;

    public static bool IsThreat(string filePath)
    {
        if (!IsEnabled) return false;
        var ext = Path.GetExtension(filePath);
        if (!_scanExtensions.Contains(ext)) return false;
        try
        {
            var info = new FileInfo(filePath);
            if (!info.Exists || info.Length > MaxScanBytes) return false;
            var bytes = File.ReadAllBytes(filePath);
            if (AmsiInitialize("FluentCleaner", out var ctx) != 0) return false;
            try
            {
                uint hr = AmsiScanBuffer(ctx, bytes, (uint)bytes.Length,
                    Path.GetFileName(filePath), IntPtr.Zero, out var result);
                return hr == 0 && result >= 32768;
            }
            finally { AmsiUninitialize(ctx); }
        }
        catch { return false; }
    }

    [DllImport("amsi.dll", CharSet = CharSet.Unicode)]
    private static extern uint AmsiInitialize(string appName, out IntPtr amsiContext);
    [DllImport("amsi.dll")]
    private static extern void AmsiUninitialize(IntPtr amsiContext);
    [DllImport("amsi.dll", CharSet = CharSet.Unicode)]
    private static extern uint AmsiScanBuffer(IntPtr amsiContext, byte[] buffer, uint length,
        string contentName, IntPtr amsiSession, out int result);
}
