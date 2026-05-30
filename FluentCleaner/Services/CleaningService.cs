using System.IO.Enumeration;
using System.Runtime.InteropServices;
using FluentCleaner.Models;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace FluentCleaner.Services;

public class CleaningService
{
    private readonly PathExpander _expander = new();

    private static readonly string _winDir    = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
    private static readonly string _sysDir    = Environment.GetFolderPath(Environment.SpecialFolder.System);
    private static readonly string _sysDirX86 = Environment.GetFolderPath(Environment.SpecialFolder.SystemX86);

    private static bool IsProtectedFilePath(string path)
    {
        try
        {
            var norm = Path.GetFullPath(path);
            if (Path.GetPathRoot(norm)?.Equals(norm, StringComparison.OrdinalIgnoreCase) == true) return true;
            return norm.StartsWith(_winDir    + "\\", StringComparison.OrdinalIgnoreCase)
                || norm.StartsWith(_sysDir    + "\\", StringComparison.OrdinalIgnoreCase)
                || norm.StartsWith(_sysDirX86 + "\\", StringComparison.OrdinalIgnoreCase);
        }
        catch { return true; }
    }

    private static bool IsProtectedRegistryPath(string keyPath)
    {
        var u = keyPath.ToUpperInvariant();
        return u == "HKLM\\SYSTEM" || u.StartsWith("HKLM\\SYSTEM\\", StringComparison.Ordinal)
            || u == "HKLM\\SAM"    || u.StartsWith("HKLM\\SAM\\",    StringComparison.Ordinal)
            || u == "HKLM\\SECURITY" || u.StartsWith("HKLM\\SECURITY\\", StringComparison.Ordinal)
            || u == "HKLM" || u == "HKCU" || u == "HKU" || u == "HKCC" || u == "HKCR";
    }

    public Task<ScanResult> AnalyzeAsync(CleanerEntry entry, IProgress<string>? progress = null, CancellationToken token = default) =>
        Task.Run(() => Analyze(entry, progress, token), token);

    public Task<(int count, long bytes)> CleanAsync(ScanResult result, IProgress<string>? progress = null, CancellationToken token = default) =>
        Task.Run(() => Clean(result, progress, token), token);

    private ScanResult Analyze(CleanerEntry entry, IProgress<string>? progress, CancellationToken token = default)
    {
        var result   = new ScanResult { Entry = entry };
        var excluded = BuildExclusions(entry);
        IProgress<string>? entryProgress = progress is null ? null : new PrefixedProgress(entry.Name, progress);

        foreach (var fileKey in entry.FileKeys)
        {
            try
            {
                foreach (var file in FindFiles(fileKey, excluded, entryProgress, token))
                {
                    if (result.FilesToDelete.Contains(file)) continue;
                    var size = TryGetDeletableSize(file);
                    if (size < 0) continue;
                    if (AmsiScanner.IsThreat(file))
                        result.ThreatFiles.Add(file);
                    else
                        result.FilesToDelete.Add(file);
                    result.TotalBytes += size;
                }
            }
            catch (OperationCanceledException) { throw; }
            catch { }
        }

        foreach (var regKey in entry.RegKeys)
        {
            token.ThrowIfCancellationRequested();
            try { result.RegistryToDelete.AddRange(FindRegistryItems(regKey)); }
            catch (OperationCanceledException) { throw; }
            catch { }
        }

        return result;
    }

    private IEnumerable<string> FindFiles(FileKeyEntry fileKey, List<ExclusionRule> excluded, IProgress<string>? progress, CancellationToken token = default)
    {
        bool recurse = fileKey.Flag is FileKeyFlag.Recurse or FileKeyFlag.RemoveSelf;
        var patterns = fileKey.Pattern.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        foreach (var dir in _expander.ResolvePaths(fileKey.Path))
        {
            if (!Directory.Exists(dir)) continue;
            progress?.Report(dir);
            foreach (var f in EnumerateFilesSafe(dir, patterns, recurse, progress, token))
                if (!IsExcluded(f, excluded) && !IsProtectedFilePath(f))
                    yield return f;
        }
    }

    private static IEnumerable<string> EnumerateFilesSafe(string root, string[] patterns, bool recurse, IProgress<string>? progress = null, CancellationToken token = default)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in patterns)
        {
            IEnumerable<string> files;
            try { files = Directory.EnumerateFiles(root, p); }
            catch { files = []; }
            foreach (var f in files)
                if (seen.Add(f)) yield return f;
        }
        if (!recurse) yield break;
        IEnumerable<string> dirs;
        try { dirs = Directory.EnumerateDirectories(root).Where(d => (File.GetAttributes(d) & FileAttributes.ReparsePoint) == 0); }
        catch { yield break; }
        foreach (var sub in dirs)
        {
            token.ThrowIfCancellationRequested();
            progress?.Report(sub);
            foreach (var f in EnumerateFilesSafe(sub, patterns, recurse: true, progress, token))
                yield return f;
        }
    }

    private static IEnumerable<RegistryItemToDelete> FindRegistryItems(RegKeyEntry regKey)
    {
        if (IsProtectedRegistryPath(regKey.KeyPath)) yield break;
        var (hive, subKey) = SplitHiveSubKey(regKey.KeyPath);
        using var root = OpenHive(hive);
        if (root is null) yield break;
        using var key = root.OpenSubKey(subKey, writable: false);
        if (key is null) yield break;
        if (regKey.ValueName is not null)
        {
            if (key.GetValue(regKey.ValueName) is not null)
                yield return new RegistryItemToDelete { KeyPath = regKey.KeyPath, ValueName = regKey.ValueName };
        }
        else
        {
            yield return new RegistryItemToDelete { KeyPath = regKey.KeyPath };
        }
    }

    private (int count, long bytes) Clean(ScanResult result, IProgress<string>? progress, CancellationToken token = default)
    {
        int  count = 0;
        long bytes = 0;

        foreach (var file in result.FilesToDelete)
        {
            token.ThrowIfCancellationRequested();
            try
            {
                var size = new FileInfo(file).Length;
                File.Delete(file);
                count++; bytes += size;
                progress?.Report($"Deleted: {file}");
            }
            catch { }
        }

        foreach (var file in result.ThreatFiles)
        {
            token.ThrowIfCancellationRequested();
            try
            {
                QuarantineService.MoveToQuarantine(file);
                count++;
                progress?.Report($"Quarantined: {file}");
            }
            catch { }
        }

        foreach (var regItem in result.RegistryToDelete)
        {
            try { DeleteRegistryItem(regItem); count++; progress?.Report($"Registry: {regItem}"); }
            catch { }
        }

        foreach (var fk in result.Entry.FileKeys.Where(fk => fk.Flag == FileKeyFlag.RemoveSelf))
            foreach (var resolved in _expander.ResolvePaths(fk.Path))
                TryPruneEmptyDirs(resolved);

        return (count, bytes);
    }

    private static void DeleteRegistryItem(RegistryItemToDelete item)
    {
        var (hive, subKey) = SplitHiveSubKey(item.KeyPath);
        using var root = OpenHive(hive);
        if (root is null) return;
        if (item.ValueName is not null)
        {
            using var key = root.OpenSubKey(subKey, writable: true);
            key?.DeleteValue(item.ValueName, throwOnMissingValue: false);
        }
        else
        {
            var parentSubKey = Path.GetDirectoryName(subKey)?.Replace('/', '\\') ?? "";
            var keyName      = Path.GetFileName(subKey);
            using var parent = root.OpenSubKey(parentSubKey, writable: true);
            parent?.DeleteSubKeyTree(keyName, throwOnMissingSubKey: false);
        }
    }

    private static void TryPruneEmptyDirs(string path)
    {
        if (!Directory.Exists(path)) return;
        try
        {
            foreach (var sub in Directory.GetDirectories(path, "*", SearchOption.AllDirectories).OrderByDescending(d => d.Length))
                if (Directory.GetFileSystemEntries(sub).Length == 0) Directory.Delete(sub);
            if (Directory.GetFileSystemEntries(path).Length == 0) Directory.Delete(path);
        }
        catch { }
    }

    private List<ExclusionRule> BuildExclusions(CleanerEntry entry)
    {
        var rules = new List<ExclusionRule>();
        foreach (var ex in entry.ExcludeKeys)
        {
            if (ex.Type is ExcludeType.Reg) continue;
            foreach (var p in _expander.ResolvePaths(ex.Path))
                rules.Add(new ExclusionRule(p.TrimEnd('\\') + "\\", ex.Pattern));
        }
        return rules;
    }

    private static long TryGetDeletableSize(string path)
    {
        const uint DELETE = 0x00010000, FILE_SHARE_ALL = 0x7, OPEN_EXISTING = 3;
        using var handle = CreateFileW(path, DELETE, FILE_SHARE_ALL, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
        if (handle.IsInvalid) return -1;
        try { return new FileInfo(path).Length; }
        catch { return -1; }
    }

    private static bool IsExcluded(string path, List<ExclusionRule> rules)
    {
        foreach (var rule in rules)
            if (rule.Matches(path)) return true;
        return false;
    }

    private static (string hive, string subKey) SplitHiveSubKey(string path)
    {
        var idx = path.IndexOf('\\');
        return idx < 0 ? (path.ToUpperInvariant(), "") : (path[..idx].ToUpperInvariant(), path[(idx + 1)..]);
    }

    internal static RegistryKey? OpenHive(string hive) => hive switch
    {
        "HKCU" or "HKEY_CURRENT_USER"   => Registry.CurrentUser,
        "HKLM" or "HKEY_LOCAL_MACHINE"  => Registry.LocalMachine,
        "HKU"  or "HKEY_USERS"          => Registry.Users,
        "HKCC" or "HKEY_CURRENT_CONFIG" => Registry.CurrentConfig,
        "HKCR" or "HKEY_CLASSES_ROOT"   => Registry.ClassesRoot,
        _ => null
    };

    private readonly record struct ExclusionRule(string DirPrefix, string? Pattern)
    {
        public bool Matches(string filePath)
        {
            if (!filePath.StartsWith(DirPrefix, StringComparison.OrdinalIgnoreCase)) return false;
            if (Pattern is null) return true;
            if (Pattern.Contains('*') || Pattern.Contains('?'))
                return FileSystemName.MatchesSimpleExpression(Pattern, Path.GetFileName(filePath), ignoreCase: true);
            return filePath[DirPrefix.Length..].Equals(Pattern, StringComparison.OrdinalIgnoreCase);
        }
    }

    private sealed class PrefixedProgress(string prefix, IProgress<string> inner) : IProgress<string>
    {
        public void Report(string path) => inner.Report($"{prefix}  ›  {path}");
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string lpFileName, uint dwDesiredAccess, uint dwShareMode,
        IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);
}
