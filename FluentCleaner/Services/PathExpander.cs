namespace FluentCleaner.Services;

public class PathExpander
{
    private readonly Dictionary<string, string> _vars = BuildVarMap();

    private static Dictionary<string, string> BuildVarMap()
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        void Add(string name, string value)
        {
            if (!string.IsNullOrEmpty(value))
                map[$"%{name}%"] = value.TrimEnd('\\', '/');
        }
        Add("AppData",           Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData));
        Add("LocalAppData",      Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));
        Add("LocalLowAppData",   Path.GetFullPath(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "..", "LocalLow")));
        Add("ProgramFiles",      Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
        Add("ProgramFiles(x86)", Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86));
        Add("ProgramFilesX86",   Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86));
        Add("ProgramData",       Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
        Add("CommonAppData",     Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
        Add("UserProfile",       Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
        Add("Documents",         Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments));
        Add("Desktop",           Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory));
        Add("Music",             Environment.GetFolderPath(Environment.SpecialFolder.MyMusic));
        Add("Pictures",          Environment.GetFolderPath(Environment.SpecialFolder.MyPictures));
        Add("Videos",            Environment.GetFolderPath(Environment.SpecialFolder.MyVideos));
        Add("SystemRoot",        Environment.GetFolderPath(Environment.SpecialFolder.Windows));
        Add("WinDir",            Environment.GetFolderPath(Environment.SpecialFolder.Windows));
        Add("System",            Environment.GetFolderPath(Environment.SpecialFolder.System));
        Add("SystemX86",         Environment.GetFolderPath(Environment.SpecialFolder.SystemX86));
        Add("Temp",              Path.GetTempPath().TrimEnd('\\', '/'));
        Add("Tmp",               Path.GetTempPath().TrimEnd('\\', '/'));
        Add("SystemDrive",       Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.Windows))?.TrimEnd('\\') ?? "C:");
        return map;
    }

    public string ExpandVariables(string path)
    {
        foreach (var (token, value) in _vars)
            path = path.Replace(token, value, StringComparison.OrdinalIgnoreCase);
        path = Environment.ExpandEnvironmentVariables(path);
        if (path.Length == 2 && char.IsLetter(path[0]) && path[1] == ':')
            path += Path.DirectorySeparatorChar;
        return path;
    }

    public List<string> ResolvePaths(string rawPath)
    {
        var results = new List<string>();
        ResolveRecursive(ExpandVariables(rawPath), results);
        if (rawPath.Contains("%ProgramFiles%", StringComparison.OrdinalIgnoreCase))
        {
            var x86Path = rawPath.Replace("%ProgramFiles%", "%ProgramFiles(x86)%", StringComparison.OrdinalIgnoreCase);
            var expanded = ExpandVariables(x86Path);
            if (!results.Contains(expanded))
                ResolveRecursive(expanded, results);
        }
        return results;
    }

    private static void ResolveRecursive(string path, List<string> results)
    {
        var parts = path.Split(new[] { '\\', '/' }, StringSplitOptions.None);
        int wcIdx = Array.FindIndex(parts, p => p.Contains('*') || p.Contains('?'));
        if (wcIdx < 0) { results.Add(path); return; }
        var basePath = wcIdx == 0 ? Path.GetPathRoot(path) ?? "" : string.Join('\\', parts[..wcIdx]);
        if (!Directory.Exists(basePath)) return;
        var wildcard  = parts[wcIdx];
        var remaining = parts[(wcIdx + 1)..];
        try
        {
            var matches = remaining.Length == 0
                ? Directory.GetFileSystemEntries(basePath, wildcard)
                : Directory.GetDirectories(basePath, wildcard);
            foreach (var match in matches)
            {
                if ((File.GetAttributes(match) & FileAttributes.ReparsePoint) != 0) continue;
                if (remaining.Length == 0)
                    results.Add(match);
                else
                    ResolveRecursive(Path.Combine(match, string.Join('\\', remaining)), results);
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
    }
}
