namespace FluentCleaner.Services;

public static class QuarantineService
{
    public static readonly string QuarantineDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "FluentCleaner", "Quarantine");

    public static void MoveToQuarantine(string filePath)
    {
        Directory.CreateDirectory(QuarantineDir);
        var qPath = Path.Combine(QuarantineDir, Guid.NewGuid().ToString("N") + ".qtn");
        File.Move(filePath, qPath, overwrite: false);
        File.WriteAllText(qPath + ".origin", filePath);
    }

    public static bool TryRestore(string qtnPath)
    {
        try
        {
            var originFile = qtnPath + ".origin";
            if (!File.Exists(originFile)) return false;
            var origin = File.ReadAllText(originFile).Trim();
            Directory.CreateDirectory(Path.GetDirectoryName(origin)!);
            File.Move(qtnPath, origin, overwrite: false);
            File.Delete(originFile);
            return true;
        }
        catch { return false; }
    }

    public static IEnumerable<(string QtnPath, string OriginalPath)> ListQuarantined()
    {
        if (!Directory.Exists(QuarantineDir)) yield break;
        foreach (var f in Directory.GetFiles(QuarantineDir, "*.qtn"))
        {
            var originFile = f + ".origin";
            var origin = File.Exists(originFile) ? File.ReadAllText(originFile).Trim() : "unknown";
            yield return (f, origin);
        }
    }
}
