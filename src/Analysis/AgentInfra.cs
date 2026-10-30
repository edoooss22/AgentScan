using System.Text;
using AgentScan.Core;
using AgentScan.Report;

namespace AgentScan.Analysis;

internal static class AgentInfra
{
    public static JarIndex BuildJarIndex(ScanContext ctx, SweepResult sweep)
    {
        var idx = new JarIndex();

        foreach (var r in ctx.Regions)
        {
            string? p = r.MappedFileDos ?? r.MappedFile;
            if (p is null) continue;
            if (p.EndsWith(".jar", StringComparison.OrdinalIgnoreCase)) idx.AddJar(p);
        }

        string cmd = ctx.Target.GetCommandLine() ?? "";
        foreach (var token in Tokenize(cmd))
        {
            if (token.StartsWith("@", StringComparison.Ordinal))
            {
                try
                {
                    string argFile = token[1..].Trim('"');
                    if (File.Exists(argFile))
                        foreach (var t2 in Tokenize(File.ReadAllText(argFile)))
                            AddClassPath(idx, t2);
                }
                catch { }
            }
            AddClassPath(idx, token);
        }

        string cwd = ctx.Target.GetCurrentDirectory() ?? "";
        if (cwd.Length > 3)
        {
            idx.AddDirectory(Path.Combine(cwd, "mods"), recursive: true);
            idx.AddDirectory(Path.Combine(cwd, "versions"), recursive: true);
            idx.AddDirectory(Path.Combine(cwd, "libraries"), recursive: true);
            idx.AddDirectory(Path.Combine(cwd, "shaderpacks"));
            idx.AddDirectory(cwd);
        }

        foreach (var kv in sweep.JarPaths)
            if (kv.Key.EndsWith(".jar", StringComparison.OrdinalIgnoreCase)) idx.AddJar(kv.Key);

        return idx;
    }

    private static void AddClassPath(JarIndex idx, string token)
    {
        string t = token.Trim().Trim('"');
        if (t.Length == 0) return;
        if (t.EndsWith(".jar", StringComparison.OrdinalIgnoreCase)) { idx.AddJar(t); return; }
        if (t.Contains(';') && t.Contains(".jar", StringComparison.OrdinalIgnoreCase))
            foreach (var part in t.Split(';', StringSplitOptions.RemoveEmptyEntries))
                if (part.EndsWith(".jar", StringComparison.OrdinalIgnoreCase)) idx.AddJar(part);
    }

    private static IEnumerable<string> Tokenize(string s)
    {
        bool q = false;
        var cur = new StringBuilder();
        foreach (char ch in s)
        {
            if (ch == '"') { q = !q; continue; }
            if (!q && (ch == ' ' || ch == '\r' || ch == '\n' || ch == '\t'))
            {
                if (cur.Length > 0) { yield return cur.ToString(); cur.Clear(); }
                continue;
            }
            cur.Append(ch);
        }
        if (cur.Length > 0) yield return cur.ToString();
    }

    public static void DetectRemap(ScanContext ctx, SweepResult sweep)
    {
        int intermediary = 0;
        void Count(string name)
        {
            if (name.Contains("\\u", StringComparison.Ordinal)) return;
            string plain = name;
            int marker = plain.IndexOf("+0x", StringComparison.Ordinal);
            if (marker < 0) marker = plain.IndexOf("/0x", StringComparison.Ordinal);
            if (marker > 0) return;
            if (JarIndex.IsRuntimeClass(plain) || JarIndex.GeneratedKind(plain) is not null) return;
            if (IsIntermediary(SimpleName(plain))) intermediary++;
        }
        foreach (var kv in ctx.LiveKlasses) Count(kv.Value);
        foreach (var kv in ctx.AllKlassObjects) Count(kv.Value);
        foreach (var c in sweep.Classes.Values) Count(c.Name);

        int inJars = ctx.Jars?.AllClasses.Count(IsVanillaObf) ?? 0;
        ctx.GameIsRemapped = intermediary >= 500 || inJars < 16;
    }

    private static string SimpleName(string n)
    {
        int slash = n.LastIndexOf('/');
        string s = slash >= 0 ? n[(slash + 1)..] : n;
        int dollar = s.LastIndexOf('$');
        if (dollar > 0 && dollar < s.Length - 1 && !char.IsDigit(s[dollar + 1]))
            s = s[(dollar + 1)..];
        return s;
    }

    private static bool IsIntermediary(string simple)
    {
        foreach (string p in new[] { "class_", "method_", "field_", "comp_" })
        {
            if (!simple.StartsWith(p, StringComparison.Ordinal)) continue;
            string rest = simple[p.Length..];
            if (rest.Length > 0 && rest.All(char.IsDigit)) return true;
        }
        return false;
    }

    public static bool IsVanillaObf(string name)
    {
        foreach (string part in name.Split('/', '$'))
        {
            if (part.Length is 0 or > 3) return false;
            foreach (char c in part)
                if (c is < 'a' or > 'z') return false;
        }
        return true;
    }

    public static void CollectMirrorCounters(ScanContext ctx)
    {
        var java = ctx.Java;
        int offMirror = ctx.Vm?.Off("Klass", "_java_mirror") ?? -1;
        if (java is null || offMirror < 0) return;

        int redefined = 0;
        foreach (var kv in ctx.LiveKlasses)
        {
            string name = kv.Value;
            if (name.Length == 0 || JarIndex.IsRuntimeClass(name)) continue;
            ulong handle = java.Cache.U64(kv.Key + (ulong)offMirror);
            if (handle is < 0x1000 or > 0x7FFFFFFFFFFF) continue;
            ulong mirrorObj = java.Cache.U64(handle);
            if (mirrorObj is < 0x1000 or > 0x7FFFFFFFFFFF) continue;
            int count = java.IntField(mirrorObj, "classRedefinedCount");
            if (count is <= 0 or >= 100000) continue;
            ctx.RedefinedClassMirrors.Add((name, count));
            redefined++;
        }
    }

    public static void ReportSweep(ScanContext ctx, SweepResult sweep)
    {
        var rep = ctx.Report;
        foreach (var g in sweep.Hits.GroupBy(h => h.Sig)
                                    .OrderByDescending(g => g.Key.Severity))
        {
            var sig = g.Key;
            int total = g.Sum(h => h.OccurrencesInRegion);

            var f = rep.Report("СИГНАТУРЫ",
                $"[{sig.Category}] {sig.Name}: найдено {total} совпадений в " +
                $"{g.Count()} регионах",
                sig.Severity,
                sig.Note);
            f.Add("искомая строка", sig.Text);
            f.Add("область поиска", sig.Scope switch
            {
                SigScope.NonImage => "только вне образов PE",
                SigScope.PrivateOnly => "только приватная память",
                SigScope.PrivateExec => "только приватная исполняемая память",
                _ => "вся память",
            });

            var sb = new StringBuilder();
            foreach (var h in g.OrderByDescending(x => x.OccurrencesInRegion).Take(40))
            {
                string where = h.Region.MappedFileDos ?? h.Region.MappedFile
                               ?? $"{h.Region.TypeString}/{h.Region.ProtectString}";
                sb.AppendLine($"  0x{h.Address:X}  ({(h.Utf16 ? "UTF-16" : "ASCII")}, " +
                              $"×{h.OccurrencesInRegion})  {where}");
                sb.AppendLine($"      …{h.Context}…");
            }
            if (g.Count() > 40) sb.AppendLine($"  ... и ещё {g.Count() - 40} регионов");
            f.Block("Совпадения", sb.ToString().TrimEnd());
        }

        var stats = rep.Report("СКАН ПАМЯТИ",
            $"Просканировано {MemoryAnalyzer.Human((ulong)sweep.BytesScanned)} " +
            $"в {sweep.RegionsScanned} регионах за {sweep.Elapsed.TotalSeconds:F1} с",
            Severity.Info, null);
        stats.Add("сигнатурных совпадений", sweep.Hits.Count.ToString());
        stats.Add("class-файлов Java", sweep.Classes.Count.ToString());
        foreach (var rp in sweep.RawPatterns)
            stats.Add($"иголка «{rp.Name}»", $"{rp.TotalHits} совпадений");
        if (sweep.BudgetExhausted)
            stats.Add("ВНИМАНИЕ", "исчерпан лимит объёма скана — часть памяти не проверена");
    }
}
