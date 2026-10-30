using System.IO.Compression;

namespace AgentScan.Core;

internal sealed class JarIndex
{
    private readonly Dictionary<string, List<string>> _classes = new(StringComparer.Ordinal);

    private readonly Dictionary<string, ZipArchive?> _open =
        new(StringComparer.OrdinalIgnoreCase);

    public byte[]? ReadClassBytes(string internalName) =>
        ReadAllClassBytes(internalName).FirstOrDefault();

    public List<byte[]> ReadAllClassBytes(string internalName)
    {
        var res = new List<byte[]>();
        if (!_classes.TryGetValue(internalName, out var jars) || jars.Count == 0) return res;
        foreach (string jar in jars)
        {
            if (jar.Contains('!'))
            {
                var parts = jar.Split('!', 2);
                try
                {
                    using var outer = ZipFile.OpenRead(parts[0]);
                    var e0 = outer.GetEntry(parts[1]);
                    if (e0 is null) continue;
                    using var s0 = e0.Open();
                    using var ms = new MemoryStream();
                    s0.CopyTo(ms);
                    ms.Position = 0;
                    using var inner = new ZipArchive(ms, ZipArchiveMode.Read);
                    var e1 = inner.GetEntry(internalName + ".class");
                    if (e1 is null) continue;
                    var d1 = ReadEntry(e1);
                    if (d1 is not null) res.Add(d1);
                    continue;
                }
                catch { continue; }
            }

            if (!_open.TryGetValue(jar, out var zip))
            {
                try { zip = ZipFile.OpenRead(jar); }
                catch { zip = null; }
                if (_open.Count > 512) CloseAll();
                _open[jar] = zip;
            }
            if (zip is null) continue;
            try
            {
                var e = zip.GetEntry(internalName + ".class");
                if (e is not null)
                {
                    var d = ReadEntry(e);
                    if (d is not null) res.Add(d);
                }
            }
            catch { }
        }
        return res;
    }

    private static byte[]? ReadEntry(ZipArchiveEntry e)
    {
        try
        {
            if (e.Length > 32 * 1024 * 1024) return null;
            using var s = e.Open();
            using var ms = new MemoryStream((int)Math.Max(e.Length, 16));
            s.CopyTo(ms);
            return ms.ToArray();
        }
        catch { return null; }
    }

    public void CloseAll()
    {
        foreach (var z in _open.Values) z?.Dispose();
        _open.Clear();
    }

    private readonly Dictionary<string, List<string>> _mixinConfigs =
        new(StringComparer.OrdinalIgnoreCase);

    public List<string> Jars { get; } = new();
    public List<string> Errors { get; } = new();
    public int ClassCount => _classes.Count;
    public int MixinConfigCount => AllMixinConfigs.Count();

    private static bool LooksLikeMixinConfig(string name) =>
        name.Contains("mixin", StringComparison.OrdinalIgnoreCase) &&
        name.EndsWith(".json", StringComparison.OrdinalIgnoreCase);

    public bool Contains(string internalName) => _classes.ContainsKey(internalName);

    public IEnumerable<string> AllClasses => _classes.Keys;

    public IReadOnlyList<string>? JarsOf(string internalName) =>
        _classes.TryGetValue(internalName, out var v) ? v : null;

    private Dictionary<string, List<string>>? _packages;

    private Dictionary<string, List<string>> Packages()
    {
        if (_packages is not null) return _packages;
        var res = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        foreach (var kv in _classes)
        {
            int slash = kv.Key.LastIndexOf('/');
            if (slash <= 0) continue;
            string pkg = kv.Key.Substring(0, slash);
            if (!res.TryGetValue(pkg, out var l)) res[pkg] = l = new List<string>();
            foreach (string j in kv.Value)
                if (!l.Contains(j)) l.Add(j);
        }
        _packages = res;
        return res;
    }

    public (string Package, IReadOnlyList<string> Jars)? OwningPackage(string internalName)
    {
        if (internalName.Length == 0) return null;
        var pkgs = Packages();
        int cut = internalName.LastIndexOf('/');
        while (cut > 0)
        {
            string pkg = internalName.Substring(0, cut);
            if (pkg.Count(c => c == '/') >= 1 && pkgs.TryGetValue(pkg, out var jars))
                return (pkg, jars);
            cut = pkg.LastIndexOf('/');
        }
        return null;
    }

    public string? RepairTornName(string prefix, string suffix)
    {
        if (prefix.Length < 8 || suffix.Length < 4) return null;
        string? found = null;
        foreach (string k in _classes.Keys)
        {
            if (!k.StartsWith(prefix, StringComparison.Ordinal)) continue;
            if (!k.EndsWith(suffix, StringComparison.Ordinal)) continue;
            if (found is not null) return null;
            found = k;
        }
        return found;
    }

    public bool HasMixinConfig(string name) => _mixinConfigs.ContainsKey(name);

    public IReadOnlyList<string>? MixinConfigJars(string name) =>
        _mixinConfigs.TryGetValue(name, out var v) ? v : null;

    public IEnumerable<string> AllMixinConfigs =>
        _mixinConfigs.Keys.Where(k => !k.Contains('/') && LooksLikeMixinConfig(k));

    public void AddJar(string path)
    {
        string full;
        try { full = Path.GetFullPath(path); }
        catch { return; }
        if (Jars.Contains(full, StringComparer.OrdinalIgnoreCase)) return;
        if (!File.Exists(full)) return;

        Jars.Add(full);
        try
        {
            using var zip = ZipFile.OpenRead(full);
            foreach (var e in zip.Entries)
            {
                string n = e.FullName;
                if (n.EndsWith(".class", StringComparison.OrdinalIgnoreCase))
                {
                    string cn = n[..^6].Replace('\\', '/');
                    if (!_classes.TryGetValue(cn, out var list))
                        _classes[cn] = list = new List<string>(1);
                    if (list.Count < 8) list.Add(full);
                }
                else if (n.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
                {
                    AddJsonEntry(n, full);
                }
                else if (n.EndsWith(".jar", StringComparison.OrdinalIgnoreCase) &&
                         e.Length is > 0 and < 64 * 1024 * 1024)
                {
                    AddNestedJar(full, e);
                }
            }
        }
        catch (Exception ex)
        {
            Errors.Add($"{Path.GetFileName(full)}: {ex.GetType().Name}: {ex.Message}");
        }
    }

    private void AddJsonEntry(string entryName, string source)
    {
        string full = entryName.Replace('\\', '/');
        foreach (string key in new[] { full, Path.GetFileName(full) })
        {
            if (key.Length == 0) continue;
            if (!_mixinConfigs.TryGetValue(key, out var list))
                _mixinConfigs[key] = list = new List<string>(1);
            if (list.Count < 8 && !list.Contains(source)) list.Add(source);
        }
    }

    private void AddNestedJar(string outerPath, ZipArchiveEntry entry)
    {
        try
        {
            using var s = entry.Open();
            using var ms = new MemoryStream();
            s.CopyTo(ms);
            ms.Position = 0;
            using var inner = new ZipArchive(ms, ZipArchiveMode.Read);
            string tag = $"{outerPath}!{entry.FullName}";
            foreach (var e in inner.Entries)
            {
                if (e.FullName.EndsWith(".class", StringComparison.OrdinalIgnoreCase))
                {
                    string cn = e.FullName[..^6].Replace('\\', '/');
                    if (!_classes.TryGetValue(cn, out var list))
                        _classes[cn] = list = new List<string>(1);
                    if (list.Count < 8) list.Add(tag);
                }
                else if (e.FullName.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
                    AddJsonEntry(e.FullName, tag);
            }
        }
        catch {  }
    }

    public void AddDirectory(string dir, bool recursive = false, int limit = 4000)
    {
        try
        {
            if (!Directory.Exists(dir)) return;
            var opt = recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
            int n = 0;
            foreach (var f in Directory.EnumerateFiles(dir, "*.jar", opt))
            {
                AddJar(f);
                if (++n >= limit) break;
            }
        }
        catch (Exception ex) { Errors.Add($"{dir}: {ex.Message}"); }
    }

    public static bool IsRuntimeClass(string name) =>
        name.StartsWith("java/", StringComparison.Ordinal) ||
        name.StartsWith("javax/", StringComparison.Ordinal) ||
        name.StartsWith("jdk/", StringComparison.Ordinal) ||
        name.StartsWith("sun/", StringComparison.Ordinal) ||
        name.StartsWith("com/sun/", StringComparison.Ordinal) ||
        name.StartsWith("org/w3c/", StringComparison.Ordinal) ||
        name.StartsWith("org/xml/", StringComparison.Ordinal) ||
        name.StartsWith("org/ietf/", StringComparison.Ordinal) ||
        name.StartsWith("org/jcp/", StringComparison.Ordinal) ||
        name.StartsWith("netscape/", StringComparison.Ordinal);

    public static string? GeneratedKind(string name)
    {
        if (name.Contains("$$Lambda", StringComparison.Ordinal)) return "лямбда JVM";
        if (name.Contains("/0x", StringComparison.Ordinal)) return "скрытый класс (defineHiddenClass)";
        if (name.StartsWith("com/sun/proxy/", StringComparison.Ordinal) ||
            name.Contains("$Proxy", StringComparison.Ordinal)) return "динамический прокси";
        if (name.Contains("GeneratedMethodAccessor", StringComparison.Ordinal) ||
            name.Contains("GeneratedConstructorAccessor", StringComparison.Ordinal) ||
            name.Contains("GeneratedSerializationConstructor", StringComparison.Ordinal))
            return "акцессор рефлексии";
        if (name.Contains("$$EnhancerBy", StringComparison.Ordinal) ||
            name.Contains("$$FastClassBy", StringComparison.Ordinal)) return "CGLIB";
        if (name.StartsWith("org/spongepowered/asm/synthetic/", StringComparison.Ordinal))
            return "синтетика Mixin";
        if (name.Contains("$Anonymous$", StringComparison.Ordinal)) return "анонимный класс Mixin";
        if (name.Contains("mixinextras/sugar/impl/ref/generated/", StringComparison.Ordinal))
            return "генерация MixinExtras";
        if (name.Contains("$$InjectedInvoker", StringComparison.Ordinal) ||
            name.EndsWith("InjectedInvoker", StringComparison.Ordinal))
            return "инвокер ByteBuddy/Mixin";
        if (name.StartsWith("net/bytebuddy/renamed/", StringComparison.Ordinal) ||
            name.Contains("$ByteBuddy$", StringComparison.Ordinal)) return "генерация ByteBuddy";
        if (name.StartsWith("[", StringComparison.Ordinal)) return "массив";
        return null;
    }
}
