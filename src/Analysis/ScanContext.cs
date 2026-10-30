using AgentScan.Core;
using AgentScan.Report;

namespace AgentScan.Analysis;

internal readonly record struct CodeBlobInfo(ulong Lo, ulong Hi, string Cls, string Name,
    ulong CodeBegin, ulong EntryPoint, ulong VerifiedEntry, ulong Method, bool IsNmethod,
    sbyte State, ulong Address);

internal sealed class ScanContext
{
    public required ProcessTarget Target { get; init; }
    public required Options Options { get; init; }
    public required ScanReport Report { get; init; }

    public List<MemRegion> Regions { get; set; } = new();
    public LoaderModules.Result Loader { get; set; } = new();
    public RegionDumper? Dumper { get; set; }
    public JarIndex? Jars { get; set; }
    public bool GameIsRemapped { get; set; }
    public VmStructs? Vm { get; set; }

    public Dictionary<ulong, string> LiveKlasses { get; } = new();
    public HashSet<ulong> LiveMethods { get; } = new();
    public Dictionary<ulong, string> AllKlassObjects { get; } = new();
    public List<ulong> ClassLoaderDatas { get; } = new();
    public List<(string Cls, ulong Vtable, RawPattern Pattern)> VtablePatterns { get; } = new();
    public List<ulong> JvmtiEnvs { get; } = new();
    public List<VmTable> VmTables { get; set; } = new();
    public List<(string Name, string Handle, ulong NameAddr, ulong HandleAddr,
        RawPattern Pattern)> EventLogPatterns { get; } = new();

    public JavaMeta? Java { get; set; }
    public JavaHeapIndex? HeapIndex { get; set; }
    public List<CodeBlobInfo> CodeBlobs { get; } = new();
    public List<ImageInMemory> Images { get; set; } = new();
    public List<ThreadInfo> Threads { get; set; } = new();

    public List<(string Ring, double Seconds, ulong Thread, string Text)> VmEvents
    { get; } = new();
    public Dictionary<string, (int Length, int Count)> VmEventRings { get; } =
        new(StringComparer.Ordinal);
    public List<(string Name, int Count)> RedefinedClassMirrors { get; } = new();

    private List<MemRegion>? _sortedRegions;

    public MemRegion? RegionAt(ulong addr)
    {
        _sortedRegions ??= Regions.OrderBy(r => r.Base).ToList();
        int lo = 0, hi = _sortedRegions.Count - 1;
        while (lo <= hi)
        {
            int mid = (lo + hi) / 2;
            var r = _sortedRegions[mid];
            if (addr < r.Base) hi = mid - 1;
            else if (addr >= r.End) lo = mid + 1;
            else return r;
        }
        return null;
    }

    public ImageInMemory? ImageAt(ulong addr)
    {
        foreach (var im in Images)
            if (addr >= im.Base && addr < im.Base + im.Size) return im;
        return null;
    }

    public string Describe(ulong addr)
    {
        if (addr == 0) return "NULL";
        var im = ImageAt(addr);
        if (im is not null)
        {
            string sym = im.Exports.ResolveNearest(addr - im.Base, out ulong delta);
            if (sym.Length > 0)
                return delta == 0
                    ? $"{im.Name}!{sym}"
                    : $"{im.Name}!{sym}+0x{delta:X}";
            return $"{im.Name}+0x{addr - im.Base:X}";
        }
        var r = RegionAt(addr);
        if (r is null) return $"0x{addr:X} <не отображено>";
        string? tag = r.MappedFileDos ?? r.MappedFile;
        if (tag is not null) return $"0x{addr:X} <{r.TypeString} {Path.GetFileName(tag)}+0x{addr - r.Base:X}>";
        return $"0x{addr:X} <{r.TypeString}/{r.ProtectString}, база 0x{r.AllocationBase:X}>";
    }
}
