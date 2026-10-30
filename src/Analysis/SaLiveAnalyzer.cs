using System.Text;
using AgentScan.Core;
using AgentScan.Report;

namespace AgentScan.Analysis;

internal static class SaLiveAnalyzer
{
    private const uint JVMTI_MAGIC = 0x71EE;
    private const uint DISPOSED_MAGIC = 0xDEFC;
    private const uint BAD_MAGIC = 0xDEAD;

    private static readonly (string Cls, int MaxHits)[] Tracked =
    {
        ("InstanceKlass", 200_000),
        ("InstanceMirrorKlass", 2000),
        ("InstanceRefKlass", 2000),
        ("InstanceClassLoaderKlass", 2000),
        ("InstanceStackChunkKlass", 2000),
        ("ObjArrayKlass", 20_000),
        ("TypeArrayKlass", 2000),
        ("Method", 400_000),
        ("ConstantPool", 200_000),
        ("JvmtiAgentThread", 512),
        ("JvmtiBreakpoint", 4096),
        ("JvmtiVMObjectAllocEventCollector", 512),
        ("JvmtiDynamicCodeEventCollector", 512),
    };

    private static readonly string[] KlassClasses =
    {
        "InstanceKlass", "InstanceMirrorKlass", "InstanceRefKlass",
        "InstanceClassLoaderKlass", "InstanceStackChunkKlass",
        "ObjArrayKlass", "TypeArrayKlass",
    };

    public static List<RawPattern> Prepare(ScanContext ctx)
    {
        var res = new List<RawPattern>();
        var jvm = JvmAnalyzer.FindJvm(ctx);
        if (jvm is null || !jvm.Pe.Valid) return res;

        var vm = VmStructs.Load(ctx.Target, jvm.Base, jvm.Pe);
        ctx.Vm = vm;
        if (vm.Vtables.Count == 0) return res;

        foreach (var (cls, max) in Tracked)
        {
            ulong vt = vm.Vtable(cls);
            if (vt == 0) continue;
            var rp = new RawPattern
            {
                Name = $"vtable {cls} @ 0x{vt:X}",
                Bytes = BitConverter.GetBytes(vt),
                MaxHits = max,
            };
            ctx.VtablePatterns.Add((cls, vt, rp));
            res.Add(rp);
        }
        return res;
    }

    public static void Run(ScanContext ctx, SweepResult sweep)
    {
        var jvm = JvmAnalyzer.FindJvm(ctx);
        if (jvm is null || !jvm.Pe.Valid) return;

        var vm = ctx.Vm ??= VmStructs.Load(ctx.Target, jvm.Base, jvm.Pe);
        ctx.Report.Section("РАСКЛАДКА СТРУКТУР HOTSPOT (живой VMStructs)", vm.Render());

        if (!vm.Valid)
        {
            ctx.Report.Report("JVM",
                "Таблицы VMStructs в jvm.dll не разобраны — разбор структур ВМ недоступен",
                Severity.Medium,
                "gHotSpotVMStructs — экспортируемая таблица, через которую HotSpot сообщает " +
                "раскладку своих внутренних структур; она есть в любой штатной сборке jvm.dll, " +
                "потому что на неё опирается Serviceability Agent. Её отсутствие или " +
                "непрочитываемость означает либо необычную сборку ВМ, либо намеренную порчу " +
                "этих данных, чтобы помешать разбору состояния виртуальной машины.")
                .Add("диагностика", string.Join("; ", vm.Diagnostics));
            return;
        }

        var idx = BuildIndex(ctx, vm);
        var sb = new StringBuilder();

        var graph = WalkClassLoaderDataGraph(ctx, vm, sb);
        ReportGraph(ctx, vm, graph, sweep, sb);
        ReportOrphans(ctx, vm, graph, idx, sb);
        ReportRedefinedMethods(ctx, vm, graph, sb);
        ReportBreakpoints(ctx, vm, graph, sb);
        ReportJvmtiObjects(ctx, vm, idx, sb);
        WalkJvmtiEnvironments(ctx, vm, jvm, sb);
        ReportJvmtiExportFlags(ctx, vm, sb);
        ReportJvmtiVmStructEntries(ctx, vm, sb);

        ctx.Report.Section("ЖИВОЙ SA: МЕТАПРОСТРАНСТВО, ЗАГРУЗЧИКИ, JVMTI", sb.ToString());
    }

    private sealed class VtIndex
    {
        public Dictionary<string, List<ulong>> ByClass = new(StringComparer.Ordinal);
        public bool FromSweep;
        public bool Truncated;
        public long BytesScanned;

        public List<ulong> Get(string cls) =>
            ByClass.TryGetValue(cls, out var l) ? l : new List<ulong>();

        public IEnumerable<ulong> AllKlasses =>
            KlassClasses.SelectMany(Get);
    }

    private static VtIndex BuildIndex(ScanContext ctx, VmStructs vm)
    {
        var idx = new VtIndex();

        if (ctx.VtablePatterns.Count > 0 &&
            ctx.VtablePatterns.Any(p => p.Pattern.TotalHits > 0))
        {
            idx.FromSweep = true;
            foreach (var (cls, _, pat) in ctx.VtablePatterns)
            {
                var list = new List<ulong>(pat.Hits.Count);
                foreach (var (addr, _) in pat.Hits)
                    if ((addr & 7) == 0) list.Add(addr);
                idx.ByClass[cls] = list;
                if (pat.TotalHits > pat.Hits.Count) idx.Truncated = true;
            }
            return idx;
        }

        var wanted = new Dictionary<ulong, string>();
        foreach (var (cls, _) in Tracked)
        {
            ulong vt = vm.Vtable(cls);
            if (vt != 0) wanted[vt] = cls;
            idx.ByClass[cls] = new List<ulong>();
        }
        if (wanted.Count == 0) return idx;

        foreach (var ch in MemoryScan.Chunks(ctx, MemoryScan.PrivateAnyData))
        {
            idx.BytesScanned += ch.Length;
            for (int i = 0; i + 8 <= ch.Length; i += 8)
            {
                ulong v = BitConverter.ToUInt64(ch.Data, i);
                if (v == 0 || !wanted.TryGetValue(v, out var cls)) continue;
                ulong at = ch.Base + (ulong)i;
                var list = idx.ByClass[cls];
                if (list.Count > 0 && list[^1] == at) continue;
                list.Add(at);
            }
        }
        return idx;
    }

    private sealed class KlassRec
    {
        public ulong Address;
        public ulong Cld;
        public string Name = "";
        public uint AccessFlags;
        public byte InitState;
        public ulong Methods;
        public ulong Constants;
        public ulong Breakpoints;
    }

    private sealed class CldRec
    {
        public ulong LoaderOop;
        public ulong Address;
        public string LoaderClass = "";
        public bool HasClassMirrorHolder;
        public List<KlassRec> Klasses = new();
    }

    private sealed class Graph
    {
        public List<CldRec> Clds = new();
        public Dictionary<ulong, KlassRec> Klasses = new();
        public HashSet<ulong> Methods = new();
        public HashSet<ulong> ConstantPools = new();
        public bool Walked;
        public string Problem = "";
        public PageCache Cache = null!;
    }

    private static Graph WalkClassLoaderDataGraph(ScanContext ctx, VmStructs vm, StringBuilder sb)
    {
        var g = new Graph { Cache = new PageCache(ctx.Target, 65536) };
        var c = g.Cache;

        ulong headVar = vm.StaticAddr("ClassLoaderDataGraph", "_head");
        int offNext = vm.Off("ClassLoaderData", "_next");
        int offKlasses = vm.Off("ClassLoaderData", "_klasses");
        int offLoader = vm.Off("ClassLoaderData", "_class_loader");
        int offMirrorHolder = vm.OffAny("ClassLoaderData",
            "_has_class_mirror_holder", "_is_unsafe_anonymous");
        int offNextLink = vm.Off("Klass", "_next_link");
        int offName = vm.Off("Klass", "_name");
        int offCld = vm.Off("Klass", "_class_loader_data");
        int offAcc = vm.Off("Klass", "_access_flags");

        sb.AppendLine("ОБХОД ГРАФА ЗАГРУЗЧИКОВ ПО СТРУКТУРАМ ВМ");
        sb.AppendLine($"  ClassLoaderDataGraph::_head : 0x{headVar:X}");
        sb.AppendLine($"  ClassLoaderData::_next      : +0x{offNext:X}   _klasses: +0x{offKlasses:X}");
        sb.AppendLine($"  Klass::_next_link           : +0x{offNextLink:X}   _name: +0x{offName:X}   " +
                      $"_class_loader_data: +0x{offCld:X}");

        if (headVar == 0 || offNext < 0 || offKlasses < 0 || offNextLink < 0 || offName < 0)
        {
            g.Problem = "в VMStructs нет полей, нужных для обхода графа загрузчиков";
            sb.AppendLine("  " + g.Problem);
            sb.AppendLine();
            return g;
        }

        int offIkMethods = vm.Off("InstanceKlass", "_methods");
        int offIkConst = vm.Off("InstanceKlass", "_constants");
        int offIkInit = vm.Off("InstanceKlass", "_init_state");
        int offIkBp = vm.Off("InstanceKlass", "_breakpoints");

        ulong cld = c.U64(headVar);
        int guard = 0;
        var seenCld = new HashSet<ulong>();

        while (cld is >= 0x10000 and <= 0x7FFFFFFFFFFF && guard++ < 100_000)
        {
            if (!seenCld.Add(cld)) break;
            var rec = new CldRec { Address = cld };

            if (offLoader >= 0)
            {
                ulong handle = c.U64(cld + (ulong)offLoader);
                ulong oop = handle == 0 ? 0 : c.U64(handle);
                rec.LoaderOop = oop;
                rec.LoaderClass = oop == 0
                    ? "<загрузчик начальной загрузки>"
                    : NameOfOopKlass(c, vm, oop) ?? "<не определён>";
            }
            if (offMirrorHolder >= 0)
                rec.HasClassMirrorHolder = ctx.Target.ReadU8(cld + (ulong)offMirrorHolder) != 0;

            ulong k = c.U64(cld + (ulong)offKlasses);
            int kguard = 0;
            while (k is >= 0x10000 and <= 0x7FFFFFFFFFFF && kguard++ < 200_000)
            {
                if (g.Klasses.ContainsKey(k)) break;

                var kr = new KlassRec
                {
                    Address = k,
                    Cld = offCld >= 0 ? c.U64(k + (ulong)offCld) : cld,
                    Name = ReadSymbol(c, vm, c.U64(k + (ulong)offName)) ?? "",
                    AccessFlags = offAcc >= 0 ? c.U32(k + (ulong)offAcc) : 0,
                };
                if (offIkMethods >= 0) kr.Methods = c.U64(k + (ulong)offIkMethods);
                if (offIkConst >= 0) kr.Constants = c.U64(k + (ulong)offIkConst);
                if (offIkInit >= 0) kr.InitState = (byte)(c.U32(k + (ulong)offIkInit) & 0xFF);
                if (offIkBp >= 0) kr.Breakpoints = c.U64(k + (ulong)offIkBp);

                g.Klasses[k] = kr;
                rec.Klasses.Add(kr);
                k = c.U64(k + (ulong)offNextLink);
            }

            g.Clds.Add(rec);
            cld = c.U64(cld + (ulong)offNext);
        }

        foreach (var kr in g.Klasses.Values)
        {
            if (kr.Constants is >= 0x10000 and <= 0x7FFFFFFFFFFF)
                g.ConstantPools.Add(kr.Constants);
            foreach (ulong m in ReadMetaArray(c, kr.Methods, 200_000))
                g.Methods.Add(m);
        }

        g.Walked = g.Clds.Count > 0;
        foreach (var kv in g.Klasses) ctx.LiveKlasses[kv.Key] = kv.Value.Name;
        foreach (var m in g.Methods) ctx.LiveMethods.Add(m);
        foreach (var rec in g.Clds)
        {
            ctx.ClassLoaderDatas.Add(rec.Address);
        }

        sb.AppendLine($"  загрузчиков (ClassLoaderData): {g.Clds.Count}");
        sb.AppendLine($"  классов в графе              : {g.Klasses.Count}");
        sb.AppendLine($"  методов у этих классов       : {g.Methods.Count}");
        sb.AppendLine();
        return g;
    }

    private static IEnumerable<ulong> ReadMetaArray(PageCache c, ulong array, int cap)
    {
        if (array is < 0x10000 or > 0x7FFFFFFFFFFF) yield break;
        int len = (int)c.U32(array);
        if (len is <= 0 or > 200_000) yield break;
        for (int i = 0; i < len && i < cap; i++)
        {
            ulong v = c.U64(array + 8 + (ulong)i * 8);
            if (v is >= 0x10000 and <= 0x7FFFFFFFFFFF) yield return v;
        }
    }

    private static string? ReadSymbol(PageCache c, VmStructs vm, ulong sym)
    {
        if (sym is < 0x10000 or > 0x7FFFFFFFFFFF) return null;
        int offLen = vm.Off("Symbol", "_length");
        int offBody = vm.OffAny("Symbol", "_body[0]", "_body");
        if (offLen < 0) offLen = 4;
        if (offBody < 0) offBody = 6;

        Span<byte> head = stackalloc byte[8];
        if (!c.Read(sym, head)) return null;
        int len = BitConverter.ToUInt16(head[offLen..]);
        if (len is < 1 or > 512) return null;
        var body = new byte[len];
        if (!c.Read(sym + (ulong)offBody, body)) return null;
        return JavaNames.DecodeModifiedUtf8(body);
    }

    private static ulong KlassOfOop(PageCache c, VmStructs vm, ulong oop)
    {
        int off = vm.OffAny("oopDesc", "_metadata._compressed_klass", "_metadata._klass");
        if (off < 0) off = 8;
        var f = vm.Field("oopDesc", "_metadata._compressed_klass");
        if (f is null)
            return c.U64(oop + (ulong)off);

        ulong baseAddr = 0;
        int shift = 0;
        ulong bv = vm.StaticAddrAny(("CompressedKlassPointers", "_narrow_klass._base"),
            ("Universe", "_narrow_klass._base"));
        ulong sv = vm.StaticAddrAny(("CompressedKlassPointers", "_narrow_klass._shift"),
            ("Universe", "_narrow_klass._shift"));
        if (bv != 0) baseAddr = c.U64(bv);
        if (sv != 0) shift = (int)c.U32(sv);

        uint narrow = c.U32(oop + (ulong)off);
        if (narrow == 0) return 0;
        return baseAddr + ((ulong)narrow << shift);
    }

    private static string? NameOfOopKlass(PageCache c, VmStructs vm, ulong oop)
    {
        ulong k = KlassOfOop(c, vm, oop);
        if (k is < 0x10000 or > 0x7FFFFFFFFFFF) return null;
        int offName = vm.Off("Klass", "_name");
        return offName < 0 ? null : ReadSymbol(c, vm, c.U64(k + (ulong)offName));
    }

    private static void ReportGraph(ScanContext ctx, VmStructs vm, Graph g,
        SweepResult sweep, StringBuilder sb)
    {
        if (!g.Walked)
        {
            ctx.Report.Report("JVM",
                "Граф загрузчиков классов по структурам ВМ не обойдён",
                Severity.Low,
                "Раскладка структур получена, но пройти ClassLoaderDataGraph не удалось. " +
                "Остальные проверки классов (по байт-коду в памяти и по архивам) работают " +
                "независимо.")
                .Add("причина", g.Problem.Length > 0 ? g.Problem : "цепочка загрузчиков пуста");
            return;
        }

        sb.AppendLine("ЗАГРУЗЧИКИ (по ClassLoaderDataGraph):");
        sb.AppendLine($"{"АДРЕС CLD",-18} {"КЛАССОВ",-9} {"HIDDEN",-7} КЛАСС ЗАГРУЗЧИКА");
        sb.AppendLine(new string('-', 120));
        var shown = g.Clds.OrderByDescending(x => x.Klasses.Count).Take(80).ToList();
        foreach (var cld in shown)
            sb.AppendLine($"0x{cld.Address:X16} {cld.Klasses.Count,-9} " +
                          $"{(cld.HasClassMirrorHolder ? "да" : "-"),-7} {cld.LoaderClass}");
        if (g.Clds.Count > shown.Count)
            sb.AppendLine($"  ... и ещё {g.Clds.Count - shown.Count} загрузчиков с одним-двумя " +
                          "классами (скрытые классы: лямбды, дескрипторы методов)");
        sb.AppendLine();

        var f = ctx.Report.Report("JVM",
            $"Граф загрузчиков ВМ обойдён по структурам: {g.Clds.Count} загрузчиков, " +
            $"{g.Klasses.Count} классов, {g.Methods.Count} методов",
            Severity.Info,
            "Это перечисление сделано по внутренним спискам самой виртуальной машины " +
            "(ClassLoaderDataGraph → ClassLoaderData → Klass::_next_link), а не поиском " +
            "байт-кода в памяти. Список авторитетный: в нём ровно то, что JVM считает " +
            "загруженным прямо сейчас. Сравнение этого списка с байт-кодом, найденным " +
            "в памяти, показывает классы, которые определялись, но в графе их нет.");
        foreach (var cld in g.Clds.OrderByDescending(x => x.Klasses.Count).Take(48))
            f.Add($"CLD 0x{cld.Address:X}",
                $"{cld.Klasses.Count} классов, загрузчик {cld.LoaderClass}" +
                (cld.HasClassMirrorHolder ? ", изолированный (hidden class)" : ""));

        var hidden = g.Clds.Where(x => x.HasClassMirrorHolder).ToList();
        sb.AppendLine($"Загрузчиков скрытых классов (has_class_mirror_holder): {hidden.Count}");
        var hiddenNames = hidden.SelectMany(h => h.Klasses).Select(k => k.Name)
            .Where(n => n.Length > 0).ToList();
        foreach (var n in hiddenNames.Take(80)) sb.AppendLine("    " + n);
        sb.AppendLine();

        if (sweep.Classes.Count > 0)
        {
            var live = new HashSet<string>(g.Klasses.Values.Select(k => k.Name.Replace('.', '/')),
                StringComparer.Ordinal);
            var ghosts = sweep.Classes.Values
                .Where(x => x.Name.Length > 0 && !live.Contains(x.Name))
                .ToList();

            sb.AppendLine($"Классов найдено байт-кодом в памяти: {sweep.Classes.Count}");
            sb.AppendLine($"Из них отсутствуют в живом графе ВМ: {ghosts.Count}");
            foreach (var x in ghosts.Take(120))
                sb.AppendLine($"    0x{x.Address:X}  {x.Name}" +
                              (x.Occurrences > 1 ? $"  (копий: {x.Occurrences})" : ""));
            sb.AppendLine();

            if (ghosts.Count > 0)
            {
                var f2 = ctx.Report.Report("JVM",
                    $"{ghosts.Count} классов присутствуют в памяти байт-кодом, но " +
                    "отсутствуют в живом графе загрузчиков ВМ",
                    Severity.Info,
                    "Байт-код класса попадает в память при его определении и остаётся там, " +
                    "пока буфер не переиспользуют. Класс, чей байт-код в памяти есть, а в " +
                    "ClassLoaderDataGraph его нет, — это класс, который определялся и был " +
                    "выгружен (или определялся как скрытый). Штатно так выглядят лямбды, " +
                    "генерируемые прокси и результат работы Mixin. Так же выглядит и класс " +
                    "чита, снятый после «анхука»: смотрите на имена и сверяйте их с " +
                    "разделом о происхождении классов.");
                foreach (var x in ghosts.Take(60))
                    f2.Add(x.Name, $"0x{x.Address:X}, версия class-файла {x.MajorVersion}" +
                                   (x.Occurrences > 1 ? $", копий в памяти: {x.Occurrences}" : ""));
            }
        }

    }

    private static void ReportOrphans(ScanContext ctx, VmStructs vm, Graph g, VtIndex idx,
        StringBuilder sb)
    {
        var c = g.Cache;
        int offName = vm.Off("Klass", "_name");
        int offCld = vm.Off("Klass", "_class_loader_data");

        var allKlassObjs = idx.AllKlasses.Distinct().ToList();
        foreach (ulong a in allKlassObjs)
        {
            if (ctx.AllKlassObjects.ContainsKey(a)) continue;
            ctx.AllKlassObjects[a] = g.Klasses.TryGetValue(a, out var kr)
                ? kr.Name
                : offName < 0 ? "" : ReadSymbol(c, vm, c.U64(a + (ulong)offName)) ?? "";
        }

        var orphanKlasses = g.Walked
            ? allKlassObjs.Where(a => !g.Klasses.ContainsKey(a)).ToList()
            : new List<ulong>();

        var allMethods = idx.Get("Method");
        var orphanMethods = g.Walked
            ? allMethods.Where(a => !g.Methods.Contains(a)).ToList()
            : new List<ulong>();

        var allPools = idx.Get("ConstantPool");
        var orphanPools = g.Walked
            ? allPools.Where(a => !g.ConstantPools.Contains(a)).ToList()
            : new List<ulong>();

        sb.AppendLine("ОБЪЕКТЫ МЕТАПРОСТРАНСТВА (опознание по точному адресу vtable):");
        sb.AppendLine($"  источник: {(idx.FromSweep ? "сплошной скан памяти" : "собственный проход")}" +
                      (idx.Truncated ? " (списки усечены по лимиту)" : ""));
        foreach (var (cls, _) in Tracked)
        {
            var list = idx.Get(cls);
            if (list.Count == 0) continue;
            sb.AppendLine($"  {cls,-36} {list.Count}");
        }
        sb.AppendLine();
        sb.AppendLine($"  Klass-объектов всего: {allKlassObjs.Count}, " +
                      $"из них вне графа загрузчиков: {orphanKlasses.Count}");
        sb.AppendLine($"  Method-объектов всего: {allMethods.Count}, " +
                      $"из них вне живых классов: {orphanMethods.Count}");
        sb.AppendLine($"  ConstantPool всего: {allPools.Count}, " +
                      $"из них вне живых классов: {orphanPools.Count}");
        sb.AppendLine();

        if (!g.Walked) return;

        var described = new List<(ulong Addr, string Name, ulong Cld, bool CldLive)>();
        var liveClds = g.Clds.Select(x => x.Address).ToHashSet();
        foreach (ulong a in orphanKlasses.Take(4000))
        {
            string name = offName < 0 ? "" : ReadSymbol(c, vm, c.U64(a + (ulong)offName)) ?? "";
            ulong cld = offCld < 0 ? 0 : c.U64(a + (ulong)offCld);
            described.Add((a, name, cld, liveClds.Contains(cld)));
        }

        foreach (var d in described.Take(200))
            sb.AppendLine($"    осиротевший Klass 0x{d.Addr:X}  «{Short(d.Name)}»  " +
                          $"CLD 0x{d.Cld:X} ({(d.CldLive ? "живой" : "НЕ в графе")})" +
                          (IsRuntimeNoise(d.Name) ? "  [штатный мусор ВМ]" : ""));
        if (described.Count > 0) sb.AppendLine();

        if (described.Count > 0)
        {
            var noisy = described.Where(x => IsRuntimeNoise(x.Name)).ToList();
            var hard = described.Where(x => !IsRuntimeNoise(x.Name)).ToList();

            var f = ctx.Report.Report("JVM",
                $"В метапространстве {orphanKlasses.Count} объектов Klass не достижимы из " +
                $"графа загрузчиков (генерируемых рантаймом: {noisy.Count}, " +
                $"с осмысленным именем: {hard.Count})",
                hard.Count > 0 ? Severity.High : Severity.Info,
                "Объект класса опознан по точному адресу таблицы виртуальных функций, " +
                "экспортируемой самой jvm.dll, — это не эвристика. Живая ВМ держит все свои " +
                "классы в списках ClassLoaderData; класс, до которого по этим спискам не " +
                "дойти, — это метаданные, оставшиеся после выгрузки загрузчика или после " +
                "переопределения класса (RedefineClasses/RetransformClasses). " +
                "ВАЖНО о трактовке: такие объекты есть и в чистой игре — это лямбды и " +
                "прочие скрытые классы, чью память метапространство ещё не переиспользовало " +
                "(проверено на чистом клиенте). Поэтому отдельно посчитаны классы с " +
                "осмысленным именем, не похожим на генерируемое рантаймом: вот они " +
                "объяснения требуют, потому что классы чита после «анхука» выглядят " +
                "именно так.");
            foreach (var d in hard.Take(60))
                f.Add(d.Name.Length > 0 ? Short(d.Name) : $"0x{d.Addr:X}",
                    $"объект 0x{d.Addr:X}, ClassLoaderData 0x{d.Cld:X} " +
                    $"({(d.CldLive ? "загрузчик жив" : "загрузчика нет в графе")})");
            if (hard.Count == 0)
                f.Block("Примеры (все опознаны как генерируемые рантаймом)",
                    string.Join("\n", noisy.Take(24).Select(x => "  " + Short(x.Name))));
        }

        if (orphanMethods.Count > 0)
        {
            var holders = ResolveMethodHolders(c, vm, orphanMethods.Take(2000));
            var interesting = holders.Where(x => !IsRuntimeMethodHolder(x.Value)).ToList();

            sb.AppendLine("Классы-владельцы осиротевших методов:");
            foreach (var kv in holders.GroupBy(x => x.Value).OrderByDescending(x => x.Count())
                         .Take(40))
                sb.AppendLine($"    {kv.Count(),6}  {Short(kv.Key)}");
            sb.AppendLine();

            var f = ctx.Report.Report("JVM",
                $"В метапространстве {orphanMethods.Count} объектов Method не принадлежат " +
                $"ни одному живому классу (с осмысленным классом-владельцем: {interesting.Count})",
                interesting.Count >= 8 ? Severity.Medium : Severity.Info,
                "Каждый живой класс хранит свои методы в массиве InstanceKlass::_methods. " +
                "Объект Method, которого нет ни в одном таком массиве, — это либо метод " +
                "выгруженного класса, либо СТАРАЯ ВЕРСИЯ метода, оставленная " +
                "RedefineClasses/RetransformClasses: при переопределении класса JVM не " +
                "удаляет прежние методы, пока на них могут ссылаться кадры стека и " +
                "скомпилированный код. Класс-владелец берётся по цепочке " +
                "Method → ConstMethod → ConstantPool → _pool_holder, поэтому видно, " +
                "код каких именно классов оставил после себя эти методы. Часть таких " +
                "объектов есть и в чистой игре (лямбды и скрытые классы), они посчитаны " +
                "отдельно.");
            f.Add("объектов Method всего", allMethods.Count.ToString());
            f.Add("вне живых классов", orphanMethods.Count.ToString());
            foreach (var g2 in interesting.GroupBy(x => x.Value)
                         .OrderByDescending(x => x.Count()).Take(40))
                f.Add(Short(g2.Key), $"{g2.Count()} осиротевших методов");
        }

        if (orphanPools.Count > 0)
        {
            ctx.Report.Report("JVM",
                    $"В метапространстве {orphanPools.Count} пулов констант не принадлежат " +
                    "ни одному живому классу",
                    Severity.Info,
                    "ConstantPool живого класса всегда достижим через InstanceKlass::_constants. " +
                    "Осиротевший пул остаётся после переопределения класса (у новой версии " +
                    "класса свой пул, старый живёт, пока на него ссылаются старые методы) " +
                    "и после выгрузки классов. В чистой игре такие пулы тоже есть — их " +
                    "оставляют лямбды и скрытые классы, поэтому смотреть надо не на само " +
                    "число, а на список классов-владельцев осиротевших методов выше.")
                .Add("пулов всего", allPools.Count.ToString())
                .Add("осиротевших", orphanPools.Count.ToString())
                .Block("Адреса (первые 64)",
                    string.Join("\n", orphanPools.Take(64).Select(a => $"  0x{a:X}")));
        }
    }

    internal static Dictionary<ulong, string> ResolveMethodHolders(PageCache c, VmStructs vm,
        IEnumerable<ulong> methods)
    {
        var res = new Dictionary<ulong, string>();
        int offConstMethod = vm.Off("Method", "_constMethod");
        int offConstants = vm.Off("ConstMethod", "_constants");
        int offHolder = vm.Off("ConstantPool", "_pool_holder");
        int offName = vm.Off("Klass", "_name");
        if (offConstMethod < 0 || offConstants < 0 || offHolder < 0 || offName < 0) return res;

        foreach (ulong m in methods)
        {
            ulong cm = c.U64(m + (ulong)offConstMethod);
            if (cm is < 0x10000 or > 0x7FFFFFFFFFFF) { res[m] = "<не определён>"; continue; }
            ulong cp = c.U64(cm + (ulong)offConstants);
            if (cp is < 0x10000 or > 0x7FFFFFFFFFFF) { res[m] = "<не определён>"; continue; }
            ulong k = c.U64(cp + (ulong)offHolder);
            if (k is < 0x10000 or > 0x7FFFFFFFFFFF) { res[m] = "<не определён>"; continue; }
            res[m] = ReadSymbol(c, vm, c.U64(k + (ulong)offName)) ?? "<не определён>";
        }
        return res;
    }

    private static bool IsRuntimeNoise(string name)
    {
        if (name.Length == 0) return true;
        if (name.Contains('?')) return true;
        if (JavaNames.LooksLikeFreedMemory(name)) return true;
        if (name.Contains("$$Lambda", StringComparison.Ordinal)) return true;
        if (name.Contains("/LambdaForm$", StringComparison.Ordinal)) return true;
        if (name.Contains("$$Proxy", StringComparison.Ordinal)) return true;
        if (name.StartsWith("jdk/proxy", StringComparison.Ordinal)) return true;
        if (name.StartsWith("com/sun/proxy/", StringComparison.Ordinal)) return true;
        if (name.Contains("$$InjectedInvoker", StringComparison.Ordinal)) return true;
        if (name.Contains("Lambda$", StringComparison.Ordinal)) return true;
        return false;
    }

    internal static bool IsRuntimeMethodHolder(string name) =>
        IsRuntimeNoise(name) ||
        name is "java/lang/invoke/MethodHandle" or "java/lang/invoke/VarHandle";

    private static string Short(string s) => s.Length <= 120 ? s : s[..117] + "...";

    private static readonly (uint Bit, string Name, string Why)[] MethodInternalFlags =
    {
        (0x00008000, "JVM_ACC_IS_DELETED",
            "метод удалён при переопределении класса через RedefineClasses"),
        (0x00010000, "JVM_ACC_IS_OLD",
            "метод заменён при переопределении класса — это его СТАРАЯ версия"),
        (0x00020000, "JVM_ACC_IS_OBSOLETE",
            "метод объявлен устаревшим после RedefineClasses"),
        (0x00040000, "JVM_ACC_IS_PREFIXED_NATIVE",
            "JVMTI переименовала нативный метод (SetNativeMethodPrefix) — приём агента " +
            "для перехвата нативных методов"),
        (0x00080000, "JVM_ACC_ON_STACK",
            "метод был на стеке в момент переопределения класса"),
    };

    private static void ReportRedefinedMethods(ScanContext ctx, VmStructs vm, Graph g,
        StringBuilder sb)
    {
        if (!g.Walked) return;
        int offAcc = vm.Off("Method", "_access_flags");
        int offConst = vm.Off("Method", "_constMethod");
        if (offAcc < 0) return;

        var c = g.Cache;
        var hits = new List<(ulong Addr, uint Flags, string Klass)>();
        var byKlass = new Dictionary<ulong, string>();
        foreach (var kr in g.Klasses.Values) byKlass[kr.Address] = kr.Name;

        foreach (var kr in g.Klasses.Values)
        {
            foreach (ulong m in ReadMetaArray(c, kr.Methods, 100_000))
            {
                uint fl = c.U32(m + (ulong)offAcc);
                uint internalBits = fl & 0x000F8000;
                if (internalBits == 0) continue;
                hits.Add((m, fl, kr.Name));
                if (hits.Count > 4000) break;
            }
            if (hits.Count > 4000) break;
        }

        sb.AppendLine("ФЛАГИ ПЕРЕОПРЕДЕЛЕНИЯ У ЖИВЫХ МЕТОДОВ:");
        sb.AppendLine($"  методов с внутренними флагами redefine/prefix: {hits.Count}");
        foreach (var h in hits.Take(120))
            sb.AppendLine($"    0x{h.Addr:X}  flags=0x{h.Flags:X8}  {DecodeMethodFlags(h.Flags)}  " +
                          $"в классе {h.Klass}");
        sb.AppendLine();

        if (hits.Count == 0) return;

        var f = ctx.Report.Report("JVM",
            $"{hits.Count} методов помечены внутренними флагами переопределения " +
            "(RedefineClasses / RetransformClasses / SetNativeMethodPrefix)",
            Severity.Critical,
            "AccessFlags метода содержит не только флаги из class-файла, но и служебные " +
            "биты самой ВМ. Биты IS_OLD, IS_OBSOLETE, IS_DELETED выставляются ТОЛЬКО " +
            "функциями RedefineClasses и RetransformClasses, а IS_PREFIXED_NATIVE — " +
            "функцией SetNativeMethodPrefix. Всё это — возможности JVMTI: обычный код на " +
            "Java до них не дотягивается, ни один штатный компонент Minecraft их не " +
            "использует. Флаги остаются на объектах метаданных навсегда, поэтому видны " +
            "и после того, как агент отработал и отключился.");
        foreach (var h in hits.Take(80))
            f.Add($"0x{h.Addr:X}", $"{DecodeMethodFlags(h.Flags)} — класс {h.Klass}");
        f.Add("объяснение флагов", string.Join("; ",
            MethodInternalFlags.Where(x => hits.Any(h => (h.Flags & x.Bit) != 0))
                .Select(x => $"{x.Name}: {x.Why}")));
        _ = offConst;
    }

    private static string DecodeMethodFlags(uint fl)
    {
        var parts = MethodInternalFlags.Where(x => (fl & x.Bit) != 0).Select(x => x.Name).ToList();
        return parts.Count == 0 ? "-" : string.Join("|", parts);
    }

    private static void ReportMethodBreakpointCounters(ScanContext ctx, VmStructs vm, Graph g,
        StringBuilder sb)
    {
        int offCounters = vm.Off("Method", "_method_counters");
        int offNum = vm.Off("MethodCounters", "_number_of_breakpoints");
        sb.AppendLine("СЧЁТЧИКИ ТОЧЕК ОСТАНОВА У МЕТОДОВ");
        if (offCounters < 0 || offNum < 0)
        {
            sb.AppendLine("  поля MethodCounters в этой сборке не описаны — проверка пропущена.");
            sb.AppendLine();
            return;
        }

        var c = g.Cache;
        var hits = new List<(string Klass, ulong Method, int Count)>();
        int withCounters = 0;

        foreach (var kr in g.Klasses.Values)
        {
            foreach (ulong m in ReadMetaArray(c, kr.Methods, 100_000))
            {
                ulong mc = c.U64(m + (ulong)offCounters);
                if (mc is < 0x10000 or > 0x7FFFFFFFFFFF) continue;
                withCounters++;
                int n = (int)(c.U32(mc + (ulong)offNum) & 0xFFFF);
                if (n is <= 0 or > 4096) continue;
                hits.Add((kr.Name, m, n));
                if (hits.Count > 512) break;
            }
            if (hits.Count > 512) break;
        }

        sb.AppendLine($"  методов со счётчиками   : {withCounters}");
        sb.AppendLine($"  с ненулевым счётчиком   : {hits.Count}");
        foreach (var h in hits.Take(64))
            sb.AppendLine($"      {h.Klass}  Method 0x{h.Method:X}  точек останова: {h.Count}");
        sb.AppendLine();
        if (hits.Count == 0) return;

        var f = ctx.Report.Report("JVM",
            $"У {hits.Count} методов ненулевой счётчик точек останова JVMTI",
            Severity.Critical,
            "Счётчик точек останова у метода увеличивает только функция JVMTI SetBreakpoint. " +
            "Ни код на Java, ни сама виртуальная машина трогать его не могут. Это вторая, " +
            "независимая от списка точек останова у класса запись о том же событии — и " +
            "она переживает уход агента надёжнее: список у класса при отключении " +
            "очищается, а счётчик у метода остаётся. Ненулевое значение означает, что " +
            "выполнение конкретных методов игры перехватывалось.");
        foreach (var h in hits.Take(48))
            f.Add(h.Klass, $"Method 0x{h.Method:X}, точек останова: {h.Count}");
    }

    private static void ReportBreakpoints(ScanContext ctx, VmStructs vm, Graph g, StringBuilder sb)
    {
        if (!g.Walked) return;
        ReportMethodBreakpointCounters(ctx, vm, g, sb);
        if (vm.Off("InstanceKlass", "_breakpoints") < 0)
        {
            sb.AppendLine("Поле InstanceKlass::_breakpoints в этой сборке не описано — " +
                          "проверка точек останова JVMTI не выполнялась.");
            sb.AppendLine();
            return;
        }

        var withBp = g.Klasses.Values.Where(k => k.Breakpoints is >= 0x10000 and <= 0x7FFFFFFFFFFF)
            .ToList();

        sb.AppendLine("ТОЧКИ ОСТАНОВА JVMTI:");
        sb.AppendLine($"  классов с непустым _breakpoints        : {withBp.Count}");
        foreach (var k in withBp.Take(64))
            sb.AppendLine($"    {k.Name}  (BreakpointInfo* = 0x{k.Breakpoints:X})");
        sb.AppendLine();

        if (withBp.Count == 0) return;

        var f = ctx.Report.Report("JVM",
            $"У {withBp.Count} классов установлены точки останова JVMTI " +
            "(InstanceKlass::_breakpoints не пуст)",
            Severity.Critical,
            "Список BreakpointInfo у класса заполняет только функция JVMTI SetBreakpoint. " +
            "Ни JVM сама, ни код на Java этого сделать не могут: это возможность агента, " +
            "требующая capability can_generate_breakpoint_events. Точка останова означает, " +
            "что кто-то перехватывал выполнение конкретного метода игры — типовой приём " +
            "для чтения и подмены значений в рантайме.");
        foreach (var k in withBp.Take(48))
            f.Add(k.Name.Length > 0 ? k.Name : $"0x{k.Address:X}",
                $"InstanceKlass 0x{k.Address:X}, BreakpointInfo* 0x{k.Breakpoints:X}");
    }

    private static readonly (string Cls, Severity Sev, string Why)[] JvmtiObjectClasses =
    {
        ("JvmtiAgentThread", Severity.Critical,
            "JvmtiAgentThread — объект потока, созданного функцией JVMTI RunAgentThread. " +
            "Такой поток заводит только агент; ни JVM, ни Minecraft его не создают. " +
            "Объект живёт в куче C++ и остаётся там после завершения потока."),
        ("JvmtiBreakpoint", Severity.Critical,
            "JvmtiBreakpoint — запись о точке останова. Такие объекты создаёт только " +
            "функция JVMTI SetBreakpoint, в том числе как временные на стеке потока. " +
            "И то и другое означает, что агент ставил точку останова на метод игры."),
        ("JvmtiVMObjectAllocEventCollector", Severity.Info,
            "Сборщик событий выделения объектов. ВАЖНО: HotSpot создаёт его как локальную " +
            "переменную в функциях JNI (jni_AllocObject и других) БЕЗУСЛОВНО, поэтому его " +
            "таблица виртуальных функций постоянно оказывается на стеках потоков и в " +
            "чистой игре. Проверено на чистом клиенте Minecraft — уликой не является, " +
            "приводится как справка."),
        ("JvmtiDynamicCodeEventCollector", Severity.Info,
            "Сборщик событий генерации кода. Создаётся как локальная переменная внутри " +
            "самой ВМ независимо от наличия агента — уликой не является."),
    };

    private static void ReportJvmtiObjects(ScanContext ctx, VmStructs vm, VtIndex idx,
        StringBuilder sb)
    {
        sb.AppendLine("ОБЪЕКТЫ ИНФРАСТРУКТУРЫ JVMTI (поиск по точному адресу vtable):");
        foreach (var (cls, sev, why) in JvmtiObjectClasses)
        {
            ulong vt = vm.Vtable(cls);
            var list = idx.Get(cls);
            sb.AppendLine($"  {cls,-38} vtable=0x{vt:X}  найдено: " +
                          (vt == 0 ? "vtable не экспортирована" : list.Count.ToString()) +
                          (sev == Severity.Info ? "  (в находки не выносится)" : ""));
            foreach (ulong a in list.Take(16))
                sb.AppendLine($"      0x{a:X}  {ctx.RegionAt(a)?.TypeString}/" +
                              $"{ctx.RegionAt(a)?.ProtectString}");
            if (vt == 0 || list.Count == 0 || sev == Severity.Info) continue;

            var f = ctx.Report.Report("JVM",
                $"В памяти найдено {list.Count} объектов {cls}", sev, why);
            f.Add("адрес таблицы виртуальных функций", vt);
            f.Add("объектов", list.Count.ToString());
            foreach (ulong a in list.Take(24))
                f.Add($"объект 0x{a:X}", ctx.RegionAt(a)?.ToString() ?? "-");
            var dump = ctx.Target.ReadBytes(list[0], 256);
            if (dump is not null) f.Block($"Первый объект 0x{list[0]:X}",
                HexDump.Format(dump, list[0]));
        }
        sb.AppendLine();
    }

    private sealed class EnvRec
    {
        public ulong Address;
        public ulong Functions;
        public uint Magic;
        public uint Version;
        public ulong Next;
        public bool Retransformable;
        public ulong TagMap;
        public ulong LocalStorage;
        public int CallbacksOffset = -1;
        public List<string> Subscriptions = new();
        public List<string> Capabilities = new();
        public List<string> Prohibited = new();
        public ulong[] EventEnable = Array.Empty<ulong>();
        public byte[]? Dump;

        public string MagicName => Magic switch
        {
            JVMTI_MAGIC => "0x71EE JVMTI_MAGIC (активно)",
            DISPOSED_MAGIC => "0xDEFC DISPOSED_MAGIC (ОТКЛЮЧЕНО)",
            BAD_MAGIC => "0xDEAD BAD_MAGIC (выведено из обращения)",
            _ => $"0x{Magic:X}",
        };
    }

    private static readonly string[] EventNames =
    {
        "VMInit", "VMDeath", "ThreadStart", "ThreadEnd", "ClassFileLoadHook",
        "ClassLoad", "ClassPrepare", "VMStart", "Exception", "ExceptionCatch",
        "SingleStep", "FramePop", "Breakpoint", "FieldAccess", "FieldModification",
        "MethodEntry", "MethodExit", "NativeMethodBind", "CompiledMethodLoad",
        "CompiledMethodUnload", "DynamicCodeGenerated", "DataDumpRequest", "reserved72",
        "MonitorWait", "MonitorWaited", "MonitorContendedEnter", "MonitorContendedEntered",
        "reserved77", "reserved78", "reserved79", "ResourceExhausted",
        "GarbageCollectionStart", "GarbageCollectionFinish", "ObjectFree", "VMObjectAlloc",
        "reserved85", "SampledObjectAlloc",
    };

    private static readonly string[] CapabilityNames =
    {
        "can_tag_objects", "can_generate_field_modification_events",
        "can_generate_field_access_events", "can_get_bytecodes",
        "can_get_synthetic_attribute", "can_get_owned_monitor_info",
        "can_get_current_contended_monitor", "can_get_monitor_info", "can_pop_frame",
        "can_redefine_classes", "can_signal_thread", "can_get_source_file_name",
        "can_get_line_numbers", "can_get_source_debug_extension",
        "can_access_local_variables", "can_maintain_original_method_order",
        "can_generate_single_step_events", "can_generate_exception_events",
        "can_generate_frame_pop_events", "can_generate_breakpoint_events", "can_suspend",
        "can_redefine_any_class", "can_get_current_thread_cpu_time",
        "can_get_thread_cpu_time", "can_generate_method_entry_events",
        "can_generate_method_exit_events", "can_generate_all_class_hook_events",
        "can_generate_compiled_method_load_events", "can_generate_monitor_events",
        "can_generate_vm_object_alloc_events", "can_generate_native_method_bind_events",
        "can_generate_garbage_collection_events", "can_generate_object_free_events",
        "can_force_early_return", "can_get_owned_monitor_stack_depth_info",
        "can_get_constant_pool", "can_set_native_method_prefix", "can_retransform_classes",
        "can_retransform_any_class", "can_generate_resource_exhaustion_heap_events",
        "can_generate_resource_exhaustion_threads_events", "can_generate_early_vmstart",
        "can_generate_early_class_hook_events", "can_generate_sampled_object_alloc_events",
        "can_support_virtual_threads",
    };

    private static readonly HashSet<string> DangerousCapabilities = new(StringComparer.Ordinal)
    {
        "can_redefine_classes", "can_redefine_any_class", "can_retransform_classes",
        "can_retransform_any_class", "can_generate_breakpoint_events",
        "can_generate_single_step_events", "can_generate_all_class_hook_events",
        "can_generate_early_class_hook_events", "can_set_native_method_prefix",
        "can_generate_native_method_bind_events", "can_pop_frame", "can_force_early_return",
        "can_access_local_variables", "can_suspend", "can_tag_objects",
        "can_generate_field_modification_events", "can_generate_field_access_events",
    };

    private static void WalkJvmtiEnvironments(ScanContext ctx, VmStructs vm, ImageInMemory jvm,
        StringBuilder sb)
    {
        var c = new PageCache(ctx.Target, 8192);
        var rdata = jvm.Pe.Sections
            .Where(s => !s.IsExecutable && s.VirtualSize > 0)
            .Select(s => (Lo: jvm.Base + s.VirtualAddress,
                          Hi: jvm.Base + s.VirtualAddress + s.VirtualSize))
            .ToList();
        bool InJvmData(ulong v) => rdata.Any(x => v >= x.Lo && v < x.Hi);

        bool LooksLikeEnv(ulong a)
        {
            if (a is < 0x10000 or > 0x7FFFFFFFFFFF) return false;
            ulong fn = c.U64(a);
            if (!InJvmData(fn)) return false;
            uint magic = c.U32(a + 8);
            return magic is JVMTI_MAGIC or DISPOSED_MAGIC or BAD_MAGIC;
        }

        ulong head = 0, headVar = 0;
        foreach (var sec in jvm.Pe.Sections)
        {
            if (sec.IsExecutable || sec.VirtualSize is 0 or > 32 * 1024 * 1024) continue;
            if (sec.Name is not (".data" or ".rdata")) continue;
            var buf = new byte[sec.VirtualSize];
            ulong va = jvm.Base + sec.VirtualAddress;
            ctx.Target.ReadPartial(va, buf, out _);
            for (int i = 0; i + 8 <= buf.Length && head == 0; i += 8)
            {
                ulong v = BitConverter.ToUInt64(buf, i);
                if (!LooksLikeEnv(v)) continue;
                head = v;
                headVar = va + (ulong)i;
            }
            if (head != 0) break;
        }

        sb.AppendLine("СПИСОК ОКРУЖЕНИЙ JVMTI (JvmtiEnvBase::_head_environment):");
        if (head == 0)
        {
            sb.AppendLine("  голова списка не найдена — в данных jvm.dll нет указателя на объект " +
                          "окружения.");
            sb.AppendLine();

            FindDetachedEnvironments(ctx, c, jvm, InJvmData, new List<EnvRec>(), sb);

            if (ctx.JvmtiEnvs.Count == 0)
                ctx.Report.Report("JVM",
                    "Список окружений JVMTI пуст: ни одного объекта JvmtiEnvBase не найдено",
                    Severity.Info,
                    "HotSpot связывает все окружения агентов односвязным списком, голова " +
                    "которого — статическая переменная в данных jvm.dll. Указателя на объект " +
                    "окружения там нет, и сплошной просмотр памяти таких объектов тоже не " +
                    "нашёл: за время жизни процесса ни один агент к этой виртуальной машине " +
                    "не подключался. Это отрицательный результат, и он тоже важен для решения.");
            return;
        }

        sb.AppendLine($"  переменная-голова: 0x{headVar:X}  →  0x{head:X}");

        var envs = new List<EnvRec>();
        ulong p = head;
        var seen = new HashSet<ulong>();
        while (p is >= 0x10000 and <= 0x7FFFFFFFFFFF && envs.Count < 64 && seen.Add(p))
        {
            var e = ReadEnv(ctx, c, p);
            if (e is null) break;
            envs.Add(e);
            p = e.Next;
        }

        sb.AppendLine($"  окружений в списке: {envs.Count} " +
                      $"(активных: {envs.Count(x => x.Magic == JVMTI_MAGIC)}, " +
                      $"отключённых: {envs.Count(x => x.Magic == DISPOSED_MAGIC)}, " +
                      $"выведенных из обращения: {envs.Count(x => x.Magic == BAD_MAGIC)})");
        sb.AppendLine();

        FindDetachedEnvironments(ctx, c, jvm, InJvmData, envs, sb);

        foreach (var e in envs)
        {
            ctx.JvmtiEnvs.Add(e.Address);
            sb.AppendLine($"  jvmtiEnv 0x{e.Address:X}  {e.MagicName}  version=0x{e.Version:X}");
            sb.AppendLine($"    таблица функций : {ctx.Describe(e.Functions)}");
            sb.AppendLine($"    retransformable : {(e.Retransformable ? "ДА (значение по умолчанию)" : "нет — AddCapabilities вызывался")}");
            sb.AppendLine($"    JvmtiTagMap*    : 0x{e.TagMap:X}");
            sb.AppendLine($"    возможности     : {(e.Capabilities.Count == 0 ? "-" : string.Join(", ", e.Capabilities))}");
            sb.AppendLine($"    подписки        : {(e.Subscriptions.Count == 0 ? "-" : string.Join(", ", e.Subscriptions.Select(s => s.Split(' ')[0])))}");
            sb.AppendLine();

            ReportEnv(ctx, e);
        }

    }

    private static void FindDetachedEnvironments(ScanContext ctx, PageCache c, ImageInMemory jvm,
        Func<ulong, bool> inJvmData, List<EnvRec> known, StringBuilder sb)
    {
        var inList = known.Select(e => e.Address).ToHashSet();
        var found = new List<EnvRec>();

        foreach (var ch in MemoryScan.Chunks(ctx, MemoryScan.PrivateData, overlap: 0x20))
        {
            var buf = ch.Data;
            for (int i = 0; i + 0x20 <= ch.Length; i += 8)
            {
                ulong fn = BitConverter.ToUInt64(buf, i);
                if (!inJvmData(fn)) continue;
                uint magic = BitConverter.ToUInt32(buf, i + 8);
                if (magic is not (JVMTI_MAGIC or DISPOSED_MAGIC or BAD_MAGIC)) continue;

                ulong addr = ch.Base + (ulong)i;
                if (inList.Contains(addr)) continue;
                if (found.Any(x => x.Address == addr)) continue;
                var e = ReadEnv(ctx, c, addr);
                if (e is null) continue;
                found.Add(e);
                if (found.Count > 64) break;
            }
            if (found.Count > 64) break;
        }

        sb.AppendLine($"  просмотрено приватной памяти: " +
                      MemoryAnalyzer.Human(MemoryScan.TotalReadable(ctx, MemoryScan.PrivateData)) +
                      " (без ограничения по объёму)");
        sb.AppendLine($"  окружений вне списка ВМ (освобождённых): {found.Count}");
        foreach (var e in found)
            sb.AppendLine($"      0x{e.Address:X}  {e.MagicName}  " +
                          $"возможностей: {e.Capabilities.Count}, " +
                          $"подписок: {e.Subscriptions.Count}");
        sb.AppendLine();
        if (found.Count == 0) return;

        foreach (var e in found) { ctx.JvmtiEnvs.Add(e.Address); ReportEnv(ctx, e); }

        bool listEmpty = known.Count == 0;
        var f = ctx.Report.Report("JVM",
            $"Найдено {found.Count} объектов окружения JVMTI, которых НЕТ в списке " +
            "окружений виртуальной машины" +
            (listEmpty ? " (а сам список пуст)" : ""),
            Severity.Critical,
            "Виртуальная машина связывает все окружения агентов односвязным списком, " +
            "голова которого — статическая переменная в данных jvm.dll. Найденный объект " +
            "в этом списке не числится, но объектом окружения быть не перестаёт: его " +
            "опознают три независимых поля — указатель на таблицу функций " +
            "jvmtiInterface_1_ внутри jvm.dll, магическое число сразу за ним и номер " +
            "версии JVMTI. " +
            (listEmpty
                ? "Список при этом ПУСТ. Такого сочетания в исправной ВМ не бывает: " +
                  "окружение либо есть в списке, либо его нет вовсе. Объект, существующий " +
                  "мимо реестра, — это либо окружение, отвязанное от списка вручную, либо " +
                  "созданное в обход штатного пути. Ровно это даёт перехват конструктора " +
                  "JvmtiEnvBase: окружение создаётся, а в список не попадает, и любое " +
                  "перечисление агентов его не видит."
                : "Так выглядит и след DisposeEnvironment: окружение выведено из списка, " +
                  "а его память ещё не переиспользована."));
        foreach (var e in found)
            f.Add($"окружение 0x{e.Address:X}",
                $"{e.MagicName}, версия JVMTI 0x{e.Version:X}, " +
                $"_next = 0x{e.Next:X}, возможностей {e.Capabilities.Count}, " +
                $"подписок на события {e.Subscriptions.Count}, " +
                $"регион {ctx.RegionAt(e.Address)?.ToString() ?? "-"}");
        _ = jvm;
    }

    private static EnvRec? ReadEnv(ScanContext ctx, PageCache c, ulong addr)
    {
        var dump = ctx.Target.ReadBytes(addr, 0x400);
        if (dump is null) return null;

        var e = new EnvRec
        {
            Address = addr,
            Functions = BitConverter.ToUInt64(dump, 0),
            Magic = BitConverter.ToUInt32(dump, 8),
            Version = BitConverter.ToUInt32(dump, 12),
            Next = BitConverter.ToUInt64(dump, 0x10),
            Retransformable = dump[0x18] != 0,
            LocalStorage = BitConverter.ToUInt64(dump, 0x20),
            Dump = dump,
        };

        var layout = JvmtiEnvLayout.Probe(ctx, dump);
        e.CallbacksOffset = layout?.Callbacks ?? -1;

        if (layout is not null)
        {
            foreach (var (ev, target) in JvmtiEnvLayout.Callbacks(dump, layout))
                e.Subscriptions.Add($"{ev} → {ctx.Describe(target)}");

            e.TagMap = BitConverter.ToUInt64(dump, layout.TagMap);
            e.EventEnable = layout.Masks;
            e.Capabilities = DecodeCapabilities(dump, layout.Capabilities);
            e.Prohibited = DecodeCapabilities(dump, layout.Prohibited);
        }
        return e;
    }

    private static List<string> DecodeCapabilities(byte[] dump, int off)
    {
        var res = new List<string>();
        ulong lo = BitConverter.ToUInt64(dump, off);
        ulong hi = BitConverter.ToUInt64(dump, off + 8);
        if (hi != 0) return res;
        for (int i = 0; i < CapabilityNames.Length; i++)
            if ((lo & (1UL << i)) != 0) res.Add(CapabilityNames[i]);
        return res;
    }

    private static void ReportEnv(ScanContext ctx, EnvRec e)
    {
        Severity sev = e.Magic switch
        {
            DISPOSED_MAGIC => Severity.Critical,
            JVMTI_MAGIC => Severity.Critical,
            BAD_MAGIC => Severity.Critical,
            _ => Severity.High,
        };

        string why = e.Magic == DISPOSED_MAGIC
            ? "Окружение найдено обходом СПИСКА окружений самой ВМ и помечено как " +
              "отключённое: агент был подключён к этой JVM и вызвал DisposeEnvironment. " +
              "Именно так выглядит «анхук» JVMTI-чита. Список окружений — внутренняя " +
              "структура HotSpot; агент не удаляет из неё свою запись, а только меняет " +
              "магическое число, поэтому запрошенные им возможности и подписки на события " +
              "остаются доступными для чтения."
            : e.Magic == JVMTI_MAGIC
                ? "Активное окружение JVMTI: к виртуальной машине прямо сейчас подключён " +
                  "агент. В клиенте Minecraft без агентов таких окружений нет ни одного."
                : e.Magic == BAD_MAGIC
                    ? "Окружение с меткой BAD_MAGIC. Это не «повреждение»: значение 0xDEAD " +
                      "пишет сама виртуальная машина, и код, который это делает, сначала " +
                      "проверяет JVMTI_MAGIC и лишь затем затирает его (проверено разбором " +
                      "jvm.dll — функция стоит рядом с конструктором окружения). То есть " +
                      "объект был настоящим действующим окружением JVMTI, и его вывели из " +
                      "обращения. Улика здесь — сам факт существования объекта: в клиенте " +
                      "без агентов их нет ни одного, в каком бы состоянии они ни были."
                    : "Окружение JVMTI с неизвестной меткой состояния.";

        var f = ctx.Report.Report("JVM",
            $"Окружение JVMTI 0x{e.Address:X} в списке окружений ВМ: {e.MagicName}", sev, why);
        f.Add("адрес объекта", e.Address);
        f.Add("таблица функций", $"0x{e.Functions:X} → {ctx.Describe(e.Functions)}");
        f.Add("версия JVMTI", $"0x{e.Version:X}");
        f.Add("_is_retransformable", JvmtiEnvLayout.DescribeRetransformable(e.Retransformable));
        f.Add("JvmtiTagMap*", e.TagMap == 0 ? "не создавалась" : $"0x{e.TagMap:X}");
        f.Add("_env_local_storage", e.LocalStorage == 0
            ? "пусто"
            : $"0x{e.LocalStorage:X} → {ctx.Describe(e.LocalStorage)} — агент сохранил " +
              "здесь указатель на свои данные (SetEnvironmentLocalStorage)");
        f.Add("смещение таблицы колбэков", e.CallbacksOffset >= 0
            ? $"+0x{e.CallbacksOffset:X}" : "не опознано");

        if (e.Capabilities.Count > 0)
        {
            f.Block("Запрошенные возможности (jvmtiCapabilities)",
                string.Join("\n", e.Capabilities.Select(x =>
                    (DangerousCapabilities.Contains(x) ? "  !! " : "     ") + x)));

            var danger = e.Capabilities.Where(DangerousCapabilities.Contains).ToList();
            if (danger.Count > 0)
            {
                ctx.Report.Report("JVM",
                        $"Окружение JVMTI 0x{e.Address:X} располагает возможностями, которые " +
                        $"позволяют менять код и состояние игры ({danger.Count} шт.)",
                        Severity.Critical,
                        "jvmtiCapabilities — набор возможностей, который агент ЯВНО запросил " +
                        "у виртуальной машины через AddCapabilities. Запросить их можно " +
                        "только будучи агентом, и запрошенное остаётся записанным в объекте " +
                        "окружения даже после отключения агента. По этому набору видно, что " +
                        "именно агент собирался делать: переопределять классы, " +
                        "останавливаться на методах, читать и менять локальные переменные, " +
                        "подменять привязку нативных методов.")
                    .Add("объект окружения", e.Address)
                    .Add("состояние", e.MagicName)
                    .Block("Опасные возможности", string.Join("\n", danger.Select(x => "  " + x)))
                    .Block("Все запрошенные возможности",
                        string.Join("\n", e.Capabilities.Select(x => "  " + x)));
            }
        }

        if (e.Subscriptions.Count > 0)
        {
            f.Block("Подписки на события (позиция указателя = событие)",
                string.Join("\n", e.Subscriptions.Select(x => "  " + x)));

            if (e.Subscriptions.Any(s => s.StartsWith("ClassFileLoadHook", StringComparison.Ordinal)))
                ctx.Report.Report("JVM",
                        $"Окружение JVMTI 0x{e.Address:X} подписано на ClassFileLoadHook",
                        Severity.Critical,
                        "ClassFileLoadHook отдаёт агенту байт-код каждого загружаемого класса " +
                        "и принимает изменённый. Это основной механизм подмены кода игры.")
                    .Add("состояние окружения", e.MagicName)
                    .Block("Подписки", string.Join("\n", e.Subscriptions.Select(x => "  " + x)));
        }

        if (e.EventEnable.Length == 3)
        {
            f.Block("Битовые маски включения событий (user / callback / enabled)",
                $"  _event_user_enabled     = 0x{e.EventEnable[0]:X16}  {Bits(e.EventEnable[0])}\n" +
                $"  _event_callback_enabled = 0x{e.EventEnable[1]:X16}  {Bits(e.EventEnable[1])}\n" +
                $"  _event_enabled          = 0x{e.EventEnable[2]:X16}  {Bits(e.EventEnable[2])}");
        }

        if (e.TagMap is >= 0x10000 and <= 0x7FFFFFFFFFFF)
            ctx.Report.Report("JVM",
                    $"У окружения JVMTI 0x{e.Address:X} создана таблица тегов объектов " +
                    $"(JvmtiTagMap 0x{e.TagMap:X})",
                    Severity.Critical,
                    "JvmtiTagMap создаётся при первом же вызове SetTag / GetObjectsWithTags / " +
                    "IterateOverHeap. Это означает, что агент помечал и перебирал объекты " +
                    "в куче Java — так чит ищет объекты игрока, мира и сущностей, чтобы " +
                    "получить к ним доступ напрямую.")
                .Add("окружение", e.Address)
                .Add("JvmtiTagMap*", e.TagMap);

        if (e.Dump is not null)
            f.Block("Объект окружения (0x400 байт)", HexDump.Format(e.Dump, e.Address));

        if (ctx.Dumper is not null)
        {
            ulong from = e.Address > 0x1000 ? e.Address - 0x1000 : e.Address;
            string? path = ctx.Dumper.DumpRange(from, 0x4000, "jvmtienv-sa",
                $"объект окружения JVMTI из списка ВМ ({e.MagicName})",
                $"сам объект по 0x{e.Address:X}");
            if (path is not null) f.Add("дамп окрестности", path);
        }
    }

    private static string Bits(ulong v)
    {
        if (v == 0) return "(нет включённых событий)";
        var names = new List<string>();
        for (int i = 0; i < EventNames.Length; i++)
            if ((v & (1UL << i)) != 0) names.Add(EventNames[i]);
        return names.Count == 0 ? "(биты вне известного диапазона)" : string.Join(",", names);
    }

    private static readonly (string Field, string Why)[] ExportFlags =
    {
        ("_can_hotswap_or_post_breakpoint",
            "включается, когда какой-либо агент запросил can_redefine_classes, " +
            "can_retransform_classes или can_generate_breakpoint_events. Пока флаг взведён, " +
            "виртуальная машина ведёт полный учёт зависимостей скомпилированного кода и " +
            "не применяет часть оптимизаций — то есть работа агента отражается на самой ВМ."),
        ("_can_access_local_variables",
            "включается при запросе can_access_local_variables: агент собирался читать и " +
            "менять локальные переменные в кадрах стека игры."),
        ("_can_post_on_exceptions",
            "включается при подписке на события исключений."),
        ("_can_walk_any_space",
            "включается при возможности обхода произвольных областей кучи."),
    };

    private static void ReportJvmtiExportFlags(ScanContext ctx, VmStructs vm, StringBuilder sb)
    {
        sb.AppendLine("СТАТИЧЕСКИЕ ФЛАГИ JvmtiExport (адреса из VMStructs):");
        var on = new List<(string Name, ulong Addr, string Why)>();
        bool any = false;

        foreach (var (field, why) in ExportFlags)
        {
            ulong a = vm.StaticAddr("JvmtiExport", field);
            if (a == 0) { sb.AppendLine($"  {field,-40} не описан в этой сборке"); continue; }
            any = true;
            byte val = ctx.Target.ReadU8(a);
            sb.AppendLine($"  {field,-40} 0x{a:X}  = {val}");
            if (val != 0) on.Add((field, a, why));
        }
        sb.AppendLine();
        if (!any) return;

        if (on.Count == 0)
        {
            ctx.Report.Report("JVM",
                "Статические флаги JvmtiExport выключены — возможности агента у ВМ " +
                "сейчас не запрошены",
                Severity.Info,
                "JvmtiExport хранит объединение возможностей, запрошенных всеми " +
                "окружениями агентов. Все проверенные флаги нулевые: на момент проверки " +
                "ни одно окружение не держит права на переопределение классов, точки " +
                "останова и доступ к локальным переменным. Отрицательный результат " +
                "фиксируется явно, потому что он нужен для решения.")
                .Add("проверено флагов", ExportFlags.Length.ToString());
            return;
        }

        var f = ctx.Report.Report("JVM",
            $"У виртуальной машины взведены статические флаги JvmtiExport ({on.Count} шт.): " +
            string.Join(", ", on.Select(x => x.Name)),
            Severity.Critical,
            "Это глобальные переменные внутри jvm.dll, адреса которых виртуальная машина " +
            "сообщает сама через таблицу VMStructs. Их выставляет только механизм JVMTI, " +
            "когда агент запрашивает соответствующие возможности. Взведённый флаг означает, " +
            "что возможности агента у этой ВМ действительно запрашивались; в чистом клиенте " +
            "Minecraft все они нулевые.");
        foreach (var (name, addr, why) in on) f.Add($"{name} (0x{addr:X})", why);
    }

    private static void ReportJvmtiVmStructEntries(ScanContext ctx, VmStructs vm, StringBuilder sb)
    {
        var hits = vm.AllFields
            .Where(x => x.TypeName.Contains("Jvmti", StringComparison.OrdinalIgnoreCase) ||
                        x.FieldName.Contains("jvmti", StringComparison.OrdinalIgnoreCase) ||
                        x.TypeString.Contains("Jvmti", StringComparison.OrdinalIgnoreCase))
            .ToList();
        var types = vm.Types.Values
            .Where(x => x.TypeName.Contains("Jvmti", StringComparison.OrdinalIgnoreCase))
            .ToList();

        sb.AppendLine("ЗАПИСИ VMStructs, ОТНОСЯЩИЕСЯ К JVMTI:");
        sb.AppendLine($"  полей: {hits.Count}, типов: {types.Count}");
        foreach (var x in hits) sb.AppendLine("    " + x);
        foreach (var x in types) sb.AppendLine("    тип " + x);
        sb.AppendLine();
    }
}
