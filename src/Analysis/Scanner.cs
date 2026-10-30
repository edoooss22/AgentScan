using System.Diagnostics;
using System.Text;
using AgentScan.Core;
using AgentScan.Report;

namespace AgentScan.Analysis;

internal static class Scanner
{
    public static ScanReport Run(int pid, Options opt)
    {
        var rep = new ScanReport();
        _opt = opt;
        _skipped.Clear();
        _done = _current = 0;
        CancelRequested = false;
        using var target = ProcessTarget.Open(pid);

        var ctx = new ScanContext { Target = target, Options = opt, Report = rep };
        if (opt.DumpSuspicious && opt.DumpDir is not null)
            ctx.Dumper = new RegionDumper(target, opt.DumpDir, opt.MaxDumpBytes);

        Step("Информация о процессе", () => ProcessInfoAnalyzer.Run(ctx), rep);
        Step("Карта памяти", () => { ctx.Regions = MemoryMap.Enumerate(target); }, rep);
        Step("Списки загрузчика", () =>
        {
            ctx.Loader = LoaderModules.Enumerate(target);
            foreach (var e in ctx.Loader.Errors) rep.Errors.Add("Загрузчик: " + e);
        }, rep);
        Quiet("Модули (служебно)", () => ModuleAnalyzer.Run(ctx), rep);
        Quiet("Потоки (служебно)", () => ThreadAnalyzer.Run(ctx), rep);

        List<VmTable> tables = new();
        Step("Таблицы JNI/JVMTI", () =>
        {
            tables = JvmAnalyzer.FindVmTables(ctx);
            ctx.VmTables = tables;
        }, rep);

        var raw = new List<RawPattern>();
        Step("Раскладка структур HotSpot (живой VMStructs)",
            () => raw.AddRange(SaLiveAnalyzer.Prepare(ctx)), rep);
        Step("Журналы событий ВМ: подготовка поиска",
            () => raw.AddRange(VmEventLogAnalyzer.Prepare(ctx)), rep);

        foreach (var tbl in tables)
        {
            var rp = new RawPattern
            {
                Name = $"{tbl.Kind} @ 0x{tbl.Address:X}",
                Bytes = BitConverter.GetBytes(tbl.Address),
                MaxHits = 512,
            };
            tbl.RefPattern = rp;
            raw.Add(rp);
        }

        var sweep = new SweepResult();
        if (opt.FullStringScan)
        {
            Step("Сплошной скан памяти", () =>
            {
                var sigs = Signatures.Load(null);
                sweep = MemorySweep.Run(ctx, sigs, raw, Progress);
                Console.Error.Write("\r".PadRight(60) + "\r");
            }, rep);
        }
        Step("Индекс архивов игры", () => ctx.Jars = AgentInfra.BuildJarIndex(ctx, sweep), rep);

        Step("Сигнатуры агентов и JVMTI в памяти",
            () => AgentInfra.ReportSweep(ctx, sweep), rep);
        Step("JVM / JVMTI: командная строка, модули агентов, потоки, таблицы",
            () => JvmAnalyzer.Run(ctx, sweep, tables), rep);
        Step("JVM: таблица JavaVM и переопределённые классы",
            () => JvmExtraAnalyzer.Run(ctx, sweep), rep);
        Step("JVM: остаточное состояние агентов",
            () => JvmResidualAnalyzer.Run(ctx, tables, sweep), rep);
        Step("Чёрный ящик HotSpot: журналы событий виртуальной машины",
            () => VmEventLogAnalyzer.Run(ctx, sweep), rep);
        Step("Живой SA: метапространство, загрузчики, JVMTI",
            () => SaLiveAnalyzer.Run(ctx, sweep), rep);
        Step("Раскладка полей классов Java (чтение объектов по именам полей)",
            () => ctx.Java = JavaMeta.Create(ctx), rep);
        Step("Почерк имён игры (служебно)", () => AgentInfra.DetectRemap(ctx, sweep), rep);
        Step("Флаги виртуальной машины: значения и происхождение",
            () => VmFlagsAnalyzer.Run(ctx), rep);
        Step("Точки подключения: списки агентов HotSpot и механизм attach",
            () => JvmtiAgentListForensicsAnalyzer.Run(ctx), rep);
        Step("Происхождение агента JVMTI (восстановление по остаткам)",
            () => JvmtiAgentProvenanceAnalyzer.Run(ctx), rep);
        Step("Окружения JVMTI по магическому числу (независимый поиск)",
            () => JvmtiMagicScanAnalyzer.Run(ctx), rep);
        Quiet("Кодовый кеш: структурный обход (служебно)",
            () => CodeCacheWalkAnalyzer.Run(ctx), rep);
        Step("Куча Java: указатель по объектам", () =>
        {
            var idx = JavaHeapIndex.Get(ctx);
            if (idx is not null && idx.Diagnostics.Count > 0)
                rep.Errors.Add("Куча Java: " + string.Join("; ", idx.Diagnostics));
        }, rep);
        Step("Операции в точках безопасности",
            () => SafepointProfileAnalyzer.Run(ctx), rep);
        Step("Механизм агентов Java: Instrumentation и преобразователи классов",
            () => AgentInstrumentationAnalyzer.Run(ctx), rep);
        Step("Классы в привилегированных загрузчиках",
            () => BootLoaderIntrusionAnalyzer.Run(ctx), rep);
        Step("Среда исполнения Java: свойства, открытые пакеты, нативные библиотеки",
            () => JavaRuntimeStateAnalyzer.Run(ctx), rep);
        Step("Счётчики производительности ВМ (hsperfdata)",
            () => PerfDataAnalyzer.Run(ctx), rep);
        Step("Счётчики подмен в зеркалах классов (служебно)",
            () => AgentInfra.CollectMirrorCounters(ctx), rep);
        Step("Последствия переопределения классов: сведение источников",
            () => RedefinitionResidualGraphAnalyzer.Run(ctx), rep);

        if (_skipped.Count > 0)
        {
            rep.AddMeta("ПРОГОН НЕПОЛНЫЙ",
                $"пропущено отбором шагов: {_skipped.Count} (--only/--skip) — " +
                "сравнивать с полными прогонами нельзя");
            var sb = new StringBuilder();
            sb.AppendLine("ПРОГОН ВЫПОЛНЕН С ОТБОРОМ ШАГОВ — ОТЧЁТ НЕПОЛНЫЙ");
            sb.AppendLine();
            if (opt.OnlySteps.Count > 0)
                sb.AppendLine("  --only: " + string.Join(", ", opt.OnlySteps));
            if (opt.SkipSteps.Count > 0)
                sb.AppendLine("  --skip: " + string.Join(", ", opt.SkipSteps));
            sb.AppendLine();
            foreach (string s in _skipped) sb.AppendLine("    · " + s);
            rep.Section("ОТБОР ШАГОВ: ЧТО НЕ ВЫПОЛНЯЛОСЬ", sb.ToString());
        }

        Report(TotalWeight, "Готово");
        return rep;
    }

    private static void Progress(string s)
    {
        Console.Error.Write($"\r  {s}   ");
        var m = System.Text.RegularExpressions.Regex.Match(s, @"(\d+)%");
        if (m.Success && int.TryParse(m.Groups[1].Value, out int pct))
            Report(_done + _current * Math.Clamp(pct, 0, 100) / 100.0, s);
    }

    public static event Action<double, string>? ProgressChanged;

    private const int StepCount = 31;

    private static readonly (string Prefix, double Weight)[] Weights =
    {
        ("Сплошной скан", 17), ("Живой SA", 12), ("Происхождение агента", 12),
        ("Индекс архивов", 9), ("Точки подключения", 9), ("Куча Java", 2.5),
        ("Модули", 1.5), ("Окружения JVMTI по магическому", 1.3), ("JVM: остаточное", 1),
    };
    private const double DefaultWeight = 0.2;
    private static readonly double TotalWeight =
        Weights.Sum(w => w.Weight) + (StepCount - Weights.Length) * DefaultWeight;
    private static double _done, _current;

    private static double WeightOf(string name)
    {
        foreach (var (p, w) in Weights)
            if (name.StartsWith(p, StringComparison.Ordinal)) return w;
        return DefaultWeight;
    }

    private static void Report(double doneWeight, string text) =>
        ProgressChanged?.Invoke(Math.Clamp(doneWeight / TotalWeight, 0, 1), text);

    private static Options? _opt;
    private static readonly List<string> _skipped = new();

    private static bool Selected(string name)
    {
        if (_opt is null) return true;
        foreach (string s in _opt.SkipSteps)
            if (name.Contains(s, StringComparison.OrdinalIgnoreCase)) return false;
        if (_opt.OnlySteps.Count == 0) return true;
        foreach (string s in _opt.OnlySteps)
            if (name.Contains(s, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    private static void Quiet(string name, Action a, ScanReport rep)
    {
        int findings = rep.Findings.Count, sections = rep.Sections.Count;
        Step(name, a, rep);
        if (rep.Findings.Count > findings)
            rep.Findings.RemoveRange(findings, rep.Findings.Count - findings);
        if (rep.Sections.Count > sections)
            rep.Sections.RemoveRange(sections, rep.Sections.Count - sections);
    }

    public static volatile bool CancelRequested;

    private static void Step(string name, Action a, ScanReport rep)
    {
        if (CancelRequested) throw new OperationCanceledException("Проверка прервана");

        if (!Selected(name))
        {
            _skipped.Add(name);
            return;
        }

        var sw = Stopwatch.StartNew();
        Console.Error.Write($"  [..] {name}");
        _current = WeightOf(name);
        Report(_done, name);
        try
        {
            a();
            Console.Error.WriteLine($"\r  [ok] {name} ({sw.ElapsedMilliseconds} мс)".PadRight(70));
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"\r  [!!] {name}: {ex.GetType().Name}: {ex.Message}".PadRight(70));
            rep.Errors.Add($"{name}: {ex}");
        }
        _done += _current;
        _current = 0;
    }
}
