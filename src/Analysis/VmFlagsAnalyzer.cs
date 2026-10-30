using System.Text;
using AgentScan.Core;
using AgentScan.Report;

namespace AgentScan.Analysis;

internal static class VmFlagsAnalyzer
{
    private static readonly string[] OriginNames =
    {
        "значение по умолчанию",
        "командная строка",
        "переменная окружения",
        "файл настроек",
        "интерфейс управления",
        "эргономика (подобрала ВМ)",
        "ПОДКЛЮЧЕНИЕ НА ХОДУ",
        "внутреннее присвоение",
        "ресурс образа JDK",
    };

    private const uint OriginMask = 0xF;
    private const uint OriginDefault = 0;
    private const uint OriginCommandLine = 1;
    private const uint OriginEnviron = 2;
    private const uint OriginConfigFile = 3;
    private const uint OriginManagement = 4;
    private const uint OriginErgonomic = 5;
    private const uint OriginAttachOnDemand = 6;

    private static readonly string[] Sensitive =
    {
        "EnableDynamicAgentLoading", "DisableAttachMechanism", "StartAttachListener",
        "AllowRedefinitionToAddDeleteMethods", "TraceRedefineClasses",
        "UnlockDiagnosticVMOptions", "UnlockExperimentalVMOptions",
        "PrintFlagsFinal", "HeapDumpOnOutOfMemoryError", "HeapDumpPath",
        "OnError", "OnOutOfMemoryError", "AbortVMOnException", "ErrorFile",
        "LogFile", "LogVMOutput", "DisplayVMOutput", "UseSharedSpaces",
        "SharedArchiveFile", "ExtendedDTraceProbes", "FlightRecorderOptions",
        "StartFlightRecording", "NativeMemoryTracking", "PerfDisableSharedMem",
        "UsePerfData", "CreateCoredumpOnCrash", "ShowMessageBoxOnError",
        "MaxJavaStackTraceDepth", "OmitStackTraceInFastThrow",
    };

    private sealed class FlagRec
    {
        public string Name = "";
        public int Type;
        public uint Raw;
        public ulong ValueAddr;
        public string Value = "";
        public uint Origin => Raw & OriginMask;
        public bool WasSetOnCommandLine => (Raw & (1u << 17)) != 0;
    }

    public static void Run(ScanContext ctx)
    {
        var vm = ctx.Vm;
        var sb = new StringBuilder();
        sb.AppendLine("ФЛАГИ ВИРТУАЛЬНОЙ МАШИНЫ: ЗНАЧЕНИЕ И ПРОИСХОЖДЕНИЕ");
        sb.AppendLine();

        if (vm is null || !vm.Valid)
        {
            sb.AppendLine("  раскладка структур HotSpot не разобрана — проверка пропущена.");
            ctx.Report.Section("ФЛАГИ ВИРТУАЛЬНОЙ МАШИНЫ", sb.ToString());
            return;
        }

        var c = new PageCache(ctx.Target, 8192);

        var args = ReadArguments(ctx, vm, c, sb);

        var flags = ReadFlags(vm, c, sb);
        if (flags.Count == 0)
        {
            ctx.Report.Section("ФЛАГИ ВИРТУАЛЬНОЙ МАШИНЫ", sb.ToString());
            return;
        }

        bool trusted = SelfCheck(flags, args.CmdFlagNames, sb);

        Census(flags, sb);
        ReportOrigins(ctx, flags, trusted, sb);
        ReportSensitive(ctx, flags, args, sb);
        ReportArgumentMismatch(ctx, args, flags, trusted, sb);

        ctx.Report.Section("ФЛАГИ ВИРТУАЛЬНОЙ МАШИНЫ", sb.ToString());
    }

    private static List<FlagRec> ReadFlags(VmStructs vm, PageCache c, StringBuilder sb)
    {
        var res = new List<FlagRec>();

        ulong arrPtr = vm.StaticAddr("JVMFlag", "flags");
        ulong numPtr = vm.StaticAddr("JVMFlag", "numFlags");
        int size = (int)vm.TypeSize("JVMFlag");
        int oAddr = vm.Off("JVMFlag", "_addr");
        int oName = vm.Off("JVMFlag", "_name");
        int oFlags = vm.Off("JVMFlag", "_flags");
        int oType = vm.Off("JVMFlag", "_type");

        if (arrPtr == 0 || numPtr == 0 || size <= 0 || oAddr < 0 || oName < 0 || oFlags < 0)
        {
            sb.AppendLine("  таблица флагов в этой сборке не описана (нет JVMFlag::flags / " +
                          "numFlags / полей записи) — проверка пропущена.");
            sb.AppendLine();
            return res;
        }

        ulong arr = c.U64(arrPtr);
        ulong n = c.U64(numPtr);
        sb.AppendLine($"  таблица флагов              : 0x{arr:X}, записей {n}, " +
                      $"размер записи {size} байт");
        if (arr is < 0x10000 or > 0x7FFFFFFFFFFFFF || n is 0 or > 20000)
        {
            sb.AppendLine("  адрес или длина таблицы неправдоподобны — проверка пропущена.");
            sb.AppendLine();
            return res;
        }

        for (ulong i = 0; i < n; i++)
        {
            ulong e = arr + i * (ulong)size;
            string name = ReadCStr(c, c.U64(e + (ulong)oName), 96);
            if (name.Length == 0) continue;

            var f = new FlagRec
            {
                Name = name,
                Raw = c.U32(e + (ulong)oFlags),
                Type = oType >= 0 ? (int)c.U32(e + (ulong)oType) : -1,
                ValueAddr = c.U64(e + (ulong)oAddr),
            };
            f.Value = FormatValue(c, f);
            res.Add(f);
        }

        sb.AppendLine($"  прочитано записей           : {res.Count}");
        sb.AppendLine();
        return res;
    }

    private static string FormatValue(PageCache c, FlagRec f)
    {
        ulong a = f.ValueAddr;
        if (a is < 0x1000 or > 0x7FFFFFFFFFFFFF) return "<адрес значения недоступен>";
        switch (f.Type)
        {
            case 0:
            {
                Span<byte> b = stackalloc byte[1];
                return c.Read(a, b) ? (b[0] != 0 ? "true" : "false") : "?";
            }
            case 1: return ((int)c.U32(a)).ToString();
            case 2: return c.U32(a).ToString();
            case 3: return ((long)c.U64(a)).ToString();
            case 4:
            case 5:
            case 6: return c.U64(a).ToString();
            case 7:
            {
                Span<byte> b = stackalloc byte[8];
                return c.Read(a, b) ? BitConverter.ToDouble(b).ToString("G6") : "?";
            }
            case 8:
            case 9:
            {
                ulong p = c.U64(a);
                string s = ReadCStr(c, p, 400);
                return s.Length > 0 ? "\"" + s + "\"" : (p == 0 ? "<пусто>" : $"0x{p:X}");
            }
            default: return $"0x{c.U64(a):X} <тип {f.Type} неизвестен>";
        }
    }

    private sealed class ArgsRec
    {
        public List<string> JvmArgs = new();
        public List<string> JvmFlags = new();
        public string JavaCommand = "";
        public HashSet<string> CmdFlagNames = new(StringComparer.Ordinal);
        public bool Read;
    }

    private static ArgsRec ReadArguments(ScanContext ctx, VmStructs vm, PageCache c,
        StringBuilder sb)
    {
        var r = new ArgsRec();
        sb.AppendLine("СОБСТВЕННАЯ КОПИЯ АРГУМЕНТОВ ВИРТУАЛЬНОЙ МАШИНЫ");

        ulong pArgs = vm.StaticAddr("Arguments", "_jvm_args_array");
        ulong pNArgs = vm.StaticAddr("Arguments", "_num_jvm_args");
        ulong pFlags = vm.StaticAddr("Arguments", "_jvm_flags_array");
        ulong pNFlags = vm.StaticAddr("Arguments", "_num_jvm_flags");
        ulong pCmd = vm.StaticAddr("Arguments", "_java_command");

        if (pArgs == 0 || pNArgs == 0)
        {
            sb.AppendLine("  поля Arguments в этой сборке не описаны — копия недоступна.");
            sb.AppendLine();
            return r;
        }
        r.Read = true;
        r.JvmArgs = ReadStrArray(c, c.U64(pArgs), (int)c.U32(pNArgs));
        if (pFlags != 0 && pNFlags != 0)
            r.JvmFlags = ReadStrArray(c, c.U64(pFlags), (int)c.U32(pNFlags));
        if (pCmd != 0) r.JavaCommand = ReadCStr(c, c.U64(pCmd), 1024);

        foreach (string a in r.JvmArgs.Concat(r.JvmFlags))
        {
            string? nm = FlagNameOf(a);
            if (nm is not null) r.CmdFlagNames.Add(nm);
            foreach (string implied in ImpliedFlags(a)) r.CmdFlagNames.Add(implied);
        }

        sb.AppendLine($"  аргументов ВМ               : {r.JvmArgs.Count}");
        foreach (string a in r.JvmArgs) sb.AppendLine("      " + a);
        if (r.JvmFlags.Count > 0)
        {
            sb.AppendLine($"  из файла настроек (-XX:Flags): {r.JvmFlags.Count}");
            foreach (string a in r.JvmFlags) sb.AppendLine("      " + a);
        }
        sb.AppendLine($"  главный класс и его аргументы:");
        sb.AppendLine("      " + JavaMeta.Clean(r.JavaCommand, 900));
        sb.AppendLine();

        ReportAgentArguments(ctx, r);
        ReportCommandLineDivergence(ctx, r, sb);
        return r;
    }

    private static IEnumerable<string> ImpliedFlags(string arg)
    {
        if (arg.StartsWith("-Xmx", StringComparison.Ordinal))
            return new[] { "MaxHeapSize", "SoftMaxHeapSize", "MaxNewSize" };
        if (arg.StartsWith("-Xms", StringComparison.Ordinal))
            return new[] { "InitialHeapSize", "MinHeapSize" };
        if (arg.StartsWith("-Xss", StringComparison.Ordinal))
            return new[] { "ThreadStackSize" };
        if (arg.StartsWith("-Xmn", StringComparison.Ordinal))
            return new[] { "NewSize", "MaxNewSize" };
        if (arg.StartsWith("-Xnoclassgc", StringComparison.Ordinal))
            return new[] { "ClassUnloading", "ClassUnloadingWithConcurrentMark" };
        if (arg.StartsWith("-Xbatch", StringComparison.Ordinal))
            return new[] { "BackgroundCompilation" };
        if (arg.StartsWith("-Xint", StringComparison.Ordinal))
            return new[] { "UseCompiler", "UseInterpreter" };
        if (arg.StartsWith("-Xcomp", StringComparison.Ordinal))
            return new[] { "UseCompiler", "CompileThreshold", "BackgroundCompilation" };
        if (arg.StartsWith("-Xrs", StringComparison.Ordinal))
            return new[] { "ReduceSignalUsage" };
        if (arg.StartsWith("-Xshare", StringComparison.Ordinal))
            return new[] { "UseSharedSpaces", "RequireSharedSpaces" };
        if (arg.StartsWith("-XX:MaxTenuringThreshold", StringComparison.Ordinal))
            return new[] { "AlwaysTenure", "NeverTenure" };
        if (arg.StartsWith("-XX:InitialTenuringThreshold", StringComparison.Ordinal))
            return new[] { "AlwaysTenure", "NeverTenure" };
        if (arg.StartsWith("-Xlog", StringComparison.Ordinal))
            return new[] { "LogVMOutput", "DisplayVMOutput", "LogFile" };
        return Array.Empty<string>();
    }

    private static string? FlagNameOf(string arg)
    {
        if (!arg.StartsWith("-XX:", StringComparison.Ordinal)) return null;
        string s = arg[4..];
        if (s.Length == 0) return null;
        if (s[0] is '+' or '-') s = s[1..];
        int eq = s.IndexOf('=');
        if (eq >= 0) s = s[..eq];
        return s.Length > 0 ? s : null;
    }

    private static void ReportAgentArguments(ScanContext ctx, ArgsRec r)
    {
        string[] markers =
        {
            "-javaagent:", "-agentlib:", "-agentpath:", "-Xbootclasspath",
            "-Xrunjdwp", "-agentlib:jdwp", "-XX:+EnableDynamicAgentLoading",
            "-Xshare:off", "-XX:TraceClassLoading",
        };
        var hits = r.JvmArgs.Concat(r.JvmFlags)
            .Where(a => markers.Any(m => a.StartsWith(m, StringComparison.OrdinalIgnoreCase)))
            .ToList();
        if (hits.Count == 0) return;

        var f = ctx.Report.Report("JVM",
            $"Виртуальная машина запущена с {hits.Count} аргументами загрузки постороннего кода",
            Severity.Critical,
            "Аргументы -javaagent / -agentlib / -agentpath подключают к виртуальной машине " +
            "постороннюю библиотеку или агента ещё до запуска игры. Лаунчер Minecraft таких " +
            "аргументов не ставит. Список прочитан из СОБСТВЕННОЙ копии аргументов внутри " +
            "виртуальной машины (Arguments::_jvm_args_array), а не из командной строки " +
            "процесса: копия сделана в момент создания ВМ, и подменить её после запуска " +
            "нельзя, тогда как командную строку в блоке окружения переписать можно.");
        foreach (string h in hits) f.Add("аргумент", h);
    }

    private static void ReportCommandLineDivergence(ScanContext ctx, ArgsRec r, StringBuilder sb)
    {
        string? peb = ctx.Target.GetCommandLine();
        sb.AppendLine("СВЕРКА С КОМАНДНОЙ СТРОКОЙ ПРОЦЕССА (блок окружения)");
        if (string.IsNullOrEmpty(peb))
        {
            sb.AppendLine("  командная строка процесса не прочитана — сверка пропущена.");
            sb.AppendLine();
            return;
        }

        var missing = r.JvmArgs
            .Where(a => a.Length > 3 && !peb.Contains(a, StringComparison.Ordinal))
            .ToList();
        sb.AppendLine($"  аргументов ВМ, которых нет в командной строке процесса: {missing.Count}");
        foreach (string mssng in missing.Take(40)) sb.AppendLine("      " + mssng);
        sb.AppendLine();
        if (missing.Count == 0) return;

        bool agentish = missing.Any(a =>
            a.StartsWith("-javaagent", StringComparison.OrdinalIgnoreCase) ||
            a.StartsWith("-agent", StringComparison.OrdinalIgnoreCase) ||
            a.StartsWith("-Xbootclasspath", StringComparison.OrdinalIgnoreCase));

        var f = ctx.Report.Report("JVM",
            $"{missing.Count} аргументов виртуальной машины нет в командной строке процесса",
            agentish ? Severity.Critical : Severity.Low,
            "Виртуальная машина хранит собственную копию аргументов, с которыми её создали. " +
            "Командная строка процесса в блоке окружения — независимая запись того же. " +
            "Расхождение означает, что аргументы пришли не из командной строки: обычно из " +
            "переменных окружения JAVA_TOOL_OPTIONS / _JAVA_OPTIONS / JDK_JAVA_OPTIONS, " +
            "которыми постороннюю нагрузку подсаживают мимо лаунчера. Само по себе " +
            "расхождение законно (так работают и некоторые лаунчеры), уликой его делает " +
            "содержание расходящихся аргументов.");
        foreach (string mssng in missing.Take(30)) f.Add("только в копии ВМ", mssng);
    }

    private static bool SelfCheck(List<FlagRec> flags, HashSet<string> cmdNames, StringBuilder sb)
    {
        sb.AppendLine("САМОПРОВЕРКА РАЗБОРА ПРОИСХОЖДЕНИЯ");
        var fromCmd = flags.Where(f => f.Origin == OriginCommandLine).Select(f => f.Name).ToList();
        if (cmdNames.Count == 0)
        {
            sb.AppendLine("  копия аргументов ВМ недоступна — сверить происхождение не с чем; " +
                          "выводы о происхождении ниже помечены как непроверенные.");
            sb.AppendLine();
            return false;
        }
        if (fromCmd.Count == 0)
        {
            sb.AppendLine($"  флагов с источником «командная строка»: 0 при {cmdNames.Count} " +
                          "именах в аргументах — разбор разрядов источника не подтверждён.");
            sb.AppendLine();
            return false;
        }

        int hit = fromCmd.Count(cmdNames.Contains);
        double share = hit * 100.0 / fromCmd.Count;
        sb.AppendLine($"  флагов с источником «командная строка» : {fromCmd.Count}");
        sb.AppendLine($"  из них найдены среди аргументов ВМ     : {hit} ({share:F1} %)");
        var stray = fromCmd.Where(n => !cmdNames.Contains(n)).ToList();
        foreach (string s in stray.Take(20))
            sb.AppendLine($"      нет среди аргументов: {s}");
        bool ok = share >= 60;
        sb.AppendLine(ok
            ? (share >= 90
                ? "  разбор подтверждён: записи о происхождении и о командной строке сходятся."
                : "  разбор подтверждён: смещения и разряды источника верны; остаток " +
                  "расхождения приходится на псевдонимы коротких ключей.")
            : "  разбор НЕ подтверждён: совпало меньше трёх пятых — раскладка записи " +
              "или толкование разрядов неверны, выводы о происхождении отключены.");
        sb.AppendLine();
        return ok;
    }

    private static void Census(List<FlagRec> flags, StringBuilder sb)
    {
        sb.AppendLine("РАСКЛАД ПО ИСТОЧНИКАМ");
        var byOrigin = flags.GroupBy(f => f.Origin).OrderBy(g => g.Key);
        foreach (var g in byOrigin)
            sb.AppendLine($"  {OriginName(g.Key),-28} : {g.Count()}");
        sb.AppendLine();

        sb.AppendLine("ВСЕ ФЛАГИ С ИСТОЧНИКОМ, ОТЛИЧНЫМ ОТ «ЗНАЧЕНИЕ ПО УМОЛЧАНИЮ»");
        foreach (var f in flags.Where(x => x.Origin != OriginDefault)
                     .OrderBy(x => x.Origin).ThenBy(x => x.Name, StringComparer.Ordinal))
            sb.AppendLine($"  {f.Name,-42} = {f.Value,-28} " +
                          $"[{OriginName(f.Origin)}]{(f.WasSetOnCommandLine ? " (отмечен как заданный в командной строке)" : "")}");
        sb.AppendLine();
    }

    private static string OriginName(uint o) =>
        o < OriginNames.Length ? OriginNames[o] : $"источник {o}";

    private static void ReportOrigins(ScanContext ctx, List<FlagRec> flags, bool trusted,
        StringBuilder sb)
    {
        string caveat = trusted
            ? ""
            : " ВНИМАНИЕ: самопроверка разбора происхождения не прошла, значение разрядов " +
              "источника может быть истолковано неверно — сверяйте вручную.";

        var attach = flags.Where(f => f.Origin == OriginAttachOnDemand).ToList();
        if (attach.Count > 0)
        {
            var f = ctx.Report.Report("JVM",
                $"{attach.Count} флагов виртуальной машины изменены ПОДКЛЮЧЕНИЕМ К РАБОТАЮЩЕЙ ВМ",
                Severity.Critical,
                "Источник «подключение на ходу» виртуальная машина ставит флагу ровно в одном " +
                "случае: к уже работающему процессу присоединились через механизм attach и " +
                "выполнили команду смены настройки. Этим же механизмом в процесс подсаживают " +
                "агента JVMTI (VirtualMachine.attach → loadAgent). Запись живёт в статических " +
                "данных jvm.dll: отсоединение, выгрузка агента и удаление его классов её не " +
                "трогают." + caveat);
            foreach (var x in attach) f.Add(x.Name, x.Value);
        }

        var mgmt = flags.Where(f => f.Origin == OriginManagement).ToList();
        if (mgmt.Count > 0)
        {
            var f = ctx.Report.Report("JVM",
                $"{mgmt.Count} флагов виртуальной машины изменены через интерфейс управления",
                Severity.High,
                "Источник «интерфейс управления» ставится, когда настройку меняет " +
                "HotSpotDiagnosticMXBean.setVMOption — то есть код, уже находящийся внутри " +
                "процесса и добравшийся до управляющего интерфейса виртуальной машины. Игра " +
                "и её моды этого не делают." + caveat);
            foreach (var x in mgmt) f.Add(x.Name, x.Value);
        }

        var env = flags.Where(f => f.Origin is OriginEnviron or OriginConfigFile).ToList();
        if (env.Count > 0)
        {
            var f = ctx.Report.Report("JVM",
                $"{env.Count} флагов виртуальной машины пришли не из командной строки, " +
                "а из переменной окружения или файла настроек",
                Severity.Medium,
                "Переменные JAVA_TOOL_OPTIONS, _JAVA_OPTIONS и JDK_JAVA_OPTIONS и файл " +
                "-XX:Flags — штатные способы задать настройки виртуальной машины мимо " +
                "лаунчера. Ими же подсаживают -javaagent, не трогая ярлык запуска. Само по " +
                "себе это не улика (некоторые лаунчеры так и делают), но список должен быть " +
                "объяснён." + caveat);
            foreach (var x in env)
                f.Add(x.Name, $"{x.Value}  [{OriginName(x.Origin)}]");
        }
    }

    private static void ReportSensitive(ScanContext ctx, List<FlagRec> flags, ArgsRec args,
        StringBuilder sb)
    {
        var set = new HashSet<string>(Sensitive, StringComparer.Ordinal);
        var rows = flags.Where(f => set.Contains(f.Name)).ToList();

        sb.AppendLine("ФЛАГИ, ОТНОСЯЩИЕСЯ К ПОДКЛЮЧЕНИЮ И ПОДМЕНЕ КОДА");
        foreach (var f in rows.OrderBy(x => x.Name, StringComparer.Ordinal))
            sb.AppendLine($"  {f.Name,-42} = {f.Value,-28} [{OriginName(f.Origin)}]");
        sb.AppendLine();

        var touched = rows
            .Where(f => f.Origin != OriginDefault && f.Origin != OriginErgonomic)
            .Where(f => !(f.Origin == OriginCommandLine && args.CmdFlagNames.Contains(f.Name)))
            .ToList();
        sb.AppendLine($"  из них задано не лаунчером: {touched.Count}");
        sb.AppendLine();
        if (touched.Count == 0) return;

        bool loud = touched.Any(f =>
            f.Name is "EnableDynamicAgentLoading" or "DisableAttachMechanism"
                or "AllowRedefinitionToAddDeleteMethods" or "StartAttachListener");

        var fnd = ctx.Report.Report("JVM",
            $"{touched.Count} флагов, относящихся к подключению постороннего кода, " +
            "заданы явно (не по умолчанию и не эргономикой)",
            loud ? Severity.High : Severity.Medium,
            "Эти настройки управляют механизмом подключения к виртуальной машине, подменой " +
            "классов на ходу и выводом отладочных сведений. Лаунчер игры их не задаёт. " +
            "Явно заданное значение означает, что кто-то счёл нужным их изменить — и " +
            "источник значения показывает, кто и когда именно.");
        foreach (var f in touched)
            fnd.Add(f.Name, $"{f.Value}  [{OriginName(f.Origin)}]");
    }

    private static void ReportArgumentMismatch(ScanContext ctx, ArgsRec args,
        List<FlagRec> flags, bool trusted, StringBuilder sb)
    {
        if (!trusted || !args.Read || args.CmdFlagNames.Count == 0) return;

        var stray = flags
            .Where(f => f.Origin == OriginCommandLine && !args.CmdFlagNames.Contains(f.Name))
            .ToList();
        if (stray.Count == 0) return;

        var fnd = ctx.Report.Report("JVM",
            $"{stray.Count} флагов помечены как заданные в командной строке, но в " +
            "собственной копии аргументов виртуальной машины их нет",
            stray.Count > 8 ? Severity.High : Severity.Low,
            "Виртуальная машина ведёт две независимые записи: массив строк-аргументов, с " +
            "которыми её создали, и разряд происхождения у каждого флага. При разборе " +
            "командной строки они заполняются вместе и обязаны сходиться. Флаг, помеченный " +
            "как пришедший из командной строки, но отсутствующий среди аргументов, означает, " +
            "что значение присвоено в обход разбора аргументов — напрямую в память ВМ.");
        foreach (var f in stray.Take(40)) fnd.Add(f.Name, f.Value);
    }

    private static List<string> ReadStrArray(PageCache c, ulong arr, int n)
    {
        var res = new List<string>();
        if (arr is < 0x10000 or > 0x7FFFFFFFFFFFFF || n is <= 0 or > 4096) return res;
        for (int i = 0; i < n; i++)
        {
            string s = ReadCStr(c, c.U64(arr + (ulong)i * 8), 1024);
            if (s.Length > 0) res.Add(s);
        }
        return res;
    }

    private static string ReadCStr(PageCache c, ulong addr, int max)
    {
        if (addr is < 0x1000 or > 0x7FFFFFFFFFFFFF) return "";
        var b = c.Read(addr, max);
        if (b is null) return "";
        var sb = new StringBuilder();
        foreach (byte x in b)
        {
            if (x == 0) break;
            sb.Append(x is >= 32 and < 127 ? (char)x : '.');
        }
        return sb.ToString();
    }
}
