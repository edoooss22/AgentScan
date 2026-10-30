using System.Text;
using AgentScan.Core;
using AgentScan.Report;

namespace AgentScan.Analysis;

internal static class JvmResidualAnalyzer
{
    private const uint JVMTI_MAGIC = 0x71EE;
    private const uint DISPOSED_MAGIC = 0xDEFC;
    private const uint BAD_MAGIC = 0xDEAD;

    private static readonly string[] AgentThreadMarkers =
    {
        "JVMTI", "Agent", "ByteBuddy", "Byte Buddy", "Javassist", "Instrument",
        "JDWP", "Attach",
    };

    private static readonly string[] AgentModuleNames =
    {
        "instrument.dll", "jdwp.dll", "attach.dll", "dt_socket.dll", "dt_shmem.dll",
    };

    public static void Run(ScanContext ctx, List<VmTable> tables, SweepResult sweep)
    {
        var jvm = JvmAnalyzer.FindJvm(ctx);
        if (jvm is null) return;

        var sb = new StringBuilder();
        var envs = FindJvmtiEnvironments(ctx, jvm, tables, sweep, sb);
        if (envs.Count > 0) WalkAgentList(ctx, envs, jvm, sb);
        ReportEnvironments(ctx, jvm, envs, sb);
        FindAgentHolders(ctx, envs, sb);
        CheckAgentThreads(ctx, sb);
        CheckInstrumentResiduals(ctx, sweep, sb);

        ctx.Report.Section("ОСТАТОЧНОЕ СОСТОЯНИЕ JVM (следы JVMTI-агента)", sb.ToString());
    }

    private sealed class JvmtiEnv
    {
        public ulong Address;
        public ulong FunctionTable;
        public uint Magic;
        public uint Version;
        public MemRegion? Region;
        public List<(int Off, ulong Val)> ForeignPointers = new();
        public byte[]? Dump;

        public string MagicName => Magic switch
        {
            JVMTI_MAGIC => "0x71EE JVMTI_MAGIC (окружение активно)",
            DISPOSED_MAGIC => "0xDEFC DISPOSED_MAGIC (окружение ОТКЛЮЧЕНО)",
            BAD_MAGIC => "0xDEAD BAD_MAGIC (окружение выведено из обращения)",
            _ => $"0x{Magic:X} (не совпадает с известными)",
        };
    }

    private static List<JvmtiEnv> FindJvmtiEnvironments(ScanContext ctx, ImageInMemory jvm,
        List<VmTable> tables, SweepResult sweep, StringBuilder sb)
    {
        var res = new List<JvmtiEnv>();
        var jvmti = tables.FirstOrDefault(t => t.Kind.StartsWith("jvmtiInterface"));
        sb.AppendLine(jvmti is null
            ? "Таблица jvmtiInterface_1_ в jvm.dll не опознана — поиск окружений агентов " +
              "выполняется только по магическим числам."
            : $"Таблица jvmtiInterface_1_: 0x{jvmti.Address:X} ({jvmti.Slots} слотов)");

        var needles = new List<ulong>();
        if (jvmti is not null) needles.Add(jvmti.Address);

        var candidates = new List<ulong>();

        if (jvmti?.RefPattern is not null && jvmti.RefPattern.Hits.Count > 0)
        {
            foreach (var (addr, _) in jvmti.RefPattern.Hits) candidates.Add(addr);
            sb.AppendLine($"Ссылок на таблицу из сплошного скана: {jvmti.RefPattern.TotalHits}");
        }
        else if (needles.Count > 0)
        {
            int found = 0;
            var needle = BitConverter.GetBytes(needles[0]);
            foreach (var ch in MemoryScan.Chunks(ctx, MemoryScan.PrivateAnyData, overlap: 8))
            {
                int pos = 0;
                while (pos < ch.Length)
                {
                    int idx = ch.Data.AsSpan(pos, ch.Length - pos).IndexOf(needle);
                    if (idx < 0) break;
                    candidates.Add(ch.Base + (ulong)(pos + idx));
                    pos += idx + 1;
                    if (++found > 4096) break;
                }
                if (found > 4096) break;
            }
            sb.AppendLine($"Ссылок на таблицу найдено собственным сканом: " +
                          $"{candidates.Distinct().Count()} (просмотрена вся приватная память, " +
                          MemoryAnalyzer.Human(MemoryScan.TotalReadable(ctx, MemoryScan.PrivateAnyData)) + ")");
        }

        foreach (var addr in candidates.Distinct().Take(8192))
        {
            var head = ctx.Target.ReadBytes(addr, 0x18);
            if (head is null) continue;
            ulong fnTable = BitConverter.ToUInt64(head, 0);
            uint magic = BitConverter.ToUInt32(head, 8);
            uint version = BitConverter.ToUInt32(head, 12);
            if (magic is not (JVMTI_MAGIC or DISPOSED_MAGIC or BAD_MAGIC)) continue;

            var env = new JvmtiEnv
            {
                Address = addr,
                FunctionTable = fnTable,
                Magic = magic,
                Version = version,
                Region = ctx.RegionAt(addr),
            };
            env.Dump = ctx.Target.ReadBytes(addr, 0x400);
            if (env.Dump is not null)
            {
                for (int i = 0; i + 8 <= env.Dump.Length; i += 8)
                {
                    ulong v = BitConverter.ToUInt64(env.Dump, i);
                    if (v is < 0x10000 or > 0x7FFFFFFFFFFF) continue;
                    if (v >= jvm.Base && v < jvm.End) continue;
                    var reg = ctx.RegionAt(v);
                    if (reg is null || !reg.IsCommitted || !reg.IsExecutable) continue;
                    env.ForeignPointers.Add((i, v));
                }
            }
            res.Add(env);
            if (res.Count > 64) break;
        }

        if (res.Count == 0 && jvmti is null)
            sb.AppendLine("Поиск по магическим числам без известной таблицы не выполнялся: " +
                          "слишком много ложных совпадений на двух байтах.");

        sb.AppendLine($"Опознано объектов jvmtiEnv: {res.Count} " +
                      $"(активных: {res.Count(x => x.Magic == JVMTI_MAGIC)}, " +
                      $"отключённых: {res.Count(x => x.Magic == DISPOSED_MAGIC)}, " +
                      $"выведенных из обращения: {res.Count(x => x.Magic == BAD_MAGIC)})");
        sb.AppendLine();
        return res;
    }

    private static void ReportEnvironments(ScanContext ctx, ImageInMemory jvm,
        List<JvmtiEnv> envs, StringBuilder sb)
    {
        foreach (var env in envs)
        {
            sb.AppendLine($"jvmtiEnv 0x{env.Address:X}  magic={env.MagicName}  " +
                          $"version=0x{env.Version:X}  " +
                          $"{env.Region?.TypeString}/{env.Region?.ProtectString}  " +
                          $"чужих указателей: {env.ForeignPointers.Count}");

            Severity sev = env.Magic switch
            {
                DISPOSED_MAGIC => Severity.Critical,
                JVMTI_MAGIC => Severity.Critical,
                _ => Severity.High,
            };

            string why = env.Magic == DISPOSED_MAGIC
                ? "Найден объект окружения JVMTI, помеченный как ОТКЛЮЧЁННЫЙ. HotSpot " +
                  "выставляет это значение в DisposeEnvironment — то есть агент был " +
                  "подключён к этой JVM и затем сам себя отключил. Именно так выглядит " +
                  "«анхук» JVMTI-чита: библиотека агента выгружена, классы восстановлены, " +
                  "но объект окружения остаётся в куче с меткой отключения до тех пор, пока " +
                  "эту память не займут заново. В чистом клиенте Minecraft объектов " +
                  "jvmtiEnv нет вообще, ни активных, ни отключённых."
                : env.Magic == JVMTI_MAGIC
                    ? "Найден АКТИВНЫЙ объект окружения JVMTI. Каждый подключённый к JVM агент " +
                      "получает такой объект; в клиенте Minecraft без агентов их нет ни " +
                      "одного. Агент имеет полный доступ к байт-коду, классам, полям и " +
                      "стекам — это и есть механизм JVMTI-читов."
                    : "Найден объект окружения JVMTI с меткой испорченного. Это след " +
                      "агента, чьё окружение JVM признала недействительным.";

            var f = ctx.Report.Report("JVM",
                $"Объект окружения JVMTI по 0x{env.Address:X}: {env.MagicName}", sev, why);
            f.Add("адрес объекта (jvmtiEnv*)", env.Address);
            f.Add("таблица функций", $"0x{env.FunctionTable:X} → {ctx.Describe(env.FunctionTable)}");
            f.Add("magic", env.MagicName);
            f.Add("поле version", $"0x{env.Version:X}");
            f.Add("регион", env.Region?.ToString() ?? "-");
            f.Add("указателей на код вне jvm.dll", env.ForeignPointers.Count.ToString());

            if (env.ForeignPointers.Count > 0)
            {
                var body = new StringBuilder();
                foreach (var (off, v) in env.ForeignPointers.Take(48))
                {
                    var im = ctx.ImageAt(v);
                    bool alien = im is null || im.Ldr is null;
                    body.AppendLine($"  {(alien ? "!!" : "  ")} +0x{off:X3}  0x{v:X}  " +
                                    ctx.Describe(v));
                }
                f.Block("Указатели из тела объекта (колбэки событий агента)",
                    body.ToString().TrimEnd());

                if (env.ForeignPointers.Any(p => ctx.ImageAt(p.Val)?.Ldr is null))
                {
                    ctx.Report.Report("JVM",
                            $"Окружение JVMTI 0x{env.Address:X} хранит колбэки, ведущие в " +
                            "память вне загруженных модулей",
                            Severity.Critical,
                            "Таблица колбэков событий JVMTI внутри объекта окружения хранит " +
                            "адреса функций агента. Если эти адреса указывают туда, где " +
                            "больше нет ни одного загруженного модуля, значит библиотека " +
                            "агента уже выгружена, а её адреса остались — прямое " +
                            "доказательство того, что агент работал и был убран.")
                        .Add("объект окружения", env.Address)
                        .Add("колбэков вне модулей",
                            env.ForeignPointers.Count(p => ctx.ImageAt(p.Val)?.Ldr is null).ToString());
                }
            }

            DecodeEventCallbacks(ctx, env, jvm, f);

            if (env.Dump is not null)
                f.Block("Объект окружения (0x400 байт; здесь же лежат jvmtiCapabilities " +
                        "и таблица колбэков событий)", HexDump.Format(env.Dump, env.Address));

            if (ctx.Dumper is not null)
            {
                ulong from = env.Address > 0x1000 ? env.Address - 0x1000 : env.Address;
                string? p = ctx.Dumper.DumpRange(from, 0x4000, "jvmtienv",
                    $"объект окружения JVMTI ({env.MagicName}) и его окрестность в куче",
                    $"сам объект по 0x{env.Address:X}, смещение в файле " +
                    $"0x{env.Address - from:X}");
                if (p is not null) f.Add("дамп окрестности", p);
            }
        }
        if (envs.Count > 0) sb.AppendLine();
    }

    private static void WalkAgentList(ScanContext ctx, List<JvmtiEnv> envs, ImageInMemory jvm,
        StringBuilder sb)
    {
        const int NextOffset = 0x10;
        var known = envs.Select(e => e.Address).ToHashSet();
        var added = new List<JvmtiEnv>();

        foreach (var start in envs.ToList())
        {
            ulong p = ctx.Target.ReadU64(start.Address + NextOffset);
            int guard = 0;
            while (p is >= 0x10000 and <= 0x7FFFFFFFFFFF && guard++ < 64)
            {
                if (!known.Add(p)) break;

                var head = ctx.Target.ReadBytes(p, 0x18);
                if (head is null) break;
                ulong fnTable = BitConverter.ToUInt64(head, 0);
                uint magic = BitConverter.ToUInt32(head, 8);
                bool looksLikeEnv = magic is JVMTI_MAGIC or DISPOSED_MAGIC or BAD_MAGIC ||
                                    (fnTable >= jvm.Base && fnTable < jvm.End);
                if (!looksLikeEnv) break;

                var env = new JvmtiEnv
                {
                    Address = p,
                    FunctionTable = fnTable,
                    Magic = magic,
                    Version = BitConverter.ToUInt32(head, 12),
                    Region = ctx.RegionAt(p),
                    Dump = ctx.Target.ReadBytes(p, 0x400),
                };
                added.Add(env);
                p = BitConverter.ToUInt64(head, NextOffset);
            }
        }

        if (added.Count > 0)
        {
            sb.AppendLine($"Обход списка окружений по полю _next добавил {added.Count} " +
                          "окружений, не найденных сканированием:");
            foreach (var e in added)
                sb.AppendLine($"  0x{e.Address:X}  {e.MagicName}");
            sb.AppendLine();

            ctx.Report.Report("JVM",
                    $"Список окружений JVMTI содержит {added.Count} окружений, которые не " +
                    "находятся сканированием памяти",
                    Severity.Critical,
                    "Виртуальная машина связывает все окружения агентов односвязным списком. " +
                    "Пройдя по нему от найденного окружения, получены дополнительные — их не " +
                    "нашёл поиск по ссылкам на таблицу функций, то есть у них это поле уже " +
                    "затёрто или изменено. Так выглядит попытка спрятать факт подключения " +
                    "агента: сам объект из списка не выведен, а опознавательный признак с " +
                    "него снят.")
                .Add("найдено обходом списка", added.Count.ToString())
                .Block("Окружения", string.Join("\n", added.Select(e =>
                    $"  0x{e.Address:X}  magic={e.MagicName}  таблица={ctx.Describe(e.FunctionTable)}")));

            envs.AddRange(added);
        }
        else sb.AppendLine("Обход списка окружений новых объектов не дал.");
        sb.AppendLine();
    }

    private static void DecodeEventCallbacks(ScanContext ctx, JvmtiEnv env, ImageInMemory jvm,
        Finding f)
    {
        if (env.Dump is null) return;

        var layout = JvmtiEnvLayout.Probe(ctx, env.Dump);
        if (layout is null)
        {
            f.Add("таблица колбэков событий",
                "НЕ ОПОЗНАНА — ни одно из проверяемых смещений не прошло сверку " +
                "(колбэки обязаны быть нулями либо адресами исполняемой памяти). " +
                "Выводов о подписках по этому объекту не делается.");
            return;
        }

        f.Add("таблица колбэков событий", $"смещение +0x{layout.Callbacks:X} в объекте");
        f.Add("маски включения событий",
            layout.AnyEventEnabled
                ? $"user=0x{layout.Masks[0]:X16} callback=0x{layout.Masks[1]:X16} " +
                  $"enabled=0x{layout.Masks[2]:X16}"
                : "все три нулевые — на момент проверки ни одно событие не включено");

        var callbacks = JvmtiEnvLayout.Callbacks(env.Dump, layout);
        if (callbacks.Count == 0)
        {
            f.Add("подписки на события",
                "таблица колбэков опознана и ПУСТА — обработчики сняты либо не ставились");
            return;
        }

        var subscribed = callbacks
            .Select(x => $"{x.Event} → {ctx.Describe(x.Target)}")
            .ToList();
        f.Block("Подписки на события JVMTI (позиция указателя = событие)",
            string.Join("\n", subscribed.Select(x => "  " + x)));

        var cflh = callbacks.FirstOrDefault(x => x.Event == "ClassFileLoadHook");
        if (cflh.Target == 0) return;

        bool outsideModules = ctx.ImageAt(cflh.Target) is null;
        ctx.Report.Report("JVM",
                $"Окружение JVMTI 0x{env.Address:X} держит обработчик ClassFileLoadHook",
                Severity.Critical,
                "ClassFileLoadHook — событие, через которое агент получает байт-код " +
                "КАЖДОГО загружаемого класса и возвращает изменённый. Это основной " +
                "механизм Java-чита: подмена кода игры на лету. Адрес обработчика " +
                "записан в таблице колбэков самого окружения и остаётся там после того, " +
                "как агент отработал: SetEventNotificationMode выключает событие, но " +
                "таблицу колбэков не чистит. Смещение таблицы здесь не угадано, а " +
                "проверено: все её слоты либо нулевые, либо ведут в занятую исполняемую " +
                "память, а хвост объекта сходится с раскладкой JvmtiEnvBase.")
            .Add("объект окружения", env.Address)
            .Add("состояние окружения", env.MagicName)
            .Add("адрес обработчика", $"0x{cflh.Target:X} — {ctx.Describe(cflh.Target)}")
            .Add("обработчик вне загруженных модулей", outsideModules ? "ДА" : "нет")
            .Add("событие включено сейчас",
                layout.AnyEventEnabled ? "маски ненулевые" : "нет, маски обнулены")
            .Block("Подписки", string.Join("\n", subscribed.Select(x => "  " + x)));
    }

    private static void FindAgentHolders(ScanContext ctx, List<JvmtiEnv> envs, StringBuilder sb)
    {
        if (envs.Count == 0) return;

        var needles = envs.Select(e => BitConverter.GetBytes(e.Address)).ToList();
        var holders = new List<(ulong Addr, ulong Env, MemRegion Region)>();
        var seenHolders = new HashSet<ulong>();

        foreach (var ch in MemoryScan.Chunks(ctx,
                     r => MemoryScan.Readable(r) &&
                          !(r.IsImage && r.MappedFile is not null && !r.IsWritable)))
        {
            if (holders.Count > 256) break;
            for (int k = 0; k < needles.Count; k++)
            {
                int pos = 0;
                while (pos < ch.Length)
                {
                    int idx = ch.Data.AsSpan(pos, ch.Length - pos).IndexOf(needles[k]);
                    if (idx < 0) break;
                    ulong at = ch.Base + (ulong)(pos + idx);
                    pos += idx + 1;
                    if (at == envs[k].Address) continue;
                    if (!seenHolders.Add(at)) continue;
                    holders.Add((at, envs[k].Address, ch.Region));
                    if (holders.Count > 256) break;
                }
            }
        }

        sb.AppendLine($"Структур, хранящих указатель на окружение JVMTI: {holders.Count}");
        foreach (var h in holders.Take(64))
            sb.AppendLine($"  0x{h.Addr:X}  → jvmtiEnv 0x{h.Env:X}  " +
                          $"({h.Region.TypeString}/{h.Region.ProtectString}) " +
                          (ctx.ImageAt(h.Addr)?.Name is { } n ? $"в модуле {n}" : ""));

        foreach (var h in holders)
        {
            var win = ctx.Target.ReadBytes(h.Addr > 0x40 ? h.Addr - 0x40 : h.Addr, 0x100);
            if (win is null) continue;
            int envPtrs = 0;
            bool javaVm = false;
            for (int i = 0; i + 8 <= win.Length; i += 8)
            {
                ulong v = BitConverter.ToUInt64(win, i);
                if (envs.Any(e => e.Address == v)) envPtrs++;
                else if (v is >= 0x10000 and <= 0x7FFFFFFFFFFF)
                {
                    ulong t = ctx.Target.ReadU64(v);
                    var im = ctx.ImageAt(t);
                    if (im is not null &&
                        im.Name.Equals("jvm.dll", StringComparison.OrdinalIgnoreCase)) javaVm = true;
                }
            }
            if (envPtrs < 2 || !javaVm) continue;

            ctx.Report.Report("JVM",
                    $"По 0x{h.Addr:X} найдена структура, устроенная как JPLISAgent " +
                    "(нативная часть java.lang.instrument)",
                    Severity.Critical,
                    "JPLISAgent — структура, которую instrument.dll создаёт при подключении " +
                    "Java-агента. Опознаётся по характерному составу: указатель на JavaVM и " +
                    "ДВА окружения JVMTI сразу — обычное и отдельное для retransform, которое " +
                    "instrument.dll заводит специально для повторной трансформации уже " +
                    "загруженных классов. Ни один штатный компонент Minecraft такой структуры " +
                    "не создаёт: она появляется только вместе с -javaagent или динамическим " +
                    "подключением агента через Attach API.")
                .Add("адрес структуры", h.Addr)
                .Add("окружений JVMTI внутри", envPtrs.ToString())
                .Add("указатель на JavaVM", "найден")
                .Add("регион", h.Region.ToString())
                .Block("Структура", HexDump.Format(win, h.Addr > 0x40 ? h.Addr - 0x40 : h.Addr));
        }

        foreach (var g in holders.GroupBy(h => h.Env))
        {
            var f = ctx.Report.Report("JVM",
                $"На окружение JVMTI 0x{g.Key:X} ссылаются {g.Count()} структур в памяти",
                Severity.High,
                "Указатель на jvmtiEnv хранит тот, кто этим окружением пользуется: нативная " +
                "часть java.lang.instrument (структура JPLISAgent) либо собственный агент. " +
                "По расположению этих структур видно, кому принадлежал агент: адрес внутри " +
                "instrument.dll означает штатный -javaagent, адрес в приватной памяти или в " +
                "чужом модуле — собственный нативный агент.");
            foreach (var h in g.Take(32))
            {
                var im = ctx.ImageAt(h.Addr);
                f.Add($"держатель 0x{h.Addr:X}",
                    (im is not null ? $"{im.Name}+0x{h.Addr - im.Base:X}" : "приватная память") +
                    $" ({h.Region.TypeString}/{h.Region.ProtectString})");
            }
            var first = g.First();
            var dump = ctx.Target.ReadBytes(
                first.Addr > 0x40 ? first.Addr - 0x40 : first.Addr, 0x100);
            if (dump is not null)
                f.Block("Память вокруг держателя",
                    HexDump.Format(dump, first.Addr > 0x40 ? first.Addr - 0x40 : first.Addr));
        }
        sb.AppendLine();
    }

    private static void CheckAgentThreads(ScanContext ctx, StringBuilder sb)
    {
        sb.AppendLine("Потоки с именами, характерными для агентов и библиотек инструментирования:");
        int n = 0;
        foreach (var th in ctx.Threads)
        {
            if (th.Description is null) continue;
            var hit = AgentThreadMarkers.FirstOrDefault(
                m => th.Description.Contains(m, StringComparison.OrdinalIgnoreCase));
            if (hit is null) continue;
            n++;
            double sec = ctx.Target.StartTimeUtc != default && th.CreateTimeUtc != default
                ? (th.CreateTimeUtc - ctx.Target.StartTimeUtc).TotalSeconds : -1;
            sb.AppendLine($"  {th.Tid,-8} +{sec,8:F1}с  «{th.Description}»  " +
                          $"старт: {ctx.Describe(th.Win32StartAddress != 0 ? th.Win32StartAddress : th.KernelStartAddress)}");

            if (th.Description.Contains("Attach Listener", StringComparison.OrdinalIgnoreCase))
                continue;
            if (hit is "Agent" or "Attach" &&
                !th.Description.Contains("JVMTI", StringComparison.OrdinalIgnoreCase) &&
                !th.Description.Contains("Agent Thread", StringComparison.OrdinalIgnoreCase))
                continue;

            ctx.Report.Report("JVM",
                    $"Поток «{th.Description}» (TID {th.Tid}) — инфраструктура агента JVM",
                    Severity.Critical,
                    "Потоки с такими именами создаёт только код агента: JVMTI RunAgentThread, " +
                    "Byte Buddy, Javassist. Штатный клиент Minecraft их не создаёт.")
                .Add("TID", th.Tid.ToString())
                .Add("имя", th.Description)
                .Add("создан через", sec >= 0 ? $"{sec:F2} с после старта" : "-")
                .Add("стартовый адрес", ctx.Describe(
                    th.Win32StartAddress != 0 ? th.Win32StartAddress : th.KernelStartAddress));
        }
        if (n == 0) sb.AppendLine("  не найдено");
        sb.AppendLine();
    }

    private static readonly (string Needle, Severity Sev, string Why)[] InstrumentClasses =
    {
        ("sun/instrument/InstrumentationImpl", Severity.Critical,
            "Реализация java.lang.instrument.Instrumentation. Создаётся ровно один раз — " +
            "при подключении Java-агента. Её присутствие в памяти означает, что агент " +
            "к этой JVM подключался, даже если сейчас он уже отработал."),
        ("sun/instrument/TransformerManager", Severity.Critical,
            "TransformerManager хранит МАССИВ зарегистрированных ClassFileTransformer. " +
            "Он остаётся в куче и после того, как агент отработал: снятие трансформера " +
            "только убирает его из массива, а сам объект-менеджер и его следы остаются."),
        ("java/lang/instrument/ClassFileTransformer", Severity.Critical,
            "Интерфейс подмены байт-кода загружаемых классов — основной инструмент " +
            "Java-чита, работающего агентом."),
        ("java/lang/instrument/Instrumentation", Severity.Critical,
            "API инструментирования JVM."),
        ("java/lang/instrument/UnmodifiableClassException", Severity.High,
            "Класс исключения из состава java.lang.instrument: загружается вместе " +
            "с остальным API инструментирования."),
        ("net/bytebuddy/agent/ByteBuddyAgent", Severity.Critical,
            "Byte Buddy Agent — библиотека подключения агента к своей же JVM (self-attach). " +
            "В составе Minecraft и Fabric её нет."),
        ("javassist/", Severity.Medium,
            "Javassist — библиотека генерации и правки байт-кода в рантайме."),
    };

    private static void CheckInstrumentResiduals(ScanContext ctx, SweepResult sweep, StringBuilder sb)
    {
        sb.AppendLine("Следы java.lang.instrument в загруженных классах:");
        if (sweep.Classes.Count == 0)
        {
            sb.AppendLine("  сплошной скан памяти отключён — проверка по классам не выполнялась");
        }
        else
        {
            foreach (var (needle, sev, why) in InstrumentClasses)
            {
                var hits = sweep.Classes.Values
                    .Where(c => c.Name.StartsWith(needle, StringComparison.Ordinal))
                    .ToList();
                sb.AppendLine($"  {needle,-52} {(hits.Count == 0 ? "нет" : $"НАЙДЕНО ×{hits.Count}")}");
                if (hits.Count == 0) continue;

                var f = ctx.Report.Report("JVM",
                    $"В памяти JVM найден байт-код «{needle}*» ({hits.Count} шт.)", sev, why);
                foreach (var c in hits.Take(24))
                    f.Add(c.Name, $"0x{c.Address:X}, class-версия {c.MajorVersion}" +
                                  (c.Occurrences > 1 ? $", копий в памяти: {c.Occurrences}" : ""));
            }
        }
        sb.AppendLine();

        sb.AppendLine("Модули инфраструктуры агентов среди загруженных:");
        foreach (var name in AgentModuleNames)
        {
            var im = ctx.Images.FirstOrDefault(
                x => x.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
            sb.AppendLine($"  {name,-20} {(im is null ? "не загружен" : $"загружен, база 0x{im.Base:X}")}");
        }
        sb.AppendLine();
        sb.AppendLine("Примечание: Agent_OnUnload вызывается у нативного агента при выгрузке " +
                      "библиотеки. Сам факт выгрузки виден в журнале выгруженных модулей " +
                      "(отдельный раздел отчёта), а следы работы агента — в объектах " +
                      "окружения выше.");
    }
}
