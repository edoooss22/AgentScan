using System.Text;
using AgentScan.Core;
using AgentScan.Report;

namespace AgentScan.Analysis;

internal static class JvmtiAgentListForensicsAnalyzer
{
    public static void Run(ScanContext ctx)
    {
        var jvm = JvmAnalyzer.FindJvm(ctx);
        var sb = new StringBuilder();

        sb.AppendLine("Списки агентов и структуры механизма подключения читаются прямо из");
        sb.AppendLine("памяти виртуальной машины. Символов для них нет, поэтому опознание");
        sb.AppendLine("структурное: запись принимается только если сходятся ВСЕ её поля.");
        sb.AppendLine();

        if (jvm is null || !jvm.Pe.Valid)
        {
            sb.AppendLine("jvm.dll не найдена или её заголовки не разобраны — проверка невозможна.");
            ctx.Report.Section("СПИСКИ АГЕНТОВ HOTSPOT И МЕХАНИЗМ ПОДКЛЮЧЕНИЯ", sb.ToString());
            return;
        }

        var agents = FindAgentList(ctx, jvm, sb);
        ReportAgents(ctx, agents, sb);
        FindAttachOperations(ctx, jvm, sb);
        FindAgentStrings(ctx, sb);

        ctx.Report.Section("СПИСКИ АГЕНТОВ HOTSPOT И МЕХАНИЗМ ПОДКЛЮЧЕНИЯ", sb.ToString());
    }

    private sealed class ListHit
    {
        public ulong HeadVar;
        public List<AgentRecord> Chain = new();
        public string How = "";
    }

    private static List<AgentRecord> FindAgentList(ScanContext ctx, ImageInMemory jvm,
        StringBuilder sb)
    {
        var result = new List<AgentRecord>();
        var seen = new HashSet<ulong>();
        var hits = new List<ListHit>();

        sb.AppendLine("ПОИСК ГОЛОВЫ СПИСКА АГЕНТОВ В ДАННЫХ jvm.dll");

        foreach (var sec in jvm.Pe.Sections)
        {
            if (sec.IsExecutable || sec.VirtualSize is 0 or > 32 * 1024 * 1024) continue;
            if (sec.Name is not (".data" or ".rdata" or ".bss")) continue;

            var buf = new byte[sec.VirtualSize];
            ulong va = jvm.Base + sec.VirtualAddress;
            if (ctx.Target.ReadPartial(va, buf, out _) <= 0) continue;

            for (int i = 0; i + 8 <= buf.Length; i += 8)
            {
                ulong p = BitConverter.ToUInt64(buf, i);
                if (p is < 0x10000 or > 0x7FFFFFFFFFFF) continue;
                if (p >= jvm.Base && p < jvm.End) continue;
                var reg = ctx.RegionAt(p);
                if (reg is null || !reg.IsCommitted || !reg.IsPrivate || reg.IsExecutable) continue;

                var rec = JvmtiAgentProbe.TryRead(ctx, p);
                if (rec is null) continue;

                var hit = new ListHit { HeadVar = va + (ulong)i, How = $"{sec.Name}+0x{i:X}" };
                var cur = rec;
                int guard = 0;
                while (cur is not null && guard++ < 64)
                {
                    if (!seen.Add(cur.Address)) break;
                    hit.Chain.Add(cur);
                    result.Add(cur);
                    AgentRecord? next = null;
                    foreach (ulong q in cur.Pointers)
                    {
                        if (seen.Contains(q)) continue;
                        next = JvmtiAgentProbe.TryRead(ctx, q, requireHard: false);
                        if (next is not null) break;
                    }
                    cur = next;
                }
                if (hit.Chain.Count > 0) hits.Add(hit);
                if (hits.Count > 8) break;
            }
            if (hits.Count > 8) break;
        }

        if (hits.Count == 0)
        {
            sb.AppendLine("  голова списка не найдена: в данных jvm.dll нет указателя на " +
                          "объект, разбирающийся как запись об агенте.");
            sb.AppendLine("  ВАЖНО: это ещё не значит, что агентов не было. Список мог быть " +
                          "очищен вручную, а запись — освобождена. Поэтому ниже независимо " +
                          "просматривается вся куча процесса.");
            sb.AppendLine();
            FindOrphanAgents(ctx, jvm, result, sb);
            return result;
        }

        foreach (var h in hits)
        {
            sb.AppendLine($"  голова 0x{h.HeadVar:X} (jvm.dll {h.How}) → цепочка из " +
                          $"{h.Chain.Count} записей");
            foreach (var a in h.Chain)
                sb.AppendLine($"      0x{a.Address:X}  «{a.Name}»  опции: " +
                              $"{(a.Options is null ? "-" : "«" + a.Options + "»")}  {a.HowLoaded}");
        }
        sb.AppendLine();
        FindOrphanAgents(ctx, jvm, result, sb);
        return result;
    }

    private static void FindOrphanAgents(ScanContext ctx, ImageInMemory jvm,
        List<AgentRecord> known, StringBuilder sb)
    {
        var have = known.Select(a => a.Address).ToHashSet();
        var found = new List<AgentRecord>();

        var strings = new Dictionary<ulong, string>();
        foreach (var ch in MemoryScan.Chunks(ctx, MemoryScan.PrivateAnyData, overlap: 512))
        {
            if (strings.Count > 20000) break;
            var r = ch.Region;
            var buf = ch.Exact;
            ulong rbase = ch.Base;

            foreach (var ext in new[] { ".dll"u8.ToArray(), ".so"u8.ToArray() })
            {
                int pos = 0;
                while (pos < buf.Length && strings.Count <= 20000)
                {
                    int idx = buf.AsSpan(pos).IndexOf(ext);
                    if (idx < 0) break;
                    int at = pos + idx;
                    pos = at + ext.Length;
                    if (at + ext.Length >= buf.Length || buf[at + ext.Length] != 0) continue;

                    int start = at;
                    while (start > 0 && buf[start - 1] is >= 0x20 and < 0x7F &&
                           at - start < 300) start--;
                    if (at + ext.Length - start < 5) continue;
                    strings[rbase + (ulong)start] =
                        Encoding.ASCII.GetString(buf, start, at + ext.Length - start);
                }
            }
        }

        foreach (var ch in MemoryScan.Chunks(ctx, MemoryScan.PrivateData, overlap: 0x60))
        {
            if (found.Count >= 32) break;
            var r = ch.Region;
            var buf = ch.Exact;
            ulong rbase = ch.Base;

            for (int i = 0; i + 8 <= buf.Length; i += 8)
            {
                ulong v = BitConverter.ToUInt64(buf, i);
                if (v == 0 || !strings.ContainsKey(v)) continue;

                for (int back = 0; back <= 0x50; back += 8)
                {
                    if (i - back < 0) break;
                    ulong addr = rbase + (ulong)(i - back);
                    if (!have.Add(addr)) continue;
                    var rec = JvmtiAgentProbe.TryRead(ctx, addr);
                    if (rec is null) continue;
                    var dup = found.FirstOrDefault(x =>
                        x.OsLibPath is not null && x.OsLibPath == rec.OsLibPath);
                    if (dup is not null)
                    {
                        if (rec.Layout.Count <= dup.Layout.Count) break;
                        found.Remove(dup);
                        known.Remove(dup);
                    }
                    found.Add(rec);
                    known.Add(rec);
                    break;
                }
                if (found.Count >= 32) break;
            }
        }

        sb.AppendLine($"Строк, похожих на путь к библиотеке, в куче: {strings.Count}");
        sb.AppendLine($"Записей об агентах, найденных помимо списка: {found.Count}");
        foreach (var a in found)
            sb.AppendLine($"    0x{a.Address:X}  «{a.Name}»  " +
                          $"библиотека: {(a.OsLibModule ?? (a.OsLib == 0 ? "-" : $"0x{a.OsLib:X} (модуля нет)"))}");
        sb.AppendLine();
        _ = jvm;
    }

    private static void ReportAgents(ScanContext ctx, List<AgentRecord> raw, StringBuilder sb)
    {
        var unique = raw
            .GroupBy(a => a.OsLibPath ?? $"@0x{a.OsLib:X}|{a.Name}|{a.Options}")
            .Select(g =>
            {
                var best = g.OrderByDescending(x => x.Layout.Count)
                            .ThenByDescending(x => x.Options is not null ? 1 : 0).First();
                if (g.Count() > 1)
                    best.Notes.Add($"та же запись опознана с {g.Count()} смещений окна " +
                                   "разбора (адреса: " +
                                   string.Join(", ", g.Select(x => $"0x{x.Address:X}").Take(6)) +
                                   ")");
                return best;
            })
            .ToList();

        var agents = unique.Where(a => a.OsLibPath is not null).ToList();
        var weak = unique.Where(a => a.OsLibPath is null).ToList();

        if (weak.Count > 0)
        {
            sb.AppendLine($"Структур с раскладкой записи об агенте, но без пути к библиотеке: " +
                          $"{weak.Count} (в находки не выносятся — по ним ничего не " +
                          "утверждается)");
            foreach (var a in weak.Take(12))
                sb.AppendLine($"    0x{a.Address:X}  дескриптор 0x{a.OsLib:X}" +
                              (a.OsLibModule is not null ? $" → {a.OsLibModule}" : "") +
                              (a.Name is not null ? $"  имя «{a.Name}»" : ""));
            sb.AppendLine();
        }

        sb.AppendLine("ВОССТАНОВЛЕННЫЕ ЗАПИСИ ОБ АГЕНТАХ:");
        if (agents.Count == 0)
        {
            sb.AppendLine("  ни одной записи не найдено.");
            sb.AppendLine();
            ctx.Report.Report("JVM",
                "Во внутренних списках HotSpot записей об агентах не найдено",
                Severity.Info,
                "Виртуальная машина хранит подключённые агенты собственным списком " +
                "(JvmtiAgentList в JDK 21, Arguments::_agentList в более ранних) и не " +
                "очищает его при отключении агента: запись переживает и Agent_OnUnload, " +
                "и DisposeEnvironment. Поиск шёл двумя независимыми способами — от головы " +
                "списка в данных jvm.dll и сплошным структурным просмотром кучи — и не дал " +
                "ничего. Это отрицательный результат, и он важен: он означает, что через " +
                "штатный механизм агентов к этой ВМ никто не подключался.");
            return;
        }

        foreach (var a in agents)
        {
            sb.AppendLine($"  ── 0x{a.Address:X}");
            sb.AppendLine($"     имя агента           : {a.Name ?? "-"}");
            sb.AppendLine($"     опции агента         : {a.Options ?? "-"}");
            sb.AppendLine($"     дескриптор библиотеки: 0x{a.OsLib:X}" +
                          (a.OsLibModule is not null ? $" → {a.OsLibModule}" : ""));
            sb.AppendLine($"     путь к библиотеке    : {a.OsLibPath ?? "-"}");
            sb.AppendLine($"     нативная часть JPLIS : 0x{a.Jplis:X}");
            sb.AppendLine($"     способ подключения   : {a.HowLoaded}");
            sb.AppendLine($"     абсолютный путь      : {(a.AbsolutePath ? "да" : "нет")}" +
                          $"   статическая: {(a.StaticLib ? "да" : "нет")}" +
                          $"   instrument: {(a.InstrumentLib ? "да" : "нет")}" +
                          $"   загружен: {(a.Loaded ? "да" : "нет")}");
            if (a.Layout.Count > 0)
            {
                sb.AppendLine("     восстановленная раскладка записи:");
                foreach (var l in a.Layout) sb.AppendLine($"        {l}");
            }
            foreach (var n in a.Notes) sb.AppendLine($"     ! {n}");
            sb.AppendLine();
        }

        foreach (var a in agents)
        {
            bool wellKnown = a.Name is not null &&
                (a.Name.Equals("instrument", StringComparison.OrdinalIgnoreCase) ||
                 a.Name.Equals("jdwp", StringComparison.OrdinalIgnoreCase) ||
                 a.Name.Contains("management", StringComparison.OrdinalIgnoreCase));

            Severity sev = a.Dynamic ? Severity.Critical
                : wellKnown ? Severity.High
                : Severity.Critical;

            var f = ctx.Report.Report("JVM",
                $"Во внутренних структурах HotSpot есть запись об агенте " +
                $"«{a.Name ?? Path.GetFileName(a.OsLibPath!)}» ({a.HowLoaded})",
                sev,
                "Это запись из СОБСТВЕННОГО СПИСКА АГЕНТОВ виртуальной машины. Она " +
                "создаётся при подключении агента и не удаляется никогда: ни " +
                "Agent_OnUnload, ни DisposeEnvironment её не трогают, потому что ВМ " +
                "держит список до конца жизни процесса. Поэтому здесь читается то, чего " +
                "не остаётся больше нигде: имя агента, строка его опций и путь к файлу " +
                "библиотеки. " +
                (a.Dynamic
                    ? "Флаг «динамический» означает, что агент подключался не при запуске " +
                      "ВМ, а К УЖЕ РАБОТАЮЩЕЙ игре через Attach API. Лаунчер так не делает " +
                      "никогда: это ровно тот способ, которым в идущую игру заводят чит."
                    : a.DynamicKnown
                    ? "Агент указан в аргументах запуска виртуальной машины. Для клиента " +
                      "Minecraft это ненормально: лаунчер агентов не подключает."
                    : "Способ подключения по записи этого выпуска JDK не определяется: " +
                      "поля «динамический» в ней нет. Смотрите аргументы ВМ и объекты " +
                      "механизма attach.") +
                (a.OsLib != 0 && a.OsLibModule is null
                    ? " Дескриптор библиотеки ненулевой, но модуля по этому адресу больше " +
                      "нет — библиотека агента ВЫГРУЖЕНА, а запись о ней осталась."
                    : ""));
            f.Add("адрес записи", a.Address);
            f.Add("имя агента", a.Name ?? "-");
            f.Add("опции агента", a.Options ?? "-");
            f.Add("путь к библиотеке", a.OsLibPath ?? "-");
            f.Add("дескриптор библиотеки", a.OsLib == 0 ? "0 (не загружена)"
                : $"0x{a.OsLib:X}" + (a.OsLibModule is not null
                    ? $" → {a.OsLibModule}" : " → модуля с такой базой сейчас НЕТ"));
            f.Add("подключён динамически", !a.DynamicKnown
                ? "не определяется (в записи JDK до 21 нет такого поля)"
                : a.Dynamic ? "ДА (Attach API)" : "нет (аргумент запуска)");
            f.Add("библиотека java.lang.instrument", a.InstrumentLib ? "да" : "нет");
            f.Add("загружен сейчас", a.Loaded ? "да" : "нет");
            f.Add("указатель JPLIS", a.Jplis == 0 ? "-" : $"0x{a.Jplis:X}");
            if (a.Layout.Count > 0)
                f.Block("Восстановленная раскладка записи (опознание по природе полей, " +
                        "а не по фиксированным смещениям)",
                    string.Join("\n", a.Layout.Select(x => "  " + x)));
            if (a.Dump is not null)
                f.Block("Объект записи", HexDump.Format(a.Dump, a.Address));
            foreach (var n in a.Notes) f.Add("замечание", n);

            if (ctx.Dumper is not null)
            {
                string? p = ctx.Dumper.DumpRange(a.Address > 0x200 ? a.Address - 0x200 : a.Address,
                    0x1000, "agentrec", $"запись об агенте «{a.Name}» и её окрестность");
                if (p is not null) f.Add("дамп окрестности", p);
            }
        }
    }

    private static readonly (string Cls, bool AlwaysPresent, string Why)[] AttachClasses =
    {
        ("AttachOperation", true,
            "Объект операции, пришедшей в виртуальную машину ИЗВНЕ через механизм " +
            "подключения (Attach API). Такой объект создаётся на каждую команду: " +
            "«load» — загрузить агента, «properties», «threaddump» и другие. Имя " +
            "команды и её аргументы лежат в самом объекте."),
        ("Win32AttachOperation", true,
            "Реализация операции подключения для Windows: команда приходит через " +
            "именованный канал, который создаёт механизм attach. ВАЖНО о трактовке: " +
            "на Windows приёмник команд запускается вместе с виртуальной машиной " +
            "всегда и заранее размечает под очередь несколько таких объектов. " +
            "Проверено на чистом клиенте Minecraft: пустые объекты с заполнителями " +
            "«<noname>» и «<nopipe>» есть в любой игре и уликой не являются. Уликой " +
            "является ЗАПОЛНЕННОЕ имя команды."),
        ("JVMTIAgentLoadDCmd", false,
            "Команда jcmd «JVMTI.agent_load» — загрузка библиотеки агента в уже " +
            "работающую виртуальную машину по требованию извне. Объект самой команды " +
            "(не её фабрики) создаётся только в момент выполнения: штатный клиент " +
            "Minecraft таких команд не получает."),
        ("JVMTIDataDumpDCmd", false,
            "Команда jcmd «JVMTI.data_dump» — запрос дампа данных JVMTI. Объект " +
            "команды создаётся только при её выполнении."),
    };

    private static readonly string[] AttachCommands =
    {
        "load", "properties", "agentProperties", "datadump", "threaddump",
        "dumpheap", "inspectheap", "setflag", "printflag", "jcmd", "jvmtiagentload",
        "JVMTI.agent_load",
    };

    private static void FindAttachOperations(ScanContext ctx, ImageInMemory jvm, StringBuilder sb)
    {
        sb.AppendLine("ОБЪЕКТЫ МЕХАНИЗМА ПОДКЛЮЧЕНИЯ (поиск по точному адресу vtable из экспортов):");

        var wanted = new Dictionary<ulong, string>();
        foreach (var (cls, _, _) in AttachClasses)
        {
            var e = jvm.Pe.Exports.ByName($"??_7{cls}@@6B@");
            if (e is null)
            {
                sb.AppendLine($"  {cls,-28} таблица виртуальных функций не экспортирована");
                continue;
            }
            ulong vt = jvm.Base + e.Rva;
            wanted[vt] = cls;
            sb.AppendLine($"  {cls,-28} vtable 0x{vt:X}");
        }
        if (wanted.Count == 0) { sb.AppendLine(); return; }

        var found = new Dictionary<string, List<ulong>>(StringComparer.Ordinal);
        foreach (var ch in MemoryScan.Chunks(ctx, MemoryScan.PrivateAnyData))
        {
            var r = ch.Region;
            var buf = ch.Exact;
            ulong rbase = ch.Base;

            for (int i = 0; i + 8 <= buf.Length; i += 8)
            {
                ulong v = BitConverter.ToUInt64(buf, i);
                if (v == 0 || !wanted.TryGetValue(v, out var cls)) continue;
                if (!found.TryGetValue(cls, out var list)) found[cls] = list = new List<ulong>();
                if (list.Count < 64) list.Add(rbase + (ulong)i);
            }
        }

        foreach (var (cls, alwaysPresent, why) in AttachClasses)
        {
            if (!found.TryGetValue(cls, out var list) || list.Count == 0)
            {
                if (wanted.ContainsValue(cls)) sb.AppendLine($"  {cls,-28} объектов не найдено");
                continue;
            }

            sb.AppendLine($"  {cls,-28} НАЙДЕНО объектов: {list.Count}");

            var filled = new List<(ulong Addr, string Cmd, List<string> Strings)>();
            var empty = new List<(ulong Addr, List<string> Strings)>();
            foreach (ulong a in list)
            {
                var strings = HarvestObjectStrings(ctx, a);
                string? cmd = strings.FirstOrDefault(s =>
                    AttachCommands.Contains(s, StringComparer.OrdinalIgnoreCase));
                if (cmd is not null) filled.Add((a, cmd, strings));
                else empty.Add((a, strings));
                sb.AppendLine($"      0x{a:X}  {ctx.RegionAt(a)?.TypeString}/" +
                              $"{ctx.RegionAt(a)?.ProtectString}" +
                              (cmd is not null ? $"   КОМАНДА: «{cmd}»" : "   (имя команды пусто)"));
                if (strings.Count > 0)
                    sb.AppendLine("          строки внутри объекта: " +
                                  string.Join(" | ", strings.Take(8)));
            }

            Severity sev = filled.Count > 0 ? Severity.Critical
                : alwaysPresent ? Severity.Info
                : Severity.High;

            string title = filled.Count > 0
                ? $"В памяти найдено {filled.Count} объектов {cls} С ЗАПОЛНЕННЫМ именем " +
                  $"команды ({string.Join(", ", filled.Select(x => x.Cmd).Distinct())}) — " +
                  "к работающей виртуальной машине приходили команды извне"
                : $"В памяти найдено {list.Count} объектов {cls} без заполненного имени команды";

            var f = ctx.Report.Report("JVM", title, sev,
                why + (filled.Count > 0
                    ? " Здесь имя команды ЗАПОЛНЕНО: объект не просто размечен под " +
                      "очередь, а действительно нёс команду. Команда «load» — это " +
                      "загрузка библиотеки агента в идущую игру, и её аргумент содержит " +
                      "путь к этой библиотеке."
                    : " Заполненного имени команды ни в одном объекте нет, поэтому как " +
                      "улика это не засчитывается — приводится как справка."));
            f.Add("класс", cls);
            f.Add("объектов всего", list.Count.ToString());
            f.Add("из них с именем команды", filled.Count.ToString());

            foreach (var (a, cmd, strings) in filled.Take(16))
                f.Add($"объект 0x{a:X}", $"команда «{cmd}»; строки: " +
                                         string.Join(" | ", strings.Take(10)));
            foreach (var (a, strings) in empty.Take(8))
                f.Add($"объект 0x{a:X} (пустой)", strings.Count > 0
                    ? "строки: " + string.Join(" | ", strings.Take(6))
                    : ctx.RegionAt(a)?.ToString() ?? "-");

            ulong first = filled.Count > 0 ? filled[0].Addr : list[0];
            var dump = ctx.Target.ReadBytes(first, 512);
            if (dump is not null)
                f.Block($"Объект 0x{first:X}", HexDump.Format(dump, first));
        }
        sb.AppendLine();
    }

    private static List<string> HarvestObjectStrings(ScanContext ctx, ulong addr)
    {
        var res = new List<string>();
        var d = ctx.Target.ReadBytes(addr, 0x200);
        if (d is null) return res;

        var sb = new StringBuilder();
        foreach (byte b in d)
        {
            if (b is >= 0x20 and < 0x7F) sb.Append((char)b);
            else
            {
                if (sb.Length >= 3) res.Add(sb.ToString());
                sb.Clear();
            }
        }
        if (sb.Length >= 3) res.Add(sb.ToString());

        for (int i = 0; i + 8 <= d.Length; i += 8)
        {
            ulong p = BitConverter.ToUInt64(d, i);
            var s = JvmtiAgentProbe.ReadAscii(ctx, p, 256);
            if (s is { Length: >= 3 }) res.Add(s);
        }
        return res.Distinct().ToList();
    }

    private static readonly (string Needle, Severity Sev, string Why)[] AttachStrings =
    {
        ("JVMTI.agent_load", Severity.Info,
            "Имя команды загрузки агента в работающую ВМ (jcmd JVMTI.agent_load). " +
            "Строка попадает в кучу при построении реестра диагностических команд " +
            "на старте ЛЮБОЙ виртуальной машины, поэтому сама по себе уликой не " +
            "является — значим объект команды, а не её имя."),
        ("Dynamic agent loading", Severity.High,
            "Часть предупреждения ВМ о динамической загрузке агента: JDK 21 печатает " +
            "его при подключении агента к живой машине."),
        ("A JVM TI agent has been loaded dynamically", Severity.Critical,
            "Предупреждение виртуальной машины, которое печатается РОВНО ОДИН РАЗ — " +
            "при динамической загрузке агента JVMTI в работающую ВМ. Наличие этой " +
            "строки в памяти означает, что такая загрузка происходила."),
        ("-XX:+EnableDynamicAgentLoading", Severity.High,
            "Ключ, разрешающий динамическую загрузку агентов. Упоминается в тексте " +
            "предупреждения ВМ и в справке; сам по себе не улика, но идёт в паре."),
        ("sun.jvm.hotspot", Severity.Info,
            "Пакет Serviceability Agent. Имя есть в реестре модулей JDK, поэтому " +
            "встречается в куче любой игры — само по себе уликой не является."),
        ("com.sun.tools.attach", Severity.Info,
            "Пакет Attach API. Имя есть в реестре модулей JDK (модуль jdk.attach), " +
            "поэтому встречается в куче любой игры. Значимо не имя пакета, а " +
            "загруженные классы из него — их проверяет разбор байт-кода."),
        ("\\\\.\\pipe\\javatool", Severity.Critical,
            "Именованный канал механизма подключения Windows: через него внешний " +
            "процесс передаёт команды в работающую виртуальную машину."),
        ("attach_listener", Severity.High,
            "Внутреннее имя потока-приёмника команд подключения."),
    };

    private static void FindAgentStrings(ScanContext ctx, StringBuilder sb)
    {
        sb.AppendLine("СТРОКИ МЕХАНИЗМА ПОДКЛЮЧЕНИЯ В ПАМЯТИ ПРОЦЕССА:");

        var hits = new Dictionary<string, List<ulong>>(StringComparer.Ordinal);
        var needles = AttachStrings
            .Select(x => (x.Needle, Bytes: Encoding.ASCII.GetBytes(x.Needle)))
            .ToList();

        foreach (var ch in MemoryScan.Chunks(ctx,
                     r0 => MemoryScan.Readable(r0) && r0.IsPrivate && !r0.IsImage &&
                           r0.MappedFile is null && r0.MappedFileDos is null, overlap: 64))
        {
            var r = ch.Region;
            var buf = ch.Exact;
            ulong rbase = ch.Base;

            foreach (var (needle, bytes) in needles)
            {
                int pos = 0;
                while (pos < buf.Length)
                {
                    int idx = buf.AsSpan(pos).IndexOf(bytes);
                    if (idx < 0) break;
                    if (!hits.TryGetValue(needle, out var list)) hits[needle] = list = new List<ulong>();
                    if (list.Count < 32) list.Add(rbase + (ulong)(pos + idx));
                    pos += idx + bytes.Length;
                    if (list.Count >= 32) break;
                }
            }
        }

        foreach (var (needle, sev, why) in AttachStrings)
        {
            hits.TryGetValue(needle, out var list);
            int n = list?.Count ?? 0;
            sb.AppendLine($"  {needle,-46} {(n == 0 ? "нет" : $"НАЙДЕНО ×{n}")}");
            if (n == 0) continue;

            var f = ctx.Report.Report("JVM",
                $"В памяти процесса найдена строка «{needle}» ({n} вхождений в приватной памяти)",
                sev, why + " Строка найдена в ПРИВАТНОЙ памяти процесса — не в образе модуля " +
                     "и не в проекции файла JDK, а в рабочих данных: её туда положил " +
                     "выполнявшийся код.");
            foreach (ulong a in (list ?? new List<ulong>()).Take(16))
            {
                var ctxBytes = ctx.Target.ReadBytes(a > 64 ? a - 64 : a, 192);
                f.Add($"0x{a:X}", ctx.RegionAt(a)?.ToString() ?? "-");
                if (ctxBytes is not null && f.Blocks.Count < 6)
                    f.Block($"Окрестность 0x{a:X}",
                        HexDump.Format(ctxBytes, a > 64 ? a - 64 : a));
            }
        }
        sb.AppendLine();
    }
}
