using System.Text;
using AgentScan.Core;
using AgentScan.Report;

namespace AgentScan.Analysis;

internal static class VmEventLogAnalyzer
{
    private static readonly (string Name, string Handle, string What)[] Known =
    {
        ("Dll operation events", "dll",
            "загрузка и выгрузка нативных библиотек через ВМ"),
        ("Classes redefined", "redefine",
            "подмена классов на ходу (RedefineClasses / RetransformClasses)"),
        ("Classes unloaded", "unload", "выгрузка классов"),
        ("Classes loaded", "load", "загрузка классов"),
        ("Deoptimization events", "deopt", "деоптимизация скомпилированного кода"),
        ("Internal exceptions", "exc", "внутренние исключения ВМ"),
        ("VM Operations", "vmops", "операции ВМ в точках безопасности"),
        ("Nmethod flushes", "nmethodflushes", "выброс скомпилированных методов"),
        ("Memory protections", "memprotect", "смена прав доступа к памяти"),
        ("Events", "events", "общий журнал"),
        ("ZGC Phase Switch", "zgcps", "смена фаз сборщика ZGC"),
    };

    private sealed class LogRing
    {
        public string Name = "", Handle = "", What = "";
        public ulong Field;
        public int Length, Index, Count;
        public ulong Records;
        public int Stride, TextOffset;
        public bool HandleOk;
        public List<(double Ts, ulong Thread, string Text)> Entries = new();
    }

    private static int SelfPointerOffset(ScanContext ctx, ulong records)
    {
        var probe = ctx.Target.ReadBytes(records, 256);
        if (probe is null) return -1;
        for (int o = 0; o + 8 <= probe.Length && o <= 128; o += 8)
            if (BitConverter.ToUInt64(probe, o) == records + (ulong)o + 8) return o;
        return -1;
    }

    public static List<RawPattern> Prepare(ScanContext ctx)
    {
        var res = new List<RawPattern>();
        var jvm = JvmAnalyzer.FindJvm(ctx);
        if (jvm is null || !jvm.Pe.Valid) return res;

        var literals = FindLiterals(ctx, jvm,
            Known.Select(k => k.Name).Concat(Known.Select(k => k.Handle)).ToArray());

        foreach (var (name, handle, _) in Known)
        {
            if (!literals.TryGetValue(name, out var nameAddrs)) continue;
            literals.TryGetValue(handle, out var handleAddrs);

            foreach (ulong na in nameAddrs.Take(4))
            {
                var rp = new RawPattern
                {
                    Name = $"журнал ВМ «{name}» @ 0x{na:X}",
                    Bytes = BitConverter.GetBytes(na),
                    MaxHits = 64,
                };
                ctx.EventLogPatterns.Add((name, handle, na,
                    handleAddrs is { Count: > 0 } ? handleAddrs[0] : 0, rp));
                res.Add(rp);
            }
        }
        return res;
    }

    private static Dictionary<string, List<ulong>> FindLiterals(ScanContext ctx,
        ImageInMemory jvm, string[] wanted)
    {
        var res = new Dictionary<string, List<ulong>>(StringComparer.Ordinal);
        var needles = wanted.Distinct(StringComparer.Ordinal)
            .Select(w => (Text: w, Bytes: Encoding.ASCII.GetBytes(w)))
            .ToList();

        foreach (var sec in jvm.Pe.Sections)
        {
            if (sec.IsExecutable || sec.VirtualSize is 0 or > 64 * 1024 * 1024) continue;
            var buf = new byte[sec.VirtualSize];
            ulong va = jvm.Base + sec.VirtualAddress;
            if (ctx.Target.ReadPartial(va, buf, out _) <= 0) continue;

            foreach (var (text, bytes) in needles)
            {
                for (int i = 1; i + bytes.Length + 1 <= buf.Length; i++)
                {
                    if (buf[i - 1] != 0 || buf[i + bytes.Length] != 0) continue;
                    bool ok = true;
                    for (int k = 0; k < bytes.Length && ok; k++) ok = buf[i + k] == bytes[k];
                    if (!ok) continue;

                    if (!res.TryGetValue(text, out var list)) res[text] = list = new List<ulong>();
                    if (list.Count < 8) list.Add(va + (ulong)i);
                }
            }
        }
        return res;
    }

    public static void Run(ScanContext ctx, SweepResult sweep)
    {
        var sb = new StringBuilder();
        sb.AppendLine("ЧЁРНЫЙ ЯЩИК HOTSPOT: КОЛЬЦЕВЫЕ ЖУРНАЛЫ СОБЫТИЙ ВИРТУАЛЬНОЙ МАШИНЫ");
        sb.AppendLine();
        sb.AppendLine("Виртуальная машина ведёт одиннадцать кольцевых журналов того, что она");
        sb.AppendLine("делала: загрузка и выгрузка библиотек, загрузка, выгрузка и подмена");
        sb.AppendLine("классов, деоптимизации, внутренние исключения, операции ВМ. Каждая");
        sb.AppendLine("запись — текст с отметкой времени от запуска ВМ. Механизм включён по");
        sb.AppendLine("умолчанию и существует ради отчёта о падении, поэтому чит о нём обычно");
        sb.AppendLine("не знает и следов в нём не убирает.");
        sb.AppendLine();

        var jvm = JvmAnalyzer.FindJvm(ctx);
        if (jvm is null || !jvm.Pe.Valid)
        {
            sb.AppendLine("  jvm.dll в процессе не найдена — проверка не применима.");
            ctx.Report.Section("ВМ: ЖУРНАЛЫ СОБЫТИЙ (ЧЁРНЫЙ ЯЩИК)", sb.ToString());
            return;
        }

        CheckDisabled(ctx, sb);

        var rings = Locate(ctx, sweep, sb);
        if (rings.Count == 0)
        {
            sb.AppendLine("  Ни одного журнала найти не удалось.");
            sb.AppendLine();
            sb.AppendLine("  Это НЕ норма для работающей виртуальной машины: журналы заводятся");
            sb.AppendLine("  при её запуске и живут до конца процесса. Возможные причины: журналы");
            sb.AppendLine("  выключены ключом -XX:-LogEvents (см. выше), сплошной скан памяти");
            sb.AppendLine("  отключён и запасной поиск не дошёл до кучи C++, либо объекты журналов");
            sb.AppendLine("  затёрты.");
            ctx.Report.Report("ВМ",
                    "Кольцевые журналы событий виртуальной машины в памяти не найдены",
                    Severity.Medium,
                    "Журналы заводятся при запуске ВМ и существуют всё время работы " +
                    "процесса. Их отсутствие означает либо выключенный ключом механизм, " +
                    "либо затёртые объекты. И то и другое стоит разобрать вручную: " +
                    "выключать бортовой самописец виртуальной машины у обычного лаунчера " +
                    "нет никаких причин.")
                .Add("искали журналов", Known.Length.ToString())
                .Add("иголок зарегистрировано", ctx.EventLogPatterns.Count.ToString());
            ctx.Report.Section("ВМ: ЖУРНАЛЫ СОБЫТИЙ (ЧЁРНЫЙ ЯЩИК)", sb.ToString());
            return;
        }

        foreach (var r in rings) ReadEntries(ctx, r);

        foreach (var r in rings)
        {
            ctx.VmEventRings[r.Handle] = (r.Length, r.Entries.Count);
            foreach (var (ts, th, text) in r.Entries)
                ctx.VmEvents.Add((r.Handle, ts, th, text));
        }

        Render(ctx, rings, sb);

        Verdicts(ctx, rings, sb);

        ctx.Report.Section("ВМ: ЖУРНАЛЫ СОБЫТИЙ (ЧЁРНЫЙ ЯЩИК)", sb.ToString());
    }

    private static void CheckDisabled(ScanContext ctx, StringBuilder sb)
    {
        string cmd = ctx.Target.GetCommandLine() ?? "";
        bool off = cmd.Contains("-XX:-LogEvents", StringComparison.OrdinalIgnoreCase);
        bool tiny = cmd.Contains("LogEventsBufferEntries=0", StringComparison.OrdinalIgnoreCase) ||
                    cmd.Contains("LogEventsBufferEntries=1", StringComparison.OrdinalIgnoreCase);

        sb.AppendLine($"  журналы выключены ключом запуска : {(off ? "ДА (-XX:-LogEvents)" : "нет")}");
        sb.AppendLine($"  размер кольца урезан ключом      : {(tiny ? "ДА" : "нет")}");
        sb.AppendLine();

        if (!off && !tiny) return;

        ctx.Report.Report("ВМ",
                "Бортовой самописец виртуальной машины выключен ключом запуска",
                Severity.High,
                "В командной строке процесса стоит ключ, отключающий или обнуляющий " +
                "кольцевые журналы событий ВМ. Это диагностический механизм, включённый " +
                "по умолчанию; он не влияет ни на производительность игры, ни на её " +
                "поведение, и ни один штатный лаунчер его не трогает. Единственный смысл " +
                "его выключить — не оставлять записей о том, какие библиотеки и классы " +
                "загружались в процесс.")
            .Add("командная строка", JavaMeta.Clean(cmd, 600));
    }

    private static List<LogRing> Locate(ScanContext ctx, SweepResult sweep, StringBuilder sb)
    {
        var res = new List<LogRing>();
        var seen = new HashSet<ulong>();

        var candidates = new List<(string Name, string Handle, ulong NameAddr, ulong HandleAddr,
            List<ulong> At)>();

        bool fromSweep = ctx.EventLogPatterns.Count > 0 &&
                         ctx.EventLogPatterns.Any(p => p.Pattern.TotalHits > 0);

        if (fromSweep)
        {
            foreach (var p in ctx.EventLogPatterns)
                candidates.Add((p.Name, p.Handle, p.NameAddr, p.HandleAddr,
                    p.Pattern.Hits.Select(h => h.Addr).Where(a => (a & 7) == 0).ToList()));
            sb.AppendLine("  источник поиска : сплошной скан памяти");
        }
        else
        {
            var jvm = JvmAnalyzer.FindJvm(ctx);
            if (jvm is null) return res;
            var literals = FindLiterals(ctx, jvm,
                Known.Select(k => k.Name).Concat(Known.Select(k => k.Handle)).ToArray());

            var wanted = new Dictionary<ulong, (string Name, string Handle, ulong HandleAddr)>();
            foreach (var (name, handle, _) in Known)
            {
                if (!literals.TryGetValue(name, out var na) || na.Count == 0) continue;
                literals.TryGetValue(handle, out var ha);
                foreach (ulong a in na.Take(4))
                    wanted[a] = (name, handle, ha is { Count: > 0 } ? ha[0] : 0);
            }
            if (wanted.Count == 0) return res;

            var found = new Dictionary<ulong, List<ulong>>();
            foreach (var ch in MemoryScan.Chunks(ctx, MemoryScan.PrivateData))
                for (int i = 0; i + 8 <= ch.Length; i += 8)
                {
                    ulong v = BitConverter.ToUInt64(ch.Data, i);
                    if (v == 0 || !wanted.ContainsKey(v)) continue;
                    if (!found.TryGetValue(v, out var list)) found[v] = list = new List<ulong>();
                    ulong at = ch.Base + (ulong)i;
                    if (list.Count > 0 && list[^1] == at) continue;
                    if (list.Count < 256) list.Add(at);
                }

            foreach (var kv in found)
            {
                var w = wanted[kv.Key];
                candidates.Add((w.Name, w.Handle, kv.Key, w.HandleAddr, kv.Value));
            }
            sb.AppendLine("  источник поиска : отдельный проход по приватной памяти " +
                          "(сплошной скан отключён)");
        }

        var cache = new PageCache(ctx.Target, 4096);
        int examined = 0;

        foreach (var (name, handle, nameAddr, handleAddr, at) in candidates)
        {
            string what = Known.FirstOrDefault(k => k.Name == name).What ?? "";
            foreach (ulong field in at)
            {
                examined++;
                if (!seen.Add(field)) continue;

                LogRing? ring = null;
                for (int o = 8; o <= 64 && ring is null; o += 8)
                {
                    int length = (int)cache.U32(field + (ulong)o);
                    int index = (int)cache.U32(field + (ulong)o + 4);
                    int count = (int)cache.U32(field + (ulong)o + 8);
                    ulong records = cache.U64(field + (ulong)o + 16);

                    if (length is < 1 or > 1_000_000) continue;
                    if (index < 0 || index >= length) continue;
                    if (count < 0 || count > length) continue;
                    if (records is < 0x10000 or > 0x7FFFFFFFFFFF) continue;
                    if (SelfPointerOffset(ctx, records) < 0) continue;

                    ring = new LogRing
                    {
                        Name = name, Handle = handle, What = what,
                        Field = field, Length = length, Index = index, Count = count,
                        Records = records,
                        HandleOk = MatchesAscii(cache, cache.U64(field + 8), handle),
                    };
                }
                if (ring is null) continue;

                res.Add(ring);
                break;
            }
        }

        sb.AppendLine($"  проверено мест  : {examined}");
        sb.AppendLine($"  журналов найдено: {res.Count} из {Known.Length}");
        sb.AppendLine();

        sb.AppendLine($"{"ЖУРНАЛ",-24} {"ЛИТЕРАЛ",-12} {"МЕСТ",-6} {"ОПОЗНАН",-9} ПРИМЕЧАНИЕ");
        sb.AppendLine(new string('-', 100));
        foreach (var (name, handle, _) in Known)
        {
            var cand = candidates.Where(c => c.Name == name).ToList();
            bool literal = cand.Count > 0;
            int places = cand.Sum(c => c.At.Count);
            bool ok = res.Any(r => r.Name == name);
            string note = ok ? "" :
                !literal ? "строка-название не найдена в jvm.dll" :
                places == 0 ? "указателя на строку в памяти нет — журнал не создан" :
                "место найдено, но проверка полей не прошла";
            sb.AppendLine($"{name,-24} {(literal ? "есть" : "НЕТ"),-12} {places,-6} " +
                          $"{(ok ? "да" : "нет"),-9} {note}");
        }
        sb.AppendLine();
        return res;
    }

    private static bool MatchesAscii(PageCache c, ulong addr, string s)
    {
        if (addr is < 0x10000 or > 0x7FFFFFFFFFFF) return false;
        var buf = c.Read(addr, s.Length + 1);
        if (buf is null || buf[s.Length] != 0) return false;
        for (int i = 0; i < s.Length; i++) if (buf[i] != (byte)s[i]) return false;
        return true;
    }

    private static void ReadEntries(ScanContext ctx, LogRing r)
    {
        const int Probe = 8192;
        var probe = ctx.Target.ReadBytes(r.Records, Probe);
        if (probe is null) return;

        int self = SelfPointerOffset(ctx, r.Records);
        if (self < 0) return;

        int stride = -1;
        for (int o = self + 8; o + 8 <= Probe; o += 8)
            if (BitConverter.ToUInt64(probe, o) == r.Records + (ulong)o + 8)
            { stride = o - self; break; }
        if (stride is < 32 or > 8192) return;

        r.Stride = stride;
        r.TextOffset = self + 8;
        int textMax = stride - r.TextOffset + self - self;
        if (textMax is < 16 or > 8192) textMax = stride - r.TextOffset;

        long total = (long)stride * r.Length;
        if (total is <= 0 or > 64 * 1024 * 1024) return;
        var all = ctx.Target.ReadBytes(r.Records, (int)total);
        if (all is null) return;

        var order = new List<int>(r.Count);
        if (r.Count < r.Length) for (int i = 0; i < r.Count; i++) order.Add(i);
        else
        {
            for (int i = r.Index; i < r.Length; i++) order.Add(i);
            for (int i = 0; i < r.Index; i++) order.Add(i);
        }

        foreach (int slot in order)
        {
            int b = slot * stride;
            if (b + stride > all.Length) break;
            double ts = BitConverter.ToDouble(all, b + self - 16);
            ulong th = BitConverter.ToUInt64(all, b + self - 8);

            int t = b + r.TextOffset;
            int end = t;
            int limit = Math.Min(all.Length, b + stride);
            while (end < limit && all[end] != 0) end++;
            string text = Encoding.UTF8.GetString(all, t, end - t);

            if (text.Length == 0 && ts == 0) continue;
            r.Entries.Add((ts, th, Clean(text)));
        }
    }

    private static string Clean(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (char ch in s) sb.Append(ch is '\n' or '\r' ? ' ' : ch < 0x20 ? '.' : ch);
        return sb.ToString().TrimEnd();
    }

    private static void Render(ScanContext ctx, List<LogRing> rings, StringBuilder sb)
    {
        DateTime start = ctx.Target.StartTimeUtc;

        sb.AppendLine($"{"ЖУРНАЛ",-24} {"КОЛЬЦО",-8} {"ЗАПИСЕЙ",-9} {"ШАГ",-7} СМЫСЛ");
        sb.AppendLine(new string('-', 118));
        foreach (var r in rings.OrderBy(x => x.Name, StringComparer.Ordinal))
            sb.AppendLine($"{r.Name,-24} {r.Length,-8} {r.Entries.Count,-9} {r.Stride,-7} {r.What}");
        sb.AppendLine();

        foreach (var r in rings)
        {
            sb.AppendLine($"=== {r.Name} ({r.Handle}) — {r.What}");
            sb.AppendLine($"    объект: поле имени 0x{r.Field:X}, массив записей 0x{r.Records:X}, " +
                          $"кольцо {r.Length}, позиция {r.Index}, записей {r.Count}");
            if (r.Entries.Count == 0) sb.AppendLine("    (пусто)");
            foreach (var (ts, th, text) in r.Entries)
            {
                string wall = start == default
                    ? ""
                    : start.AddSeconds(ts).ToString("HH:mm:ss.fff") + " UTC  ";
                sb.AppendLine($"    +{ts,10:F3} с  {wall}поток 0x{th:X}  {text}");
            }
            sb.AppendLine();
        }
    }

    private static void Verdicts(ScanContext ctx, List<LogRing> rings, StringBuilder sb)
    {
        var byName = rings.ToDictionary(r => r.Name, r => r, StringComparer.Ordinal);

        WipedCheck(ctx, rings, sb);
        DllVerdict(ctx, byName, sb);
        RedefineVerdict(ctx, byName, sb);
        ClassVerdict(ctx, byName, sb);

        ctx.Report.Report("ВМ",
                $"Прочитан бортовой самописец виртуальной машины: {rings.Count} журналов, " +
                $"{rings.Sum(r => r.Entries.Count)} записей",
                Severity.Info,
                "Кольцевые журналы HotSpot: что виртуальная машина делала и когда. Записи " +
                "сделаны самой ВМ, а не восстановлены по обломкам, и у каждой есть отметка " +
                "времени от запуска. Раздел выводится целиком: это готовая хронология " +
                "работы процесса, по которой человек может сам сопоставить события с тем, " +
                "что нашли остальные проверки.")
            .Add("журналов", rings.Count.ToString())
            .Add("записей", rings.Sum(r => r.Entries.Count).ToString())
            .Block("Сводка по журналам", string.Join("\n", rings
                .Select(r => $"  {r.Name,-24} записей {r.Entries.Count,3} из {r.Length,-4} — {r.What}")));
    }

    private static void WipedCheck(ScanContext ctx, List<LogRing> rings, StringBuilder sb)
    {
        var loaded = rings.FirstOrDefault(r => r.Name == "Classes loaded");
        var vmops = rings.FirstOrDefault(r => r.Name == "VM Operations");
        double uptime = ctx.Target.StartTimeUtc == default
            ? 0 : (DateTime.UtcNow - ctx.Target.StartTimeUtc).TotalSeconds;

        var empty = new List<LogRing>();
        if (loaded is { Count: 0 }) empty.Add(loaded);
        if (vmops is { Count: 0 }) empty.Add(vmops);
        if (empty.Count == 0 || uptime < 60) return;

        sb.AppendLine("ПУСТЫЕ ЖУРНАЛЫ:");
        foreach (var r in empty) sb.AppendLine($"    {r.Name}");
        sb.AppendLine();

        ctx.Report.Report("ВМ",
                $"Журналы событий ВМ существуют, но пусты ({string.Join(", ", empty.Select(r => r.Name))})",
                Severity.Critical,
                "Загрузка классов и операции виртуальной машины идут непрерывно всё время " +
                "работы игры, поэтому у процесса, работающего больше минуты, эти кольца " +
                "заполнены всегда. Пустое кольцо при живом объекте журнала означает, что " +
                "содержимое затёрли намеренно: сама ВМ счётчик записей не обнуляет.")
            .Add("процесс работает, с", uptime.ToString("F0"))
            .Add("пустых журналов", empty.Count.ToString());
    }

    private static void DllVerdict(ScanContext ctx, Dictionary<string, LogRing> byName,
        StringBuilder sb)
    {
        if (!byName.TryGetValue("Dll operation events", out var r) || r.Entries.Count == 0) return;

        var loadedNow = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var im in ctx.Images)
        {
            loadedNow.Add(im.Name);
            if (im.Path is { Length: > 0 }) loadedNow.Add(Path.GetFileName(im.Path));
        }

        var unloads = new List<(double Ts, string Path)>();
        var gone = new List<(double Ts, string Path)>();
        var late = new List<(double Ts, string Path)>();

        double firstTs = r.Entries.Min(e => e.Ts);

        foreach (var (ts, _, text) in r.Entries)
        {
            string? path = ExtractPath(text);
            if (path is null) continue;
            string file = Path.GetFileName(path);
            bool isUnload = text.Contains("nloaded", StringComparison.Ordinal);

            if (isUnload) unloads.Add((ts, path));
            else if (!loadedNow.Contains(file)) gone.Add((ts, path));

            if (!isUnload && ts - firstTs > 60) late.Add((ts, path));
        }

        sb.AppendLine("РАЗБОР ЖУРНАЛА ОПЕРАЦИЙ С БИБЛИОТЕКАМИ:");
        sb.AppendLine($"    записей о выгрузке                         : {unloads.Count}");
        sb.AppendLine($"    загружено, но сейчас в процессе НЕТ        : {gone.Count}");
        sb.AppendLine($"    загружено позже чем через минуту от первой : {late.Count}");
        foreach (var (ts, p) in unloads) sb.AppendLine($"      выгрузка   +{ts,10:F3} с  {p}");
        foreach (var (ts, p) in gone) sb.AppendLine($"      нет сейчас +{ts,10:F3} с  {p}");
        foreach (var (ts, p) in late) sb.AppendLine($"      поздняя    +{ts,10:F3} с  {p}");
        sb.AppendLine();

        if (unloads.Count > 0)
            ctx.Report.Report("ВМ",
                    $"Виртуальная машина записала выгрузку {unloads.Count} нативных библиотек",
                    Severity.Critical,
                    "Запись «Unloaded dll» делает сама ВМ в момент, когда нативную " +
                    "библиотеку выгружают из процесса. Клиент Minecraft свои библиотеки " +
                    "не выгружает никогда: они грузятся на старте и живут до выхода из " +
                    "игры. Выгрузка означает, что в процесс загружали постороннюю " +
                    "библиотеку и убрали её — то самое «самоуничтожение», ради которого " +
                    "запускают сканер. Путь к файлу сохранён в записи целиком, даже если " +
                    "самого файла на диске уже нет.")
                .Add("записей", unloads.Count.ToString())
                .Block("Выгруженные библиотеки", string.Join("\n", unloads
                    .Select(u => $"  +{u.Ts:F3} с  {u.Path}")));

        if (gone.Count > 0)
            ctx.Report.Report("ВМ",
                    $"{gone.Count} библиотек значатся загруженными в журнале ВМ, но в процессе " +
                    "их сейчас нет",
                    Severity.Critical,
                    "Виртуальная машина записала загрузку библиотеки, а в списках " +
                    "загрузчика её больше нет. Это независимое от Windows свидетельство " +
                    "того, что модуль был в процессе и исчез: журнал ведёт ВМ, а списки " +
                    "модулей ведёт загрузчик образов, и подделывать пришлось бы оба. " +
                    "Сверьте путь с журналом выгруженных модулей ntdll и с находками по " +
                    "приватной исполняемой памяти.")
                .Add("библиотек", gone.Count.ToString())
                .Block("Библиотеки", string.Join("\n", gone
                    .Select(u => $"  +{u.Ts:F3} с  {u.Path}")));

        if (late.Count > 0)
            ctx.Report.Report("ВМ",
                    $"{late.Count} нативных библиотек загружены значительно позже остальных",
                    Severity.High,
                    "Игра загружает свои нативные библиотеки одной чередой при запуске и " +
                    "больше к ним не возвращается. Загрузка, отстоящая от начала этой " +
                    "череды больше чем на минуту, произошла уже во время игры. Само по " +
                    "себе это ещё не улика — так грузятся библиотеки голосового чата и " +
                    "части модов по требованию, — но путь и время видны точно, и их стоит " +
                    "сопоставить с остальными находками.")
                .Add("библиотек", late.Count.ToString())
                .Block("Библиотеки", string.Join("\n", late
                    .Select(u => $"  +{u.Ts:F3} с  {u.Path}")));
    }

    private static string? ExtractPath(string text)
    {
        int q1 = text.IndexOf('"');
        if (q1 >= 0)
        {
            int q2 = text.IndexOf('"', q1 + 1);
            if (q2 > q1 + 1) return text[(q1 + 1)..q2];
        }

        int dot = text.LastIndexOf(".dll", StringComparison.OrdinalIgnoreCase);
        if (dot < 0) dot = text.LastIndexOf(".so", StringComparison.OrdinalIgnoreCase);
        if (dot < 0) return null;

        int end = dot + (text[dot..].StartsWith(".dll", StringComparison.OrdinalIgnoreCase) ? 4 : 3);
        int start = end;
        while (start > 0 && text[start - 1] is not (' ' or '\t' or '"' or '[' or '(')) start--;
        string p = text[start..end].Trim();
        return p.Length >= 5 ? p : null;
    }

    private static void RedefineVerdict(ScanContext ctx, Dictionary<string, LogRing> byName,
        StringBuilder sb)
    {
        if (!byName.TryGetValue("Classes redefined", out var r) || r.Entries.Count == 0) return;

        sb.AppendLine($"РАЗБОР ЖУРНАЛА ПОДМЕНЫ КЛАССОВ: записей {r.Entries.Count}");
        foreach (var (ts, _, text) in r.Entries) sb.AppendLine($"    +{ts,10:F3} с  {text}");
        sb.AppendLine();

        ctx.Report.Report("ВМ",
                $"Виртуальная машина записала {r.Entries.Count} событий подмены классов на ходу",
                Severity.Critical,
                "Записи в этот журнал делает только RedefineClasses / RetransformClasses — " +
                "то есть агент JVMTI, подменяющий код уже загруженных классов. В отличие " +
                "от флагов IS_OLD у объектов Method, которые говорят лишь «подмена была», " +
                "здесь записаны ИМЕНА подменённых классов и ВРЕМЯ каждой подмены. " +
                "Единственная штатная причина таких записей — отладчик или профилировщик, " +
                "подключённый к игре.")
            .Add("событий", r.Entries.Count.ToString())
            .Block("Записи", string.Join("\n", r.Entries
                .Select(e => $"  +{e.Ts:F3} с  {e.Text}")));
    }

    private static void ClassVerdict(ScanContext ctx, Dictionary<string, LogRing> byName,
        StringBuilder sb)
    {
        if (ctx.Jars is null) return;

        foreach (string logName in new[] { "Classes loaded", "Classes unloaded" })
        {
            if (!byName.TryGetValue(logName, out var r) || r.Entries.Count == 0) continue;

            var foreign = new List<(double Ts, string Cls)>();
            foreach (var (ts, _, text) in r.Entries)
            {
                string? cls = ExtractClassName(text);
                if (cls is null) continue;
                if (JarIndex.IsRuntimeClass(cls)) continue;
                if (JarIndex.GeneratedKind(cls) is not null) continue;
                if (ctx.Jars.Contains(cls)) continue;
                foreign.Add((ts, cls));
            }

            sb.AppendLine($"РАЗБОР ЖУРНАЛА «{logName}»: записей {r.Entries.Count}, " +
                          $"классов вне архивов {foreign.Count}");
            foreach (var (ts, cls) in foreign) sb.AppendLine($"    +{ts,10:F3} с  {cls}");
            sb.AppendLine();

            if (foreign.Count == 0) continue;

            bool unload = logName == "Classes unloaded";
            ctx.Report.Report("ВМ",
                    $"В журнале «{logName}» {foreign.Count} классов, которых нет ни в одном " +
                    "архиве, доступном игре",
                    unload ? Severity.Critical : Severity.High,
                    (unload
                        ? "Виртуальная машина записала ВЫГРУЗКУ этих классов. Выгрузка " +
                          "происходит, когда умирает загрузчик, который их определил, — " +
                          "то есть код был загружен динамически и убран за собой. "
                        : "Виртуальная машина записала загрузку этих классов. ") +
                    "При этом байт-кода этих классов нет ни в одном jar-архиве из пути " +
                    "классов игры, они не принадлежат рантайму Java и не порождены самой " +
                    "ВМ. Запись сделана самой виртуальной машиной и содержит время — это " +
                    "прямое свидетельство, а не восстановление по обломкам.")
                .Add("классов", foreign.Count.ToString())
                .Add("архивов в индексе", ctx.Jars.Jars.Count.ToString())
                .Block("Классы", string.Join("\n", foreign
                    .Select(f => $"  +{f.Ts:F3} с  {f.Cls}")));
        }
    }

    private static string? ExtractClassName(string text)
    {
        int q1 = text.IndexOf('\'');
        if (q1 >= 0)
        {
            int q2 = text.IndexOf('\'', q1 + 1);
            if (q2 > q1 + 1) return text[(q1 + 1)..q2].Replace('.', '/');
        }

        const string p = "class ";
        int i = text.IndexOf(p, StringComparison.Ordinal);
        if (i < 0) return null;
        string rest = text[(i + p.Length)..].Trim();
        int sp = rest.IndexOf(' ');
        if (sp > 0) rest = rest[..sp];
        if (rest.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) return null;
        rest = rest.Replace('.', '/');
        return rest.Length is >= 3 and <= 512 ? rest : null;
    }
}
