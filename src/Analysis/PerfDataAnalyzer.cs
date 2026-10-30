using System.Text;
using AgentScan.Core;
using AgentScan.Report;

namespace AgentScan.Analysis;

internal static class PerfDataAnalyzer
{
    private const string Nl = "\n";

    private sealed class Counter
    {
        public string Name = "";
        public string Text = "";
        public long Value;
        public bool IsString;
        public char Type;
    }

    private const uint Magic = 0xCAFEC0C0;
    private const uint MagicSwapped = 0xC0C0FECA;

    private static bool IsPerfHeader(ScanContext ctx, ulong at)
    {
        uint v = ctx.Target.ReadU32(at);
        return v == Magic || v == MagicSwapped;
    }

    public static void Run(ScanContext ctx)
    {
        var sb = new StringBuilder();
        sb.AppendLine("СЧЁТЧИКИ ПРОИЗВОДИТЕЛЬНОСТИ ВИРТУАЛЬНОЙ МАШИНЫ (hsperfdata)");
        sb.AppendLine();
        sb.AppendLine("Виртуальная машина ведёт эту область сама и заполняет её при запуске.");
        sb.AppendLine("Здесь лежит её СОБСТВЕННАЯ копия командной строки и пути классов —");
        sb.AppendLine("независимая от блока параметров процесса, который доступен на запись");
        sb.AppendLine("любому коду внутри процесса.");
        sb.AppendLine();

        ulong at = Find(ctx, out string source);
        sb.AppendLine($"  область счётчиков : {(at == 0 ? "НЕ НАЙДЕНА" : $"0x{at:X}")}  {source}");

        if (at == 0)
        {
            sb.AppendLine();
            sb.AppendLine("  Область не найдена. Это не норма: виртуальная машина создаёт её при");
            sb.AppendLine("  запуске всегда, если её не отключили ключом -XX:-UsePerfData.");
            ReportMissing(ctx);
            ctx.Report.Section("ВМ: СЧЁТЧИКИ ПРОИЗВОДИТЕЛЬНОСТИ", sb.ToString());
            return;
        }

        var counters = Parse(ctx, at, sb);
        if (counters.Count == 0)
        {
            ctx.Report.Section("ВМ: СЧЁТЧИКИ ПРОИЗВОДИТЕЛЬНОСТИ", sb.ToString());
            return;
        }

        var byName = new Dictionary<string, Counter>(StringComparer.Ordinal);
        foreach (var c in counters) byName[c.Name] = c;

        Render(counters, sb);
        CheckCommandLine(ctx, byName, sb);

        ctx.Report.Section("ВМ: СЧЁТЧИКИ ПРОИЗВОДИТЕЛЬНОСТИ", sb.ToString());
    }

    private static ulong Find(ScanContext ctx, out string source)
    {
        foreach (var r in ctx.Regions)
        {
            if (!r.IsCommitted || r.IsImage) continue;
            string? f = r.MappedFileDos ?? r.MappedFile;
            if (f is null || !f.Contains("hsperfdata", StringComparison.OrdinalIgnoreCase)) continue;
            if (!IsPerfHeader(ctx, r.Base)) continue;
            source = "(по имени отображённого файла: " + f + ")";
            return r.Base;
        }

        foreach (var r in ctx.Regions)
        {
            if (!r.IsCommitted || r.IsImage || r.IsPrivate) continue;
            if (r.Size is < 0x1000 or > 0x100000) continue;
            if (!IsPerfHeader(ctx, r.Base)) continue;
            source = "(по магическому числу; имя отображённого файла недоступно)";
            return r.Base;
        }

        source = "";
        return 0;
    }

    private static void ReportMissing(ScanContext ctx)
    {
        string cmd = ctx.Target.GetCommandLine() ?? "";
        bool off = cmd.Contains("-XX:-UsePerfData", StringComparison.OrdinalIgnoreCase) ||
                   cmd.Contains("PerfDisableSharedMem", StringComparison.OrdinalIgnoreCase);

        ctx.Report.Report("ВМ",
                off
                    ? "Счётчики производительности ВМ отключены ключом запуска"
                    : "Область счётчиков производительности ВМ в памяти не найдена",
                off ? Severity.Medium : Severity.High,
                "Виртуальная машина создаёт область счётчиков при запуске всегда, если её " +
                "не отключили ключом -XX:-UsePerfData или -XX:+PerfDisableSharedMem. В ней " +
                "лежит собственная копия командной строки ВМ — единственный источник, " +
                "независимый от блока параметров процесса, который доступен на запись " +
                "изнутри. Отключение этой области само по себе не влияет ни на " +
                "производительность игры, ни на её поведение; единственный смысл — убрать " +
                "возможность сверить, как процесс запускали на самом деле.")
            .Add("командная строка", JavaMeta.Clean(cmd, 500));
    }

    private static List<Counter> Parse(ScanContext ctx, ulong at, StringBuilder sb)
    {
        var res = new List<Counter>();

        var head = ctx.Target.ReadBytes(at, 32);
        if (head is null) return res;

        byte major = head[5], minor = head[6], accessible = head[7];
        int used = BitConverter.ToInt32(head, 8);
        int overflow = BitConverter.ToInt32(head, 12);
        long modTs = BitConverter.ToInt64(head, 16);
        int entryOffset = BitConverter.ToInt32(head, 24);
        int numEntries = BitConverter.ToInt32(head, 28);

        sb.AppendLine($"  версия формата    : {major}.{minor}, доступна: {accessible}");
        sb.AppendLine($"  занято            : {used} байт, переполнение {overflow}");
        sb.AppendLine($"  записей           : {numEntries}, первая по смещению {entryOffset}");
        sb.AppendLine();

        if (numEntries is <= 0 or > 100_000 || entryOffset is < 32 or > 1 << 20 ||
            used is <= 0 or > 64 * 1024 * 1024)
        {
            sb.AppendLine("  заголовок неправдоподобен — разбор не выполнялся.");
            return res;
        }

        var blob = ctx.Target.ReadBytes(at, Math.Min(used + 4096, 8 * 1024 * 1024));
        if (blob is null) return res;

        int pos = entryOffset;
        for (int i = 0; i < numEntries && pos + 20 <= blob.Length; i++)
        {
            int entryLength = BitConverter.ToInt32(blob, pos);
            int nameOffset = BitConverter.ToInt32(blob, pos + 4);
            int vectorLength = BitConverter.ToInt32(blob, pos + 8);
            char dataType = (char)blob[pos + 12];
            int dataOffset = BitConverter.ToInt32(blob, pos + 16);

            if (entryLength is <= 0 or > 1 << 16) break;
            if (pos + entryLength > blob.Length) break;
            if (nameOffset is < 0 || dataOffset < 0 ||
                pos + nameOffset >= blob.Length || pos + dataOffset >= blob.Length)
            { pos += entryLength; continue; }

            var c = new Counter { Name = Cstr(blob, pos + nameOffset, 256), Type = dataType };
            if (c.Name.Length == 0) { pos += entryLength; continue; }

            if (vectorLength > 0)
            {
                c.IsString = true;
                int len = Math.Min(vectorLength, blob.Length - (pos + dataOffset));
                c.Text = len > 0 ? Cstr(blob, pos + dataOffset, len) : "";
            }
            else if (pos + dataOffset + 8 <= blob.Length)
            {
                c.Value = BitConverter.ToInt64(blob, pos + dataOffset);
            }

            res.Add(c);
            pos += entryLength;
        }

        sb.AppendLine($"  разобрано счётчиков: {res.Count} " +
                      $"(строковых {res.Count(x => x.IsString)})");
        sb.AppendLine($"  метка изменения    : {modTs}");
        sb.AppendLine();
        return res;
    }

    private static string Cstr(byte[] b, int from, int max)
    {
        int n = 0;
        while (n < max && from + n < b.Length && b[from + n] != 0) n++;
        return n == 0 ? "" : Encoding.UTF8.GetString(b, from, n);
    }

    private static void Render(List<Counter> counters, StringBuilder sb)
    {
        var strings = counters.Where(c => c.IsString).OrderBy(c => c.Name, StringComparer.Ordinal).ToList();
        if (strings.Count > 0)
        {
            sb.AppendLine("СТРОКОВЫЕ СЧЁТЧИКИ (собственные данные ВМ о своём запуске):");
            foreach (var c in strings)
                sb.AppendLine($"  {c.Name,-46} {JavaMeta.Clean(c.Text, 600)}");
            sb.AppendLine();
        }

        sb.AppendLine("ЧИСЛОВЫЕ СЧЁТЧИКИ:");
        foreach (var c in counters.Where(x => !x.IsString)
                     .OrderBy(x => x.Name, StringComparer.Ordinal))
            sb.AppendLine($"  {c.Name,-56} {c.Value}");
        sb.AppendLine();
    }

    private static void CheckCommandLine(ScanContext ctx, Dictionary<string, Counter> byName,
        StringBuilder sb)
    {
        string peb = ctx.Target.GetCommandLine() ?? "";

        string vmCommand = Get(byName, "sun.rt.javaCommand");
        string vmArgs = Get(byName, "java.rt.vmArgs");
        string vmFlags = Get(byName, "java.rt.vmFlags");
        if (vmFlags.Length == 0) vmFlags = Get(byName, "sun.rt.vmFlags");
        string classPath = Get(byName, "java.property.java.class.path");
        string libPath = Get(byName, "java.property.java.library.path");

        string argFile = "";
        foreach (string tok in peb.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            string t = tok.Trim('"');
            if (t.StartsWith("@", StringComparison.Ordinal) && t.Length > 1) argFile = t;
        }

        sb.AppendLine("СВЕРКА АРГУМЕНТОВ ЗАПУСКА");
        sb.AppendLine($"  блок параметров процесса : {JavaMeta.Clean(peb, 400)}");
        sb.AppendLine($"  sun.rt.javaCommand       : {JavaMeta.Clean(vmCommand, 400)}");
        sb.AppendLine($"  java.rt.vmArgs           : {JavaMeta.Clean(vmArgs, 900)}");
        if (vmFlags.Length > 0)
            sb.AppendLine($"  java.rt.vmFlags          : {JavaMeta.Clean(vmFlags, 400)}");
        if (classPath.Length > 0)
            sb.AppendLine($"  путь классов у ВМ        : {JavaMeta.Clean(classPath, 900)}");
        if (libPath.Length > 0)
            sb.AppendLine($"  путь библиотек у ВМ      : {JavaMeta.Clean(libPath, 400)}");
        sb.AppendLine($"  файл аргументов          : {(argFile.Length > 0 ? argFile : "не используется")}");
        sb.AppendLine();

        var agents = new List<string>();
        foreach (string src in new[] { vmArgs, vmFlags, vmCommand })
            foreach (string tok in src.Split(' ', StringSplitOptions.RemoveEmptyEntries))
                if (tok.StartsWith("-javaagent", StringComparison.OrdinalIgnoreCase) ||
                    tok.StartsWith("-agentlib", StringComparison.OrdinalIgnoreCase) ||
                    tok.StartsWith("-agentpath", StringComparison.OrdinalIgnoreCase))
                    agents.Add(tok);

        if (agents.Count > 0)
            ctx.Report.Report("ВМ",
                    $"По собственным счётчикам виртуальной машины она запущена с агентом " +
                    $"({agents.Count} шт.)",
                    Severity.Critical,
                    "Ключ агента виден в счётчиках, которые виртуальная машина заполнила " +
                    "при старте своими значениями. Это независимо от блока параметров " +
                    "процесса, который правится изнутри, и от файла аргументов, который " +
                    "можно подменить на диске после запуска. Агент Java получает право " +
                    "переписывать байт-код любого класса игры на лету.")
                .Add("агентов", agents.Count.ToString())
                .Add("блок параметров", JavaMeta.Clean(peb, 500))
                .Block("Ключи", string.Join(Nl, agents.Select(a => "  " + a)));

        if (argFile.Length > 0)
        {
            sb.AppendLine("  Пословная сверка не выполнялась: аргументы ВМ переданы файлом,");
            sb.AppendLine("  и в блоке параметров процесса их нет по устройству запуска.");
            sb.AppendLine();

            ctx.Report.Report("ВМ",
                    "Аргументы виртуальной машины переданы файлом — сверить их с блоком " +
                    "параметров процесса нельзя",
                    Severity.Info,
                    "В командной строке процесса стоит ссылка на файл аргументов, поэтому " +
                    "самих аргументов там нет и расхождение с копией ВМ ничего не значило " +
                    "бы. Настоящие аргументы виртуальной машины показаны выше по её " +
                    "собственным счётчикам — именно их и надо читать, а не командную " +
                    "строку процесса.")
                .Add("файл аргументов", argFile)
                .Add("java.rt.vmArgs", JavaMeta.Clean(vmArgs, 900))
                .Add("sun.rt.javaCommand", JavaMeta.Clean(vmCommand, 500));
            return;
        }

        var missing = new List<string>();
        foreach (string src in new[] { vmCommand, vmArgs })
            foreach (string tok in src.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            {
                if (tok.Length < 6) continue;
                if (peb.Contains(tok, StringComparison.OrdinalIgnoreCase)) continue;
                if (!missing.Contains(tok)) missing.Add(tok);
            }

        sb.AppendLine($"  слов из копии ВМ, отсутствующих в блоке параметров: {missing.Count}");
        sb.AppendLine();

        var f = ctx.Report.Report("ВМ",
            missing.Count == 0
                ? "Копия аргументов запуска у ВМ сходится с блоком параметров процесса"
                : $"Копия аргументов у ВМ расходится с блоком параметров процесса " +
                  $"({missing.Count} слов)",
            missing.Count == 0 ? Severity.Info : Severity.High,
            "Всё, что сканер знает о запуске игры, он читает из блока параметров " +
            "процесса. Этот блок лежит в памяти процесса, и любой код внутри может его " +
            "переписать: убрать оттуда «-javaagent:…» — одна операция. Виртуальная " +
            "машина же заполнила свои счётчики при старте собственными значениями и " +
            "больше их не трогает. Расхождение означает, что блок параметров правили — " +
            "а править его незачем никому, кроме того, кто прячет способ запуска.");
        f.Add("sun.rt.javaCommand", JavaMeta.Clean(vmCommand, 500))
            .Add("java.rt.vmArgs", JavaMeta.Clean(vmArgs, 900))
            .Add("блок параметров", JavaMeta.Clean(peb, 500));
        if (missing.Count > 0)
            f.Block("Слова, которых нет в блоке параметров",
                string.Join(Nl, missing.Take(40).Select(x => "  " + x)));
    }

    private static string Get(Dictionary<string, Counter> byName, string key) =>
        byName.TryGetValue(key, out var c) ? (c.IsString ? c.Text : c.Value.ToString()) : "";
}
