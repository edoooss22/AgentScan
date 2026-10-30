using System.Text;
using AgentScan.Core;
using AgentScan.Report;

namespace AgentScan.Analysis;

internal static class JvmExtraAnalyzer
{
    public static void Run(ScanContext ctx, SweepResult sweep)
    {
        CheckJavaVmTable(ctx);
        if (sweep.Classes.Count > 0) CheckRedefinedClasses(ctx, sweep);
    }

    private static void CheckJavaVmTable(ScanContext ctx)
    {
        var jvm = JvmAnalyzer.FindJvm(ctx);
        if (jvm is null || !jvm.Pe.Valid) return;

        var text = jvm.Pe.Sections.Where(s => s.IsExecutable).ToList();
        ulong lo = jvm.Base, hi = jvm.Base + jvm.Size;
        bool InText(ulong p)
        {
            if (p < lo || p >= hi) return false;
            uint rva = (uint)(p - lo);
            return text.Any(s => rva >= s.VirtualAddress && rva < s.VirtualAddress + s.VirtualSize);
        }

        var sb = new StringBuilder();
        int found = 0;

        foreach (var sec in jvm.Pe.Sections)
        {
            if (sec.IsExecutable || sec.Name is not (".rdata" or ".data")) continue;
            if (sec.VirtualSize is 0 or > 64 * 1024 * 1024) continue;
            var buf = new byte[sec.VirtualSize];
            ctx.Target.ReadPartial(jvm.Base + sec.VirtualAddress, buf, out _);
            ulong secVa = jvm.Base + sec.VirtualAddress;

            for (int i = 0; i + 8 * 8 <= buf.Length; i += 8)
            {
                if (BitConverter.ToUInt64(buf, i) != 0) continue;
                if (BitConverter.ToUInt64(buf, i + 8) != 0) continue;
                if (BitConverter.ToUInt64(buf, i + 16) != 0) continue;

                var slots = new ulong[5];
                int inText = 0, foreign = 0;
                bool bad = false;
                for (int k = 0; k < 5; k++)
                {
                    slots[k] = BitConverter.ToUInt64(buf, i + 24 + k * 8);
                    if (InText(slots[k])) { inText++; continue; }
                    var r = ctx.RegionAt(slots[k]);
                    if (r is null || !r.IsCommitted || !r.IsExecutable) { bad = true; break; }
                    foreign++;
                }
                if (bad || inText < 4 || inText + foreign != 5) continue;
                if (i + 64 + 8 <= buf.Length && InText(BitConverter.ToUInt64(buf, i + 64))) continue;

                ulong addr = secVa + (ulong)i;
                found++;
                sb.AppendLine($"  0x{addr:X}  внутрь jvm.dll: {inText}/5, наружу: {foreign}");
                string[] names =
                {
                    "DestroyJavaVM", "AttachCurrentThread", "DetachCurrentThread",
                    "GetEnv", "AttachCurrentThreadAsDaemon",
                };
                for (int k = 0; k < 5; k++)
                    sb.AppendLine($"      {names[k],-28} {ctx.Describe(slots[k])}");

                if (foreign == 0) continue;

                var f = ctx.Report.Report("JVM",
                    $"Таблица JNIInvokeInterface_ (JavaVM) по 0x{addr:X}: {foreign} слотов " +
                    "ведут за пределы jvm.dll",
                    Severity.Critical,
                    "Через таблицу JavaVM нативный код получает доступ к JVM " +
                    "(AttachCurrentThread → JNIEnv). Все её слоты обязаны указывать на код " +
                    "jvm.dll. Слот, ведущий наружу, — перехват точки входа в JVM: ровно то, " +
                    "что делает нативный чит, чтобы работать с игровыми объектами.");
                f.Add("адрес таблицы", addr);
                for (int k = 0; k < 5; k++)
                    f.Add(names[k], $"0x{slots[k]:X} → {ctx.Describe(slots[k])}");
                if (found > 8) return;
            }
        }

        ctx.Report.Section("ТАБЛИЦА JavaVM (JNIInvokeInterface_)",
            found == 0 ? "Кандидатов не найдено." : sb.ToString());
    }

    private static void CheckRedefinedClasses(ScanContext ctx, SweepResult sweep)
    {
        var dup = sweep.Classes.Values.Where(c => c.Occurrences > 1)
            .OrderByDescending(c => c.Occurrences).ToList();
        if (dup.Count == 0) return;

        var mc = dup.Where(c => c.Name.StartsWith("net/minecraft/", StringComparison.Ordinal) ||
                                c.Name.StartsWith("com/mojang/", StringComparison.Ordinal))
                    .ToList();

        var sb = new StringBuilder();
        foreach (var c in dup.Take(300))
            sb.AppendLine($"  ×{c.Occurrences,-3} {c.Name}   " +
                          string.Join(", ", c.AllAddresses.Take(6).Select(a => $"0x{a:X}")));

        ctx.Report.Report("JAVA",
                $"{dup.Count} классов присутствуют в памяти в нескольких экземплярах " +
                $"(из них классов игры: {mc.Count})",
                Severity.Info,
                "Байт-код одного класса, лежащий в памяти несколько раз, — типичный след " +
                "трансформации: агент через ClassFileTransformer получает исходные байты, " +
                "возвращает изменённые, и в куче остаются обе версии. То же даёт " +
                "RedefineClasses/RetransformClasses. Дубли бывают и штатно (кеши загрузчика " +
                "классов, Mixin у Fabric при сборке классов), поэтому смотрите на ИМЕНА: " +
                "дублирование классов net/minecraft/* — то, что делает Java-чит, " +
                "патчащий игру на лету.")
            .Add("всего дублей", dup.Count.ToString())
            .Add("из них классы игры", mc.Count.ToString())
            .Block("Классы", sb.ToString().TrimEnd());
    }

    private static bool IsWeird(char c) =>
        !(c is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9'
            or '_' or '$' or '/' or '[' or ']' or ';' or '.' or '-' or '+');

    private static string Escape(string s)
    {
        var sb = new StringBuilder();
        foreach (char c in s) sb.Append(IsWeird(c) ? $"\\x{(int)c:X2}" : c.ToString());
        return sb.ToString();
    }

    private static readonly string[] TempMarkers =
    {
        @"\temp\", @"\tmp\", @"\appdata\local\temp", @"\downloads\", @"\windows\temp",
        @"\users\public\", @"\desktop\", @"\recycle",
    };

    private static void Report(ScanContext ctx, List<KeyValuePair<string, int>> items,
        string kind, string why)
    {
        if (items.Count == 0) return;
        var sb = new StringBuilder();
        foreach (var kv in items.Take(300))
        {
            bool exists = false;
            try { exists = File.Exists(kv.Key); } catch { }
            string low = kv.Key.ToLowerInvariant();
            string mark = TempMarkers.Any(m => low.Contains(m)) ? "  [ВРЕМЕННЫЙ КАТАЛОГ]" : "";
            sb.AppendLine($"  ×{kv.Value,-4} {(exists ? "есть на диске" : "НЕТ на диске "),-14} " +
                          $"{kv.Key}{mark}");
        }

        bool temp = items.Any(kv => TempMarkers.Any(m => kv.Key.ToLowerInvariant().Contains(m)));
        ctx.Report.Report("ФАЙЛЫ",
                $"В памяти найдено {items.Count} путей {kind} вне известных каталогов" +
                (temp ? " (есть пути во временных каталогах)" : ""),
                temp ? Severity.High : Severity.Medium, why)
            .Block("Пути", sb.ToString().TrimEnd());
    }
}
