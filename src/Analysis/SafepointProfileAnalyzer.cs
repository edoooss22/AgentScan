using System.Text;
using AgentScan.Core;
using AgentScan.Report;

namespace AgentScan.Analysis;

internal static class SafepointProfileAnalyzer
{
    private const string Cat = "JVM";

    private static readonly (string Name, string Means)[] AgentOnly =
    {
        ("RedefineClasses", "подмена байт-кода уже загруженного класса"),
        ("ChangeBreakpoints", "установка или снятие точки останова"),
        ("ChangeSingleStep", "пошаговое исполнение"),
        ("SetFramePop", "перехват возврата из кадра стека"),
        ("PopFrame", "принудительный выход из кадра стека"),
        ("ForceEarlyReturn", "принудительный возврат из метода"),
        ("GetOrSetLocal", "чтение или ЗАПИСЬ локальной переменной чужого кадра"),
        ("GetCurrentLocation", "опрос текущей точки исполнения потока"),
        ("EnterInterpOnlyMode", "перевод потока в режим только интерпретации"),
        ("GetAllStackTraces", "снятие стеков всех потоков"),
        ("GetThreadListStackTraces", "снятие стеков выбранных потоков"),
        ("GetMultipleStackTraces", "снятие стеков нескольких потоков"),
        ("GetStackTrace", "снятие стека потока"),
        ("GetObjectMonitorUsage", "опрос владельцев блокировки объекта"),
        ("GetOwnedMonitorInfo", "опрос блокировок, которыми владеет поток"),
        ("GetCurrentContendedMonitor", "опрос блокировки, которую ждёт поток"),
        ("HeapWalkOperation", "обход кучи средствами машины"),
        ("HeapIterateOperation", "обход кучи средствами машины"),
        ("ClassLoaderStats", "сбор статистики загрузчиков"),
        ("ClassLoaderHierarchy", "обход иерархии загрузчиков"),
        ("ThreadDump", "снятие полного дампа потоков"),
        ("FindDeadlocks", "поиск взаимных блокировок"),
        ("PrintThreads", "печать состояния потоков"),
        ("GetObjectSize", "опрос размера объекта средствами машины"),
    };

    private static readonly string[] Ordinary =
    {
        "G1Collect", "G1Pause", "CGC_Operation", "CMS", "ParallelGCFailedAllocation",
        "GenCollect", "Cleanup", "RendezvousGCThreads", "HandshakeAllThreads",
        "ICBufferFull", "Deoptimize", "ZOperation", "ShenandoahOperation",
        "JFRCheckpoint", "JFROldObject", "Exit", "PrintCompileQueue",
        "BulkRevokeBias", "HandshakeOneThread", "G1TryInitiateConcMark",
    };

    public static void Run(ScanContext ctx)
    {
        var sb = new StringBuilder();
        sb.AppendLine("ОПЕРАЦИИ В ТОЧКАХ БЕЗОПАСНОСТИ: АГЕНТ ПРОТИВ ЧТЕЦА СЫРОЙ ПАМЯТИ");
        sb.AppendLine();

        var ops = ctx.VmEvents
            .Where(e => e.Ring.Contains("VM Operation", StringComparison.OrdinalIgnoreCase) ||
                        e.Text.Contains("Executing VM operation", StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (ops.Count == 0)
        {
            sb.AppendLine("  Кольцо операций машины пусто или не найдено. Если оно не найдено —");
            sb.AppendLine("  смотрите раздел чёрного ящика: там сказано, выключены ли журналы");
            sb.AppendLine("  ключом запуска. Само отсутствие записей уликой не является: кольцо");
            sb.AppendLine("  небольшое, и на тихой игре в нём бывают только операции сборщика.");
            ctx.Report.Section("ТОЧКИ БЕЗОПАСНОСТИ: ПРОФИЛЬ ОПЕРАЦИЙ", sb.ToString());
            return;
        }

        var byName = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var e in ops)
        {
            string name = OperationName(e.Text);
            if (name.Length == 0) continue;
            byName[name] = byName.TryGetValue(name, out int c) ? c + 1 : 1;
        }

        int ordinary = 0, unknown = 0;
        var agentHits = new List<(string Name, int Count, string Means)>();
        var unknownNames = new List<string>();

        foreach (var (name, count) in byName.OrderByDescending(kv => kv.Value))
        {
            var agent = AgentOnly.FirstOrDefault(a =>
                name.Contains(a.Name, StringComparison.OrdinalIgnoreCase));
            if (agent.Name is not null)
            {
                agentHits.Add((name, count, agent.Means));
                continue;
            }
            if (Ordinary.Any(x => name.Contains(x, StringComparison.OrdinalIgnoreCase)))
            { ordinary += count; continue; }
            unknown += count;
            if (unknownNames.Count < 16) unknownNames.Add($"{name} ×{count}");
        }

        sb.AppendLine($"  записей об операциях в кольце : {ops.Count}");
        sb.AppendLine($"  различных имён операций       : {byName.Count}");
        sb.AppendLine($"  сборщик мусора и хозяйство   : {ordinary}");
        sb.AppendLine($"  ТОЛЬКО ОТ АГЕНТА ИЛИ ОТЛАДЧИКА: {agentHits.Sum(a => a.Count)} " +
                      $"({agentHits.Count} различных)");
        sb.AppendLine($"  имя не опознано               : {unknown}");
        sb.AppendLine();

        sb.AppendLine($"  {"ОПЕРАЦИЯ",-44} {"РАЗ",-6} ВИД");
        foreach (var (name, count) in byName.OrderByDescending(kv => kv.Value).Take(40))
        {
            string kind = agentHits.Any(a => a.Name == name) ? "АГЕНТ/ОТЛАДЧИК"
                        : Ordinary.Any(x => name.Contains(x, StringComparison.OrdinalIgnoreCase))
                            ? "сборщик/хозяйство" : "не опознано";
            sb.AppendLine($"  {Trim(name, 43),-44} {count,-6} {kind}");
        }
        if (byName.Count > 40) sb.AppendLine($"  … и ещё {byName.Count - 40} имён");
        sb.AppendLine();

        if (agentHits.Count > 0)
        {
            sb.AppendLine("  ОПЕРАЦИИ, КОТОРЫХ САМА ИГРА НЕ ВЫЗЫВАЕТ:");
            foreach (var (name, count, means) in agentHits)
                sb.AppendLine($"    {name} ×{count} — {means}");
            sb.AppendLine();
        }

        sb.AppendLine("  Как читать. Агент JVMTI останавливает мир штатно, и каждая остановка");
        sb.AppendLine("  попадает в это кольцо под своим именем.");

        if (agentHits.Count > 0)
        {
            var f = ctx.Report.Report(Cat,
                $"В кольце операций машины {agentHits.Sum(a => a.Count)} записей об операциях, " +
                $"которые бывают только от агента или отладчика ({agentHits.Count} различных)",
                Severity.High,
                "Операция в точке безопасности — это остановка всех потоков Java, которую " +
                "делает сама машина по чьей-то просьбе. Каждую она записывает в кольцо " +
                "«VM Operations» под собственным именем.\n\n" +
                "Перечисленные ниже имена игра не вызывает никогда: подмена байт-кода, " +
                "точки останова, пошаговое исполнение, чтение и запись локальных " +
                "переменных чужого кадра, снятие стеков всех потоков, обход кучи " +
                "средствами машины. Их вызывает агент JVMTI, отладчик или средство " +
                "наблюдения, подключённое к машине.\n\n" +
                "Запись из кольца не убрать: механизм существует ради отчёта о падении и " +
                "пишет безусловно, а кольцо переживает и отключение агента, и его " +
                "выгрузку. Вытеснить запись можно только шумом — и тогда видно, что кольцо " +
                "заполнено целиком.")
                .Add("записей об операциях всего", ops.Count.ToString())
                .Add("сборщик и хозяйство", ordinary.ToString());
            foreach (var (name, count, means) in agentHits.Take(20))
                f.Add(name, $"×{count} — {means}");
        }
        else
        {
            ctx.Report.Report(Cat,
                "Операций, свойственных агенту или отладчику, в кольце машины нет: " +
                $"из {ops.Count} записей все — сборщик мусора и хозяйство",
                Severity.Info,
                "Кольцо операций в точках безопасности разобрано по именам. Ни одной " +
                "операции, которую вызывает только агент JVMTI или отладчик, в нём нет.")
                .Add("записей об операциях", ops.Count.ToString())
                .Add("различных имён", byName.Count.ToString())
                .Add("не опознано имён", unknown.ToString());
        }

        if (unknownNames.Count > 0)
            sb.AppendLine($"  не опознанные имена: {string.Join(", ", unknownNames)}");

        ctx.Report.Section("ТОЧКИ БЕЗОПАСНОСТИ: ПРОФИЛЬ ОПЕРАЦИЙ", sb.ToString());
    }

    private static string OperationName(string text)
    {
        const string marker = "VM operation:";
        int i = text.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        string s = i >= 0 ? text[(i + marker.Length)..] : text;
        s = s.Trim();
        if (s.EndsWith(" done", StringComparison.OrdinalIgnoreCase)) s = s[..^5].TrimEnd();
        return s.Length > 120 ? s[..120] : s;
    }

    private static string Trim(string s, int max) => s.Length <= max ? s : s[..(max - 1)] + "…";
}
