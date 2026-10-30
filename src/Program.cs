using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using AgentScan.Analysis;
using AgentScan.Core;
using AgentScan.Report;

namespace AgentScan;

internal static class Program
{
    public const string Version = "1.2";
    public const string Tool = "AgentScan";

    [STAThread]
    private static int Main(string[] args)
    {
        if (args.Length == 0)
        {
            EnableDebugPrivilege();
            Gui.MainForm.RunApp();
            return 0;
        }

        AttachConsole(AttachParentProcess);
        try { Console.OutputEncoding = Encoding.UTF8; } catch { }

        var opt = Options.Parse(args);
        if (opt.ShowHelp) { Options.PrintHelp(); return 0; }

        if (!EnableDebugPrivilege())
            Console.Error.WriteLine(
                "ВНИМАНИЕ: не удалось включить SeDebugPrivilege. Запустите сканер от " +
                "администратора — иначе процесс другого пользователя недоступен, а часть " +
                "данных о потоках не читается.");

        if (opt.ListOnly)
        {
            PrintCandidates();
            return 0;
        }

        int pid = opt.Pid;
        if (pid <= 0)
        {
            var cands = ProcessTarget.FindJavaProcesses();
            var mc = cands.Where(c => c.LooksLikeMinecraft).ToList();
            if (mc.Count == 0)
            {
                Console.Error.WriteLine("Не найден процесс Minecraft (java/javaw). " +
                                        "Укажите PID вручную: --pid <N>");
                PrintCandidates();
                return 2;
            }
            if (mc.Count > 1)
            {
                Console.Error.WriteLine("Найдено несколько подходящих процессов, укажите --pid:");
                foreach (var c in mc)
                    Console.Error.WriteLine($"  PID {c.Pid}  {c.Name}  ({c.Reason})");
                return 2;
            }
            pid = mc[0].Pid;
        }

        ScanOutcome res;
        try
        {
            res = ScanRunner.Run(pid, opt);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Фатальная ошибка: {ex}");
            return 3;
        }

        var console = new ConsoleWriter(opt.Verbose);
        console.Write(res.Report, res.Elapsed);

        Console.WriteLine();
        foreach (var line in res.Log) Console.WriteLine(line);
        foreach (var line in res.Errors) Console.Error.WriteLine(line);

        return ScanRunner.ExitCode(res.Report);
    }

    private const int AttachParentProcess = -1;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AttachConsole(int dwProcessId);

    internal static bool EnableDebugPrivilege()
    {
        bool ok = Native.NativeApi.EnablePrivilege("SeDebugPrivilege");
        Core.SelfProcess.HasDebugPrivilege = ok;
        return ok;
    }

    private static void PrintCandidates()
    {
        Console.WriteLine("Java-процессы в системе:");
        foreach (var c in ProcessTarget.FindJavaProcesses())
        {
            Console.WriteLine($"  PID {c.Pid,-8} {c.Name,-8} MC={(c.LooksLikeMinecraft ? "да" : "нет"),-4} " +
                              $"start={c.StartUtc.ToLocalTime():HH:mm:ss}  {c.ExePath}");
            if (c.CommandLine.Length > 0)
                Console.WriteLine($"      cmd: {Truncate(c.CommandLine, 300)}");
        }
    }

    internal static string Truncate(string s, int n) =>
        s.Length <= n ? s : s.Substring(0, n) + $"... (+{s.Length - n} симв.)";
}

internal sealed class ScanOutcome
{
    public required ScanReport Report { get; init; }
    public TimeSpan Elapsed { get; init; }
    public string? HtmlPath { get; set; }
    public string? TxtPath { get; set; }
    public string? JsonPath { get; set; }
    public List<string> Log { get; } = new();
    public List<string> Errors { get; } = new();
}

internal static class ScanRunner
{
    public static ScanOutcome Run(int pid, Options opt)
    {
        var sw = Stopwatch.StartNew();
        var report = Scanner.Run(pid, opt);
        sw.Stop();

        var res = new ScanOutcome { Report = report, Elapsed = sw.Elapsed };

        string outDir = opt.OutputDir ?? Path.Combine(AppContext.BaseDirectory, "reports");
        try { Directory.CreateDirectory(outDir); }
        catch (Exception ex)
        {
            res.Errors.Add($"Не удалось создать каталог отчётов {outDir}: {ex.Message}");
        }

        string st = DateTime.Now.ToString("yyyyMMdd-HHmmss");
        res.HtmlPath = Write(res, "Отчёт HTML  ", Path.Combine(outDir, $"agentscan-{pid}-{st}.html"),
            () => HtmlReport.Render(report, pid, res.Elapsed), false, "   ← открыть в браузере");
        res.TxtPath = Write(res, "Полный текст", Path.Combine(outDir, $"agentscan-{pid}-{st}.txt"),
            () => TextReport.Render(report, pid, res.Elapsed), true);
        res.JsonPath = Write(res, "JSON        ", Path.Combine(outDir, $"agentscan-{pid}-{st}.json"),
            () => JsonReport.Render(report, pid, res.Elapsed), false);

        if (opt.DumpDir is not null && Directory.Exists(opt.DumpDir))
        {
            var files = Directory.GetFiles(opt.DumpDir);
            long total = files.Sum(f => new FileInfo(f).Length);
            res.Log.Add($"Дампы       : {opt.DumpDir}   ({files.Length} файлов, " +
                        $"{total / 1024.0 / 1024.0:F1} МБ)");
        }
        return res;
    }

    public static int ExitCode(ScanReport report)
    {
        if (report.Count(Severity.Critical) > 0) return 10;
        if (report.Count(Severity.High) > 0) return 9;
        if (report.Count(Severity.Medium) > 0) return 8;
        return 0;
    }

    private static string? Write(ScanOutcome res, string label, string path, Func<string> render,
        bool bom, string suffix = "")
    {
        try
        {
            File.WriteAllText(path, render(), new UTF8Encoding(bom));
            res.Log.Add($"{label}: {path}{suffix}");
            return path;
        }
        catch (Exception ex)
        {
            res.Errors.Add($"{label}: НЕ ЗАПИСАН — {ex.GetType().Name}: {ex.Message}");
            return null;
        }
    }
}

internal sealed class Options
{
    public int Pid;
    public bool ListOnly;
    public bool ShowHelp;
    public bool Verbose;
    public string? OutputDir;
    public string? DumpDir;

    public bool FullStringScan = true;

    public bool DumpSuspicious = true;

    public List<string> OnlySteps = new();
    public List<string> SkipSteps = new();

    public long MaxDumpBytes = 256L * 1024 * 1024;

    public long ScanBudgetBytes = long.MaxValue;

    public static Options Parse(string[] args)
    {
        var o = new Options();
        for (int i = 0; i < args.Length; i++)
        {
            string a = args[i];
            switch (a.ToLowerInvariant())
            {
                case "-h" or "--help" or "/?": o.ShowHelp = true; break;
                case "-l" or "--list": o.ListOnly = true; break;
                case "-c" or "--console": break;
                case "-v" or "--verbose": o.Verbose = true; break;
                case "-p" or "--pid":
                    if (i + 1 < args.Length && int.TryParse(args[++i], out int p)) o.Pid = p;
                    break;
                case "-o" or "--out":
                    if (i + 1 < args.Length) o.OutputDir = args[++i];
                    break;
                case "--dump-dir":
                    if (i + 1 < args.Length) o.DumpDir = args[++i];
                    break;
                case "--max-dump":
                    if (i + 1 < args.Length && long.TryParse(args[++i], out long mb) && mb > 0)
                        o.MaxDumpBytes = mb * 1024 * 1024;
                    break;
                case "--no-strings": o.FullStringScan = false; break;
                case "--no-dump": o.DumpSuspicious = false; break;
                case "--only":
                    if (i + 1 < args.Length)
                        o.OnlySteps.AddRange(args[++i]
                            .Split(',', StringSplitOptions.RemoveEmptyEntries |
                                        StringSplitOptions.TrimEntries));
                    break;
                case "--skip":
                    if (i + 1 < args.Length)
                        o.SkipSteps.AddRange(args[++i]
                            .Split(',', StringSplitOptions.RemoveEmptyEntries |
                                        StringSplitOptions.TrimEntries));
                    break;
                case "--fast":
                    o.FullStringScan = false;
                    o.DumpSuspicious = false;
                    break;
                default:
                    if (int.TryParse(a, out int bare) && o.Pid == 0) o.Pid = bare;
                    break;
            }
        }
        if (o.DumpSuspicious && o.DumpDir is null)
            o.DumpDir = Path.Combine(o.OutputDir ?? Path.Combine(AppContext.BaseDirectory, "reports"),
                $"agentscan-dumps-{DateTime.Now:yyyyMMdd-HHmmss}");
        return o;
    }

    public static void PrintHelp()
    {
        Console.WriteLine($"""
        AgentScan {Program.Version} — мини-сканер процесса Minecraft: JVMTI, Java-агенты
        и окружение виртуальной машины, в том числе уже отключённые агенты.

        После проверки пишутся три файла: .html (для разбора глазами — с фильтрами,
        поиском и пояснениями), .txt (полный текст) и .json (для автоматизации).

        Использование:
          AgentScan.exe                       окно: выбор процесса, ход проверки, отчёт
          AgentScan.exe --pid <N> [опции]     консольный режим
          AgentScan.exe --console [опции]     консольный режим, процесс ищется сам

          --pid, -p <N>     PID процесса игры (по умолчанию ищется автоматически)
          --list, -l        показать java-процессы и выйти
          --out, -o <dir>   каталог для отчётов (по умолчанию ./reports)
          --dump-dir <dir>  каталог для дампов найденных остатков
          --verbose, -v     подробный вывод в консоль
          --max-dump <МБ>   предел на один дамп (по умолчанию 256 МБ)
          --no-strings      пропустить сплошной скан памяти (быстро, но часть
                            проверок останется без данных)
          --no-dump         не сохранять дампы
          --fast            = --no-strings --no-dump
          --only <часть,...>   выполнить только шаги, чьё имя содержит подстроку
                               (режим проверки самого сканера; отчёт помечается неполным)
          --skip <часть,...>   наоборот, пропустить такие шаги

        Коды возврата: 10 — есть CRITICAL, 9 — HIGH, 8 — MEDIUM, 0 — чисто,
        2 — процесс не найден, 3 — фатальная ошибка.

        Запускать от имени администратора.
        """);
    }
}
