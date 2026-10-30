using System.Text;
using AgentScan.Report;

namespace AgentScan.Analysis;

internal static class ProcessInfoAnalyzer
{
    public static void Run(ScanContext ctx)
    {
        var t = ctx.Target;
        var rep = ctx.Report;

        var f = rep.Report("ПРОЦЕСС", $"Цель: PID {t.Pid}", Severity.Info, null);
        f.Add("образ", t.ImagePath);
        f.Add("запущен", t.StartTimeUtc == default ? "-" : t.StartTimeUtc.ToLocalTime().ToString("O"));
        if (t.StartTimeUtc != default)
            f.Add("работает", $"{(DateTime.UtcNow - t.StartTimeUtc).TotalMinutes:F1} мин");
        f.Add("PEB", t.PebAddress == IntPtr.Zero ? "недоступен" : $"0x{t.PebAddress.ToInt64():X}");
        f.Add("ImageBase", t.ImageBase);
        f.Add("WOW64", t.IsWow64 ? "да (32-битный процесс)" : "нет (нативный x64)");
        f.Add("хендл открыт с правами", t.OpenedWith);
        foreach (var w in t.Warnings) f.Add("предупреждение", w);

        rep.AddMeta("PID", t.Pid.ToString());
        rep.AddMeta("Образ", t.ImagePath.Length > 0 ? t.ImagePath : "-");
        rep.AddMeta("Запущен", t.StartTimeUtc == default
            ? "-"
            : t.StartTimeUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss"));
        if (t.StartTimeUtc != default)
            rep.AddMeta("Работает на момент проверки",
                $"{(DateTime.UtcNow - t.StartTimeUtc).TotalMinutes:F1} мин");
        rep.AddMeta("Рабочий каталог", t.GetCurrentDirectory() ?? "-");
        rep.AddMeta("Командная строка", t.GetCommandLine() ?? "-");
        rep.AddMeta("Разрядность", t.IsWow64 ? "WOW64 (32-битный)" : "x64");
        rep.AddMeta("Родительский процесс", t.ParentPid.ToString());
        rep.AddMeta("Хендл открыт с правами", t.OpenedWith);
        rep.AddMeta("PEB", t.PebAddress == IntPtr.Zero
            ? "недоступен" : $"0x{t.PebAddress.ToInt64():X}");

        rep.Section("ПРОЦЕСС", Render(ctx));
    }

    private static string Render(ScanContext ctx)
    {
        var t = ctx.Target;
        var sb = new StringBuilder();
        sb.AppendLine($"PID           : {t.Pid}");
        sb.AppendLine($"Образ         : {t.ImagePath}");
        sb.AppendLine($"Запущен       : {(t.StartTimeUtc == default ? "-" : t.StartTimeUtc.ToLocalTime().ToString("O"))}");
        sb.AppendLine($"PEB           : 0x{t.PebAddress.ToInt64():X}");
        sb.AppendLine($"ImageBase     : 0x{t.ImageBase:X}");
        sb.AppendLine($"Раб. каталог  : {t.GetCurrentDirectory() ?? "-"}");
        sb.AppendLine();
        sb.AppendLine("Командная строка:");
        sb.AppendLine("  " + (t.GetCommandLine() ?? "-"));
        sb.AppendLine();
        sb.AppendLine("Окружение процесса:");
        foreach (var e in t.GetEnvironment().OrderBy(x => x, StringComparer.OrdinalIgnoreCase))
            sb.AppendLine("  " + e);
        return sb.ToString();
    }
}
