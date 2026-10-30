namespace AgentScan.Analysis;

internal static class MemoryAnalyzer
{
    public static string Human(ulong bytes)
    {
        if (bytes >= 1UL << 30) return $"{bytes / (double)(1UL << 30):F2} ГБ";
        if (bytes >= 1UL << 20) return $"{bytes / (double)(1UL << 20):F2} МБ";
        if (bytes >= 1UL << 10) return $"{bytes / (double)(1UL << 10):F1} КБ";
        return $"{bytes} Б";
    }
}
