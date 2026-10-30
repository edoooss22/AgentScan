using AgentScan.Analysis;

namespace AgentScan.Core;

internal readonly struct MemChunk
{
    public required MemRegion Region { get; init; }
    public required ulong Base { get; init; }
    public required byte[] Data { get; init; }
    public required int Length { get; init; }
    public required bool IsFirst { get; init; }

    public byte[] Exact => Length == Data.Length ? Data : Data.AsSpan(0, Length).ToArray();
}

internal static class MemoryScan
{
    public const int DefaultChunk = 32 * 1024 * 1024;

    public static bool Readable(MemRegion r) =>
        r.IsCommitted && !r.IsGuard && !r.IsNoAccess;

    public static bool PrivateData(MemRegion r) =>
        Readable(r) && r.IsPrivate && !r.IsExecutable && r.IsWritable;

    public static bool PrivateAnyData(MemRegion r) =>
        Readable(r) && r.IsPrivate && !r.IsExecutable;

    public static IEnumerable<MemChunk> Chunks(ScanContext ctx, Func<MemRegion, bool> filter,
        int overlap = 8, int chunkSize = DefaultChunk)
    {
        if (chunkSize < 0x10000) chunkSize = 0x10000;
        overlap = (overlap + 7) & ~7;
        if (overlap >= chunkSize) overlap = chunkSize / 2;

        var buf = new byte[chunkSize];
        foreach (var r in ctx.Regions)
        {
            if (!filter(r)) continue;

            ulong off = 0;
            bool first = true;
            while (off < r.Size)
            {
                int len = (int)Math.Min((ulong)chunkSize, r.Size - off);
                int read = ctx.Target.ReadPartial(r.Base + off, buf.AsSpan(0, len), out _);
                if (read > 0)
                    yield return new MemChunk
                    {
                        Region = r, Base = r.Base + off, Data = buf, Length = len, IsFirst = first,
                    };

                first = false;
                if (off + (ulong)len >= r.Size) break;
                off += (ulong)Math.Max(1, len - overlap);
            }
        }
    }

    public static ulong TotalReadable(ScanContext ctx, Func<MemRegion, bool> filter)
    {
        ulong total = 0;
        foreach (var r in ctx.Regions) if (filter(r)) total += r.Size;
        return total;
    }
}
