using System.Buffers.Binary;
using System.Text;
using AgentScan.Core;

namespace AgentScan.Analysis;

internal sealed class SigHit
{
    public required Signature Sig { get; init; }
    public ulong Address;
    public bool Utf16;
    public required MemRegion Region { get; init; }
    public string Context = "";
    public int OccurrencesInRegion = 1;
}

internal sealed class ClassBlob
{
    public ulong Address;
    public string Name = "";
    public string SuperName = "";
    public int MajorVersion;

    public int Occurrences = 1;
    public List<ulong> AllAddresses = new();
}

internal sealed class RawPattern
{
    public required string Name { get; init; }
    public required byte[] Bytes { get; init; }
    public int MaxHits { get; init; } = 4096;
    public List<(ulong Addr, MemRegion Region)> Hits { get; } = new();
    public HashSet<ulong> Seen { get; } = new();
    public int TotalHits;
}

internal sealed class SweepResult
{
    public List<SigHit> Hits = new();
    public Dictionary<string, ClassBlob> Classes = new(StringComparer.Ordinal);
    public List<RawPattern> RawPatterns = new();
    public HashSet<ulong> SeenClassAddrs = new();

    public Dictionary<string, int> JarPaths = new(StringComparer.OrdinalIgnoreCase);
    public long BytesScanned;
    public int RegionsScanned;
    public TimeSpan Elapsed;
    public bool BudgetExhausted;
}

internal static class MemorySweep
{
    private const int ChunkSize = 8 * 1024 * 1024;
    private const int Overlap = 512;

    public static SweepResult Run(ScanContext ctx, List<Signature> sigs,
        List<RawPattern>? rawPatterns = null, Action<string>? progress = null)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var res = new SweepResult();
        var t = ctx.Target;
        res.RawPatterns = rawPatterns ?? new List<RawPattern>();

        var ac = new AhoCorasick();
        var patMeta = new List<(Signature sig, bool utf16)>();
        foreach (var s in sigs)
        {
            ac.Add(Encoding.ASCII.GetBytes(s.Text));
            patMeta.Add((s, false));
            if (s.Utf16)
            {
                ac.Add(Encoding.Unicode.GetBytes(s.Text));
                patMeta.Add((s, true));
            }
        }
        ac.Build();

        var regions = ctx.Regions
            .Where(r => r.IsCommitted && !r.IsGuard && !r.IsNoAccess)
            .OrderBy(r => r.Base)
            .ToList();

        long budget = ctx.Options.ScanBudgetBytes;
        var buf = new byte[ChunkSize + Overlap];
        int lastPct = -1;
        long totalBytes = regions.Sum(r => (long)r.Size);
        long done = 0;

        foreach (var region in regions)
        {
            if (budget <= 0) { res.BudgetExhausted = true; break; }
            res.RegionsScanned++;

            var perRegionCount = new Dictionary<(Signature, bool), SigHit>();

            ulong off = 0;
            while (off < region.Size)
            {
                int len = (int)Math.Min((ulong)ChunkSize, region.Size - off);
                var span = buf.AsSpan(0, len);
                int read = t.ReadPartial(region.Base + off, span, out _);
                res.BytesScanned += len;
                budget -= len;
                done += len;

                if (read > 0)
                {
                    ScanChunk(ctx, res, region, region.Base + off, span, ac, patMeta,
                        perRegionCount);
                }

                if (progress is not null && totalBytes > 0)
                {
                    int pct = (int)(done * 100 / totalBytes);
                    if (pct != lastPct) { lastPct = pct; progress($"скан памяти: {pct}%"); }
                }

                if (off + (ulong)len >= region.Size) break;
                off += (ulong)Math.Max(1, len - Overlap);
                if (budget <= 0) { res.BudgetExhausted = true; break; }
            }
        }

        res.Elapsed = sw.Elapsed;
        return res;
    }

    private static void ScanChunk(ScanContext ctx, SweepResult res, MemRegion region,
        ulong baseAddr, ReadOnlySpan<byte> data, AhoCorasick ac,
        List<(Signature sig, bool utf16)> patMeta,
        Dictionary<(Signature, bool), SigHit> perRegion)
    {
        var raw = new List<(int Id, int Idx)>();
        ac.Scan(data, (id, idx) => { if (idx >= 0) raw.Add((id, idx)); });

        foreach (var (id, idx) in raw)
        {
            var (sig, utf16) = patMeta[id];
            if (!ScopeMatches(sig.Scope, region)) continue;
            if (sig.WholeWord && !IsWholeWord(data, idx, sig.Text.Length * (utf16 ? 2 : 1),
                    utf16, sig.Text)) continue;

            var key = (sig, utf16);
            if (perRegion.TryGetValue(key, out var existing))
            {
                existing.OccurrencesInRegion++;
                continue;
            }

            var hit = new SigHit
            {
                Sig = sig,
                Address = baseAddr + (ulong)idx,
                Utf16 = utf16,
                Region = region,
                Context = MakeContext(data, idx, sig.Text.Length * (utf16 ? 2 : 1), utf16),
            };
            perRegion[key] = hit;
            res.Hits.Add(hit);
        }

        if (region.IsPrivate)
        {
            FindClassFiles(res, baseAddr, data);
            HarvestPaths(res, data);
        }

        foreach (var rp in res.RawPatterns)
        {
            int pos = 0;
            while (pos < data.Length)
            {
                int idx = data.Slice(pos).IndexOf(rp.Bytes);
                if (idx < 0) break;
                int at = pos + idx;
                pos = at + 1;
                ulong addr = baseAddr + (ulong)at;
                if (!rp.Seen.Add(addr)) continue;
                rp.TotalHits++;
                if (rp.Hits.Count < rp.MaxHits)
                    rp.Hits.Add((addr, region));
            }
        }
    }

    private static bool ScopeMatches(SigScope scope, MemRegion r) => scope switch
    {
        SigScope.Any => true,
        SigScope.NonImage => !r.IsImage,
        SigScope.PrivateOnly => r.IsPrivate,
        SigScope.PrivateExec => r.IsPrivate && (r.IsExecutable || r.AllocWasExecutable),
        _ => true,
    };

    private static bool IsWholeWord(ReadOnlySpan<byte> data, int idx, int matchLen,
        bool utf16, string text)
    {
        if (text.Length == 0) return true;
        if (!IsWordChar(text[0]) && !IsWordChar(text[^1])) return true;

        int step = utf16 ? 2 : 1;

        if (IsWordChar(text[0]))
        {
            int before = idx - step;
            if (before >= 0)
            {
                char c = utf16
                    ? (char)(data[before] | (data[before + 1] << 8))
                    : (char)data[before];
                if (IsWordChar(c)) return false;
            }
        }

        if (IsWordChar(text[^1]))
        {
            int after = idx + matchLen;
            if (after + step <= data.Length)
            {
                char c = utf16
                    ? (char)(data[after] | (data[after + 1] << 8))
                    : (char)data[after];
                if (IsWordChar(c)) return false;
            }
        }
        return true;
    }

    private static bool IsWordChar(char c) =>
        c is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9' or '_' or '$';

    private static string MakeContext(ReadOnlySpan<byte> data, int idx, int matchLen, bool utf16)
    {
        int start = Math.Max(0, idx - 64);
        int end = Math.Min(data.Length, idx + matchLen + 64);
        var slice = data.Slice(start, end - start);
        var sb = new StringBuilder();
        if (utf16)
        {
            int adj = (idx - start) % 2;
            var s = Encoding.Unicode.GetString(slice.Slice(adj, (slice.Length - adj) & ~1));
            foreach (char c in s) sb.Append(c >= 0x20 && c != 0x7F ? c : '.');
        }
        else
        {
            foreach (byte b in slice) sb.Append(b >= 0x20 && b < 0x7F ? (char)b : '.');
        }
        return sb.ToString();
    }

    private const int MaxHarvestedPaths = 20000;

    private static readonly byte[] JarAscii = { (byte)'.', (byte)'j', (byte)'a', (byte)'r' };
    private static readonly byte[] DllAscii = { (byte)'.', (byte)'d', (byte)'l', (byte)'l' };
    private static readonly byte[] JarWide =
        { (byte)'.', 0, (byte)'j', 0, (byte)'a', 0, (byte)'r', 0 };
    private static readonly byte[] DllWide =
        { (byte)'.', 0, (byte)'d', 0, (byte)'l', 0, (byte)'l', 0 };

    private static void HarvestPaths(SweepResult res, ReadOnlySpan<byte> data)
    {
        if (res.JarPaths.Count > MaxHarvestedPaths) return;
        Harvest(res.JarPaths, data, JarAscii, false);
        Harvest(res.JarPaths, data, JarWide, true);
    }

    private static void Harvest(Dictionary<string, int> sink, ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> needle, bool utf16)
    {
        int step = utf16 ? 2 : 1;
        int pos = 0;
        while (pos < data.Length && sink.Count < MaxHarvestedPaths)
        {
            int idx = data.Slice(pos).IndexOf(needle);
            if (idx < 0) break;
            int at = pos + idx;
            pos = at + step;

            int start = at;
            int limit = Math.Max(0, at - 600);
            while (start - step >= limit)
            {
                int p = start - step;
                char c = utf16
                    ? (p + 1 < data.Length ? (char)(data[p] | (data[p + 1] << 8)) : '\0')
                    : (char)data[p];
                if (!IsPathChar(c)) break;
                start = p;
            }
            int len = at + needle.Length - start;
            if (len < 8 || len > 600) continue;

            var sb = new StringBuilder();
            for (int i = start; i < at + needle.Length; i += step)
            {
                char c = utf16
                    ? (i + 1 < data.Length ? (char)(data[i] | (data[i + 1] << 8)) : '\0')
                    : (char)data[i];
                sb.Append(c);
            }
            string path = Normalize(sb.ToString());
            if (path.Length < 8) continue;
            if (!IsAbsolute(path)) continue;
            sink.TryGetValue(path, out int c0);
            sink[path] = c0 + 1;
        }
    }

    private static string Normalize(string s)
    {
        s = s.Trim().Trim('"');
        if (s.StartsWith("file:///", StringComparison.OrdinalIgnoreCase)) s = s.Substring(8);
        else if (s.StartsWith("file://", StringComparison.OrdinalIgnoreCase)) s = s.Substring(7);
        if (s.Length > 2 && s[0] == '/' && char.IsLetter(s[1]) && s[2] == ':') s = s.Substring(1);
        return s.Replace('/', '\\');
    }

    private static bool IsAbsolute(string s) =>
        (s.Length > 3 && char.IsLetter(s[0]) && s[1] == ':' && s[2] == '\\') ||
        s.StartsWith(@"\\", StringComparison.Ordinal) ||
        s.StartsWith(@"\??\", StringComparison.Ordinal) ||
        s.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase);

    private static bool IsPathChar(char c) =>
        c is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9'
          or '\\' or '/' or ':' or '.' or '-' or '_' or ' ' or '(' or ')' or '+'
          or '~' or '!' or '@' or '#' or '$' or '%' or '&' or '=' or ',' or '\'' or '[' or ']';

    private static void FindClassFiles(SweepResult res, ulong baseAddr, ReadOnlySpan<byte> data)
    {
        ReadOnlySpan<byte> magic = stackalloc byte[] { 0xCA, 0xFE, 0xBA, 0xBE };
        int pos = 0;
        while (pos + 64 < data.Length)
        {
            int idx = data.Slice(pos).IndexOf(magic);
            if (idx < 0) break;
            int at = pos + idx;
            pos = at + 4;

            var blob = JavaClassParser.TryParse(data.Slice(at), baseAddr + (ulong)at);
            if (blob is null) continue;
            if (!res.SeenClassAddrs.Add(blob.Address)) continue;
            if (res.Classes.TryGetValue(blob.Name, out var prev))
            {
                prev.Occurrences++;
                if (prev.AllAddresses.Count < 16) prev.AllAddresses.Add(blob.Address);
            }
            else
            {
                blob.AllAddresses.Add(blob.Address);
                res.Classes[blob.Name] = blob;
            }
            if (res.Classes.Count > 200000) return;
        }
    }
}

internal static class JavaClassParser
{
    public static ClassBlob? TryParse(ReadOnlySpan<byte> d, ulong addr)
    {
        if (d.Length < 24) return null;
        int minor = BinaryPrimitives.ReadUInt16BigEndian(d.Slice(4));
        int major = BinaryPrimitives.ReadUInt16BigEndian(d.Slice(6));
        if (major is < 45 or > 80) return null;
        int cpCount = BinaryPrimitives.ReadUInt16BigEndian(d.Slice(8));
        if (cpCount is < 2 or > 65535) return null;

        var utf8 = new Dictionary<int, string>();
        var classNameIdx = new Dictionary<int, int>();

        int p = 10;
        for (int i = 1; i < cpCount; i++)
        {
            if (p >= d.Length) return null;
            byte tag = d[p++];
            switch (tag)
            {
                case 1:
                    if (p + 2 > d.Length) return null;
                    int len = BinaryPrimitives.ReadUInt16BigEndian(d.Slice(p));
                    p += 2;
                    if (p + len > d.Length) return null;
                    utf8[i] = DecodeModifiedUtf8(d.Slice(p, len));
                    p += len;
                    break;
                case 7:
                case 8:
                case 16:
                case 19:
                case 20:
                    if (p + 2 > d.Length) return null;
                    if (tag == 7) classNameIdx[i] = BinaryPrimitives.ReadUInt16BigEndian(d.Slice(p));
                    p += 2;
                    break;
                case 15:
                    p += 3;
                    break;
                case 3: case 4: case 9: case 10: case 11: case 12: case 17: case 18:
                    p += 4;
                    break;
                case 5: case 6:
                    p += 8;
                    i++;
                    break;
                default:
                    return null;
            }
        }

        if (p + 6 > d.Length) return null;
        int thisClass = BinaryPrimitives.ReadUInt16BigEndian(d.Slice(p + 2));
        int superClass = BinaryPrimitives.ReadUInt16BigEndian(d.Slice(p + 4));

        string name = Resolve(thisClass, classNameIdx, utf8);
        if (name.Length == 0) return null;

        var blob = new ClassBlob
        {
            Address = addr,
            Name = name,
            SuperName = Resolve(superClass, classNameIdx, utf8),
            MajorVersion = major,
        };

        return blob;
    }

    private static string Resolve(int classIdx, Dictionary<int, int> classNameIdx,
        Dictionary<int, string> utf8)
    {
        if (classIdx == 0) return "";
        return classNameIdx.TryGetValue(classIdx, out int ni) && utf8.TryGetValue(ni, out var s)
            ? s : "";
    }

    private static string DecodeModifiedUtf8(ReadOnlySpan<byte> b) =>
        JavaNames.DecodeModifiedUtf8(b);
}
