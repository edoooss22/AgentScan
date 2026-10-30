namespace AgentScan.Core;

internal sealed class PageCache
{
    private readonly ProcessTarget _t;
    private readonly Dictionary<ulong, byte[]?> _pages = new();
    private readonly int _limit;

    public PageCache(ProcessTarget t, int maxPages = 16384)
    {
        _t = t;
        _limit = maxPages;
    }

    public bool Read(ulong addr, Span<byte> dest)
    {
        for (int i = 0; i < dest.Length;)
        {
            ulong a = addr + (ulong)i;
            ulong page = a & ~0xFFFUL;
            if (!_pages.TryGetValue(page, out var buf))
            {
                buf = _t.ReadBytes(page, 0x1000);
                if (_pages.Count >= _limit) _pages.Clear();
                _pages[page] = buf;
            }
            if (buf is null) return false;
            int off = (int)(a - page);
            int n = Math.Min(0x1000 - off, dest.Length - i);
            buf.AsSpan(off, n).CopyTo(dest.Slice(i, n));
            i += n;
        }
        return true;
    }

    public byte[]? Read(ulong addr, int length)
    {
        var b = new byte[length];
        return Read(addr, b.AsSpan()) ? b : null;
    }

    public void Invalidate() => _pages.Clear();

    public uint U32(ulong addr)
    {
        Span<byte> b = stackalloc byte[4];
        return Read(addr, b) ? BitConverter.ToUInt32(b) : 0;
    }

    public ulong U64(ulong addr)
    {
        Span<byte> b = stackalloc byte[8];
        return Read(addr, b) ? BitConverter.ToUInt64(b) : 0;
    }
}
