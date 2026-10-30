using AgentScan.Analysis;

namespace AgentScan.Core;

internal sealed class KlassStat
{
    public ulong Klass;
    public string Name = "";
    public long Live;
    public long Dead;
    public List<ulong> LiveSamples = new();
    public List<ulong> DeadSamples = new();
}

internal sealed class JavaHeapIndex
{
    public sealed class Range
    {
        public ulong From, To;
        public string Kind = "";
        public bool Dead;
    }

    private readonly JavaMeta _m;
    private readonly ScanContext _sc;

    public bool Valid { get; private set; }
    public List<string> Diagnostics { get; } = new();

    public List<Range> Ranges { get; } = new();
    public Dictionary<ulong, KlassStat> Stats { get; } = new();

    public long LiveObjects, DeadObjects;
    public long LiveBytesScanned, DeadBytesScanned;
    public long DeadUnknownKlass;

    public ulong ReservedStart, ReservedEnd;
    public string GcName = "";
    public int RegionsTotal;

    private const int MaxSamples = 64;

    public List<ulong> DeadStrings { get; } = new();

    private const int MaxDeadStrings = 200_000;
    private ulong _stringKlass;

    private static readonly string[] FullyCollected =
    {
        "java/nio/Buffer", "net/fabricmc/fabric/api/event/Event",
        "java/lang/Throwable",
        "java/lang/reflect/AccessibleObject",
        "java/lang/invoke/MethodHandles$Lookup",
        "java/lang/Module", "java/lang/Thread",
        "java/lang/invoke/ResolvedMethodName",
        "java/net/InetAddress", "java/net/InetSocketAddress",
    };

    private readonly HashSet<ulong> _fullKlasses = new();
    private const int MaxFullPerKlass = 200_000;

    public Dictionary<ulong, List<ulong>> FullLive { get; } = new();

    private readonly Dictionary<ulong, int> _layout = new();

    private JavaHeapIndex(ScanContext sc, JavaMeta m)
    {
        _sc = sc;
        _m = m;
    }

    public static JavaHeapIndex? Get(ScanContext sc)
    {
        if (sc.HeapIndex is not null) return sc.HeapIndex;
        var m = sc.Java;
        if (m is null) return null;

        var idx = new JavaHeapIndex(sc, m);
        try { idx.Build(); }
        catch (Exception ex)
        {
            idx.Diagnostics.Add($"обход прерван: {ex.GetType().Name}: {ex.Message}");
        }
        sc.HeapIndex = idx;
        return idx;
    }

    private void Build()
    {
        var vm = _m.Vm;
        var c = _m.Cache;

        ulong heapVar = vm.StaticAddr("Universe", "_collectedHeap");
        ulong heap = heapVar == 0 ? 0 : c.U64(heapVar);
        int offReserved = vm.Off("CollectedHeap", "_reserved");
        int offStart = vm.Off("MemRegion", "_start");
        int offWords = vm.Off("MemRegion", "_word_size");

        if (heap is < 0x10000 or > 0x7FFFFFFFFFFF || offReserved < 0 || offStart < 0)
        {
            Diagnostics.Add("границы кучи из структур ВМ получить не удалось");
            return;
        }

        ulong heapVtable = c.U64(heap);
        GcName = vm.Vtables.FirstOrDefault(kv => kv.Value == heapVtable).Key ?? "не опознан";
        ReservedStart = c.U64(heap + (ulong)(offReserved + offStart));
        ulong words = offWords < 0 ? 0 : c.U64(heap + (ulong)(offReserved + offWords));
        ReservedEnd = ReservedStart + words * 8;

        if (ReservedStart is < 0x10000 or > 0x7FFFFFFFFFFF || ReservedEnd <= ReservedStart ||
            ReservedEnd - ReservedStart > 512UL * 1024 * 1024 * 1024)
        {
            Diagnostics.Add("границы кучи неправдоподобны");
            return;
        }

        int offLh = vm.Off("Klass", "_layout_helper");
        if (offLh < 0 || _m.Klasses.Count < 64)
        {
            Diagnostics.Add("нет Klass::_layout_helper либо список классов пуст");
            return;
        }
        foreach (ulong k in _m.Klasses.Keys)
            _layout[k] = (int)c.U32(k + (ulong)offLh);
        _stringKlass = _m.KlassByName("java/lang/String");

        foreach (ulong k in _m.Klasses.Keys)
            foreach (string t in FullyCollected)
                if (_m.IsSubclassOf(k, t)) { _fullKlasses.Add(k); break; }

        if (!EnumerateRanges(heap))
        {
            Diagnostics.Add("таблица регионов G1 не разобрана — мёртвая зона кучи " +
                            "не определяется, обход не выполнялся");
            return;
        }

        foreach (var r in Ranges) WalkRange(r);
        Valid = true;
    }

    private bool EnumerateRanges(ulong heap)
    {
        var vm = _m.Vm;
        var c = _m.Cache;

        int offHrm = vm.Off("G1CollectedHeap", "_hrm");
        int offRegions = vm.Off("HeapRegionManager", "_regions");
        int offBase = vm.Off("G1HeapRegionTable", "_base");
        int offLength = vm.Off("G1HeapRegionTable", "_length");
        int offBottom = vm.OffAnyOf(("HeapRegion", "_bottom"), ("G1HeapRegion", "_bottom"));
        int offTop = vm.OffAnyOf(("HeapRegion", "_top"), ("G1HeapRegion", "_top"));
        int offEnd = vm.OffAnyOf(("HeapRegion", "_end"), ("G1HeapRegion", "_end"));
        int offType = vm.OffAnyOf(("HeapRegion", "_type"), ("G1HeapRegion", "_type"));
        int offTag = vm.OffAnyOf(("HeapRegionType", "_tag"), ("G1HeapRegionType", "_tag"));

        if (GcName != "G1CollectedHeap" || offHrm < 0 || offRegions < 0 || offBase < 0 ||
            offLength < 0 || offBottom < 0 || offTop < 0 || offEnd < 0)
            return false;

        ulong table = heap + (ulong)(offHrm + offRegions);
        ulong arr = c.U64(table + (ulong)offBase);
        ulong len = c.U64(table + (ulong)offLength);
        if (arr is < 0x10000 or > 0x7FFFFFFFFFFF || len is 0 or > 1_000_000) return false;

        for (ulong i = 0; i < len; i++)
        {
            ulong hr = c.U64(arr + i * 8);
            if (hr is < 0x10000 or > 0x7FFFFFFFFFFF) continue;
            ulong bottom = c.U64(hr + (ulong)offBottom);
            ulong top = c.U64(hr + (ulong)offTop);
            ulong end = c.U64(hr + (ulong)offEnd);
            uint tag = offType >= 0 && offTag >= 0 ? c.U32(hr + (ulong)(offType + offTag)) : 0;

            if (bottom < ReservedStart || end > ReservedEnd || end <= bottom) continue;
            if (top < bottom || top > end) continue;
            RegionsTotal++;

            string kind = RegionTypeName(tag);
            bool contHumongous = (tag & 4) != 0 && (tag & 3) == 2;

            if (top > bottom && !contHumongous)
                Ranges.Add(new Range { From = bottom, To = top, Kind = kind, Dead = false });

            if (end > top)
                Ranges.Add(new Range { From = top, To = end, Kind = kind, Dead = true });
        }
        return Ranges.Count > 0;
    }

    private static string RegionTypeName(uint tag) => tag switch
    {
        0 => "Free",
        2 => "Eden",
        3 => "Survivor",
        5 => "StartsHumongous",
        6 => "ContinuesHumongous",
        _ when (tag & 0x10) != 0 => "Old",
        _ when (tag & 8) != 0 => "Pinned/Archive",
        _ => $"tag 0x{tag:X}",
    };

    private void WalkRange(Range r)
    {
        const int WindowBytes = 64 * 1024 * 1024;
        ulong cur = r.From;

        while (cur < r.To)
        {
            int len = (int)Math.Min((ulong)WindowBytes, r.To - cur);
            var buf = new byte[len];
            int read = _sc.Target.ReadPartial(cur, buf, out var pageOk);
            if (r.Dead) DeadBytesScanned += read; else LiveBytesScanned += read;
            if (read <= 0) { cur += (ulong)len; continue; }

            int pos = 0, lastComplete = 0;
            while (pos + 16 <= buf.Length)
            {
                int page = pos / 0x1000;
                if (page < pageOk.Length && !pageOk[page])
                { pos = (page + 1) * 0x1000; lastComplete = pos; continue; }

                ulong addr = cur + (ulong)pos;
                int size = ObjectAt(buf, pos, out ulong klass);

                if (size <= 0)
                {
                    if (r.Dead && klass == ulong.MaxValue) DeadUnknownKlass++;
                    pos += 8;
                    lastComplete = pos;
                    continue;
                }

                if (r.Dead && ChainLength(buf, pos) < 3)
                {
                    pos += 8;
                    lastComplete = pos;
                    continue;
                }

                if (pos + size > buf.Length) break;

                Record(klass, addr, r.Dead);
                if (r.Dead) DeadObjects++; else LiveObjects++;

                pos += (size + 7) & ~7;
                lastComplete = pos;
            }

            ulong advance = (ulong)Math.Max(lastComplete, 0x1000);
            if (advance > (ulong)len) advance = (ulong)len;
            cur += advance;
        }
    }

    private int ChainLength(byte[] buf, int pos)
    {
        int n = 0;
        int p = pos;
        while (n < 4 && p + 16 <= buf.Length)
        {
            int size = ObjectAt(buf, p, out _);
            if (size <= 0) break;
            n++;
            p += (size + 7) & ~7;
        }
        return n;
    }

    private int ObjectAt(byte[] buf, int pos, out ulong klass)
    {
        klass = 0;
        if (pos + 16 > buf.Length) return 0;

        ulong mark = BitConverter.ToUInt64(buf, pos);
        if ((mark & 3) == 3) return 0;
        if ((mark >> 56) != 0) return 0;

        ulong k = _m.CompressedKlass
            ? _m.DecodeKlass(BitConverter.ToUInt32(buf, pos + 8))
            : BitConverter.ToUInt64(buf, pos + 8);
        if (k == 0) return 0;

        if (!_layout.TryGetValue(k, out int lh))
        {
            klass = ulong.MaxValue;
            return 0;
        }
        klass = k;

        int hdr = _m.HeaderSize;
        if (lh > 0)
        {
            int size = lh & ~7;
            return size is < 8 or > 1 << 24 ? 0 : size;
        }
        if (lh < 0)
        {
            int hsize = (lh >> 16) & 0xFF;
            int log2esz = lh & 0x3F;
            if (hsize is < 12 or > 64 || log2esz > 3) return 0;
            if (pos + hdr + 4 > buf.Length) return 0;
            int alen = BitConverter.ToInt32(buf, pos + hdr);
            if (alen is < 0 or > 64 * 1024 * 1024) return 0;
            long size = (long)hsize + ((long)alen << log2esz);
            return size is < 16 or > 512 * 1024 * 1024 ? 0 : (int)size;
        }
        return 0;
    }

    private void Record(ulong klass, ulong addr, bool dead)
    {
        if (!Stats.TryGetValue(klass, out var st))
        {
            Stats[klass] = st = new KlassStat
            {
                Klass = klass,
                Name = _m.KlassName(klass) ?? $"0x{klass:X}",
            };
        }
        if (dead)
        {
            st.Dead++;
            if (st.DeadSamples.Count < MaxSamples) st.DeadSamples.Add(addr);
            if (klass == _stringKlass && DeadStrings.Count < MaxDeadStrings)
                DeadStrings.Add(addr);
        }
        else
        {
            st.Live++;
            if (st.LiveSamples.Count < MaxSamples) st.LiveSamples.Add(addr);
            if (_fullKlasses.Contains(klass))
            {
                if (!FullLive.TryGetValue(klass, out var full))
                    FullLive[klass] = full = new List<ulong>();
                if (full.Count < MaxFullPerKlass) full.Add(addr);
            }
        }
    }

    public delegate void LiveObjectVisitor(ulong address, ulong klass, int size,
        byte[] buffer, int offset);

    public void ForEachLiveObject(LiveObjectVisitor visit)
    {
        const int WindowBytes = 64 * 1024 * 1024;
        foreach (var r in Ranges)
        {
            if (r.Dead) continue;
            ulong cur = r.From;
            while (cur < r.To)
            {
                int len = (int)Math.Min((ulong)WindowBytes, r.To - cur);
                var buf = new byte[len];
                int read = _sc.Target.ReadPartial(cur, buf, out var pageOk);
                if (read <= 0) { cur += (ulong)len; continue; }

                int pos = 0, lastComplete = 0;
                while (pos + 16 <= buf.Length)
                {
                    int page = pos / 0x1000;
                    if (page < pageOk.Length && !pageOk[page])
                    { pos = (page + 1) * 0x1000; lastComplete = pos; continue; }

                    int size = ObjectAt(buf, pos, out ulong klass);
                    if (size <= 0) { pos += 8; lastComplete = pos; continue; }
                    if (pos + size > buf.Length) break;

                    visit(cur + (ulong)pos, klass, size, buf, pos);

                    pos += (size + 7) & ~7;
                    lastComplete = pos;
                }

                ulong advance = (ulong)Math.Max(lastComplete, 0x1000);
                if (advance > (ulong)len) advance = (ulong)len;
                cur += advance;
            }
        }
    }

    public List<ulong> LiveInstancesOf(string className)
    {
        ulong k = _m.KlassByName(className);
        if (k != 0 && Stats.TryGetValue(k, out var st)) return st.LiveSamples;
        return new List<ulong>();
    }

    public List<(ulong Obj, string Klass)> LiveInstancesAssignableTo(string ancestor, int limit = 4096)
    {
        var res = new List<(ulong, string)>();
        foreach (var st in Stats.Values)
        {
            if (st.Live == 0 || st.LiveSamples.Count == 0) continue;
            if (!_m.IsAssignableTo(st.Klass, ancestor)) continue;
            var src = FullLive.TryGetValue(st.Klass, out var full) && full.Count > 0
                ? full : st.LiveSamples;
            foreach (ulong o in src)
            {
                res.Add((o, st.Name));
                if (res.Count >= limit) return res;
            }
        }
        return res;
    }

    public KlassStat? StatOf(string className)
    {
        ulong k = _m.KlassByName(className);
        return k != 0 && Stats.TryGetValue(k, out var st) ? st : null;
    }
}
