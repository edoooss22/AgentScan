using System.Text;
using AgentScan.Core;

namespace AgentScan.Analysis;

internal static class CodeCacheWalkAnalyzer
{
    private sealed class Heap
    {
        public ulong Low, High;
        public ulong SegmapLow, SegmapHigh;
        public int Log2SegmentSize;
    }

    public static void Run(ScanContext ctx)
    {
        var jvm = JvmAnalyzer.FindJvm(ctx);
        var vm = ctx.Vm;
        if (jvm is null || vm is null || !vm.Valid) return;

        var cache = new PageCache(ctx.Target, 65536);
        var vtableByAddr = vm.Vtables.GroupBy(x => x.Value)
            .ToDictionary(g => g.Key, g => string.Join("/", g.Select(x => x.Key)));

        foreach (var h in FindHeaps(ctx, vm, cache))
            WalkHeap(ctx, vm, cache, h, jvm, vtableByAddr);
    }

    private static List<Heap> FindHeaps(ScanContext ctx, VmStructs vm, PageCache c)
    {
        var res = new List<Heap>();
        ulong heapsVar = vm.StaticAddrAny(("CodeCache", "_heaps"), ("CodeCache", "_heap"));

        int offMemory = vm.Off("CodeHeap", "_memory");
        int offLog2 = vm.Off("CodeHeap", "_log2_segment_size");
        int offSegmap = vm.Off("CodeHeap", "_segmap");
        int offLow = vm.Off("VirtualSpace", "_low");
        int offHigh = vm.Off("VirtualSpace", "_high");

        if (heapsVar == 0 || offMemory < 0 || offLow < 0 || offHigh < 0 || offLog2 < 0)
            return res;

        ulong ga = c.U64(heapsVar);
        if (ga is < 0x10000 or > 0x7FFFFFFFFFFF) return res;

        bool TryLayout(int dataOff, out int len, out ulong data)
        {
            len = (int)c.U32(ga);
            data = c.U64(ga + (ulong)dataOff);
            if (len is <= 0 or > 32) return false;
            if (data is < 0x10000 or > 0x7FFFFFFFFFFF) return false;
            for (int i = 0; i < len; i++)
            {
                ulong hp = c.U64(data + (ulong)i * 8);
                if (hp is < 0x10000 or > 0x7FFFFFFFFFFF) return false;
                ulong lo = c.U64(hp + (ulong)(offMemory + offLow));
                ulong hi = c.U64(hp + (ulong)(offMemory + offHigh));
                if (lo is < 0x10000 or > 0x7FFFFFFFFFFF) return false;
                if (hi < lo || hi - lo > 2UL * 1024 * 1024 * 1024) return false;
            }
            return true;
        }

        int count;
        ulong dataPtr;
        if (!TryLayout(8, out count, out dataPtr) && !TryLayout(16, out count, out dataPtr))
            return res;

        for (int i = 0; i < count; i++)
        {
            ulong hp = c.U64(dataPtr + (ulong)i * 8);
            var h = new Heap
            {
                Low = c.U64(hp + (ulong)(offMemory + offLow)),
                High = c.U64(hp + (ulong)(offMemory + offHigh)),
                Log2SegmentSize = (int)c.U32(hp + (ulong)offLog2),
            };
            if (offSegmap >= 0)
            {
                h.SegmapLow = c.U64(hp + (ulong)(offSegmap + offLow));
                h.SegmapHigh = c.U64(hp + (ulong)(offSegmap + offHigh));
            }
            if (h.Log2SegmentSize is < 4 or > 12) h.Log2SegmentSize = 6;
            res.Add(h);
        }
        return res;
    }

    private static void WalkHeap(ScanContext ctx, VmStructs vm, PageCache c, Heap h,
        ImageInMemory jvm, Dictionary<ulong, string> vtableByAddr)
    {
        ulong size = h.High - h.Low;
        if (size == 0 || size > 1UL * 1024 * 1024 * 1024) return;

        var body = new byte[(int)size];
        if (ctx.Target.ReadPartial(h.Low, body, out _) <= 0) return;

        byte[]? segmap = null;
        if (h.SegmapLow != 0 && h.SegmapHigh > h.SegmapLow &&
            h.SegmapHigh - h.SegmapLow < 64UL * 1024 * 1024)
        {
            segmap = new byte[(int)(h.SegmapHigh - h.SegmapLow)];
            ctx.Target.ReadPartial(h.SegmapLow, segmap, out _);
        }

        int hdrLen = vm.Off("HeapBlock::Header", "_length");
        int hdrUsed = vm.Off("HeapBlock::Header", "_used");
        if (hdrLen < 0) hdrLen = 0;
        if (hdrUsed < 0) hdrUsed = 8;
        int blockHdrSize = (int)Math.Max(16UL, vm.TypeSize("HeapBlock"));

        int offBlobName = vm.Off("CodeBlob", "_name");
        int offMethod = vm.OffAnyOf(("CompiledMethod", "_method"), ("nmethod", "_method"));
        int offEntry = vm.Off("nmethod", "_entry_point");
        int offVEntry = vm.Off("nmethod", "_verified_entry_point");
        int offState = vm.Off("nmethod", "_state");

        ulong nmVtable = vm.Vtable("nmethod");
        ulong cur = h.Low;
        int blocks = 0;

        while (cur + (ulong)blockHdrSize <= h.High && blocks++ < 500_000)
        {
            int off = (int)(cur - h.Low);
            ulong length = BitConverter.ToUInt64(body, off + hdrLen);
            if (segmap is not null)
            {
                long seg = (long)((cur - h.Low) >> h.Log2SegmentSize);
                if (seg >= 0 && seg < segmap.Length && segmap[seg] == 0xFF) break;
            }
            if (length == 0 || length > (ulong)(size >> h.Log2SegmentSize) + 1) break;
            ulong bytes = length << h.Log2SegmentSize;
            ulong blob = cur + (ulong)blockHdrSize;

            int bo = off + blockHdrSize;
            if (body[off + hdrUsed] != 0 && bo + 0x160 <= body.Length)
            {
                ulong vtable = BitConverter.ToUInt64(body, bo);
                string cls = vtableByAddr.TryGetValue(vtable, out var cn) ? cn : "";
                string name = "";
                if (offBlobName >= 0)
                {
                    ulong np = BitConverter.ToUInt64(body, bo + offBlobName);
                    if (np >= jvm.Base && np < jvm.End) name = ReadCString(c, np) ?? "";
                }
                bool isNm = nmVtable != 0 && vtable == nmVtable;
                ulong method = 0, entry = 0, ventry = 0;
                sbyte state = 0;
                if (isNm && offMethod >= 0)
                {
                    method = BitConverter.ToUInt64(body, bo + offMethod);
                    if (offEntry >= 0) entry = BitConverter.ToUInt64(body, bo + offEntry);
                    if (offVEntry >= 0) ventry = BitConverter.ToUInt64(body, bo + offVEntry);
                    if (offState >= 0) state = (sbyte)body[bo + offState];
                }
                ctx.CodeBlobs.Add(new CodeBlobInfo(cur, cur + bytes, cls, name, blob,
                    entry, ventry, method, isNm, state, blob));
            }

            ulong next = cur + bytes;
            if (next <= cur) break;
            cur = next;
        }
    }

    private static string? ReadCString(PageCache c, ulong addr)
    {
        var b = c.Read(addr, 64);
        if (b is null) return null;
        int n = 0;
        while (n < b.Length && b[n] >= 0x20 && b[n] < 0x7F) n++;
        return n is 0 or > 60 ? null : Encoding.ASCII.GetString(b, 0, n);
    }
}
