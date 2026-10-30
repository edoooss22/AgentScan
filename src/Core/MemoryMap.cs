using System.Text;
using AgentScan.Native;
using static AgentScan.Native.NativeApi;

namespace AgentScan.Core;

internal sealed class MemRegion
{
    public ulong Base;
    public ulong Size;
    public ulong AllocationBase;
    public uint AllocationProtect;
    public uint Protect;
    public uint State;
    public uint Type;

    public string? MappedFile;
    public string? MappedFileDos;

    public bool HasRegionInfo;
    public MEMORY_REGION_INFORMATION RegionInfo;

    public bool HasImageInfo;
    public MEMORY_IMAGE_INFORMATION ImageInfo;

    public int ResidentPages = -1;
    public int TotalPages;
    public bool AnyPrivatePage;
    public bool AnySharedPage;

    public bool IsCommitted => State == MEM_COMMIT;
    public bool IsFree => State == MEM_FREE;
    public bool IsReserved => State == MEM_RESERVE;
    public bool IsImage => Type == MEM_IMAGE;
    public bool IsMapped => Type == MEM_MAPPED;
    public bool IsPrivate => Type == MEM_PRIVATE;

    public bool IsExecutable => (Protect & EXEC_MASK) != 0;
    public bool IsWritable => (Protect & WRITE_MASK) != 0;
    public bool IsGuard => (Protect & PAGE_GUARD) != 0;
    public bool IsNoAccess => (Protect & 0xFF) == PAGE_NOACCESS;

    public bool AllocWasExecutable => (AllocationProtect & EXEC_MASK) != 0;

    public ulong End => Base + Size;

    public string ProtectString => ProtToString(Protect);
    public string AllocProtectString => ProtToString(AllocationProtect);

    public string TypeString => Type switch
    {
        MEM_IMAGE => "IMAGE",
        MEM_MAPPED => "MAPPED",
        MEM_PRIVATE => "PRIVATE",
        0 => "-",
        _ => $"0x{Type:X}"
    };

    public string StateString => State switch
    {
        MEM_COMMIT => "COMMIT",
        MEM_RESERVE => "RESERVE",
        MEM_FREE => "FREE",
        _ => $"0x{State:X}"
    };

    public static string ProtToString(uint p)
    {
        if (p == 0) return "-";
        string s = (p & 0xFF) switch
        {
            PAGE_NOACCESS => "---",
            PAGE_READONLY => "R--",
            PAGE_READWRITE => "RW-",
            PAGE_WRITECOPY => "RWC",
            PAGE_EXECUTE => "--X",
            PAGE_EXECUTE_READ => "R-X",
            PAGE_EXECUTE_READWRITE => "RWX",
            PAGE_EXECUTE_WRITECOPY => "RWXC",
            _ => $"0x{p & 0xFF:X2}"
        };
        if ((p & PAGE_GUARD) != 0) s += "+GUARD";
        if ((p & PAGE_NOCACHE) != 0) s += "+NC";
        if ((p & PAGE_WRITECOMBINE) != 0) s += "+WC";
        return s;
    }

    public override string ToString() =>
        $"{Base:X16}-{End:X16} {Size,12} {StateString,-7} {TypeString,-7} {ProtectString,-7} " +
        $"(alloc {AllocProtectString}) {MappedFileDos ?? MappedFile ?? ""}";
}

internal static unsafe class MemoryMap
{
    public static List<MemRegion> Enumerate(ProcessTarget t, bool includeFree = false,
        bool queryWorkingSet = true)
    {
        var list = new List<MemRegion>();
        GetSystemInfo(out var si);
        ulong max = (ulong)si.MaximumApplicationAddress.ToInt64();
        ulong addr = 0;

        while (addr < max)
        {
            MEMORY_BASIC_INFORMATION mbi;
            nuint got = VirtualQueryEx(t.Handle, (IntPtr)addr, out mbi,
                (nuint)sizeof(MEMORY_BASIC_INFORMATION));
            if (got == 0)
            {
                addr += 0x1000;
                continue;
            }

            ulong regionBase = (ulong)mbi.BaseAddress.ToInt64();
            ulong regionSize = mbi.RegionSize;
            if (regionSize == 0) { addr += 0x1000; continue; }

            if (mbi.State != MEM_FREE || includeFree)
            {
                var r = new MemRegion
                {
                    Base = regionBase,
                    Size = regionSize,
                    AllocationBase = (ulong)mbi.AllocationBase.ToInt64(),
                    AllocationProtect = mbi.AllocationProtect,
                    Protect = mbi.Protect,
                    State = mbi.State,
                    Type = mbi.Type,
                    TotalPages = (int)(regionSize / 0x1000),
                };
                Enrich(t, r, queryWorkingSet);
                list.Add(r);
            }

            ulong next = regionBase + regionSize;
            if (next <= addr) break;
            addr = next;
        }
        return list;
    }

    private static void Enrich(ProcessTarget t, MemRegion r, bool queryWorkingSet)
    {
        if (r.Type is MEM_IMAGE or MEM_MAPPED)
        {
            r.MappedFile = QueryMappedFileName(t, r.Base);
            r.MappedFileDos = r.MappedFile is null ? null : DevicePathMap.ToDos(r.MappedFile);
        }

        MEMORY_REGION_INFORMATION mri;
        if (NtQueryVirtualMemory(t.Handle, (IntPtr)r.Base,
                MEMORY_INFORMATION_CLASS.MemoryRegionInformation, &mri,
                (nuint)sizeof(MEMORY_REGION_INFORMATION), null) == 0)
        {
            r.HasRegionInfo = true;
            r.RegionInfo = mri;
        }

        if (r.Type == MEM_IMAGE)
        {
            MEMORY_IMAGE_INFORMATION mii;
            if (NtQueryVirtualMemory(t.Handle, (IntPtr)r.Base,
                    MEMORY_INFORMATION_CLASS.MemoryImageInformation, &mii,
                    (nuint)sizeof(MEMORY_IMAGE_INFORMATION), null) == 0)
            {
                r.HasImageInfo = true;
                r.ImageInfo = mii;
            }
        }

        if (queryWorkingSet && r.State == MEM_COMMIT && r.TotalPages > 0 && r.TotalPages <= 8192)
            QueryWorkingSet(t, r);
    }

    private static void QueryWorkingSet(ProcessTarget t, MemRegion r)
    {
        int n = r.TotalPages;
        var buf = new MEMORY_WORKING_SET_EX_INFORMATION[n];
        fixed (MEMORY_WORKING_SET_EX_INFORMATION* p = buf)
        {
            for (int i = 0; i < n; i++)
                p[i].VirtualAddress = (IntPtr)(r.Base + (ulong)i * 0x1000);

            int st = NtQueryVirtualMemory(t.Handle, IntPtr.Zero,
                MEMORY_INFORMATION_CLASS.MemoryWorkingSetExInformation, p,
                (nuint)(n * sizeof(MEMORY_WORKING_SET_EX_INFORMATION)), null);
            if (st != 0) return;

            int resident = 0;
            for (int i = 0; i < n; i++)
            {
                if (p[i].Valid)
                {
                    resident++;
                    if (p[i].Shared) r.AnySharedPage = true;
                    else r.AnyPrivatePage = true;
                }
            }
            r.ResidentPages = resident;
        }
    }

    public static MEMORY_WORKING_SET_EX_INFORMATION[]? QueryPages(ProcessTarget t,
        ulong baseAddr, int pages)
    {
        if (pages is <= 0 or > 65536) return null;
        var buf = new MEMORY_WORKING_SET_EX_INFORMATION[pages];
        fixed (MEMORY_WORKING_SET_EX_INFORMATION* p = buf)
        {
            for (int i = 0; i < pages; i++)
                p[i].VirtualAddress = (IntPtr)(baseAddr + (ulong)i * 0x1000);
            int st = NtQueryVirtualMemory(t.Handle, IntPtr.Zero,
                MEMORY_INFORMATION_CLASS.MemoryWorkingSetExInformation, p,
                (nuint)(pages * sizeof(MEMORY_WORKING_SET_EX_INFORMATION)), null);
            if (st != 0) return null;
        }
        return buf;
    }

    public static string? QueryMappedFileName(ProcessTarget t, ulong addr)
    {
        const int cap = 4096;
        byte* buf = stackalloc byte[cap];
        nuint ret;
        int st = NtQueryVirtualMemory(t.Handle, (IntPtr)addr,
            MEMORY_INFORMATION_CLASS.MemoryMappedFilenameInformation, buf, cap, &ret);
        if (st != 0) return null;

        var us = *(UNICODE_STRING*)buf;
        if (us.Length == 0) return null;
        return new string((char*)(buf + sizeof(UNICODE_STRING)), 0, us.Length / 2);
    }
}

internal static class DevicePathMap
{
    private static readonly Dictionary<string, string> Map = Build();

    private static Dictionary<string, string> Build()
    {
        var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var sb = new StringBuilder(1024);
        for (char c = 'A'; c <= 'Z'; c++)
        {
            sb.Clear();
            if (QueryDosDeviceW($"{c}:", sb, sb.Capacity) != 0)
                d[sb.ToString()] = $"{c}:";
        }
        return d;
    }

    public static string? ToDos(string ntPath)
    {
        foreach (var kv in Map)
        {
            if (ntPath.StartsWith(kv.Key, StringComparison.OrdinalIgnoreCase))
                return kv.Value + ntPath.Substring(kv.Key.Length);
        }
        return null;
    }

    [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet =
        System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
    private static extern int QueryDosDeviceW(string device, StringBuilder buf, int size);
}
