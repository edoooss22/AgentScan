using AgentScan.Native;
using static AgentScan.Native.NativeApi;

namespace AgentScan.Core;

internal sealed class LdrModule
{
    public ulong EntryAddress;
    public ulong DllBase;
    public ulong EntryPoint;
    public uint SizeOfImage;
    public string FullDllName = "";
    public string BaseDllName = "";
    public uint Flags;
    public ushort LoadCount;
    public uint TimeDateStamp;
    public ulong OriginalBase;
    public long LoadTimeRaw;
    public uint LoadReason;

    public const uint LoadReasonDynamicLoad = 4;
    public byte SigningLevel;
    public uint BaseNameHashValue;

    public bool InLoadOrder, InMemoryOrder, InInitOrder;

    public int LoadOrderIndex, MemoryOrderIndex, InitOrderIndex;

    public DateTime? LoadTimeUtc =>
        LoadTimeRaw > 0 && LoadTimeRaw < 0x7FFF_FFFF_FFFF_FFFF
            ? DateTime.FromFileTimeUtc(LoadTimeRaw)
            : null;

    public string LoadReasonString => LoadReason switch
    {
        0xFFFFFFFF => "Unknown",
        0 => "StaticDependency",
        1 => "StaticForwarderDependency",
        2 => "DynamicForwarderDependency",
        3 => "DelayloadDependency",
        4 => "DynamicLoad (LoadLibrary)",
        5 => "AsImageLoad",
        6 => "AsDataLoad",
        7 => "EnclavePrimary",
        8 => "EnclaveDependency",
        9 => "PatchImage",
        _ => $"0x{LoadReason:X}"
    };

    public string SigningLevelString => SigningLevel switch
    {
        0 => "Unchecked",
        1 => "Unsigned",
        2 => "Enterprise",
        3 => "Custom1/Developer",
        4 => "Authenticode",
        5 => "Custom2",
        6 => "Store",
        7 => "Antimalware",
        8 => "Microsoft",
        12 => "Windows",
        14 => "WindowsTcb",
        _ => $"0x{SigningLevel:X}"
    };

    public string ListMembership =>
        (InLoadOrder ? "L" : "-") + (InMemoryOrder ? "M" : "-") + (InInitOrder ? "I" : "-");

    public ulong End => DllBase + SizeOfImage;
}

internal static unsafe class LoaderModules
{
    private const int LDR_InLoadOrderModuleList = 0x10;
    private const int LDR_InMemoryOrderModuleList = 0x20;
    private const int LDR_InInitializationOrderModuleList = 0x30;

    private const int E_InLoadOrderLinks = 0x00;
    private const int E_InMemoryOrderLinks = 0x10;
    private const int E_InInitializationOrderLinks = 0x20;
    private const int E_DllBase = 0x30;
    private const int E_EntryPoint = 0x38;
    private const int E_SizeOfImage = 0x40;
    private const int E_FullDllName = 0x48;
    private const int E_BaseDllName = 0x58;
    private const int E_Flags = 0x68;
    private const int E_ObsoleteLoadCount = 0x6C;
    private const int E_TimeDateStamp = 0x80;
    private const int E_OriginalBase = 0xF8;
    private const int E_LoadTime = 0x100;
    private const int E_BaseNameHashValue = 0x108;
    private const int E_LoadReason = 0x10C;
    private const int E_SigningLevel = 0x11C;

    public sealed class Result
    {
        public List<LdrModule> Modules = new();
        public List<string> Errors = new();
        public int LoadOrderCount, MemoryOrderCount, InitOrderCount;
        public ulong LdrAddress;
        public bool LdrInitialized;
    }

    public static Result Enumerate(ProcessTarget t)
    {
        var res = new Result();
        if (t.PebAddress == IntPtr.Zero)
        {
            res.Errors.Add("PEB недоступен — список модулей из загрузчика не прочитан.");
            return res;
        }

        ulong ldr = t.ReadU64((ulong)t.PebAddress + ProcessTarget.PEB_Ldr);
        res.LdrAddress = ldr;
        if (ldr == 0)
        {
            res.Errors.Add("PEB->Ldr == 0");
            return res;
        }
        res.LdrInitialized = t.ReadU8(ldr + 4) != 0;

        var byEntry = new Dictionary<ulong, LdrModule>();

        res.LoadOrderCount = Walk(t, ldr + LDR_InLoadOrderModuleList, E_InLoadOrderLinks,
            byEntry, res, (m, i) => { m.InLoadOrder = true; m.LoadOrderIndex = i; });
        res.MemoryOrderCount = Walk(t, ldr + LDR_InMemoryOrderModuleList, E_InMemoryOrderLinks,
            byEntry, res, (m, i) => { m.InMemoryOrder = true; m.MemoryOrderIndex = i; });
        res.InitOrderCount = Walk(t, ldr + LDR_InInitializationOrderModuleList,
            E_InInitializationOrderLinks, byEntry, res,
            (m, i) => { m.InInitOrder = true; m.InitOrderIndex = i; });

        res.Modules = byEntry.Values.OrderBy(m => m.DllBase).ToList();
        return res;
    }

    private static int Walk(ProcessTarget t, ulong listHead, int linkOffset,
        Dictionary<ulong, LdrModule> sink, Result res, Action<LdrModule, int> mark)
    {
        int count = 0;
        ulong flink = t.ReadU64(listHead);
        var seen = new HashSet<ulong>();

        while (flink != 0 && flink != listHead && count < 4096)
        {
            if (!seen.Add(flink))
            {
                res.Errors.Add($"Цикл в списке загрузчика по адресу 0x{flink:X} " +
                               "(повреждённая/подделанная структура).");
                break;
            }

            ulong entry = flink - (ulong)linkOffset;
            if (!sink.TryGetValue(entry, out var m))
            {
                m = ReadEntry(t, entry);
                if (m is null)
                {
                    res.Errors.Add($"Не удалось прочитать LDR_DATA_TABLE_ENTRY по 0x{entry:X}");
                    break;
                }
                sink[entry] = m;
            }
            count++;
            mark(m, count);

            ulong next = t.ReadU64(flink);
            if (next == flink) break;
            flink = next;
        }
        return count;
    }

    private static LdrModule? ReadEntry(ProcessTarget t, ulong entry)
    {
        var buf = new byte[0x140];
        if (!t.TryRead(entry, buf)) return null;

        fixed (byte* p = buf)
        {
            var m = new LdrModule
            {
                EntryAddress = entry,
                DllBase = *(ulong*)(p + E_DllBase),
                EntryPoint = *(ulong*)(p + E_EntryPoint),
                SizeOfImage = *(uint*)(p + E_SizeOfImage),
                Flags = *(uint*)(p + E_Flags),
                LoadCount = *(ushort*)(p + E_ObsoleteLoadCount),
                TimeDateStamp = *(uint*)(p + E_TimeDateStamp),
                OriginalBase = *(ulong*)(p + E_OriginalBase),
                LoadTimeRaw = *(long*)(p + E_LoadTime),
                BaseNameHashValue = *(uint*)(p + E_BaseNameHashValue),
                LoadReason = *(uint*)(p + E_LoadReason),
                SigningLevel = *(p + E_SigningLevel),
            };
            m.FullDllName = t.ReadUnicodeString(*(UNICODE_STRING*)(p + E_FullDllName)) ?? "";
            m.BaseDllName = t.ReadUnicodeString(*(UNICODE_STRING*)(p + E_BaseDllName)) ?? "";
            return m;
        }
    }

    public static string DecodeFlags(uint f)
    {
        var parts = new List<string>();
        void Add(int bit, string name) { if ((f & (1u << bit)) != 0) parts.Add(name); }
        Add(0, "PackagedBinary");
        Add(1, "MarkedForRemoval");
        Add(2, "ImageDll");
        Add(3, "LoadNotificationsSent");
        Add(4, "TelemetryEntryProcessed");
        Add(5, "ProcessStaticImport");
        Add(6, "InLegacyLists");
        Add(7, "InIndexes");
        Add(8, "ShimDll");
        Add(9, "InExceptionTable");
        Add(12, "LoadInProgress");
        Add(13, "LoadConfigProcessed");
        Add(14, "EntryProcessed");
        Add(15, "ProtectDelayLoad");
        Add(18, "DontCallForThreads");
        Add(19, "ProcessAttachCalled");
        Add(20, "ProcessAttachFailed");
        Add(21, "CorDeferredValidate");
        Add(22, "CorImage");
        Add(23, "DontRelocate");
        Add(24, "CorILOnly");
        Add(25, "ChpeImage");
        Add(26, "ChpeEmulatorImage");
        Add(28, "Redirected");
        Add(31, "CompatDatabaseProcessed");
        return parts.Count == 0 ? "-" : string.Join("|", parts);
    }
}
