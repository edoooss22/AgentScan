using System.Runtime.InteropServices;

namespace AgentScan.Native;

internal static unsafe class NativeApi
{
    [Flags]
    public enum ProcessAccess : uint
    {
        Terminate = 0x0001,
        VmRead = 0x0010,
        DupHandle = 0x0040,
        QueryInformation = 0x0400,
        SetInformation = 0x0200,
        QueryLimitedInformation = 0x1000,
        Synchronize = 0x00100000,
    }

    [Flags]
    public enum ThreadAccess : uint
    {
        Terminate = 0x0001,
        QueryInformation = 0x0040,
        SetInformation = 0x0020,
        QueryLimitedInformation = 0x0800,
        Synchronize = 0x00100000,
    }

    public const uint MEM_COMMIT = 0x1000;
    public const uint MEM_RESERVE = 0x2000;
    public const uint MEM_FREE = 0x10000;
    public const uint MEM_PRIVATE = 0x20000;
    public const uint MEM_MAPPED = 0x40000;
    public const uint MEM_IMAGE = 0x1000000;

    public const uint PAGE_NOACCESS = 0x01;
    public const uint PAGE_READONLY = 0x02;
    public const uint PAGE_READWRITE = 0x04;
    public const uint PAGE_WRITECOPY = 0x08;
    public const uint PAGE_EXECUTE = 0x10;
    public const uint PAGE_EXECUTE_READ = 0x20;
    public const uint PAGE_EXECUTE_READWRITE = 0x40;
    public const uint PAGE_EXECUTE_WRITECOPY = 0x80;
    public const uint PAGE_GUARD = 0x100;
    public const uint PAGE_NOCACHE = 0x200;
    public const uint PAGE_WRITECOMBINE = 0x400;
    public const uint PAGE_TARGETS_INVALID = 0x40000000;

    public const uint EXEC_MASK = PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                  PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

    public const uint WRITE_MASK = PAGE_READWRITE | PAGE_WRITECOPY |
                                   PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        private readonly uint __alignment1;
        public ulong RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
        private readonly uint __alignment2;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(ProcessAccess access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenThread(ThreadAccess access, bool inherit, int tid);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr h);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr addr, byte* buffer,
        nuint size, out nuint read);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern nuint VirtualQueryEx(IntPtr hProcess, IntPtr addr,
        out MEMORY_BASIC_INFORMATION mbi, nuint length);




    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetProcessTimes(IntPtr hProcess, out long creation,
        out long exit, out long kernel, out long user);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool QueryFullProcessImageNameW(IntPtr hProcess, uint flags,
        char* buf, ref uint size);




    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool IsWow64Process2(IntPtr hProcess, out ushort machine,
        out ushort nativeMachine);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern int GetThreadDescription(IntPtr hThread, out IntPtr desc);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern int GetProcessId(IntPtr hProcess);



    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr LocalFree(IntPtr p);


    [DllImport("kernel32.dll")]
    public static extern void GetSystemInfo(out SYSTEM_INFO info);

    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEM_INFO
    {
        public ushort ProcessorArchitecture;
        public ushort Reserved;
        public uint PageSize;
        public IntPtr MinimumApplicationAddress;
        public IntPtr MaximumApplicationAddress;
        public IntPtr ActiveProcessorMask;
        public uint NumberOfProcessors;
        public uint ProcessorType;
        public uint AllocationGranularity;
        public ushort ProcessorLevel;
        public ushort ProcessorRevision;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct VM_COUNTERS_EX2
    {
        public nuint PeakVirtualSize;
        public nuint VirtualSize;
        public uint PageFaultCount;
        private readonly uint __pad;
        public nuint PeakWorkingSetSize;
        public nuint WorkingSetSize;
        public nuint QuotaPeakPagedPoolUsage;
        public nuint QuotaPagedPoolUsage;
        public nuint QuotaPeakNonPagedPoolUsage;
        public nuint QuotaNonPagedPoolUsage;
        public nuint PagefileUsage;
        public nuint PeakPagefileUsage;
        public nuint PrivateUsage;
        public nuint PrivateWorkingSetSize;
        public nuint SharedCommitUsage;
    }

    public enum PROCESSINFOCLASS
    {
        ProcessBasicInformation = 0,
        ProcessVmCounters = 3,
        ProcessDebugPort = 7,
        ProcessWow64Information = 26,
        ProcessImageFileName = 27,
        ProcessDebugObjectHandle = 30,
        ProcessDebugFlags = 31,
        ProcessCookie = 36,
        ProcessImageFileNameWin32 = 43,
        ProcessCommandLineInformation = 60,
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
    {
        public uint Version;
        public uint Reserved;
        public IntPtr Callback;
    }

    public enum THREADINFOCLASS
    {
        ThreadQuerySetWin32StartAddress = 9,
    }

    public enum MEMORY_INFORMATION_CLASS
    {
        MemoryBasicInformation = 0,
        MemoryMappedFilenameInformation = 2,
        MemoryRegionInformation = 3,
        MemoryWorkingSetExInformation = 4,
        MemoryImageInformation = 6,
    }

    public enum SYSTEM_INFORMATION_CLASS
    {
        SystemProcessInformation = 5,
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_BASIC_INFORMATION
    {
        public uint ExitStatus;
        private readonly uint __pad;
        public IntPtr PebBaseAddress;
        public IntPtr AffinityMask;
        public int BasePriority;
        private readonly uint __pad2;
        public IntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct THREAD_BASIC_INFORMATION
    {
        public uint ExitStatus;
        private readonly uint __pad;
        public IntPtr TebBaseAddress;
        public IntPtr UniqueProcess;
        public IntPtr UniqueThread;
        public IntPtr AffinityMask;
        public int Priority;
        public int BasePriority;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KERNEL_USER_TIMES
    {
        public long CreateTime;
        public long ExitTime;
        public long KernelTime;
        public long UserTime;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_REGION_INFORMATION
    {
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public uint Flags;
        public ulong RegionSize;
        public ulong CommitSize;
        public ulong PartitionId;
        public ulong NodePreference;

        public bool IsPrivate => (Flags & 1) != 0;
        public bool IsMappedDataFile => (Flags & 2) != 0;
        public bool IsMappedImage => (Flags & 4) != 0;
        public bool IsMappedPageFile => (Flags & 8) != 0;
        public bool IsMappedPhysical => (Flags & 0x10) != 0;
        public bool IsDirectMapped => (Flags & 0x20) != 0;
        public bool IsSoftwareEnclave => (Flags & 0x40) != 0;
        public bool IsPlaceholderReservation => (Flags & 0x100) != 0;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_IMAGE_INFORMATION
    {
        public IntPtr ImageBase;
        public ulong SizeOfImage;
        public uint ImageFlags;

        public bool ImagePartialMap => (ImageFlags & 1) != 0;
        public bool ImageNotExecutable => (ImageFlags & 2) != 0;
        public int ImageSigningLevel => (int)((ImageFlags >> 2) & 0xF);
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_WORKING_SET_EX_INFORMATION
    {
        public IntPtr VirtualAddress;
        public ulong VirtualAttributes;

        public bool Valid => (VirtualAttributes & 1) != 0;
        public int ShareCount => (int)((VirtualAttributes >> 1) & 0x7);
        public uint Win32Protection => (uint)((VirtualAttributes >> 4) & 0x7FF);
        public bool Shared => ((VirtualAttributes >> 15) & 1) != 0;
        public bool Locked => ((VirtualAttributes >> 22) & 1) != 0;
        public bool LargePage => ((VirtualAttributes >> 23) & 1) != 0;
        public bool Bad => ((VirtualAttributes >> 31) & 1) != 0;

        public bool SharedOriginal => ((VirtualAttributes >> 30) & 1) != 0;

        public int Priority => (int)((VirtualAttributes >> 24) & 0x7);

        public int Node => (int)((VirtualAttributes >> 16) & 0x3F);

        public bool InvalidPageTable => !Valid && ((VirtualAttributes >> 21) & 1) != 0;

        public int InvalidLocation => (int)((VirtualAttributes >> 22) & 0x3);

        public bool InvalidModifiedList => !Valid && ((VirtualAttributes >> 27) & 1) != 0;

        public string LocationString => InvalidLocation switch
        {
            0 => "нет нигде (нулевая либо в файле подкачки)",
            1 => "переходное состояние (список ожидания/изменённых)",
            2 => "в файле подкачки",
            3 => "в спроецированном файле",
            _ => "?",
        };

        public bool HasContent => Valid || InvalidLocation != 0 || InvalidModifiedList;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        private readonly uint __pad;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct OBJECT_TYPE_INFORMATION
    {
        public UNICODE_STRING TypeName;
        public uint TotalNumberOfObjects;
        public uint TotalNumberOfHandles;
        public uint TotalPagedPoolUsage;
        public uint TotalNonPagedPoolUsage;
        public uint TotalNamePoolUsage;
        public uint TotalHandleTableUsage;
        public uint HighWaterNumberOfObjects;
        public uint HighWaterNumberOfHandles;
        public uint HighWaterPagedPoolUsage;
        public uint HighWaterNonPagedPoolUsage;
        public uint HighWaterNamePoolUsage;
        public uint HighWaterHandleTableUsage;
        public uint InvalidAttributes;
        public uint GenericRead, GenericWrite, GenericExecute, GenericAll;
        public uint ValidAccessMask;
        public byte SecurityRequired;
        public byte MaintainHandleCount;
        public byte TypeIndex;
        public byte ReservedByte;
        public uint PoolType;
        public uint DefaultPagedPoolCharge;
        public uint DefaultNonPagedPoolCharge;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
    {
        public IntPtr Object;
        public IntPtr UniqueProcessId;
        public IntPtr HandleValue;
        public uint GrantedAccess;
        public ushort CreatorBackTraceIndex;
        public ushort ObjectTypeIndex;
        public uint HandleAttributes;
        private readonly uint __reserved;
    }

    [DllImport("ntdll.dll")]
    public static extern int NtQueryInformationProcess(IntPtr hProcess, PROCESSINFOCLASS cls,
        void* buffer, uint len, uint* retLen);

    [DllImport("ntdll.dll")]
    public static extern int NtQueryInformationThread(IntPtr hThread, THREADINFOCLASS cls,
        void* buffer, uint len, uint* retLen);

    [DllImport("ntdll.dll")]
    public static extern int NtQueryVirtualMemory(IntPtr hProcess, IntPtr addr,
        MEMORY_INFORMATION_CLASS cls, void* buffer, nuint len, nuint* retLen);

    [DllImport("ntdll.dll")]
    public static extern int NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS cls,
        void* buffer, uint len, uint* retLen);


    public enum SECTION_INFORMATION_CLASS
    {
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SECTION_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public uint AllocationAttributes;
        private readonly uint __pad;
        public long MaximumSize;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SECTION_IMAGE_INFORMATION
    {
        public IntPtr TransferAddress;
        public uint ZeroBits;
        private readonly uint __pad0;
        public nuint MaximumStackSize;
        public nuint CommittedStackSize;
        public uint SubSystemType;
        public ushort SubSystemMinorVersion;
        public ushort SubSystemMajorVersion;
        public uint OperatingSystemVersion;
        public ushort ImageCharacteristics;
        public ushort DllCharacteristics;
        public ushort Machine;
        public byte ImageContainsCode;
        public byte ImageFlags;
        public uint LoaderFlags;
        public uint ImageFileSize;
        public uint CheckSum;
    }

    public const uint SEC_BASED = 0x00200000;
    public const uint SEC_NO_CHANGE = 0x00400000;
    public const uint SEC_FILE = 0x00800000;
    public const uint SEC_IMAGE = 0x01000000;
    public const uint SEC_PROTECTED_IMAGE = 0x02000000;
    public const uint SEC_RESERVE = 0x04000000;
    public const uint SEC_COMMIT = 0x08000000;
    public const uint SEC_NOCACHE = 0x10000000;
    public const uint SEC_WRITECOMBINE = 0x40000000;
    public const uint SEC_LARGE_PAGES = 0x80000000;




    [StructLayout(LayoutKind.Sequential)]
    private struct LUID { public uint Low; public int High; }

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        public LUID Luid;
        public uint Attributes;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr hProcess, uint access, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LookupPrivilegeValueW(string? system, string name, out LUID luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll,
        ref TOKEN_PRIVILEGES newState, uint len, IntPtr prev, IntPtr retLen);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    public static bool EnablePrivilege(string name)
    {
        if (!OpenProcessToken(GetCurrentProcess(), 0x0020  | 0x0008 , out var tok))
            return false;
        try
        {
            if (!LookupPrivilegeValueW(null, name, out var luid)) return false;
            var tp = new TOKEN_PRIVILEGES
            {
                PrivilegeCount = 1,
                Luid = luid,
                Attributes = 0x00000002
            };
            if (!AdjustTokenPrivileges(tok, false, ref tp, (uint)sizeof(TOKEN_PRIVILEGES),
                    IntPtr.Zero, IntPtr.Zero))
                return false;
            return Marshal.GetLastWin32Error() == 0;
        }
        finally { CloseHandle(tok); }
    }

    public const int CONTEXT_SIZE = 1232;
    public const int CONTEXT_ALIGN = 16;
    public const uint CONTEXT_AMD64 = 0x00100000;
    public const uint CONTEXT_CONTROL = CONTEXT_AMD64 | 0x1;
    public const uint CONTEXT_INTEGER = CONTEXT_AMD64 | 0x2;
    public const uint CONTEXT_SEGMENTS = CONTEXT_AMD64 | 0x4;
    public const uint CONTEXT_DEBUG_REGISTERS = CONTEXT_AMD64 | 0x10;

    public const int CTX_OFF_FLAGS = 0x30;
    public const int CTX_OFF_DR0 = 0x48;
    public const int CTX_OFF_DR1 = 0x50;
    public const int CTX_OFF_DR2 = 0x58;
    public const int CTX_OFF_DR3 = 0x60;
    public const int CTX_OFF_DR6 = 0x68;
    public const int CTX_OFF_DR7 = 0x70;
    public const int CTX_OFF_RSP = 0x98;
    public const int CTX_OFF_RIP = 0xF8;

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid action, ref WINTRUST_DATA data);

}
