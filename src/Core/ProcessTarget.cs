using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using AgentScan.Native;
using static AgentScan.Native.NativeApi;

namespace AgentScan.Core;

internal sealed unsafe class ProcessTarget : IDisposable
{
    public int Pid { get; }
    public IntPtr Handle { get; private set; }
    public string ImagePath { get; private set; } = "";
    public DateTime StartTimeUtc { get; private set; }
    public IntPtr PebAddress { get; private set; }
    public int ParentPid { get; private set; }
    public bool IsWow64 { get; private set; }
    public string OpenedWith { get; private set; } = "";

    public List<string> Warnings { get; } = new();

    private ProcessTarget(int pid, IntPtr handle)
    {
        Pid = pid;
        Handle = handle;
    }

    public static ProcessTarget Open(int pid)
    {
        var levels = new (ProcessAccess acc, string name)[]
        {
            (ProcessAccess.QueryInformation | ProcessAccess.VmRead | ProcessAccess.DupHandle,
                "QUERY_INFORMATION|VM_READ|DUP_HANDLE"),
            (ProcessAccess.QueryInformation | ProcessAccess.VmRead,
                "QUERY_INFORMATION|VM_READ"),
            (ProcessAccess.QueryLimitedInformation | ProcessAccess.VmRead,
                "QUERY_LIMITED_INFORMATION|VM_READ"),
            (ProcessAccess.QueryLimitedInformation, "QUERY_LIMITED_INFORMATION"),
        };

        IntPtr h = IntPtr.Zero;
        string used = "";
        foreach (var (acc, name) in levels)
        {
            h = OpenProcess(acc, false, pid);
            if (h != IntPtr.Zero) { used = name; break; }
        }
        if (h == IntPtr.Zero)
            throw new InvalidOperationException(
                $"OpenProcess({pid}) не удался: Win32 error {Marshal.GetLastWin32Error()}. " +
                "Запустите сканер от администратора.");

        var t = new ProcessTarget(pid, h) { OpenedWith = used };
        t.Init();
        return t;
    }

    private void Init()
    {
        uint cap = 4096;
        var buf = stackalloc char[(int)cap];
        if (QueryFullProcessImageNameW(Handle, 0, buf, ref cap))
            ImagePath = new string(buf, 0, (int)cap);
        else
            Warnings.Add("QueryFullProcessImageName failed");

        if (GetProcessTimes(Handle, out long create, out _, out _, out _))
            StartTimeUtc = DateTime.FromFileTimeUtc(create);

        PROCESS_BASIC_INFORMATION pbi;
        uint ret;
        int st = NtQueryInformationProcess(Handle, PROCESSINFOCLASS.ProcessBasicInformation,
            &pbi, (uint)sizeof(PROCESS_BASIC_INFORMATION), &ret);
        if (st == 0)
        {
            PebAddress = pbi.PebBaseAddress;
            ParentPid = (int)pbi.InheritedFromUniqueProcessId.ToInt64();
        }
        else Warnings.Add($"NtQueryInformationProcess(BasicInformation) = 0x{st:X8}");

        if (IsWow64Process2(Handle, out ushort machine, out _))
            IsWow64 = machine != 0;
    }

    public HashSet<ulong>? NoReadPages;

    public bool TryRead(ulong address, Span<byte> dest)
    {
        if (NoReadPages is { Count: > 0 } && Touches(address, dest.Length))
            return ReadAroundCanaries(address, dest);

        fixed (byte* p = dest)
        {
            return ReadProcessMemory(Handle, (IntPtr)address, p, (nuint)dest.Length, out var read)
                   && read == (nuint)dest.Length;
        }
    }

    private bool Touches(ulong address, int length)
    {
        ulong first = address & ~0xFFFUL;
        ulong last = (address + (ulong)Math.Max(0, length - 1)) & ~0xFFFUL;
        if (last - first > 0x1000_0000) return false;
        for (ulong p = first; p <= last; p += 0x1000)
            if (NoReadPages!.Contains(p)) return true;
        return false;
    }

    private bool ReadAroundCanaries(ulong address, Span<byte> dest)
    {
        bool all = true;
        int done = 0;
        while (done < dest.Length)
        {
            ulong a = address + (ulong)done;
            ulong page = a & ~0xFFFUL;
            int inPage = (int)(0x1000 - (a - page));
            int len = Math.Min(inPage, dest.Length - done);
            var slice = dest.Slice(done, len);
            if (NoReadPages!.Contains(page))
            {
                slice.Clear();
            }
            else
            {
                bool ok;
                fixed (byte* p = slice)
                    ok = ReadProcessMemory(Handle, (IntPtr)a, p, (nuint)len, out var read)
                         && read == (nuint)len;
                if (!ok) { slice.Clear(); all = false; }
            }
            done += len;
        }
        return all;
    }

    public int ReadPartial(ulong address, Span<byte> dest, out bool[] pageOk)
    {
        const int PAGE = 0x1000;
        int pages = (dest.Length + PAGE - 1) / PAGE;
        pageOk = new bool[pages];
        int total = 0;

        if (TryRead(address, dest))
        {
            for (int i = 0; i < pages; i++) pageOk[i] = true;
            return dest.Length;
        }

        for (int i = 0; i < pages; i++)
        {
            int off = i * PAGE;
            int len = Math.Min(PAGE, dest.Length - off);
            if (TryRead(address + (ulong)off, dest.Slice(off, len)))
            {
                pageOk[i] = true;
                total += len;
            }
            else
            {
                dest.Slice(off, len).Clear();
            }
        }
        return total;
    }

    public byte[]? ReadBytes(ulong address, int length)
    {
        if (length <= 0 || length > 0x8000000) return null;
        var b = new byte[length];
        return TryRead(address, b) ? b : null;
    }

    public byte ReadU8(ulong a) { byte v = 0; TryRead(a, new Span<byte>(&v, 1)); return v; }

    public ushort ReadU16(ulong a)
    {
        ushort v = 0;
        TryRead(a, new Span<byte>(&v, 2));
        return v;
    }

    public uint ReadU32(ulong a)
    {
        uint v = 0;
        TryRead(a, new Span<byte>(&v, 4));
        return v;
    }

    public ulong ReadU64(ulong a)
    {
        ulong v = 0;
        TryRead(a, new Span<byte>(&v, 8));
        return v;
    }

    public bool TryReadU64(ulong a, out ulong v)
    {
        ulong t = 0;
        bool ok = TryRead(a, new Span<byte>(&t, 8));
        v = t;
        return ok;
    }

    public string? ReadUnicodeString(ulong structAddr)
    {
        UNICODE_STRING us;
        if (!TryRead(structAddr, new Span<byte>(&us, sizeof(UNICODE_STRING)))) return null;
        return ReadUnicodeString(us);
    }

    public string? ReadUnicodeString(UNICODE_STRING us)
    {
        if (us.Buffer == IntPtr.Zero || us.Length == 0 || us.Length > 0xFFF0) return null;
        var b = new byte[us.Length];
        if (!TryRead((ulong)us.Buffer, b)) return null;
        return Encoding.Unicode.GetString(b);
    }

    public const int PEB_ImageBaseAddress = 0x10;
    public const int PEB_Ldr = 0x18;
    public const int PEB_ProcessParameters = 0x20;
    public const int PEB_ProcessHeap = 0x30;
    public const int PEB_ApiSetMap = 0x68;
    public const int PEB_NumberOfHeaps = 0xE8;

    public const int RUPP_CurrentDirectory = 0x38;
    public const int RUPP_DllPath = 0x50;
    public const int RUPP_CommandLine = 0x70;
    public const int RUPP_Environment = 0x80;
    public const int RUPP_WindowTitle = 0xB0;
    public const int RUPP_EnvironmentSize = 0x3F0;

    public ulong ProcessParametersAddress =>
        PebAddress == IntPtr.Zero ? 0 : ReadU64((ulong)PebAddress + PEB_ProcessParameters);

    public string? GetCommandLine()
    {
        ulong pp = ProcessParametersAddress;
        return pp == 0 ? null : ReadUnicodeString(pp + RUPP_CommandLine);
    }


    public string? GetCurrentDirectory()
    {
        ulong pp = ProcessParametersAddress;
        return pp == 0 ? null : ReadUnicodeString(pp + RUPP_CurrentDirectory);
    }

    public string? GetDllPath()
    {
        ulong pp = ProcessParametersAddress;
        return pp == 0 ? null : ReadUnicodeString(pp + RUPP_DllPath);
    }

    public List<string> GetEnvironment()
    {
        var result = new List<string>();
        ulong pp = ProcessParametersAddress;
        if (pp == 0) return result;

        ulong envPtr = ReadU64(pp + RUPP_Environment);
        if (envPtr == 0) return result;

        ulong envSize = ReadU64(pp + RUPP_EnvironmentSize);
        if (envSize == 0 || envSize > 1 << 20) envSize = 0x8000;

        var raw = new byte[(int)envSize];
        ReadPartial(envPtr, raw, out _);

        var s = Encoding.Unicode.GetString(raw);
        foreach (var part in s.Split('\0'))
        {
            if (part.Length == 0) continue;
            result.Add(part);
        }
        return result;
    }



    public ulong ImageBase =>
        PebAddress == IntPtr.Zero ? 0 : ReadU64((ulong)PebAddress + PEB_ImageBaseAddress);

    public const int PEB_CrossProcessFlags = 0x50;
    public const int PEB_KernelCallbackTable = 0x58;
    public const int PEB_pShimData = 0x2D8;
    public const int PEB_ActivationContextData = 0x2F8;

    public uint CrossProcessFlags =>
        PebAddress == IntPtr.Zero ? 0 : ReadU32((ulong)PebAddress + PEB_CrossProcessFlags);

    public ulong KernelCallbackTable =>
        PebAddress == IntPtr.Zero ? 0 : ReadU64((ulong)PebAddress + PEB_KernelCallbackTable);

    public ulong ApiSetMap =>
        PebAddress == IntPtr.Zero ? 0 : ReadU64((ulong)PebAddress + PEB_ApiSetMap);

    public ulong ProcessHeap =>
        PebAddress == IntPtr.Zero ? 0 : ReadU64((ulong)PebAddress + PEB_ProcessHeap);

    public uint NumberOfHeaps =>
        PebAddress == IntPtr.Zero ? 0 : ReadU32((ulong)PebAddress + PEB_NumberOfHeaps);






    public void Dispose()
    {
        if (Handle != IntPtr.Zero)
        {
            CloseHandle(Handle);
            Handle = IntPtr.Zero;
        }
    }

    public sealed record Candidate(int Pid, string Name, string ExePath, string CommandLine,
        DateTime StartUtc, bool LooksLikeMinecraft, string Reason);

    public static List<Candidate> FindJavaProcesses()
    {
        var list = new List<Candidate>();
        foreach (var p in Process.GetProcesses())
        {
            string name;
            try { name = p.ProcessName; } catch { continue; }
            bool javaish = name.Equals("java", StringComparison.OrdinalIgnoreCase)
                        || name.Equals("javaw", StringComparison.OrdinalIgnoreCase)
                        || name.Equals("minecraft", StringComparison.OrdinalIgnoreCase);
            if (!javaish) { p.Dispose(); continue; }

            string exe = "", cmd = "";
            DateTime start = default;
            try { start = p.StartTime.ToUniversalTime(); } catch { }

            try
            {
                using var t = Open(p.Id);
                exe = t.ImagePath;
                cmd = t.GetCommandLine() ?? "";
            }
            catch { }

            string reason = "";
            bool mc = false;
            if (cmd.Contains("net.minecraft", StringComparison.OrdinalIgnoreCase)) { mc = true; reason = "cmdline: net.minecraft"; }
            else if (cmd.Contains("fabricmc", StringComparison.OrdinalIgnoreCase)) { mc = true; reason = "cmdline: fabric loader"; }
            else if (cmd.Contains("cpw.mods", StringComparison.OrdinalIgnoreCase) || cmd.Contains("forge", StringComparison.OrdinalIgnoreCase)) { mc = true; reason = "cmdline: forge"; }
            else if (cmd.Contains("minecraft", StringComparison.OrdinalIgnoreCase)) { mc = true; reason = "cmdline: minecraft"; }
            else if (cmd.Contains("lwjgl", StringComparison.OrdinalIgnoreCase)) { mc = true; reason = "cmdline: lwjgl"; }

            list.Add(new Candidate(p.Id, name, exe, cmd, start, mc, reason));
            p.Dispose();
        }
        return list;
    }
}
