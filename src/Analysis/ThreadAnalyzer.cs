using System.Runtime.InteropServices;
using static AgentScan.Native.NativeApi;

namespace AgentScan.Analysis;

internal sealed class ThreadInfo
{
    public int Tid;
    public ulong KernelStartAddress;
    public ulong Win32StartAddress;
    public DateTime CreateTimeUtc;
    public string? Description;
}

internal static unsafe class ThreadAnalyzer
{
    public static void Run(ScanContext ctx)
    {
        var threads = Enumerate(ctx.Target.Pid);
        foreach (var th in threads) Fill(th);
        ctx.Threads = threads;
    }

    public static List<ThreadInfo> Enumerate(int pid)
    {
        var result = new List<ThreadInfo>();
        uint size = 1 << 20;
        IntPtr buf = IntPtr.Zero;
        try
        {
            for (int attempt = 0; attempt < 8; attempt++)
            {
                if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf);
                buf = Marshal.AllocHGlobal((int)size);
                uint ret = 0;
                int st = NtQuerySystemInformation(
                    SYSTEM_INFORMATION_CLASS.SystemProcessInformation,
                    (void*)buf, size, &ret);
                if (st == unchecked((int)0xC0000004) )
                {
                    size = Math.Max(ret + (1 << 20), size * 2);
                    continue;
                }
                if (st != 0) return result;
                break;
            }

            byte* p = (byte*)buf;
            while (true)
            {
                uint next = *(uint*)p;
                uint nThreads = *(uint*)(p + 4);
                long procId = *(long*)(p + 0x50);
                if (procId == pid)
                {
                    byte* th = p + 0x100;
                    for (uint i = 0; i < nThreads && i < 100000; i++, th += 0x50)
                    {
                        var ti = new ThreadInfo
                        {
                            CreateTimeUtc = FromFileTime(*(long*)(th + 0x10)),
                            KernelStartAddress = *(ulong*)(th + 0x20),
                            Tid = (int)*(long*)(th + 0x30),
                        };
                        result.Add(ti);
                    }
                    break;
                }
                if (next == 0) break;
                p += next;
            }
        }
        finally
        {
            if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf);
        }
        return result;
    }

    private static DateTime FromFileTime(long ft)
    {
        try { return ft > 0 ? DateTime.FromFileTimeUtc(ft) : default; }
        catch { return default; }
    }

    private static void Fill(ThreadInfo th)
    {
        IntPtr h = OpenThread(ThreadAccess.QueryInformation, false, th.Tid);
        if (h == IntPtr.Zero) h = OpenThread(ThreadAccess.QueryLimitedInformation, false, th.Tid);
        if (h == IntPtr.Zero) return;
        try
        {
            ulong start = 0;
            if (NtQueryInformationThread(h, THREADINFOCLASS.ThreadQuerySetWin32StartAddress,
                    &start, 8, null) == 0)
                th.Win32StartAddress = start;

            if (GetThreadDescription(h, out IntPtr desc) >= 0 && desc != IntPtr.Zero)
            {
                string s = Marshal.PtrToStringUni(desc) ?? "";
                if (s.Length > 0) th.Description = s;
                LocalFree(desc);
            }
        }
        finally { CloseHandle(h); }
    }
}
