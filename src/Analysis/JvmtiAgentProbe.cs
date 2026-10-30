using System.Text;
using AgentScan.Core;

namespace AgentScan.Analysis;

internal sealed class AgentRecord
{
    public ulong Address;
    public string? Name;
    public string? Options;
    public ulong OsLib;
    public string? OsLibPath;
    public ulong Jplis;
    public bool Dynamic;
    public bool AbsolutePath;
    public bool StaticLib;
    public bool InstrumentLib;
    public bool Loaded;
    public bool FlagsFound;
    public bool DynamicKnown;
    public byte[]? Dump;
    public string? OsLibModule;
    public List<ulong> Pointers { get; } = new();
    public List<string> Notes { get; } = new();
    public List<string> Layout { get; } = new();

    public string HowLoaded => !FlagsFound || !DynamicKnown ? "способ подключения не восстановлен"
        : Dynamic ? "подключён К РАБОТАЮЩЕЙ ВМ (Attach API)"
        : "подключён при запуске ВМ (аргумент командной строки)";

    public string Describe() =>
        $"{Name ?? OsLibPath ?? $"0x{Address:X}"} — {HowLoaded}";
}

internal static class JvmtiAgentProbe
{
    private const int Window = 0x60;
    private const int Slots = Window / 8;

    public static AgentRecord? TryRead(ScanContext ctx, ulong addr, bool requireHard = true)
    {
        if (addr is < 0x10000 or > 0x7FFFFFFFFFFF) return null;
        if ((addr & 7) != 0) return null;
        var reg = ctx.RegionAt(addr);
        if (reg is null || !reg.IsCommitted || reg.IsGuard || reg.IsNoAccess) return null;
        if (reg.IsExecutable) return null;

        var d = ctx.Target.ReadBytes(addr, Window);
        if (d is null) return null;

        var r = new AgentRecord { Address = addr, Dump = d };
        bool hard = false;
        var strings = new List<(int Slot, string Text)>();

        for (int i = 0; i < Slots; i++)
        {
            ulong v = BitConverter.ToUInt64(d, i * 8);

            if (!r.FlagsFound && IsFlagBlock(d, i * 8))
            {
                int o = i * 8;
                if (JdkMajor(ctx) >= 21)
                {
                    r.Loaded = d[o] != 0;
                    r.AbsolutePath = d[o + 1] != 0;
                    r.StaticLib = d[o + 2] != 0;
                    r.InstrumentLib = d[o + 3] != 0;
                    r.Dynamic = d[o + 4] != 0;
                    r.DynamicKnown = true;
                }
                else
                {
                    r.AbsolutePath = d[o] != 0;
                    r.StaticLib = d[o + 1] != 0;
                    r.InstrumentLib = d[o + 2] != 0;
                    r.Loaded = d[o + 4] != 0;
                }
                r.FlagsFound = true;
                r.Layout.Add($"+0x{i * 8:X2}  флаги: dynamic={(r.DynamicKnown ? r.Dynamic.ToString() : "нет поля")}, " +
                             $"absolute_path={r.AbsolutePath}, static_lib={r.StaticLib}, " +
                             $"instrument_lib={r.InstrumentLib}, loaded={r.Loaded}");
                continue;
            }

            if (v is < 0x10000 or > 0x7FFFFFFFFFFF) continue;

            if ((v & 0xFFFF) == 0 && r.OsLib == 0)
            {
                var im = ctx.ImageAt(v);
                if (im is not null && im.Base == v)
                {
                    r.OsLib = v;
                    r.OsLibModule = im.Name;
                    r.Layout.Add($"+0x{i * 8:X2}  дескриптор библиотеки → {im.Name}");
                    hard = true;
                    continue;
                }
                if (im is null && ctx.RegionAt(v) is null)
                {
                    r.OsLib = v;
                    r.Notes.Add("дескриптор библиотеки указывает в НЕ ОТОБРАЖЁННУЮ область: " +
                                "библиотека агента была загружена и уже выгружена");
                    r.Layout.Add($"+0x{i * 8:X2}  дескриптор выгруженной библиотеки 0x{v:X}");
                    hard = true;
                    continue;
                }
            }

            string? s = ReadAscii(ctx, v, 600);
            if (s is { Length: >= 2 })
            {
                strings.Add((i, s));
                bool isLib = s.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ||
                             s.EndsWith(".so", StringComparison.OrdinalIgnoreCase);
                bool isPath = s.Contains('\\') || s.Contains('/');
                if (isLib && isPath && r.OsLibPath is null)
                {
                    r.OsLibPath = s;
                    r.Layout.Add($"+0x{i * 8:X2}  путь к библиотеке: {s}");
                    hard = true;
                    continue;
                }
                r.Layout.Add($"+0x{i * 8:X2}  строка: {Short(s)}");
                continue;
            }

            r.Pointers.Add(v);
            var pr = ctx.RegionAt(v);
            if (pr is not null && pr.IsCommitted && !pr.IsExecutable && r.Jplis == 0)
                r.Jplis = v;
        }

        if (!r.FlagsFound) return null;
        if (requireHard && !hard) return null;

        foreach (var (_, s) in strings)
        {
            bool path = s.Contains('\\') || s.Contains('/');
            if (!path && r.Name is null && LooksLikeAgentName(s)) { r.Name = s; continue; }
            if (r.Options is null || s.Length > r.Options.Length) r.Options = s;
        }
        if (r.Name is null && r.OsLibPath is not null)
        {
            try
            {
                r.Name = Path.GetFileNameWithoutExtension(r.OsLibPath);
                r.Notes.Add("имя агента в записи не восстановлено — взято из имени файла " +
                            "библиотеки. На JDK 21 поле имени у агента java.lang.instrument " +
                            "пустое при любом способе подключения (проверено и для " +
                            "-javaagent, и для Attach API)");
            }
            catch { }
        }
        if (r.Options is not null && r.Options == r.OsLibPath) r.Options = null;

        return r;
    }

    private static int _jdkMajor = -1;

    private static int JdkMajor(ScanContext ctx)
    {
        if (_jdkMajor >= 0) return _jdkMajor;
        _jdkMajor = 0;
        string? v = JvmAnalyzer.FindJvm(ctx)?.FileVersion;
        if (v is not null)
        {
            int dot = v.IndexOf('.');
            if (int.TryParse(dot > 0 ? v[..dot] : v, out int major)) _jdkMajor = major;
        }
        return _jdkMajor;
    }

    private static bool IsFlagBlock(byte[] d, int off)
    {
        if (off + 8 > d.Length) return false;
        int set = 0;
        for (int i = 0; i < 5; i++)
        {
            if (d[off + i] > 1) return false;
            if (d[off + i] != 0) set++;
        }
        for (int i = 5; i < 8; i++) if (d[off + i] != 0) return false;
        return set >= 2;
    }

    private static bool LooksLikeAgentName(string s)
    {
        if (s.Length is < 2 or > 280) return false;
        bool path = s.Contains('\\') || s.Contains('/');
        foreach (char ch in s)
        {
            if (ch is < ' ' or > '~') return false;
            bool ok = char.IsLetterOrDigit(ch) || ch is '_' or '-' or '.' or '+' or '$' or '~';
            if (!ok && path) ok = ch is '\\' or '/' or ':' or ' ' or '(' or ')';
            if (!ok) return false;
        }
        if (path)
            return s.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ||
                   s.EndsWith(".so", StringComparison.OrdinalIgnoreCase);
        return s.Length <= 64 && char.IsLetter(s[0]);
    }

    private static string Short(string s) => s.Length <= 120 ? s : s[..117] + "...";

    public static string? ReadAscii(ScanContext ctx, ulong addr, int max)
    {
        if (addr is < 0x10000 or > 0x7FFFFFFFFFFF) return null;
        var reg = ctx.RegionAt(addr);
        if (reg is null || !reg.IsCommitted || reg.IsGuard || reg.IsNoAccess) return null;
        var b = ctx.Target.ReadBytes(addr, Math.Min(max, 0x400));
        if (b is null) return null;
        int z = Array.IndexOf(b, (byte)0);
        if (z <= 0) return null;
        var sb = new StringBuilder(z);
        for (int i = 0; i < z; i++)
        {
            if (b[i] is < 0x09 or > 0x7E) return null;
            sb.Append((char)b[i]);
        }
        return sb.ToString();
    }
}
