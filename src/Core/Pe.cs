using System.Buffers.Binary;
using System.Text;

namespace AgentScan.Core;

internal interface IRvaReader
{
    bool Read(uint rva, Span<byte> dest);
}

internal sealed class PeSection
{
    public string Name = "";
    public uint VirtualAddress;
    public uint VirtualSize;
    public uint PointerToRawData;
    public uint SizeOfRawData;
    public uint Characteristics;

    public bool IsExecutable => (Characteristics & 0x20000000) != 0;
    public bool IsWritable => (Characteristics & 0x80000000) != 0;
    public bool IsReadable => (Characteristics & 0x40000000) != 0;
    public bool ContainsCode => (Characteristics & 0x00000020) != 0;
    public bool IsDiscardable => (Characteristics & 0x02000000) != 0;

    public string Flags =>
        (IsReadable ? "R" : "-") + (IsWritable ? "W" : "-") + (IsExecutable ? "X" : "-") +
        (ContainsCode ? " CODE" : "") + (IsDiscardable ? " DISCARD" : "");
}

internal sealed class ExportEntry
{
    public string Name = "";
    public uint Rva;
    public ushort Ordinal;
    public string? Forwarder;
}

internal sealed class ExportTable
{
    public string ModuleName = "";
    public List<ExportEntry> Entries { get; } = new();
    private (uint rva, string name)[]? _sorted;

    public void Finish()
    {
        _sorted = Entries.Where(e => e.Forwarder is null)
                         .Select(e => (e.Rva, e.Name.Length > 0 ? e.Name : $"#{e.Ordinal}"))
                         .OrderBy(x => x.Item1)
                         .ToArray();
    }

    public string ResolveNearest(ulong rva, out ulong delta)
    {
        delta = 0;
        if (_sorted is null || _sorted.Length == 0) return "";
        if (rva > uint.MaxValue) return "";
        uint r = (uint)rva;
        int lo = 0, hi = _sorted.Length - 1, best = -1;
        while (lo <= hi)
        {
            int mid = (lo + hi) / 2;
            if (_sorted[mid].rva <= r) { best = mid; lo = mid + 1; }
            else hi = mid - 1;
        }
        if (best < 0) return "";
        delta = r - _sorted[best].rva;
        if (delta > 0x20000) return "";
        return _sorted[best].name;
    }

    public ExportEntry? ByName(string n) =>
        Entries.FirstOrDefault(e => e.Name.Equals(n, StringComparison.Ordinal));
}

internal sealed class ImportedFunction
{
    public string Dll = "";
    public string Name = "";
    public ushort Ordinal;
    public uint IatRva;
    public bool ByOrdinal;
}

internal sealed class PeInfo
{
    public bool Valid;
    public string? Error;

    public ushort Machine;
    public ushort NumberOfSections;
    public uint TimeDateStamp;
    public ushort Characteristics;
    public ushort Magic;
    public ulong ImageBase;
    public uint SizeOfImage;
    public uint SizeOfHeaders;
    public uint CheckSum;
    public ushort Subsystem;
    public ushort DllCharacteristics;
    public uint AddressOfEntryPoint;
    public uint NtHeaderOffset;

    public List<PeSection> Sections { get; } = new();
    public ExportTable Exports { get; } = new();
    public List<ImportedFunction> Imports { get; } = new();
    public List<ulong> TlsCallbacks { get; } = new();
    public string? PdbPath;
    public Guid PdbGuid;
    public uint PdbAge;
    public List<uint> RelocRvas { get; } = new();

    public uint[] DataDirRva = new uint[16];
    public uint[] DataDirSize = new uint[16];

    public bool IsDll => (Characteristics & 0x2000) != 0;
    public bool HasAslr => (DllCharacteristics & 0x0040) != 0;
    public bool HasNx => (DllCharacteristics & 0x0100) != 0;
    public bool ForceIntegrity => (DllCharacteristics & 0x0080) != 0;
    public bool GuardCf => (DllCharacteristics & 0x4000) != 0;

    public string MachineString => Machine switch
    {
        0x8664 => "x64",
        0x014C => "x86",
        0xAA64 => "arm64",
        _ => $"0x{Machine:X4}"
    };

    public DateTime? LinkTimeUtc =>
        TimeDateStamp is > 0 and < 0xF0000000
            ? DateTimeOffset.FromUnixTimeSeconds(TimeDateStamp).UtcDateTime
            : null;

    public PeSection? SectionAtRva(uint rva) =>
        Sections.FirstOrDefault(s => rva >= s.VirtualAddress &&
                                     rva < s.VirtualAddress + Math.Max(s.VirtualSize, s.SizeOfRawData));
}

internal static class PeParser
{
    private const int MaxDir = 16;

    public static PeInfo Parse(IRvaReader r, bool parseImports = true, bool parseRelocs = false)
    {
        var pe = new PeInfo();
        Span<byte> hdr = stackalloc byte[0x40];
        if (!r.Read(0, hdr)) { pe.Error = "не удалось прочитать DOS-заголовок"; return pe; }
        if (hdr[0] != 'M' || hdr[1] != 'Z') { pe.Error = "нет сигнатуры MZ"; return pe; }

        uint e_lfanew = BinaryPrimitives.ReadUInt32LittleEndian(hdr.Slice(0x3C));
        if (e_lfanew is 0 or > 0x10000) { pe.Error = $"некорректный e_lfanew=0x{e_lfanew:X}"; return pe; }
        pe.NtHeaderOffset = e_lfanew;

        var nt = new byte[0x18];
        if (!r.Read(e_lfanew, nt)) { pe.Error = "не удалось прочитать NT-заголовок"; return pe; }
        if (nt[0] != 'P' || nt[1] != 'E' || nt[2] != 0 || nt[3] != 0)
        { pe.Error = "нет сигнатуры PE"; return pe; }

        pe.Machine = BinaryPrimitives.ReadUInt16LittleEndian(nt.AsSpan(4));
        pe.NumberOfSections = BinaryPrimitives.ReadUInt16LittleEndian(nt.AsSpan(6));
        pe.TimeDateStamp = BinaryPrimitives.ReadUInt32LittleEndian(nt.AsSpan(8));
        ushort sizeOfOptional = BinaryPrimitives.ReadUInt16LittleEndian(nt.AsSpan(0x14));
        pe.Characteristics = BinaryPrimitives.ReadUInt16LittleEndian(nt.AsSpan(0x16));

        uint optOff = e_lfanew + 0x18;
        var opt = new byte[Math.Max(sizeOfOptional, (ushort)0xF0)];
        if (!r.Read(optOff, opt)) { pe.Error = "не удалось прочитать OptionalHeader"; return pe; }

        pe.Magic = BinaryPrimitives.ReadUInt16LittleEndian(opt);
        bool pe32Plus = pe.Magic == 0x20B;
        if (!pe32Plus && pe.Magic != 0x10B) { pe.Error = $"неизвестный Magic=0x{pe.Magic:X}"; return pe; }

        pe.AddressOfEntryPoint = BinaryPrimitives.ReadUInt32LittleEndian(opt.AsSpan(0x10));
        pe.ImageBase = pe32Plus
            ? BinaryPrimitives.ReadUInt64LittleEndian(opt.AsSpan(0x18))
            : BinaryPrimitives.ReadUInt32LittleEndian(opt.AsSpan(0x1C));
        pe.SizeOfImage = BinaryPrimitives.ReadUInt32LittleEndian(opt.AsSpan(pe32Plus ? 0x38 : 0x38));
        pe.SizeOfHeaders = BinaryPrimitives.ReadUInt32LittleEndian(opt.AsSpan(0x3C));
        pe.CheckSum = BinaryPrimitives.ReadUInt32LittleEndian(opt.AsSpan(0x40));
        pe.Subsystem = BinaryPrimitives.ReadUInt16LittleEndian(opt.AsSpan(0x44));
        pe.DllCharacteristics = BinaryPrimitives.ReadUInt16LittleEndian(opt.AsSpan(0x46));

        int ddOff = pe32Plus ? 0x70 : 0x60;
        for (int i = 0; i < MaxDir; i++)
        {
            int o = ddOff + i * 8;
            if (o + 8 > opt.Length) break;
            pe.DataDirRva[i] = BinaryPrimitives.ReadUInt32LittleEndian(opt.AsSpan(o));
            pe.DataDirSize[i] = BinaryPrimitives.ReadUInt32LittleEndian(opt.AsSpan(o + 4));
        }

        uint secOff = optOff + sizeOfOptional;
        int nsec = Math.Min(pe.NumberOfSections, (ushort)96);
        var secBuf = new byte[nsec * 40];
        if (nsec > 0 && r.Read(secOff, secBuf))
        {
            for (int i = 0; i < nsec; i++)
            {
                var s = secBuf.AsSpan(i * 40, 40);
                var sec = new PeSection
                {
                    Name = Encoding.ASCII.GetString(s.Slice(0, 8)).TrimEnd('\0'),
                    VirtualSize = BinaryPrimitives.ReadUInt32LittleEndian(s.Slice(8)),
                    VirtualAddress = BinaryPrimitives.ReadUInt32LittleEndian(s.Slice(12)),
                    SizeOfRawData = BinaryPrimitives.ReadUInt32LittleEndian(s.Slice(16)),
                    PointerToRawData = BinaryPrimitives.ReadUInt32LittleEndian(s.Slice(20)),
                    Characteristics = BinaryPrimitives.ReadUInt32LittleEndian(s.Slice(36)),
                };
                pe.Sections.Add(sec);
            }
        }

        ParseExports(r, pe);
        if (parseImports) ParseImports(r, pe, pe32Plus);
        ParseDebug(r, pe);
        ParseTls(r, pe, pe32Plus);
        if (parseRelocs) ParseRelocs(r, pe);

        pe.Valid = true;
        return pe;
    }

    private static void ParseExports(IRvaReader r, PeInfo pe)
    {
        uint dirRva = pe.DataDirRva[0], dirSize = pe.DataDirSize[0];
        if (dirRva == 0 || dirSize == 0) { pe.Exports.Finish(); return; }

        var d = new byte[40];
        if (!r.Read(dirRva, d)) { pe.Exports.Finish(); return; }

        uint nameRva = BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(12));
        uint ordBase = BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(16));
        uint nFuncs = BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(20));
        uint nNames = BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(24));
        uint funcsRva = BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(28));
        uint namesRva = BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(32));
        uint ordsRva = BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(36));

        pe.Exports.ModuleName = ReadCString(r, nameRva, 260) ?? "";
        if (nFuncs is 0 or > 200000) { pe.Exports.Finish(); return; }

        var funcs = new byte[nFuncs * 4];
        if (!r.Read(funcsRva, funcs)) { pe.Exports.Finish(); return; }

        var byOrdinal = new ExportEntry[nFuncs];
        for (uint i = 0; i < nFuncs; i++)
        {
            uint rva = BinaryPrimitives.ReadUInt32LittleEndian(funcs.AsSpan((int)(i * 4)));
            if (rva == 0) continue;
            var e = new ExportEntry { Rva = rva, Ordinal = (ushort)(ordBase + i) };
            if (rva >= dirRva && rva < dirRva + dirSize)
                e.Forwarder = ReadCString(r, rva, 260);
            byOrdinal[i] = e;
            pe.Exports.Entries.Add(e);
        }

        if (nNames is > 0 and <= 200000 && namesRva != 0 && ordsRva != 0)
        {
            var names = new byte[nNames * 4];
            var ords = new byte[nNames * 2];
            if (r.Read(namesRva, names) && r.Read(ordsRva, ords))
            {
                for (uint i = 0; i < nNames; i++)
                {
                    ushort ord = BinaryPrimitives.ReadUInt16LittleEndian(ords.AsSpan((int)(i * 2)));
                    if (ord >= nFuncs) continue;
                    var e = byOrdinal[ord];
                    if (e is null) continue;
                    uint nrva = BinaryPrimitives.ReadUInt32LittleEndian(names.AsSpan((int)(i * 4)));
                    e.Name = ReadCString(r, nrva, 512) ?? "";
                }
            }
        }
        pe.Exports.Finish();
    }

    private static void ParseImports(IRvaReader r, PeInfo pe, bool pe32Plus)
    {
        uint dirRva = pe.DataDirRva[1];
        if (dirRva == 0) return;

        for (int i = 0; i < 4096; i++)
        {
            var desc = new byte[20];
            if (!r.Read((uint)(dirRva + i * 20), desc)) break;
            uint oft = BinaryPrimitives.ReadUInt32LittleEndian(desc.AsSpan(0));
            uint nameRva = BinaryPrimitives.ReadUInt32LittleEndian(desc.AsSpan(12));
            uint firstThunk = BinaryPrimitives.ReadUInt32LittleEndian(desc.AsSpan(16));
            if (oft == 0 && nameRva == 0 && firstThunk == 0) break;

            string dll = ReadCString(r, nameRva, 260) ?? "?";
            uint lookup = oft != 0 ? oft : firstThunk;
            if (lookup == 0) continue;

            int step = pe32Plus ? 8 : 4;
            for (int k = 0; k < 8192; k++)
            {
                var tb = new byte[8];
                if (!r.Read((uint)(lookup + k * step), tb.AsSpan(0, step))) break;
                ulong val = pe32Plus
                    ? BinaryPrimitives.ReadUInt64LittleEndian(tb)
                    : BinaryPrimitives.ReadUInt32LittleEndian(tb);
                if (val == 0) break;

                var imp = new ImportedFunction
                {
                    Dll = dll,
                    IatRva = (uint)(firstThunk + k * step),
                };
                ulong ordFlag = pe32Plus ? 0x8000000000000000UL : 0x80000000UL;
                if ((val & ordFlag) != 0)
                {
                    imp.ByOrdinal = true;
                    imp.Ordinal = (ushort)(val & 0xFFFF);
                    imp.Name = $"#{imp.Ordinal}";
                }
                else
                {
                    uint hintRva = (uint)(val & 0x7FFFFFFF);
                    imp.Name = ReadCString(r, hintRva + 2, 512) ?? "?";
                }
                pe.Imports.Add(imp);
                if (pe.Imports.Count > 100000) return;
            }
        }
    }

    private static void ParseDebug(IRvaReader r, PeInfo pe)
    {
        uint dirRva = pe.DataDirRva[6], size = pe.DataDirSize[6];
        if (dirRva == 0 || size < 28) return;
        int n = (int)Math.Min(size / 28, 32);
        for (int i = 0; i < n; i++)
        {
            var d = new byte[28];
            if (!r.Read((uint)(dirRva + i * 28), d)) return;
            uint type = BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(12));
            uint sizeOfData = BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(16));
            uint addrRaw = BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(20));
            if (type != 2  || sizeOfData is 0 or > 4096) continue;
            var cv = new byte[sizeOfData];
            if (!r.Read(addrRaw, cv)) continue;
            if (cv.Length < 25) continue;
            if (cv[0] == 'R' && cv[1] == 'S' && cv[2] == 'D' && cv[3] == 'S')
            {
                pe.PdbGuid = new Guid(cv.AsSpan(4, 16).ToArray());
                pe.PdbAge = BinaryPrimitives.ReadUInt32LittleEndian(cv.AsSpan(20));
                int z = Array.IndexOf(cv, (byte)0, 24);
                if (z < 0) z = cv.Length;
                pe.PdbPath = Encoding.UTF8.GetString(cv, 24, z - 24);
            }
        }
    }

    private static void ParseTls(IRvaReader r, PeInfo pe, bool pe32Plus)
    {
        uint dirRva = pe.DataDirRva[9];
        if (dirRva == 0 || !pe32Plus) return;
        var d = new byte[40];
        if (!r.Read(dirRva, d)) return;
        ulong cbVa = BinaryPrimitives.ReadUInt64LittleEndian(d.AsSpan(24));
        if (cbVa == 0 || cbVa < pe.ImageBase) return;
        uint cbRva = (uint)(cbVa - pe.ImageBase);
        for (int i = 0; i < 64; i++)
        {
            var p = new byte[8];
            if (!r.Read((uint)(cbRva + i * 8), p)) break;
            ulong v = BinaryPrimitives.ReadUInt64LittleEndian(p);
            if (v == 0) break;
            pe.TlsCallbacks.Add(v);
        }
    }

    private static void ParseRelocs(IRvaReader r, PeInfo pe)
    {
        uint dirRva = pe.DataDirRva[5], size = pe.DataDirSize[5];
        if (dirRva == 0 || size == 0 || size > 16 * 1024 * 1024) return;
        var blob = new byte[size];
        if (!r.Read(dirRva, blob)) return;

        int off = 0;
        while (off + 8 <= blob.Length)
        {
            uint pageRva = BinaryPrimitives.ReadUInt32LittleEndian(blob.AsSpan(off));
            uint blockSize = BinaryPrimitives.ReadUInt32LittleEndian(blob.AsSpan(off + 4));
            if (blockSize < 8 || off + blockSize > blob.Length) break;
            int count = (int)((blockSize - 8) / 2);
            for (int i = 0; i < count; i++)
            {
                ushort e = BinaryPrimitives.ReadUInt16LittleEndian(blob.AsSpan(off + 8 + i * 2));
                int type = e >> 12;
                int ofs = e & 0xFFF;
                if (type == 10 )
                    pe.RelocRvas.Add(pageRva + (uint)ofs);
            }
            off += (int)blockSize;
        }
    }

    public static string? ReadCString(IRvaReader r, uint rva, int max)
    {
        if (rva == 0) return null;
        var buf = new byte[max];
        int got = 0;
        while (got < max)
        {
            int chunk = Math.Min(64, max - got);
            if (!r.Read((uint)(rva + got), buf.AsSpan(got, chunk))) break;
            int z = Array.IndexOf(buf, (byte)0, got, chunk);
            got += chunk;
            if (z >= 0) return Encoding.UTF8.GetString(buf, 0, z);
        }
        if (got == 0) return null;
        int zz = Array.IndexOf(buf, (byte)0, 0, got);
        return Encoding.UTF8.GetString(buf, 0, zz >= 0 ? zz : got);
    }
}

internal sealed class RemoteImageReader : IRvaReader
{
    private readonly ProcessTarget _t;
    private readonly ulong _base;
    private readonly uint _limit;

    public RemoteImageReader(ProcessTarget t, ulong imageBase, uint sizeOfImage = 0)
    {
        _t = t; _base = imageBase;
        _limit = sizeOfImage == 0 ? 0x8000000 : sizeOfImage;
    }

    public bool Read(uint rva, Span<byte> dest)
    {
        if (rva > _limit) return false;
        return _t.TryRead(_base + rva, dest);
    }
}

internal sealed class FileImageReader : IRvaReader
{
    private readonly byte[] _raw;
    private PeInfo? _layout;

    public FileImageReader(byte[] raw) { _raw = raw; }

    public byte[] Raw => _raw;

    public void SetLayout(PeInfo pe) => _layout = pe;

    public bool Read(uint rva, Span<byte> dest)
    {
        long off = _layout is null ? rva : RvaToOffset(rva);
        if (off < 0 || off + dest.Length > _raw.Length) return false;
        _raw.AsSpan((int)off, dest.Length).CopyTo(dest);
        return true;
    }

    public long RvaToOffset(uint rva)
    {
        if (_layout is null) return rva;
        if (rva < _layout.SizeOfHeaders) return rva;
        foreach (var s in _layout.Sections)
        {
            uint vend = s.VirtualAddress + Math.Max(s.VirtualSize, s.SizeOfRawData);
            if (rva >= s.VirtualAddress && rva < vend)
            {
                uint delta = rva - s.VirtualAddress;
                if (delta >= s.SizeOfRawData) return -1;
                return s.PointerToRawData + delta;
            }
        }
        return -1;
    }

    public static (PeInfo pe, FileImageReader rdr)? Load(string path, bool relocs = true)
    {
        byte[] raw;
        try { raw = File.ReadAllBytes(path); } catch { return null; }
        var rdr = new FileImageReader(raw);
        var flat = PeParser.Parse(rdr, parseImports: false);
        if (!flat.Valid) return null;
        rdr.SetLayout(flat);
        var full = PeParser.Parse(rdr, parseImports: true, parseRelocs: relocs);
        if (!full.Valid) return null;
        rdr.SetLayout(full);
        return (full, rdr);
    }
}
