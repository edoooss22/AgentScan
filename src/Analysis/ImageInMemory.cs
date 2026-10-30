using AgentScan.Core;

namespace AgentScan.Analysis;

internal sealed class ImageInMemory
{
    public ulong Base;
    public uint Size;
    public string Name = "";
    public string Path = "";

    public LdrModule? Ldr;

    public MemRegion? BaseRegion;

    public string MapKind = "?";

    public PeInfo Pe = new();
    public ExportTable Exports => Pe.Exports;

    public bool FileOnDisk;
    public long FileSize;
    public DateTime FileWriteUtc;
    public string? FileVersion;
    public string? FileDescription;
    public string? CompanyName;
    public string? InternalName;
    public string? OriginalFilename;
    public Native.SignatureResult Signature = new();
    public string? Sha256;

    public List<MemRegion> Regions { get; } = new();

    public ulong End => Base + Size;

    public bool IsSystemPath =>
        Path.StartsWith(@"C:\Windows\", StringComparison.OrdinalIgnoreCase);

    public string SignatureStatusString => Signature.Describe();

    public bool SignatureValid => Signature.Valid;

    public string SignatureShort => Signature.Status switch
    {
        -1 => "-",
        0 => Signature.Method == "каталог" ? "OK (каталог)" : "OK",
        unchecked((int)0x800B0100) => "не подписан",
        unchecked((int)0x80096010) => "ПОДПИСЬ БИТА",
        _ => $"0x{Signature.Status:X8}",
    };

    public override string ToString() =>
        $"{Base:X16}+{Size:X8} {Name}";
}
