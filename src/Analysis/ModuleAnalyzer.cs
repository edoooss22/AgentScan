using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using AgentScan.Core;
using AgentScan.Report;

namespace AgentScan.Analysis;

internal static class ModuleAnalyzer
{
    public static void Run(ScanContext ctx)
    {
        var t = ctx.Target;

        var byBase = new Dictionary<ulong, ImageInMemory>();

        foreach (var m in ctx.Loader.Modules)
        {
            if (m.DllBase == 0) continue;
            var im = new ImageInMemory
            {
                Base = m.DllBase,
                Size = m.SizeOfImage,
                Name = m.BaseDllName.Length > 0 ? m.BaseDllName : $"base_{m.DllBase:X}",
                Path = m.FullDllName,
                Ldr = m,
            };
            byBase[m.DllBase] = im;
        }

        foreach (var g in ctx.Regions.Where(r => r.IsImage && r.AllocationBase != 0)
                                     .GroupBy(r => r.AllocationBase))
        {
            ulong b = g.Key;
            if (!byBase.TryGetValue(b, out var im))
            {
                string? file = g.Select(x => x.MappedFileDos ?? x.MappedFile)
                                .FirstOrDefault(x => x is not null);
                im = new ImageInMemory
                {
                    Base = b,
                    Size = (uint)g.Sum(x => (long)x.Size),
                    Name = file is null ? $"image_{b:X}" : Path.GetFileName(file),
                    Path = file ?? "",
                };
                byBase[b] = im;
            }
            im.BaseRegion = g.OrderBy(x => x.Base).First();
            im.MapKind = "IMAGE";
            im.Regions.AddRange(g);
        }

        foreach (var r in ctx.Regions)
        {
            if (!r.IsCommitted || r.IsImage) continue;
            if (r.Base != r.AllocationBase) continue;
            if (r.Size < 0x1000) continue;
            if (byBase.ContainsKey(r.Base)) continue;
            if (r.IsMapped && (r.MappedFile is not null || r.MappedFileDos is not null)) continue;
            if (!LooksLikePe(t, r.Base)) continue;

            var im = new ImageInMemory
            {
                Base = r.Base,
                Size = 0,
                Name = $"pe_{r.Base:X}",
                Path = "",
                BaseRegion = r,
                MapKind = r.IsPrivate ? "PRIVATE" : "PAGEFILE",
            };
            byBase[r.Base] = im;
        }

        foreach (var im in byBase.Values)
        {
            var rdr = new RemoteImageReader(t, im.Base, im.Size == 0 ? 0 : im.Size);
            im.Pe = PeParser.Parse(rdr, parseImports: true);
            if (im.Size == 0 && im.Pe.Valid) im.Size = im.Pe.SizeOfImage;
            if (im.Regions.Count == 0)
                im.Regions.AddRange(ctx.Regions.Where(r => r.Base >= im.Base && r.Base < im.End));
            if (im.MapKind == "?") im.MapKind = im.BaseRegion?.TypeString ?? "?";
        }

        ctx.Images = byBase.Values.OrderBy(x => x.Base).ToList();
        LoadDiskMetadata(ctx.Images);
    }

    private static bool LooksLikePe(ProcessTarget t, ulong addr)
    {
        Span<byte> b = stackalloc byte[2];
        if (!t.TryRead(addr, b) || b[0] != 'M' || b[1] != 'Z') return false;
        uint lfanew = t.ReadU32(addr + 0x3C);
        if (lfanew is 0 or > 0x1000) return false;
        return t.ReadU32(addr + lfanew) == 0x00004550;
    }

    internal static void FillModuleData(ScanContext ctx, Finding f, ImageInMemory im)
    {
        f.Add("база", im.Base);
        f.Add("размер", $"0x{im.Size:X} ({im.Size / 1024} КБ)");
        f.Add("путь", im.Path.Length > 0 ? im.Path : "-");
        f.Add("тип отображения", im.MapKind);
        f.Add("в списках загрузчика", im.Ldr?.ListMembership ?? "нет записи");
        if (im.Ldr is not null)
        {
            f.Add("LDR entry", im.Ldr.EntryAddress);
            f.Add("LDR флаги", LoaderModules.DecodeFlags(im.Ldr.Flags));
            f.Add("LDR SigningLevel", im.Ldr.SigningLevelString);
            f.Add("LDR OriginalBase", im.Ldr.OriginalBase);
            if (im.Ldr.LoadTimeUtc is { } lt)
                f.Add("LDR LoadTime", lt.ToLocalTime().ToString("O"));
            f.Add("LDR LoadReason", im.Ldr.LoadReasonString);
        }
        if (im.Pe.Valid)
        {
            f.Add("PE machine", im.Pe.MachineString);
            f.Add("PE timestamp", im.Pe.LinkTimeUtc?.ToString("O") ?? $"0x{im.Pe.TimeDateStamp:X8}");
            f.Add("PE ImageBase", im.Pe.ImageBase);
            f.Add("PE SizeOfImage", $"0x{im.Pe.SizeOfImage:X}");
            f.Add("PE EntryPoint", im.Base + im.Pe.AddressOfEntryPoint);
            f.Add("PE экспортов", im.Pe.Exports.Entries.Count.ToString());
            f.Add("PE импортов", im.Pe.Imports.Count.ToString());
            f.Add("PE внутреннее имя", im.Pe.Exports.ModuleName.Length > 0
                ? im.Pe.Exports.ModuleName : "-");
            if (im.Pe.PdbPath is not null) f.Add("PDB", im.Pe.PdbPath);
            f.Add("PE секции", string.Join(", ",
                im.Pe.Sections.Select(s => $"{s.Name}({s.Flags})")));
            if (im.Pe.TlsCallbacks.Count > 0)
                f.Add("TLS callbacks", string.Join(", ", im.Pe.TlsCallbacks.Select(x => $"0x{x:X}")));
        }
        else if (im.Pe.Error is not null)
        {
            f.Add("PE", $"не разобран: {im.Pe.Error}");
        }
        if (im.FileOnDisk)
        {
            LoadFileDetails(im);
            f.Add("файл на диске", $"{im.FileSize} байт, изменён {im.FileWriteUtc.ToLocalTime():O}");
            if (im.Sha256 is not null) f.Add("SHA-256", im.Sha256);
            if (im.FileVersion is not null) f.Add("версия файла", im.FileVersion);
            if (im.CompanyName is not null) f.Add("издатель (VERSIONINFO)", im.CompanyName);
            if (im.OriginalFilename is not null) f.Add("OriginalFilename", im.OriginalFilename);
            f.Add("подпись", im.SignatureStatusString);
            if (im.Signature.CatalogPath is not null) f.Add("каталог", im.Signature.CatalogPath);
        }
        else if (im.Path.Length > 0)
        {
            f.Add("файл на диске", "ОТСУТСТВУЕТ");
        }

        if (im.Regions.Count > 0)
        {
            var sb = new StringBuilder();
            foreach (var r in im.Regions.OrderBy(x => x.Base))
                sb.AppendLine($"  {r}");
            f.Block("Регионы образа", sb.ToString().TrimEnd());
        }
    }

    private static void LoadDiskMetadata(List<ImageInMemory> images)
    {
        Parallel.ForEach(images, new ParallelOptions { MaxDegreeOfParallelism = 8 }, im =>
        {
            if (im.Path.Length == 0) return;
            string p = im.Path;
            try
            {
                var fi = new FileInfo(p);
                if (!fi.Exists) return;
                im.FileOnDisk = true;
                im.FileSize = fi.Length;
                im.FileWriteUtc = fi.LastWriteTimeUtc;
            }
            catch { return; }

            try
            {
                var vi = FileVersionInfo.GetVersionInfo(p);
                im.FileVersion = vi.FileVersion;
                im.CompanyName = vi.CompanyName;
                im.OriginalFilename = vi.OriginalFilename;
            }
            catch { }
        });
    }

    private static void LoadFileDetails(ImageInMemory im)
    {
        if (im.Signature.Status != -1 || im.Sha256 is not null) return;
        try { im.Signature = Native.Authenticode.Verify(im.Path); } catch { }
        try
        {
            if (im.FileSize < 128 * 1024 * 1024)
            {
                using var fs = File.OpenRead(im.Path);
                im.Sha256 = Convert.ToHexString(SHA256.HashData(fs));
            }
        }
        catch { }
    }
}
