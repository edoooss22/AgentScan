using System.Security.Cryptography;
using System.Text;

namespace AgentScan.Core;

internal sealed class RegionDumper
{
    private readonly ProcessTarget _t;
    private readonly string _dir;
    private readonly long _maxBytes;
    private bool _dirReady;

    public RegionDumper(ProcessTarget target, string dir, long maxBytesPerDump)
    {
        _t = target;
        _dir = dir;
        _maxBytes = maxBytesPerDump;
    }

    public string Directory => _dir;
    public int FileCount { get; private set; }
    public long TotalBytes { get; private set; }
    public List<string> Errors { get; } = new();

    private readonly List<Entry> _manifest = new();
    private readonly HashSet<string> _done = new(StringComparer.OrdinalIgnoreCase);

    private sealed record Entry(string File, ulong Address, long Size, string Kind,
        string Reason, string Details, string Sha256);

    private bool EnsureDir()
    {
        if (_dirReady) return true;
        try
        {
            System.IO.Directory.CreateDirectory(_dir);
            _dirReady = true;
        }
        catch (Exception ex)
        {
            Errors.Add($"каталог дампов {_dir} не создан: {ex.Message}");
        }
        return _dirReady;
    }

    public string? DumpAllocation(List<MemRegion> regions, string kind, string reason,
        string details = "")
    {
        var list = regions.Where(r => r.IsCommitted && !r.IsGuard).OrderBy(r => r.Base).ToList();
        if (list.Count == 0) return null;

        ulong lo = list[0].Base;
        ulong hi = list[^1].End;
        long size = (long)(hi - lo);
        if (size <= 0) return null;
        if (size > _maxBytes)
        {
            Errors.Add($"аллокация 0x{lo:X} ({size} байт) больше лимита дампа " +
                       $"({_maxBytes} байт) — сохранено начало; поднимите --max-dump");
            size = _maxBytes;
        }

        string name = $"{kind}_{lo:X16}_{size:X}.bin";
        if (!_done.Add(name)) return System.IO.Path.Combine(_dir, name);
        if (!EnsureDir()) return null;

        try
        {
            var buf = new byte[size];
            foreach (var r in list)
            {
                if (r.Base >= lo + (ulong)size) break;
                long off = (long)(r.Base - lo);
                int len = (int)Math.Min((long)r.Size, size - off);
                if (len <= 0) continue;
                if (r.IsNoAccess) continue;
                _t.ReadPartial(r.Base, buf.AsSpan((int)off, len), out _);
            }

            string path = System.IO.Path.Combine(_dir, name);
            File.WriteAllBytes(path, buf);
            Record(name, lo, size, kind, reason,
                details.Length > 0 ? details : DescribeRegions(list), buf);
            return path;
        }
        catch (Exception ex)
        {
            Errors.Add($"дамп 0x{lo:X} не сохранён: {ex.Message}");
            return null;
        }
    }

    public string? DumpRange(ulong address, int size, string kind, string reason,
        string details = "")
    {
        if (size <= 0 || size > _maxBytes) size = (int)Math.Min(size, _maxBytes);
        string name = $"{kind}_{address:X16}_{size:X}.bin";
        if (!_done.Add(name)) return System.IO.Path.Combine(_dir, name);
        if (!EnsureDir()) return null;

        try
        {
            var buf = new byte[size];
            int read = _t.ReadPartial(address, buf, out _);
            if (read <= 0) { Errors.Add($"по адресу 0x{address:X} читать нечего"); return null; }
            string path = System.IO.Path.Combine(_dir, name);
            File.WriteAllBytes(path, buf);
            Record(name, address, size, kind, reason, details, buf);
            return path;
        }
        catch (Exception ex)
        {
            Errors.Add($"дамп 0x{address:X} не сохранён: {ex.Message}");
            return null;
        }
    }

    public (string? Memory, string? Disk) DumpModuleRange(ulong imageBase, uint rva, int size,
        string moduleName, string diskPath, string reason)
    {
        string tag = SafeName(moduleName);
        string memName = $"mod_{tag}_{imageBase + rva:X16}_rva{rva:X}_{size:X}.mem.bin";
        string diskName = $"mod_{tag}_{imageBase + rva:X16}_rva{rva:X}_{size:X}.disk.bin";
        if (!EnsureDir()) return (null, null);

        string? memPath = null, diskPathOut = null;
        try
        {
            var mem = new byte[size];
            _t.ReadPartial(imageBase + rva, mem, out _);
            memPath = System.IO.Path.Combine(_dir, memName);
            if (_done.Add(memName))
            {
                File.WriteAllBytes(memPath, mem);
                Record(memName, imageBase + rva, size, "module",
                    reason, $"{moduleName}, RVA 0x{rva:X}, копия ИЗ ПАМЯТИ", mem);
            }
        }
        catch (Exception ex) { Errors.Add($"дамп кода {moduleName} не сохранён: {ex.Message}"); }

        try
        {
            var loaded = FileImageReader.Load(diskPath, relocs: false);
            if (loaded is not null)
            {
                var disk = new byte[size];
                if (loaded.Value.rdr.Read(rva, disk))
                {
                    diskPathOut = System.IO.Path.Combine(_dir, diskName);
                    if (_done.Add(diskName))
                    {
                        File.WriteAllBytes(diskPathOut, disk);
                        Record(diskName, imageBase + rva, size, "module",
                            reason, $"{moduleName}, RVA 0x{rva:X}, эталон С ДИСКА ({diskPath})",
                            disk);
                    }
                }
            }
        }
        catch (Exception ex) { Errors.Add($"эталон {moduleName} не сохранён: {ex.Message}"); }

        return (memPath, diskPathOut);
    }

    private void Record(string file, ulong addr, long size, string kind, string reason,
        string details, byte[] data)
    {
        FileCount++;
        TotalBytes += size;
        _manifest.Add(new Entry(file, addr, size, kind, reason, details,
            Convert.ToHexString(SHA256.HashData(data))));
    }

    private static string DescribeRegions(List<MemRegion> list) =>
        string.Join("; ", list.Select(r =>
            $"0x{r.Base:X}+0x{r.Size:X} {r.TypeString}/{r.ProtectString} " +
            $"(создан {r.AllocProtectString})"));

    private static string SafeName(string s)
    {
        var sb = new StringBuilder();
        foreach (char c in s)
            sb.Append(char.IsLetterOrDigit(c) || c is '.' or '-' or '_' ? c : '_');
        return sb.ToString();
    }

    public string? Finish(int pid, string imagePath)
    {
        if (_manifest.Count == 0 || !_dirReady) return null;
        try
        {
            var sb = new StringBuilder();
            sb.AppendLine("Дампы памяти, сохранённые AgentScan для ручного разбора");
            sb.AppendLine($"Процесс: PID {pid}, {imagePath}");
            sb.AppendLine($"Снято: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"Файлов: {_manifest.Count}, суммарно: {TotalBytes / 1024.0 / 1024.0:F2} МБ");
            sb.AppendLine();
            sb.AppendLine("Смещение в файле = адрес в памяти минус базовый адрес из колонки АДРЕС.");
            sb.AppendLine("Страницы, недоступные для чтения, в файле заполнены нулями.");
            sb.AppendLine("Файлы *.mem.bin и *.disk.bin — одна и та же область из памяти и из файла");
            sb.AppendLine("на диске: сравнивайте их побайтово (fc /b, cmp, любой hex-редактор).");
            sb.AppendLine();

            foreach (var e in _manifest.OrderBy(x => x.Address))
            {
                sb.AppendLine(new string('-', 100));
                sb.AppendLine($"ФАЙЛ    : {e.File}");
                sb.AppendLine($"АДРЕС   : 0x{e.Address:X16}");
                sb.AppendLine($"РАЗМЕР  : {e.Size} байт (0x{e.Size:X})");
                sb.AppendLine($"ТИП     : {e.Kind}");
                sb.AppendLine($"ПРИЧИНА : {e.Reason}");
                if (e.Details.Length > 0) sb.AppendLine($"ДЕТАЛИ  : {e.Details}");
                sb.AppendLine($"SHA-256 : {e.Sha256}");
            }

            if (Errors.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("ЗАМЕЧАНИЯ ПРИ СОХРАНЕНИИ:");
                foreach (var e in Errors) sb.AppendLine("  " + e);
            }

            string path = System.IO.Path.Combine(_dir, "manifest.txt");
            File.WriteAllText(path, sb.ToString(), new UTF8Encoding(true));
            return path;
        }
        catch (Exception ex)
        {
            Errors.Add($"manifest.txt не записан: {ex.Message}");
            return null;
        }
    }
}
