using System.Text;
using AgentScan.Core;
using AgentScan.Report;

namespace AgentScan.Analysis;

internal static class BootLoaderIntrusionAnalyzer
{
    private sealed class Cld
    {
        public ulong Address;
        public ulong LoaderOop;
        public string LoaderClass = "";
        public bool HasMirrorHolder;
        public readonly List<(ulong Klass, string Name)> Klasses = new();
    }

    public static void Run(ScanContext ctx)
    {
        var sb = new StringBuilder();
        sb.AppendLine("КЛАССЫ В ПРИВИЛЕГИРОВАННЫХ ЗАГРУЗЧИКАХ");
        sb.AppendLine();

        var vm = ctx.Vm;
        var m = ctx.Java;
        if (vm is null || !vm.Valid || m is null)
        {
            sb.AppendLine("  раскладка структур HotSpot или карта классов недоступны — " +
                          "проверка пропущена.");
            ctx.Report.Section("ПРИВИЛЕГИРОВАННЫЕ ЗАГРУЗЧИКИ", sb.ToString());
            return;
        }

        int offLoader = vm.Off("ClassLoaderData", "_class_loader");
        int offKlasses = vm.Off("ClassLoaderData", "_klasses");
        int offNextK = vm.Off("Klass", "_next_link");
        int offMirrorHolder = vm.OffAny("ClassLoaderData",
            "_has_class_mirror_holder", "_is_unsafe_anonymous");

        sb.AppendLine($"  ClassLoaderData::_class_loader = {offLoader}, _klasses = {offKlasses}");
        sb.AppendLine($"  Klass::_next_link = {offNextK}, признак скрытого = {offMirrorHolder}");
        sb.AppendLine($"  объектов загрузчиков в графе: {ctx.ClassLoaderDatas.Count}");
        sb.AppendLine();

        if (offLoader < 0 || offKlasses < 0 || offNextK < 0 || ctx.ClassLoaderDatas.Count == 0)
        {
            sb.AppendLine("  граф загрузчиков не разобран — проверка пропущена.");
            ctx.Report.Section("ПРИВИЛЕГИРОВАННЫЕ ЗАГРУЗЧИКИ", sb.ToString());
            return;
        }

        var c = m.Cache;
        var clds = new List<Cld>();

        foreach (ulong cldAddr in ctx.ClassLoaderDatas)
        {
            var cld = new Cld { Address = cldAddr };
            ulong handle = c.U64(cldAddr + (ulong)offLoader);
            cld.LoaderOop = handle == 0 ? 0 : c.U64(handle);
            cld.LoaderClass = cld.LoaderOop == 0
                ? "<загрузчик начальной загрузки>"
                : m.ClassNameOf(cld.LoaderOop) ?? "<не определён>";
            if (offMirrorHolder >= 0)
                cld.HasMirrorHolder = ctx.Target.ReadU8(cldAddr + (ulong)offMirrorHolder) != 0;

            ulong k = c.U64(cldAddr + (ulong)offKlasses);
            int guard = 0;
            var seen = new HashSet<ulong>();
            while (k is >= 0x10000 and <= 0x7FFFFFFFFFFFFF && guard++ < 200_000)
            {
                if (!seen.Add(k)) break;
                string? n = m.KlassName(k);
                if (n is not null) cld.Klasses.Add((k, n));
                k = c.U64(k + (ulong)offNextK);
            }
            clds.Add(cld);
        }

        Render(clds, sb);
        ReportDuplicateBootLoaders(ctx, clds, sb);
        ReportIntruders(ctx, clds, sb);
        ReportHiddenClassLoaders(ctx, clds, sb);

        ctx.Report.Section("ПРИВИЛЕГИРОВАННЫЕ ЗАГРУЗЧИКИ", sb.ToString());
    }

    private static bool NoOriginOnDisk(ScanContext ctx, string name)
    {
        if (name.Length == 0) return false;
        var jars = ctx.Jars;
        if (jars is null) return false;
        if (JarIndex.IsRuntimeClass(name)) return false;
        if (JarIndex.GeneratedKind(name) is not null) return false;
        if (ctx.GameIsRemapped && AgentInfra.IsVanillaObf(name)) return true;
        return !jars.Contains(name) && jars.OwningPackage(name) is null;
    }

    private static bool Privileged(Cld cld) =>
        cld.LoaderOop == 0 ||
        cld.LoaderClass.EndsWith("$PlatformClassLoader", StringComparison.Ordinal) ||
        cld.LoaderClass.EndsWith("BootClassLoader", StringComparison.Ordinal);

    private static void Render(List<Cld> clds, StringBuilder sb)
    {
        sb.AppendLine("ЗАГРУЗЧИКИ И ЧИСЛО КЛАССОВ В КАЖДОМ");
        foreach (var cld in clds.OrderByDescending(x => x.Klasses.Count))
            sb.AppendLine($"  0x{cld.Address:X}  {cld.LoaderClass,-64} классов " +
                          $"{cld.Klasses.Count}" +
                          (cld.HasMirrorHolder ? "  [загрузчик скрытого класса]" : "") +
                          (Privileged(cld) ? "  [привилегированный]" : ""));
        sb.AppendLine();
    }

    private static void ReportDuplicateBootLoaders(ScanContext ctx, List<Cld> clds,
        StringBuilder sb)
    {
        var nulls = clds.Where(x => x.LoaderOop == 0 && !x.HasMirrorHolder).ToList();
        sb.AppendLine($"ОБЪЕКТОВ ЗАГРУЗЧИКА С ПУСТОЙ ССЫЛКОЙ НА ЗАГРУЗЧИК: {nulls.Count}");
        foreach (var cld in nulls)
            sb.AppendLine($"  0x{cld.Address:X}  классов {cld.Klasses.Count}");
        sb.AppendLine();
        if (nulls.Count <= 1) return;

        var f = ctx.Report.Report("JVM",
            $"В графе {nulls.Count} объектов загрузчика с пустой ссылкой на объект-загрузчик, " +
            "а должен быть один",
            Severity.High,
            "Загрузчик начальной загрузки в виртуальной машине один: его объект " +
            "ClassLoaderData создаётся при запуске и существует в единственном " +
            "экземпляре. Объекты загрузчика скрытых классов тоже не имеют " +
            "объекта-загрузчика, но у них поднят признак «держатель зеркала класса», и " +
            "они здесь не учитываются. Второй объект без признака означает структуру, " +
            "созданную в обход штатного пути создания загрузчиков.");
        foreach (var cld in nulls)
            f.Add($"0x{cld.Address:X}", $"классов {cld.Klasses.Count}: " +
                                        string.Join(", ", cld.Klasses.Take(8).Select(x => x.Name)));
    }

    private static void ReportHiddenClassLoaders(ScanContext ctx, List<Cld> clds, StringBuilder sb)
    {
        var hits = clds.Where(x => x.LoaderOop != 0 &&
                                   (x.LoaderClass.Contains("+0x", StringComparison.Ordinal) ||
                                    x.LoaderClass.Contains("/0x", StringComparison.Ordinal)))
            .ToList();

        sb.AppendLine($"ЗАГРУЗЧИКОВ, ЧЕЙ СОБСТВЕННЫЙ КЛАСС — СКРЫТЫЙ: {hits.Count}");
        foreach (var cld in hits)
            sb.AppendLine($"  0x{cld.Address:X}  {cld.LoaderClass}  классов {cld.Klasses.Count}");
        sb.AppendLine();
        if (hits.Count == 0) return;

        var f = ctx.Report.Report("JAVA",
            $"{hits.Count} загрузчиков классов сами являются скрытыми классами " +
            $"(загружено ими классов: {hits.Sum(x => x.Klasses.Count)})",
            Severity.Critical,
            "Скрытый класс намеренно лишён имени, по которому его можно найти: в имени " +
            "стоит адрес, в словари имён он не попадает и сослаться на него из байт-кода " +
            "нельзя. Штатно так делают только лямбды и переходники механизма " +
            "java.lang.invoke — они существуют по одному экземпляру и классов не " +
            "загружают. Загрузчик классов — прямая противоположность: это публичная " +
            "точка, к которой обращаются по имени. Скрытым его делают ровно затем, " +
            "чтобы происхождение загруженного им кода нельзя было установить по имени " +
            "загрузчика.");
        foreach (var cld in hits)
        {
            f.Add(cld.LoaderClass, $"ClassLoaderData 0x{cld.Address:X}, классов " +
                                   $"{cld.Klasses.Count}");
            foreach (var (k, name) in cld.Klasses.Take(12))
                f.Add("    загружен им", $"{name} (Klass 0x{k:X})");
        }
    }

    private static void ReportIntruders(ScanContext ctx, List<Cld> clds, StringBuilder sb)
    {
        var intruders = new List<(Cld Cld, ulong Klass, string Name)>();
        foreach (var cld in clds)
        {
            if (!Privileged(cld)) continue;
            foreach (var (k, name) in cld.Klasses)
            {
                if (JarIndex.IsRuntimeClass(name)) continue;
                if (JarIndex.GeneratedKind(name) is not null) continue;
                if (name.StartsWith("[", StringComparison.Ordinal)) continue;
                intruders.Add((cld, k, name));
            }
        }

        sb.AppendLine("КЛАССЫ В ПРИВИЛЕГИРОВАННЫХ ЗАГРУЗЧИКАХ, НЕ ПРИНАДЛЕЖАЩИЕ ОБРАЗУ JDK");
        sb.AppendLine($"  найдено: {intruders.Count}");
        foreach (var (cld, k, name) in intruders.Take(500))
            sb.AppendLine($"      {name}   (Klass 0x{k:X}, загрузчик {cld.LoaderClass})");
        sb.AppendLine();
        if (intruders.Count == 0) return;

        var jars = ctx.Jars;
        var f = ctx.Report.Report("JAVA",
            $"{intruders.Count} классов загружены привилегированным загрузчиком, хотя не " +
            "принадлежат образу рантайма JDK",
            Severity.Critical,
            "Загрузчик начальной загрузки и платформенный загрузчик берут классы только " +
            "из образа рантайма JDK, и все их имена начинаются с java/, jdk/, sun/, javax/ " +
            "и подобных. Классы игры и модов загружает загрузчик Fabric и попасть сюда не " +
            "могут в принципе. Класс с посторонним именем в привилегированном загрузчике " +
            "положили туда намеренно, и способов ровно два: дописать архив ключом " +
            "-Xbootclasspath/a: до запуска либо определить класс напрямую из нативного " +
            "кода вызовом JNI DefineClass с пустым загрузчиком. Второй способ — обычная " +
            "работа шеллкода, принёсшего с собой байт-код: он не оставляет ни файла на " +
            "диске, ни записи в графе пользовательских загрузчиков.");
        foreach (var (cld, k, name) in intruders.Take(60))
        {
            string origin = jars is null ? "индекс архивов не построен"
                : NoOriginOnDisk(ctx, name) ? "НЕТ В АРХИВАХ"
                : jars.Contains(name) ? "есть в архивах на диске"
                : jars.OwningPackage(name) is { } p ? $"нет в архивах, пакет-предок «{p}» есть"
                : "происхождение не установлено";
            f.Add(name, $"Klass 0x{k:X}, загрузчик {cld.LoaderClass} (0x{cld.Address:X}) " +
                        $"[{origin}]");
        }
    }
}
