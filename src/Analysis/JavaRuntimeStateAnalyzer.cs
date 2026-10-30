using System.Text;
using AgentScan.Core;
using AgentScan.Report;

namespace AgentScan.Analysis;

internal static class JavaRuntimeStateAnalyzer
{
    public static void Run(ScanContext ctx)
    {
        var sb = new StringBuilder();
        sb.AppendLine("СОСТОЯНИЕ СРЕДЫ ИСПОЛНЕНИЯ JAVA");
        sb.AppendLine();

        var m = ctx.Java;
        int offMirror = ctx.Vm?.Off("Klass", "_java_mirror") ?? -1;
        if (m is null || offMirror < 0)
        {
            sb.AppendLine("  карта классов или доступ к статическим полям недоступны — " +
                          "проверка пропущена.");
            ctx.Report.Section("СРЕДА ИСПОЛНЕНИЯ JAVA", sb.ToString());
            return;
        }

        Properties(ctx, m, offMirror, sb);
        OpenedPackages(ctx, m, sb);
        NativeLibraries(ctx, m, sb);

        ctx.Report.Section("СРЕДА ИСПОЛНЕНИЯ JAVA", sb.ToString());
    }

    private static void Properties(ScanContext ctx, JavaMeta m, int offMirror, StringBuilder sb)
    {
        sb.AppendLine("СИСТЕМНЫЕ СВОЙСТВА: ЖИВАЯ ТАБЛИЦА И СНИМОК, СДЕЛАННЫЙ ПРИ ЗАПУСКЕ");
        sb.AppendLine();

        ulong liveObj = StaticOop(m, offMirror, "java/lang/System", "props");
        ulong savedObj = StaticOop(m, offMirror, "jdk/internal/misc/VM", "savedProps");

        var live = liveObj != 0 ? ReadMap(m, liveObj) : null;
        var saved = savedObj != 0 ? ReadMap(m, savedObj) : null;

        sb.AppendLine($"  живая таблица java.lang.System.props        : " +
                      $"0x{liveObj:X}, прочитано {(live?.Count.ToString() ?? "нет")}");
        sb.AppendLine($"  снимок jdk.internal.misc.VM.savedProps      : " +
                      $"0x{savedObj:X}, прочитано {(saved?.Count.ToString() ?? "нет")}");
        sb.AppendLine();

        if (live is null || live.Count == 0)
        {
            sb.AppendLine("  живая таблица свойств не прочитана — сверка не выполнялась.");
            sb.AppendLine();
            return;
        }

        sb.AppendLine("  ЖИВАЯ ТАБЛИЦА ЦЕЛИКОМ");
        foreach (var kv in live.OrderBy(x => x.Key, StringComparer.Ordinal))
            sb.AppendLine($"      {kv.Key} = {JavaMeta.Clean(kv.Value, 400)}");
        sb.AppendLine();

        CheckAttachSelf(ctx, live);

        if (saved is null || saved.Count == 0)
        {
            sb.AppendLine("  снимок свойств не прочитан — сравнить живую таблицу не с чем.");
            sb.AppendLine();
            return;
        }

        var added = live.Where(kv => !saved.ContainsKey(kv.Key)).ToList();
        var changed = live.Where(kv => saved.TryGetValue(kv.Key, out string? o) && o != kv.Value)
            .Select(kv => (kv.Key, Was: saved[kv.Key], Now: kv.Value)).ToList();
        var removed = saved.Keys.Where(k => !live.ContainsKey(k)).ToList();

        sb.AppendLine($"  появилось после запуска : {added.Count}");
        foreach (var kv in added.OrderBy(x => x.Key, StringComparer.Ordinal))
            sb.AppendLine($"      + {kv.Key} = {JavaMeta.Clean(kv.Value, 400)}");
        sb.AppendLine($"  изменилось после запуска: {changed.Count}");
        foreach (var (k, was, now) in changed.OrderBy(x => x.Key, StringComparer.Ordinal))
        {
            sb.AppendLine($"      ~ {k}");
            sb.AppendLine($"           было: {JavaMeta.Clean(was, 400)}");
            sb.AppendLine($"           стало: {JavaMeta.Clean(now, 400)}");
        }
        sb.AppendLine($"  исчезло из живой таблицы: {removed.Count}");
        foreach (string k in removed) sb.AppendLine($"      - {k}");
        sb.AppendLine();

        ReportRuntimeProps(ctx, added, changed, removed);
    }

    private static void CheckAttachSelf(ScanContext ctx, Dictionary<string, string> live)
    {
        string[] keys =
        {
            "jdk.attach.allowAttachSelf", "jdk.attach.allowPermissionsToAttachSelf",
        };
        foreach (string key in keys)
        {
            if (!live.TryGetValue(key, out string? v)) continue;
            bool on = v.Equals("true", StringComparison.OrdinalIgnoreCase) || v.Length == 0;
            ctx.Report.Report("JVM",
                $"Свойство {key} = «{v}»",
                on ? Severity.Critical : Severity.Medium,
                "Это свойство разрешает процессу подключиться механизмом attach к " +
                "СОБСТВЕННОЙ виртуальной машине. По умолчанию оно не задано вовсе, и " +
                "попытка самоподключения отклоняется. Задают его ровно затем, чтобы код, " +
                "уже работающий внутри процесса, мог подсадить в него агента JVMTI, не " +
                "имея отдельного процесса-загрузчика. Игра и её моды этого не делают.")
                .Add("свойство", key)
                .Add("значение", v.Length == 0 ? "<пусто, что означает «включено»>" : v);
        }
    }

    private static void ReportRuntimeProps(ScanContext ctx, List<KeyValuePair<string, string>> added,
        List<(string Key, string Was, string Now)> changed, List<string> removed)
    {
        bool Routine(string k) =>
            k.StartsWith("java.vm.", StringComparison.Ordinal) ||
            k.StartsWith("java.specification", StringComparison.Ordinal) ||
            k is "java.class.version" or "line.separator" or "java.io.tmpdir" or
                "user.timezone" or "java.vendor.url.bug" or "sun.font.fontmanager" or
                "java.awt.graphicsenv" or "awt.toolkit" or "sun.awt.enableExtraMouseButtons" or
                "java.awt.printerjob" or "sun.java2d.d3d";

        var interesting = added.Where(kv => !Routine(kv.Key)).ToList();
        if (interesting.Count > 0)
        {
            bool loud = interesting.Any(kv => AgentRelated(kv.Key) || AgentRelated(kv.Value));
            var f = ctx.Report.Report("JAVA",
                $"{interesting.Count} системных свойств установлены уже во время работы — " +
                "их нет в снимке, сделанном при запуске виртуальной машины",
                loud ? Severity.High : Severity.Info,
                "Среда исполнения хранит две копии таблицы свойств: живую, которую можно " +
                "менять вызовом System.setProperty, и неизменяемый снимок, снятый при " +
                "запуске машины до выполнения кода приложения. Свойство, которое есть в " +
                "живой таблице и отсутствует в снимке, поставил уже работающий код. Само " +
                "по себе это законно — так делают и моды, — но список должен быть объяснён: " +
                "именно через свойства настраивают загрузку агентов, пути к библиотекам и " +
                "поведение механизма подключения.");
            foreach (var kv in interesting.Take(60))
                f.Add(kv.Key, JavaMeta.Clean(kv.Value, 300));
        }

        var keyChanged = changed.Where(x =>
            x.Key is "java.class.path" or "java.library.path" or "sun.boot.library.path" or
                "sun.java.command" or "java.home" or "user.dir" or "jdk.module.path" or
                "java.system.class.loader" or "java.protocol.handler.pkgs").ToList();
        if (keyChanged.Count > 0)
        {
            var f = ctx.Report.Report("JAVA",
                $"{keyChanged.Count} опорных свойств среды исполнения переписаны после запуска",
                Severity.High,
                "Путь поиска классов, путь поиска нативных библиотек, домашний каталог и " +
                "командная строка приложения задаются при запуске и в норме не меняются " +
                "никогда. Значение, отличающееся от снимка, снятого при старте машины, " +
                "означает, что кто-то переписал опору, по которой среда исполнения ищет " +
                "код и библиотеки.");
            foreach (var (k, was, now) in keyChanged)
            {
                f.Add(k + " (было)", JavaMeta.Clean(was, 400));
                f.Add(k + " (стало)", JavaMeta.Clean(now, 400));
            }
        }

        removed = removed.Where(k => !StrippedByRuntime(k)).ToList();
        if (removed.Count > 0)
        {
            var f = ctx.Report.Report("JAVA",
                $"{removed.Count} свойств есть в снимке при запуске, но их нет в живой таблице",
                Severity.Medium,
                "Свойство из живой таблицы можно только удалить вызовом " +
                "System.clearProperty либо подменой всей таблицы. Ни игра, ни среда " +
                "исполнения этого не делают. Удаление своих следов из живой таблицы — " +
                "естественный шаг для того, кто их туда клал, и снимок при запуске это " +
                "показывает.");
            foreach (string k in removed.Take(60)) f.Add("удалено", k);
        }
    }

    private static bool StrippedByRuntime(string key) =>
        key is "jdk.boot.class.path.append" or "sun.nio.MaxDirectMemorySize" or
            "java.class.path.append" or "sun.java.launcher.diag" or
            "jdk.internal.lambda.dumpProxyClasses";

    private static bool AgentRelated(string s) =>
        s.Contains("javaagent", StringComparison.OrdinalIgnoreCase) ||
        s.Contains("premain", StringComparison.OrdinalIgnoreCase) ||
        s.Contains("agentmain", StringComparison.OrdinalIgnoreCase) ||
        s.Contains("instrument", StringComparison.OrdinalIgnoreCase) ||
        s.Contains("jdk.attach", StringComparison.OrdinalIgnoreCase) ||
        s.Contains("attachSelf", StringComparison.OrdinalIgnoreCase) ||
        s.Contains("bootclasspath", StringComparison.OrdinalIgnoreCase) ||
        s.Contains("-agentlib", StringComparison.OrdinalIgnoreCase) ||
        s.Contains("-agentpath", StringComparison.OrdinalIgnoreCase);

    private static void OpenedPackages(ScanContext ctx, JavaMeta m, StringBuilder sb)
    {
        sb.AppendLine("ПАКЕТЫ, ОТКРЫТЫЕ ДОПОЛНИТЕЛЬНО К ОПИСАНИЮ МОДУЛЯ");
        sb.AppendLine();

        var idx = ctx.HeapIndex;
        if (idx is null || !idx.Valid)
        {
            sb.AppendLine("  указатель по куче Java не построен — карты модулей не читались.");
            sb.AppendLine();
            return;
        }

        ulong modKlass = m.KlassByName("java/lang/Module");
        var modules = modKlass != 0 && idx.FullLive.TryGetValue(modKlass, out var allMods)
            ? allMods
            : idx.LiveInstancesOf("java/lang/Module");
        sb.AppendLine($"  объектов java.lang.Module в куче: {modules.Count}");

        var rows = new List<(string Module, string Kind, string Package, string To)>();
        foreach (ulong mod in modules)
        {
            string name = m.StringField(mod, "name") ?? "<модуль без имени>";
            foreach (string fld in new[] { "openPackages", "exportedPackages" })
            {
                ulong map = m.OopField(mod, fld);
                if (map == 0) continue;
                string kind = fld == "openPackages" ? "открыт" : "экспортирован";
                foreach (var (pkg, targets) in ReadPackageMap(m, map))
                    rows.Add((name, kind, pkg, targets));
            }
        }

        sb.AppendLine($"  записей о добавленных открытиях : {rows.Count}");
        foreach (var r in rows.OrderBy(x => x.Module, StringComparer.Ordinal)
                     .ThenBy(x => x.Package, StringComparer.Ordinal))
            sb.AppendLine($"      {r.Module}/{r.Package} {r.Kind} → {r.To}");
        sb.AppendLine();

        if (rows.Count == 0) return;

        ReportOpens(ctx, rows);
    }

    private static IEnumerable<(string Package, string Targets)> ReadPackageMap(
        JavaMeta m, ulong map)
    {
        ulong table = m.OopField(map, "table");
        if (table == 0) yield break;

        foreach (ulong head in m.ObjArray(table, 8192))
        {
            ulong node = head;
            int guard = 0;
            while (node != 0 && guard++ < 4096)
            {
                ulong kOop = m.OopField(node, "key");
                ulong vOop = m.OopField(node, "val");
                if (vOop == 0) vOop = m.OopField(node, "value");
                string? pkg = kOop != 0 ? m.StringValue(kOop) : null;
                if (pkg is not null)
                    yield return (pkg, DescribeTargets(m, vOop));
                node = m.OopField(node, "next");
            }
        }
    }

    private static string DescribeTargets(JavaMeta m, ulong set)
    {
        if (set == 0) return "<получатели не прочитаны>";
        var names = new List<string>();

        void AddModule(ulong mod)
        {
            if (mod == 0) return;
            string? n = m.StringField(mod, "name");
            names.Add(n is null or "" ? "БЕЗЫМЯННЫЙ МОДУЛЬ (весь путь классов)" : n);
        }

        foreach (string d in new[] { "c", "s", "m" })
        {
            ulong inner = m.OopField(set, d);
            if (inner != 0 && inner != set) { set = inner; break; }
        }

        foreach (string f in new[] { "e0", "e1" })
        {
            ulong e = m.OopField(set, f);
            if (e != 0) AddModule(e);
        }
        ulong arr = m.OopField(set, "elements");
        if (arr == 0) arr = m.OopField(set, "table");
        if (arr != 0)
            foreach (ulong e in m.ObjArray(arr, 512))
                if (e != 0) AddModule(e);

        return names.Count > 0
            ? string.Join(", ", names.Distinct().Take(8))
            : "<получатели не прочитаны>";
    }

    private static bool FullyEncapsulated(string module) =>
        module is "java.base" or "java.management" or "java.instrument" or
            "jdk.attach" or "jdk.internal.jvmstat";

    private static void ReportOpens(ScanContext ctx,
        List<(string Module, string Kind, string Package, string To)> rows)
    {
        var opens = rows.Where(r => r.Kind == "открыт").ToList();
        var sensitive = opens.Where(r => FullyEncapsulated(r.Module)).ToList();
        var toUnnamed = opens.Where(r => r.To.Contains("БЕЗЫМЯННЫЙ", StringComparison.Ordinal))
            .ToList();

        if (sensitive.Count > 0)
        {
            var f = ctx.Report.Report("JAVA",
                $"{sensitive.Count} пакетов ЗАКРЫТЫХ модулей платформы открыты для " +
                "отражения",
                Severity.High,
                "Система модулей закрывает внутренности платформы от отражения. " +
                "Открыть пакет можно ключом --add-opens при запуске либо вызовом " +
                "Modules.addOpens уже во время работы; и то, и другое записывается в " +
                "карту openPackages объекта модуля, а штатные открытия из описания " +
                "модуля в эту карту НЕ попадают. Значит, каждая запись — чьё-то " +
                "решение. Закрыть пакет обратно нечем: запись переживает и уход того, " +
                "кто её сделал. Открытые пакеты платформы — обязательный шаг для " +
                "постороннего кода: без них не получить ни доверенный Lookup, ни " +
                "Unsafe, ни доступ к приватным полям платформы. Сверьте список с " +
                "ключами --add-opens в командной строке: то, чего там нет, открыли " +
                "изнутри процесса.");
            foreach (var r in sensitive.Take(60))
                f.Add($"{r.Module}/{r.Package}", "открыт → " + r.To);
        }

        if (toUnnamed.Count > 0 && sensitive.Count == 0)
        {
            var f = ctx.Report.Report("JAVA",
                $"{toUnnamed.Count} пакетов открыты безымянному модулю (всему пути классов)",
                Severity.Info,
                "Открытие безымянному модулю снимает ограничение для ВСЕГО кода, " +
                "загруженного с пути классов, а не для одного названного модуля. " +
                "Запись сделана либо ключом --add-opens, либо вызовом изнутри процесса, " +
                "и не очищается никогда.");
            foreach (var r in toUnnamed.Take(60))
                f.Add($"{r.Module}/{r.Package}", "открыт → " + r.To);
        }
    }

    private static void NativeLibraries(ScanContext ctx, JavaMeta m, StringBuilder sb)
    {
        sb.AppendLine("НАТИВНЫЕ БИБЛИОТЕКИ ГЛАЗАМИ САМОЙ JAVA");
        sb.AppendLine();

        var idx = ctx.HeapIndex;
        if (idx is null || !idx.Valid)
        {
            sb.AppendLine("  указатель по куче Java не построен — реестр библиотек не читался.");
            sb.AppendLine();
            return;
        }

        var names = m.KlassesWhere(n =>
            n.EndsWith("NativeLibraries$NativeLibraryImpl", StringComparison.Ordinal) ||
            n.EndsWith("ClassLoader$NativeLibrary", StringComparison.Ordinal) ||
            n.EndsWith("NativeLibraries$NativeLibraryContext", StringComparison.Ordinal))
            .Select(x => x.Name).Distinct().ToList();

        if (names.Count == 0)
        {
            sb.AppendLine("  класс реестра нативных библиотек в этой машине не найден.");
            sb.AppendLine();
            return;
        }

        var rows = new List<(string Lib, ulong Handle, string From, string Module, bool Builtin)>();
        foreach (string cls in names)
        {
            sb.AppendLine($"  класс реестра: {cls}");
            foreach (ulong obj in idx.LiveInstancesOf(cls))
            {
                string lib = m.StringField(obj, "name") ?? "";
                long handle = m.LongField(obj, "handle");
                ulong fromClass = m.OopField(obj, "fromClass");
                bool builtin = false;
                int bo = m.FieldOffset(m.KlassOf(obj), "isBuiltin");
                if (bo >= 0) builtin = ctx.Target.ReadU8(obj + (ulong)bo) != 0;

                string from = fromClass != 0 ? MirrorClassName(ctx, m, fromClass) : "";
                string module = DescribeHandle(ctx, (ulong)handle);
                rows.Add((lib, (ulong)handle, from, module, builtin));
            }
        }

        sb.AppendLine($"  найдено записей: {rows.Count}");
        foreach (var r in rows.OrderBy(x => x.Lib, StringComparer.OrdinalIgnoreCase))
        {
            sb.AppendLine($"      {(r.Lib.Length > 0 ? r.Lib : "<имя не прочитано>")}");
            sb.AppendLine($"          дескриптор 0x{r.Handle:X} → {r.Module}" +
                          $"{(r.Builtin ? ", встроена в среду исполнения" : "")}");
            if (r.From.Length > 0) sb.AppendLine($"          загрузку запросил класс: {r.From}");
        }
        sb.AppendLine();

        ReportDetachedLibraries(ctx, rows);
        ReportForeignLoaders(ctx, rows);
    }

    private static string DescribeHandle(ScanContext ctx, ulong handle)
    {
        if (handle == 0) return "дескриптор нулевой";
        var im = ctx.ImageAt(handle);
        if (im is not null)
            return handle == im.Base
                ? im.Name
                : $"{im.Name}+0x{handle - im.Base:X} (не база модуля)";
        var r = ctx.RegionAt(handle);
        return r is null
            ? "МОДУЛЯ ПО ЭТОМУ АДРЕСУ НЕТ (память не отображена)"
            : $"МОДУЛЯ ПО ЭТОМУ АДРЕСУ НЕТ ({r.TypeString}/{r.ProtectString})";
    }

    private static string MirrorClassName(ScanContext ctx, JavaMeta m, ulong mirror)
    {
        ulong a = m.Vm.StaticAddr("java_lang_Class", "_klass_offset");
        if (a != 0)
        {
            int off = (int)m.Cache.U32(a);
            if (off is > 0 and < 4096)
            {
                ulong klass = m.Cache.U64(mirror + (ulong)off);
                string? n = klass is >= 0x10000 and <= 0x7FFFFFFFFFFFFF
                    ? m.KlassName(klass)
                    : null;
                if (n is not null) return n;
            }
        }
        return m.Describe(mirror);
    }

    private static void ReportDetachedLibraries(ScanContext ctx,
        List<(string Lib, ulong Handle, string From, string Module, bool Builtin)> rows)
    {
        var hits = rows.Where(r => !r.Builtin && r.Handle != 0 &&
                                   r.Module.StartsWith("МОДУЛЯ", StringComparison.Ordinal))
            .ToList();
        if (hits.Count == 0) return;

        var f = ctx.Report.Report("JVM",
            $"{hits.Count} нативных библиотек числятся у Java загруженными, но модуля по " +
            "их дескриптору в процессе нет",
            Severity.High,
            "Дескриптор загруженной библиотеки — это база её модуля в адресном " +
            "пространстве. Пока библиотека загружена, по этому адресу лежит образ PE, и " +
            "модуль виден в списках загрузчика. Запись в куче Java с дескриптором, по " +
            "которому модуля больше нет, означает, что библиотеку выгрузили, а объект, " +
            "описывающий её, уцелел в куче. Именно так выглядит нативная часть чита после " +
            "отключения: код убран, а запись о нём в куче Java осталась и называет и файл, " +
            "и класс, который его загрузил.");
        foreach (var r in hits)
            f.Add(r.Lib.Length > 0 ? r.Lib : $"0x{r.Handle:X}",
                $"дескриптор 0x{r.Handle:X}, {r.Module}" +
                (r.From.Length > 0 ? $", загрузил класс {r.From}" : ""));
    }

    private static void ReportForeignLoaders(ScanContext ctx,
        List<(string Lib, ulong Handle, string From, string Module, bool Builtin)> rows)
    {
        if (ctx.Jars is null) return;
        var hits = rows.Where(r => NoOriginOnDisk(ctx, r.From)).ToList();
        if (hits.Count == 0) return;

        var f = ctx.Report.Report("JVM",
            $"{hits.Count} нативных библиотек загружены классами, которых нет ни в одном " +
            "архиве, доступном игре",
            Severity.Critical,
            "На каждый успешный System.loadLibrary или System.load среда исполнения " +
            "запоминает класс, который загрузку запросил. Класс без файла на диске, " +
            "загрузивший нативную библиотеку, — это посторонний код, у которого была " +
            "нативная часть. Запись переживает и выгрузку самой библиотеки, и стирание " +
            "байт-кода загрузившего класса.");
        foreach (var r in hits)
            f.Add(r.From, $"библиотека {r.Lib}, дескриптор 0x{r.Handle:X}, {r.Module}");
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

    private static ulong StaticOop(JavaMeta m, int offMirror, string className, string field)
    {
        ulong klass = m.KlassByName(className);
        if (klass == 0) return 0;
        ulong handle = m.Cache.U64(klass + (ulong)offMirror);
        if (handle is < 0x1000 or > 0x7FFFFFFFFFFF) return 0;
        ulong mirror = m.Cache.U64(handle);
        if (mirror is < 0x1000 or > 0x7FFFFFFFFFFF) return 0;
        foreach (var f in m.DeclaredFields(klass))
        {
            if (!f.IsStatic || f.Name != field) continue;
            if (!f.Signature.StartsWith('L') && !f.Signature.StartsWith('[')) return 0;
            return m.Oop(mirror, f.Offset);
        }
        return 0;
    }

    private static Dictionary<string, string> ReadMap(JavaMeta m, ulong obj, int depth = 0)
    {
        var res = new Dictionary<string, string>(StringComparer.Ordinal);
        if (obj == 0 || depth > 3) return res;

        ulong klass = m.KlassOf(obj);
        string name = m.KlassName(klass) ?? "";

        if (name.EndsWith("/Properties", StringComparison.Ordinal))
        {
            ulong inner = m.OopField(obj, "map");
            if (inner != 0) return ReadMap(m, inner, depth + 1);
        }
        foreach (string delegateField in new[] { "m", "map", "delegate" })
        {
            if (name.Contains("Unmodifiable", StringComparison.Ordinal) ||
                name.Contains("Synchronized", StringComparison.Ordinal))
            {
                ulong inner = m.OopField(obj, delegateField);
                if (inner != 0 && inner != obj) return ReadMap(m, inner, depth + 1);
            }
        }

        ulong table = m.OopField(obj, "table");
        if (table == 0) return res;

        var cells = m.ObjArray(table);

        if (name.Contains("ImmutableCollections", StringComparison.Ordinal))
        {
            for (int i = 0; i + 1 < cells.Count; i += 2)
            {
                string? k = cells[i] == 0 ? null : m.StringValue(cells[i]);
                if (k is null) continue;
                res[k] = (cells[i + 1] == 0 ? null : m.StringValue(cells[i + 1])) ?? "";
            }
            return res;
        }

        foreach (ulong head in cells)
        {
            ulong node = head;
            int guard = 0;
            while (node != 0 && guard++ < 4096)
            {
                ulong kOop = m.OopField(node, "key");
                ulong vOop = m.OopField(node, "val");
                if (vOop == 0) vOop = m.OopField(node, "value");
                string? k = kOop != 0 ? m.StringValue(kOop) : null;
                if (k is not null)
                    res[k] = (vOop != 0 ? m.StringValue(vOop) : null) ?? "";
                node = m.OopField(node, "next");
            }
        }
        return res;
    }
}
