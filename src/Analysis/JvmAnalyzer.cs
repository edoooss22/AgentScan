using System.Text;
using AgentScan.Core;
using AgentScan.Report;

namespace AgentScan.Analysis;

internal sealed class VmTable
{
    public ulong Address;
    public int Slots;
    public int NonNull;
    public int OutsideJvm;
    public List<(int Slot, ulong Target)> Foreign = new();
    public string Kind = "?";
    public RawPattern? RefPattern;
}

internal static class JvmAnalyzer
{
    private static readonly string[] AgentModules =
    {
        "instrument.dll", "jdwp.dll", "attach.dll", "management.dll", "management_ext.dll",
        "management_agent.dll", "jsig.dll"
    };

    private static readonly (string Name, Severity Sev, string Why)[] TellTaleThreads =
    {
        ("JVMTI Agent Thread", Severity.Critical,
            "Служебный поток, создаваемый через JVMTI RunAgentThread. Существует только " +
            "при активном JVMTI-агенте."),
        ("JDWP", Severity.High,
            "Поток отладочного транспорта JDWP — к JVM подключён отладчик."),
        ("Java Debug", Severity.High, "Инфраструктура отладки JVM активна."),
        ("Attach Listener", Severity.Info,
            "На Windows этот поток создаётся при старте JVM всегда, уликой не является. " +
            "Важно другое: если он создан заметно позже старта процесса — значит, " +
            "механизм attach срабатывал повторно."),
    };

    public static ImageInMemory? FindJvm(ScanContext ctx) =>
        ctx.Images.FirstOrDefault(i => i.Name.Equals("jvm.dll", StringComparison.OrdinalIgnoreCase));

    public static List<VmTable> FindVmTables(ScanContext ctx)
    {
        var res = new List<VmTable>();
        var jvm = FindJvm(ctx);
        if (jvm is null || !jvm.Pe.Valid) return res;

        ulong imgLo = jvm.Base, imgHi = jvm.Base + jvm.Size;
        var textSections = jvm.Pe.Sections.Where(s => s.IsExecutable).ToList();
        if (textSections.Count == 0) return res;

        bool InText(ulong p)
        {
            if (p < imgLo || p >= imgHi) return false;
            uint rva = (uint)(p - imgLo);
            return textSections.Any(s => rva >= s.VirtualAddress &&
                                         rva < s.VirtualAddress + s.VirtualSize);
        }

        foreach (var sec in jvm.Pe.Sections)
        {
            if (sec.IsExecutable) continue;
            if (sec.VirtualSize is 0 or > 64 * 1024 * 1024) continue;
            if (sec.Name is not (".rdata" or ".data")) continue;

            var buf = new byte[sec.VirtualSize];
            ctx.Target.ReadPartial(jvm.Base + sec.VirtualAddress, buf, out _);
            ulong secVa = jvm.Base + sec.VirtualAddress;

            var runs = new List<(int Start, int Slots, int NonNull)>();
            int i = 0;
            while (i + 8 <= buf.Length)
            {
                ulong v = BitConverter.ToUInt64(buf, i);
                if (v != 0 && !InText(v)) { i += 8; continue; }

                int start = i, nonNull = 0;
                while (i + 8 <= buf.Length)
                {
                    ulong x = BitConverter.ToUInt64(buf, i);
                    if (x == 0) { i += 8; continue; }
                    if (!InText(x)) break;
                    nonNull++;
                    i += 8;
                }
                runs.Add((start, (i - start) / 8, nonNull));
            }

            for (int k = 0; k < runs.Count; k++)
            {
                var (start, slots, nonNull) = runs[k];
                if (slots < 24) continue;

                var foreign = new List<(int, ulong)>();
                int end = start + slots * 8;
                int m = k;
                while (m + 1 < runs.Count)
                {
                    var next = runs[m + 1];
                    int gapBytes = next.Start - end;
                    if (gapBytes is <= 0 or > 8 * 8) break;
                    if (next.Slots < 24) break;
                    for (int q = 0; q < gapBytes; q += 8)
                    {
                        ulong fv = BitConverter.ToUInt64(buf, end + q);
                        foreign.Add(((end + q - start) / 8, fv));
                    }
                    slots += gapBytes / 8 + next.Slots;
                    nonNull += gapBytes / 8 + next.NonNull;
                    end = next.Start + next.Slots * 8;
                    m++;
                }

                if (slots >= 100 && nonNull >= 80)
                {
                    var tbl = new VmTable
                    {
                        Address = secVa + (ulong)start,
                        Slots = slots,
                        NonNull = nonNull,
                        OutsideJvm = foreign.Count,
                        Foreign = foreign,
                        Kind = "массив указателей",
                    };
                    AnchorInterface(buf, secVa, start, slots, tbl);
                    res.Add(tbl);
                }
                k = m;
            }
        }
        return res;
    }

    private const int JvmtiSlots = 156;
    private const int JniSlots = 233;

    private static void AnchorInterface(byte[] buf, ulong secVa, int runStart, int slots,
        VmTable tbl)
    {
        int lastNonNull = -1;
        for (int i = slots - 1; i >= 0; i--)
        {
            if (BitConverter.ToUInt64(buf, runStart + i * 8) != 0) { lastNonNull = i; break; }
        }
        if (lastNonNull < 0) return;

        bool Try(int size, int leadingNulls, string kind)
        {
            int startSlot = lastNonNull - (size - 1);
            if (startSlot < 0) return false;
            for (int i = 0; i < leadingNulls; i++)
                if (BitConverter.ToUInt64(buf, runStart + (startSlot + i) * 8) != 0) return false;
            if (BitConverter.ToUInt64(buf, runStart + (startSlot + leadingNulls) * 8) == 0)
                return false;

            tbl.Kind = kind;
            tbl.Address = secVa + (ulong)(runStart + startSlot * 8);
            tbl.Slots = size;
            return true;
        }

        if (Try(JvmtiSlots, 1, "jvmtiInterface_1_ (jvmtiEnv)")) return;
        Try(JniSlots, 4, "JNINativeInterface_ (JNIEnv)");
    }

    public static void Run(ScanContext ctx, SweepResult sweep, List<VmTable> tables)
    {
        var rep = ctx.Report;

        CheckCommandLineAndEnv(ctx, rep);
        CheckAgentModules(ctx, rep);
        CheckAgentExports(ctx, rep);
        CheckTellTaleThreads(ctx, rep);
        CheckVmTables(ctx, rep, tables);
        CheckAgentClasses(ctx, rep, sweep);

        rep.Section("JVM", RenderJvmSection(ctx, tables, sweep));
    }

    private static void CheckCommandLineAndEnv(ScanContext ctx, ScanReport rep)
    {
        string cmd = ctx.Target.GetCommandLine() ?? "";
        var env = ctx.Target.GetEnvironment();

        var agentFlags = new[] { "-javaagent:", "-agentpath:", "-agentlib:" };
        foreach (var flag in agentFlags)
        {
            int i = cmd.IndexOf(flag, StringComparison.OrdinalIgnoreCase);
            if (i < 0) continue;
            int end = cmd.IndexOf(' ', i);
            string val = end < 0 ? cmd.Substring(i) : cmd.Substring(i, end - i);
            rep.Report("JVM", $"В командной строке JVM присутствует {flag}", Severity.Critical,
                    "Агент подключён при запуске JVM. Для чистого клиента Minecraft " +
                    "таких аргументов быть не должно (исключение — отладка/профилирование).")
                .Add("аргумент", val)
                .Add("полная командная строка", cmd);
        }

        foreach (var e in env)
        {
            string upper = e.ToUpperInvariant();
            bool interesting =
                upper.StartsWith("_JAVA_OPTIONS=") ||
                upper.StartsWith("JAVA_TOOL_OPTIONS=") ||
                upper.StartsWith("JDK_JAVA_OPTIONS=") ||
                upper.StartsWith("JAVA_OPTIONS=") ||
                upper.StartsWith("CLASSPATH=");
            if (!interesting) continue;

            int eq = e.IndexOf('=');
            string value = eq >= 0 ? e[(eq + 1)..].Trim() : "";
            bool hasAgent = agentFlags.Any(f => e.Contains(f, StringComparison.OrdinalIgnoreCase));
            rep.Report("JVM",
                    $"Переменная окружения процесса: {e.Split('=')[0]}" +
                    (value.Length == 0 ? " (пустая)" : ""),
                    hasAgent ? Severity.Critical
                        : value.Length == 0 ? Severity.Info : Severity.Medium,
                    "_JAVA_OPTIONS / JAVA_TOOL_OPTIONS / JDK_JAVA_OPTIONS позволяют " +
                    "незаметно добавить JVM аргументы (в том числе -javaagent) без правки " +
                    "лаунчера. Лаунчер Minecraft обычно очищает эти переменные.")
                .Add("значение", e);
        }

        rep.Report("JVM", "Командная строка и окружение процесса", Severity.Info, null)
            .Add("командная строка", cmd)
            .Add("рабочий каталог", ctx.Target.GetCurrentDirectory() ?? "-")
            .Add("DllPath", ctx.Target.GetDllPath() ?? "-")
            .Block("Окружение", string.Join("\n", env.Select(x => "  " + x)));
    }

    private static void CheckAgentModules(ScanContext ctx, ScanReport rep)
    {
        foreach (var im in ctx.Images)
        {
            var hit = AgentModules.FirstOrDefault(
                m => im.Name.Equals(m, StringComparison.OrdinalIgnoreCase));
            if (hit is null) continue;

            Severity sev = hit switch
            {
                "instrument.dll" => Severity.Critical,
                "jdwp.dll" => Severity.Critical,
                "attach.dll" => Severity.High,
                _ => Severity.Info,
            };
            string why = hit switch
            {
                "instrument.dll" =>
                    "instrument.dll — нативная часть java.lang.instrument. Она загружается " +
                    "в JVM ТОЛЬКО при подключении Java-агента: либо -javaagent при запуске, " +
                    "либо динамически через Attach API. Штатный Minecraft её не грузит.",
                "jdwp.dll" =>
                    "jdwp.dll — транспорт отладчика Java. Присутствие означает, что JVM " +
                    "запускалась с отладочным агентом или к ней подключался отладчик.",
                "attach.dll" =>
                    "attach.dll используется механизмом Dynamic Attach.",
                _ => "Модуль служебной инфраструктуры JVM; сам по себе не улика, " +
                     "но в связке с другими признаками важен.",
            };

            var f = rep.Report("JVM", $"Загружен модуль {im.Name}", sev, why);
            ModuleAnalyzer.FillModuleData(ctx, f, im);
        }
    }

    private static void CheckAgentExports(ScanContext ctx, ScanReport rep)
    {
        string[] entries = { "Agent_OnLoad", "Agent_OnAttach", "Agent_OnUnload",
                             "Agent_OnLoad_L", "Agent_OnAttach_L", "JVM_OnLoad" };

        foreach (var im in ctx.Images)
        {
            if (!im.Pe.Valid) continue;
            if (im.Name.Equals("instrument.dll", StringComparison.OrdinalIgnoreCase)) continue;

            var found = im.Pe.Exports.Entries
                .Where(e => entries.Any(x => e.Name.StartsWith(x, StringComparison.Ordinal)))
                .Select(e => e.Name)
                .Distinct()
                .ToList();
            if (found.Count == 0) continue;

            var f = rep.Report("JVM",
                $"Модуль {im.Name} экспортирует точки входа JVMTI-агента: " +
                string.Join(", ", found),
                Severity.Critical,
                "Нативный JVMTI-агент обязан экспортировать Agent_OnLoad (загрузка при " +
                "старте) или Agent_OnAttach (подключение к живой JVM). Ни одна библиотека " +
                "штатного Minecraft этих функций не экспортирует. Наличие такого модуля " +
                "в процессе означает, что к JVM подключался нативный агент — это и есть " +
                "механизм JVMTI-читов.");
            ModuleAnalyzer.FillModuleData(ctx, f, im);
        }
    }

    private static readonly (string Prefix, Severity Sev, string Why)[] AgentClasses =
    {
        ("sun/instrument/InstrumentationImpl", Severity.Critical,
            "Реализация java.lang.instrument.Instrumentation. Этот класс загружается " +
            "в JVM исключительно при подключении Java-агента (-javaagent или динамический " +
            "attach). В чистом Minecraft его нет."),
        ("java/lang/instrument/ClassFileTransformer", Severity.Critical,
            "Интерфейс трансформации байт-кода загруженных классов — то, чем Java-читы " +
            "патчат код игры на лету. Загружается только вместе с агентом."),
        ("java/lang/instrument/Instrumentation", Severity.Critical,
            "API инструментирования. Присутствует только при подключённом агенте."),
        ("sun/tools/attach/", Severity.Critical,
            "Классы Attach API внутри самой игры означают, что процесс подключался агентом " +
            "сам к себе (self-attach) — типовой приём инжекта Java-чита без внешнего файла."),
        ("com/sun/tools/attach/VirtualMachine", Severity.Critical,
            "Attach API загружен внутри процесса игры."),
        ("jdk/internal/agent/", Severity.Medium,
            "Инфраструктура управляющего агента JVM."),
        ("org/objectweb/asm/ClassWriter", Severity.Info,
            "ASM используется самим Fabric — сам по себе не улика."),
    };

    private static void CheckAgentClasses(ScanContext ctx, ScanReport rep, SweepResult sweep)
    {
        if (sweep.Classes.Count == 0) return;

        foreach (var (prefix, sev, why) in AgentClasses)
        {
            if (sev == Severity.Info) continue;
            var hits = sweep.Classes.Values
                .Where(c => c.Name.StartsWith(prefix, StringComparison.Ordinal))
                .ToList();
            if (hits.Count == 0) continue;

            var f = rep.Report("JVM",
                $"В памяти найден байт-код классов «{prefix}*» ({hits.Count} шт.)", sev, why);
            foreach (var c in hits.Take(20))
                f.Add(c.Name, $"0x{c.Address:X}, class-версия {c.MajorVersion}" +
                              (c.SuperName.Length > 0 ? $", extends {c.SuperName}" : ""));
        }
    }

    private static void CheckTellTaleThreads(ScanContext ctx, ScanReport rep)
    {
        foreach (var th in ctx.Threads)
        {
            if (th.Description is null) continue;
            foreach (var (name, sev0, why) in TellTaleThreads)
            {
                if (!th.Description.Contains(name, StringComparison.OrdinalIgnoreCase)) continue;

                var sev = sev0;
                if (name == "Attach Listener" && ctx.Target.StartTimeUtc != default &&
                    th.CreateTimeUtc != default &&
                    (th.CreateTimeUtc - ctx.Target.StartTimeUtc).TotalSeconds > 10)
                    sev = Severity.High;

                var f = rep.Report("JVM",
                    $"В процессе присутствует поток JVM «{th.Description}»", sev, why);
                f.Add("TID", th.Tid.ToString());
                if (th.CreateTimeUtc != default)
                {
                    f.Add("создан", th.CreateTimeUtc.ToLocalTime().ToString("O"));
                    if (ctx.Target.StartTimeUtc != default)
                        f.Add("создан через",
                            $"{(th.CreateTimeUtc - ctx.Target.StartTimeUtc).TotalSeconds:F2} с после старта JVM");
                }
                ulong a = th.Win32StartAddress != 0 ? th.Win32StartAddress : th.KernelStartAddress;
                f.Add("стартовый адрес", ctx.Describe(a));
            }
        }
    }

    private static void CheckVmTables(ScanContext ctx, ScanReport rep, List<VmTable> tables)
    {
        var referenced = tables.Where(t => (t.RefPattern?.TotalHits ?? 0) > 0).ToList();
        if (tables.Count > 0 && tables.All(t => t.RefPattern is null))
        {
            rep.Report("JVM", "Поиск объектов jvmtiEnv не выполнялся", Severity.Info,
                "Подсчёт ссылок на таблицы JNI/JVMTI требует сплошного скана памяти. " +
                "Он отключён ключом --no-strings / --fast.");
            return;
        }

        foreach (var tbl in referenced)
        {
            var rp = tbl.RefPattern!;
            bool isJni = tbl.Kind.StartsWith("JNINativeInterface");
            bool isJvmti = tbl.Kind.StartsWith("jvmtiInterface");
            if (!isJni && !isJvmti) continue;

            if (isJni)
            {
                var fi = rep.Report("JVM",
                    $"Таблица JNI найдена: 0x{tbl.Address:X}, ссылок из памяти: {rp.TotalHits}",
                    Severity.Info,
                    "Это штатная таблица JNINativeInterface_ и указатели JNIEnv потоков Java. " +
                    "Число ссылок примерно равно числу потоков Java.");
                fi.Add("слотов", tbl.Slots.ToString());
                fi.Add("непустых слотов", tbl.NonNull.ToString());
                ReportForeignSlots(ctx, rep, tbl, "JNI");
                continue;
            }

            {
                var f = rep.Report("JVM",
                    $"Найдено {rp.TotalHits} ссылок на таблицу jvmtiInterface_1_ " +
                    $"по 0x{tbl.Address:X} — это объекты jvmtiEnv",
                    Severity.Critical,
                    "Каждый подключённый к JVM агент получает объект jvmtiEnv, первое поле " +
                    "которого — указатель на таблицу jvmtiInterface_1_ в jvm.dll. " +
                    "В процессе Minecraft без агентов таких объектов нет ни одного. " +
                    "После DisposeEnvironment память объекта освобождается, но её содержимое " +
                    "обычно сохраняется до повторного использования — то есть след " +
                    "переживает выгрузку чита.");
                f.Add("адрес таблицы", tbl.Address);
                f.Add("слотов в таблице", tbl.Slots.ToString());
                f.Add("непустых слотов", tbl.NonNull.ToString());

                var sb = new StringBuilder();
                foreach (var (addr, region) in rp.Hits.Take(64))
                {
                    sb.AppendLine($"  0x{addr:X}  в {region.TypeString}/{region.ProtectString} " +
                                  $"(аллокация 0x{region.AllocationBase:X})");
                    var head = ctx.Target.ReadBytes(addr, 64);
                    if (head is not null)
                        sb.AppendLine(HexDump.Format(head, addr).Replace("\n", "\n    "));
                }
                f.Block("Найденные объекты", sb.ToString().TrimEnd());
                ReportForeignSlots(ctx, rep, tbl, "JVMTI");
            }
        }

        var jvmti = tables.FirstOrDefault(t => t.Kind.StartsWith("jvmtiInterface"));
        if (jvmti is not null && (jvmti.RefPattern?.TotalHits ?? 0) == 0)
        {
            rep.Report("JVM",
                    "Объектов jvmtiEnv в памяти не найдено — следов JVMTI-агента нет",
                    Severity.Info,
                    "Таблица jvmtiInterface_1_ в jvm.dll найдена, но ни один объект в памяти " +
                    "на неё не ссылается. Значит, за время жизни процесса JVMTI-окружение " +
                    "не создавалось — либо его память уже полностью перезаписана.")
                .Add("адрес таблицы", jvmti.Address)
                .Add("слотов", jvmti.Slots.ToString());
        }

    }

    private static void ReportForeignSlots(ScanContext ctx, ScanReport rep, VmTable tbl,
        string kind, Severity sev = Severity.Critical)
    {
        if (tbl.OutsideJvm == 0) return;
        var f = rep.Report("JVM",
            $"Таблица {kind} по 0x{tbl.Address:X}: {tbl.OutsideJvm} слотов указывают " +
            "за пределы jvm.dll",
            sev,
            "Таблица функций JNI/JVMTI состоит из указателей на код самой jvm.dll. " +
            "Слот, указывающий наружу, означает перехват соответствующей функции.");
        foreach (var (slot, target) in tbl.Foreign.Take(64))
            f.Add($"слот #{slot}", $"0x{target:X} → {ctx.Describe(target)}");
    }

    private static readonly string[] ExpectedRoots =
    {
        "java/", "javax/", "jdk/", "sun/", "com/sun/", "net/minecraft/", "com/mojang/",
        "net/fabricmc/", "org/objectweb/asm/", "org/spongepowered/", "org/slf4j/",
        "org/apache/", "com/google/", "io/netty/", "it/unimi/", "org/lwjgl/", "org/joml/",
        "com/ibm/icu/", "oshi/", "com/fasterxml/", "org/lz4/", "net/java/dev/jna/",
        "com/jcraft/", "org/jcraft/", "com/nimbusds/", "net/minidev/", "joptsimple/",
        "org/quiltmc/", "com/mojang/blaze3d/", "net/minecraftforge/", "cpw/mods/",
        "org/lwjglx/", "com/electronwill/", "org/objenesis/", "me/", "dev/", "mixin/",
        "org/intellij/", "org/jetbrains/", "com/electron", "org/w3c/", "org/xml/",
        "javassist/", "kotlin/", "kotlinx/", "org/checkerframework/", "com/mojang/logging/",
    };

    private static string RenderJvmSection(ScanContext ctx, List<VmTable> tables, SweepResult sweep)
    {
        var sb = new StringBuilder();
        var jvm = FindJvm(ctx);
        sb.AppendLine(jvm is null
            ? "jvm.dll не найдена — процесс не является JVM либо модуль скрыт."
            : $"jvm.dll: база 0x{jvm.Base:X}, размер 0x{jvm.Size:X}, путь {jvm.Path}");
        sb.AppendLine();
        sb.AppendLine($"Кандидатов в таблицы функций ВМ: {tables.Count} " +
                      $"(со ссылками из памяти: {tables.Count(x => (x.RefPattern?.TotalHits ?? 0) > 0)})");
        foreach (var t in tables.Where(x => (x.RefPattern?.TotalHits ?? 0) > 0 || x.Slots >= 150)
                                .OrderByDescending(x => x.RefPattern?.TotalHits ?? 0).Take(40))
            sb.AppendLine($"  0x{t.Address:X}  слотов={t.Slots,4}  непустых={t.NonNull,4}  " +
                          $"чужих={t.OutsideJvm}  ссылок в памяти={t.RefPattern?.TotalHits ?? -1}  {t.Kind}");
        sb.AppendLine();
        sb.AppendLine("Потоки JVM (по именам):");
        foreach (var th in ctx.Threads.Where(x => x.Description is not null)
                                      .OrderBy(x => x.CreateTimeUtc))
        {
            string dt = ctx.Target.StartTimeUtc != default && th.CreateTimeUtc != default
                ? $"+{(th.CreateTimeUtc - ctx.Target.StartTimeUtc).TotalSeconds,8:F1}с" : "";
            sb.AppendLine($"  {th.Tid,-8} {dt,-12} {th.Description}");
        }
        sb.AppendLine();
        sb.AppendLine($"Class-файлов в памяти: {sweep.Classes.Count}");
        return sb.ToString();
    }
}
