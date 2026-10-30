using System.Text;
using AgentScan.Core;
using AgentScan.Report;

namespace AgentScan.Analysis;

internal static class AgentInstrumentationAnalyzer
{
    private const string Impl = "sun/instrument/InstrumentationImpl";
    private const string TransformerIface = "java/lang/instrument/ClassFileTransformer";

    public static void Run(ScanContext ctx)
    {
        var sb = new StringBuilder();
        sb.AppendLine("МЕХАНИЗМ АГЕНТОВ JAVA: ОБЪЕКТ INSTRUMENTATION И ПРЕОБРАЗОВАТЕЛИ КЛАССОВ");
        sb.AppendLine();

        var m = ctx.Java;
        var idx = ctx.HeapIndex;
        if (m is null)
        {
            sb.AppendLine("  карта классов недоступна — проверка пропущена.");
            ctx.Report.Section("МЕХАНИЗМ АГЕНТОВ JAVA", sb.ToString());
            return;
        }

        ClassPresence(ctx, m, sb);

        if (idx is null || !idx.Valid)
        {
            sb.AppendLine("  указатель по куче Java не построен — объекты не искались.");
            ctx.Report.Section("МЕХАНИЗМ АГЕНТОВ JAVA", sb.ToString());
            return;
        }

        Instances(ctx, m, idx, sb);
        Transformers(ctx, m, idx, sb);

        ctx.Report.Section("МЕХАНИЗМ АГЕНТОВ JAVA", sb.ToString());
    }

    private static void ClassPresence(ScanContext ctx, JavaMeta m, StringBuilder sb)
    {
        string[] marks =
        {
            Impl, "sun/instrument/TransformerManager",
            "sun/instrument/TransformerManager$TransformerInfo",
            "java/lang/instrument/Instrumentation", TransformerIface,
            "java/lang/instrument/ClassDefinition",
            "java/lang/instrument/UnmodifiableClassException",
            "jdk/internal/module/Modules",
        };

        sb.AppendLine("ЗАГРУЖЕННОСТЬ КЛАССОВ МЕХАНИЗМА АГЕНТОВ");
        var loaded = new List<string>();
        foreach (string s in marks)
        {
            ulong k = m.KlassByName(s);
            sb.AppendLine($"  {(k != 0 ? "ЕСТЬ  " : "нет   ")} {s}" +
                          (k != 0 ? $"   Klass 0x{k:X}" : ""));
            if (k != 0) loaded.Add(s);
        }
        sb.AppendLine();

        var strong = loaded.Where(s => s.StartsWith("sun/instrument/", StringComparison.Ordinal) ||
                                       s == TransformerIface ||
                                       s == "java/lang/instrument/ClassDefinition").ToList();
        if (strong.Count == 0) return;

        var f = ctx.Report.Report("JVM",
            $"В памяти загружены классы механизма агентов Java ({strong.Count} из " +
            $"{marks.Length} искомых)",
            Severity.High,
            "Классы механизма агентов среда исполнения загружает лениво — только когда " +
            "агент действительно подключается, при запуске ключом -javaagent или на ходу " +
            "через attach. В клиенте Minecraft на Fabric агентов нет: загрузчик модов " +
            "переписывает байт-код своим загрузчиком классов и к механизму агентов не " +
            "обращается. Поэтому сама загруженность этих классов означает, что механизм " +
            "агентов в этом процессе разворачивали. Класс остаётся загруженным навсегда — " +
            "отсоединение агента его не выгружает.");
        foreach (string s in loaded) f.Add("загружен", s);
    }

    private static void Instances(ScanContext ctx, JavaMeta m, JavaHeapIndex idx, StringBuilder sb)
    {
        sb.AppendLine("ОБЪЕКТЫ INSTRUMENTATION");

        ulong implKlass = m.KlassByName(Impl);
        if (implKlass == 0)
        {
            sb.AppendLine("  класс реализации не загружен — объектов быть не может.");
            sb.AppendLine();
            return;
        }

        var live = idx.LiveInstancesOf(Impl);
        var dead = DeadInstancesOf(idx, implKlass);
        sb.AppendLine($"  живых объектов: {live.Count}, в мёртвой зоне: {dead.Count}");

        var all = live.Select(o => (Obj: o, Dead: false))
            .Concat(dead.Select(o => (Obj: o, Dead: true))).ToList();
        if (all.Count == 0)
        {
            sb.AppendLine();
            return;
        }

        var rows = new List<(ulong Obj, bool Dead, long Native, string Caps, List<string> Ts)>();
        foreach (var (obj, isDead) in all)
        {
            long native = m.LongField(obj, "mNativeAgent");
            var caps = new List<string>();
            foreach (string cap in new[]
                     {
                         "mEnvironmentSupportsRedefineClasses",
                         "mEnvironmentSupportsRetransformClassesKnown",
                         "mEnvironmentSupportsRetransformClasses",
                         "mEnvironmentSupportsNativeMethodPrefix",
                     })
            {
                int off = m.FieldOffset(m.KlassOf(obj), cap);
                if (off < 0) continue;
                caps.Add($"{cap}={(ctx.Target.ReadU8(obj + (ulong)off) != 0 ? "да" : "нет")}");
            }

            var ts = new List<string>();
            foreach (string mgr in new[] { "mTransformerManager", "mRetransfomableTransformerManager",
                         "mRetransformableTransformerManager" })
            {
                ulong tm = m.OopField(obj, mgr);
                if (tm == 0) continue;
                foreach (string t in ReadTransformerManager(m, tm))
                    ts.Add($"{mgr}: {t}");
            }

            rows.Add((obj, isDead, native, string.Join(", ", caps), ts));
        }

        foreach (var r in rows)
        {
            sb.AppendLine($"  объект 0x{r.Obj:X}{(r.Dead ? " [в мёртвой зоне]" : "")}");
            sb.AppendLine($"      нативная часть агента: 0x{r.Native:X} " +
                          $"({DescribeNative(ctx, (ulong)r.Native)})");
            sb.AppendLine($"      возможности: {(r.Caps.Length > 0 ? r.Caps : "не прочитаны")}");
            foreach (string t in r.Ts) sb.AppendLine($"      преобразователь — {t}");
            if (r.Ts.Count == 0) sb.AppendLine("      списки преобразователей пусты");
        }
        sb.AppendLine();

        var f = ctx.Report.Report("JVM",
            $"В куче Java найдено {rows.Count} объектов Instrumentation " +
            $"(в мёртвой зоне: {rows.Count(r => r.Dead)})",
            Severity.Critical,
            "Объект Instrumentation среда исполнения создаёт ровно один раз на агента и " +
            "отдаёт ему в метод premain или agentmain. Его существование означает, что " +
            "агент Java в этом процессе был. В чистом клиенте Minecraft объектов " +
            "Instrumentation нет ни одного: загрузчик модов работает своим загрузчиком " +
            "классов и механизм агентов не задействует. Объект, найденный в мёртвой зоне " +
            "кучи, означает, что агент отработал и был отсоединён, а его объект уже " +
            "собран сборщиком мусора — но содержимое ещё читается.");
        foreach (var r in rows)
        {
            f.Add($"объект 0x{r.Obj:X}",
                $"{(r.Dead ? "в мёртвой зоне, " : "")}нативная часть 0x{r.Native:X} " +
                $"({DescribeNative(ctx, (ulong)r.Native)}), возможности: {r.Caps}");
            foreach (string t in r.Ts.Take(20)) f.Add("    преобразователь", t);
        }
    }

    private static string DescribeNative(ScanContext ctx, ulong addr)
    {
        if (addr == 0) return "нативной части нет";
        var r = ctx.RegionAt(addr);
        if (r is null) return "ПАМЯТЬ ПО ЭТОМУ АДРЕСУ НЕ ОТОБРАЖЕНА — нативная часть исчезла";
        return $"{r.TypeString}/{r.ProtectString}, база аллокации 0x{r.AllocationBase:X}";
    }

    private static List<string> ReadTransformerManager(JavaMeta m, ulong tm)
    {
        var res = new List<string>();
        ulong arr = m.OopField(tm, "mTransformerList");
        if (arr == 0) arr = m.OopField(tm, "transformerList");
        if (arr == 0) return res;

        foreach (ulong info in m.ObjArray(arr, 4096))
        {
            if (info == 0) continue;
            ulong t = m.OopField(info, "mTransformer");
            if (t == 0) t = m.OopField(info, "transformer");
            string cls = t != 0 ? m.ClassNameOf(t) ?? "?" : m.ClassNameOf(info) ?? "?";
            res.Add($"{cls} (объект 0x{(t != 0 ? t : info):X})");
        }
        return res;
    }

    private static void Transformers(ScanContext ctx, JavaMeta m, JavaHeapIndex idx,
        StringBuilder sb)
    {
        sb.AppendLine("ОБЪЕКТЫ-ПРЕОБРАЗОВАТЕЛИ БАЙТ-КОДА В КУЧЕ");

        if (m.KlassByName(TransformerIface) == 0)
        {
            sb.AppendLine("  интерфейс преобразователя не загружен — искать нечего.");
            sb.AppendLine();
            return;
        }

        var rows = new List<(string Klass, long Live, long Dead, ulong Sample)>();
        foreach (var st in idx.Stats.Values)
        {
            if (st.Klass == 0 || st.Name.Length == 0) continue;
            if (!m.IsAssignableTo(st.Klass, TransformerIface)) continue;
            ulong sample = st.LiveSamples.FirstOrDefault();
            if (sample == 0) sample = st.DeadSamples.FirstOrDefault();
            rows.Add((st.Name, st.Live, st.Dead, sample));
        }

        sb.AppendLine($"  различных классов-преобразователей: {rows.Count}");
        foreach (var r in rows.OrderByDescending(x => x.Live + x.Dead))
            sb.AppendLine($"      {r.Klass}   живых {r.Live}, в мёртвой зоне {r.Dead}" +
                          (r.Sample != 0 ? $", пример 0x{r.Sample:X}" : ""));
        sb.AppendLine();
        if (rows.Count == 0) return;

        var jars = ctx.Jars;
        var f = ctx.Report.Report("JAVA",
            $"В куче найдены объекты {rows.Count} классов, переписывающих байт-код " +
            "чужих классов",
            Severity.Critical,
            "Класс, реализующий интерфейс преобразователя, получает байт-код КАЖДОГО " +
            "загружаемого класса и возвращает его изменённым. Это и есть механизм " +
            "переписывания игры на лету. Зарегистрировать такой класс можно только через " +
            "объект Instrumentation, то есть только будучи агентом. Убрать его из списка " +
            "регистраций можно, а из кучи — нет: объект остаётся до сборки мусора, а после " +
            "сборки его содержимое ещё какое-то время читается в мёртвой зоне.");
        foreach (var r in rows.OrderByDescending(x => x.Live + x.Dead).Take(50))
        {
            string origin = jars is null ? "индекс архивов не построен"
                : NoOriginOnDisk(ctx, r.Klass) ? "НЕТ В АРХИВАХ"
                : JarIndex.IsRuntimeClass(r.Klass) ? "класс среды исполнения"
                : jars.Contains(r.Klass) ? "есть в архивах"
                : "происхождение не установлено";
            f.Add(r.Klass, $"живых {r.Live}, в мёртвой зоне {r.Dead} [{origin}]");
        }
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

    private static List<ulong> DeadInstancesOf(JavaHeapIndex idx, ulong klass) =>
        idx.Stats.TryGetValue(klass, out var st) ? st.DeadSamples : new List<ulong>();
}
