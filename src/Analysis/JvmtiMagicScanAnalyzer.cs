using System.Text;
using AgentScan.Core;
using AgentScan.Report;

namespace AgentScan.Analysis;

internal static class JvmtiMagicScanAnalyzer
{
    private const uint JVMTI_MAGIC = 0x71EE;
    private const uint DISPOSED_MAGIC = 0xDEFC;
    private const uint BAD_MAGIC = 0xDEAD;

    private static readonly string[] EventNames =
    {
        "VMInit", "VMDeath", "ThreadStart", "ThreadEnd", "ClassFileLoadHook",
        "ClassLoad", "ClassPrepare", "VMStart", "Exception", "ExceptionCatch",
        "SingleStep", "FramePop", "Breakpoint", "FieldAccess", "FieldModification",
        "MethodEntry", "MethodExit", "NativeMethodBind", "CompiledMethodLoad",
        "CompiledMethodUnload", "DynamicCodeGenerated", "DataDumpRequest", "reserved72",
        "MonitorWait", "MonitorWaited", "MonitorContendedEnter", "MonitorContendedEntered",
        "reserved77", "reserved78", "reserved79", "ResourceExhausted",
        "GarbageCollectionStart", "GarbageCollectionFinish", "ObjectFree", "VMObjectAlloc",
        "reserved85", "SampledObjectAlloc",
    };

    private static readonly string[] CapabilityNames =
    {
        "can_tag_objects", "can_generate_field_modification_events",
        "can_generate_field_access_events", "can_get_bytecodes",
        "can_get_synthetic_attribute", "can_get_owned_monitor_info",
        "can_get_current_contended_monitor", "can_get_monitor_info", "can_pop_frame",
        "can_redefine_classes", "can_signal_thread", "can_get_source_file_name",
        "can_get_line_numbers", "can_get_source_debug_extension",
        "can_access_local_variables", "can_maintain_original_method_order",
        "can_generate_single_step_events", "can_generate_exception_events",
        "can_generate_frame_pop_events", "can_generate_breakpoint_events", "can_suspend",
        "can_redefine_any_class", "can_get_current_thread_cpu_time",
        "can_get_thread_cpu_time", "can_generate_method_entry_events",
        "can_generate_method_exit_events", "can_generate_all_class_hook_events",
        "can_generate_compiled_method_load_events", "can_generate_monitor_events",
        "can_generate_vm_object_alloc_events", "can_generate_native_method_bind_events",
        "can_generate_garbage_collection_events", "can_generate_object_free_events",
        "can_force_early_return", "can_get_owned_monitor_stack_depth_info",
        "can_get_constant_pool", "can_set_native_method_prefix", "can_retransform_classes",
        "can_retransform_any_class", "can_generate_resource_exhaustion_heap_events",
        "can_generate_resource_exhaustion_threads_events", "can_generate_early_vmstart",
        "can_generate_early_class_hook_events", "can_generate_sampled_object_alloc_events",
        "can_support_virtual_threads",
    };

    private sealed class Hit
    {
        public ulong Address;
        public uint Magic, Version;
        public ulong Functions;
        public ulong Next;
        public ulong TagMap;
        public bool TagMapConfirmed;
        public bool FunctionsValid;
        public int CallbacksOff = -1;
        public int NonNullCallbacks;
        public List<string> Subscriptions = new();
        public List<string> Caps = new();
        public int Score;
        public List<string> Checks = new();
        public byte[]? Dump;

        public string MagicName => Magic switch
        {
            JVMTI_MAGIC => "0x71EE JVMTI_MAGIC (активно)",
            DISPOSED_MAGIC => "0xDEFC DISPOSED_MAGIC (ОТКЛЮЧЕНО через DisposeEnvironment)",
            BAD_MAGIC => "0xDEAD BAD_MAGIC (выведено из обращения)",
            _ => $"0x{Magic:X}",
        };
    }

    public static void Run(ScanContext ctx)
    {
        var jvm = JvmAnalyzer.FindJvm(ctx);
        var sb = new StringBuilder();

        sb.AppendLine("Поиск объектов окружения JVMTI по магическому числу HotSpot, без опоры");
        sb.AppendLine("на указатель таблицы функций. Прежние проверки опознают окружение именно");
        sb.AppendLine("по этому указателю, поэтому его затирание слепит их все разом; здесь");
        sb.AppendLine("признак другой, а достоверность набирается независимыми проверками.");
        sb.AppendLine();

        var known = ctx.JvmtiEnvs.ToHashSet();
        var hits = Scan(ctx, jvm, sb);

        sb.AppendLine($"Совпадений по магическому числу, прошедших проверку: {hits.Count}");
        sb.AppendLine($"Из них уже найдено прежними проверками: {hits.Count(h => known.Contains(h.Address))}");
        sb.AppendLine();

        foreach (var h in hits)
        {
            Render(ctx, h, known.Contains(h.Address), sb);
            Report(ctx, h, known.Contains(h.Address));
        }

        if (hits.Count == 0)
            sb.AppendLine("Ни одного объекта, похожего на окружение JVMTI, не найдено.");

        ctx.Report.Section("ОКРУЖЕНИЯ JVMTI ПО МАГИЧЕСКОМУ ЧИСЛУ (независимый поиск)",
            sb.ToString());
    }

    private static List<Hit> Scan(ScanContext ctx, ImageInMemory? jvm, StringBuilder sb)
    {
        var res = new List<Hit>();
        var seen = new HashSet<ulong>();

        var data = jvm is { Pe.Valid: true }
            ? jvm.Pe.Sections.Where(s => !s.IsExecutable && s.VirtualSize > 0)
                  .Select(s => (Lo: jvm.Base + s.VirtualAddress,
                                Hi: jvm.Base + s.VirtualAddress + s.VirtualSize)).ToList()
            : new List<(ulong Lo, ulong Hi)>();
        bool InJvmData(ulong v) => data.Any(x => v >= x.Lo && v < x.Hi);

        long candidates = 0, rejected = 0;

        foreach (var ch in MemoryScan.Chunks(ctx, MemoryScan.PrivateData, overlap: 0x400))
        {
            for (int i = 8; i + 8 <= ch.Length; i += 8)
            {
                uint magic = BitConverter.ToUInt32(ch.Data, i);
                if (magic is not (JVMTI_MAGIC or DISPOSED_MAGIC or BAD_MAGIC)) continue;

                ulong addr = ch.Base + (ulong)i - 8;
                if (!seen.Add(addr)) continue;
                candidates++;

                var h = Validate(ctx, addr, magic, InJvmData);
                if (h is null) { rejected++; continue; }
                res.Add(h);
                if (res.Count >= 64) break;
            }
            if (res.Count >= 64) break;
        }

        sb.AppendLine($"Просмотрено приватной памяти : " +
                      MemoryAnalyzer.Human(MemoryScan.TotalReadable(ctx, MemoryScan.PrivateData)) +
                      " (без ограничения по объёму)");
        sb.AppendLine($"Совпадений магического числа : {candidates}");
        sb.AppendLine($"Отсеяно проверками структуры : {rejected}");
        return res;
    }

    private static Hit? Validate(ScanContext ctx, ulong addr, uint magic,
        Func<ulong, bool> inJvmData)
    {
        var d = ctx.Target.ReadBytes(addr, 0x400);
        if (d is null) return null;

        var h = new Hit
        {
            Address = addr,
            Magic = magic,
            Functions = BitConverter.ToUInt64(d, 0),
            Version = BitConverter.ToUInt32(d, 12),
            Next = BitConverter.ToUInt64(d, 0x10),
            Dump = d,
        };

        if ((h.Version >> 24) != 0x30) return null;
        h.Score += 2;
        h.Checks.Add($"номер версии JVMTI 0x{h.Version:X8} корректен " +
                     $"(JVMTI {(h.Version >> 16) & 0xFF}.{(h.Version >> 8) & 0xFF}." +
                     $"{h.Version & 0xFF})");

        if (h.Next != 0)
        {
            if (h.Next is < 0x10000 or > 0x7FFFFFFFFFFF) return null;
            var nr = ctx.RegionAt(h.Next);
            if (nr is null || !nr.IsCommitted) return null;
            h.Score++;
            h.Checks.Add($"поле _next ведёт в закоммиченную память (0x{h.Next:X})");
        }
        else h.Checks.Add("поле _next пусто (единственное окружение либо конец списка)");

        if (inJvmData(h.Functions))
        {
            h.FunctionsValid = true;
            h.Score += 3;
            h.Checks.Add("поле таблицы функций цело и ведёт в данные jvm.dll — " +
                         "объект видят и прежние проверки");
        }
        else
            h.Checks.Add(h.Functions == 0
                ? "поле таблицы функций ОБНУЛЕНО — прежние проверки такой объект не видят"
                : $"поле таблицы функций (0x{h.Functions:X}) НЕ ведёт в данные jvm.dll — " +
                  "прежние проверки такой объект не видят");

        foreach (int cb in new[] { 0x28, 0x20, 0x30, 0x38, 0x40 })
        {
            if (cb + EventNames.Length * 8 + 0x40 > d.Length) continue;
            bool ok = true;
            int nonNull = 0;
            for (int i = 0; i < EventNames.Length && ok; i++)
            {
                ulong v = BitConverter.ToUInt64(d, cb + i * 8);
                if (v == 0) continue;
                if (v is < 0x10000 or > 0x7FFFFFFFFFFF) { ok = false; break; }
                var reg = ctx.RegionAt(v);
                if (reg is null || !reg.IsCommitted || !reg.IsExecutable) { ok = false; break; }
                nonNull++;
            }
            if (!ok) continue;

            int after = cb + EventNames.Length * 8;
            int tagOff = after + 8;
            int capsOff = tagOff + 8 + 24;
            if (capsOff + 32 > d.Length) continue;

            if (BitConverter.ToUInt64(d, capsOff + 8) != 0) continue;
            if (BitConverter.ToUInt64(d, capsOff + 24) != 0) continue;

            ulong tagMap = BitConverter.ToUInt64(d, tagOff);
            if (tagMap != 0)
            {
                if (tagMap is < 0x10000 or > 0x7FFFFFFFFFFF) continue;
                if (ctx.Target.ReadU64(tagMap) == addr)
                {
                    h.TagMap = tagMap;
                    h.TagMapConfirmed = true;
                    h.Score += 4;
                    h.Checks.Add($"таблица тегов 0x{tagMap:X} ссылается ОБРАТНО на это " +
                                 "окружение — раскладка подтверждена однозначно");
                }
                else h.TagMap = tagMap;
            }

            h.CallbacksOff = cb;
            h.NonNullCallbacks = nonNull;
            h.Score += nonNull > 0 ? 3 : 1;
            h.Checks.Add(nonNull > 0
                ? $"таблица колбэков на +0x{cb:X}: {nonNull} обработчиков, все ведут в " +
                  "исполняемую память"
                : $"таблица колбэков на +0x{cb:X} пуста (агент снял обработчики перед уходом)");

            for (int i = 0; i < EventNames.Length; i++)
            {
                ulong v = BitConverter.ToUInt64(d, cb + i * 8);
                if (v != 0) h.Subscriptions.Add($"{EventNames[i]} → {ctx.Describe(v)}");
            }

            ulong caps = BitConverter.ToUInt64(d, capsOff);
            for (int i = 0; i < CapabilityNames.Length; i++)
                if ((caps & (1UL << i)) != 0) h.Caps.Add(CapabilityNames[i]);
            if (h.Caps.Count > 0) h.Score += 2;
            break;
        }

        if (h.CallbacksOff < 0 && !h.FunctionsValid) return null;
        return h.Score >= 5 ? h : null;
    }

    private static void Render(ScanContext ctx, Hit h, bool alreadyKnown, StringBuilder sb)
    {
        sb.AppendLine(new string('=', 100));
        sb.AppendLine($"КАНДИДАТ 0x{h.Address:X}  {h.MagicName}");
        sb.AppendLine($"  достоверность           : {h.Score} " +
                      (alreadyKnown ? "(объект уже найден прежними проверками)"
                                    : "(НОВЫЙ объект — прежние проверки его не видят)"));
        sb.AppendLine($"  поле таблицы функций    : 0x{h.Functions:X} " +
                      (h.FunctionsValid ? "(цело)" : "(ЗАТЁРТО или подменено)"));
        sb.AppendLine($"  версия JVMTI            : 0x{h.Version:X8}");
        sb.AppendLine($"  _next                   : 0x{h.Next:X}");
        sb.AppendLine($"  таблица тегов           : " +
                      (h.TagMap == 0 ? "нет"
                        : $"0x{h.TagMap:X}" + (h.TagMapConfirmed ? " (подтверждена)" : "")));
        sb.AppendLine($"  регион                  : {ctx.RegionAt(h.Address)?.ToString() ?? "-"}");
        sb.AppendLine("  выполненные проверки:");
        foreach (var c in h.Checks) sb.AppendLine("      • " + c);
        if (h.Caps.Count > 0)
        {
            sb.AppendLine("  запрошенные возможности:");
            foreach (var c in h.Caps) sb.AppendLine("      " + c);
        }
        if (h.Subscriptions.Count > 0)
        {
            sb.AppendLine("  подписки на события:");
            foreach (var s in h.Subscriptions) sb.AppendLine("      " + s);
        }
        if (h.Dump is not null) sb.AppendLine(HexDump.Format(h.Dump, h.Address));
        sb.AppendLine();
    }

    private static void Report(ScanContext ctx, Hit h, bool alreadyKnown)
    {
        Severity sev = h.FunctionsValid && alreadyKnown ? Severity.Info : Severity.Critical;

        var f = ctx.Report.Report("JVM",
            $"Поиск по магическому числу: окружение JVMTI 0x{h.Address:X} — {h.MagicName}" +
            (h.FunctionsValid ? "" : ", поле таблицы функций ЗАТЁРТО") +
            (alreadyKnown ? " (подтверждает уже найденное)" : " (прежние проверки его не видели)"),
            sev,
            "Объект найден НЕ по указателю на таблицу функций, а по магическому числу " +
            "HotSpot внутри него. Это важно: все остальные проверки окружений опознают " +
            "объект именно по первому полю, поэтому затирание восьми байт скрывает его " +
            "от них всех разом, хотя сам объект со всеми возможностями и подписками " +
            "остаётся в памяти. " +
            (h.FunctionsValid
                ? "Здесь поле цело, и находка совпадает с тем, что нашли прежние проверки, — " +
                  "то есть это перекрёстное подтверждение, а не новая улика."
                : "Здесь поле НЕ ведёт в данные jvm.dll: либо обнулено, либо подменено. " +
                  "Само по себе это уже аномалия — виртуальная машина такое поле не " +
                  "меняет никогда. Объект опознан по независимым признакам: корректный " +
                  "номер версии JVMTI, согласованное поле _next, таблица из 37 слотов " +
                  "обработчиков, каждый из которых либо пуст, либо ведёт в исполняемую " +
                  "память" +
                  (h.TagMapConfirmed
                      ? ", и таблица тегов, ссылающаяся обратно на это же окружение"
                      : "") + "."));

        f.Add("адрес объекта", h.Address);
        f.Add("магическое число", h.MagicName);
        f.Add("версия JVMTI", $"0x{h.Version:X8}");
        f.Add("поле таблицы функций", h.FunctionsValid
            ? $"0x{h.Functions:X} (цело)"
            : $"0x{h.Functions:X} — НЕ ведёт в данные jvm.dll");
        f.Add("оценка достоверности", h.Score.ToString());
        f.Add("нашли ли прежние проверки", alreadyKnown ? "да" : "НЕТ");
        f.Add("обработчиков событий", h.NonNullCallbacks.ToString());
        f.Add("таблица тегов", h.TagMap == 0 ? "нет"
            : $"0x{h.TagMap:X}" + (h.TagMapConfirmed ? " (обратная ссылка подтверждена)" : ""));
        f.Add("регион", ctx.RegionAt(h.Address)?.ToString() ?? "-");

        f.Block("Выполненные проверки", string.Join("\n", h.Checks.Select(x => "  • " + x)));
        if (h.Caps.Count > 0)
            f.Block("Запрошенные возможности", string.Join("\n", h.Caps.Select(x => "  " + x)));
        if (h.Subscriptions.Count > 0)
            f.Block("Подписки на события", string.Join("\n", h.Subscriptions.Select(x => "  " + x)));
        if (h.Dump is not null)
            f.Block("Объект окружения (0x400 байт)", HexDump.Format(h.Dump, h.Address));

        if (ctx.Dumper is not null && !alreadyKnown)
        {
            ulong from = h.Address > 0x1000 ? h.Address - 0x1000 : h.Address;
            string? p = ctx.Dumper.DumpRange(from, 0x4000, "jvmtienv-magic",
                "окружение JVMTI, найденное по магическому числу",
                $"сам объект по 0x{h.Address:X}, {h.MagicName}");
            if (p is not null) f.Add("дамп окрестности", p);
        }
    }
}
