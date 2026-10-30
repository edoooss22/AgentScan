using System.Text;
using AgentScan.Core;
using AgentScan.Report;

namespace AgentScan.Analysis;

internal static class JvmtiAgentProvenanceAnalyzer
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

    private sealed class Env
    {
        public ulong Address;
        public byte[] Dump = Array.Empty<byte>();
        public ulong Functions;
        public uint Magic, Version;
        public ulong Next;
        public bool Retransformable;
        public ulong LocalStorage;

        public int CallbacksOff = -1;
        public int TagMapOff = -1;
        public int EnableOff = -1;
        public int CapsOff = -1;
        public bool LayoutConfirmed;

        public ulong TagMap;
        public ulong[] Enable = Array.Empty<ulong>();
        public List<string> Caps = new();
        public List<string> Prohibited = new();
        public List<(string Event, ulong Target)> Callbacks = new();
        public List<string> Prefixes = new();
        public ulong AgentPtr;
        public AgentRecord? Agent;

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

        if (jvm is null || !jvm.Pe.Valid)
        {
            sb.AppendLine("jvm.dll не найдена — восстановление агента невозможно.");
            ctx.Report.Section("ПРОИСХОЖДЕНИЕ АГЕНТА JVMTI (восстановление по остаткам)",
                sb.ToString());
            return;
        }

        var envs = Collect(ctx, jvm, sb);
        sb.AppendLine($"Объектов окружения JVMTI для разбора: {envs.Count}");
        sb.AppendLine();

        foreach (var e in envs)
        {
            Recover(ctx, jvm, e);
            Render(ctx, e, sb);
            ReportEnv(ctx, e);
        }

        if (envs.Count == 0)
        {
            sb.AppendLine("Ни одного объекта окружения JVMTI не найдено — восстанавливать нечего.");
            sb.AppendLine("Это отрицательный результат: за время жизни процесса окружение");
            sb.AppendLine("агента либо не создавалось, либо его память полностью перезаписана.");
        }

        ctx.Report.Section("ПРОИСХОЖДЕНИЕ АГЕНТА JVMTI (восстановление по остаткам)",
            sb.ToString());
    }

    private static List<Env> Collect(ScanContext ctx, ImageInMemory jvm, StringBuilder sb)
    {
        var res = new List<Env>();
        var seen = new HashSet<ulong>();

        var data = jvm.Pe.Sections
            .Where(s => !s.IsExecutable && s.VirtualSize > 0)
            .Select(s => (Lo: jvm.Base + s.VirtualAddress,
                          Hi: jvm.Base + s.VirtualAddress + s.VirtualSize))
            .ToList();
        bool InJvmData(ulong v) => data.Any(x => v >= x.Lo && v < x.Hi);

        foreach (ulong a in ctx.JvmtiEnvs)
        {
            if (!seen.Add(a)) continue;
            var e = ReadEnv(ctx, a, InJvmData);
            if (e is not null) res.Add(e);
        }

        foreach (var ch in MemoryScan.Chunks(ctx, MemoryScan.PrivateData, overlap: 0x20))
        {
            if (res.Count > 64) break;
            for (int i = 0; i + 0x20 <= ch.Length; i += 8)
            {
                ulong fn = BitConverter.ToUInt64(ch.Data, i);
                if (!InJvmData(fn)) continue;
                uint magic = BitConverter.ToUInt32(ch.Data, i + 8);
                if (magic is not (JVMTI_MAGIC or DISPOSED_MAGIC or BAD_MAGIC)) continue;
                ulong addr = ch.Base + (ulong)i;
                if (!seen.Add(addr)) continue;
                var e = ReadEnv(ctx, addr, InJvmData);
                if (e is not null) res.Add(e);
                if (res.Count > 64) break;
            }
        }

        sb.AppendLine("Объекты окружения JVMTI опознаются по паре независимых признаков:");
        sb.AppendLine("указатель на таблицу функций внутри данных jvm.dll и магическое число");
        sb.AppendLine("HotSpot сразу за ним. Оба признака вместе случайными быть не могут.");
        sb.AppendLine();
        return res;
    }

    private static Env? ReadEnv(ScanContext ctx, ulong addr, Func<ulong, bool> inJvmData)
    {
        var d = ctx.Target.ReadBytes(addr, 0x400);
        if (d is null) return null;
        ulong fn = BitConverter.ToUInt64(d, 0);
        if (!inJvmData(fn)) return null;
        uint magic = BitConverter.ToUInt32(d, 8);
        if (magic is not (JVMTI_MAGIC or DISPOSED_MAGIC or BAD_MAGIC)) return null;

        return new Env
        {
            Address = addr,
            Dump = d,
            Functions = fn,
            Magic = magic,
            Version = BitConverter.ToUInt32(d, 12),
            Next = BitConverter.ToUInt64(d, 0x10),
            Retransformable = d[0x18] != 0,
            LocalStorage = BitConverter.ToUInt64(d, 0x20),
        };
    }

    private static void Recover(ScanContext ctx, ImageInMemory jvm, Env e)
    {
        ProbeLayout(ctx, e);
        RecoverCallbacks(ctx, e);
        RecoverPrefixes(ctx, e);
        RecoverAgentPointer(ctx, e);
        _ = jvm;
    }

    private static void ProbeLayout(ScanContext ctx, Env e)
    {
        var d = e.Dump;
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
                var r = ctx.RegionAt(v);
                if (r is null || !r.IsCommitted || !r.IsExecutable) { ok = false; break; }
                nonNull++;
            }
            if (!ok) continue;

            int after = cb + EventNames.Length * 8;
            int tagOff = after + 8;
            int enableOff = tagOff + 8;
            int capsOff = enableOff + 24;
            if (capsOff + 32 > d.Length) continue;

            ulong tagMap = BitConverter.ToUInt64(d, tagOff);
            bool tagOk = tagMap == 0;
            if (!tagOk && tagMap is >= 0x10000 and <= 0x7FFFFFFFFFFF)
            {
                ulong back = ctx.Target.ReadU64(tagMap);
                tagOk = back == e.Address;
            }
            if (!tagOk) continue;

            ulong capsHi = BitConverter.ToUInt64(d, capsOff + 8);
            ulong prohHi = BitConverter.ToUInt64(d, capsOff + 24);
            if (capsHi != 0 || prohHi != 0) continue;

            e.CallbacksOff = cb;
            e.TagMapOff = tagOff;
            e.EnableOff = enableOff;
            e.CapsOff = capsOff;
            e.TagMap = tagMap;
            e.LayoutConfirmed = tagMap != 0 || nonNull > 0;
            e.Enable = new[]
            {
                BitConverter.ToUInt64(d, enableOff),
                BitConverter.ToUInt64(d, enableOff + 8),
                BitConverter.ToUInt64(d, enableOff + 16),
            };
            e.Caps = DecodeCaps(BitConverter.ToUInt64(d, capsOff));
            e.Prohibited = DecodeCaps(BitConverter.ToUInt64(d, capsOff + 16));
            return;
        }
    }

    private static List<string> DecodeCaps(ulong lo)
    {
        var res = new List<string>();
        for (int i = 0; i < CapabilityNames.Length; i++)
            if ((lo & (1UL << i)) != 0) res.Add(CapabilityNames[i]);
        return res;
    }

    private static void RecoverCallbacks(ScanContext ctx, Env e)
    {
        if (e.CallbacksOff < 0) return;
        for (int i = 0; i < EventNames.Length; i++)
        {
            ulong v = BitConverter.ToUInt64(e.Dump, e.CallbacksOff + i * 8);
            if (v == 0) continue;
            e.Callbacks.Add((EventNames[i], v));
        }
    }

    private static void RecoverPrefixes(ScanContext ctx, Env e)
    {
        for (int off = 0x20; off + 8 <= e.Dump.Length; off += 8)
        {
            ulong arr = BitConverter.ToUInt64(e.Dump, off);
            if (arr is < 0x10000 or > 0x7FFFFFFFFFFF) continue;
            var reg = ctx.RegionAt(arr);
            if (reg is null || !reg.IsCommitted || reg.IsExecutable) continue;

            var found = new List<string>();
            for (int k = 0; k < 8; k++)
            {
                ulong p = ctx.Target.ReadU64(arr + (ulong)k * 8);
                if (p == 0) break;
                string? s = JvmtiAgentProbe.ReadAscii(ctx, p, 128);
                if (s is null || s.Length is < 1 or > 100) break;
                if (!s.All(ch => char.IsLetterOrDigit(ch) || ch is '_' or '$')) break;
                found.Add(s);
            }
            if (found.Count == 0) continue;
            foreach (var s in found)
                if (!e.Prefixes.Contains(s)) e.Prefixes.Add(s);
            if (e.Prefixes.Count >= 8) return;
        }
    }

    private static void RecoverAgentPointer(ScanContext ctx, Env e)
    {
        int from = e.CapsOff >= 0 ? e.CapsOff + 32 : 0x28;
        for (int off = from; off + 8 <= Math.Min(e.Dump.Length, from + 0x80); off += 8)
        {
            ulong p = BitConverter.ToUInt64(e.Dump, off);
            if (p is < 0x10000 or > 0x7FFFFFFFFFFF) continue;
            var rec = JvmtiAgentProbe.TryRead(ctx, p);
            if (rec is null) continue;
            e.AgentPtr = p;
            e.Agent = rec;
            return;
        }
    }

    private static List<(string Klass, int Count)> TaggedClasses(ScanContext ctx, ulong tagMap)
    {
        var res = new Dictionary<string, int>(StringComparer.Ordinal);
        if (tagMap is < 0x10000 or > 0x7FFFFFFFFFFF) return new List<(string, int)>();
        var vm = ctx.Vm;
        if (vm is null || !vm.Valid || ctx.AllKlassObjects.Count == 0)
            return new List<(string, int)>();

        int offKlass = vm.OffAny("oopDesc", "_metadata._compressed_klass", "_metadata._klass");
        if (offKlass < 0) offKlass = 8;
        bool compressed = vm.Field("oopDesc", "_metadata._compressed_klass") is not null;
        ulong narrowBase = 0;
        int narrowShift = 0;
        if (compressed)
        {
            ulong bv = vm.StaticAddrAny(("CompressedKlassPointers", "_narrow_klass._base"),
                ("Universe", "_narrow_klass._base"));
            ulong sv = vm.StaticAddrAny(("CompressedKlassPointers", "_narrow_klass._shift"),
                ("Universe", "_narrow_klass._shift"));
            if (bv != 0) narrowBase = ctx.Target.ReadU64(bv);
            if (sv != 0) narrowShift = (int)ctx.Target.ReadU32(sv);
        }

        var cache = new PageCache(ctx.Target, 8192);
        var reg = ctx.RegionAt(tagMap);
        if (reg is null) return new List<(string, int)>();

        var queue = new Queue<ulong>();
        var visited = new HashSet<ulong>();
        queue.Enqueue(tagMap);
        int budget = 4096;

        while (queue.Count > 0 && budget-- > 0)
        {
            ulong at = queue.Dequeue();
            if (!visited.Add(at)) continue;
            var blk = cache.Read(at, 0x80);
            if (blk is null) continue;

            for (int i = 0; i + 8 <= blk.Length; i += 8)
            {
                ulong v = BitConverter.ToUInt64(blk, i);
                if (v is < 0x10000 or > 0x7FFFFFFFFFFF) continue;

                ulong k;
                if (compressed)
                {
                    uint narrow = cache.U32(v + (ulong)offKlass);
                    if (narrow == 0) k = 0;
                    else k = narrowBase + ((ulong)narrow << narrowShift);
                }
                else k = cache.U64(v + (ulong)offKlass);

                if (k != 0 && ctx.AllKlassObjects.TryGetValue(k, out var name) &&
                    name.Length > 0)
                {
                    res[name] = res.GetValueOrDefault(name) + 1;
                    continue;
                }

                var vr = ctx.RegionAt(v);
                if (vr is not null && vr.IsCommitted && vr.IsPrivate && !vr.IsExecutable &&
                    visited.Count < 2048)
                    queue.Enqueue(v);
            }
        }

        return res.OrderByDescending(x => x.Value).Select(x => (x.Key, x.Value)).ToList();
    }

    private static void Render(ScanContext ctx, Env e, StringBuilder sb)
    {
        sb.AppendLine(new string('=', 100));
        sb.AppendLine($"ОКРУЖЕНИЕ JVMTI 0x{e.Address:X}");
        sb.AppendLine($"  состояние (magic)        : {e.MagicName}");
        sb.AppendLine($"  версия JVMTI (_version)  : 0x{e.Version:X} " +
                      $"(JVMTI {(e.Version >> 16) & 0xFF}.{(e.Version >> 8) & 0xFF}." +
                      $"{e.Version & 0xFF})");
        sb.AppendLine($"  таблица функций          : 0x{e.Functions:X} → {ctx.Describe(e.Functions)}");
        sb.AppendLine($"  _next                    : 0x{e.Next:X}");
        sb.AppendLine($"  _is_retransformable      : {(e.Retransformable ? "ДА (значение по умолчанию, см. пояснение находки)" : "нет — значит, AddCapabilities вызывался")}");
        sb.AppendLine($"  _env_local_storage       : 0x{e.LocalStorage:X}" +
                      (e.LocalStorage != 0 ? $" → {ctx.Describe(e.LocalStorage)}" : ""));
        sb.AppendLine($"  раскладка объекта        : " +
                      (e.CallbacksOff < 0
                          ? "НЕ ОПОЗНАНА (таблица колбэков не нашлась)"
                          : $"колбэки +0x{e.CallbacksOff:X}, теги +0x{e.TagMapOff:X}, " +
                            $"маски +0x{e.EnableOff:X}, возможности +0x{e.CapsOff:X}" +
                            (e.TagMap != 0 ? " — подтверждена обратным указателем таблицы тегов" : "")));
        sb.AppendLine();

        if (e.Caps.Count > 0)
        {
            sb.AppendLine("  ЗАПРОШЕННЫЕ ВОЗМОЖНОСТИ (jvmtiCapabilities):");
            foreach (var c in e.Caps) sb.AppendLine("      " + c);
            sb.AppendLine();
        }
        if (e.Prohibited.Count > 0)
        {
            sb.AppendLine("  ЗАПРЕЩЁННЫЕ ВОЗМОЖНОСТИ (_prohibited_capabilities):");
            foreach (var c in e.Prohibited) sb.AppendLine("      " + c);
            sb.AppendLine();
        }

        if (e.Callbacks.Count > 0)
        {
            sb.AppendLine("  ТАБЛИЦА КОЛБЭКОВ СОБЫТИЙ (позиция = событие):");
            foreach (var (ev, target) in e.Callbacks)
            {
                var im = ctx.ImageAt(target);
                string where = im is null
                    ? "МОДУЛЯ НЕТ — библиотека агента выгружена"
                    : im.Ldr is null ? $"{im.Name} (модуль скрыт от загрузчика)" : im.Name;
                sb.AppendLine($"      {ev,-26} → 0x{target:X}  [{where}]  {ctx.Describe(target)}");
            }
            sb.AppendLine();
        }

        if (e.Enable.Length == 3)
        {
            sb.AppendLine("  МАСКИ ВКЛЮЧЕНИЯ СОБЫТИЙ:");
            sb.AppendLine($"      _event_user_enabled     = 0x{e.Enable[0]:X16}  {Bits(e.Enable[0])}");
            sb.AppendLine($"      _event_callback_enabled = 0x{e.Enable[1]:X16}  {Bits(e.Enable[1])}");
            sb.AppendLine($"      _event_enabled          = 0x{e.Enable[2]:X16}  {Bits(e.Enable[2])}");
            sb.AppendLine();
        }

        if (e.Prefixes.Count > 0)
        {
            sb.AppendLine("  ПРЕФИКСЫ НАТИВНЫХ МЕТОДОВ (SetNativeMethodPrefix):");
            foreach (var p in e.Prefixes) sb.AppendLine($"      «{p}»");
            sb.AppendLine();
        }

        if (e.Agent is not null)
        {
            sb.AppendLine("  ЗАПИСЬ ОБ АГЕНТЕ, НА КОТОРУЮ ССЫЛАЕТСЯ ОКРУЖЕНИЕ:");
            sb.AppendLine($"      адрес   : 0x{e.Agent.Address:X}");
            sb.AppendLine($"      имя     : {e.Agent.Name}");
            sb.AppendLine($"      опции   : {e.Agent.Options ?? "-"}");
            sb.AppendLine($"      путь    : {e.Agent.OsLibPath ?? "-"}");
            sb.AppendLine($"      способ  : {e.Agent.HowLoaded}");
            sb.AppendLine();
        }

        if (e.LocalStorage != 0)
        {
            var blk = ctx.Target.ReadBytes(e.LocalStorage, 256);
            if (blk is not null)
            {
                sb.AppendLine("  СОБСТВЕННЫЕ ДАННЫЕ АГЕНТА (_env_local_storage):");
                sb.AppendLine(HexDump.Format(blk, e.LocalStorage));
                var strings = StringExtract.Ascii(blk, 4);
                if (strings.Count > 0)
                    sb.AppendLine("      строки: " + string.Join(" | ", strings.Take(12)));
                sb.AppendLine();
            }
        }

        sb.AppendLine("  ОБЪЕКТ ОКРУЖЕНИЯ ЦЕЛИКОМ:");
        sb.AppendLine(HexDump.Format(e.Dump, e.Address));
        sb.AppendLine();
    }

    private static string Bits(ulong v)
    {
        if (v == 0) return "(нет включённых событий)";
        var names = new List<string>();
        for (int i = 0; i < EventNames.Length; i++)
            if ((v & (1UL << i)) != 0) names.Add(EventNames[i]);
        return names.Count == 0 ? "(биты вне известного диапазона)" : string.Join(",", names);
    }

    private static bool LooksInternal(ScanContext ctx, Env e)
    {
        if (e.Callbacks.Count == 0) return false;
        foreach (var (_, target) in e.Callbacks)
        {
            var im = ctx.ImageAt(target);
            if (im is null || !im.Name.Equals("jvm.dll", StringComparison.OrdinalIgnoreCase))
                return false;
        }
        return true;
    }

    private static void ReportEnv(ScanContext ctx, Env e)
    {
        bool internalEnv = LooksInternal(ctx, e);
        var f = ctx.Report.Report("JVM",
            $"Восстановление агента по окружению JVMTI 0x{e.Address:X}: {e.MagicName}, " +
            $"возможностей {e.Caps.Count}, подписок {e.Callbacks.Count}" +
            (e.Prefixes.Count > 0 ? $", префиксов нативных методов {e.Prefixes.Count}" : "") +
            (e.Agent is not null ? $", агент «{e.Agent.Name}»" : "") +
            (internalEnv ? " — ПОХОЖЕ НА ВНУТРЕННЕЕ ОКРУЖЕНИЕ САМОЙ ВМ" : ""),
            internalEnv ? Severity.High : Severity.Critical,
            (internalEnv
                ? "ВАЖНО О ТРАКТОВКЕ: все обработчики событий этого окружения ведут внутрь " +
                  "самой jvm.dll. Так выглядит не посторонний агент, а внутренний механизм " +
                  "виртуальной машины — HotSpot заводит собственное окружение JVMTI для " +
                  "Flight Recorder и инструментирует им классы событий. У чужого агента " +
                  "обработчики лежат в ЕГО библиотеке либо там, где модуля уже нет. " +
                  "Проверьте список обработчиков ниже. "
                : "") +
            "Объект окружения — это всё, что виртуальная машина знает об агенте, и он " +
            "переживает и Agent_OnUnload, и DisposeEnvironment: HotSpot лишь меняет в нём " +
            "магическое число. Раскладка объекта здесь не постулирована, а проверена: " +
            "таблица колбэков опознана по тому, что все её 37 слотов либо нулевые, либо " +
            "ведут в исполняемую память, а найденное смещение подтверждено обратным " +
            "указателем из таблицы тегов на это же окружение. Ниже — всё, что удалось " +
            "восстановить об агенте: какие возможности он запросил, на какие события " +
            "подписался, куда вели его функции-обработчики, какие строки он задавал сам.");

        f.Add("адрес окружения", e.Address);
        f.Add("состояние", e.MagicName);
        f.Add("версия JVMTI", $"0x{e.Version:X}");
        f.Add("таблица функций", $"0x{e.Functions:X} → {ctx.Describe(e.Functions)}");
        f.Add("раскладка подтверждена", e.LayoutConfirmed ? "да" : "частично");
        f.Add("_is_retransformable", JvmtiEnvLayout.DescribeRetransformable(e.Retransformable));

        if (e.Callbacks.Count > 0)
        {
            var byModule = e.Callbacks
                .GroupBy(x => ctx.ImageAt(x.Target)?.Name ?? "<МОДУЛЯ НЕТ>")
                .ToList();
            f.Add("обработчики событий ведут в",
                string.Join(", ", byModule.Select(g => $"{g.Key} ×{g.Count()}")));

            var body = new StringBuilder();
            foreach (var (ev, target) in e.Callbacks)
            {
                var im = ctx.ImageAt(target);
                body.AppendLine($"  {(im is null ? "!!" : "  ")} {ev,-26} → 0x{target:X}  " +
                                (im is null
                                    ? "модуля по этому адресу НЕТ"
                                    : $"{im.Name}+0x{target - im.Base:X}" +
                                      (im.Ldr is null ? " (модуль скрыт от загрузчика)" : "")));
                var code = ctx.Target.ReadBytes(target, 16);
                if (code is not null)
                    body.AppendLine("            байты: " +
                                    string.Join(" ", code.Select(x => x.ToString("X2"))));
            }
            f.Block("Обработчики событий агента", body.ToString().TrimEnd());

            int orphan = e.Callbacks.Count(x => ctx.ImageAt(x.Target) is null);
            if (orphan > 0)
                ctx.Report.Report("JVM",
                        $"У окружения JVMTI 0x{e.Address:X} {orphan} обработчиков событий " +
                        "ведут туда, где нет ни одного модуля",
                        Severity.Critical,
                        "Адреса функций агента остались записанными в таблице колбэков, а " +
                        "модуля по этим адресам больше нет. Это прямое доказательство того, " +
                        "что библиотека агента работала и была выгружена: пока она была " +
                        "загружена, адреса вели в неё. Сама запись их не переживает только " +
                        "в одном случае — если агент аккуратно обнулил таблицу перед " +
                        "уходом, а он этого не сделал.")
                    .Add("окружение", e.Address)
                    .Add("осиротевших обработчиков", orphan.ToString())
                    .Block("Обработчики", string.Join("\n", e.Callbacks
                        .Where(x => ctx.ImageAt(x.Target) is null)
                        .Select(x => $"  {x.Event,-26} → 0x{x.Target:X} " +
                                     $"({ctx.RegionAt(x.Target)?.ToString() ?? "не отображено"})")));
        }

        if (e.Caps.Count > 0)
            f.Block("Запрошенные возможности", string.Join("\n", e.Caps.Select(x => "  " + x)));
        if (e.Prohibited.Count > 0)
            f.Block("Запрещённые возможности", string.Join("\n", e.Prohibited.Select(x => "  " + x)));

        if (e.Prefixes.Count > 0)
        {
            ctx.Report.Report("JVM",
                    $"Агент задавал префиксы нативных методов: " +
                    string.Join(", ", e.Prefixes.Select(x => $"«{x}»")),
                    Severity.Critical,
                    "Функция JVMTI SetNativeMethodPrefix позволяет агенту переименовать " +
                    "нативный метод так, чтобы его вызов сначала попадал в обёртку агента. " +
                    "Строка префикса — это ЛИТЕРАЛ, который написал автор агента: он " +
                    "хранится в окружении как есть. Ни виртуальная машина, ни игра эту " +
                    "функцию не вызывают: она существует исключительно для агентов " +
                    "инструментирования.")
                .Add("окружение", e.Address)
                .Block("Префиксы", string.Join("\n", e.Prefixes.Select(x => $"  «{x}»")));
        }

        if (e.Agent is not null)
        {
            f.Add("запись об агенте", $"0x{e.Agent.Address:X}, имя «{e.Agent.Name}», " +
                                      $"{e.Agent.HowLoaded}");
            if (e.Agent.Options is not null) f.Add("опции агента", e.Agent.Options);
            if (e.Agent.OsLibPath is not null) f.Add("путь к библиотеке агента", e.Agent.OsLibPath);
        }

        if (e.LocalStorage != 0)
        {
            var blk = ctx.Target.ReadBytes(e.LocalStorage, 512);
            var strings = blk is null ? new List<string>() : StringExtract.Ascii(blk, 4);
            ctx.Report.Report("JVM",
                    $"Окружение JVMTI 0x{e.Address:X} хранит указатель на собственные " +
                    $"данные агента (_env_local_storage = 0x{e.LocalStorage:X})",
                    Severity.Critical,
                    "Это поле заполняет только сам агент вызовом SetEnvironmentLocalStorage: " +
                    "он кладёт туда указатель на свою структуру состояния, чтобы находить " +
                    "её в обработчиках событий. Ни виртуальная машина, ни игра это поле не " +
                    "трогают. По содержимому структуры часто видно и назначение агента: " +
                    "там лежат его настройки, дескрипторы и строки.")
                .Add("окружение", e.Address)
                .Add("адрес данных", e.LocalStorage)
                .Add("где лежат данные", ctx.RegionAt(e.LocalStorage)?.ToString() ?? "не отображено")
                .Block("Содержимое", blk is null ? "не читается"
                    : HexDump.Format(blk, e.LocalStorage))
                .Block("Строки внутри", strings.Count == 0 ? "нет"
                    : string.Join("\n", strings.Take(40).Select(x => "  " + x)));
        }

        if (e.TagMap != 0)
        {
            var tagged = TaggedClasses(ctx, e.TagMap);
            var tf = ctx.Report.Report("JVM",
                $"У окружения JVMTI 0x{e.Address:X} создана таблица тегов объектов" +
                (tagged.Count > 0
                    ? $"; помеченные объекты принадлежат {tagged.Count} классам"
                    : ""),
                Severity.Critical,
                "JvmtiTagMap создаётся при первом же вызове SetTag, GetObjectsWithTags или " +
                "IterateOverHeap. Это означает, что агент помечал объекты в куче Java и " +
                "перебирал их — так чит находит объекты игрока, мира и сущностей, чтобы " +
                "обращаться к ним напрямую. Классы помеченных объектов восстановлены по " +
                "самопроверяемому признаку: значение из таблицы считается объектом Java " +
                "только если указатель на его класс совпадает с реальным объектом Klass " +
                "в метапространстве.");
            tf.Add("окружение", e.Address);
            tf.Add("JvmtiTagMap", e.TagMap);
            foreach (var (klass, n) in tagged.Take(40))
                tf.Add(klass, $"{n} помеченных объектов");
            var tm = ctx.Target.ReadBytes(e.TagMap, 256);
            if (tm is not null) tf.Block("Таблица тегов", HexDump.Format(tm, e.TagMap));
        }

        f.Block("Объект окружения (0x400 байт)", HexDump.Format(e.Dump, e.Address));

        if (ctx.Dumper is not null)
        {
            ulong from = e.Address > 0x2000 ? e.Address - 0x2000 : e.Address;
            string? p = ctx.Dumper.DumpRange(from, 0x8000, "jvmtienv-prov",
                "объект окружения JVMTI и его окрестность для восстановления агента",
                $"сам объект по 0x{e.Address:X}");
            if (p is not null) f.Add("дамп окрестности", p);
        }
    }
}
