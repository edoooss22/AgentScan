namespace AgentScan.Analysis;

internal static class JvmtiEnvLayout
{
    public const uint JVMTI_MAGIC = 0x71EE;
    public const uint DISPOSED_MAGIC = 0xDEFC;
    public const uint BAD_MAGIC = 0xDEAD;

    public const int OffFunctions = 0x00;
    public const int OffMagic = 0x08;
    public const int OffVersion = 0x0C;
    public const int OffNext = 0x10;
    public const int OffRetransformable = 0x18;
    public const int OffLocalStorage = 0x20;

    public static readonly string[] EventNames =
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

    private static readonly int[] Candidates = { 0x28, 0x20, 0x30, 0x38 };

    internal sealed class Layout
    {
        public int Callbacks;
        public int ExtCallbacks;
        public int TagMap;
        public int EventEnable;
        public int Capabilities;
        public int Prohibited;

        public int NonNullCallbacks;

        public ulong[] Masks = new ulong[3];

        public bool AnyEventEnabled => Masks[0] != 0 || Masks[1] != 0 || Masks[2] != 0;
    }

    public static Layout? Probe(ScanContext ctx, byte[] dump)
    {
        Layout? fallback = null;

        foreach (int cb in Candidates)
        {
            int ext = cb + EventNames.Length * 8;
            int tag = ext + 8;
            int enable = tag + 8;
            int caps = enable + 24;
            int prohib = caps + 16;
            if (prohib + 16 > dump.Length) continue;

            int nonNull = 0;
            bool ok = true;
            for (int i = 0; i < EventNames.Length; i++)
            {
                ulong v = BitConverter.ToUInt64(dump, cb + i * 8);
                if (v == 0) continue;
                if (v is < 0x10000 or > 0x7FFFFFFFFFFF) { ok = false; break; }
                var r = ctx.RegionAt(v);
                if (r is null || !r.IsCommitted || !r.IsExecutable) { ok = false; break; }
                nonNull++;
            }
            if (!ok) continue;

            ulong tagMap = BitConverter.ToUInt64(dump, tag);
            if (tagMap != 0 && tagMap is < 0x10000 or > 0x7FFFFFFFFFFF) continue;

            if (BitConverter.ToUInt64(dump, caps + 8) != 0) continue;
            if (BitConverter.ToUInt64(dump, prohib + 8) != 0) continue;

            var layout = new Layout
            {
                Callbacks = cb,
                ExtCallbacks = ext,
                TagMap = tag,
                EventEnable = enable,
                Capabilities = caps,
                Prohibited = prohib,
                NonNullCallbacks = nonNull,
                Masks = new[]
                {
                    BitConverter.ToUInt64(dump, enable),
                    BitConverter.ToUInt64(dump, enable + 8),
                    BitConverter.ToUInt64(dump, enable + 16),
                },
            };

            if (nonNull > 0) return layout;
            fallback ??= layout;
        }

        return fallback;
    }

    public static List<(string Event, ulong Target)> Callbacks(byte[] dump, Layout layout)
    {
        var res = new List<(string, ulong)>();
        for (int i = 0; i < EventNames.Length; i++)
        {
            int off = layout.Callbacks + i * 8;
            if (off + 8 > dump.Length) break;
            ulong v = BitConverter.ToUInt64(dump, off);
            if (v != 0) res.Add((EventNames[i], v));
        }
        return res;
    }

    public static string DescribeRetransformable(bool value) => value
        ? "ДА, но это значение ПО УМОЛЧАНИЮ: конструктор JvmtiEnvBase взводит поле у " +
          "каждого окружения. Осмысленным оно становится только после AddCapabilities — " +
          "тогда в нём лежит запрошенное can_retransform_classes. Само по себе уликой не " +
          "является; смотреть надо на список возможностей."
        : "нет — и это уже содержательно: значение по умолчанию true, сбросить его может " +
          "только AddCapabilities. Значит, возможности запрашивались, и повторной " +
          "трансформации среди них не было.";
}
