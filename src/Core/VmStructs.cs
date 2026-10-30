using System.Text;

namespace AgentScan.Core;

internal sealed class VmField
{
    public string TypeName = "";
    public string FieldName = "";
    public string TypeString = "";
    public bool IsStatic;
    public ulong Offset;
    public ulong Address;

    public override string ToString() => IsStatic
        ? $"{TypeName}::{FieldName} [static {TypeString}] @ 0x{Address:X}"
        : $"{TypeName}::{FieldName} [{TypeString}] +0x{Offset:X}";
}

internal sealed class VmType
{
    public string TypeName = "";
    public string SuperclassName = "";
    public bool IsOopType, IsIntegerType, IsUnsigned;
    public ulong Size;

    public override string ToString() =>
        $"{TypeName,-44} size={Size,-6} super={(SuperclassName.Length > 0 ? SuperclassName : "-")}";
}

internal sealed class VmStructs
{
    public bool Valid;
    public string Source = "";
    public List<string> Diagnostics { get; } = new();

    public ulong StructsArray, TypesArray, IntConstArray, LongConstArray;

    public Dictionary<string, Dictionary<string, VmField>> Fields { get; } =
        new(StringComparer.Ordinal);

    public List<VmField> AllFields { get; } = new();
    public Dictionary<string, VmType> Types { get; } = new(StringComparer.Ordinal);
    public Dictionary<string, long> IntConstants { get; } = new(StringComparer.Ordinal);
    public Dictionary<string, ulong> LongConstants { get; } = new(StringComparer.Ordinal);

    public Dictionary<string, ulong> Vtables { get; } = new(StringComparer.Ordinal);

    public ulong Vtable(string cls) => Vtables.TryGetValue(cls, out ulong v) ? v : 0;

    public VmField? Field(string type, string field) =>
        Fields.TryGetValue(type, out var m) && m.TryGetValue(field, out var f) ? f : null;

    public int Off(string type, string field)
    {
        var f = Field(type, field);
        return f is null || f.IsStatic || f.Offset > 0x10000 ? -1 : (int)f.Offset;
    }

    public ulong StaticAddr(string type, string field)
    {
        var f = Field(type, field);
        return f is null || !f.IsStatic ? 0 : f.Address;
    }

    public ulong TypeSize(string type) =>
        Types.TryGetValue(type, out var t) ? t.Size : 0;

    public ulong StaticAddrAny(params (string Type, string Field)[] candidates)
    {
        foreach (var (t, f) in candidates)
        {
            ulong a = StaticAddr(t, f);
            if (a != 0) return a;
        }
        return 0;
    }

    public int OffAnyOf(params (string Type, string Field)[] candidates)
    {
        foreach (var (t, f) in candidates)
        {
            int o = Off(t, f);
            if (o >= 0) return o;
        }
        return -1;
    }

    public bool HasType(string type) => Types.ContainsKey(type);

    public string? FirstType(params string[] names) =>
        names.FirstOrDefault(Types.ContainsKey);

    public int OffAny(string type, params string[] names)
    {
        foreach (var n in names)
        {
            int o = Off(type, n);
            if (o >= 0) return o;
        }
        return -1;
    }

    public long IntConst(string name, long fallback)
    {
        if (IntConstants.TryGetValue(name, out long v)) return v;
        foreach (var kv in IntConstants)
            if (kv.Key.EndsWith("::" + name, StringComparison.Ordinal)) return kv.Value;
        return fallback;
    }

    public bool TryIntConst(string name, out long value)
    {
        if (IntConstants.TryGetValue(name, out value)) return true;
        foreach (var kv in IntConstants)
        {
            if (!kv.Key.EndsWith("::" + name, StringComparison.Ordinal)) continue;
            value = kv.Value;
            return true;
        }
        value = 0;
        return false;
    }

    private const int MaxEntries = 20000;

    public static VmStructs Load(ProcessTarget t, ulong jvmBase, PeInfo jvmPe)
    {
        var v = new VmStructs();
        try { v.Init(t, jvmBase, jvmPe); }
        catch (Exception ex) { v.Diagnostics.Add($"разбор VMStructs прерван: {ex.GetType().Name}: {ex.Message}"); }
        return v;
    }

    private void Init(ProcessTarget t, ulong jvmBase, PeInfo pe)
    {
        var cache = new PageCache(t, 32768);

        ulong ExportVar(string name)
        {
            var e = pe.Exports.ByName(name);
            return e is null ? 0 : jvmBase + e.Rva;
        }

        ulong pStructs = ExportVar("gHotSpotVMStructs");
        ulong pTypes = ExportVar("gHotSpotVMTypes");
        ulong pInt = ExportVar("gHotSpotVMIntConstants");
        ulong pLong = ExportVar("gHotSpotVMLongConstants");

        if (pStructs != 0)
        {
            Source = "экспорты jvm.dll";
            StructsArray = cache.U64(pStructs);
            TypesArray = pTypes == 0 ? 0 : cache.U64(pTypes);
            IntConstArray = pInt == 0 ? 0 : cache.U64(pInt);
            LongConstArray = pLong == 0 ? 0 : cache.U64(pLong);

            ulong U(string n) { ulong a = ExportVar(n); return a == 0 ? 0 : cache.U64(a); }

            var sl = new StructLayout
            {
                TypeName = (int)U("gHotSpotVMStructEntryTypeNameOffset"),
                FieldName = (int)U("gHotSpotVMStructEntryFieldNameOffset"),
                TypeString = (int)U("gHotSpotVMStructEntryTypeStringOffset"),
                IsStatic = (int)U("gHotSpotVMStructEntryIsStaticOffset"),
                Offset = (int)U("gHotSpotVMStructEntryOffsetOffset"),
                Address = (int)U("gHotSpotVMStructEntryAddressOffset"),
                Stride = (int)U("gHotSpotVMStructEntryArrayStride"),
            };
            if (sl.Stride is <= 0 or > 256) sl = StructLayout.Default;
            ParseStructs(cache, StructsArray, sl, jvmBase, pe);

            var tl = new TypeLayout
            {
                TypeName = (int)U("gHotSpotVMTypeEntryTypeNameOffset"),
                SuperName = (int)U("gHotSpotVMTypeEntrySuperclassNameOffset"),
                IsOop = (int)U("gHotSpotVMTypeEntryIsOopTypeOffset"),
                IsInt = (int)U("gHotSpotVMTypeEntryIsIntegerTypeOffset"),
                IsUnsigned = (int)U("gHotSpotVMTypeEntryIsUnsignedOffset"),
                Size = (int)U("gHotSpotVMTypeEntrySizeOffset"),
                Stride = (int)U("gHotSpotVMTypeEntryArrayStride"),
            };
            if (tl.Stride is <= 0 or > 256) tl = TypeLayout.Default;
            ParseTypes(cache, TypesArray, tl);

            int icName = (int)U("gHotSpotVMIntConstantEntryNameOffset");
            int icVal = (int)U("gHotSpotVMIntConstantEntryValueOffset");
            int icStride = (int)U("gHotSpotVMIntConstantEntryArrayStride");
            if (icStride is <= 0 or > 64) { icName = 0; icVal = 8; icStride = 16; }
            ParseIntConstants(cache, IntConstArray, icName, icVal, icStride);

            int lcName = (int)U("gHotSpotVMLongConstantEntryNameOffset");
            int lcVal = (int)U("gHotSpotVMLongConstantEntryValueOffset");
            int lcStride = (int)U("gHotSpotVMLongConstantEntryArrayStride");
            if (lcStride is <= 0 or > 64) { lcName = 0; lcVal = 8; lcStride = 16; }
            ParseLongConstants(cache, LongConstArray, lcName, lcVal, lcStride);
        }
        else
        {
            Diagnostics.Add("экспорт gHotSpotVMStructs не найден — таблица ищется " +
                            "по раскладке в данных jvm.dll");
            ulong found = FindStructsArray(t, jvmBase, pe);
            if (found != 0)
            {
                Source = "поиск по данным jvm.dll";
                StructsArray = found;
                ParseStructs(cache, found, StructLayout.Default, jvmBase, pe);
            }
        }

        CollectVtables(jvmBase, pe);

        Valid = AllFields.Count > 0;
        if (!Valid && Diagnostics.Count == 0)
            Diagnostics.Add("таблицы VMStructs не разобраны");
    }

    private void CollectVtables(ulong jvmBase, PeInfo pe)
    {
        foreach (var e in pe.Exports.Entries)
        {
            if (!e.Name.StartsWith("??_7", StringComparison.Ordinal)) continue;
            if (!e.Name.EndsWith("@@6B@", StringComparison.Ordinal)) continue;
            string mid = e.Name[4..^5];
            if (mid.Length is 0 or > 64) continue;
            if (mid.Contains('?') || mid.Contains('@') || mid.Contains('$')) continue;
            Vtables[mid] = jvmBase + e.Rva;
        }
        if (Vtables.Count == 0)
            Diagnostics.Add("экспортов таблиц виртуальных функций (??_7…@@6B@) не найдено — " +
                            "точное опознание объектов метапространства недоступно");
    }

    private sealed class StructLayout
    {
        public int TypeName, FieldName, TypeString, IsStatic, Offset, Address, Stride;
        public static StructLayout Default => new()
        {
            TypeName = 0, FieldName = 8, TypeString = 0x10, IsStatic = 0x18,
            Offset = 0x20, Address = 0x28, Stride = 0x30,
        };
    }

    private sealed class TypeLayout
    {
        public int TypeName, SuperName, IsOop, IsInt, IsUnsigned, Size, Stride;
        public static TypeLayout Default => new()
        {
            TypeName = 0, SuperName = 8, IsOop = 0x10, IsInt = 0x14, IsUnsigned = 0x18,
            Size = 0x20, Stride = 0x28,
        };
    }

    private void ParseStructs(PageCache cache, ulong array, StructLayout l, ulong jvmBase, PeInfo pe)
    {
        if (array is < 0x10000 or > 0x7FFFFFFFFFFF) return;
        for (int i = 0; i < MaxEntries; i++)
        {
            ulong e = array + (ulong)(i * l.Stride);
            ulong pType = cache.U64(e + (ulong)l.TypeName);
            if (pType == 0) break;
            ulong pField = cache.U64(e + (ulong)l.FieldName);
            if (pField == 0) break;

            string? type = ReadCString(cache, pType, 128);
            string? field = ReadCString(cache, pField, 128);
            if (type is null || field is null) break;

            var f = new VmField
            {
                TypeName = type,
                FieldName = field,
                TypeString = ReadCString(cache, cache.U64(e + (ulong)l.TypeString), 160) ?? "",
                IsStatic = cache.U32(e + (ulong)l.IsStatic) != 0,
            };
            if (f.IsStatic) f.Address = cache.U64(e + (ulong)l.Address);
            else f.Offset = cache.U64(e + (ulong)l.Offset);

            AllFields.Add(f);
            if (!Fields.TryGetValue(type, out var map))
                Fields[type] = map = new Dictionary<string, VmField>(StringComparer.Ordinal);
            map[field] = f;
        }
    }

    private void ParseTypes(PageCache cache, ulong array, TypeLayout l)
    {
        if (array is < 0x10000 or > 0x7FFFFFFFFFFF) return;
        for (int i = 0; i < MaxEntries; i++)
        {
            ulong e = array + (ulong)(i * l.Stride);
            ulong pType = cache.U64(e + (ulong)l.TypeName);
            if (pType == 0) break;
            string? name = ReadCString(cache, pType, 160);
            if (name is null) break;

            Types[name] = new VmType
            {
                TypeName = name,
                SuperclassName = ReadCString(cache, cache.U64(e + (ulong)l.SuperName), 160) ?? "",
                IsOopType = cache.U32(e + (ulong)l.IsOop) != 0,
                IsIntegerType = cache.U32(e + (ulong)l.IsInt) != 0,
                IsUnsigned = cache.U32(e + (ulong)l.IsUnsigned) != 0,
                Size = cache.U64(e + (ulong)l.Size),
            };
        }
    }

    private void ParseIntConstants(PageCache cache, ulong array, int nameOff, int valOff, int stride)
    {
        if (array is < 0x10000 or > 0x7FFFFFFFFFFF) return;
        for (int i = 0; i < MaxEntries; i++)
        {
            ulong e = array + (ulong)(i * stride);
            ulong p = cache.U64(e + (ulong)nameOff);
            if (p == 0) break;
            string? name = ReadCString(cache, p, 160);
            if (name is null) break;
            IntConstants[name] = (int)cache.U32(e + (ulong)valOff);
        }
    }

    private void ParseLongConstants(PageCache cache, ulong array, int nameOff, int valOff, int stride)
    {
        if (array is < 0x10000 or > 0x7FFFFFFFFFFF) return;
        for (int i = 0; i < MaxEntries; i++)
        {
            ulong e = array + (ulong)(i * stride);
            ulong p = cache.U64(e + (ulong)nameOff);
            if (p == 0) break;
            string? name = ReadCString(cache, p, 160);
            if (name is null) break;
            LongConstants[name] = cache.U64(e + (ulong)valOff);
        }
    }

    private static ulong FindStructsArray(ProcessTarget t, ulong jvmBase, PeInfo pe)
    {
        var cache = new PageCache(t, 32768);
        const int stride = 0x30;

        foreach (var sec in pe.Sections)
        {
            if (sec.IsExecutable || sec.VirtualSize is 0 or > 64 * 1024 * 1024) continue;
            if (sec.Name is not (".data" or ".rdata")) continue;

            var buf = new byte[sec.VirtualSize];
            ulong secVa = jvmBase + sec.VirtualAddress;
            t.ReadPartial(secVa, buf, out _);

            for (int i = 0; i + stride * 6 <= buf.Length; i += 8)
            {
                bool ok = true;
                for (int k = 0; k < 6 && ok; k++)
                {
                    int o = i + k * stride;
                    ulong a = BitConverter.ToUInt64(buf, o);
                    ulong b = BitConverter.ToUInt64(buf, o + 8);
                    uint st = BitConverter.ToUInt32(buf, o + 0x18);
                    ok = st <= 1 &&
                         a >= jvmBase && a < jvmBase + pe.SizeOfImage &&
                         b >= jvmBase && b < jvmBase + pe.SizeOfImage &&
                         ReadCString(cache, a, 128) is { Length: > 0 } &&
                         ReadCString(cache, b, 128) is { Length: > 0 };
                }
                if (ok) return secVa + (ulong)i;
            }
        }
        return 0;
    }

    private static string? ReadCString(PageCache cache, ulong addr, int max)
    {
        if (addr is < 0x10000 or > 0x7FFFFFFFFFFF) return null;
        var b = new byte[max];
        int n = 0;
        Span<byte> one = stackalloc byte[1];
        while (n < max)
        {
            if (!cache.Read(addr + (ulong)n, one)) return n == 0 ? null : null;
            if (one[0] == 0) break;
            if (one[0] < 0x20 || one[0] > 0x7E) return null;
            b[n++] = one[0];
        }
        if (n is 0 or >= 160) return null;
        return Encoding.ASCII.GetString(b, 0, n);
    }

    public string Render(int maxFieldLines = 6000)
    {
        var sb = new StringBuilder();
        sb.AppendLine("Живой Serviceability Agent: раскладка структур HotSpot прочитана");
        sb.AppendLine("из самой виртуальной машины, без отладочных символов и без");
        sb.AppendLine("прикрепления к процессу.");
        sb.AppendLine();
        sb.AppendLine($"Источник        : {(Source.Length > 0 ? Source : "не найден")}");
        sb.AppendLine($"gHotSpotVMStructs      → 0x{StructsArray:X}  записей: {AllFields.Count}");
        sb.AppendLine($"gHotSpotVMTypes        → 0x{TypesArray:X}  типов: {Types.Count}");
        sb.AppendLine($"gHotSpotVMIntConstants → 0x{IntConstArray:X}  констант: {IntConstants.Count}");
        sb.AppendLine($"gHotSpotVMLongConstants→ 0x{LongConstArray:X}  констант: {LongConstants.Count}");
        sb.AppendLine($"Таблиц виртуальных функций из экспортов: {Vtables.Count}");
        foreach (var d in Diagnostics) sb.AppendLine("  ! " + d);
        sb.AppendLine();

        if (Vtables.Count > 0)
        {
            sb.AppendLine("ОПОРНЫЕ ТАБЛИЦЫ ВИРТУАЛЬНЫХ ФУНКЦИЙ (по ним опознаются объекты):");
            foreach (var n in new[]
                     {
                         "Klass", "InstanceKlass", "InstanceMirrorKlass", "InstanceRefKlass",
                         "InstanceClassLoaderKlass", "ObjArrayKlass", "TypeArrayKlass",
                         "Method", "ConstantPool", "CodeBlob", "RuntimeBlob", "BufferBlob",
                         "AdapterBlob", "MethodHandlesAdapterBlob", "CompiledMethod", "nmethod",
                         "JvmtiAgentThread", "JvmtiBreakpoint", "JvmtiEventCollector",
                         "JvmtiVMObjectAllocEventCollector", "JvmtiDynamicCodeEventCollector",
                     })
                if (Vtables.TryGetValue(n, out ulong a))
                    sb.AppendLine($"  {n,-38} 0x{a:X}");
            sb.AppendLine();
        }

        if (Types.Count > 0)
        {
            sb.AppendLine("ТИПЫ (имя, размер, предок):");
            foreach (var t in Types.Values.OrderBy(x => x.TypeName, StringComparer.Ordinal))
                sb.AppendLine("  " + t);
            sb.AppendLine();
        }

        if (AllFields.Count > 0)
        {
            sb.AppendLine("ПОЛЯ (тип::поле, смещение либо адрес статической переменной):");
            int n = 0;
            foreach (var g in Fields.OrderBy(x => x.Key, StringComparer.Ordinal))
            {
                sb.AppendLine($"  {g.Key}  (размер типа: " +
                              (TypeSize(g.Key) > 0 ? TypeSize(g.Key).ToString() : "?") + ")");
                foreach (var f in g.Value.Values.OrderBy(x => x.IsStatic ? ulong.MaxValue : x.Offset))
                {
                    sb.AppendLine(f.IsStatic
                        ? $"      static  0x{f.Address:X16}  {f.FieldName,-40} {f.TypeString}"
                        : $"      +0x{f.Offset:X4}              {f.FieldName,-40} {f.TypeString}");
                    if (++n > maxFieldLines) break;
                }
                if (n > maxFieldLines) { sb.AppendLine("      ... (список усечён)"); break; }
            }
            sb.AppendLine();
        }

        if (IntConstants.Count > 0)
        {
            sb.AppendLine("ЦЕЛЫЕ КОНСТАНТЫ:");
            foreach (var kv in IntConstants.OrderBy(x => x.Key, StringComparer.Ordinal))
                sb.AppendLine($"  {kv.Key,-64} = {kv.Value} (0x{kv.Value:X})");
            sb.AppendLine();
        }

        if (LongConstants.Count > 0)
        {
            sb.AppendLine("64-БИТНЫЕ КОНСТАНТЫ:");
            foreach (var kv in LongConstants.OrderBy(x => x.Key, StringComparer.Ordinal))
                sb.AppendLine($"  {kv.Key,-64} = {kv.Value} (0x{kv.Value:X})");
        }
        return sb.ToString();
    }
}
