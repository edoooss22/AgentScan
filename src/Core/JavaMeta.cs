using System.Text;
using AgentScan.Analysis;

namespace AgentScan.Core;

internal sealed class JavaFieldInfo
{
    public string Name = "";
    public string Signature = "";
    public int Offset;
    public uint AccessFlags;
    public bool Injected;

    public int InitialValueIndex = -1;

    public bool IsStatic => (AccessFlags & 0x0008) != 0;
    public bool IsFinal => (AccessFlags & 0x0010) != 0;

    public override string ToString() =>
        $"{(IsStatic ? "static " : "")}{Signature} {Name} @ +{Offset}";
}

internal sealed class JavaMeta
{
    public readonly ScanContext Sc;
    public readonly VmStructs Vm;
    public readonly PageCache Cache;

    public List<string> Diagnostics { get; } = new();

    public bool FieldsAvailable { get; private set; }

    public bool CompressedKlass, CompressedOops;
    public ulong NarrowKlassBase, NarrowOopBase;
    public int NarrowKlassShift, NarrowOopShift;

    private readonly int _offKlassName, _offKlassSuper, _offKlassLayout;
    private readonly int _offIkConstants, _offIkMethods, _offFieldStream, _offFieldsLegacy;
    private readonly int _offIkFieldCount;
    private readonly int _offMethodConstMethod, _offCmConstants, _offCmName, _offCmSig;
    private readonly int _offSymLen, _offSymBody;
    private readonly ulong _cpSize;
    private readonly ulong _methodVtable;

    private readonly int _ffInitialized, _ffInjected, _ffGeneric, _ffContended;

    private readonly Dictionary<ulong, string?> _symbols = new();
    private readonly Dictionary<ulong, JavaFieldInfo[]> _fields = new();
    private readonly Dictionary<(ulong, string), int> _fieldOffsets = new();
    private readonly Dictionary<string, ulong> _byName = new(StringComparer.Ordinal);

    public readonly Dictionary<ulong, string> Klasses = new();

    private int _strValue = -1, _strCoder = -1;

    private JavaMeta(ScanContext sc, VmStructs vm)
    {
        Sc = sc;
        Vm = vm;
        Cache = new PageCache(sc.Target, 65536);

        _offKlassName = vm.Off("Klass", "_name");
        _offKlassSuper = vm.Off("Klass", "_super");
        _offKlassLayout = vm.Off("Klass", "_layout_helper");
        _offIkConstants = vm.Off("InstanceKlass", "_constants");
        _offIkMethods = vm.Off("InstanceKlass", "_methods");
        _offFieldStream = vm.Off("InstanceKlass", "_fieldinfo_stream");
        _offFieldsLegacy = vm.Off("InstanceKlass", "_fields");
        _offIkFieldCount = vm.Off("InstanceKlass", "_java_fields_count");
        _offMethodConstMethod = vm.Off("Method", "_constMethod");
        _offCmConstants = vm.Off("ConstMethod", "_constants");
        _offCmName = vm.Off("ConstMethod", "_name_index");
        _offCmSig = vm.Off("ConstMethod", "_signature_index");

        int sl = vm.Off("Symbol", "_length");
        _offSymLen = sl >= 0 ? sl : 4;
        int sb = vm.OffAny("Symbol", "_body[0]", "_body");
        _offSymBody = sb >= 0 ? sb : 6;

        _cpSize = vm.TypeSize("ConstantPool");
        _methodVtable = vm.Vtable("Method");

        _ffInitialized = (int)vm.IntConst("FieldInfo::FieldFlags::_ff_initialized", 0);
        _ffInjected = (int)vm.IntConst("FieldInfo::FieldFlags::_ff_injected", 1);
        _ffGeneric = (int)vm.IntConst("FieldInfo::FieldFlags::_ff_generic", 2);
        _ffContended = (int)vm.IntConst("FieldInfo::FieldFlags::_ff_contended", 4);
    }

    public static JavaMeta? Create(ScanContext sc)
    {
        var vm = sc.Vm;
        if (vm is null || !vm.Valid) return null;

        var m = new JavaMeta(sc, vm);
        m.LoadPointerCompression();
        m.LoadKlasses();
        m.Calibrate();
        return m;
    }

    private void LoadPointerCompression()
    {
        var c = Cache;
        ulong nkBase = Vm.StaticAddrAny(("CompressedKlassPointers", "_narrow_klass._base"),
            ("Universe", "_narrow_klass._base"));
        ulong nkShift = Vm.StaticAddrAny(("CompressedKlassPointers", "_narrow_klass._shift"),
            ("Universe", "_narrow_klass._shift"));
        CompressedKlass = Vm.Field("oopDesc", "_metadata._compressed_klass") is not null;
        if (nkBase != 0) NarrowKlassBase = c.U64(nkBase);
        if (nkShift != 0) NarrowKlassShift = (int)c.U32(nkShift);

        ulong noBase = Vm.StaticAddr("CompressedOops", "_narrow_oop._base");
        ulong noShift = Vm.StaticAddr("CompressedOops", "_narrow_oop._shift");
        CompressedOops = noBase != 0 || noShift != 0;
        if (noBase != 0) NarrowOopBase = c.U64(noBase);
        if (noShift != 0) NarrowOopShift = (int)c.U32(noShift);
    }

    private void LoadKlasses()
    {
        foreach (var kv in Sc.AllKlassObjects) Klasses[kv.Key] = kv.Value;
        foreach (var kv in Sc.LiveKlasses) Klasses[kv.Key] = kv.Value;
        foreach (var kv in Klasses) _byName.TryAdd(kv.Value, kv.Key);
    }

    private void Calibrate()
    {
        if (_offFieldStream < 0 && _offFieldsLegacy < 0)
        {
            Diagnostics.Add("в таблицах ВМ нет ни InstanceKlass::_fieldinfo_stream, " +
                            "ни InstanceKlass::_fields — раскладка полей недоступна");
            return;
        }

        ulong strKlass = KlassByName("java/lang/String");
        if (strKlass == 0)
        {
            Diagnostics.Add("класс java/lang/String не найден среди объектов Klass — " +
                            "калибровать карту полей не на чем");
            return;
        }

        var fs = DeclaredFields(strKlass);
        foreach (var f in fs)
        {
            if (f.IsStatic) continue;
            if (f.Name == "value" && f.Signature == "[B") _strValue = f.Offset;
            else if (f.Name == "coder" && f.Signature == "B") _strCoder = f.Offset;
        }

        if (_strValue < 0)
        {
            Diagnostics.Add($"у java/lang/String не найдено поле value типа [B: разбор дал " +
                            $"{fs.Length} полей ({string.Join(", ", fs.Take(8).Select(x => x.Name))}) " +
                            "— карта полей объявлена недоступной");
            return;
        }

        Diagnostics.Add($"карта полей проверена на java/lang/String: value +{_strValue}, " +
                        $"coder +{_strCoder}; источник — " +
                        (_offFieldStream >= 0 ? "FieldInfoStream (JDK 21+)" : "массив _fields"));
        FieldsAvailable = true;
    }

    public string? Symbol(ulong sym)
    {
        if (sym is < 0x10000 or > 0x7FFFFFFFFFFF) return null;
        if (_symbols.TryGetValue(sym, out var cached)) return cached;
        if (_symbols.Count > 1 << 20) _symbols.Clear();

        string? res = null;
        Span<byte> head = stackalloc byte[8];
        if (Cache.Read(sym, head))
        {
            int len = BitConverter.ToUInt16(head[_offSymLen..]);
            if (len is >= 1 and <= 4096)
            {
                var body = new byte[len];
                if (Cache.Read(sym + (ulong)_offSymBody, body))
                    res = JavaNames.DecodeModifiedUtf8(body);
            }
        }
        _symbols[sym] = res;
        return res;
    }

    public string? KlassName(ulong klass)
    {
        if (klass == 0) return null;
        if (Klasses.TryGetValue(klass, out var n)) return n;
        if (_offKlassName < 0) return null;
        return Symbol(Cache.U64(klass + (ulong)_offKlassName));
    }

    public ulong KlassByName(string name) =>
        _byName.TryGetValue(name, out ulong k) ? k : 0;

    public IEnumerable<(ulong Klass, string Name)> KlassesWhere(Func<string, bool> pred)
    {
        foreach (var kv in Klasses)
            if (pred(kv.Value)) yield return (kv.Key, kv.Value);
    }

    public ulong SuperKlass(ulong klass) =>
        _offKlassSuper < 0 ? 0 : Cache.U64(klass + (ulong)_offKlassSuper);

    public IEnumerable<ulong> KlassChain(ulong klass)
    {
        var seen = new HashSet<ulong>();
        ulong k = klass;
        while (k is >= 0x10000 and <= 0x7FFFFFFFFFFF && seen.Add(k))
        {
            yield return k;
            k = SuperKlass(k);
        }
    }

    public bool IsSubclassOf(ulong klass, string ancestorName)
    {
        foreach (ulong k in KlassChain(klass))
            if (KlassName(k) == ancestorName) return true;
        return false;
    }

    public bool Implements(ulong klass, string ifaceName)
    {
        int off = Vm.OffAnyOf(("InstanceKlass", "_transitive_interfaces"));
        if (off < 0) return false;

        foreach (ulong k in KlassChain(klass))
        {
            ulong arr = Cache.U64(k + (ulong)off);
            if (arr is < 0x10000 or > 0x7FFFFFFFFFFF) continue;
            int len = (int)Cache.U32(arr);
            if (len is <= 0 or > 4096) continue;
            for (int i = 0; i < len; i++)
            {
                ulong iface = Cache.U64(arr + 8 + (ulong)i * 8);
                if (iface is < 0x10000 or > 0x7FFFFFFFFFFF) continue;
                if (KlassName(iface) == ifaceName) return true;
            }
        }
        return false;
    }

    public bool IsAssignableTo(ulong klass, string typeName)
    {
        var key = (klass, " assignable " + typeName);
        if (_fieldOffsets.TryGetValue(key, out int cached)) return cached != 0;
        bool res = IsSubclassOf(klass, typeName) || Implements(klass, typeName);
        _fieldOffsets[key] = res ? 1 : 0;
        return res;
    }

    public ulong ConstantPoolOf(ulong klass) =>
        _offIkConstants < 0 ? 0 : Cache.U64(klass + (ulong)_offIkConstants);

    public string? CpUtf8(ulong cp, int index)
    {
        if (cp is < 0x10000 or > 0x7FFFFFFFFFFF) return null;
        if (index is <= 0 or > 200_000) return null;
        if (_cpSize is < 0x20 or > 0x200) return null;
        return Symbol(Cache.U64(cp + _cpSize + (ulong)index * 8));
    }

    public ulong CpSlot(ulong cp, int index)
    {
        if (cp is < 0x10000 or > 0x7FFFFFFFFFFF) return 0;
        if (index is <= 0 or > 200_000) return 0;
        if (_cpSize is < 0x20 or > 0x200) return 0;
        return cp + _cpSize + (ulong)index * 8;
    }

    public bool CpNumber(ulong cp, int index, string signature, out double value, out string text)
    {
        value = 0; text = "";
        ulong slot = CpSlot(cp, index);
        if (slot == 0) return false;
        ulong raw = Cache.U64(slot);
        switch (signature)
        {
            case "I": value = (int)(uint)raw; text = ((int)(uint)raw).ToString(); return true;
            case "S": value = (short)(uint)raw; text = ((short)(uint)raw).ToString(); return true;
            case "B": value = (sbyte)(uint)raw; text = ((sbyte)(uint)raw).ToString(); return true;
            case "C": value = (ushort)(uint)raw; text = ((ushort)(uint)raw).ToString(); return true;
            case "Z": value = (uint)raw & 1; text = (((uint)raw & 0xFF) != 0).ToString(); return true;
            case "J": value = (long)raw; text = ((long)raw).ToString(); return true;
            case "F":
                value = BitConverter.Int32BitsToSingle((int)(uint)raw);
                text = ((float)value).ToString("R"); return true;
            case "D":
                value = BitConverter.Int64BitsToDouble((long)raw);
                text = value.ToString("R"); return true;
            default: return false;
        }
    }

    public bool IsMethodObject(ulong addr) =>
        _methodVtable != 0 && addr is >= 0x10000 and <= 0x7FFFFFFFFFFF &&
        Cache.U64(addr) == _methodVtable;

    public (string Name, string Signature) MethodNameSig(ulong method)
    {
        if (_offMethodConstMethod < 0 || _offCmConstants < 0 || _offCmName < 0) return ("", "");
        ulong cm = Cache.U64(method + (ulong)_offMethodConstMethod);
        if (cm is < 0x10000 or > 0x7FFFFFFFFFFF) return ("", "");
        ulong cp = Cache.U64(cm + (ulong)_offCmConstants);
        if (cp is < 0x10000 or > 0x7FFFFFFFFFFF) return ("", "");
        int ni = (int)(Cache.U32(cm + (ulong)_offCmName) & 0xFFFF);
        int si = _offCmSig < 0 ? 0 : (int)(Cache.U32(cm + (ulong)_offCmSig) & 0xFFFF);
        return (CpUtf8(cp, ni) ?? "", si > 0 ? CpUtf8(cp, si) ?? "" : "");
    }

    public ulong MethodHolder(ulong method)
    {
        if (_offMethodConstMethod < 0 || _offCmConstants < 0) return 0;
        ulong cm = Cache.U64(method + (ulong)_offMethodConstMethod);
        if (cm is < 0x10000 or > 0x7FFFFFFFFFFF) return 0;
        ulong cp = Cache.U64(cm + (ulong)_offCmConstants);
        if (cp is < 0x10000 or > 0x7FFFFFFFFFFF) return 0;
        int offHolder = Vm.OffAny("ConstantPool", "_pool_holder");
        if (offHolder < 0) return 0;
        return Cache.U64(cp + (ulong)offHolder);
    }

    public string DescribeMethod(ulong method)
    {
        var (name, sig) = MethodNameSig(method);
        ulong holder = MethodHolder(method);
        string cls = KlassName(holder) ?? (holder != 0 ? $"0x{holder:X}" : "?");
        return name.Length == 0 ? $"{cls}.?" : $"{cls}.{name}{sig}";
    }

    public IEnumerable<ulong> MethodsOf(ulong klass)
    {
        if (_offIkMethods < 0) yield break;
        ulong arr = Cache.U64(klass + (ulong)_offIkMethods);
        if (arr is < 0x10000 or > 0x7FFFFFFFFFFF) yield break;
        int len = (int)Cache.U32(arr);
        if (len is <= 0 or > 100_000) yield break;
        for (int i = 0; i < len; i++)
        {
            ulong m = Cache.U64(arr + 8 + (ulong)i * 8);
            if (m is >= 0x10000 and <= 0x7FFFFFFFFFFF) yield return m;
        }
    }

    public JavaFieldInfo[] DeclaredFields(ulong klass)
    {
        if (klass is < 0x10000 or > 0x7FFFFFFFFFFF) return Array.Empty<JavaFieldInfo>();
        if (_fields.TryGetValue(klass, out var cached)) return cached;

        JavaFieldInfo[] res;
        try
        {
            res = _offFieldStream >= 0 ? ParseFieldStream(klass) : ParseFieldsLegacy(klass);
        }
        catch { res = Array.Empty<JavaFieldInfo>(); }

        if (_fields.Count > 200_000) _fields.Clear();
        _fields[klass] = res;
        return res;
    }

    public int FieldOffset(ulong klass, string name)
    {
        if (klass == 0) return -1;
        var key = (klass, name);
        if (_fieldOffsets.TryGetValue(key, out int cached)) return cached;

        int res = -1;
        foreach (ulong k in KlassChain(klass))
        {
            foreach (var f in DeclaredFields(k))
            {
                if (f.IsStatic || f.Name != name) continue;
                res = f.Offset;
                break;
            }
            if (res >= 0) break;
        }
        _fieldOffsets[key] = res;
        return res;
    }

    public int FieldOffsetAny(ulong klass, params string[] names)
    {
        foreach (string n in names)
        {
            int o = FieldOffset(klass, n);
            if (o >= 0) return o;
        }
        return -1;
    }

    public int SoleFieldOfType(ulong klass, string signature)
    {
        int found = -1;
        foreach (ulong k in KlassChain(klass))
            foreach (var f in DeclaredFields(k))
            {
                if (f.IsStatic || f.Signature != signature) continue;
                if (found >= 0) return -1;
                found = f.Offset;
            }
        return found;
    }

    public List<JavaFieldInfo> AllInstanceFields(ulong klass)
    {
        var res = new List<JavaFieldInfo>();
        foreach (ulong k in KlassChain(klass))
            foreach (var f in DeclaredFields(k))
                if (!f.IsStatic) res.Add(f);
        return res;
    }

    private JavaFieldInfo[] ParseFieldStream(ulong klass)
    {
        ulong arr = Cache.U64(klass + (ulong)_offFieldStream);
        if (arr is < 0x10000 or > 0x7FFFFFFFFFFF) return Array.Empty<JavaFieldInfo>();
        int len = (int)Cache.U32(arr);
        if (len is <= 0 or > 1 << 20) return Array.Empty<JavaFieldInfo>();

        var data = Cache.Read(arr + 4, len);
        if (data is null) return Array.Empty<JavaFieldInfo>();

        ulong cp = ConstantPoolOf(klass);
        int p = 0;
        uint javaFields = ReadU5(data, ref p);
        uint injectedFields = ReadU5(data, ref p);
        long total = (long)javaFields + injectedFields;
        if (total is <= 0 or > 20000) return Array.Empty<JavaFieldInfo>();

        var res = new List<JavaFieldInfo>((int)total);
        for (long i = 0; i < total && p < data.Length; i++)
        {
            uint nameIdx = ReadU5(data, ref p);
            uint sigIdx = ReadU5(data, ref p);
            uint offset = ReadU5(data, ref p);
            uint access = ReadU5(data, ref p);
            uint flags = ReadU5(data, ref p);
            int initIdx = -1;
            if ((flags & (1u << _ffInitialized)) != 0) initIdx = (int)ReadU5(data, ref p);
            if ((flags & (1u << _ffGeneric)) != 0) ReadU5(data, ref p);
            if ((flags & (1u << _ffContended)) != 0) ReadU5(data, ref p);

            bool injected = (flags & (1u << _ffInjected)) != 0;
            if (offset > 1 << 22) return Array.Empty<JavaFieldInfo>();

            res.Add(new JavaFieldInfo
            {
                Name = injected ? $"<внедрено ВМ:{nameIdx}>" : CpUtf8(cp, (int)nameIdx) ?? "",
                Signature = injected ? "" : CpUtf8(cp, (int)sigIdx) ?? "",
                Offset = (int)offset,
                AccessFlags = access,
                Injected = injected,
                InitialValueIndex = initIdx,
            });
        }
        return res.ToArray();
    }

    private JavaFieldInfo[] ParseFieldsLegacy(ulong klass)
    {
        if (_offFieldsLegacy < 0) return Array.Empty<JavaFieldInfo>();
        ulong arr = Cache.U64(klass + (ulong)_offFieldsLegacy);
        if (arr is < 0x10000 or > 0x7FFFFFFFFFFF) return Array.Empty<JavaFieldInfo>();
        int len = (int)Cache.U32(arr);
        if (len is <= 0 or > 6 * 20000) return Array.Empty<JavaFieldInfo>();

        var data = Cache.Read(arr + 4, len * 2);
        if (data is null) return Array.Empty<JavaFieldInfo>();

        ulong cp = ConstantPoolOf(klass);
        var res = new List<JavaFieldInfo>(len / 6);
        for (int i = 0; i * 12 + 12 <= data.Length; i++)
        {
            int b = i * 12;
            ushort access = BitConverter.ToUInt16(data, b);
            ushort nameIdx = BitConverter.ToUInt16(data, b + 2);
            ushort sigIdx = BitConverter.ToUInt16(data, b + 4);
            ushort initIdxOld = BitConverter.ToUInt16(data, b + 6);
            ushort lo = BitConverter.ToUInt16(data, b + 8);
            ushort hi = BitConverter.ToUInt16(data, b + 10);

            if ((lo & 3) != 1) continue;
            int offset = (int)((((uint)hi << 16) | lo) >> 2);
            if (offset > 1 << 22) continue;

            bool injected = (access & 0x0400) != 0;
            res.Add(new JavaFieldInfo
            {
                Name = injected ? $"<внедрено ВМ:{nameIdx}>" : CpUtf8(cp, nameIdx) ?? "",
                Signature = injected ? "" : CpUtf8(cp, sigIdx) ?? "",
                Offset = offset,
                AccessFlags = access,
                Injected = injected,
                InitialValueIndex = initIdxOld == 0 ? -1 : initIdxOld,
            });
        }
        return res.ToArray();
    }

    private static uint ReadU5(byte[] d, ref int p)
    {
        const uint X = 1, L = 191;
        const int LgH = 6;
        if (p >= d.Length) return 0;
        uint sum = (uint)d[p++] - X;
        if (sum < L) return sum;
        int lgHi = LgH;
        for (int i = 1; i < 5 && p < d.Length; i++)
        {
            uint b = (uint)d[p++] - X;
            sum += b << lgHi;
            if (b < L) break;
            lgHi += LgH;
        }
        return sum;
    }

    public ulong DecodeKlass(uint narrow) =>
        narrow == 0 ? 0 : NarrowKlassBase + ((ulong)narrow << NarrowKlassShift);

    public ulong DecodeOop(uint narrow) =>
        narrow == 0 ? 0 : NarrowOopBase + ((ulong)narrow << NarrowOopShift);

    public int HeaderSize => CompressedKlass ? 12 : 16;

    public ulong KlassOf(ulong obj)
    {
        if (obj is < 0x10000 or > 0x7FFFFFFFFFFF) return 0;
        return CompressedKlass ? DecodeKlass(Cache.U32(obj + 8)) : Cache.U64(obj + 8);
    }

    public string? ClassNameOf(ulong obj) => KlassName(KlassOf(obj));

    public ulong Oop(ulong obj, int offset)
    {
        if (offset < 0 || obj is < 0x10000 or > 0x7FFFFFFFFFFF) return 0;
        ulong a = obj + (ulong)offset;
        return CompressedOops ? DecodeOop(Cache.U32(a)) : Cache.U64(a);
    }

    public ulong OopField(ulong obj, string name)
    {
        int off = FieldOffset(KlassOf(obj), name);
        return off < 0 ? 0 : Oop(obj, off);
    }

    public int IntField(ulong obj, string name)
    {
        int off = FieldOffset(KlassOf(obj), name);
        return off < 0 ? 0 : (int)Cache.U32(obj + (ulong)off);
    }

    public long LongField(ulong obj, string name)
    {
        int off = FieldOffset(KlassOf(obj), name);
        return off < 0 ? 0 : (long)Cache.U64(obj + (ulong)off);
    }

    public int ArrayLength(ulong arr)
    {
        if (arr is < 0x10000 or > 0x7FFFFFFFFFFF) return -1;
        int len = (int)Cache.U32(arr + (ulong)HeaderSize);
        return len is < 0 or > 64 * 1024 * 1024 ? -1 : len;
    }

    public int ArrayBase(ulong klass)
    {
        if (_offKlassLayout < 0 || klass == 0) return -1;
        int lh = (int)Cache.U32(klass + (ulong)_offKlassLayout);
        if (lh >= 0) return -1;
        int hsize = (lh >> 16) & 0xFF;
        return hsize is < 12 or > 64 ? -1 : hsize;
    }

    public List<ulong> ObjArray(ulong arr, int max = 65536)
    {
        var res = new List<ulong>();
        int len = ArrayLength(arr);
        if (len <= 0) return res;
        int baseOff = ArrayBase(KlassOf(arr));
        if (baseOff < 0) baseOff = HeaderSize + 4;
        int step = CompressedOops ? 4 : 8;
        int n = Math.Min(len, max);
        var buf = Cache.Read(arr + (ulong)baseOff, n * step);
        if (buf is null) return res;
        for (int i = 0; i < n; i++)
            res.Add(CompressedOops
                ? DecodeOop(BitConverter.ToUInt32(buf, i * step))
                : BitConverter.ToUInt64(buf, i * step));
        return res;
    }

    public string? StringValue(ulong strObj)
    {
        if (!FieldsAvailable || _strValue < 0) return null;
        if (strObj is < 0x10000 or > 0x7FFFFFFFFFFF) return null;

        ulong val = Oop(strObj, _strValue);
        int len = ArrayLength(val);
        if (len is < 0 or > 1 << 20) return null;
        if (len == 0) return "";

        int baseOff = ArrayBase(KlassOf(val));
        if (baseOff < 0) baseOff = HeaderSize + 4;
        var buf = Cache.Read(val + (ulong)baseOff, len);
        if (buf is null) return null;

        byte coder = _strCoder >= 0 ? (byte)(Cache.U32(strObj + (ulong)_strCoder) & 0xFF) : (byte)0;
        return coder == 1 ? Encoding.Unicode.GetString(buf) : Encoding.Latin1.GetString(buf);
    }

    public string? StringField(ulong obj, string name)
    {
        ulong s = OopField(obj, name);
        return s == 0 ? null : StringValue(s);
    }

    public string Describe(ulong obj)
    {
        if (obj == 0) return "null";
        string cls = ClassNameOf(obj) ?? "?";
        if (cls == "java/lang/String")
        {
            string? s = StringValue(obj);
            if (s is not null) return $"\"{Clean(s, 120)}\"";
        }
        return $"{cls}@0x{obj:X}";
    }

    public static string Clean(string s, int max)
    {
        var sb = new StringBuilder(Math.Min(s.Length, max));
        foreach (char ch in s)
        {
            if (sb.Length >= max) { sb.Append('…'); break; }
            sb.Append(ch < 0x20 || ch == 0x7F ? '.' : ch);
        }
        return sb.ToString();
    }
}
