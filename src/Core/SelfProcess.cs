namespace AgentScan.Core;

internal static class SelfProcess
{
    public static bool HasDebugPrivilege { get; set; }

    private static ProcessTarget? _self;
    private static bool _tried;

    public static ProcessTarget? Target
    {
        get
        {
            if (_tried) return _self;
            _tried = true;
            try { _self = ProcessTarget.Open(Environment.ProcessId); }
            catch { _self = null; }
            return _self;
        }
    }

    private static Dictionary<string, (ulong Base, uint Size)>? _modules;

    public static Dictionary<string, (ulong Base, uint Size)> Modules
    {
        get
        {
            if (_modules is not null) return _modules;
            _modules = new Dictionary<string, (ulong, uint)>(StringComparer.OrdinalIgnoreCase);
            var t = Target;
            if (t is null) return _modules;
            try
            {
                foreach (var m in LoaderModules.Enumerate(t).Modules)
                {
                    if (m.BaseDllName.Length == 0 || m.DllBase == 0) continue;
                    _modules[m.BaseDllName] = (m.DllBase, m.SizeOfImage);
                }
            }
            catch { }
            return _modules;
        }
    }

    public static ulong BaseOf(string moduleName) =>
        Modules.TryGetValue(moduleName, out var v) ? v.Base : 0;

    public static byte[]? Read(ulong address, int length) => Target?.ReadBytes(address, length);

    public static ulong ReadU64(ulong address) => Target?.ReadU64(address) ?? 0;
}
