using System.Text;
using System.Text.Json;
using AgentScan.Report;

namespace AgentScan.Analysis;

internal enum SigScope
{
    Any,
    NonImage,
    PrivateOnly,
    PrivateExec,
}

internal sealed class Signature
{
    public required string Name { get; init; }
    public required string Category { get; init; }
    public required string Text { get; init; }
    public Severity Severity { get; init; } = Severity.Medium;
    public SigScope Scope { get; init; } = SigScope.Any;
    public bool Utf16 { get; init; } = true;

    public bool WholeWord { get; init; } = true;

    public string? Note { get; init; }
}

internal static class Signatures
{
    public static List<Signature> Default()
    {
        var s = new List<Signature>();

        void Inj(string name, string txt, Severity sev, SigScope scope, string note)
            => s.Add(new Signature
            {
                Name = name, Category = "Артефакт инжекта", Text = txt,
                Severity = sev, Scope = scope, Note = note
            });

        Inj("JVMTI Agent_OnAttach вне модулей", "Agent_OnAttach", Severity.High, SigScope.PrivateExec,
            "Строка точки входа JVMTI-агента в приватной исполняемой памяти. В jvm.dll " +
            "она есть всегда, а вот в чужой памяти — только у кода агента/инжектора.");
        Inj("JVMTI Agent_OnUnload вне модулей", "Agent_OnUnload", Severity.High, SigScope.PrivateExec,
            "Точка выгрузки JVMTI-агента вне загруженных модулей.");
        Inj("JPLISAgent", "JPLISAgent", Severity.High, SigScope.PrivateOnly,
            "Внутреннее имя агента java.lang.instrument (instrument.dll). " +
            "Появляется при загрузке -javaagent или динамическом attach.");
        Inj("attach pipe", @"\\.\pipe\javatool", Severity.Critical, SigScope.PrivateOnly,
            "Именованный канал механизма Dynamic Attach (VirtualMachine.attach). " +
            "Имя канала передаётся в ВМ, когда к ней подключаются агентом.");
        Inj("VirtualMachine.loadAgent", "loadAgentLibrary", Severity.High, SigScope.PrivateOnly,
            "Вызов подключения нативной библиотеки-агента к живой JVM.");
        Inj("JNI_GetCreatedJavaVMs", "JNI_GetCreatedJavaVMs", Severity.High, SigScope.PrivateExec,
            "Поиск указателя на JavaVM из нативного кода — типовой первый шаг " +
            "нативного чита, работающего через JNI.");
        Inj("AttachCurrentThread", "AttachCurrentThread", Severity.High, SigScope.PrivateExec,
            "Присоединение нативного потока к JVM из кода вне модулей.");

        void Jvmti(string txt, Severity sev = Severity.High)
            => s.Add(new Signature
            {
                Name = $"JVMTI: {txt}", Category = "Артефакт JVMTI-агента", Text = txt,
                Severity = sev, Scope = SigScope.PrivateExec,
                Note = "Имя функции JVMTI в приватной исполняемой памяти. Внутри jvm.dll " +
                       "такие строки есть всегда, а вот в чужой памяти они появляются " +
                       "только в коде агента, который эти функции вызывает."
            });

        Jvmti("RetransformClasses");
        Jvmti("RedefineClasses");
        Jvmti("GetLoadedClasses");
        Jvmti("SetJNIFunctionTable", Severity.Critical);
        Jvmti("SetEventNotificationMode");
        Jvmti("AddCapabilities");
        Jvmti("IterateOverInstancesOfClass");
        Jvmti("GetObjectsWithTags");
        Jvmti("FollowReferences");
        Jvmti("DisposeEnvironment");
        Jvmti("GetJNIFunctionTable", Severity.Critical);

        Inj("appendToSystemClassLoaderSearch", "appendToSystemClassLoaderSearch",
            Severity.Critical, SigScope.PrivateOnly,
            "Метод Instrumentation, добавляющий произвольный jar в поиск системного " +
            "загрузчика классов. Это стандартный способ подсунуть JVM код Java-чита " +
            "после запуска игры.");
        Inj("appendToBootstrapClassLoaderSearch", "appendToBootstrapClassLoaderSearch",
            Severity.Critical, SigScope.PrivateOnly, "");
        Inj("redefineModule", "redefineModule", Severity.Medium, SigScope.PrivateOnly, "");
        Inj("ByteBuddy", "net/bytebuddy/agent", Severity.High, SigScope.PrivateOnly,
            "Byte Buddy Agent — библиотека, которой пользуются для подключения " +
            "Java-агента к своей же JVM (self-attach). Клиент Minecraft её не содержит.");
        Inj("Javassist", "javassist/ClassPool", Severity.Medium, SigScope.PrivateOnly,
            "Библиотека генерации байт-кода в рантайме.");
        Inj("Unsafe.defineAnonymousClass", "defineAnonymousClass", Severity.Low,
            SigScope.PrivateOnly, "");

        const string InstrNote =
            "Строка относится к механизму java.lang.instrument. Одиночные вхождения " +
            "бывают и в чистой JVM (имена классов модуля java.instrument разбираются " +
            "при старте). Значение имеет количество вхождений и, главное, наличие " +
            "самого байт-кода этих классов — см. раздел остаточного состояния JVM.";

        Inj("sun.instrument.InstrumentationImpl", "sun/instrument/InstrumentationImpl",
            Severity.Low, SigScope.PrivateOnly, InstrNote);
        Inj("sun.instrument.InstrumentationImpl (точечная нотация)",
            "sun.instrument.InstrumentationImpl", Severity.Low, SigScope.PrivateOnly, InstrNote);
        Inj("TransformerManager", "TransformerManager", Severity.Low, SigScope.PrivateOnly,
            "Менеджер зарегистрированных ClassFileTransformer. " + InstrNote);
        Inj("premain агента", "loadClassAndCallPremain", Severity.High,
            SigScope.PrivateOnly,
            "Внутренняя функция instrument.dll, запускающая premain агента. В отличие от " +
            "имён классов, эта строка принадлежит нативной библиотеке instrument.dll, " +
            "которая грузится только вместе с агентом.");
        Inj("agentmain", "loadClassAndCallAgentmain", Severity.High, SigScope.PrivateOnly,
            "Внутренняя функция instrument.dll, запускающая agentmain динамически " +
            "подключённого агента.");
        Inj("addTransformer", "addTransformer", Severity.Low, SigScope.PrivateOnly,
            "Регистрация ClassFileTransformer — подмена байт-кода классов на лету. " + InstrNote);
        Inj("retransformClasses", "retransformClasses", Severity.Low, SigScope.PrivateOnly,
            "Повторная трансформация уже загруженных классов игры. " + InstrNote);
        Inj("ByteBuddy", "net/bytebuddy/", Severity.High, SigScope.PrivateOnly,
            "Byte Buddy — библиотека генерации байт-кода, часто применяемая Java-читами " +
            "для self-attach и подмены методов.");
        Inj("Javassist", "javassist/", Severity.Medium, SigScope.PrivateOnly, "");
        Inj("Mixin вне Fabric", "org/spongepowered/asm/mixin/transformer", Severity.Info,
            SigScope.PrivateOnly,
            "Mixin входит в состав Fabric и Forge — сам по себе уликой не является.");

        return s;
    }

    public static List<Signature> Load(string? extraPath)
    {
        var list = Default();
        string path = extraPath ?? Path.Combine(AppContext.BaseDirectory, "signatures.json");
        if (!File.Exists(path)) return list;
        try
        {
            var json = File.ReadAllText(path);
            var extra = JsonSerializer.Deserialize<List<Signature>>(json,
                new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true,
                    ReadCommentHandling = JsonCommentHandling.Skip,
                    AllowTrailingCommas = true,
                });
            if (extra is not null) list.AddRange(extra);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"signatures.json не загружен: {ex.Message}");
        }
        return list;
    }

    public static byte[] Ascii(string s) => Encoding.ASCII.GetBytes(s);
    public static byte[] Utf16(string s) => Encoding.Unicode.GetBytes(s);
}
