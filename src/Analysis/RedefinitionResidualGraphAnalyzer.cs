using System.Text;
using AgentScan.Core;
using AgentScan.Report;

namespace AgentScan.Analysis;

internal static class RedefinitionResidualGraphAnalyzer
{
    private sealed class Ev
    {
        public string Ring = "";
        public double Ts;
        public ulong Thread;
        public string Text = "";
        public string? ClassName;
    }

    private sealed class Episode
    {
        public Ev Redefine = null!;
        public List<Ev> Nearby = new();
        public List<(ulong Method, uint Flags, string Klass)> OldMethods = new();
        public List<CodeBlobInfo> DeadBlobs = new();
    }

    private const double WindowSeconds = 2.0;

    public static void Run(ScanContext ctx)
    {
        var sb = new StringBuilder();
        Preamble(sb);

        var vm = ctx.Vm;
        var events = ctx.VmEvents
            .Select(e => new Ev
            {
                Ring = e.Ring, Ts = e.Seconds, Thread = e.Thread, Text = e.Text,
                ClassName = ExtractClassName(e.Text),
            })
            .OrderBy(e => e.Ts)
            .ToList();

        var oldMethods = CollectOldMethods(ctx);
        var invalid = ctx.CodeBlobs.Where(b => b.IsNmethod && b.State != 0).ToList();
        var deadMethodBlobs = CollectDeadMethodBlobs(ctx);

        RenderSources(ctx, events, oldMethods, invalid, deadMethodBlobs, sb);

        var episodes = BuildEpisodes(ctx, events, oldMethods, deadMethodBlobs);
        RenderEpisodes(ctx, episodes, sb);

        var bands = InvalidationBands(ctx, sb);

        ReportDisagreement(ctx, events, oldMethods, deadMethodBlobs, sb);
        ReportMirrorCounters(ctx, events, sb);
        ReportEpisodes(ctx, episodes);
        bool redefinitionSeen = events.Any(e => e.Ring == "redefine") ||
                                oldMethods.Count > 0 || ctx.RedefinedClassMirrors.Count > 0;
        ReportBands(ctx, bands, redefinitionSeen);
        ReportDeoptStorm(ctx, events, sb);
        ReportOrphanDeoptState(ctx, invalid, sb);

        ctx.Report.Section("ПОСЛЕДСТВИЯ ПЕРЕОПРЕДЕЛЕНИЯ КЛАССОВ: СВЕДЕНИЕ ИСТОЧНИКОВ",
            sb.ToString());
    }

    private static void Preamble(StringBuilder sb)
    {
        sb.AppendLine("ГРАФ ПОСЛЕДСТВИЙ ПЕРЕОПРЕДЕЛЕНИЯ КЛАССОВ И ДЕОПТИМИЗАЦИИ");
        sb.AppendLine();
        sb.AppendLine("Переопределяя класс, виртуальная машина оставляет четыре следа в");
        sb.AppendLine("четырёх разных местах, и ведут их разные подсистемы:");
        sb.AppendLine();
        sb.AppendLine("    1) текстовая запись в кольцевом журнале «Classes redefined»;");
        sb.AppendLine("    2) флаги IS_OLD / IS_OBSOLETE у объектов Method старой версии;");
        sb.AppendLine("    3) перевод всех nmethod класса в состояние «недействителен»;");
        sb.AppendLine("    4) зависимости evol_method в скомпилированном коде.");
        sb.AppendLine();
        sb.AppendLine("Чтобы спрятать переопределение, вычистить надо все четыре и согласованно.");
        sb.AppendLine("Поэтому здесь ищутся не следы, а РАССОГЛАСОВАНИЕ между ними: место, где");
        sb.AppendLine("один источник говорит о событии, а другой о нём молчит.");
        sb.AppendLine();
    }

    private static List<(ulong Method, uint Flags, string Klass)> CollectOldMethods(
        ScanContext ctx)
    {
        var res = new List<(ulong, uint, string)>();
        var vm = ctx.Vm;
        if (vm is null || !vm.Valid || ctx.LiveKlasses.Count == 0) return res;

        int offMethods = vm.Off("InstanceKlass", "_methods");
        int offAcc = vm.Off("Method", "_access_flags");
        if (offMethods < 0 || offAcc < 0) return res;

        var c = new PageCache(ctx.Target);
        foreach (var kv in ctx.LiveKlasses)
        {
            ulong arr = c.U64(kv.Key + (ulong)offMethods);
            if (arr is < 0x10000 or > 0x7FFFFFFFFFFF) continue;
            int len = (int)c.U32(arr);
            if (len is <= 0 or > 100_000) continue;

            for (int i = 0; i < len; i++)
            {
                ulong m = c.U64(arr + 8 + (ulong)i * 8);
                if (m is < 0x10000 or > 0x7FFFFFFFFFFF) continue;
                uint acc = c.U32(m + (ulong)offAcc);
                if ((acc & 0x00070000) == 0) continue;
                res.Add((m, acc, kv.Value));
                if (res.Count > 20000) return res;
            }
        }
        return res;
    }

    private static List<CodeBlobInfo> CollectDeadMethodBlobs(ScanContext ctx)
    {
        if (ctx.LiveMethods.Count == 0) return new List<CodeBlobInfo>();
        var dead = ctx.CodeBlobs
            .Where(b => b.IsNmethod && b.Method != 0 && !ctx.LiveMethods.Contains(b.Method))
            .ToList();
        if (dead.Count == 0 || ctx.Vm is not { Valid: true } vm) return dead;

        var holders = SaLiveAnalyzer.ResolveMethodHolders(new PageCache(ctx.Target), vm,
            dead.Select(b => b.Method).Distinct());
        return dead
            .Where(b => !holders.TryGetValue(b.Method, out var h) ||
                        !SaLiveAnalyzer.IsRuntimeMethodHolder(h))
            .ToList();
    }

    private static void RenderSources(ScanContext ctx, List<Ev> events,
        List<(ulong Method, uint Flags, string Klass)> oldMethods,
        List<CodeBlobInfo> invalid, List<CodeBlobInfo> deadBlobs, StringBuilder sb)
    {
        int redef = events.Count(e => e.Ring == "redefine");
        int deopt = events.Count(e => e.Ring == "deopt");
        int flush = events.Count(e => e.Ring == "nmethodflushes");
        int unload = events.Count(e => e.Ring == "unload");

        sb.AppendLine("ЧТО ГОВОРИТ КАЖДЫЙ ИСТОЧНИК");
        sb.AppendLine($"  журнал переопределений (redefine)   : {redef} записей" +
                      RingNote(ctx, "redefine"));
        sb.AppendLine($"  журнал деоптимизаций (deopt)        : {deopt} записей" +
                      RingNote(ctx, "deopt"));
        sb.AppendLine($"  журнал выброса методов (nmethodflushes): {flush} записей" +
                      RingNote(ctx, "nmethodflushes"));
        sb.AppendLine($"  журнал выгрузки классов (unload)    : {unload} записей" +
                      RingNote(ctx, "unload"));
        sb.AppendLine($"  методов с флагами переопределения   : {oldMethods.Count}");
        sb.AppendLine($"  недействительных nmethod в кеше     : {invalid.Count} " +
                      $"из {ctx.CodeBlobs.Count(b => b.IsNmethod)}");
        sb.AppendLine($"  nmethod с недостижимым Method       : {deadBlobs.Count}");
        sb.AppendLine($"  счётчик подмен в зеркале класса > 0 : {ctx.RedefinedClassMirrors.Count} классов" +
                      (ctx.RedefinedClassMirrors.Count > 0
                          ? $", всего подмен {ctx.RedefinedClassMirrors.Sum(x => (long)x.Count)}"
                          : ""));
        sb.AppendLine();

        if (oldMethods.Count > 0)
        {
            sb.AppendLine("  Классы, у которых есть методы с флагами переопределения:");
            foreach (var g in oldMethods.GroupBy(x => x.Klass)
                                        .OrderByDescending(g => g.Count()).Take(40))
                sb.AppendLine($"      {g.Count(),5}  {g.Key}");
            sb.AppendLine();
        }
    }

    private static void ReportMirrorCounters(ScanContext ctx, List<Ev> events, StringBuilder sb)
    {
        var counters = ctx.RedefinedClassMirrors;
        if (counters.Count == 0) return;

        var logged = events.Where(e => e.Ring == "redefine" && e.ClassName is not null)
            .Select(e => e.ClassName!.Replace('.', '/'))
            .ToHashSet(StringComparer.Ordinal);
        var lost = counters.Where(c => !logged.Contains(c.Name.Replace('.', '/'))).ToList();

        sb.AppendLine("СЧЁТЧИКИ ПОДМЕН В ЗЕРКАЛАХ КЛАССОВ ПРОТИВ ЖУРНАЛА");
        sb.AppendLine($"  классов со счётчиком > 0     : {counters.Count}");
        sb.AppendLine($"  из них есть в журнале        : {counters.Count - lost.Count}");
        sb.AppendLine($"  журнал ПОТЕРЯЛ               : {lost.Count}");
        foreach (var c in counters.OrderByDescending(x => x.Count))
            sb.AppendLine($"      {c.Count,4} ×  {c.Name}" +
                          (logged.Contains(c.Name.Replace('.', '/')) ? "" : "   [в журнале нет]"));
        sb.AppendLine();

        long total = counters.Sum(x => (long)x.Count);
        var f = ctx.Report.Report("JVM",
            $"Зеркала {counters.Count} классов хранят счётчик подмен через JVMTI: всего " +
            $"{total} подмен" + (lost.Count > 0 ? $", из них {lost.Count} классов журнал ВМ уже потерял" : ""),
            Severity.Critical,
            "Поле classRedefinedCount объекта java.lang.Class виртуальная машина " +
            "увеличивает при каждом RedefineClasses и не сбрасывает никогда. В отличие " +
            "от кольцевого журнала на двадцать записей это точный учёт по каждому " +
            "классу за всю жизнь процесса. Подмена класса на ходу возможна только через " +
            "агента JVMTI; штатный клиент не подменяет ни одного класса, и на чистой " +
            "цели счётчик равен нулю у всех.");
        foreach (var c in counters.OrderByDescending(x => x.Count).Take(40))
            f.Add(c.Name, $"подмен {c.Count}" +
                          (logged.Contains(c.Name.Replace('.', '/')) ? "" : " — в журнале нет"));
    }

    private static string RingNote(ScanContext ctx, string handle)
    {
        if (!ctx.VmEventRings.TryGetValue(handle, out var r)) return "  [журнал не найден]";
        return r.Count >= r.Length
            ? $"  [кольцо заполнено целиком: {r.Count}/{r.Length}, старые записи вытеснены]"
            : $"  [кольцо {r.Count}/{r.Length}, вытеснения не было]";
    }

    private static List<Episode> BuildEpisodes(ScanContext ctx, List<Ev> events,
        List<(ulong Method, uint Flags, string Klass)> oldMethods,
        List<CodeBlobInfo> deadBlobs)
    {
        var res = new List<Episode>();
        foreach (var r in events.Where(e => e.Ring == "redefine"))
        {
            var ep = new Episode { Redefine = r };
            foreach (var e in events)
            {
                if (ReferenceEquals(e, r)) continue;
                if (Math.Abs(e.Ts - r.Ts) > WindowSeconds) continue;
                ep.Nearby.Add(e);
            }
            if (r.ClassName is not null)
            {
                string norm = r.ClassName.Replace('.', '/');
                ep.OldMethods = oldMethods
                    .Where(m => m.Klass.Replace('.', '/')
                        .Equals(norm, StringComparison.OrdinalIgnoreCase))
                    .ToList();
            }
            res.Add(ep);
        }
        return res;
    }

    private static void RenderEpisodes(ScanContext ctx, List<Episode> episodes, StringBuilder sb)
    {
        sb.AppendLine("ЭПИЗОДЫ ПЕРЕОПРЕДЕЛЕНИЯ (событие и всё, что случилось рядом по времени)");
        if (episodes.Count == 0)
        {
            sb.AppendLine("  Записей о переопределении классов в журнале нет.");
            sb.AppendLine();
            return;
        }

        DateTime start = ctx.Target.StartTimeUtc;
        foreach (var ep in episodes)
        {
            string wall = start == default ? ""
                : "  (" + start.AddSeconds(ep.Redefine.Ts).ToString("HH:mm:ss.fff") + " UTC)";
            sb.AppendLine($"=== +{ep.Redefine.Ts:F3} с{wall}  поток 0x{ep.Redefine.Thread:X}");
            sb.AppendLine($"    {ep.Redefine.Text}");
            sb.AppendLine($"    методов этого класса с флагами переопределения: " +
                          $"{ep.OldMethods.Count}");
            if (ep.Nearby.Count > 0)
            {
                sb.AppendLine($"    рядом по времени (±{WindowSeconds:F0} с): {ep.Nearby.Count} событий");
                foreach (var e in ep.Nearby.OrderBy(x => x.Ts).Take(20))
                    sb.AppendLine($"        +{e.Ts:F3} с  [{e.Ring}]  {Cut(e.Text, 96)}");
                if (ep.Nearby.Count > 20)
                    sb.AppendLine($"        ... ещё {ep.Nearby.Count - 20}");
            }
            else
            {
                sb.AppendLine("    рядом по времени НИЧЕГО не произошло — ни деоптимизаций,");
                sb.AppendLine("    ни выброса скомпилированных методов, ни загрузки классов.");
            }
            sb.AppendLine();
        }
    }

    private sealed class Band
    {
        public int From, To, Count;
        public List<CodeBlobInfo> Blobs = new();
    }

    private static List<Band> InvalidationBands(ScanContext ctx, StringBuilder sb)
    {
        sb.AppendLine("ПОЛОСЫ ИНВАЛИДАЦИИ В НУМЕРАЦИИ КОМПИЛЯТОРА");

        var nm = ctx.CodeBlobs.Where(b => b.IsNmethod).ToList();
        if (nm.Count == 0)
        {
            sb.AppendLine("  Разметка кодового кеша не получена — проверка не применима.");
            sb.AppendLine();
            return new List<Band>();
        }

        var ordered = nm.OrderBy(b => b.Lo).ToList();
        var bands = new List<Band>();
        int i = 0;
        while (i < ordered.Count)
        {
            if (ordered[i].State == 0) { i++; continue; }
            int j = i;
            while (j + 1 < ordered.Count && ordered[j + 1].State != 0) j++;
            int count = j - i + 1;
            if (count >= 4)
            {
                var b = new Band { From = i, To = j, Count = count };
                b.Blobs.AddRange(ordered.Skip(i).Take(count));
                bands.Add(b);
            }
            i = j + 1;
        }

        int invalid = nm.Count(b => b.State != 0);
        sb.AppendLine($"  скомпилированных методов в кеше: {nm.Count}, из них " +
                      $"недействительных: {invalid}");
        sb.AppendLine($"  сплошных полос (4 и более подряд): {bands.Count}");
        foreach (var b in bands.OrderByDescending(x => x.Count).Take(20))
            sb.AppendLine($"      {b.Count,5} подряд, адреса 0x{b.Blobs[0].Lo:X}…" +
                          $"0x{b.Blobs[^1].Hi:X}");
        sb.AppendLine();
        return bands;
    }

    private static void ReportDisagreement(ScanContext ctx, List<Ev> events,
        List<(ulong Method, uint Flags, string Klass)> oldMethods,
        List<CodeBlobInfo> deadBlobs, StringBuilder sb)
    {
        int redef = events.Count(e => e.Ring == "redefine");
        bool ringFound = ctx.VmEventRings.ContainsKey("redefine");
        bool ringFull = ringFound && ctx.VmEventRings["redefine"].Count >=
                        ctx.VmEventRings["redefine"].Length;

        sb.AppendLine("СВЕДЕНИЕ ИСТОЧНИКОВ");

        if (oldMethods.Count > 0 && redef == 0)
        {
            sb.AppendLine("  РАССОГЛАСОВАНИЕ: методы с флагами переопределения есть, а записей");
            sb.AppendLine("  в журнале переопределений нет.");
            ctx.Report.Report("JVM",
                    $"Методы с флагами переопределения есть ({oldMethods.Count} штук), а " +
                    "журнал переопределений пуст",
                    ringFound && !ringFull ? Severity.Critical : Severity.High,
                    "Флаги IS_OLD и IS_OBSOLETE выставляет ТОЛЬКО переопределение класса " +
                    "(RedefineClasses / RetransformClasses), и та же операция обязана " +
                    "оставить текстовую запись в кольцевом журнале «Classes redefined». " +
                    "Записи нет, а флаги есть — значит, эти две записи об одном событии " +
                    "разошлись. Кольцо переопределений в спокойной игре не переполняется: " +
                    "переопределять классы игре незачем, и записи в нём не вытесняются. " +
                    (ringFound && !ringFull
                        ? "Кольцо найдено и заполнено НЕ ЦЕЛИКОМ — значит, вытеснения не " +
                          "было и запись пропала не сама: журнал затёрли."
                        : "Кольцо либо не найдено, либо заполнено целиком, поэтому " +
                          "естественное вытеснение исключить нельзя — но проверить это " +
                          "стоит вручную по остальным журналам."))
                .Add("методов с флагами", oldMethods.Count.ToString())
                .Add("классов затронуто", oldMethods.Select(m => m.Klass).Distinct().Count()
                    .ToString())
                .Add("состояние кольца", RingNote(ctx, "redefine").Trim())
                .Add("классы", string.Join(", ",
                    oldMethods.Select(m => m.Klass).Distinct().Take(12)));
        }

        if (redef > 0 && oldMethods.Count == 0)
        {
            sb.AppendLine("  РАССОГЛАСОВАНИЕ: журнал говорит о переопределении, а ни одного");
            sb.AppendLine("  метода с флагами не осталось.");
            ctx.Report.Report("JVM",
                    $"Журнал сообщает о {redef} переопределениях классов, но ни одного " +
                    "метода с флагами переопределения в метапространстве нет",
                    Severity.High,
                    "Переопределение класса оставляет старую версию его методов в " +
                    "метапространстве с флагами IS_OLD и IS_OBSOLETE — они нужны самой " +
                    "виртуальной машине, чтобы доработали кадры стека, начатые на старом " +
                    "коде. Полное отсутствие таких методов при непустом журнале означает, " +
                    "что старые версии уже собраны, — либо что флаги сняли. Первое " +
                    "возможно и естественно; второе — нет. Различить их помогают " +
                    "остальные источники: если в кеше при этом висят nmethod с " +
                    "недостижимыми Method, старые версии действительно были.")
                .Add("записей о переопределении", redef.ToString())
                .Add("nmethod с недостижимым Method", deadBlobs.Count.ToString())
                .Add("классы из журнала", string.Join(", ", events
                    .Where(e => e.Ring == "redefine" && e.ClassName is not null)
                    .Select(e => e.ClassName!).Distinct().Take(12)));
        }

        int flush = events.Count(e => e.Ring == "nmethodflushes");
        if (deadBlobs.Count > 0 && flush == 0 && redef == 0)
        {
            sb.AppendLine("  РАССОГЛАСОВАНИЕ: в кеше есть код методов, которых больше нет,");
            sb.AppendLine("  а журналы об этом молчат.");
            var f = ctx.Report.Report("JVM",
                $"В кодовом кеше {deadBlobs.Count} скомпилированных методов ссылаются на " +
                "недостижимые объекты Method, при пустых журналах переопределения и " +
                "выброса методов",
                Severity.High,
                "Скомпилированный код переживает свой метод в двух случаях: класс " +
                "выгрузили или класс переопределили. И то и другое виртуальная машина " +
                "записывает в свои журналы. Код есть, а записей нет — значит, третий " +
                "источник (кодовый кеш) помнит событие, о котором два других молчат. " +
                "Такое рассогласование само по себе требует ручного разбора: по этим " +
                "nmethod видно, код каких именно методов игры был заменён.");
            foreach (var b in deadBlobs.Take(30))
                f.Add($"nmethod 0x{b.Address:X}",
                    $"Method 0x{b.Method:X} недостижим, состояние {StateName(b.State)}, " +
                    $"имя блока «{b.Name}»");
        }

        if (redef == 0 && oldMethods.Count == 0 && deadBlobs.Count == 0)
            sb.AppendLine("  Все источники согласны между собой: следов переопределения нет.");
        sb.AppendLine();
    }

    private static void ReportEpisodes(ScanContext ctx, List<Episode> episodes)
    {
        if (episodes.Count == 0) return;

        DateTime start = ctx.Target.StartTimeUtc;
        var f = ctx.Report.Report("JVM",
            $"В журнале виртуальной машины {episodes.Count} эпизодов переопределения классов",
            Severity.Critical,
            "Переопределение класса на ходу (RedefineClasses / RetransformClasses) — это " +
            "возможность, доступная только агенту JVMTI. Игра своих классов не " +
            "переопределяет: ей незачем, весь её код загружается из архивов один раз. " +
            "Каждая такая запись сделана самой виртуальной машиной, содержит имя класса " +
            "и время, и означает, что чей-то агент подменил код игры прямо в работающем " +
            "процессе. Ниже к каждому эпизоду приложено всё, что произошло рядом по " +
            "времени: по этому окружению видно, что именно машина делала следом — " +
            "выбрасывала скомпилированный код, деоптимизировала методы, грузила новые " +
            "классы.");
        foreach (var ep in episodes.Take(30))
        {
            string wall = start == default ? ""
                : ", " + start.AddSeconds(ep.Redefine.Ts).ToString("HH:mm:ss.fff") + " UTC";
            f.Add($"+{ep.Redefine.Ts:F3} с{wall}",
                $"{ep.Redefine.Text} — методов с флагами: {ep.OldMethods.Count}, " +
                $"событий рядом: {ep.Nearby.Count}");
        }

        var body = new StringBuilder();
        foreach (var ep in episodes.Take(12))
        {
            body.AppendLine($"+{ep.Redefine.Ts:F3} с  {ep.Redefine.Text}");
            foreach (var e in ep.Nearby.OrderBy(x => x.Ts).Take(24))
                body.AppendLine($"    +{e.Ts:F3} с  [{e.Ring}]  {Cut(e.Text, 110)}");
            body.AppendLine();
        }
        f.Block("Окружение эпизодов по времени", body.ToString().TrimEnd());
    }

    private static void ReportBands(ScanContext ctx, List<Band> bands, bool redefinitionSeen)
    {
        var big = bands.Where(b => b.Count >= 8).ToList();
        if (big.Count == 0) return;

        var f = ctx.Report.Report("JVM",
            $"{big.Count} сплошных полос недействительного скомпилированного кода " +
            $"(наибольшая — {big.Max(b => b.Count)} методов подряд)" +
            (redefinitionSeen ? "" : " — переопределение другими источниками не подтверждено"),
            redefinitionSeen ? Severity.Medium : Severity.Low,
            "Аллокатор кодового кеша выдаёт память последовательно, поэтому порядок " +
            "блоков по адресам — это порядок их компиляции. Обычная деоптимизация " +
            "выбивает отдельные методы, и недействительные блоки оказываются разбросаны " +
            "среди действительных. Сплошная полоса означает, что большая группа методов " +
            "была признана недействительной ЗА ОДИН РАЗ. Именно так работает " +
            "переопределение класса: оно выбрасывает скомпилированный код всех методов " +
            "класса разом. Сама по себе полоса уликой не является — так же выглядит " +
            "массовая деоптимизация при смене уровня компиляции, — но её положение и " +
            "ширина показывают, где искать событие, которое её вызвало.");
        foreach (var b in big.OrderByDescending(x => x.Count).Take(20))
        {
            var names = b.Blobs.Select(x => x.Name).Where(x => x.Length > 0)
                               .Distinct().Take(4);
            f.Add($"{b.Count} подряд",
                $"адреса 0x{b.Blobs[0].Lo:X}…0x{b.Blobs[^1].Hi:X}, " +
                $"состояния: {string.Join("/", b.Blobs.Select(x => StateName(x.State)).Distinct())}" +
                (names.Any() ? ", например " + string.Join(", ", names) : ""));
        }
    }

    private static void ReportDeoptStorm(ScanContext ctx, List<Ev> events, StringBuilder sb)
    {
        var deopt = events.Where(e => e.Ring == "deopt").OrderBy(e => e.Ts).ToList();
        if (deopt.Count < 4) return;

        var clusters = new List<List<Ev>>();
        var cur = new List<Ev> { deopt[0] };
        for (int i = 1; i < deopt.Count; i++)
        {
            if (deopt[i].Ts - deopt[i - 1].Ts <= 0.25) cur.Add(deopt[i]);
            else { clusters.Add(cur); cur = new List<Ev> { deopt[i] }; }
        }
        clusters.Add(cur);

        var storms = clusters.Where(c => c.Count >= 8).ToList();
        sb.AppendLine("ПЛОТНОСТЬ ДЕОПТИМИЗАЦИЙ");
        sb.AppendLine($"  записей в кольце: {deopt.Count}, сгустков (шаг ≤ 0,25 с): " +
                      $"{clusters.Count}, из них плотных (8 и более): {storms.Count}");
        foreach (var c in clusters.OrderByDescending(x => x.Count).Take(10))
            sb.AppendLine($"      {c.Count,4} записей за {c[^1].Ts - c[0].Ts:F3} с, " +
                          $"начиная с +{c[0].Ts:F3} с");
        sb.AppendLine();

        if (storms.Count == 0) return;

        var f = ctx.Report.Report("JVM",
            $"{storms.Count} плотных всплесков деоптимизации " +
            $"(наибольший — {storms.Max(s => s.Count)} записей подряд)",
            Severity.Medium,
            "Деоптимизация сама по себе — обычная работа оптимизирующего компилятора: он " +
            "делает предположения о коде и откатывает их, когда они перестают " +
            "выполняться. Но при разогреве эти события РАСТЯНУТЫ во времени: методы " +
            "переучиваются по одному. Плотный всплеск — десятки записей за доли секунды " +
            "— означает, что действительность большого куска скомпилированного кода " +
            "нарушило одно событие. Переопределение класса и подмена его методов " +
            "выглядят именно так. Стоит сверить время всплеска с эпизодами выше и с " +
            "журналом загрузки классов.");
        foreach (var s in storms.OrderByDescending(x => x.Count).Take(12))
            f.Add($"+{s[0].Ts:F3} с",
                $"{s.Count} деоптимизаций за {s[^1].Ts - s[0].Ts:F3} с; первая: " +
                Cut(s[0].Text, 110));
    }

    private static void ReportOrphanDeoptState(ScanContext ctx, List<CodeBlobInfo> invalid,
        StringBuilder sb)
    {
        if (invalid.Count == 0) return;

        var byState = invalid.GroupBy(b => b.State)
                             .ToDictionary(g => g.Key, g => g.Count());
        sb.AppendLine("СОСТОЯНИЯ НЕДЕЙСТВИТЕЛЬНОГО КОДА");
        foreach (var kv in byState.OrderByDescending(x => x.Value))
            sb.AppendLine($"      {StateName(kv.Key),-16} {kv.Value}");
        sb.AppendLine();

        var liveMethodInvalid = invalid
            .Where(b => b.Method != 0 && ctx.LiveMethods.Contains(b.Method))
            .ToList();
        if (liveMethodInvalid.Count == 0 || ctx.LiveMethods.Count == 0) return;

        double share = (double)liveMethodInvalid.Count /
                       Math.Max(1, ctx.CodeBlobs.Count(b => b.IsNmethod));
        if (share < 0.10) return;

        ctx.Report.Report("JVM",
                $"{liveMethodInvalid.Count} скомпилированных методов недействительны, хотя " +
                $"сами методы живы и достижимы ({share:P0} всего кеша)",
                Severity.Low,
                "Недействительный код при живом методе — это обычный ход вещей: " +
                "компилятор откатил предположение и метод будет перекомпилирован. " +
                "Значима доля: когда недействительной оказывается заметная часть всего " +
                "кеша, это уже не отдельные откаты, а массовая инвалидация. Строка " +
                "приводится как мера фона, с которой надо сверять полосы инвалидации и " +
                "всплески деоптимизации выше.")
            .Add("недействительных при живом методе", liveMethodInvalid.Count.ToString())
            .Add("всего скомпилированных методов",
                ctx.CodeBlobs.Count(b => b.IsNmethod).ToString())
            .Add("доля кеша", $"{share:P1}");
    }

    private static string? ExtractClassName(string text)
    {
        const string nameEq = "name=";
        int i = text.IndexOf(nameEq, StringComparison.Ordinal);
        if (i >= 0)
        {
            int s = i + nameEq.Length;
            int e = s;
            while (e < text.Length && text[e] != ',' && text[e] != ' ') e++;
            if (e > s) return text.Substring(s, e - s);
        }

        int q = text.IndexOf('\'');
        if (q >= 0)
        {
            int e = text.IndexOf('\'', q + 1);
            if (e > q + 1) return text.Substring(q + 1, e - q - 1);
        }

        const string cls = "class ";
        i = text.IndexOf(cls, StringComparison.Ordinal);
        if (i < 0) return null;
        int st = i + cls.Length;
        int en = st;
        while (en < text.Length && text[en] != ' ' && text[en] != ',') en++;
        return en > st ? text.Substring(st, en - st) : null;
    }

    private static string StateName(sbyte s) => s switch
    {
        0 => "in_use",
        1 => "not_used",
        2 => "not_entrant",
        3 => "zombie",
        4 => "unloaded",
        -1 => "not_installed",
        _ => $"состояние {s}",
    };

    private static string Cut(string s, int n) =>
        s.Length <= n ? s : s.Substring(0, n - 1) + "…";
}
