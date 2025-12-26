using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Xml;

sealed class Options
{
    public int? Hours { get; set; }
    public string LogName { get; set; } = "Security";
    public string? EvtxPath { get; set; }
    public List<int> EventIds { get; set; } = new();
    public int ProgressInterval { get; set; } = 1000;
    public string OutputFolder { get; set; } = @"C:\Logs\Security";
    public bool UseWinApi { get; set; }
}

sealed class EventRecord
{
    public string? TimeCreated { get; init; }
    public int? EventId { get; init; }
    public string? ProviderName { get; init; }
    public string? Computer { get; init; }
    public long? RecordId { get; init; }
    public Dictionary<string, string> EventData { get; init; } = new();
}

static class Program
{

    private static int Main(string[] args)
    {
        var options = ParseArgs(args);
        Console.ForegroundColor = ConsoleColor.Magenta;
        Console.WriteLine("=== CollectWevtutilStream v2.5 (EVTX supported, optional EventIds, ConvertTo-Json -Compress) ===");
        Console.ResetColor();

        var swTotal = Stopwatch.StartNew();
        var swRead = new Stopwatch();
        var swRegex = new Stopwatch();
        var swParse = new Stopwatch();
        var swConvert = new Stopwatch();
        var swWrite = new Stopwatch();

        if (!Directory.Exists(options.OutputFolder))
        {
            Directory.CreateDirectory(options.OutputFolder);
        }

        string? startTimeUtc = null;
        if (options.Hours is not null)
        {
            startTimeUtc = DateTime.UtcNow.AddHours(-options.Hours.Value).ToString("o");
        }

        var useEvtxFile = false;
        var sourceLabel = options.LogName;
        if (!string.IsNullOrWhiteSpace(options.EvtxPath))
        {
            if (!File.Exists(options.EvtxPath))
            {
                throw new FileNotFoundException($"EVTX file not found: {options.EvtxPath}");
            }

            useEvtxFile = true;
            sourceLabel = Path.GetFileName(options.EvtxPath);
        }

        var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        var outKind = useEvtxFile ? "evtx" : "live";
        var hoursLabel = options.Hours?.ToString() ?? string.Empty;
        var jsonFile = Path.Combine(options.OutputFolder, $"{timestamp}_{sourceLabel}_{outKind}_last{hoursLabel}h.json");

        var sourceText = useEvtxFile ? $"EVTX file: {options.EvtxPath}" : $"Live log: {options.LogName}";
        var eventIdsText = options.EventIds.Count > 0 ? string.Join(", ", options.EventIds) : "<none> (all Event IDs)";

        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($"Source: {sourceText}");
        if (startTimeUtc is not null)
        {
            Console.WriteLine($"StartTime (UTC): {startTimeUtc}");
        }
        else
        {
            Console.WriteLine("StartTime: <none> (all available events)");
        }

        Console.WriteLine($"EventIds filter: {eventIdsText}");
        Console.WriteLine($"Output file: {jsonFile}");
        Console.ResetColor();

        var xpathQuery = BuildXPathQuery(options.EventIds, startTimeUtc);
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("XPath:");
        Console.WriteLine(xpathQuery);
        Console.ResetColor();

        var encoding = new UTF8Encoding(false);
        using var writer = new StreamWriter(jsonFile, false, encoding);
        var jsonOptions = new JsonSerializerOptions { WriteIndented = false };

        var processed = 0;
        try
        {
            EventLogCollectorBase collector = options.UseWinApi
                ? new WinApiEventLogCollector()
                : new WevtutilEventLogCollector();

            Console.ForegroundColor = ConsoleColor.DarkCyan;
            Console.WriteLine($"Collector: {collector.CollectorName}");
            Console.ResetColor();

            processed = collector.Collect(
                options,
                xpathQuery,
                writer,
                jsonOptions,
                swRead,
                swRegex,
                swParse,
                swConvert,
                swWrite);
        }
        finally
        {
            swTotal.Stop();
        }

        var fileLen = new FileInfo(jsonFile).Length;

        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("===== SUMMARY =====");
        Console.WriteLine($"Events processed : {processed}");
        Console.WriteLine($"File size (bytes): {fileLen}");
        Console.ResetColor();

        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine($"Read time        : {swRead.Elapsed.TotalSeconds:N2} sec");
        Console.WriteLine($"XML Parse time   : {swParse.Elapsed.TotalSeconds:N2} sec");
        Console.WriteLine($"Regex time       : {swRegex.Elapsed.TotalSeconds:N2} sec");
        Console.WriteLine($"Convert time     : {swConvert.Elapsed.TotalSeconds:N2} sec");
        Console.WriteLine($"Write time       : {swWrite.Elapsed.TotalSeconds:N2} sec");
        Console.ResetColor();

        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($"Total time       : {swTotal.Elapsed.TotalSeconds:N2} sec");
        Console.ResetColor();

        return 0;
    }

    private static string BuildXPathQuery(List<int> eventIds, string? startTimeUtc)
    {
        if (eventIds.Count > 0)
        {
            var conditions = string.Join(" or ", eventIds.Select(id => $"EventID={id}"));
            if (startTimeUtc is not null)
            {
                return $"*[System[({conditions}) and TimeCreated[@SystemTime>='{startTimeUtc}']]]";
            }

            return $"*[System[{conditions}]]";
        }

        if (startTimeUtc is not null)
        {
            return $"*[System[TimeCreated[@SystemTime>='{startTimeUtc}']]]";
        }

        return "*";
    }

    internal static EventRecord ParseEventToObject(string eventXml)
    {
        var settings = new XmlReaderSettings
        {
            ConformanceLevel = ConformanceLevel.Fragment,
            IgnoreWhitespace = true,
            DtdProcessing = DtdProcessing.Prohibit
        };

        using var stringReader = new StringReader(eventXml);
        using var reader = XmlReader.Create(stringReader, settings);

        string? timeCreated = null;
        int? eventId = null;
        string? providerName = null;
        string? computer = null;
        long? recordId = null;
        var eventData = new Dictionary<string, string>();

        while (reader.Read())
        {
            if (reader.NodeType != XmlNodeType.Element)
            {
                continue;
            }

            switch (reader.Name)
            {
                case "Provider":
                {
                    var name = reader.GetAttribute("Name");
                    if (!string.IsNullOrEmpty(name))
                    {
                        providerName = name;
                    }

                    break;
                }
                case "EventID":
                {
                    var text = reader.ReadElementContentAsString();
                    if (int.TryParse(text, out var parsedId))
                    {
                        eventId = parsedId;
                    }

                    break;
                }
                case "Computer":
                {
                    computer = reader.ReadElementContentAsString();
                    break;
                }
                case "EventRecordID":
                {
                    var text = reader.ReadElementContentAsString();
                    if (long.TryParse(text, out var parsedRecordId))
                    {
                        recordId = parsedRecordId;
                    }

                    break;
                }
                case "TimeCreated":
                {
                    var systemTime = reader.GetAttribute("SystemTime");
                    if (!string.IsNullOrWhiteSpace(systemTime))
                    {
                        timeCreated = systemTime;
                    }

                    break;
                }
                case "Data":
                {
                    var name = reader.GetAttribute("Name");
                    var value = reader.ReadElementContentAsString();
                    if (!string.IsNullOrEmpty(name))
                    {
                        eventData[name] = value;
                    }

                    break;
                }
            }
        }

        return new EventRecord
        {
            TimeCreated = timeCreated,
            EventId = eventId,
            ProviderName = providerName,
            Computer = computer,
            RecordId = recordId,
            EventData = eventData
        };
    }

    private static Options ParseArgs(string[] args)
    {
        var options = new Options();
        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];
            switch (arg)
            {
                case "--hours":
                    options.Hours = ParseIntValue(args, ref i);
                    break;
                case "--logname":
                    options.LogName = ParseStringValue(args, ref i) ?? options.LogName;
                    break;
                case "--evtxpath":
                    options.EvtxPath = ParseStringValue(args, ref i);
                    break;
                case "--eventids":
                    var eventIdValue = ParseStringValue(args, ref i);
                    if (!string.IsNullOrWhiteSpace(eventIdValue))
                    {
                        options.EventIds = eventIdValue.Split(',', StringSplitOptions.RemoveEmptyEntries)
                            .Select(value => value.Trim())
                            .Where(value => int.TryParse(value, out _))
                            .Select(int.Parse)
                            .ToList();
                    }

                    break;
                case "--progressinterval":
                    options.ProgressInterval = ParseIntValue(args, ref i) ?? options.ProgressInterval;
                    break;
                case "--outputfolder":
                    options.OutputFolder = ParseStringValue(args, ref i) ?? options.OutputFolder;
                    break;
                case "--usewinapi":
                    options.UseWinApi = true;
                    break;
                case "--help":
                case "-h":
                case "/?":
                    PrintHelp();
                    Environment.Exit(0);
                    break;
            }
        }

        return options;
    }

    private static int? ParseIntValue(string[] args, ref int index)
    {
        if (index + 1 >= args.Length)
        {
            return null;
        }

        index++;
        if (int.TryParse(args[index], out var value))
        {
            return value;
        }

        return null;
    }

    private static string? ParseStringValue(string[] args, ref int index)
    {
        if (index + 1 >= args.Length)
        {
            return null;
        }

        index++;
        return args[index];
    }

    private static void PrintHelp()
    {
        Console.WriteLine("Usage: EventLogCollector [options]");
        Console.WriteLine();
        Console.WriteLine("Options:");
        Console.WriteLine("  --hours <int>            Look back N hours (UTC). Omit for all events.");
        Console.WriteLine("  --logname <string>       Windows log name (default: Security).");
        Console.WriteLine("  --evtxpath <path>         Path to .evtx file to read.");
        Console.WriteLine("  --eventids <list>         Comma-separated Event IDs.");
        Console.WriteLine("  --progressinterval <int> Print progress every N events (0 = disable).");
        Console.WriteLine("  --outputfolder <path>     Output folder (default: C:\\Logs\\Security).");
        Console.WriteLine("  --usewinapi              Use WinAPI (EvtQuery/EvtNext/EvtRender) instead of wevtutil.");
    }
}
