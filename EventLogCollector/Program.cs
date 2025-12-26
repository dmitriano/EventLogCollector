using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml;
using Microsoft.Win32.SafeHandles;

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
    private static readonly Regex EventBeginRegex = new("<Event(\\s|>)", RegexOptions.Compiled);
    private static readonly Regex EventEndRegex = new("</Event>", RegexOptions.Compiled);

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
            if (options.UseWinApi)
            {
                Console.ForegroundColor = ConsoleColor.DarkCyan;
                Console.WriteLine("Collector: WinAPI (EvtQuery/EvtNext/EvtRender)");
                Console.ResetColor();

                var collector = new WinApiEventLogCollector();
                processed = collector.Collect(options, xpathQuery, writer, jsonOptions, swRead, swParse, swConvert, swWrite);
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.DarkCyan;
                Console.WriteLine("Collector: wevtutil.exe");
                Console.ResetColor();

                processed = CollectViaWevtutil(options, xpathQuery, writer, jsonOptions, swRead, swRegex, swParse, swConvert, swWrite);
            }
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

    private static int CollectViaWevtutil(
        Options options,
        string xpathQuery,
        StreamWriter writer,
        JsonSerializerOptions jsonOptions,
        Stopwatch swRead,
        Stopwatch swRegex,
        Stopwatch swParse,
        Stopwatch swConvert,
        Stopwatch swWrite)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "wevtutil.exe",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };

        if (!string.IsNullOrWhiteSpace(options.EvtxPath))
        {
            psi.Arguments = $"qe \"{options.EvtxPath}\" /lf:true /q:\"{xpathQuery}\" /f:XML";
        }
        else
        {
            psi.Arguments = $"qe {options.LogName} /q:\"{xpathQuery}\" /f:XML";
        }

        using var proc = new Process { StartInfo = psi };
        if (!proc.Start())
        {
            throw new InvalidOperationException("Failed to start wevtutil process.");
        }

        writer.WriteLine("[");
        writer.Flush();

        var buffer = new StringBuilder();
        var inEvent = false;
        var processed = 0;
        var first = true;

        while (!proc.StandardOutput.EndOfStream)
        {
            swRead.Start();
            var line = proc.StandardOutput.ReadLine();
            swRead.Stop();

            if (line is null)
            {
                break;
            }

            swRegex.Start();
            var matchesBegin = EventBeginRegex.IsMatch(line);
            swRegex.Stop();

            if (!inEvent && matchesBegin)
            {
                inEvent = true;
                buffer.Clear();
            }

            if (inEvent)
            {
                buffer.AppendLine(line);

                swRegex.Start();
                var matchesEnd = EventEndRegex.IsMatch(line);
                swRegex.Stop();

                if (matchesEnd)
                {
                    inEvent = false;

                    swParse.Start();
                    var record = ParseEventToObject(buffer.ToString());
                    swParse.Stop();

                    processed++;

                    swConvert.Start();
                    var json = JsonSerializer.Serialize(record, jsonOptions);
                    swConvert.Stop();

                    swWrite.Start();
                    if (first)
                    {
                        first = false;
                    }
                    else
                    {
                        writer.WriteLine(",");
                    }

                    writer.Write(json);

                    if (options.ProgressInterval > 0 && processed % options.ProgressInterval == 0)
                    {
                        Console.ForegroundColor = ConsoleColor.DarkGray;
                        Console.WriteLine($"Processed {processed} events...");
                        Console.ResetColor();
                        writer.Flush();
                    }

                    swWrite.Stop();
                }
            }
        }

        writer.WriteLine();
        writer.WriteLine("]");
        writer.Flush();

        proc.WaitForExit();
        var stderr = proc.StandardError.ReadToEnd();
        if (proc.ExitCode != 0)
        {
            throw new InvalidOperationException($"wevtutil exit code {proc.ExitCode}. stderr: {stderr}");
        }

        return processed;
    }
}

sealed class WinApiEventLogCollector
{
    private const int EvtQueryChannelPath = 0x1;
    private const int EvtQueryFilePath = 0x2;
    private const int EvtRenderEventXml = 1;
    private const int ErrorInsufficientBuffer = 122;
    private const int ErrorNoMoreItems = 259;
    private const int DefaultBatchSize = 32;

    public int Collect(
        Options options,
        string xpathQuery,
        StreamWriter writer,
        JsonSerializerOptions jsonOptions,
        Stopwatch swRead,
        Stopwatch swParse,
        Stopwatch swConvert,
        Stopwatch swWrite)
    {
        var queryPath = string.IsNullOrWhiteSpace(options.EvtxPath) ? options.LogName : options.EvtxPath;
        var flags = string.IsNullOrWhiteSpace(options.EvtxPath) ? EvtQueryChannelPath : EvtQueryFilePath;

        using var resultSet = EvtQuery(IntPtr.Zero, queryPath, xpathQuery, flags);
        if (resultSet.IsInvalid)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "EvtQuery failed.");
        }

        writer.WriteLine("[");
        writer.Flush();

        var processed = 0;
        var first = true;
        var handles = new IntPtr[DefaultBatchSize];

        while (true)
        {
            swRead.Start();
            var success = EvtNext(resultSet, handles.Length, handles, 0, 0, out var returned);
            swRead.Stop();

            if (!success)
            {
                var error = Marshal.GetLastWin32Error();
                if (error == ErrorNoMoreItems)
                {
                    break;
                }

                throw new Win32Exception(error, "EvtNext failed.");
            }

            for (var i = 0; i < returned; i++)
            {
                using var evtHandle = new SafeEvtHandle(handles[i], ownsHandle: true);
                handles[i] = IntPtr.Zero;

                swRead.Start();
                var xml = RenderEventXml(evtHandle);
                swRead.Stop();

                swParse.Start();
                var record = Program.ParseEventToObject(xml);
                swParse.Stop();

                processed++;

                swConvert.Start();
                var json = JsonSerializer.Serialize(record, jsonOptions);
                swConvert.Stop();

                swWrite.Start();
                if (first)
                {
                    first = false;
                }
                else
                {
                    writer.WriteLine(",");
                }

                writer.Write(json);

                if (options.ProgressInterval > 0 && processed % options.ProgressInterval == 0)
                {
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.WriteLine($"Processed {processed} events...");
                    Console.ResetColor();
                    writer.Flush();
                }

                swWrite.Stop();
            }
        }

        writer.WriteLine();
        writer.WriteLine("]");
        writer.Flush();

        return processed;
    }

    private static string RenderEventXml(SafeEvtHandle evtHandle)
    {
        if (EvtRender(IntPtr.Zero, evtHandle, EvtRenderEventXml, 0, IntPtr.Zero, out var bufferUsed, out _))
        {
            return string.Empty;
        }

        var error = Marshal.GetLastWin32Error();
        if (error != ErrorInsufficientBuffer)
        {
            throw new Win32Exception(error, "EvtRender failed to get buffer size.");
        }

        var buffer = Marshal.AllocHGlobal(bufferUsed);
        try
        {
            if (!EvtRender(IntPtr.Zero, evtHandle, EvtRenderEventXml, bufferUsed, buffer, out bufferUsed, out _))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "EvtRender failed.");
            }

            var charCount = Math.Max(0, (bufferUsed / 2) - 1);
            return Marshal.PtrToStringUni(buffer, charCount) ?? string.Empty;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    [DllImport("wevtapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeEvtHandle EvtQuery(IntPtr session, string path, string query, int flags);

    [DllImport("wevtapi.dll", SetLastError = true)]
    private static extern bool EvtNext(SafeEvtHandle resultSet, int eventArraySize, IntPtr[] events, int timeout, int flags, out int returned);

    [DllImport("wevtapi.dll", SetLastError = true)]
    private static extern bool EvtRender(IntPtr context, SafeEvtHandle fragment, int flags, int bufferSize, IntPtr buffer, out int bufferUsed, out int propertyCount);

    [DllImport("wevtapi.dll")]
    private static extern bool EvtClose(IntPtr handle);

    private sealed class SafeEvtHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeEvtHandle()
            : base(true)
        {
        }

        public SafeEvtHandle(IntPtr handle, bool ownsHandle)
            : base(ownsHandle)
        {
            SetHandle(handle);
        }

        protected override bool ReleaseHandle()
        {
            return EvtClose(handle);
        }
    }
}
