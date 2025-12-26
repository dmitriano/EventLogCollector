using System.Diagnostics;
using System.Text.Json;

public abstract class Collector
{
    public virtual string CollectorName => "Base";

    public virtual int Collect(
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
        writer.WriteLine("[");
        writer.Flush();

        var processed = 0;
        var first = true;

        foreach (var xml in ReadEventXml(options, xpathQuery, swRead, swRegex))
        {
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

        writer.WriteLine();
        writer.WriteLine("]");
        writer.Flush();

        return processed;
    }

    protected abstract IEnumerable<string> ReadEventXml(
        Options options,
        string xpathQuery,
        Stopwatch swRead,
        Stopwatch swRegex);
}
