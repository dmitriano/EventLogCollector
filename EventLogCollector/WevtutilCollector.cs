using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;

sealed class WevtutilCollector : Collector
{
    private static readonly Regex EventBeginRegex = new("<Event(\\s|>)", RegexOptions.Compiled);
    private static readonly Regex EventEndRegex = new("</Event>", RegexOptions.Compiled);

    public override string CollectorName => "wevtutil.exe";

    protected override IEnumerable<string> ReadEventXml(
        Options options,
        string xpathQuery,
        Stopwatch swRead,
        Stopwatch swRegex)
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

        var buffer = new StringBuilder();
        var inEvent = false;

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
                    yield return buffer.ToString();
                }
            }
        }

        proc.WaitForExit();
        var stderr = proc.StandardError.ReadToEnd();
        if (proc.ExitCode != 0)
        {
            throw new InvalidOperationException($"wevtutil exit code {proc.ExitCode}. stderr: {stderr}");
        }
    }
}
