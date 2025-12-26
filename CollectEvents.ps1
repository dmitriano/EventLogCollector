[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Args
)

$ErrorActionPreference = 'Stop'

if ($PSVersionTable.PSEdition -eq 'Desktop') {
    $pwsh = Get-Command pwsh -ErrorAction SilentlyContinue
    if (-not $pwsh) {
        throw 'CollectWevtutilStream.ps1 requires PowerShell 6+ (pwsh). Install PowerShell 6+ or run via pwsh directly.'
    }

    $argumentList = @('-NoProfile', '-File', $MyInvocation.MyCommand.Path) + $Args
    $process = Start-Process -FilePath $pwsh.Source -ArgumentList $argumentList -NoNewWindow -Wait -PassThru
    exit $process.ExitCode
}

class Options {
    [Nullable[int]]$Hours
    [string]$LogName = 'Security'
    [string]$EvtxPath
    [System.Collections.Generic.List[int]]$EventIds = [System.Collections.Generic.List[int]]::new()
    [int]$ProgressInterval = 1000
    [string]$OutputFolder = 'C:\Logs\Security'
    [bool]$UseWinApi
}

class EventRecord {
    [string]$TimeCreated
    [Nullable[int]]$EventId
    [string]$ProviderName
    [string]$Computer
    [Nullable[long]]$RecordId
    [System.Collections.Generic.Dictionary[string, string]]$EventData = [System.Collections.Generic.Dictionary[string, string]]::new()
}

class Collector {
    [string]$CollectorName = 'Base'

    [int] Collect(
        [Options]$options,
        [string]$xpathQuery,
        [System.IO.StreamWriter]$writer,
        $jsonOptions,
        [System.Diagnostics.Stopwatch]$swRead,
        [System.Diagnostics.Stopwatch]$swRegex,
        [System.Diagnostics.Stopwatch]$swParse,
        [System.Diagnostics.Stopwatch]$swConvert,
        [System.Diagnostics.Stopwatch]$swWrite) {
        $writer.WriteLine('[')
        $writer.Flush()

        $processed = 0
        $first = $true

        foreach ($xml in $this.ReadEventXml($options, $xpathQuery, $swRead, $swRegex)) {
            $swParse.Start()
            $record = Parse-EventToObject -EventXml $xml
            $swParse.Stop()

            $processed++

            $swConvert.Start()
            $json = $record | ConvertTo-Json -Compress -Depth 8
            $swConvert.Stop()

            $swWrite.Start()
            if ($first) {
                $first = $false
            } else {
                $writer.WriteLine(',')
            }

            $writer.Write($json)

            if ($options.ProgressInterval -gt 0 -and ($processed % $options.ProgressInterval) -eq 0) {
                Write-Host "Processed $processed events..." -ForegroundColor DarkGray
                $writer.Flush()
            }

            $swWrite.Stop()
        }

        $writer.WriteLine()
        $writer.WriteLine(']')
        $writer.Flush()

        return $processed
    }

    [System.Collections.Generic.IEnumerable[string]] ReadEventXml(
        [Options]$options,
        [string]$xpathQuery,
        [System.Diagnostics.Stopwatch]$swRead,
        [System.Diagnostics.Stopwatch]$swRegex) {
        throw 'ReadEventXml must be implemented by derived classes.'
        return @()
    }
}

class WevtutilCollector : Collector {
    hidden static [System.Text.RegularExpressions.Regex]$EventBeginRegex = [System.Text.RegularExpressions.Regex]::new('<Event(\s|>)', [System.Text.RegularExpressions.RegexOptions]::Compiled)
    hidden static [System.Text.RegularExpressions.Regex]$EventEndRegex = [System.Text.RegularExpressions.Regex]::new('</Event>', [System.Text.RegularExpressions.RegexOptions]::Compiled)

    WevtutilCollector() {
        $this.CollectorName = 'wevtutil.exe'
    }

    [System.Collections.Generic.IEnumerable[string]] ReadEventXml(
        [Options]$options,
        [string]$xpathQuery,
        [System.Diagnostics.Stopwatch]$swRead,
        [System.Diagnostics.Stopwatch]$swRegex) {
        $results = [System.Collections.Generic.List[string]]::new()
        $psi = [System.Diagnostics.ProcessStartInfo]::new()
        $psi.FileName = 'wevtutil.exe'
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.CreateNoWindow = $true

        if (-not [string]::IsNullOrWhiteSpace($options.EvtxPath)) {
            $psi.Arguments = "qe `"$($options.EvtxPath)`" /lf:true /q:`"$xpathQuery`" /f:XML"
        } else {
            $psi.Arguments = "qe $($options.LogName) /q:`"$xpathQuery`" /f:XML"
        }

        $proc = [System.Diagnostics.Process]::new()
        $proc.StartInfo = $psi
        if (-not $proc.Start()) {
            throw 'Failed to start wevtutil process.'
        }

        $buffer = [System.Text.StringBuilder]::new()
        $inEvent = $false

        while (-not $proc.StandardOutput.EndOfStream) {
            $swRead.Start()
            $line = $proc.StandardOutput.ReadLine()
            $swRead.Stop()

            if ($null -eq $line) {
                break
            }

            $swRegex.Start()
            $matchesBegin = [WevtutilCollector]::EventBeginRegex.IsMatch($line)
            $swRegex.Stop()

            if (-not $inEvent -and $matchesBegin) {
                $inEvent = $true
                $buffer.Clear() | Out-Null
            }

            if ($inEvent) {
                $buffer.AppendLine($line) | Out-Null

                $swRegex.Start()
                $matchesEnd = [WevtutilCollector]::EventEndRegex.IsMatch($line)
                $swRegex.Stop()

                if ($matchesEnd) {
                    $inEvent = $false
                    $results.Add($buffer.ToString()) | Out-Null
                }
            }
        }

        $proc.WaitForExit()
        $stderr = $proc.StandardError.ReadToEnd()
        if ($proc.ExitCode -ne 0) {
            throw "wevtutil exit code $($proc.ExitCode). stderr: $stderr"
        }

        return $results
    }
}

class WinapiCollector : Collector {
    WinapiCollector() {
        $this.CollectorName = 'WinAPI (EventLogReader)'
    }

    [System.Collections.Generic.IEnumerable[string]] ReadEventXml(
        [Options]$options,
        [string]$xpathQuery,
        [System.Diagnostics.Stopwatch]$swRead,
        [System.Diagnostics.Stopwatch]$swRegex) {
        $results = [System.Collections.Generic.List[string]]::new()
        $queryPath = if ([string]::IsNullOrWhiteSpace($options.EvtxPath)) { $options.LogName } else { $options.EvtxPath }
        $pathType = if ([string]::IsNullOrWhiteSpace($options.EvtxPath)) {
            [System.Diagnostics.Eventing.Reader.PathType]::LogName
        } else {
            [System.Diagnostics.Eventing.Reader.PathType]::FilePath
        }

        $query = [System.Diagnostics.Eventing.Reader.EventLogQuery]::new($queryPath, $pathType, $xpathQuery)
        $reader = [System.Diagnostics.Eventing.Reader.EventLogReader]::new($query)
        try {
            while ($true) {
                $swRead.Start()
                $evt = $reader.ReadEvent()
                $swRead.Stop()
                if ($null -eq $evt) {
                    break
                }

                try {
                    $swRead.Start()
                    $xml = $evt.ToXml()
                    $swRead.Stop()
                    $results.Add($xml) | Out-Null
                } finally {
                    $evt.Dispose()
                }
            }
        } finally {
            $reader.Dispose()
        }

        return $results
    }
}

function Show-Help {
    Write-Host "Usage: CollectWevtutilStream.ps1 [options]"
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  --hours <int>            Look back N hours (UTC). Omit for all events."
    Write-Host "  --logname <string>       Windows log name (default: Security)."
    Write-Host "  --evtxpath <path>         Path to .evtx file to read."
    Write-Host "  --eventids <list>         Comma-separated Event IDs."
    Write-Host "  --progressinterval <int> Print progress every N events (0 = disable)."
    Write-Host "  --outputfolder <path>     Output folder (default: C:\Logs\Security)."
    Write-Host "  --usewinapi              Use WinAPI (EvtQuery/EvtNext/EvtRender) instead of wevtutil."
}

function Parse-IntValue {
    param(
        [string[]]$Arguments,
        [ref]$Index
    )

    if ($Index.Value + 1 -ge $Arguments.Length) {
        return $null
    }

    $Index.Value++
    $value = 0
    if ([int]::TryParse($Arguments[$Index.Value], [ref]$value)) {
        return $value
    }

    return $null
}

function Parse-StringValue {
    param(
        [string[]]$Arguments,
        [ref]$Index
    )

    if ($Index.Value + 1 -ge $Arguments.Length) {
        return $null
    }

    $Index.Value++
    return $Arguments[$Index.Value]
}

function Build-XPathQuery {
    param(
        [System.Collections.Generic.List[int]]$EventIds,
        [string]$StartTimeUtc
    )

    if ($EventIds.Count -gt 0) {
        $conditions = ($EventIds | ForEach-Object { "EventID=$_" }) -join ' or '
        if ($StartTimeUtc) {
            return "*[System[($conditions) and TimeCreated[@SystemTime>='$StartTimeUtc']]]"
        }

        return "*[System[$conditions]]"
    }

    if ($StartTimeUtc) {
        return "*[System[TimeCreated[@SystemTime>='$StartTimeUtc']]]"
    }

    return "*"
}

function Parse-EventToObject {
    param(
        [string]$EventXml
    )

    $settings = [System.Xml.XmlReaderSettings]::new()
    $settings.ConformanceLevel = [System.Xml.ConformanceLevel]::Fragment
    $settings.IgnoreWhitespace = $true
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit

    $stringReader = [System.IO.StringReader]::new($EventXml)
    $reader = [System.Xml.XmlReader]::Create($stringReader, $settings)

    $timeCreated = $null
    $eventId = $null
    $providerName = $null
    $computer = $null
    $recordId = $null
    $eventData = [System.Collections.Generic.Dictionary[string, string]]::new()

    try {
        while ($reader.Read()) {
            if ($reader.NodeType -ne [System.Xml.XmlNodeType]::Element) {
                continue
            }

            switch ($reader.Name) {
                'Provider' {
                    $name = $reader.GetAttribute('Name')
                    if (-not [string]::IsNullOrEmpty($name)) {
                        $providerName = $name
                    }
                }
                'EventID' {
                    $text = $reader.ReadElementContentAsString()
                    $parsedId = 0
                    if ([int]::TryParse($text, [ref]$parsedId)) {
                        $eventId = $parsedId
                    }
                }
                'Computer' {
                    $computer = $reader.ReadElementContentAsString()
                }
                'EventRecordID' {
                    $text = $reader.ReadElementContentAsString()
                    $parsedRecordId = 0
                    if ([long]::TryParse($text, [ref]$parsedRecordId)) {
                        $recordId = $parsedRecordId
                    }
                }
                'TimeCreated' {
                    $systemTime = $reader.GetAttribute('SystemTime')
                    if (-not [string]::IsNullOrWhiteSpace($systemTime)) {
                        $timeCreated = $systemTime
                    }
                }
                'Data' {
                    $name = $reader.GetAttribute('Name')
                    $value = $reader.ReadElementContentAsString()
                    if (-not [string]::IsNullOrEmpty($name)) {
                        $eventData[$name] = $value
                    }
                }
            }
        }
    } finally {
        $reader.Dispose()
        $stringReader.Dispose()
    }

    $record = [EventRecord]::new()
    $record.TimeCreated = $timeCreated
    $record.EventId = $eventId
    $record.ProviderName = $providerName
    $record.Computer = $computer
    $record.RecordId = $recordId
    $record.EventData = $eventData
    return $record
}

$options = [Options]::new()

for ($i = 0; $i -lt $Args.Length; $i++) {
    $arg = $Args[$i]
    switch ($arg) {
        '--hours' { $options.Hours = Parse-IntValue -Arguments $Args -Index ([ref]$i) }
        '--logname' { $value = Parse-StringValue -Arguments $Args -Index ([ref]$i); if ($value) { $options.LogName = $value } }
        '--evtxpath' { $options.EvtxPath = Parse-StringValue -Arguments $Args -Index ([ref]$i) }
        '--eventids' {
            $value = Parse-StringValue -Arguments $Args -Index ([ref]$i)
            if ($value) {
                $list = [System.Collections.Generic.List[int]]::new()
                foreach ($part in $value.Split(',', [System.StringSplitOptions]::RemoveEmptyEntries)) {
                    $trimmed = $part.Trim()
                    $id = 0
                    if ([int]::TryParse($trimmed, [ref]$id)) {
                        $list.Add($id)
                    }
                }

                $options.EventIds = $list
            }
        }
        '--progressinterval' { $value = Parse-IntValue -Arguments $Args -Index ([ref]$i); if ($null -ne $value) { $options.ProgressInterval = $value } }
        '--outputfolder' { $value = Parse-StringValue -Arguments $Args -Index ([ref]$i); if ($value) { $options.OutputFolder = $value } }
        '--usewinapi' { $options.UseWinApi = $true }
        '--help' { Show-Help; exit 0 }
        '-h' { Show-Help; exit 0 }
        '/?' { Show-Help; exit 0 }
    }
}

Write-Host "=== CollectWevtutilStream v2.5 (EVTX supported, optional EventIds, ConvertTo-Json -Compress) ===" -ForegroundColor Magenta

$swTotal = [System.Diagnostics.Stopwatch]::StartNew()
$swRead = [System.Diagnostics.Stopwatch]::new()
$swRegex = [System.Diagnostics.Stopwatch]::new()
$swParse = [System.Diagnostics.Stopwatch]::new()
$swConvert = [System.Diagnostics.Stopwatch]::new()
$swWrite = [System.Diagnostics.Stopwatch]::new()

if (-not (Test-Path $options.OutputFolder)) {
    New-Item -ItemType Directory -Path $options.OutputFolder | Out-Null
}

$startTimeUtc = $null
if ($null -ne $options.Hours) {
    $startTimeUtc = [DateTime]::UtcNow.AddHours(-$options.Hours).ToString('o')
}

$useEvtxFile = $false
$sourceLabel = $options.LogName
if (-not [string]::IsNullOrWhiteSpace($options.EvtxPath)) {
    if (-not (Test-Path $options.EvtxPath)) {
        throw "EVTX file not found: $($options.EvtxPath)"
    }

    $useEvtxFile = $true
    $sourceLabel = [System.IO.Path]::GetFileName($options.EvtxPath)
}

$timestamp = [DateTime]::Now.ToString('yyyyMMdd_HHmmss')
$outKind = if ($useEvtxFile) { 'evtx' } else { 'live' }
$hoursLabel = if ($null -ne $options.Hours) { $options.Hours.ToString() } else { '' }
$jsonFile = Join-Path $options.OutputFolder "${timestamp}_${sourceLabel}_${outKind}_last${hoursLabel}h.json"

$sourceText = if ($useEvtxFile) { "EVTX file: $($options.EvtxPath)" } else { "Live log: $($options.LogName)" }
$eventIdsText = if ($options.EventIds.Count -gt 0) { $options.EventIds -join ', ' } else { '<none> (all Event IDs)' }

Write-Host "Source: $sourceText" -ForegroundColor Cyan
if ($startTimeUtc) {
    Write-Host "StartTime (UTC): $startTimeUtc" -ForegroundColor Cyan
} else {
    Write-Host "StartTime: <none> (all available events)" -ForegroundColor Cyan
}

Write-Host "EventIds filter: $eventIdsText" -ForegroundColor Cyan
Write-Host "Output file: $jsonFile" -ForegroundColor Cyan

$xpathQuery = Build-XPathQuery -EventIds $options.EventIds -StartTimeUtc $startTimeUtc
Write-Host "XPath:" -ForegroundColor Yellow
Write-Host $xpathQuery -ForegroundColor Yellow

$encoding = [System.Text.UTF8Encoding]::new($false)
$writer = [System.IO.StreamWriter]::new($jsonFile, $false, $encoding)
$jsonOptions = $null

$processed = 0
try {
    $collector = if ($options.UseWinApi) { [WinapiCollector]::new() } else { [WevtutilCollector]::new() }
    Write-Host "Collector: $($collector.CollectorName)" -ForegroundColor DarkCyan

    $processed = $collector.Collect(
        $options,
        $xpathQuery,
        $writer,
        $jsonOptions,
        $swRead,
        $swRegex,
        $swParse,
        $swConvert,
        $swWrite)
}
finally {
    $swTotal.Stop()
    $writer.Dispose()
}

$fileLen = (Get-Item $jsonFile).Length

Write-Host ""
Write-Host "===== SUMMARY =====" -ForegroundColor Green
Write-Host "Events processed : $processed" -ForegroundColor Green
Write-Host "File size (bytes): $fileLen" -ForegroundColor Green

Write-Host "Read time        : $([Math]::Round($swRead.Elapsed.TotalSeconds, 2)) sec" -ForegroundColor Yellow
Write-Host "XML Parse time   : $([Math]::Round($swParse.Elapsed.TotalSeconds, 2)) sec" -ForegroundColor Yellow
Write-Host "Regex time       : $([Math]::Round($swRegex.Elapsed.TotalSeconds, 2)) sec" -ForegroundColor Yellow
Write-Host "Convert time     : $([Math]::Round($swConvert.Elapsed.TotalSeconds, 2)) sec" -ForegroundColor Yellow
Write-Host "Write time       : $([Math]::Round($swWrite.Elapsed.TotalSeconds, 2)) sec" -ForegroundColor Yellow

Write-Host "Total time       : $([Math]::Round($swTotal.Elapsed.TotalSeconds, 2)) sec" -ForegroundColor Cyan

exit 0
