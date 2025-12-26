[CmdletBinding()]

param(
    [Nullable[int]]$Hours = $null,

    [string]$LogName = 'Security',

    # Optional path to an .evtx file. If set, wevtutil reads from the file (/lf:true).
    [string]$EvtxPath = $null,

    # Optional Event IDs filter. If $null or empty -> no EventID filter (all IDs).
    [int[]]$EventIds = $null,

    # How often to print "Processed N events..." (0 = disable)
    [int]$ProgressInterval = 1000,

    [string]$OutputFolder = "C:\Logs\Security",

    [switch]$UseWinApi,

    [switch]$Help
)

$ErrorActionPreference = 'Stop'

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

        foreach ($xml in $this.ReadEventXml($xpathQuery, $swRead, $swRegex)) {
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

            if ($script:ProgressInterval -gt 0 -and ($processed % $script:ProgressInterval) -eq 0) {
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

        if (-not [string]::IsNullOrWhiteSpace($script:EvtxPath)) {
            $psi.Arguments = "qe `"$($script:EvtxPath)`" /lf:true /q:`"$xpathQuery`" /f:XML"
        } else {
            $psi.Arguments = "qe $($script:LogName) /q:`"$xpathQuery`" /f:XML"
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
        $this.CollectorName = 'WinAPI'
    }

    [System.Collections.Generic.IEnumerable[string]] ReadEventXml(
        [string]$xpathQuery,
        [System.Diagnostics.Stopwatch]$swRead,
        [System.Diagnostics.Stopwatch]$swRegex) {
        $results = [System.Collections.Generic.List[string]]::new()
        $queryPath = if ([string]::IsNullOrWhiteSpace($script:EvtxPath)) { $script:LogName } else { $script:EvtxPath }
        $pathType = if ([string]::IsNullOrWhiteSpace($script:EvtxPath)) {
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
    Write-Host "Usage: CollectEvents.ps1 [options]"
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  -Hours <int>             Look back N hours (UTC). Omit for all events."
    Write-Host "  -LogName <string>        Windows log name (default: Security)."
    Write-Host "  -EvtxPath <path>         Path to .evtx file to read."
    Write-Host "  -EventIds <int[]>        Event IDs to filter (comma-separated)."
    Write-Host "  -ProgressInterval <int>  Print progress every N events (0 = disable)."
    Write-Host "  -OutputFolder <path>     Output folder (default: C:\Logs\Security)."
    Write-Host "  -UseWinApi               Use WinAPI (EvtQuery/EvtNext/EvtRender) instead of wevtutil."
    Write-Host "  -Help                    Show this help message."
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

$eventIdList = [System.Collections.Generic.List[int]]::new()
if ($EventIds) {
    foreach ($id in $EventIds) {
        if ($null -ne $id) {
            $eventIdList.Add($id)
        }
    }
}

if ($Help) {
    Show-Help
    exit 0
}

Write-Host "=== CollectEvents.ps1 ===" -ForegroundColor Magenta

$swTotal = [System.Diagnostics.Stopwatch]::StartNew()
$swRead = [System.Diagnostics.Stopwatch]::new()
$swRegex = [System.Diagnostics.Stopwatch]::new()
$swParse = [System.Diagnostics.Stopwatch]::new()
$swConvert = [System.Diagnostics.Stopwatch]::new()
$swWrite = [System.Diagnostics.Stopwatch]::new()

if (-not (Test-Path $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder | Out-Null
}

$startTimeUtc = $null
if ($null -ne $Hours) {
    $startTimeUtc = [DateTime]::UtcNow.AddHours(-$Hours).ToString('o')
}

$useEvtxFile = $false
$sourceLabel = $LogName
if (-not [string]::IsNullOrWhiteSpace($EvtxPath)) {
    if (-not (Test-Path $EvtxPath)) {
        throw "EVTX file not found: $($EvtxPath)"
    }

    $useEvtxFile = $true
    $sourceLabel = [System.IO.Path]::GetFileName($EvtxPath)
}

$timestamp = [DateTime]::Now.ToString('yyyyMMdd_HHmmss')
$outKind = if ($useEvtxFile) { 'evtx' } else { 'live' }
$hoursLabel = if ($null -ne $Hours) { $Hours.ToString() } else { '' }
$jsonFile = Join-Path $OutputFolder "${timestamp}_${sourceLabel}_${outKind}_last${hoursLabel}h.json"

$sourceText = if ($useEvtxFile) { "EVTX file: $($EvtxPath)" } else { "Live log: $($LogName)" }
$eventIdsText = if ($eventIdList.Count -gt 0) { $eventIdList -join ', ' } else { '<none> (all Event IDs)' }

Write-Host "Source: $sourceText" -ForegroundColor Cyan
if ($startTimeUtc) {
    Write-Host "StartTime (UTC): $startTimeUtc" -ForegroundColor Cyan
} else {
    Write-Host "StartTime: <none> (all available events)" -ForegroundColor Cyan
}

Write-Host "EventIds filter: $eventIdsText" -ForegroundColor Cyan
Write-Host "Output file: $jsonFile" -ForegroundColor Cyan

$xpathQuery = Build-XPathQuery -EventIds $eventIdList -StartTimeUtc $startTimeUtc
Write-Host "XPath:" -ForegroundColor Yellow
Write-Host $xpathQuery -ForegroundColor Yellow

$encoding = [System.Text.UTF8Encoding]::new($false)
$writer = [System.IO.StreamWriter]::new($jsonFile, $false, $encoding)
$jsonOptions = $null

$processed = 0
try {
    $collector = if ($UseWinApi) { [WinapiCollector]::new() } else { [WevtutilCollector]::new() }
    Write-Host "Collector: $($collector.CollectorName)" -ForegroundColor DarkCyan

    $processed = $collector.Collect(
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
