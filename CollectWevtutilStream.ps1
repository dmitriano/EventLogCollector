[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Args
)

$ErrorActionPreference = 'Stop'

if ($PSVersionTable.PSEdition -eq 'Desktop') {
    throw 'CollectWevtutilStream.ps1 requires PowerShell 7+ (pwsh). Windows PowerShell cannot load .NET 9 assemblies.'
}

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectPath = Join-Path $scriptRoot 'EventLogCollector/EventLogCollector.csproj'
$configuration = 'Release'
$targetFramework = 'net9.0'
$dllPath = Join-Path $scriptRoot "EventLogCollector/bin/$configuration/$targetFramework/EventLogCollector.dll"

if (-not (Test-Path $dllPath)) {
    Write-Host "Building EventLogCollector ($configuration)..." -ForegroundColor Cyan
    dotnet build $projectPath -c $configuration | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet build failed with exit code $LASTEXITCODE"
    }
}

[System.Runtime.Loader.AssemblyLoadContext]::Default.LoadFromAssemblyPath($dllPath) | Out-Null

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

$options = [Options]::new()
$options.LogName = 'Security'
$options.EventIds = [System.Collections.Generic.List[int]]::new()
$options.ProgressInterval = 1000
$options.OutputFolder = 'C:\Logs\Security'
$options.UseWinApi = $false

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
$jsonOptions = [System.Text.Json.JsonSerializerOptions]::new()
$jsonOptions.WriteIndented = $false

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
