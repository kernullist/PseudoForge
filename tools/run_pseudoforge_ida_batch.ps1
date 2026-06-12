[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$IdaPath,

    [Parameter(Mandatory = $true)]
    [string]$IdbPath,

    [string]$TargetPath = "",
    [string]$OutputDir = "",
    [string]$ForgePath = "",
    [string]$CompareDir = "",
    [string]$ProfileDir = "",
    [string]$ReportPath = "",
    [string]$CancelFile = "",
    [string]$IdaLogPath = "",
    [int]$MaxFunctions = 0,
    [int]$MaxSeconds = 0,
    [int]$CompareContext = 3,
    [switch]$LlmRenames,
    [string]$LlmProvider = "",
    [string]$LlmApiKey = "",
    [string]$LlmBaseUrl = "",
    [string]$LlmModel = "",
    [string]$LlmCommand = "",
    [int]$LlmTimeout = 0,
    [string[]]$Ea = @(),
    [string]$EaFile = "",
    [string]$StartEa = "",
    [string]$EndEa = "",
    [string]$NameRegex = "",
    [switch]$Resume,
    [switch]$OverwriteForge,
    [switch]$UpsertForge,
    [switch]$SkipLibThunk,
    [switch]$StopOnError,
    [switch]$NoPdb,
    [switch]$NoAutoWait,
    [switch]$Visible,
    [switch]$NoWait,
    [switch]$NoSummary
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function ConvertTo-CommandLineArgument
{
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [switch]$AlwaysQuote
    )

    if (-not $AlwaysQuote -and $Value -notmatch '[\s"]')
    {
        return $Value
    }

    return '"' + ($Value -replace '"', '\"') + '"'
}

function Add-Option
{
    param(
        [Parameter(Mandatory = $true)][System.Collections.Generic.List[string]]$Args,
        [Parameter(Mandatory = $true)][string]$Name,
        [string]$Value = ""
    )

    $Args.Add($Name)
    if ($Value)
    {
        $Args.Add($Value)
    }
}

if (-not (Test-Path -LiteralPath $IdaPath))
{
    throw "IDA executable not found: $IdaPath"
}
if (-not (Test-Path -LiteralPath $IdbPath))
{
    throw "IDB path not found: $IdbPath"
}

$toolDir = Split-Path -Parent $PSCommandPath
$batchScript = Join-Path $toolDir "pseudoforge_ida_batch.py"
$summaryScript = Join-Path $toolDir "summarize_pseudoforge_ida_batch.py"
if (-not (Test-Path -LiteralPath $batchScript))
{
    throw "Batch script not found: $batchScript"
}

$stem = [System.IO.Path]::GetFileNameWithoutExtension($IdbPath)
$safeStem = $stem -replace '[^A-Za-z0-9_.-]', '_'
if (-not $OutputDir)
{
    $OutputDir = Join-Path $env:TEMP (Join-Path "pseudoforge_ida_batch" $safeStem)
}
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
if (-not $ForgePath)
{
    $ForgePath = Join-Path $OutputDir ($safeStem + ".forge")
}
if (-not $ReportPath)
{
    $ReportPath = Join-Path $OutputDir ($safeStem + "_" + $timestamp + ".jsonl")
}
if (-not $IdaLogPath)
{
    $IdaLogPath = Join-Path $OutputDir ($safeStem + "_" + $timestamp + "_ida.log")
}
if (-not $TargetPath)
{
    $TargetPath = $IdbPath
}

if (-not $Resume -and -not $PSBoundParameters.ContainsKey("OverwriteForge") -and -not $PSBoundParameters.ContainsKey("UpsertForge"))
{
    $OverwriteForge = $true
}

$scriptArgs = [System.Collections.Generic.List[string]]::new()
$scriptArgs.Add($batchScript)
Add-Option -Args $scriptArgs -Name "--report" -Value $ReportPath
Add-Option -Args $scriptArgs -Name "--forge-path" -Value $ForgePath
Add-Option -Args $scriptArgs -Name "--target-path" -Value $TargetPath
if ($CompareDir) { Add-Option -Args $scriptArgs -Name "--compare-dir" -Value $CompareDir }
if ($ProfileDir) { Add-Option -Args $scriptArgs -Name "--profile-dir" -Value $ProfileDir }
if ($CancelFile) { Add-Option -Args $scriptArgs -Name "--cancel-file" -Value $CancelFile }
if ($CompareContext -ne 3) { Add-Option -Args $scriptArgs -Name "--compare-context" -Value ([string]$CompareContext) }
if ($LlmRenames) { $scriptArgs.Add("--llm-renames") }
if ($LlmProvider) { Add-Option -Args $scriptArgs -Name "--llm-provider" -Value $LlmProvider }
if ($LlmApiKey) { Add-Option -Args $scriptArgs -Name "--llm-api-key" -Value $LlmApiKey }
if ($LlmBaseUrl) { Add-Option -Args $scriptArgs -Name "--llm-base-url" -Value $LlmBaseUrl }
if ($LlmModel) { Add-Option -Args $scriptArgs -Name "--llm-model" -Value $LlmModel }
if ($LlmCommand) { Add-Option -Args $scriptArgs -Name "--llm-command" -Value $LlmCommand }
if ($LlmTimeout -gt 0) { Add-Option -Args $scriptArgs -Name "--llm-timeout" -Value ([string]$LlmTimeout) }
if ($MaxFunctions -gt 0) { Add-Option -Args $scriptArgs -Name "--max-functions" -Value ([string]$MaxFunctions) }
if ($MaxSeconds -gt 0) { Add-Option -Args $scriptArgs -Name "--max-seconds" -Value ([string]$MaxSeconds) }
foreach ($item in $Ea)
{
    if ($item)
    {
        Add-Option -Args $scriptArgs -Name "--ea" -Value $item
    }
}
if ($EaFile) { Add-Option -Args $scriptArgs -Name "--ea-file" -Value $EaFile }
if ($StartEa) { Add-Option -Args $scriptArgs -Name "--start-ea" -Value $StartEa }
if ($EndEa) { Add-Option -Args $scriptArgs -Name "--end-ea" -Value $EndEa }
if ($NameRegex) { Add-Option -Args $scriptArgs -Name "--name-regex" -Value $NameRegex }
if ($Resume) { $scriptArgs.Add("--resume") }
if ($OverwriteForge) { $scriptArgs.Add("--overwrite-forge") }
if ($UpsertForge) { $scriptArgs.Add("--upsert-forge") }
if ($SkipLibThunk) { $scriptArgs.Add("--skip-lib-thunk") }
if ($StopOnError) { $scriptArgs.Add("--stop-on-error") }
if ($NoAutoWait) { $scriptArgs.Add("--no-auto-wait") }

$scriptCommand = ($scriptArgs | ForEach-Object { ConvertTo-CommandLineArgument $_ }) -join " "
$idaArgs = [System.Collections.Generic.List[string]]::new()
$idaArgs.Add("-A")
if ($NoPdb)
{
    $idaArgs.Add("-Opdb:off")
}
$idaArgs.Add("-L" + (ConvertTo-CommandLineArgument $IdaLogPath -AlwaysQuote))
$idaArgs.Add("-S" + (ConvertTo-CommandLineArgument $scriptCommand -AlwaysQuote))
$idaArgs.Add((ConvertTo-CommandLineArgument $IdbPath -AlwaysQuote))
$argumentLine = $idaArgs -join " "
$windowStyle = if ($Visible) { "Normal" } else { "Hidden" }

Write-Host "PseudoForge IDA batch"
Write-Host "  IDA:    $IdaPath"
Write-Host "  IDB:    $IdbPath"
Write-Host "  Forge:  $ForgePath"
if ($CompareDir)
{
    Write-Host "  Compare: $CompareDir"
}
if ($ProfileDir)
{
    Write-Host "  Profile:$ProfileDir"
}
if ($CancelFile)
{
    Write-Host "  Cancel: $CancelFile"
}
if ($LlmRenames)
{
    $llmLabel = if ($LlmProvider) { $LlmProvider } else { "configured provider" }
    Write-Host "  LLM:    enabled ($llmLabel)"
}
if ($NoPdb)
{
    Write-Host "  PDB:    disabled (-Opdb:off)"
}
Write-Host "  Report: $ReportPath"
Write-Host "  IDA log:$IdaLogPath"

function Invoke-IdaBatch
{
    param(
        [Parameter(Mandatory = $true)][string]$Reason
    )

    if ($Reason)
    {
        Write-Host "  Run:    $Reason"
    }
    $process = Start-Process -FilePath $IdaPath -ArgumentList $argumentLine -PassThru -WindowStyle $windowStyle
    Write-Host "  PID:    $($process.Id)"
    $process.WaitForExit()
    Write-Host "  Exit:   $($process.ExitCode)"
    return $process.ExitCode
}

$exitCode = 0
if ($NoWait)
{
    $process = Start-Process -FilePath $IdaPath -ArgumentList $argumentLine -PassThru -WindowStyle $windowStyle
    Write-Host "  PID:    $($process.Id)"
    return
}

$exitCode = Invoke-IdaBatch -Reason "initial"
if ($exitCode -ne 0 -and (Test-Path -LiteralPath $ReportPath) -and (Get-Item -LiteralPath $ReportPath).Length -eq 0)
{
    Write-Host "  Retry:  empty report after initial IDA load"
    $exitCode = Invoke-IdaBatch -Reason "retry"
}

if (-not $NoSummary -and (Test-Path -LiteralPath $summaryScript) -and (Test-Path -LiteralPath $ReportPath))
{
    python -B $summaryScript $ReportPath
}

exit $exitCode
