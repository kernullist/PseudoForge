[CmdletBinding()]
param(
    [string]$IdaPath = "",
    [string]$IdbPath = "",
    [string]$TargetPath = "",
    [string]$KernelCorpusRepo = "",
    [string]$ArtifactId = "",
    [string]$Build = "",
    [string]$Arch = "amd64",
    [int]$Revision = 2,
    [string]$WorkRoot = "",
    [string]$InstallRoot = "",
    [string]$GithubRepo = "",
    [string]$VolumeSize = "1900m",
    [string]$ProfileDir = "",
    [string]$PdbPath = "",
    [string]$SymbolPath = "",
    [int]$MaxFunctions = 0,
    [int]$MaxSeconds = 0,
    [string]$NameRegex = "",
    [string]$EaFile = "",
    [string]$StartEa = "",
    [string]$EndEa = "",
    [switch]$Resume,
    [switch]$SkipLibThunk,
    [switch]$StopOnError,
    [switch]$NoPdb,
    [switch]$Visible,
    [switch]$NoPackage,
    [switch]$CleanOutput,
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-EnvironmentValue
{
    param([Parameter(Mandatory = $true)][string]$Name)

    $value = [System.Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($value))
    {
        return ""
    }

    return $value
}

function Set-DefaultFromEnvironment
{
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if (-not [string]::IsNullOrWhiteSpace($Value))
    {
        return $Value
    }

    return Get-EnvironmentValue -Name $Name
}

function Resolve-RequiredPath
{
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$PathText,
        [Parameter(Mandatory = $true)][string]$Label,
        [string]$ParameterName = "",
        [string]$EnvironmentName = ""
    )

    if ([string]::IsNullOrWhiteSpace($PathText))
    {
        $message = "$Label is required."
        if ($ParameterName -and $EnvironmentName)
        {
            $message += " Pass -$ParameterName or set $EnvironmentName."
        }
        elseif ($ParameterName)
        {
            $message += " Pass -$ParameterName."
        }
        elseif ($EnvironmentName)
        {
            $message += " Set $EnvironmentName."
        }

        throw $message
    }

    if (-not (Test-Path -LiteralPath $PathText))
    {
        throw "$Label not found: $PathText"
    }

    return (Resolve-Path -LiteralPath $PathText).Path
}

function Get-SafeName
{
    param([Parameter(Mandatory = $true)][string]$Text)

    $safe = $Text -replace '[^A-Za-z0-9_.-]', '-'
    $safe = $safe.Trim(".-")
    if (-not $safe)
    {
        return "kernel-corpus"
    }

    return $safe
}

function Get-TargetPath
{
    param([Parameter(Mandatory = $true)][string]$ResolvedIdbPath)

    if ($TargetPath)
    {
        return (Resolve-RequiredPath -PathText $TargetPath -Label "Target binary" -ParameterName "TargetPath" -EnvironmentName "PSEUDOFORGE_TARGET_PATH")
    }

    $candidate = ""
    if ($ResolvedIdbPath.EndsWith(".i64", [System.StringComparison]::OrdinalIgnoreCase) -or
        $ResolvedIdbPath.EndsWith(".idb", [System.StringComparison]::OrdinalIgnoreCase))
    {
        $candidate = [System.IO.Path]::Combine(
            [System.IO.Path]::GetDirectoryName($ResolvedIdbPath),
            [System.IO.Path]::GetFileNameWithoutExtension($ResolvedIdbPath)
        )
    }

    if ($candidate -and (Test-Path -LiteralPath $candidate))
    {
        return (Resolve-Path -LiteralPath $candidate).Path
    }

    return $ResolvedIdbPath
}

function Get-ImageName
{
    param([Parameter(Mandatory = $true)][string]$ResolvedTargetPath)

    $name = [System.IO.Path]::GetFileName($ResolvedTargetPath)
    if (-not $name)
    {
        $name = [System.IO.Path]::GetFileNameWithoutExtension($IdbPath)
    }

    if ($name.EndsWith(".exe", [System.StringComparison]::OrdinalIgnoreCase) -or
        $name.EndsWith(".sys", [System.StringComparison]::OrdinalIgnoreCase) -or
        $name.EndsWith(".dll", [System.StringComparison]::OrdinalIgnoreCase))
    {
        $name = [System.IO.Path]::GetFileNameWithoutExtension($name)
    }

    return (Get-SafeName -Text $name).ToLowerInvariant()
}

function Get-BuildName
{
    param([Parameter(Mandatory = $true)][string]$ResolvedIdbPath)

    if ($Build)
    {
        return Get-SafeName -Text $Build
    }

    $parent = Split-Path -Leaf (Split-Path -Parent $ResolvedIdbPath)
    if ($parent -match '^\d+(?:\.\d+)+$')
    {
        return $parent
    }

    return "unknown-build"
}

function Invoke-NativeStep
{
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    Write-Host ""
    Write-Host "== $Name =="
    Write-Host $FilePath
    foreach ($arg in $Arguments)
    {
        Write-Host "  $arg"
    }

    & $FilePath @Arguments
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0)
    {
        throw "$Name failed with exit code $exitCode"
    }
}

function Invoke-NativeJsonStep
{
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$JsonOut
    )

    Write-Host ""
    Write-Host "== $Name =="
    Write-Host $FilePath
    foreach ($arg in $Arguments)
    {
        Write-Host "  $arg"
    }

    $output = & $FilePath @Arguments
    $exitCode = $LASTEXITCODE
    $text = ($output | Out-String).Trim()
    $jsonDir = Split-Path -Parent $JsonOut
    New-Item -ItemType Directory -Path $jsonDir -Force | Out-Null
    $text | Set-Content -LiteralPath $JsonOut -Encoding UTF8
    if ($exitCode -ne 0)
    {
        throw "$Name failed with exit code $exitCode"
    }

    return ($text | ConvertFrom-Json)
}

function Remove-GeneratedPath
{
    param(
        [Parameter(Mandatory = $true)][string]$Target,
        [Parameter(Mandatory = $true)][string]$AllowedRoot
    )

    if (-not (Test-Path -LiteralPath $Target))
    {
        return
    }

    $resolvedTarget = (Resolve-Path -LiteralPath $Target).Path
    $resolvedRoot = (Resolve-Path -LiteralPath $AllowedRoot).Path
    $separator = [System.IO.Path]::DirectorySeparatorChar
    $altSeparator = [System.IO.Path]::AltDirectorySeparatorChar
    $trimChars = [char[]]@($separator, $altSeparator)
    $normalizedTarget = $resolvedTarget.TrimEnd($trimChars)
    $normalizedRoot = $resolvedRoot.TrimEnd($trimChars)
    $rootPrefix = $normalizedRoot + $separator
    $comparison = [System.StringComparison]::OrdinalIgnoreCase

    if ([string]::Equals($normalizedTarget, $normalizedRoot, $comparison))
    {
        throw "Refusing to remove the work root itself: $resolvedTarget"
    }

    if (-not $normalizedTarget.StartsWith($rootPrefix, $comparison))
    {
        throw "Refusing to remove path outside work root: $resolvedTarget"
    }

    Remove-Item -LiteralPath $resolvedTarget -Recurse -Force
}

function Write-ReleaseNotes
{
    param(
        [Parameter(Mandatory = $true)][string]$OutputDir,
        [Parameter(Mandatory = $true)][string]$ResolvedArtifactId,
        [Parameter(Mandatory = $true)][string]$ResolvedPackRoot,
        [Parameter(Mandatory = $true)][string]$ResolvedCorpusRoot
    )

    $path = Join-Path $OutputDir "RELEASE_NOTES.md"
    $lines = @(
        "# $ResolvedArtifactId",
        "",
        "- Rebuilt from IDB: ``$IdbPath``",
        "- Kernel pack: ``$ResolvedPackRoot``",
        "- Raw corpus: ``$ResolvedCorpusRoot``",
        '- Pack schema: `kernel_corpus_pack_v2`',
        "- Includes function data references when IDA metadata can resolve them.",
        '- Includes per-function `function.disasm.asm` artifacts for pseudocode verification.',
        "",
        'Generated by `tools/rebuild_kernel_corpus_release.ps1`.'
    )
    $lines | Set-Content -LiteralPath $path -Encoding UTF8
}

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$python = "python"
$IdaPath = Set-DefaultFromEnvironment -Value $IdaPath -Name "PSEUDOFORGE_IDA_PATH"
$IdbPath = Set-DefaultFromEnvironment -Value $IdbPath -Name "PSEUDOFORGE_IDB_PATH"
$TargetPath = Set-DefaultFromEnvironment -Value $TargetPath -Name "PSEUDOFORGE_TARGET_PATH"
$KernelCorpusRepo = Set-DefaultFromEnvironment -Value $KernelCorpusRepo -Name "PSEUDOFORGE_KERNEL_CORPUS_REPO"
$ArtifactId = Set-DefaultFromEnvironment -Value $ArtifactId -Name "PSEUDOFORGE_KERNEL_CORPUS_ARTIFACT_ID"
$Build = Set-DefaultFromEnvironment -Value $Build -Name "PSEUDOFORGE_KERNEL_BUILD"
$WorkRoot = Set-DefaultFromEnvironment -Value $WorkRoot -Name "PSEUDOFORGE_KERNEL_CORPUS_WORK_ROOT"
$InstallRoot = Set-DefaultFromEnvironment -Value $InstallRoot -Name "PSEUDOFORGE_KERNEL_CORPUS_INSTALL_ROOT"
$GithubRepo = Set-DefaultFromEnvironment -Value $GithubRepo -Name "PSEUDOFORGE_KERNEL_CORPUS_GITHUB_REPO"
$PdbPath = Set-DefaultFromEnvironment -Value $PdbPath -Name "PSEUDOFORGE_PDB_PATH"
$SymbolPath = Set-DefaultFromEnvironment -Value $SymbolPath -Name "PSEUDOFORGE_SYMBOL_PATH"
if (-not $GithubRepo)
{
    $GithubRepo = "kernullist/kernel-corpus"
}
if (-not $SymbolPath)
{
    $SymbolPath = Get-EnvironmentValue -Name "_NT_SYMBOL_PATH"
}

$resolvedIdaPath = Resolve-RequiredPath -PathText $IdaPath -Label "IDA executable" -ParameterName "IdaPath" -EnvironmentName "PSEUDOFORGE_IDA_PATH"
$resolvedIdbPath = Resolve-RequiredPath -PathText $IdbPath -Label "IDB path" -ParameterName "IdbPath" -EnvironmentName "PSEUDOFORGE_IDB_PATH"
$resolvedTargetPath = Get-TargetPath -ResolvedIdbPath $resolvedIdbPath
$resolvedKernelCorpusRepo = Resolve-RequiredPath -PathText $KernelCorpusRepo -Label "Kernel Corpus repo" -ParameterName "KernelCorpusRepo" -EnvironmentName "PSEUDOFORGE_KERNEL_CORPUS_REPO"
$resolvedBuild = Get-BuildName -ResolvedIdbPath $resolvedIdbPath
$resolvedImageName = Get-ImageName -ResolvedTargetPath $resolvedTargetPath
$resolvedArch = Get-SafeName -Text $Arch
if (-not $ArtifactId)
{
    $ArtifactId = "$resolvedImageName-$resolvedBuild-$resolvedArch-r$Revision"
}
$ArtifactId = Get-SafeName -Text $ArtifactId

if (-not $WorkRoot)
{
    $WorkRoot = Join-Path $repoRoot "pseudoforge_out\kernel_corpus_builds"
}
$resolvedWorkRoot = [System.IO.Path]::GetFullPath($WorkRoot)
if (-not $InstallRoot)
{
    $InstallRoot = Join-Path ([System.Environment]::GetFolderPath("UserProfile")) "pseudoforge-corpora"
}
$runRoot = Join-Path $resolvedWorkRoot $ArtifactId
$corpusRoot = Join-Path $runRoot "raw-corpus"
$packRoot = Join-Path $runRoot "kernel-pack"
$logsRoot = Join-Path $runRoot "logs"
$releaseRoot = Join-Path $resolvedKernelCorpusRepo "release"
$packageJson = Join-Path $logsRoot "package-release-result.json"
$buildJson = Join-Path $logsRoot "builder-result.json"
$statusJson = Join-Path $logsRoot "corpus-status.json"
$dataRefSmokeJson = Join-Path $logsRoot "data-ref-smoke.json"
$mcpConfigJson = Join-Path $logsRoot "mcp-config.json"
$validationText = Join-Path $logsRoot "validate-pack.txt"

New-Item -ItemType Directory -Path $resolvedWorkRoot -Force | Out-Null
if ($CleanOutput)
{
    Remove-GeneratedPath -Target $runRoot -AllowedRoot $resolvedWorkRoot
}
New-Item -ItemType Directory -Path $corpusRoot -Force | Out-Null
New-Item -ItemType Directory -Path $packRoot -Force | Out-Null
New-Item -ItemType Directory -Path $logsRoot -Force | Out-Null
New-Item -ItemType Directory -Path $releaseRoot -Force | Out-Null

$plan = [ordered]@{
    artifact_id = $ArtifactId
    ida_path = $resolvedIdaPath
    idb_path = $resolvedIdbPath
    target_path = $resolvedTargetPath
    work_root = $resolvedWorkRoot
    corpus_root = $corpusRoot
    pack_root = $packRoot
    kernel_corpus_repo = $resolvedKernelCorpusRepo
    release_root = $releaseRoot
    install_pack_root = (Join-Path (Join-Path $InstallRoot $ArtifactId) "kernel-pack")
    dry_run = [bool]$DryRun
}
$planPath = Join-Path $logsRoot "rebuild-plan.json"
($plan | ConvertTo-Json -Depth 5) | Set-Content -LiteralPath $planPath -Encoding UTF8

Write-Host "Kernel Corpus rebuild plan"
Write-Host "  Artifact: $ArtifactId"
Write-Host "  IDA:      $resolvedIdaPath"
Write-Host "  IDB:      $resolvedIdbPath"
Write-Host "  Target:   $resolvedTargetPath"
Write-Host "  Corpus:   $corpusRoot"
Write-Host "  Pack:     $packRoot"
Write-Host "  Release:  $releaseRoot"
Write-Host "  Plan:     $planPath"

$idaCliArgs = @(
    "-B",
    (Join-Path $repoRoot "tools\pseudoforge_ida_cli.py"),
    $resolvedIdaPath,
    $resolvedIdbPath,
    $corpusRoot,
    "--target-path",
    $resolvedTargetPath,
    "--no-llm-renames",
    "--allow-no-llm"
)
if ($ProfileDir)
{
    $idaCliArgs += @("--profile-dir", (Resolve-RequiredPath -PathText $ProfileDir -Label "Profile dir"))
}
if ($MaxFunctions -gt 0)
{
    $idaCliArgs += @("--max-functions", [string]$MaxFunctions)
}
if ($MaxSeconds -gt 0)
{
    $idaCliArgs += @("--max-seconds", [string]$MaxSeconds)
}
if ($NameRegex)
{
    $idaCliArgs += @("--name-regex", $NameRegex)
}
if ($EaFile)
{
    $idaCliArgs += @("--ea-file", (Resolve-RequiredPath -PathText $EaFile -Label "EA file"))
}
if ($StartEa)
{
    $idaCliArgs += @("--start-ea", $StartEa)
}
if ($EndEa)
{
    $idaCliArgs += @("--end-ea", $EndEa)
}
if ($Resume)
{
    $idaCliArgs += "--resume"
}
if ($SkipLibThunk)
{
    $idaCliArgs += "--skip-lib-thunk"
}
if ($StopOnError)
{
    $idaCliArgs += "--stop-on-error"
}
if ($Visible)
{
    $idaCliArgs += "--visible"
}
if ($NoPdb)
{
    $idaCliArgs += "--no-pdb"
}
else
{
    if ($PdbPath -and (Test-Path -LiteralPath $PdbPath))
    {
        $idaCliArgs += @("--pdb-path", (Resolve-Path -LiteralPath $PdbPath).Path)
    }
    elseif ($PdbPath)
    {
        Write-Host "Warning: PDB path not found, continuing without --pdb-path: $PdbPath"
    }
    if ($SymbolPath)
    {
        $idaCliArgs += @("--symbol-path", $SymbolPath)
    }
}
if ($DryRun)
{
    $idaCliArgs += "--dry-run"
}

Invoke-NativeStep -Name "IDA corpus export" -FilePath $python -Arguments $idaCliArgs
if ($DryRun)
{
    Write-Host ""
    Write-Host "Dry run complete. Pack build and release package were skipped."
    exit 0
}

$indexPath = Join-Path $corpusRoot "pseudoforge-corpus-index.json"
if (-not (Test-Path -LiteralPath $indexPath))
{
    throw "Corpus index was not produced: $indexPath"
}

$builderArgs = @(
    "-B",
    (Join-Path $repoRoot "tools\kernel_corpus\builder.py"),
    "--corpus-root",
    $corpusRoot,
    "--pack-root",
    $packRoot,
    "--overwrite",
    "--json"
)
Invoke-NativeJsonStep -Name "Build Kernel Corpus pack" -FilePath $python -Arguments $builderArgs -JsonOut $buildJson | Out-Null

$validateArgs = @(
    "-B",
    (Join-Path $repoRoot "tools\kernel_corpus\validate_pack.py"),
    "--pack-root",
    $packRoot,
    "--include-derived",
    "--format",
    "text"
)
Write-Host ""
Write-Host "== Validate Kernel Corpus pack =="
& $python @validateArgs 2>&1 | Tee-Object -FilePath $validationText
if ($LASTEXITCODE -ne 0)
{
    throw "validate_pack.py failed with exit code $LASTEXITCODE"
}

$statusArgs = @(
    "-B",
    (Join-Path $repoRoot "tools\kernel_corpus\query.py"),
    "status",
    "--pack-root",
    $packRoot
)
Invoke-NativeJsonStep -Name "Write corpus status" -FilePath $python -Arguments $statusArgs -JsonOut $statusJson | Out-Null

$dataRefSmokeArgs = @(
    "-B",
    (Join-Path $repoRoot "tools\kernel_corpus\query.py"),
    "search-data-ref",
    "--pack-root",
    $packRoot,
    "--query",
    "PsProcessType",
    "--limit",
    "10"
)
Invoke-NativeJsonStep -Name "Write data-ref smoke query" -FilePath $python -Arguments $dataRefSmokeArgs -JsonOut $dataRefSmokeJson | Out-Null

$mcpArgs = @(
    "-B",
    (Join-Path $repoRoot "tools\kernel_corpus\install_wiring.py"),
    "mcp-config",
    "--pack-root",
    $packRoot
)
Invoke-NativeJsonStep -Name "Write MCP config snippet" -FilePath $python -Arguments $mcpArgs -JsonOut $mcpConfigJson | Out-Null

if (-not $NoPackage)
{
    $commit = ""
    try
    {
        $commit = (& git -C $repoRoot rev-parse HEAD).Trim()
    }
    catch
    {
        $commit = ""
    }

    $packageArgs = @(
        "-B",
        (Join-Path $repoRoot "tools\kernel_corpus\package_release.py"),
        "--pack-root",
        $packRoot,
        "--source-corpus-root",
        $corpusRoot,
        "--artifact-id",
        $ArtifactId,
        "--output-dir",
        $releaseRoot,
        "--github-repo",
        $GithubRepo,
        "--install-root",
        $InstallRoot,
        "--volume-size",
        $VolumeSize
    )
    if ($commit)
    {
        $packageArgs += @("--pseudoforge-commit", $commit)
    }

    $packageResult = Invoke-NativeJsonStep -Name "Package Kernel Corpus release assets" -FilePath $python -Arguments $packageArgs -JsonOut $packageJson
    Write-ReleaseNotes -OutputDir ([string]$packageResult.output_dir) -ResolvedArtifactId $ArtifactId -ResolvedPackRoot $packRoot -ResolvedCorpusRoot $corpusRoot
    Write-Host ""
    Write-Host "Package output: $($packageResult.output_dir)"
    Write-Host "Release command:"
    Write-Host $packageResult.release_command
}

Write-Host ""
Write-Host "Kernel Corpus rebuild complete"
Write-Host "  Pack root:       $packRoot"
Write-Host "  Corpus root:     $corpusRoot"
Write-Host "  Validation:      $validationText"
Write-Host "  Status JSON:     $statusJson"
Write-Host "  Data-ref smoke:  $dataRefSmokeJson"
Write-Host "  MCP config JSON: $mcpConfigJson"
if (-not $NoPackage)
{
    Write-Host "  Package JSON:    $packageJson"
}
