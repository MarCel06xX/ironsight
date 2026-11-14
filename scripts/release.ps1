<#
.SYNOPSIS
    Builds Ironsight and publishes a GitHub release with the NSIS installer, a portable zip
    and SHA256SUMS.txt.

.DESCRIPTION
    The version comes from src-tauri/tauri.conf.json; src-tauri/Cargo.toml and package.json
    must contain the same version. Aborts if the working tree is dirty, HEAD is not pushed,
    or the tag or release already exists. Release notes list the commits since the last tag.
    Works with Windows PowerShell 5.1 and PowerShell 7.

.PARAMETER NoPublish
    Only run the checks, build and collect the files in release/ - no tag, no GitHub release.

.EXAMPLE
    .\scripts\release.ps1
.EXAMPLE
    .\scripts\release.ps1 -NoPublish
#>
[CmdletBinding()]
param(
    [switch]$NoPublish
)

Set-StrictMode -Version Latest
# Native tools (cargo, npm) report progress on stderr; their exit codes are checked instead.
$ErrorActionPreference = 'Continue'

$Target = 'x86_64-pc-windows-msvc'
$Repo = Split-Path -Parent $PSScriptRoot

function Fail([string]$Message) {
    throw $Message
}

function Step([string]$Name) {
    Write-Host ''
    Write-Host "==> $Name" -ForegroundColor Cyan
}

# Runs a native command and aborts on a non-zero exit code.
function Invoke-Native([string]$Name, [scriptblock]$Command) {
    & $Command
    if ($LASTEXITCODE -ne 0) { Fail "$Name failed (exit code $LASTEXITCODE)" }
}

# Returns the trimmed stdout of a native command; aborts on a non-zero exit code.
function Get-NativeOutput([string]$Name, [scriptblock]$Command) {
    $output = & $Command
    if ($LASTEXITCODE -ne 0) { Fail "$Name failed (exit code $LASTEXITCODE)" }
    return (@($output) -join "`n").Trim()
}

function Write-Utf8File([string]$Path, [string]$Text) {
    [IO.File]::WriteAllText($Path, $Text, (New-Object Text.UTF8Encoding $false))
}

function Get-Version {
    $conf = Get-Content -Raw -Encoding UTF8 'src-tauri/tauri.conf.json' | ConvertFrom-Json
    $version = [string]$conf.version
    if ($version -notmatch '^\d+\.\d+\.\d+$') { Fail "unexpected version '$version' in tauri.conf.json" }

    $npmVersion = [string](Get-Content -Raw -Encoding UTF8 'package.json' | ConvertFrom-Json).version
    $cargoLine = Select-String -Path 'src-tauri/Cargo.toml' -Pattern '^version\s*=\s*"([^"]+)"' |
        Select-Object -First 1
    $cargoVersion = if ($cargoLine) { $cargoLine.Matches[0].Groups[1].Value } else { '' }
    if ($npmVersion -ne $version -or $cargoVersion -ne $version) {
        Fail ("versions differ: tauri.conf.json $version, package.json $npmVersion, " +
            "Cargo.toml $cargoVersion - keep them in sync")
    }
    return $version
}

function Assert-CleanTree([string]$When) {
    $dirty = Get-NativeOutput 'git status' { git status --porcelain }
    if ($dirty) { Fail "working tree is not clean $When`n$dirty" }
}

function Assert-Publishable([string]$Tag) {
    Invoke-Native 'git fetch' { git fetch --quiet --tags origin }
    $null = git rev-parse -q --verify "refs/tags/$Tag"
    if ($LASTEXITCODE -eq 0) { Fail "tag $Tag already exists" }

    $head = Get-NativeOutput 'git rev-parse' { git rev-parse HEAD }
    $upstream = git rev-parse '@{u}' 2>$null
    if ($LASTEXITCODE -ne 0 -or $upstream -ne $head) {
        Fail 'HEAD is not pushed to its upstream branch - push first'
    }

    $null = gh release view $Tag 2>$null
    if ($LASTEXITCODE -eq 0) { Fail "GitHub release $Tag already exists" }
}

function Invoke-Checks {
    Push-Location 'src-tauri'
    try {
        Invoke-Native 'cargo fmt' { cargo fmt --check }
        Invoke-Native 'cargo clippy' { cargo clippy --all-targets --locked -- -D warnings }
        Invoke-Native 'cargo test' { cargo test --locked }
    } finally {
        Pop-Location
    }
    Invoke-Native 'npm typecheck' { npm run typecheck }
}

# Copies the installer, builds the portable zip and writes SHA256SUMS.txt.
function New-ReleaseFiles([string]$Version, [string]$ReleaseDir) {
    if (Test-Path $ReleaseDir) { Remove-Item $ReleaseDir -Recurse -Force -ErrorAction Stop }
    New-Item -ItemType Directory $ReleaseDir -ErrorAction Stop | Out-Null

    $buildDir = Join-Path $Repo "src-tauri/target/$Target/release"
    $installerName = "Ironsight_${Version}_x64-setup.exe"
    $installer = Join-Path $buildDir "bundle/nsis/$installerName"
    if (-not (Test-Path $installer)) { Fail "installer not found: $installer" }
    Copy-Item $installer $ReleaseDir -ErrorAction Stop

    $staging = Join-Path $ReleaseDir 'portable-staging'
    New-Item -ItemType Directory $staging -ErrorAction Stop | Out-Null
    Copy-Item (Join-Path $buildDir 'ironsight.exe') (Join-Path $staging 'Ironsight.exe') -ErrorAction Stop
    New-Item -ItemType File (Join-Path $staging 'portable') -ErrorAction Stop | Out-Null
    Copy-Item 'LICENSE-MIT', 'LICENSE-APACHE' $staging -ErrorAction Stop
    Copy-Item 'scripts/portable-readme.txt' (Join-Path $staging 'README.txt') -ErrorAction Stop

    $zipName = "Ironsight_${Version}_x64-portable.zip"
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::CreateFromDirectory(
        $staging, (Join-Path $ReleaseDir $zipName), [IO.Compression.CompressionLevel]::Optimal, $false)
    Remove-Item $staging -Recurse -Force -ErrorAction Stop

    # Same format as `sha256sum`, so `sha256sum -c SHA256SUMS.txt` works too.
    $sums = foreach ($name in $installerName, $zipName) {
        $hash = (Get-FileHash -Algorithm SHA256 (Join-Path $ReleaseDir $name)).Hash.ToLowerInvariant()
        "$hash  $name"
    }
    Write-Utf8File (Join-Path $ReleaseDir 'SHA256SUMS.txt') (($sums -join "`n") + "`n")
    return @($installerName, $zipName, 'SHA256SUMS.txt')
}

function New-ReleaseNotes([string]$Version, [string]$Path) {
    $previous = git describe --tags --abbrev=0 2>$null
    if ($LASTEXITCODE -ne 0) { $previous = $null }
    if ($previous) {
        $commits = Get-NativeOutput 'git log' { git log "$previous..HEAD" --no-merges --pretty=format:'- %s' }
        $heading = "## Changes since $previous"
    } else {
        $commits = Get-NativeOutput 'git log' { git log --no-merges --pretty=format:'- %s' }
        $heading = '## Changes'
    }
    $template = @'
__HEADING__

__COMMITS__

## Downloads

| File | Description |
| --- | --- |
| `Ironsight___VERSION___x64-setup.exe` | Installer - installs for the current user, no administrator rights needed |
| `Ironsight___VERSION___x64-portable.zip` | Portable - unzip and run `Ironsight.exe`; settings stay in `data/` next to it |
| `SHA256SUMS.txt` | SHA-256 checksums of both files |

Requires Windows 10/11 (x64) with the Microsoft Edge WebView2 runtime (part of Windows 11; the installer downloads it if missing).
The binaries are not code-signed, so Windows SmartScreen may show a warning. Verify a download with
`Get-FileHash <file> -Algorithm SHA256` and compare the result with `SHA256SUMS.txt`.

> Only scan networks you own or are explicitly authorized to scan.
'@
    $notes = $template.Replace('__HEADING__', $heading).Replace('__COMMITS__', $commits).Replace('__VERSION__', $Version)
    Write-Utf8File $Path $notes
}

function Main {
    Step 'Version'
    $version = Get-Version
    $tag = "v$version"
    Write-Host "Version $version (tag $tag)"

    Step 'Repository state'
    Assert-CleanTree 'before the release'
    if (-not $NoPublish) { Assert-Publishable $tag }

    Step 'Checks: fmt, clippy, tests, typecheck'
    Invoke-Checks

    Step "Build: NSIS installer, $Target"
    Invoke-Native 'tauri build' { npm run tauri build '--' --bundles nsis --target $Target }

    Step 'Collect release files'
    $releaseDir = Join-Path $Repo 'release'
    $files = New-ReleaseFiles $version $releaseDir
    $notesPath = Join-Path $releaseDir 'RELEASE_NOTES.md'
    New-ReleaseNotes $version $notesPath
    Get-Content (Join-Path $releaseDir 'SHA256SUMS.txt') | Write-Host

    if ($NoPublish) {
        Write-Host ''
        Write-Host "Done without publishing. Files are in $releaseDir" -ForegroundColor Green
        return
    }

    Step "Tag $tag"
    Assert-CleanTree 'after the build'
    Invoke-Native 'git tag' { git tag -a $tag -m "Ironsight $version" }
    Invoke-Native 'git push tag' { git push origin $tag }

    Step 'GitHub release'
    $assets = $files | ForEach-Object { Join-Path $releaseDir $_ }
    Invoke-Native 'gh release create' {
        gh release create $tag @assets --title "Ironsight $version" --notes-file $notesPath --verify-tag
    }
    $url = Get-NativeOutput 'gh release view' { gh release view $tag --json url --jq .url }
    Write-Host ''
    Write-Host "Released: $url" -ForegroundColor Green
}

$exitCode = 0
$previousEncoding = [Console]::OutputEncoding
Push-Location $Repo
try {
    # Decode git output (commit subjects) as UTF-8.
    [Console]::OutputEncoding = New-Object Text.UTF8Encoding $false
    Main
} catch {
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    $exitCode = 1
} finally {
    [Console]::OutputEncoding = $previousEncoding
    Pop-Location
}
exit $exitCode
