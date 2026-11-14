<#
.SYNOPSIS
    Builds Ironsight and publishes a GitHub release: NSIS installer (+ updater signature),
    portable exe, SHA256SUMS.txt and latest.json for the in-app updater.

.DESCRIPTION
    The version comes from src-tauri/tauri.conf.json; src-tauri/Cargo.toml and package.json
    must contain the same version. Aborts if the working tree is dirty, HEAD is not pushed,
    the tag or release already exists, or the signing key is missing.

    The updater signing key is expected at %USERPROFILE%\.tauri\ironsight.key (no password).
    The script only passes its path to the Tauri CLI; it never reads the private key.

    Works with Windows PowerShell 5.1 and PowerShell 7.

.PARAMETER NoPublish
    Only run the checks, build and write the files to release/ - no tag, no GitHub release.

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
$KeyPath = Join-Path $env:USERPROFILE '.tauri\ironsight.key'
$PublicKeyPath = "$KeyPath.pub"

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

# PowerShell removes a variable when it is set to ''; the Tauri CLI needs it to exist with an
# empty value (key without password), so it is set through the Win32 API.
function Set-ProcessEnvironment([string]$Name, [string]$Value) {
    if (-not ('Ironsight.NativeEnvironment' -as [type])) {
        Add-Type -Namespace Ironsight -Name NativeEnvironment -MemberDefinition @'
[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern bool SetEnvironmentVariable(string name, string value);
'@
    }
    if (-not [Ironsight.NativeEnvironment]::SetEnvironmentVariable($Name, $Value)) {
        Fail "could not set environment variable $Name"
    }
}

function Read-Config {
    return Get-Content -Raw -Encoding UTF8 'src-tauri/tauri.conf.json' | ConvertFrom-Json
}

function Get-Version($Config) {
    $version = [string]$Config.version
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

# Base URL of the GitHub repository, taken from the updater endpoint in tauri.conf.json.
function Get-RepoUrl($Config) {
    $endpoint = [string]@($Config.plugins.updater.endpoints)[0]
    $suffix = '/releases/latest/download/latest.json'
    if (-not $endpoint.StartsWith('https://github.com/') -or -not $endpoint.EndsWith($suffix)) {
        Fail "unexpected updater endpoint '$endpoint'"
    }
    return $endpoint.Substring(0, $endpoint.Length - $suffix.Length)
}

function Assert-SigningKey($Config) {
    if (-not (Test-Path -PathType Leaf $KeyPath)) { Fail "signing key not found: $KeyPath" }
    if (-not (Test-Path -PathType Leaf $PublicKeyPath)) { Fail "public key not found: $PublicKeyPath" }
    $publicKey = (Get-Content -Raw $PublicKeyPath).Trim()
    if ([string]$Config.plugins.updater.pubkey -ne $publicKey) {
        Fail "plugins.updater.pubkey in tauri.conf.json does not match $PublicKeyPath"
    }
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
        Invoke-Native 'cargo clippy (portable)' {
            cargo clippy --all-targets --locked --features portable -- -D warnings
        }
        Invoke-Native 'cargo test' { cargo test --locked }
    } finally {
        Pop-Location
    }
    Invoke-Native 'npm typecheck' { npm run typecheck }
}

# Commit subjects since the previous tag, as a Markdown list.
function Get-ChangeList {
    $previous = git describe --tags --abbrev=0 2>$null
    if ($LASTEXITCODE -ne 0) { $previous = $null }
    $range = if ($previous) { "$previous..HEAD" } else { 'HEAD' }
    $commits = Get-NativeOutput 'git log' { git log $range --no-merges --pretty=format:'- %s' }
    return @{ Previous = $previous; Commits = $commits }
}

function New-ReleaseNotes([string]$Version, $Changes, [string]$Path) {
    $heading = if ($Changes.Previous) { "## Changes since $($Changes.Previous)" } else { '## Changes' }
    $template = @'
__HEADING__

__COMMITS__

## Downloads

| File | Description |
| --- | --- |
| `Ironsight___VERSION___x64-setup.exe` | Installer - installs for the current user, no administrator rights needed; updates itself |
| `Ironsight___VERSION___x64-portable.exe` | Portable - a single exe; settings are stored in `ironsight-settings.json` next to it |
| `SHA256SUMS.txt` | SHA-256 checksums of both files |
| `latest.json`, `*.sig` | Used by the in-app updater |

Requires Windows 10/11 (x64) with the Microsoft Edge WebView2 runtime (part of Windows 11; the installer downloads it if missing).
The binaries are not code-signed, so Windows SmartScreen may show a warning. Verify a download with
`Get-FileHash <file> -Algorithm SHA256` and compare the result with `SHA256SUMS.txt`.

> Only scan networks you own or are explicitly authorized to scan.
'@
    $notes = $template.Replace('__HEADING__', $heading).Replace('__COMMITS__', $Changes.Commits).Replace('__VERSION__', $Version)
    Write-Utf8File $Path $notes
}

function Build-Portable([string]$Destination) {
    Invoke-Native 'tauri build (portable)' {
        npm run tauri build '--' --no-bundle --features portable --target $Target
    }
    $exe = Join-Path $Repo "src-tauri/target/$Target/release/ironsight.exe"
    if (-not (Test-Path $exe)) { Fail "portable exe not found: $exe" }
    Copy-Item $exe $Destination -ErrorAction Stop
}

function Build-Installer([string]$InstallerName, [string]$ReleaseDir) {
    $env:TAURI_SIGNING_PRIVATE_KEY = $KeyPath
    Set-ProcessEnvironment 'TAURI_SIGNING_PRIVATE_KEY_PASSWORD' ''
    try {
        Invoke-Native 'tauri build (installer)' {
            npm run tauri build '--' --bundles nsis --target $Target --ci
        }
    } finally {
        Remove-Item Env:TAURI_SIGNING_PRIVATE_KEY -ErrorAction SilentlyContinue
        Remove-Item Env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD -ErrorAction SilentlyContinue
    }
    $bundleDir = Join-Path $Repo "src-tauri/target/$Target/release/bundle/nsis"
    foreach ($name in $InstallerName, "$InstallerName.sig") {
        $file = Join-Path $bundleDir $name
        if (-not (Test-Path $file)) { Fail "build output not found: $file" }
        Copy-Item $file $ReleaseDir -ErrorAction Stop
    }
}

function Write-Checksums([string]$ReleaseDir, [string[]]$Names) {
    # Same format as `sha256sum`, so `sha256sum -c SHA256SUMS.txt` works too.
    $lines = foreach ($name in $Names) {
        $hash = (Get-FileHash -Algorithm SHA256 (Join-Path $ReleaseDir $name)).Hash.ToLowerInvariant()
        "$hash  $name"
    }
    Write-Utf8File (Join-Path $ReleaseDir 'SHA256SUMS.txt') (($lines -join "`n") + "`n")
}

# Static update manifest for tauri-plugin-updater.
function Write-UpdateManifest([string]$Version, [string]$Notes, [string]$Url, [string]$SignaturePath, [string]$Path) {
    $manifest = [ordered]@{
        version   = $Version
        notes     = $Notes
        pub_date  = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        platforms = [ordered]@{
            'windows-x86_64' = [ordered]@{
                signature = (Get-Content -Raw $SignaturePath).Trim()
                url       = $Url
            }
        }
    }
    Write-Utf8File $Path (($manifest | ConvertTo-Json -Depth 5) + "`n")
}

function Main {
    Step 'Version'
    $config = Read-Config
    $version = Get-Version $config
    $repoUrl = Get-RepoUrl $config
    $tag = "v$version"
    Write-Host "Version $version (tag $tag), repository $repoUrl"

    Step 'Repository state and signing key'
    Assert-CleanTree 'before the release'
    Assert-SigningKey $config
    if (-not $NoPublish) { Assert-Publishable $tag }

    Step 'Checks: fmt, clippy, tests, typecheck'
    Invoke-Checks

    $releaseDir = Join-Path $Repo 'release'
    if (Test-Path $releaseDir) { Remove-Item $releaseDir -Recurse -Force -ErrorAction Stop }
    New-Item -ItemType Directory $releaseDir -ErrorAction Stop | Out-Null
    $installerName = "Ironsight_${version}_x64-setup.exe"
    $portableName = "Ironsight_${version}_x64-portable.exe"

    # Both builds share the target dir: portable first, then the installer.
    Step "Build: portable exe ($Target)"
    Build-Portable (Join-Path $releaseDir $portableName)

    Step "Build: NSIS installer with updater signature ($Target)"
    Build-Installer $installerName $releaseDir

    Step 'Checksums, update manifest, release notes'
    Write-Checksums $releaseDir @($installerName, $portableName)
    $changes = Get-ChangeList
    $notesPath = Join-Path $releaseDir 'RELEASE_NOTES.md'
    New-ReleaseNotes $version $changes $notesPath
    Write-UpdateManifest $version $changes.Commits "$repoUrl/releases/download/$tag/$installerName" `
        (Join-Path $releaseDir "$installerName.sig") (Join-Path $releaseDir 'latest.json')
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
    $assets = @($installerName, "$installerName.sig", $portableName, 'SHA256SUMS.txt', 'latest.json') |
        ForEach-Object { Join-Path $releaseDir $_ }
    # A normal, latest release: releases/latest/download/latest.json must point to it.
    Invoke-Native 'gh release create' {
        gh release create $tag @assets --title "Ironsight $version" --notes-file $notesPath --verify-tag --latest
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
