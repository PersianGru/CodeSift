<#
.SYNOPSIS
    Install (or uninstall) CodeSift for the current user. No admin rights needed.

.DESCRIPTION
    Creates %USERPROFILE%\.codesift (venv, checksum-verified scanners, rules, command shim), installs
    the Claude Code skill /sift and a default config. Asks before it adds the shim folder to your
    user PATH and before it copies Bifrost credentials (the copy gets a user-only ACL).

.EXAMPLE
    ./install.ps1
    ./install.ps1 -AddToPath -CredentialsFrom C:\path\to\bifrost.env
    ./install.ps1 -Uninstall            # keeps runs and credentials
    ./install.ps1 -Uninstall -Purge     # removes everything
#>
[CmdletBinding()]
param(
    [switch]$AddToPath,
    [string]$CredentialsFrom = "",
    [switch]$NoSkill,
    [switch]$Uninstall,
    [switch]$Purge,
    [switch]$Yes  # non-interactive: never prompt (PATH/credentials only with the explicit switches)
)
$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot

function Find-Python {
    $candidates = @(@("py", "-3.13"), @("py", "-3.12"), @("py", "-3.11"), @("python"), @("python3"))
    foreach ($c in $candidates) {
        $exe = $c[0]
        $rest = @($c | Select-Object -Skip 1)
        if (-not (Get-Command $exe -ErrorAction SilentlyContinue)) { continue }
        try {
            $ok = & $exe @rest -c "import sys; print(sys.version_info >= (3, 11))" 2>$null
            if ($LASTEXITCODE -eq 0 -and $ok -eq "True") { return , $c }
        } catch { }
    }
    throw "Python 3.11 or newer was not found. Install it from https://www.python.org/ and re-run."
}

$py = Find-Python
$pyExe = $py[0]
$pyArgs = @($py | Select-Object -Skip 1)
$env:PYTHONPATH = Join-Path $Root "src"
$home_ = if ($env:CODESIFT_HOME) { $env:CODESIFT_HOME } else { Join-Path $env:USERPROFILE ".codesift" }
$bin = Join-Path $home_ "bin"
$configDir = if ($env:CODESIFT_CONFIG) { $env:CODESIFT_CONFIG } else { Join-Path $home_ "config" }

if ($Uninstall) {
    $a = @("-m", "codesift", "uninstall")
    if ($Purge) { $a += "--purge" }
    & $pyExe @pyArgs @a
    exit $LASTEXITCODE
}

$installArgs = @("-m", "codesift", "install")
if ($NoSkill) { $installArgs += "--no-skill" }

$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
$onPath = $false
if ($userPath) { $onPath = ($userPath -split ";") -contains $bin }
if ($AddToPath) {
    $installArgs += "--add-to-path"
} elseif (-not $onPath -and -not $Yes) {
    $answer = Read-Host "Add $bin to your user PATH so 'sift' works in every terminal? [y/N]"
    if ($answer -match "^[yY]") { $installArgs += "--add-to-path" }
}

$credFile = Join-Path $configDir "bifrost.env"
if ($CredentialsFrom) {
    $installArgs += @("--credentials-from", $CredentialsFrom)
} elseif (-not (Test-Path $credFile) -and -not $Yes) {
    Write-Host "LLM triage needs Bifrost credentials (BIFROST_BASE_URL, BIFROST_API_KEY)."
    $src = Read-Host "Path of an env file to copy them from (Enter to skip; values are never shown)"
    if ($src) { $installArgs += @("--credentials-from", $src) }
}

& $pyExe @pyArgs @installArgs
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host ""
Write-Host "Next: open a new terminal and run 'sift doctor', then 'sift scan' in any project."
Write-Host "In Claude Code: /sift"
