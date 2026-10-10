# Run a single offline F2 audit and, only on explicit -Publish, publish only its script.
# Usage: .\run-f2-audit.ps1 -Name s13_5a121_boot_postselect_target_cfg_audit -Expected BOOT_ZIMAGE_GUARD=PASS,A120_LITERAL_GUARD=PASS,TARGET_PREFIX_CLASSIFIED=YES -Publish
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-zA-Z0-9_]+$')][string]$Name,
    [string]$Root = 'C:\Users\verto\F2-Altice-MobiWire',
    [string]$Python = 'C:\Users\verto\mtkclient\.venv\Scripts\python.exe',
    [string]$Boot = 'C:\Users\verto\mtkclient\research\f2\work\extracted\altice_platform\boot_zimage.bin',
    [string[]]$Expected = @(),
    [switch]$Publish
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
function Assert-OK([string]$Description) {
    if ($LASTEXITCODE -ne 0) { throw "ABORT: $Description (exit $LASTEXITCODE)" }
}
$Rel = "research/f2/scripts/analysis/$Name.py"
$Script = Join-Path $Root $Rel
$Report = Join-Path $Root "research/f2/work/reports/$Name.txt"
foreach ($p in @($Root, $Python, $Script, $Boot)) {
    if (!(Test-Path -LiteralPath $p)) { throw "ABORT: absent: $p" }
}
Set-Location -LiteralPath $Root
if ((git branch --show-current) -ne 'main') { throw 'ABORT: branche main requise' }
& $Python -B $Script --self-test; Assert-OK 'self-test'
if (!(Test-Path -LiteralPath $Report)) {
    & $Python -B $Script --root $Root --boot $Boot --out $Report
    Assert-OK 'audit'
} else {
    Write-Host "Rapport existant preserve: $Report"
}
$Text = [IO.File]::ReadAllText($Report)
foreach ($needle in $Expected) {
    if (!$Text.Contains($needle)) { throw "ABORT: preuve absente du rapport: $needle" }
}
Write-Host "Rapport: $Report" -ForegroundColor Green
Get-Content -LiteralPath $Report | Select-String 'GUARD=|TARGET=|CALL=|BRANCH=|EXIT=|LITERAL=|NOTES=|CLASSIFIED=|NEXT='
if (!$Publish) { Write-Host 'Lecture seule terminee (sans commit/push).'; return }
if ($Expected.Count -eq 0) { throw 'ABORT: -Publish necessite -Expected pour valider le rapport' }
$staged = @(git diff --cached --name-only); Assert-OK 'git index'
if ($staged.Count -gt 0) { throw 'ABORT: index Git non vide' }
& git fetch origin main; Assert-OK 'git fetch'
$Local = (git rev-parse HEAD).Trim(); Assert-OK 'local SHA'
$Remote = (git rev-parse refs/remotes/origin/main).Trim(); Assert-OK 'remote SHA'
if ($Local -eq $Remote) {
    $tracked = @(git ls-files -- $Rel); Assert-OK 'git ls-files'
    if ($tracked.Count -gt 0) {
        # Existing, tracked, unchanged file: never create a duplicate commit.
        & git diff --quiet HEAD -- $Rel; Assert-OK 'tracked audit script has uncommitted changes'
        Write-Host 'Script deja versionne et identique a HEAD : aucun commit necessaire.' -ForegroundColor Yellow
    } else {
        & git add -- $Rel; Assert-OK 'git add'
        $files = @(git diff --cached --name-only); Assert-OK 'git staged names'
        if ($files.Count -ne 1 -or $files[0].Trim() -ne $Rel) { throw 'ABORT: index inattendu' }
        & git diff --cached --check; Assert-OK 'git diff check'
        & git commit -m "research(f2): add $Name offline audit"; Assert-OK 'git commit'
    }
} else {
    $Base = (git merge-base origin/main HEAD).Trim(); Assert-OK 'merge base'
    $Ahead = [int](git rev-list --count origin/main..HEAD); Assert-OK 'ahead'
    $Files = @(git diff-tree --no-commit-id --name-only -r HEAD); Assert-OK 'last commit files'
    $Msg = (git log -1 --format=%s).Trim(); Assert-OK 'last commit message'
    if ($Base -ne $Remote -or $Ahead -ne 1 -or $Files.Count -ne 1 -or $Files[0].Trim() -ne $Rel -or !$Msg.Contains($Name)) {
        throw 'ABORT: divergence Git ou commit local inattendu'
    }
}
$Commit = (git rev-parse HEAD).Trim(); Assert-OK 'commit SHA'
if ($Commit -eq $Remote) {
    Write-Host 'GitHub main deja synchronise : aucun push necessaire.' -ForegroundColor Green
    git log -1 --oneline
    git status --short
    return
}
& git push origin main
if ($LASTEXITCODE -ne 0) {
    $Line = @(git ls-remote origin refs/heads/main); Assert-OK 'remote confirmation'
    if ($Line.Count -ne 1 -or ($Line[0] -split '\s+')[0] -ne $Commit) { throw 'ABORT: push non confirme; ne pas refaire le commit' }
}
Write-Host 'TERMINE' -ForegroundColor Green
git log -1 --oneline
git status --short
