param(
    [Parameter(Mandatory=$true)][string]$InputPath,
    [string]$Label = 'ELKI_DS_L_V01.2_181106_MP',
    [string]$Ghidra = 'C:\Tools\ghidra_12.1.4_PUBLIC',
    [string]$Python = 'C:\Python314\python.exe',
    [string]$AlticeExport = ''
)
$ErrorActionPreference = 'Stop'
$workspace = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..\..')).Path
$f2 = Join-Path $workspace 'research\f2'
$inputFull = (Resolve-Path -LiteralPath $InputPath).Path
$safeLabel = [System.IO.Path]::GetFileNameWithoutExtension($Label) -replace '[^A-Za-z0-9_.-]','_'
$outDir = Join-Path $f2 (Join-Path 'work\ghidra\references' $safeLabel)
$reports = Join-Path $f2 'work\ghidra\alice_reports'
$inventory = Join-Path $reports 'reference_firmware_inventory.json'
$manifest = Join-Path $outDir 'manifest.json'

& $Python (Join-Path $PSScriptRoot 'prepare_f2_reference.py') --input $inputFull --out $outDir --ghidra $Ghidra --analyze
if ($LASTEXITCODE -ne 0) { throw "Reference extraction/Ghidra failed ($LASTEXITCODE). See $outDir" }
if (-not (Test-Path -LiteralPath $manifest)) { throw "Manifest missing: $manifest" }
if (-not (Test-Path -LiteralPath $inventory)) {
    & $Python (Join-Path $PSScriptRoot 'inventory_f2_reference.py')
    if ($LASTEXITCODE -ne 0) { throw "Firmware inventory failed ($LASTEXITCODE)" }
}
if (-not $AlticeExport) { $AlticeExport = Join-Path $reports 'altice_details.jsonl' }
if (-not (Test-Path -LiteralPath $AlticeExport)) { throw "Altice Ghidra export missing: $AlticeExport" }

$manifestData = Get-Content -LiteralPath $manifest -Raw -Encoding UTF8 | ConvertFrom-Json
$proximity = @()
foreach ($alice in $manifestData.alice) {
    if (-not $alice.functions_export) { continue }
    $dest = Join-Path $reports ($safeLabel + '_' + $alice.type + '_proximity.json')
    & $Python (Join-Path $PSScriptRoot 'compare_f2_reference.py') --witness $alice.functions_export `
        --altice $AlticeExport --out $dest --label $Label
    if ($LASTEXITCODE -ne 0) { throw "Proximity comparison failed ($LASTEXITCODE)" }
    $proximity += $dest
}
$reportArgs = @((Join-Path $PSScriptRoot 'build_f2_multimedia_report.py'), '--manifest',$manifest,
    '--inventory',$inventory,'--out',(Join-Path $reports 'f2_multimedia_reference_analysis.txt'))
foreach ($p in $proximity) { $reportArgs += @('--proximity',$p) }
& $Python @reportArgs
if ($LASTEXITCODE -ne 0) { throw "Reference report generation failed ($LASTEXITCODE)" }
Write-Host "Static offline analysis complete: $(Join-Path $reports 'f2_multimedia_reference_analysis.txt')"
