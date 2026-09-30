param(
    [string]$Ghidra = 'C:\Tools\ghidra_12.1.4_PUBLIC',
    [string]$Python = 'C:\Python314\python.exe'
)
$ErrorActionPreference = 'Stop'
$workspace = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..\..')).Path
$f2 = Join-Path $workspace 'research\f2'
$projects = Join-Path $f2 'work\ghidra\alice_projects'
$reports = Join-Path $f2 'work\ghidra\alice_reports'
$scripts = Join-Path $f2 'scripts\ghidra'
$headless = Join-Path $Ghidra 'support\analyzeHeadless.bat'
$qroots = @('103fe66a','10415c14','104323d4','102f13b6','10314ca8','103512f0','10408eda')
$aroots = @('10289d10','102c6f8c','102d82d0','10220344','1024ec0c','1027a1b0','1024a55c')

function Invoke-AnalysisTool {
    param([string]$Executable, [string[]]$ToolArguments)
    & $Executable @ToolArguments
    if ($LASTEXITCODE -ne 0) { throw "$Executable exited with $LASTEXITCODE" }
}

# Existing projects are always opened read-only. No binary export is performed.
Invoke-AnalysisTool $headless (@($projects,'QMobile_ALICE_Code','-process','alice-py.bin',
    '-readOnly','-noanalysis','-scriptPath',$scripts,'-postScript','ExportAliceDetails.java',
    (Join-Path $reports 'qmobile_details.jsonl')) + $qroots)
Invoke-AnalysisTool $headless (@($projects,'Altice_ALICE_Code','-process','alice-py.bin',
    '-readOnly','-noanalysis','-scriptPath',$scripts,'-postScript','ExportAliceDetails.java',
    (Join-Path $reports 'altice_details.jsonl')) + $aroots)

$normalizedRoots = @('103fe67c') + $qroots[1..6]
if (Test-Path -LiteralPath (Join-Path $projects 'QMobile_ALICE_Normalized.gpr')) {
    $normalizedArgs = @($projects,'QMobile_ALICE_Normalized','-process','alice-py.bin','-readOnly','-noanalysis')
} else {
    $normalizedArgs = @($projects,'QMobile_ALICE_Normalized','-import',(Join-Path $f2 'work\extracted\qmobile_alice\alice-py.bin'),
        '-loader','BinaryLoader','-loader-baseAddr','1018A598','-processor','ARM:LE:32:v5t','-cspec','default',
        '-preScript','AnalyzeAliceNormalized.java','103fe67c','10415c14','102f13b6','103512f0','10408eda')
}
Invoke-AnalysisTool $headless ($normalizedArgs + @('-scriptPath',$scripts,'-postScript','ExportAliceDetails.java',
    (Join-Path $reports 'qmobile_normalized_details.jsonl')) + $normalizedRoots)

Invoke-AnalysisTool $headless @($projects,'QMobile_ALICE_Normalized','-process','alice-py.bin',
    '-readOnly','-noanalysis','-scriptPath',$scripts,'-postScript','DecompileAliceTree.java',
    (Join-Path $reports 'qmobile_extra_trees.txt'),
    '10394dcc','102c4d2c','103aa774','103cabf4','103aa808','103b27f4','10394d80','102f6d08',
    '102ee9cc','10405164','10405978','102e0238','103512f0','1032b6d4','102bc944')

Invoke-AnalysisTool $Python @((Join-Path $PSScriptRoot 'analyze_alice_extra_calls.py'))
Invoke-AnalysisTool $Python @((Join-Path $PSScriptRoot 'match_alice_callees.py'))
Invoke-AnalysisTool $Python @((Join-Path $PSScriptRoot 'rank_alice_targets.py'),
    '10394dcc','10300eb4','1032668c','1032a9c4','1031ea94','10329cc0','1032af68','102c4d2c','1032b6d4','102bc944')
Invoke-AnalysisTool $Python @((Join-Path $PSScriptRoot 'verify_extra_call_evidence.py'))
Invoke-AnalysisTool $Python @((Join-Path $PSScriptRoot 'write_extra_call_report.py'))
