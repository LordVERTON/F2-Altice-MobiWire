param(
    [string]$RepoRoot = "C:\Users\verto\F2-Altice-MobiWire",
    [string]$PythonExe = "C:\Users\verto\mtkclient\.venv\Scripts\python.exe",
    [string]$Inbox = "C:\Users\verto\Downloads",
    [string]$Branch = "automate-research",
    [string]$Remote = "github",
    [ValidateRange(1,3600)][int]$PollSeconds = 5,
    [switch]$Once,
    [switch]$NoPush
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
# Only commits created in this process may be automatically rebased/pushed.
$script:OwnedCommits = @{}
$script:HadJobError = $false

function Log([string]$Message) {
    Write-Host "[$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))] $Message"
}
function Invoke-GitNative([string[]]$GitArgs) {
    $output = @(& git.exe -C $RepoRoot @GitArgs)
    if ($LASTEXITCODE -ne 0) { throw "git $($GitArgs -join ' ') failed with exit code $LASTEXITCODE" }
    return $output
}
function GitText([string[]]$GitArgs) {
    return ((Invoke-GitNative $GitArgs) -join "`n").Trim()
}
function Test-Clean {
    return [string]::IsNullOrEmpty((GitText @('status','--porcelain','--untracked-files=all')))
}
function Assert-Branch {
    if ((GitText @('rev-parse','--abbrev-ref','HEAD')) -cne $Branch) { throw "Wrong branch; expected $Branch." }
    foreach ($state in @('MERGE_HEAD','CHERRY_PICK_HEAD','REVERT_HEAD','rebase-merge','rebase-apply')) {
        $statePath = GitText @('rev-parse','--git-path',$state)
        if (-not [IO.Path]::IsPathRooted($statePath)) { $statePath = Join-Path $RepoRoot $statePath }
        if (Test-Path -LiteralPath $statePath) { throw "Unfinished Git operation: $state. Resolve manually." }
    }
}
function RepoPath([string]$Relative, [string]$Prefix, [string]$Extension = '') {
    if ([string]::IsNullOrWhiteSpace($Relative) -or [IO.Path]::IsPathRooted($Relative)) { throw 'Expected repository-relative path.' }
    $normal = $Relative.Replace('\','/')
    if ($normal -match '[:*?\[\]]' -or @($normal.Split('/') | Where-Object { $_ -in @('','.', '..') }).Count -gt 0) { throw "Unsafe path: $Relative" }
    $root = [IO.Path]::GetFullPath($RepoRoot).TrimEnd('\','/')
    $full = [IO.Path]::GetFullPath((Join-Path $root $normal))
    $allowed = [IO.Path]::GetFullPath((Join-Path $root $Prefix)).TrimEnd('\','/') + [IO.Path]::DirectorySeparatorChar
    if (-not $full.StartsWith($allowed,[StringComparison]::OrdinalIgnoreCase)) { throw "Path must be under $Prefix : $Relative" }
    if ($Extension -and [IO.Path]::GetExtension($full) -cne $Extension) { throw "Expected $Extension : $Relative" }
    $cursor = $full
    while ($cursor -and $cursor.Length -ge $root.Length) {
        if (Test-Path -LiteralPath $cursor) {
            if (((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Reparse point forbidden: $cursor" }
        }
        $cursor = Split-Path -Parent $cursor
    }
    return $full
}
function Assert-Committed([string]$Relative) {
    $blob = GitText @('rev-parse',"HEAD:$Relative")
    $workingBlob = GitText @('hash-object','--',$Relative)
    if ($blob -cne $workingBlob) { throw "File differs from committed HEAD: $Relative" }
}
function Validate-Safety($Job) {
    if ($Job.safety.mode -cne 'offline_analysis') { throw 'Rejected: safety.mode must be offline_analysis.' }
    foreach ($name in @('phone_access','flash_write','erase','repack')) {
        $property = $Job.safety.PSObject.Properties[$name]
        if ($null -eq $property -or $property.Value -isnot [bool] -or $property.Value -ne $false) { throw "Rejected: safety.$name must be JSON false." }
    }
}
function Prepare-Job([string]$ManifestPath, [string]$Source, [string]$ZipScript = '') {
    $job = Get-Content -LiteralPath $ManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($job.job_id -isnot [string] -or $job.job_id -cnotmatch '^[A-Za-z0-9._-]+$') { throw 'Invalid job_id.' }
    $jobId = $job.job_id
    $resultRel = "research/f2/automation/results/$jobId.result.json"
    $resultPath = RepoPath $resultRel 'research/f2/automation/results'
    if (Test-Path -LiteralPath $resultPath) { Log "Receipt exists; skipping $jobId"; return $null }
    if ($job.schema_version -ne 1) { throw 'Unsupported schema_version.' }
    if ($job.enabled -isnot [bool]) { throw 'enabled must be a JSON boolean.' }
    if (-not $job.enabled) { Log "Disabled job: $jobId"; return $null }
    Validate-Safety $job
    $argsList = @()
    if ($job.args -isnot [Array]) { throw 'args must be a JSON array of strings.' }
    foreach ($argument in $job.args) {
        if ($argument -isnot [string] -or $argument.Contains([char]0)) { throw 'args must contain strings without NUL.' }
        $argsList += $argument
    }
    $scriptRel = "research/f2/automation/jobs/$jobId.py"
    $manifestRel = "research/f2/automation/manifests/$jobId.job.json"
    if ($Source -eq 'repo_queue') {
        $scriptRel = [string]$job.script
        $manifestRel = "research/f2/automation/queue/$jobId.job.json"
        $expectedManifest = RepoPath $manifestRel 'research/f2/automation/queue' '.json'
        if ([IO.Path]::GetFullPath($ManifestPath) -cne $expectedManifest) { throw 'Manifest filename must match job_id.' }
        Assert-Committed $manifestRel
    }
    $scriptRepo = RepoPath $scriptRel 'research/f2/automation/jobs' '.py'
    $manifestRepo = RepoPath $manifestRel $(if ($Source -eq 'repo_queue') { 'research/f2/automation/queue' } else { 'research/f2/automation/manifests' }) '.json'
    $reportRel = [string]$job.report
    $reportRepo = RepoPath $reportRel 'research/f2/work/reports'
    $scriptPath = $scriptRepo
    if ($Source -eq 'zip') { $scriptPath = $ZipScript } else { Assert-Committed $scriptRel }
    if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) { throw "Script missing: $scriptRel" }
    if ($job.script_sha256 -isnot [string] -or $job.script_sha256 -cnotmatch '^[a-fA-F0-9]{64}$') { throw 'Invalid script_sha256.' }
    $actualHash = (Get-FileHash -LiteralPath $scriptPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -cne $job.script_sha256.ToLowerInvariant()) { throw 'SHA256 mismatch.' }
    if (Test-Path -LiteralPath $reportRepo) { throw "Existing report without receipt; preserving $reportRel" }
    if ($Source -eq 'zip' -and ((Test-Path -LiteralPath $scriptRepo) -or (Test-Path -LiteralPath $manifestRepo))) { throw 'ZIP would overwrite an existing script/manifest; use a new job_id.' }
    return [pscustomobject]@{
        Id = $jobId; Source = $Source; Script = $scriptRel; ScriptPath = $scriptRepo
        Manifest = $manifestRel; ManifestPath = $manifestRepo; InputManifest = $ManifestPath
        InputScript = $scriptPath; Report = $reportRel; ReportPath = $reportRepo
        Result = $resultRel; ResultPath = $resultPath; Hash = $actualHash; Arguments = $argsList
    }
}
function Get-Counts {
    $parts = (GitText @('rev-list','--left-right','--count',"HEAD...$Remote/$Branch")) -split '\s+'
    return @([int]$parts[0], [int]$parts[1])
}
function Assert-OwnedAhead {
    foreach ($sha in @(Invoke-GitNative @('rev-list',"$Remote/$Branch..HEAD"))) {
        if (-not $script:OwnedCommits.ContainsKey($sha)) { throw "Local commit $sha is not owned by this runner session; manual synchronization required." }
    }
}
function Try-Push {
    if ($NoPush) { return }
    Assert-Branch
    if (-not (Test-Clean)) { throw 'Push blocked: working tree is dirty. Local result is preserved.' }
    Assert-OwnedAhead
    & git.exe -C $RepoRoot push $Remote $Branch
    if ($LASTEXITCODE -eq 0) { return }
    Log 'Push failed; preserving local result commit and fetching remote.'
    Invoke-GitNative @('fetch',$Remote,$Branch) | Out-Null
    Assert-Branch
    if (-not (Test-Clean)) { throw 'Rebase blocked: working tree is dirty.' }
    Assert-OwnedAhead
    $counts = Get-Counts
    if ($counts[1] -gt 0) {
        Invoke-GitNative @('-c','rebase.autoStash=false','pull','--rebase',$Remote,$Branch) | Out-Null
        $script:OwnedCommits.Clear()
        foreach ($sha in @(Invoke-GitNative @('rev-list',"$Remote/$Branch..HEAD"))) { $script:OwnedCommits[$sha] = $true }
    }
    Invoke-GitNative @('push',$Remote,$Branch) | Out-Null
}
function Sync-Repository {
    Assert-Branch
    Invoke-GitNative @('fetch',$Remote,$Branch,'--quiet') | Out-Null
    $counts = Get-Counts
    if (-not (Test-Clean)) { Log 'BLOCKED: working tree is dirty; no pull, rebase or jobs.'; return $false }
    if ($counts[0] -gt 0) {
        Assert-OwnedAhead
        if ($NoPush -and $counts[1] -gt 0) { throw 'Diverged with NoPush; manual synchronization required.' }
        Try-Push
        $counts = Get-Counts
    }
    if ($counts[1] -gt 0) {
        Invoke-GitNative @('-c','rebase.autoStash=false','pull','--ff-only',$Remote,$Branch) | Out-Null
        Log 'Remote advancement integrated with --ff-only.'
    }
    return $true
}
function Execute-Job($Context) {
    Assert-Branch
    if (-not (Test-Clean)) { throw 'Execution blocked: working tree is dirty.' }
    $c = $Context
    $baseHead = GitText @('rev-parse','HEAD')
    $stagePaths = @($c.Report, $c.Result)
    if ($c.Source -eq 'zip') { $stagePaths += @($c.Script,$c.Manifest) }
    foreach ($path in @($c.ReportPath,$c.ResultPath,$c.ScriptPath,$c.ManifestPath)) { New-Item -ItemType Directory -Force -Path (Split-Path -Parent $path) | Out-Null }
    if ($c.Source -eq 'zip') {
        Copy-Item -LiteralPath $c.InputScript -Destination $c.ScriptPath
        Copy-Item -LiteralPath $c.InputManifest -Destination $c.ManifestPath
    }
    if ((Get-FileHash -LiteralPath $c.ScriptPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $c.Hash) { throw 'Script changed after validation.' }
    $started = (Get-Date).ToUniversalTime()
    Set-Content -LiteralPath $c.ReportPath -Encoding UTF8 -Value @(
        '========================================================================================================', 'F2 AUTOMATION RUNNER',
        "JOB ID          : $($c.Id)", "SOURCE          : $($c.Source)",
        "SCRIPT          : $($c.Script)", "SCRIPT SHA256   : $($c.Hash)",
        "PYTHON          : $PythonExe", "BRANCH          : $Branch",
        'SAFETY MODE     : offline_analysis', 'PHONE ACCESS    : false', 'FLASH WRITE     : false',
        'ERASE           : false', 'REPACK          : false', "START UTC       : $($started.ToString('o'))", ''
    )
    Log "Executing $($c.Source): $($c.Id)"
    $previousOffline = $env:F2_AUTOMATION_OFFLINE
    $env:F2_AUTOMATION_OFFLINE = '1'
    Push-Location $RepoRoot
    try {
        $argsList = @($c.Arguments)
        # PS 5.1 wraps native stderr in ErrorRecord objects; retain text and exit code.
        $savedPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            & $PythonExe $c.ScriptPath @argsList 2>&1 | ForEach-Object {
                Add-Content -LiteralPath $c.ReportPath -Value $_.ToString() -Encoding UTF8 -ErrorAction Stop
                Write-Host $_.ToString()
            }
            $exitCode = $LASTEXITCODE
        } finally { $ErrorActionPreference = $savedPreference }
    } finally {
        Pop-Location
        $env:F2_AUTOMATION_OFFLINE = $previousOffline
    }
    $finished = (Get-Date).ToUniversalTime()
    Add-Content -LiteralPath $c.ReportPath -Encoding UTF8 -Value @('',"EXIT CODE        : $exitCode","FINISH UTC       : $($finished.ToString('o'))")
    [ordered]@{
        schema_version = 1; job_id = $c.Id; status = $(if ($exitCode -eq 0) { 'completed' } else { 'failed' })
        exit_code = $exitCode; source = $c.Source; script = $c.Script; script_sha256 = $c.Hash
        manifest = $c.Manifest; report = $c.Report; source_commit = $baseHead
        started_utc = $started.ToString('o'); finished_utc = $finished.ToString('o')
        safety = [ordered]@{ mode = 'offline_analysis'; phone_access = $false; flash_write = $false; erase = $false; repack = $false }
    } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $c.ResultPath -Encoding UTF8
    Assert-Branch
    if ((GitText @('rev-parse','HEAD')) -cne $baseHead) { throw 'HEAD changed during execution; result preserved, no commit.' }
    if (GitText @('diff','--cached','--name-only')) { throw 'Index changed during execution; preserving state.' }
    $changed = @(Invoke-GitNative @('diff','--name-only'))
    $changed += @(Invoke-GitNative @('ls-files','--others','--exclude-standard'))
    foreach ($path in $changed) {
        if ($path -cnotin $stagePaths) { throw "Unexpected job modification: $path. Result preserved, no commit." }
    }
    Invoke-GitNative (@('add','-f','--') + $stagePaths) | Out-Null
    Invoke-GitNative @('commit','-m',"automation: $($c.Id) (exit $exitCode)") | Out-Null
    $sha = GitText @('rev-parse','HEAD')
    $script:OwnedCommits[$sha] = $true
    Log "Result committed: $sha (exit $exitCode)"
    Try-Push
}
function Process-Queue {
    $queueDir = Join-Path $RepoRoot 'research/f2/automation/queue'
    if (-not (Test-Path -LiteralPath $queueDir)) { return }
    $jobs = @(Get-ChildItem -LiteralPath $queueDir -Filter '*.job.json' -File | Sort-Object Name)
    foreach ($manifest in $jobs) {
        try { $context = Prepare-Job $manifest.FullName 'repo_queue' }
        catch { Log "REJECTED [$($manifest.Name)]: $($_.Exception.Message)"; $script:HadJobError = $true; continue }
        if ($null -ne $context) { Execute-Job $context }
    }
}
function Archive-Zip([IO.FileInfo]$ZipFile, [string]$Directory) {
    $destinationDir = Join-Path $Inbox $Directory
    New-Item -ItemType Directory -Force -Path $destinationDir | Out-Null
    $destination = Join-Path $destinationDir $ZipFile.Name
    if (Test-Path -LiteralPath $destination) { $destination = Join-Path $destinationDir (([guid]::NewGuid().ToString('N')) + '_' + $ZipFile.Name) }
    Move-Item -LiteralPath $ZipFile.FullName -Destination $destination
}
function Process-JobZip([IO.FileInfo]$ZipFile) {
    $tempParent = [IO.Path]::GetFullPath($env:TEMP).TrimEnd('\','/')
    $tempRoot = Join-Path $tempParent ('f2job_' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tempRoot | Out-Null
    try {
        try {
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            $archive = [IO.Compression.ZipFile]::OpenRead($ZipFile.FullName)
            try {
                $names = @($archive.Entries | ForEach-Object { $_.FullName })
                if ($names.Count -ne 2 -or @($names | Where-Object { $_ -ceq 'job.json' }).Count -ne 1 -or @($names | Where-Object { $_ -ceq 'script.py' }).Count -ne 1) { throw 'ZIP must contain exactly job.json and script.py.' }
            } finally { $archive.Dispose() }
            Expand-Archive -LiteralPath $ZipFile.FullName -DestinationPath $tempRoot
            $context = Prepare-Job (Join-Path $tempRoot 'job.json') 'zip' (Join-Path $tempRoot 'script.py')
        } catch {
            Log "ZIP REJECTED [$($ZipFile.Name)]: $($_.Exception.Message)"
            $script:HadJobError = $true
            Archive-Zip $ZipFile 'F2AutomationFailed'
            return
        }
        if ($null -ne $context) { Execute-Job $context }
        Archive-Zip $ZipFile 'F2AutomationDone'
    } finally {
        $resolvedTemp = [IO.Path]::GetFullPath($tempRoot)
        if ((Split-Path -Parent $resolvedTemp) -ne $tempParent -or (Split-Path -Leaf $resolvedTemp) -notmatch '^f2job_[a-f0-9]{32}$') { throw 'Unsafe temp cleanup path.' }
        Remove-Item -LiteralPath $resolvedTemp -Recurse -Force
    }
}
if (-not (Test-Path -LiteralPath $RepoRoot -PathType Container)) { throw "RepoRoot does not exist: $RepoRoot" }
if ($PythonExe -ine 'C:\Users\verto\mtkclient\.venv\Scripts\python.exe') { throw 'Only the canonical Python executable is permitted.' }
if (-not (Test-Path -LiteralPath $PythonExe -PathType Leaf)) { throw "PythonExe does not exist: $PythonExe" }
if (-not (Test-Path -LiteralPath $Inbox -PathType Container)) { throw "Inbox does not exist: $Inbox" }
if (-not (Get-Command git.exe -ErrorAction SilentlyContinue)) { throw 'git.exe missing from PATH.' }
$RepoRoot = [IO.Path]::GetFullPath($RepoRoot)
$mutex = New-Object Threading.Mutex($false,'Local\F2AlticeAutomationRunner')
if (-not $mutex.WaitOne(0)) { $mutex.Dispose(); throw 'Another F2 automation runner instance is already running.' }
try {
    Log 'F2 automation runner started'
    Log "Repo   : $RepoRoot"
    Log "Inbox  : $Inbox"
    Log "Branch : $Branch"
    Log "Remote : $Remote"
    Log "Python : $PythonExe"
    Log 'Safety : offline_analysis jobs only; repo queue first, ZIP fallback second'
    do {
        if (Sync-Repository) {
            Process-Queue
            $jobs = @(Get-ChildItem -LiteralPath $Inbox -Filter 'f2job_*.zip' -File | Sort-Object CreationTime,Name)
            if ($jobs.Count -eq 0) { Log 'No new f2job_*.zip in Downloads.' }
            foreach ($zip in $jobs) { Process-JobZip $zip }
        }
        if (-not $Once) { Start-Sleep -Seconds $PollSeconds }
    } while (-not $Once)
} finally {
    try { $mutex.ReleaseMutex() } finally { $mutex.Dispose() }
}
if ($script:HadJobError) { exit 1 }
