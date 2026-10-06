param(
    [string]$RepoRoot = "C:\Users\verto\F2-Altice-MobiWire",
    [string]$PythonExe = "C:\Users\verto\mtkclient\.venv\Scripts\python.exe",
    [string]$Inbox = "C:\Users\verto\Downloads",
    [string]$Branch = "s12-alice-extension",
    [string]$Remote = "",
    [int]$PollSeconds = 5,
    [switch]$Once,
    [switch]$NoPush
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Log([string]$Message) {
    $stamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    Write-Host "[$stamp] $Message"
}

function RepoPath([string]$Relative) {
    if ([string]::IsNullOrWhiteSpace($Relative)) { throw "Empty repository-relative path." }
    if ([IO.Path]::IsPathRooted($Relative)) { throw "Absolute path forbidden in job manifest: $Relative" }

    $root = [IO.Path]::GetFullPath($RepoRoot).TrimEnd('\') + '\'
    $full = [IO.Path]::GetFullPath((Join-Path $RepoRoot $Relative))
    if (-not $full.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Path escapes repository root: $Relative"
    }
    return $full
}

function Invoke-GitNative([string[]]$GitArgs, [switch]$AllowFailure) {
    & git.exe -C $RepoRoot @GitArgs
    $code = $LASTEXITCODE
    if (($code -ne 0) -and (-not $AllowFailure)) {
        throw "git $($GitArgs -join ' ') failed with exit code $code"
    }
    return $code
}

function Validate-Safety($Job) {
    if ($null -eq $Job.safety) { throw "Missing safety block." }
    if ($Job.safety.mode -ne "offline_analysis") {
        throw "Rejected: safety.mode must be offline_analysis."
    }

    foreach ($name in @("phone_access","flash_write","erase","repack")) {
        $p = $Job.safety.PSObject.Properties[$name]
        if ($null -eq $p) { throw "Rejected: missing safety.$name." }
        if ([bool]$p.Value) { throw "Rejected: safety.$name must be false." }
    }
}

function Try-Push {
    if ($NoPush) { return }

    & git.exe -C $RepoRoot push $Remote $Branch
    if ($LASTEXITCODE -eq 0) { return }

    Log "Push failed. Local automation commit is preserved."
    Log "No automatic pull/rebase is attempted because unrelated local changes may exist."
}

function Process-JobZip([IO.FileInfo]$ZipFile) {
    Log "Found job: $($ZipFile.Name)"

    $tempRoot = Join-Path $env:TEMP ("f2job_" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Force -Path $tempRoot | Out-Null

    try {
        Expand-Archive -LiteralPath $ZipFile.FullName -DestinationPath $tempRoot -Force

        $manifestPath = Join-Path $tempRoot "job.json"
        $scriptPath = Join-Path $tempRoot "script.py"

        if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
            throw "job.json missing from archive."
        }
        if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
            throw "script.py missing from archive."
        }

        $extra = @(Get-ChildItem -LiteralPath $tempRoot -Recurse -File |
            Where-Object { $_.FullName -ne $manifestPath -and $_.FullName -ne $scriptPath })
        if ($extra.Count -gt 0) {
            throw "Archive contains unexpected extra files."
        }

        $job = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        if ($job.schema_version -ne 1) { throw "Unsupported schema_version: $($job.schema_version)" }
        if (-not [bool]$job.enabled) { throw "Job is disabled." }
        if ([string]::IsNullOrWhiteSpace([string]$job.job_id)) { throw "Missing job_id." }

        Validate-Safety $job

        $jobId = [string]$job.job_id
        if ($jobId -notmatch '^[A-Za-z0-9._-]+$') {
            throw "Invalid job_id: $jobId"
        }

        $actualHash = (Get-FileHash -LiteralPath $scriptPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $expectedHash = ([string]$job.script_sha256).ToLowerInvariant()
        if ($expectedHash -notmatch '^[0-9a-f]{64}$') { throw "Invalid script_sha256." }
        if ($actualHash -ne $expectedHash) {
            throw "SHA256 mismatch. expected=$expectedHash actual=$actualHash"
        }

        $reportRel = [string]$job.report
        $reportNorm = $reportRel.Replace("/","\")
        if (-not $reportNorm.StartsWith("research\f2\work\reports\", [StringComparison]::OrdinalIgnoreCase)) {
            throw "Report path must be under research\f2\work\reports\"
        }

        $scriptRel = "research/f2/automation/jobs/$jobId.py"
        $manifestRel = "research/f2/automation/manifests/$jobId.job.json"
        $resultRel = "research/f2/automation/results/$jobId.result.json"

        $scriptRepo = RepoPath $scriptRel
        $manifestRepo = RepoPath $manifestRel
        $resultRepo = RepoPath $resultRel
        $reportRepo = RepoPath $reportRel

        if (Test-Path -LiteralPath $resultRepo -PathType Leaf) {
            Log "Already completed: $jobId"
            $doneDir = Join-Path $Inbox "F2AutomationDone"
            New-Item -ItemType Directory -Force -Path $doneDir | Out-Null
            Move-Item -LiteralPath $ZipFile.FullName -Destination (Join-Path $doneDir $ZipFile.Name) -Force
            return
        }

        foreach ($p in @($scriptRepo,$manifestRepo,$resultRepo,$reportRepo)) {
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $p) | Out-Null
        }

        Copy-Item -LiteralPath $scriptPath -Destination $scriptRepo -Force
        Copy-Item -LiteralPath $manifestPath -Destination $manifestRepo -Force

        $argsList = @()
        if ($null -ne $job.args) {
            foreach ($a in $job.args) { $argsList += [string]$a }
        }

        $started = (Get-Date).ToUniversalTime()
        $header = @(
            "========================================================================================================",
            "F2 AUTOMATION RUNNER",
            "========================================================================================================",
            "JOB ID          : $jobId",
            "SOURCE ZIP      : $($ZipFile.Name)",
            "SCRIPT SHA256   : $actualHash",
            "PYTHON          : $PythonExe",
            "BRANCH          : $Branch",
            "SAFETY MODE     : offline_analysis",
            "PHONE ACCESS    : false",
            "FLASH WRITE     : false",
            "ERASE           : false",
            "REPACK          : false",
            "START UTC       : $($started.ToString('o'))",
            "========================================================================================================",
            ""
        )
        Set-Content -LiteralPath $reportRepo -Value $header -Encoding UTF8

        Log "Executing $jobId"
        $previousOffline = $env:F2_AUTOMATION_OFFLINE
        $env:F2_AUTOMATION_OFFLINE = "1"

        Push-Location $RepoRoot
        try {
            & $PythonExe $scriptRepo @argsList 2>&1 |
                ForEach-Object { Add-Content -LiteralPath $reportRepo -Value $_ -Encoding UTF8; Write-Output $_ }
            $exitCode = $LASTEXITCODE
        }
        finally {
            Pop-Location
            $env:F2_AUTOMATION_OFFLINE = $previousOffline
        }

        $finished = (Get-Date).ToUniversalTime()
        Add-Content -LiteralPath $reportRepo -Value @(
            "",
            "========================================================================================================",
            "EXIT CODE        : $exitCode",
            "FINISH UTC       : $($finished.ToString('o'))",
            "========================================================================================================"
        ) -Encoding UTF8

        $result = [ordered]@{
            schema_version = 1
            job_id = $jobId
            status = $(if ($exitCode -eq 0) { "completed" } else { "failed" })
            exit_code = $exitCode
            script = $scriptRel
            script_sha256 = $actualHash
            manifest = $manifestRel
            report = $reportRel
            source_zip = $ZipFile.Name
            started_utc = $started.ToString("o")
            finished_utc = $finished.ToString("o")
            safety = [ordered]@{
                mode = "offline_analysis"
                phone_access = $false
                flash_write = $false
                erase = $false
                repack = $false
            }
        }
        $result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $resultRepo -Encoding UTF8

        Log "Completed $jobId with exit code $exitCode"
        Log "Report: $reportRepo"

        Invoke-GitNative @("add","--",$scriptRel,$manifestRel,$resultRel) | Out-Null
        Invoke-GitNative @("add","-f","--",$reportRel) | Out-Null
        & git.exe -C $RepoRoot diff --cached --quiet
        if ($LASTEXITCODE -ne 0) {
            Invoke-GitNative @("commit","-m","automation: $jobId (exit $exitCode)") | Out-Null
            Try-Push
        }

        $doneDir = Join-Path $Inbox "F2AutomationDone"
        New-Item -ItemType Directory -Force -Path $doneDir | Out-Null
        Move-Item -LiteralPath $ZipFile.FullName -Destination (Join-Path $doneDir $ZipFile.Name) -Force
    }
    finally {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if (-not (Test-Path -LiteralPath $RepoRoot -PathType Container)) {
    throw "RepoRoot does not exist: $RepoRoot"
}
if (-not (Test-Path -LiteralPath $PythonExe -PathType Leaf)) {
    throw "PythonExe does not exist: $PythonExe"
}
if (-not (Test-Path -LiteralPath $Inbox -PathType Container)) {
    throw "Inbox does not exist: $Inbox"
}
if (-not (Get-Command git.exe -ErrorAction SilentlyContinue)) {
    throw "git.exe was not found in PATH."
}

$mutex = New-Object Threading.Mutex($false,"Local\F2AlticeAutomationRunner")
if (-not $mutex.WaitOne(0)) {
    throw "Another F2 automation runner instance is already running."
}

try {
    $currentBranch = (& git.exe -C $RepoRoot rev-parse --abbrev-ref HEAD).Trim()
    if ($LASTEXITCODE -ne 0) { throw "Could not determine current git branch." }
    if ($currentBranch -ne $Branch) {
        throw "Wrong branch. Current=$currentBranch Expected=$Branch. Run: git -C `"$RepoRoot`" switch $Branch"
    }

    if ([string]::IsNullOrWhiteSpace($Remote)) {
        $upstream = (& git.exe -C $RepoRoot rev-parse --abbrev-ref --symbolic-full-name "@{u}" 2>$null)
        if ($LASTEXITCODE -eq 0 -and $upstream -match '^([^/]+)/') {
            $Remote = $Matches[1]
        } elseif ((& git.exe -C $RepoRoot remote) -contains "github") {
            $Remote = "github"
        } elseif ((& git.exe -C $RepoRoot remote) -contains "origin") {
            $Remote = "origin"
        } else {
            throw "Could not determine Git remote. Pass -Remote explicitly."
        }
    }

    Log "F2 automation runner started"
    Log "Repo   : $RepoRoot"
    Log "Inbox  : $Inbox"
    Log "Branch : $Branch"
    Log "Remote : $Remote"
    Log "Python : $PythonExe"
    Log "Safety : offline_analysis jobs only"
    Log "Local unrelated changes are preserved and are never staged automatically."

    do {
        # Fetch is safe with a dirty working tree and lets us verify staleness.
        & git.exe -C $RepoRoot fetch $Remote $Branch --quiet
        if ($LASTEXITCODE -ne 0) {
            Log "git fetch failed; skipping jobs this cycle."
        }
        else {
            $remoteRef = "$Remote/$Branch"
            $counts = (& git.exe -C $RepoRoot rev-list --left-right --count "HEAD...$remoteRef").Trim()
            $parts = $counts -split '\s+'
            $ahead = [int]$parts[0]
            $behind = [int]$parts[1]

            if ($behind -gt 0) {
                Log "Local branch is behind $remoteRef by $behind commit(s)."
                Log "Jobs are paused to avoid running against stale code. Resolve/update manually first."
            }
            else {
                if ($ahead -gt 0 -and (-not $NoPush)) {
                    Log "Local branch is ahead by $ahead commit(s); attempting push."
                    Try-Push
                }

                $jobs = @(Get-ChildItem -LiteralPath $Inbox -Filter "f2job_*.zip" -File |
                    Sort-Object CreationTime, Name)

                if ($jobs.Count -eq 0) {
                    Log "No new f2job_*.zip in Downloads."
                }

                foreach ($zip in $jobs) {
                    try {
                        Process-JobZip $zip
                    }
                    catch {
                        Log "JOB ERROR [$($zip.Name)]: $($_.Exception.Message)"
                        $failedDir = Join-Path $Inbox "F2AutomationFailed"
                        New-Item -ItemType Directory -Force -Path $failedDir | Out-Null
                        Move-Item -LiteralPath $zip.FullName -Destination (Join-Path $failedDir $zip.Name) -Force
                    }
                }
            }
        }

        if (-not $Once) {
            Start-Sleep -Seconds $PollSeconds
        }
    } while (-not $Once)
}
finally {
    try { $mutex.ReleaseMutex() | Out-Null } catch {}
    $mutex.Dispose()
}
