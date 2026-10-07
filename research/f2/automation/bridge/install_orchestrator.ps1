param([switch]$StartNow)
$ErrorActionPreference = 'Stop'
$taskName = 'F2 Research Orchestrator'
$repo = 'C:\Users\verto\F2-Altice-MobiWire'
$python = 'C:\Users\verto\mtkclient\.venv\Scripts\python.exe'
$script = Join-Path $PSScriptRoot 'research_orchestrator.py'
$branch = & git.exe -C $repo branch --show-current
if ($LASTEXITCODE -ne 0 -or $branch -ne 'automate-research') { throw 'Wrong branch.' }
$dirty = & git.exe -C $repo status --porcelain --untracked-files=all
if ($LASTEXITCODE -ne 0 -or $dirty) { throw 'Working tree must be clean.' }
& $python (Join-Path $repo 'research\f2\automation\tests\test_orchestrator.py')
if ($LASTEXITCODE -ne 0) { throw 'Offline tests failed; installation refused.' }
& $python $script --check
if ($LASTEXITCODE -ne 0) { throw 'Preflight failed; installation refused.' }
$argument = '"' + $script + '"'
$existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($existing -and ($existing.Actions.Execute -ne $python -or $existing.Actions.Arguments -ne $argument)) {
    throw 'Existing task differs; refusing to overwrite.'
}
if ($existing -and $existing.State -eq 'Running') { Write-Host 'Orchestrator already running; installation unchanged.'; exit 0 }
$user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$action = New-ScheduledTaskAction -Execute $python -Argument $argument -WorkingDirectory $repo
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1)
$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 20) -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'Deterministic one-minute polling; one bounded Codex call per completed offline result.' -Force | Out-Null
$stopFile = Join-Path $PSScriptRoot 'ORCHESTRATOR_STOP'
if (Test-Path -LiteralPath $stopFile) { Remove-Item -LiteralPath $stopFile }
if ($StartNow) { Start-ScheduledTask -TaskName $taskName }
Write-Host 'F2 Research Orchestrator: installed. Existing worker unchanged.'
