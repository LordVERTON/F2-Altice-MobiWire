param([switch]$StartNow)
$ErrorActionPreference = 'Stop'
$taskName = 'F2 Notion Automation Worker'
$repo = 'C:\Users\verto\F2-Altice-MobiWire'
$python = 'C:\Users\verto\mtkclient\.venv\Scripts\python.exe'
$worker = Join-Path $repo 'research\f2\automation\bridge\notion_worker.py'
$config = Join-Path $PSScriptRoot 'config.local.json'
if (-not (Test-Path -LiteralPath $config)) {
    $value = Get-Content (Join-Path $PSScriptRoot 'config.example.json') -Raw | ConvertFrom-Json
    $value.worker_host = [Environment]::MachineName
    $value.queue_id = [Environment]::GetEnvironmentVariable('F2_NOTION_QUEUE_ID','User')
    [IO.File]::WriteAllText($config,($value | ConvertTo-Json),[Text.UTF8Encoding]::new($false))
}
& $python $worker --check
if ($LASTEXITCODE -ne 0) { throw 'Preflight failed; task not installed.' }
& $python $worker --verify-installation
if ($LASTEXITCODE -ne 0) { throw 'Live validation incomplete; task not installed.' }
$stopFile = Join-Path $PSScriptRoot 'STOP'
if (Test-Path -LiteralPath $stopFile) { Remove-Item -LiteralPath $stopFile }
$user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$action = New-ScheduledTaskAction -Execute $python -Argument ('"' + $worker + '"') -WorkingDirectory $repo
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($existing) {
    if ($existing.Actions.Execute -ne $python -or $existing.Actions.Arguments -ne ('"' + $worker + '"')) { throw 'Existing task differs; refusing to overwrite it.' }
    if ($existing.State -eq 'Running') { throw 'Stop the existing worker gracefully before reinstalling.' }
}
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'Deterministic offline Notion queue worker; no LLM polling.' -Force | Out-Null
if ($StartNow) { Start-ScheduledTask -TaskName $taskName }
Get-ScheduledTask -TaskName $taskName | Select-Object TaskName,State
