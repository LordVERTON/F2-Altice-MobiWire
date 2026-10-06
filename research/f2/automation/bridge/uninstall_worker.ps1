param([switch]$StopOnly)
$ErrorActionPreference = 'Stop'
$taskName = 'F2 Notion Automation Worker'
# Cooperative stop: no new job; an active offline job is allowed to finish/publish.
[IO.File]::WriteAllText((Join-Path $PSScriptRoot 'STOP'),'stop requested',[Text.UTF8Encoding]::new($false))
$task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($task) {
    Disable-ScheduledTask -TaskName $taskName | Out-Null
    if ($task.State -eq 'Running') {
        Write-Host 'Stop requested; current job will finish. Run again after the task stops to unregister it.'
        exit 0
    }
    if (-not $StopOnly) { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false }
}
Write-Host 'Worker stopped/disabled. Job evidence, configuration and secrets were preserved.'
