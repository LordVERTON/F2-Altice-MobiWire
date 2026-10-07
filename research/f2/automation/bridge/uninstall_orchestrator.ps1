$ErrorActionPreference = 'Stop'
$taskName = 'F2 Research Orchestrator'
[IO.File]::WriteAllText((Join-Path $PSScriptRoot 'ORCHESTRATOR_STOP'), 'stop requested', [Text.UTF8Encoding]::new($false))
$task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($task) {
    Disable-ScheduledTask -TaskName $taskName | Out-Null
    # Unregistering does not kill a running instance: its transaction can finish.
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}
Write-Host 'Orchestrator uninstalled; any current transaction may finish. Worker and runtime evidence preserved.'
