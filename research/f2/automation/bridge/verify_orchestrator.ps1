$ErrorActionPreference = 'Stop'
$repo = 'C:\Users\verto\F2-Altice-MobiWire'
$python = 'C:\Users\verto\mtkclient\.venv\Scripts\python.exe'
$script = Join-Path $PSScriptRoot 'research_orchestrator.py'
& $python $script --check
if ($LASTEXITCODE -ne 0) { throw 'Orchestrator preflight failed.' }
foreach ($entry in @(
    @{ Name = 'F2 Research Orchestrator'; Script = $script },
    @{ Name = 'F2 Notion Automation Worker'; Script = (Join-Path $PSScriptRoot 'notion_worker.py') }
)) {
    $task = Get-ScheduledTask -TaskName $entry.Name -ErrorAction Stop
    if ($task.Actions.Execute -ne $python -or $task.Actions.Arguments -ne ('"' + $entry.Script + '"')) { throw 'Unexpected task action.' }
    if ($task.State -eq 'Disabled') { throw ('Task disabled: ' + $entry.Name) }
    $info = Get-ScheduledTaskInfo -TaskName $entry.Name
    Write-Host ($entry.Name + ': ' + $task.State + '; last exit=' + $info.LastTaskResult)
}
& $python $script --status
if ($LASTEXITCODE -ne 0) { throw 'Status check failed.' }
# Read-only verification: never execute a pending job or invoke Codex.
