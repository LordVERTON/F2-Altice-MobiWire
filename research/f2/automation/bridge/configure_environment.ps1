param([string]$QueueId)
$ErrorActionPreference = 'Stop'
if (-not $QueueId) { $QueueId = Read-Host 'Notion queue data source ID' }
$parsedId = [guid]::Empty
if (-not [guid]::TryParse($QueueId,[ref]$parsedId)) { throw 'Invalid queue ID' }
$secure = Read-Host 'Notion integration secret (local input, never paste in chat)' -AsSecureString
$pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try {
    $value = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    if ([string]::IsNullOrWhiteSpace($value)) { throw 'Empty token' }
    [Environment]::SetEnvironmentVariable('F2_NOTION_TOKEN',$value,'User')
    [Environment]::SetEnvironmentVariable('F2_NOTION_QUEUE_ID',$parsedId.ToString(),'User')
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    $value = $null
    $secure.Dispose()
}
Write-Host 'Notion user environment configured. Secret was not printed or saved in the repository.'
