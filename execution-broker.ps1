param([string]$Bundle,[string]$ExpectedHash,[string]$Result)
$ErrorActionPreference='Stop'
try {
 $payload=Get-Content -LiteralPath $Bundle -Raw | ConvertFrom-Json
 $executor=Join-Path $PSScriptRoot 'execute-approved.ps1'
 $args=@('-NoProfile','-File',('"'+$executor+'"'),'-Bundle',('"'+$Bundle+'"'),'-ExpectedHash',$ExpectedHash,'-Result',('"'+$Result+'"'))
 $process=Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList $args -Verb RunAs -WindowStyle Hidden -Wait -PassThru
 if (-not (Test-Path -LiteralPath $Result)) { throw 'No verified executor result was returned.' }
} catch {
 @{runId=$payload.runId;verified=$false;message=$_.Exception.Message} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $Result -Encoding UTF8
}
