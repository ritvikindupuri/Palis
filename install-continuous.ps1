$ErrorActionPreference = 'Stop'
$python = 'C:\Python314\pythonw.exe'
if (!(Test-Path -LiteralPath $python)) { throw "Python not found: $python" }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$action = New-ScheduledTaskAction -Execute $python -Argument ('"' + (Join-Path $PSScriptRoot 'keep-running.py') + '"') -WorkingDirectory $PSScriptRoot
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $identity
$principal = New-ScheduledTaskPrincipal -UserId $identity -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName 'Palis Continuous Monitor' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'Keep the local Palis dashboard and read-only collector running while signed in and Windows is awake.' -Force | Out-Null
Start-ScheduledTask -TaskName 'Palis Continuous Monitor'
Get-ScheduledTask -TaskName 'Palis Continuous Monitor' | Select-Object TaskName, State
