$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$process = Start-Process -FilePath 'C:\Python314\python.exe' -ArgumentList @((Join-Path $root 'server.py')) -WorkingDirectory $root -WindowStyle Hidden -RedirectStandardOutput (Join-Path $root 'monitor.stdout.log') -RedirectStandardError (Join-Path $root 'monitor.stderr.log') -PassThru
$process.Id | Set-Content -LiteralPath (Join-Path $root 'monitor.pid')
Write-Output "Local dashboard started. PID $($process.Id). URL http://127.0.0.1:8765"
