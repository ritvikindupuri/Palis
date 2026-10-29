param([string]$Bundle,[string]$ExpectedHash,[string]$Result)
$ErrorActionPreference='Stop'
$payload=$null
$created=$false
$receipt=$null
function Receipt($rule) {
 $port=$rule | Get-NetFirewallPortFilter
 $addr=$rule | Get-NetFirewallAddressFilter
 $app=$rule | Get-NetFirewallApplicationFilter
 $svc=$rule | Get-NetFirewallServiceFilter
 $int=$rule | Get-NetFirewallInterfaceFilter
 $intType=$rule | Get-NetFirewallInterfaceTypeFilter
 $security=$rule | Get-NetFirewallSecurityFilter
 [ordered]@{Name=[string]$rule.Name;Description=[string]$rule.Description;Action=[string]$rule.Action;Direction=[string]$rule.Direction;Profile=[string]$rule.Profile;Enabled=[string]$rule.Enabled;EdgeTraversalPolicy=[string]$rule.EdgeTraversalPolicy;Program=[string]$app.Program;Package=[string]$app.Package;Protocol=[string]$port.Protocol;LocalPort=($port.LocalPort -join ',');RemotePort=($port.RemotePort -join ',');LocalAddress=($addr.LocalAddress -join ',');RemoteAddress=($addr.RemoteAddress -join ',');Service=[string]$svc.Service;InterfaceAlias=($int.InterfaceAlias -join ',');InterfaceType=[string]$intType.InterfaceType;Authentication=[string]$security.Authentication;Encryption=[string]$security.Encryption;OverrideBlockRules=[string]$security.OverrideBlockRules}
}
function SameReceipt($left,$right) { foreach($key in $left.Keys){if([string]$left[$key] -cne [string]$right.$key){return $false}};return $true }
function RuleSignature($rule) {
 $names=@($rule.PSObject.Properties.Name | Where-Object {$_ -ne 'ExecutableExists'} | Sort-Object)
 ($names | ForEach-Object {$_+'='+[string]$rule.$_}) -join "`n"
}
try {
 if((Get-Item -LiteralPath $Bundle).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Linked bundles are rejected.'}
 if((Get-FileHash -LiteralPath $Bundle -Algorithm SHA256).Hash -ne $ExpectedHash){throw 'Approved bundle changed.'}
 $payload=Get-Content -LiteralPath $Bundle -Raw | ConvertFrom-Json
 if([DateTimeOffset]::UtcNow -gt [DateTimeOffset]::Parse($payload.expiresAt)){throw 'Approval expired. Request a new reviewed proposal.'}
 if($payload.ruleName -notmatch '^Palis-Block-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'){throw 'Invalid owned rule name.'}
 if($payload.operation -notin @('block','rollback')){throw 'Unsupported operation.'}
 $a=$payload.action
 if($a.direction -ne 'Inbound' -or $a.protocol -notin @('TCP','UDP') -or $a.profile -notin @('Public','Private','Domain')){throw 'Invalid scope.'}
 if($a.localPort -isnot [int] -or $a.localPort -lt 1 -or $a.localPort -gt 65535){throw 'Invalid single local port.'}
 $ip=[System.Net.IPAddress]::Parse($a.remoteIP)
 if($ip.ToString() -cne $a.remoteIP -or $a.remoteIP -match '[/%,\s]' -or [System.Net.IPAddress]::IsLoopback($ip) -or $a.remoteIP -in @('0.0.0.0','::','255.255.255.255') -or $ip.IsIPv6Multicast -or $ip.IsIPv6LinkLocal -or ($ip.AddressFamily -eq 'InterNetwork' -and ($ip.GetAddressBytes()[0] -ge 224 -or ($ip.GetAddressBytes()[0] -eq 169 -and $ip.GetAddressBytes()[1] -eq 254)))){throw 'Invalid single remote unicast IP.'}
 if($a.program -match '[*?%"\r\n]' -or -not [IO.Path]::IsPathRooted($a.program) -or [IO.Path]::GetExtension($a.program) -ne '.exe'){throw 'Invalid executable path.'}
 if($payload.operation -eq 'block'){
  $profiles=(& "$env:SystemRoot\System32\netsh.exe" advfirewall show allprofiles) -join "`n"
  if($LASTEXITCODE -ne 0 -or ($profiles -replace '\s','') -cne ([string]$payload.profileBaseline -replace '\s','')){throw 'Firewall profile state changed after approval.'}
  $raw=(& "$env:SystemRoot\System32\netsh.exe" advfirewall firewall show rule name=all dir=in status=enabled verbose) -join "`n"
  if($LASTEXITCODE -ne 0){throw 'Cannot verify current rule inventory.'}
  $current=@(foreach($block in ($raw -split 'Rule Name:' | Select-Object -Skip 1)){
   $row=[ordered]@{'Rule Name'=($block -split "`n")[0].Trim()}
   foreach($line in ($block -split "`n" | Select-Object -Skip 1)){if($line -match '^([^:]+):\s*(.*)$'){$row[$matches[1].Trim()]=$matches[2].Trim()}}
   [pscustomobject]$row
  })
  $before=@($payload.ruleBaseline | ForEach-Object {RuleSignature $_} | Sort-Object)
  $after=@($current | ForEach-Object {RuleSignature $_} | Sort-Object)
  if($before.Count -ne $after.Count -or ($before -join "`n---`n") -cne ($after -join "`n---`n")){throw 'Firewall inventory changed after approval; new review required.'}
  if(-not (Test-Path -LiteralPath $a.program -PathType Leaf)){throw 'Executable no longer exists.'}
  if((Get-Item -LiteralPath $a.program).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Linked executables are rejected.'}
  if([string](Get-NetFirewallProfile -Name $a.profile).Enabled -ne 'True'){throw 'Target firewall profile is disabled.'}
  if(Get-NetFirewallRule -PolicyStore PersistentStore -Name $payload.ruleName -ErrorAction SilentlyContinue){throw 'Owned rule already exists; replay rejected.'}
  $rule=New-NetFirewallRule -PolicyStore PersistentStore -Name $payload.ruleName -DisplayName $payload.ruleName -Description ('Palis human-approved block '+$payload.ruleName) -Direction Inbound -Action Block -Enabled True -Profile $a.profile -Program $a.program -Protocol $a.protocol -LocalPort $a.localPort -RemoteAddress $a.remoteIP -EdgeTraversalPolicy Block
  $created=$true
  $rule=Get-NetFirewallRule -PolicyStore PersistentStore -Name $payload.ruleName
  $receipt=Receipt $rule
  $protocol=if($a.protocol -eq 'TCP'){'6'}else{'17'}
  if($receipt.Program -ine $a.program -or $receipt.Action -ne 'Block' -or $receipt.Direction -ne 'Inbound' -or $receipt.Enabled -ne 'True' -or $receipt.Profile -ne $a.profile -or $receipt.RemoteAddress -ne $a.remoteIP -or $receipt.LocalPort -ne [string]$a.localPort -or $receipt.Protocol -notin @($a.protocol,$protocol)){throw 'Created rule failed verification. Inspect the owned rule; success is not asserted.'}
  $active=Get-NetFirewallRule -PolicyStore ActiveStore -Name $payload.ruleName -ErrorAction Stop
  if(-not (SameReceipt $receipt (Receipt $active))){throw 'Effective rule differs from created definition.'}
  @{runId=$payload.runId;verified=$true;message='Created and verified the scoped block rule. Packet-level blocking is not independently tested.';receipt=$receipt} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $Result -Encoding UTF8
 } else {
  if(-not $payload.receipt){throw 'Original creation receipt required.'}
  $rule=Get-NetFirewallRule -PolicyStore PersistentStore -Name $payload.ruleName -ErrorAction Stop
  $receipt=Receipt $rule
  if(-not (SameReceipt $receipt $payload.receipt)){throw 'Rule changed after creation; rollback refused.'}
  Remove-NetFirewallRule -PolicyStore PersistentStore -Name $payload.ruleName
  if(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop | Where-Object Name -eq $payload.ruleName){throw 'Rule removal could not be verified.'}
  if(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop | Where-Object Name -eq $payload.ruleName){throw 'Rule remains in effective policy; removal is not verified.'}
  @{runId=$payload.runId;verified=$true;message='Removed the exact unchanged Palis-owned rule.'} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $Result -Encoding UTF8
 }
} catch {
  $failure=$_.Exception.Message
  if($created -and -not $receipt){try{$receipt=Receipt (Get-NetFirewallRule -PolicyStore PersistentStore -Name $payload.ruleName)}catch{}}
  @{runId=$payload.runId;verified=$false;message=$failure;ruleMayExist=$created;receipt=$receipt} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $Result -Encoding UTF8
 exit 1
}
