[CmdletBinding()]
param([ValidateSet('Prepare','Exercise','Collect','Respond','Retest','Cleanup')][string]$Step,[string]$ConfigPath)
$ErrorActionPreference='Stop'
$Root=Split-Path -Parent $PSScriptRoot
if(!$Step){throw 'Specify a workflow step.'}
if(!$ConfigPath){$ConfigPath=Join-Path $Root 'config/lab.local.json'}
if(!(Test-Path -LiteralPath $ConfigPath)){throw 'Create config/lab.local.json from the example first.'}
$Config=Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
foreach($Property in @('servicesPublicIp','siemPublicIp')){
 $Ip=[System.Net.IPAddress]::Parse([string]$Config.$Property)
 if($Ip.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork){throw 'IPv4 endpoints required.'}
 if([string]$Config.$Property -match '^(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)'){throw 'Replace documentation-only endpoints.'}
}
$ServicesIp=[string]$Config.servicesPublicIp
$SiemIp=[string]$Config.siemPublicIp
$User=[string]$Config.sshUser
if($User -ne 'labadmin'){throw 'The published templates and installers use the labadmin guest account.'}
$BaseUrl=([string]$Config.appBaseUrl).TrimEnd('/')
if($BaseUrl -notmatch '^https://[A-Za-z0-9.-]+(:[0-9]+)?$'){throw 'Use an HTTPS application origin without a path.'}
function LocalPath([string]$Path){
 if([System.IO.Path]::IsPathRooted($Path)){return $Path}
 return Join-Path $Root $Path
}
$KeyPath=LocalPath $Config.sshKeyPath
$KnownHostsPath=LocalPath $Config.knownHostsPath
foreach($Path in @($KeyPath,$KnownHostsPath)){if(!(Test-Path -LiteralPath $Path -PathType Leaf)){throw "Missing verified SSH file: $Path"}}
Get-Command ssh,scp,curl.exe -ErrorAction Stop | Out-Null
$Common=@('-i',$KeyPath,'-o',('UserKnownHostsFile='+$KnownHostsPath),'-o','StrictHostKeyChecking=yes','-o','BatchMode=yes','-o','ConnectTimeout=20')
New-Item -ItemType Directory -Force (Join-Path $Root '.local/results') | Out-Null
$StatePath=Join-Path $Root '.local/purple-current.json'
if($Step -eq 'Prepare') {
 $State=[pscustomobject]@{run_id=([guid]::NewGuid().ToString('N').Substring(0,12));since=[DateTime]::UtcNow.ToString('o')}
 $State | ConvertTo-Json | Set-Content $StatePath
} else {$State=Get-Content $StatePath -Raw | ConvertFrom-Json}
$Run=$State.run_id
if($Run -notmatch '^[a-f0-9]{12}$'){throw 'Invalid exercise run identifier'}
$Since=([DateTimeOffset]$State.since).ToUniversalTime().ToString('o')
$Dir=Join-Path $Root ".local/results/purple-$Run"
New-Item -ItemType Directory -Force $Dir | Out-Null
$State | ConvertTo-Json | Set-Content (Join-Path $Dir 'run.json')
Add-Content (Join-Path $Root '.local/IMPLEMENTATION-LOG.md') ("`n### Purple team $Step - "+(Get-Date -Format o)+"`nRun $Run; owned lab only. Outputs: .local/results/purple-$Run. No exploit, brute force, credential theft or third-party data transfer.")
function Remote([string]$Ip,[string]$Command,[string]$File) {
 $Out=& ssh @Common "${User}@$Ip" $Command 2>&1
 $Code=$LASTEXITCODE
 $Out | Set-Content (Join-Path $Dir $File)
 if($Code){throw "Remote action failed ($Code): $File"}
 return $Out
}
function Upload([string]$Ip,[string]$File) {
 & scp @Common (Join-Path $PSScriptRoot ("purple/"+$File)) "${User}@${Ip}:/home/labadmin/$File"
 if($LASTEXITCODE){throw "Upload failed: $File"}
}
function WebTest([string]$Phase,[string]$Expected) {
 $Url="$BaseUrl/pfa-purple-probe?run=$Run&phase=$Phase"
 $Status=& curl.exe --silent --max-time 8 --output NUL --write-out '%{http_code}' $Url
 $Code=$LASTEXITCODE
 $Pass=if($Expected -eq '000'){$Status -eq '000' -and $Code -eq 28}else{$Status -eq $Expected -and $Code -eq 0}
 $Result=[pscustomobject]@{run_id=$Run;phase=$Phase;url=$Url;http_status=$Status;curl_exit=$Code;pass=$Pass;timestamp=[DateTime]::UtcNow.ToString('o')}
 $Result | ConvertTo-Json | Set-Content (Join-Path $Dir "web-$Phase.json")
 $Result
 if(-not $Pass){throw "Web test failed: $Phase"}
}
switch($Step) {
 Prepare {
  foreach($File in @('purple-rule.py','purple-host.py','purple-events.py')){Upload $ServicesIp $File}
  Upload $SiemIp 'purple-events.py'
  Remote $ServicesIp 'sudo python3 /home/labadmin/purple-rule.py alert' 'prepare.txt'
 }
 Exercise {
  Remote $ServicesIp "sudo python3 /home/labadmin/purple-host.py $Run" 'host-tests.json'
  $PreviousPreference=$ErrorActionPreference
  try {
   $ErrorActionPreference='Continue'
   $Out=& ssh @Common -o IdentitiesOnly=yes "pt-${Run}@$ServicesIp" hostname 2>&1
   $Code=$LASTEXITCODE
  } finally {$ErrorActionPreference=$PreviousPreference}
  $Out | Set-Content (Join-Path $Dir 'invalid-ssh.txt')
  if($Code -ne 255 -or ($Out -join ' ') -notmatch 'Permission denied'){throw 'SSH test did not demonstrate authentication denial'}
  WebTest 'detect' '404'
 }
 Collect {
  foreach($Job in @(@('suricata',$ServicesIp),@('wazuh',$SiemIp))){
   Remote $Job[1] "sudo python3 /home/labadmin/purple-events.py $Run $Since $($Job[0])" "$($Job[0])-events.json"
  }
 }
 Respond {
  $E=Get-Content (Join-Path $Dir 'wazuh-events.json') -Raw | ConvertFrom-Json
  if(-not($E.events | Where-Object {$_.kind -eq 'web_probe' -and $_.action -eq 'allowed'})){throw 'Response requires actual detection evidence first'}
  Remote $ServicesIp 'sudo python3 /home/labadmin/purple-rule.py drop' 'response.txt'
 }
 Retest {
  WebTest 'prevent' '000'
  $Status=& curl.exe --silent --show-error --max-time 15 --output NUL --write-out '%{http_code}' "$BaseUrl/health"
  $Code=$LASTEXITCODE
  [pscustomobject]@{http_status=$Status;exit=$Code;pass=($Code -eq 0 -and $Status -eq '200')} | ConvertTo-Json | Set-Content (Join-Path $Dir 'normal-traffic-retest.json')
  if($Code -ne 0 -or $Status -ne '200'){throw 'Normal traffic regression'}
 }
 Cleanup {
  Remote $ServicesIp "sudo rm -- /opt/pfa-demo/data/purple-$Run.txt" 'cleanup.txt'
 }
}

