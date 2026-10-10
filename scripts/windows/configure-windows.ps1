param([Parameter(Mandatory=$true)][SecureString]$DomainPassword)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$LogDir='C:\PFA\Logs'
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
# Do not start a transcript: protected join credentials must never be logged.
function Step([string]$Message){Add-Content -LiteralPath "$LogDir\implementation.log" -Value ((Get-Date -Format o)+' '+$Message); Write-Output $Message}
Step 'Start Windows member configuration; synthetic lab data only.'
Install-WindowsFeature Web-Server,FS-FileServer -IncludeManagementTools | Out-Null
Step 'Installed IIS and file server roles.'
$Data='C:\PFA\Shared'
New-Item -ItemType Directory -Path $Data -Force | Out-Null
Set-Content -LiteralPath "$Data\demo.txt" -Value 'PFA synthetic domain file DEMO-002; no personal data.'
$Installer='C:\PFA\wazuh-agent.msi'
Invoke-WebRequest -Uri 'https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.7-1.msi' -OutFile $Installer -UseBasicParsing
$Signature=Get-AuthenticodeSignature -LiteralPath $Installer
if($Signature.Status -ne 'Valid'){throw 'Wazuh MSI signature is not valid'}
Step ('Verified Wazuh MSI signature: '+$Signature.SignerCertificate.Subject)
$Proc=Start-Process msiexec.exe -ArgumentList @('/i',$Installer,'/qn','WAZUH_MANAGER=10.0.5.10','WAZUH_AGENT_NAME=pfa-windows','/l*v',"$LogDir\wazuh-msi.log") -Wait -PassThru -WindowStyle Hidden
if($Proc.ExitCode -notin @(0,3010)){throw "Wazuh MSI failed: $($Proc.ExitCode)"}
Start-Service WazuhSvc
Step 'Wazuh agent installed and started; default Windows event channel collection configured by the vendor.'
$Credential=New-Object System.Management.Automation.PSCredential('PFA\Administrator',$DomainPassword)
$System=Get-CimInstance Win32_ComputerSystem
if(!$System.PartOfDomain){
    Add-Computer -DomainName pfa.test -Credential $Credential -ErrorAction Stop
    Step 'Domain join accepted. Restart is required before domain policy/share verification.'
} elseif($System.Domain -ne 'pfa.test') {throw 'Unexpected existing domain'}
$Credential=$null
$DomainPassword=$null
Step 'COMPLETE WINDOWS SETUP (pending restart and verification).'
