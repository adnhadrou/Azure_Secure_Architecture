$ErrorActionPreference='Stop'
$LogDir='C:\PFA\Logs'
function Step([string]$Message){Add-Content -LiteralPath "$LogDir\implementation.log" -Value ((Get-Date -Format o)+' '+$Message); Write-Output $Message}
$System=Get-CimInstance Win32_ComputerSystem
if(!$System.PartOfDomain -or $System.Domain -ne 'pfa.test'){throw 'Windows domain membership was not established'}
Step ('Verified domain membership: '+$System.Name+' / '+$System.Domain)
if(!(Test-ComputerSecureChannel)){throw 'Domain secure channel check failed'}
Step 'Domain secure channel test passed.'
if(!(Get-SmbShare -Name PFAData -ErrorAction SilentlyContinue)){
    New-SmbShare -Name PFAData -Path 'C:\PFA\Shared' -FullAccess 'PFA\Domain Admins' -ReadAccess 'PFA\LabUsers' -EncryptData $true | Out-Null
}
$Acl=New-Object System.Security.AccessControl.DirectorySecurity
$Acl.SetAccessRuleProtection($true,$false)
foreach($Sid in @('S-1-5-18','S-1-5-32-544')){
    $Identity=New-Object System.Security.Principal.SecurityIdentifier($Sid)
    $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($Identity,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
}
$Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule('PFA\Domain Admins','FullControl','ContainerInherit,ObjectInherit','None','Allow')))
$Rule=New-Object System.Security.AccessControl.FileSystemAccessRule('PFA\LabUsers','ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow')
$Acl.AddAccessRule($Rule)
Set-Acl -LiteralPath 'C:\PFA\Shared' -AclObject $Acl
Step 'Created SMB share with encryption required and matching NTFS permissions: administrators full control, LabUsers read only.'
@'
<!doctype html><html><head><meta charset="utf-8"><title>PFA Windows domain member</title></head>
<body style="font:20px system-ui;background:#112438;color:#eef6ff;padding:60px">
<p>PFA / AZURE SECURITY LAB</p><h1>Windows domain member</h1>
<p>This IIS server is joined to pfa.test, hosted by Samba AD.</p>
<ul><li>SMB share: PFAData (encrypted)</li><li>Reader group: PFA\LabUsers</li><li>Endpoint telemetry: Wazuh agent</li></ul>
<p>Synthetic demonstration content only. This HTTP page is restricted to the administrator's IP.</p></body></html>
'@ | Set-Content -LiteralPath 'C:\inetpub\wwwroot\index.html' -Encoding UTF8
gpupdate /force | Out-Null
Step 'Refreshed domain policy.'
Get-SmbShare -Name PFAData | Select-Object Name,Path,EncryptData | Format-List
Get-SmbShareAccess -Name PFAData | Format-Table -AutoSize
Get-Service WazuhSvc,W3SVC | Select-Object Name,Status | Format-Table -AutoSize
Get-CimInstance Win32_ComputerSystem | Select-Object Name,Domain,PartOfDomain | Format-List
Step 'COMPLETE WINDOWS VERIFICATION'
