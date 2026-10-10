[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('Network','Core','Domain')][string]$Stage,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Za-z0-9_.()-]+$')][string]$ResourceGroup,
    [string]$ParametersFile,
    [switch]$Apply
)
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Get-Command az -ErrorAction Stop | Out-Null
$Templates = @{Network='network-foundation.json'; Core='compute.json'; Domain='domain.json'}
$Template = Join-Path $Root ('infra/' + $Templates[$Stage])
if ($Stage -ne 'Network' -and !$ParametersFile) {throw 'Supply a private local parameter file.'}
$Arguments = @('deployment','group')
if ($Apply) {$Arguments += 'create'} else {$Arguments += 'what-if'}
$Arguments += @('--resource-group',$ResourceGroup,'--name',('security-lab-' + $Stage.ToLower()),'--template-file',$Template)
if ($ParametersFile) {
    $ParametersFile = (Resolve-Path -LiteralPath $ParametersFile).Path
    $Values = (Get-Content -LiteralPath $ParametersFile -Raw | ConvertFrom-Json).parameters
    if ($Stage -ne 'Network') {
        $Source = [string]$Values.adminSource.value
        if ($Source -notmatch '^\d{1,3}(\.\d{1,3}){3}/32$') {throw 'Use one administrator IPv4 address with a /32 prefix.'}
        $Address = [System.Net.IPAddress]::Parse($Source.Split('/')[0])
        if ($Address.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {throw 'IPv4 required.'}
        if ($Source -match '^(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)') {throw 'Replace the documentation-only administrator address.'}
        if ([string]$Values.sshPublicKey.value -notmatch '^ssh-(ed25519|rsa) [A-Za-z0-9+/]+=*( .*)?$') {throw 'Supply a real SSH public key.'}
        if ($Stage -eq 'Domain' -and [string]$Values.windowsAdminPassword.value -match '^<') {throw 'Replace the Windows password placeholder locally.'}
    }
    $Arguments += @('--parameters',('@' + $ParametersFile))
}
Write-Output ('Stage: ' + $Stage + '; mode: ' + $(if($Apply){'APPLY - creates/changes billable resources'}else{'WHAT-IF'}))
& az @Arguments
if ($LASTEXITCODE -ne 0) {throw ('Azure deployment command failed, exit ' + $LASTEXITCODE)}
