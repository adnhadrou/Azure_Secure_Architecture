$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$Failures = @()
$Files = @(Get-ChildItem -LiteralPath (Join-Path $Root 'scripts'),$PSScriptRoot -Filter '*.ps1' -File -Recurse)
foreach ($File in $Files) {
    $Tokens = $null
    $ParseErrors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($File.FullName, [ref]$Tokens, [ref]$ParseErrors) | Out-Null
    foreach ($Problem in $ParseErrors) {$Failures += ($File.Name + ': ' + $Problem.Message)}
}
if ($Failures.Count) {throw ($Failures -join [Environment]::NewLine)}
Write-Output ('PASS: ' + $Files.Count + ' PowerShell files parsed; none executed.')
