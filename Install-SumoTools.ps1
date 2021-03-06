function Install-SumoTools {
[CmdletBinding()]
param()

#Script to help install/setup SumoTools
$ModulePaths = @($env:PSModulePath -split ';')
$ExpectedUserModulePath = Join-Path -Path ([Environment]::GetFolderPath('MyDocuments')) -ChildPath WindowsPowerShell\Modules
$Destination = $ModulePaths | Where-Object { $_ -eq $ExpectedUserModulePath }
if (-not $Destination) {
  $Destination = $ModulePaths | Select-Object -Index 0
}
if (-not (Test-Path ($Destination + "\SumoTools\"))) {
  New-Item -Path ($Destination + "\SumoTools\") -ItemType Directory -Force | Out-Null
  Write-Verbose 'Downloading SumoTools Module from https://raw.githubusercontent.com/ScriptAutomate/SumoTools/master/SumoTools.psm1'
  $client = (New-Object Net.WebClient)
  $client.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
  $client.DownloadFile("https://raw.githubusercontent.com/ScriptAutomate/SumoTools/master/SumoTools.psm1", $Destination + "\SumoTools\SumoTools.psm1")
  Write-Verbose 'Downloading SumoTools Module Manifest from https://raw.githubusercontent.com/ScriptAutomate/SumoTools/master/SumoTools.psd1'
  $client.DownloadFile("https://raw.githubusercontent.com/ScriptAutomate/SumoTools/master/SumoTools.psd1", $Destination + "\SumoTools\SumoTools.psd1")
  
  $executionPolicy = (Get-ExecutionPolicy)
  $executionRestricted = ($executionPolicy -eq "Restricted")
  if ($executionRestricted) {
    Write-Warning @"
Your execution policy is $executionPolicy, this means you will not be able import or use any scripts -- including modules.
To fix this, change your execution policy to something like RemoteSigned.

    PS> Set-ExecutionPolicy RemoteSigned

For more information, execute:

    PS> Get-Help about_execution_policies

"@
  }

  if (!$executionRestricted) {
    # Ensure SumoTools is imported from the location it was just installed to
    Import-Module -Name $Destination\SumoTools -Verbose:$False
    Get-Command -Module SumoTools
  }
}

""
Write-Verbose "SumoTools is installed and ready to use"
Write-Verbose @"
For more details, visit: 
https://github.com/ScriptAutomate/SumoTools
"@
}

Install-SumoTools -Verbose