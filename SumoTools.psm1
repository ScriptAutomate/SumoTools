<#
Module: SumoTools
Author: Derek Ardolf
Description:
  PowerShell functions running against the Sumo Logic API
  Requires version 3.0 of PowerShell as data is returned in JSON format,
    and the module uses the ConvertFrom-Json function. All commands
    have been tested on PowerShell 4.0, but should work on v3.0+

Version:
  - 0.1 - 09/30/14
    - Early Release
      - New-SumoCollectorSource works. There was an error in the API. Reminder: JSON
        is case-sensitive. I was using 'lognames' instead of 'logNames' -- the API
        returned "Missing required field: 'eventSources'" when it meant 'logNames'
          - This 'required field' is not documented anywhere
        - Have not confirmed functionality of other source types

TO DO:
  - Include help documentation; preferrable, an XML file that can update via Update-Help
  - Improved error checking (especially in cases where there is no error-checking!)
  - Future functions
    - Invoke-SumoSearch
    - Start-SumoSearchJob
    - Get-SumoSearchJob
    - Receive-SumoSearchJob
    - Remove-SumoSearchJob
    - Get-SumoDashBoard
    - Get-SumoDashBoardMonitor
    - Get-SumoDashBoardMonitorData
#>

#requires -version 3

function New-SumoCredential {
  $SumoCredential = Get-Credential
  $webclient = New-Object System.Net.WebClient
  $credCache = New-Object System.Net.CredentialCache
  $credCache.Add("https://api.sumologic.com/api/v1", "Basic", $SumoCredential)
  $webclient.Credentials = $credCache

  Write-Output "Verifying credentials..."
  Try {
    $Test = $webclient.DownloadString("https://api.sumologic.com/api/v1") |
      ConvertFrom-Json
  }
  Catch {
    Write-Error "Credentials failed."
    break
  }
  
  # If credentials worked, export secure string text
  $ModuleLocation = (Get-Module SumoTools).Path.Replace('\SumoTools.psm1','')
  $SumoCredential.GetNetworkCredential().Password | 
    ConvertTo-SecureString -AsPlainText -Force | 
    ConvertFrom-SecureString | 
    Out-File "$ModuleLocation\SumoAuth1"
  $SumoCredential.GetNetworkCredential().UserName | 
    ConvertTo-SecureString -AsPlainText -Force | 
    ConvertFrom-SecureString | 
    Out-File "$ModuleLocation\SumoAuth2"
    
  Write-Output Write-Verbose "Credentials successfully tested, and exported." 
  Write-Output "All commands from the SumoTools Module will now use these credentials."
}

function Get-SumoCollector {
[CmdletBinding()]
Param
(
  [Parameter(Mandatory=$false,
    ValueFromPipelineByPropertyName=$True,
    ValueFromPipeline=$True)]
  [Alias("CollectorName")]
  [String[]]$Name,
  [Parameter(Mandatory=$false)]
  [ValidateSet('Linux','Windows')]
  [String[]]$OSType,
  [Parameter(Mandatory=$false)]
  [Switch]$Active,
  [Parameter(Mandatory=$false)]
  [Switch]$Inactive
)
  Begin {
    if ($Active -and $Inactive) {
      Clear-Variable Active,Inactive
    }
    # Checking for credentials
    $ModuleLocation = (Get-Module SumoTools).Path.Replace('\SumoTools.psm1','')
    $Password = "$ModuleLocation\SumoAuth1"
    $UserName = "$ModuleLocation\SumoAuth2"
    if ((Test-Path $Password) -and (Test-Path $UserName)) {
      $CredUserSecure = Get-Content "$ModuleLocation\SumoAuth2" | ConvertTo-SecureString
      $BSTRU = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($CredUserSecure)
      $CredUser = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTRU)
      $CredPassSecure = Get-Content "$ModuleLocation\SumoAuth1" | ConvertTo-SecureString
      $BSTRP = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($CredPassSecure)
      $CredPass = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTRP)
    }
    else {
      Write-Error "Failure to find credentials. You must run New-SumoCredential before you can use the SumoTools Module."
      break
    }
    
    # Configuring connection to Sumo Logic API
    $webclient = New-Object System.Net.WebClient
    $credCache = New-Object System.Net.CredentialCache
    $creds = New-Object System.Net.NetworkCredential("$Creduser","$CredPass")
    $credCache.Add("https://api.sumologic.com/api/v1", "Basic", $creds)
    $webclient.Credentials = $credCache
  }
  
  Process {
    $Retrieve = $webclient.DownloadString("https://api.sumologic.com/api/v1/collectors") |
      ConvertFrom-Json
    if (!$Name) {
      $Collector = $Retrieve.Collectors
    }
    else {
      $Collector = @()
      foreach ($Target in $Name) {
        $Collector += $Retrieve.Collectors | where {$_.Name -like "$Target"}
      }
    }    
    if ($Active) {$Collector = $Collector | where {$_.Alive -like "True"}}
    elseif ($Inactive) {$Collector = $Collector | where {$_.Alive -like "False"}}
    if ($OSType) {$Collector | where {$_.OSName -like "$OSType*"}}
    else {$Collector}
  }
}

function Get-SumoCollectorSource {
[CmdletBinding()]
Param
(
  [Parameter(Mandatory=$True,
    ValueFromPipelineByPropertyName=$True,
    ValueFromPipeline=$True)]
  [Alias("CollectorName")]
  [String[]]$Name,
  [Parameter(Mandatory=$false)]
  [Switch]$AsJson
)
  Begin {
    # Checking for credentials
    $ModuleLocation = (Get-Module SumoTools).Path.Replace('\SumoTools.psm1','')
    $Password = "$ModuleLocation\SumoAuth1"
    $UserName = "$ModuleLocation\SumoAuth2"
    if ((Test-Path $Password) -and (Test-Path $UserName)) {
      $CredUserSecure = Get-Content "$ModuleLocation\SumoAuth2" | ConvertTo-SecureString
      $BSTRU = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($CredUserSecure)
      $CredUser = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTRU)
      $CredPassSecure = Get-Content "$ModuleLocation\SumoAuth1" | ConvertTo-SecureString
      $BSTRP = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($CredPassSecure)
      $CredPass = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTRP)
    }
    else {
      Write-Error "Failure to find credentials. You must run New-SumoCredential before you can use the SumoTools Module."
      break
    }
    
    # Configuring connection to Sumo Logic API
    $webclient = New-Object System.Net.WebClient
    $credCache = New-Object System.Net.CredentialCache
    $creds = New-Object System.Net.NetworkCredential("$Creduser","$CredPass")
    $credCache.Add("https://api.sumologic.com/api/v1", "Basic", $creds)
    $webclient.Credentials = $credCache
  }
  
  Process {
    $WebPageBase="https://api.sumologic.com/api"
    $Retrieve = $webclient.DownloadString("https://api.sumologic.com/api/v1/collectors") |
      ConvertFrom-Json
    if (!$Name) {$Collectors = $Retrieve.Collectors}
    else {
      foreach ($Query in $Name) {
        $Collectors += $Retrieve.Collectors | where {$_.Name -like "$Query"}
      }
      $Collectors = $Collectors | select -Unique
    }
    foreach ($Collector in $Collectors) {
      $SourceLink = $Collector.links.href
      if ($AsJson) {
        $webclient.DownloadString("$WebPageBase/$SourceLink")
      }
      else {
        $SourceConfig = $webclient.DownloadString("$WebPageBase/$SourceLink") |
          ConvertFrom-Json
        foreach ($Source in $SourceConfig.Sources) {
          $Source | Add-Member -MemberType NoteProperty -Name collectorName -Value $Collector.Name
          $Source | Add-Member -MemberType NoteProperty -Name collectorID -Value $Collector.ID
          $Source
        }
      }
    } #foreach ($Target in $Name)
  } #Process block end
}

function New-SumoCollectorSource {
[CmdletBinding()]
Param
(
  [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True)]
  [String[]]$ID,
  
  [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True)]
  [Alias("Path")]
  [String]$JSONFile
)
  Begin {
    # Checking for credentials
    $ModuleLocation = (Get-Module SumoTools).Path.Replace('\SumoTools.psm1','')
    $Password = "$ModuleLocation\SumoAuth1"
    $UserName = "$ModuleLocation\SumoAuth2"
    if ((Test-Path $Password) -and (Test-Path $UserName)) {
      $CredUserSecure = Get-Content "$ModuleLocation\SumoAuth2" | ConvertTo-SecureString
      $BSTRU = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($CredUserSecure)
      $CredUser = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTRU)
      $CredPassSecure = Get-Content "$ModuleLocation\SumoAuth1" | ConvertTo-SecureString
    }
    else {
      Write-Error "Failure to find credentials. You must run New-SumoCredential before you can use the SumoTools Module."
      break
    }
    
    # Configuring connection to Sumo Logic API
    $RESTCreds = New-Object System.Management.Automation.PSCredential("$CredUser",$CredPassSecure)
  }
  
  Process {
    $Output = @()
    foreach ($Collector in $ID) {
      $WebPageBase = "https://api.sumologic.com/api/v1/collectors/$ID/sources"
      $Output = Invoke-RestMethod -Uri $WebPageBase -Method Post -ContentType 'application/json' -InFile $JSONFile -Credential $RESTCreds
      $Output.source
    }
  }
}

function Remove-SumoCollectorSource {
[CmdletBinding()]
Param
(
  [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True)]
  [String]$CollectorID,
  [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True)]
  [Alias("ID")]
  [String]$SourceID
)
  Begin {
    # Checking for credentials
    $ModuleLocation = (Get-Module SumoTools).Path.Replace('\SumoTools.psm1','')
    $Password = "$ModuleLocation\SumoAuth1"
    $UserName = "$ModuleLocation\SumoAuth2"
    if ((Test-Path $Password) -and (Test-Path $UserName)) {
      $CredUserSecure = Get-Content "$ModuleLocation\SumoAuth2" | ConvertTo-SecureString
      $BSTRU = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($CredUserSecure)
      $CredUser = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTRU)
      $CredPassSecure = Get-Content "$ModuleLocation\SumoAuth1" | ConvertTo-SecureString
    }
    else {
      Write-Error "Failure to find credentials. You must run New-SumoCredential before you can use the SumoTools Module."
      break
    }
    
    # Configuring connection to Sumo Logic API
    $RESTCreds = New-Object System.Management.Automation.PSCredential("$CredUser",$CredPassSecure)
  }
  
  Process {
    $SourceProperties = Get-SumoCollector | where {$_.ID -eq $CollectorID} | Get-SumoCollectorSource | where {$_.ID -eq $SourceID}
    Write-Warning "REMOVING Sumo Collector Source $SourceID"
    Write-Warning "Collector Name: $($SourceProperties.CollectorName)"
    Write-Warning "Source Name: $($SourceProperties.Name)"
    $WebPageBase = "https://api.sumologic.com/api/v1/collectors/$CollectorID/sources/$SourceID"
    Invoke-RestMethod -Uri $WebPageBase -Method Delete -Credential $RESTCreds -ErrorAction Stop
    Write-Warning "REMOVED Sumo Collector Source. Source Name: $($SourceProperties.Name)"
  }
}

function Remove-SumoCollector {
[CmdletBinding()]
Param
(
  [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True)]
  [Alias("CollectorID")]
  [String[]]$ID
)
  Begin {
    # Checking for credentials
    $ModuleLocation = (Get-Module SumoTools).Path.Replace('\SumoTools.psm1','')
    $Password = "$ModuleLocation\SumoAuth1"
    $UserName = "$ModuleLocation\SumoAuth2"
    if ((Test-Path $Password) -and (Test-Path $UserName)) {
      $CredUserSecure = Get-Content "$ModuleLocation\SumoAuth2" | ConvertTo-SecureString
      $BSTRU = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($CredUserSecure)
      $CredUser = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTRU)
      $CredPassSecure = Get-Content "$ModuleLocation\SumoAuth1" | ConvertTo-SecureString
    }
    else {
      Write-Error "Failure to find credentials. You must run New-SumoCredential before you can use the SumoTools Module."
      break
    }
    
    # Configuring connection to Sumo Logic API
    $RESTCreds = New-Object System.Management.Automation.PSCredential("$CredUser",$CredPassSecure)
  }
  
  Process {
    foreach ($Collector in $ID) {
      $CollectorName = (Get-SumoCollector | where {$_.ID -eq $ID}).Name
      Write-Warning "REMOVING Sumo Collector $Collector."
      Write-Warning "Name: $CollectorName"
      $WebPageBase = "https://api.sumologic.com/api/v1/collectors/$Collector"
      Invoke-RestMethod -Uri $WebPageBase -Method Delete -Credential $RESTCreds -ErrorAction Stop
      Write-Warning "REMOVED Sumo Collector $Collector. Name: $CollectorName"
    }
  }
}