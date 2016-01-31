<#
Module: SumoTools
Author: Derek Ardolf

NOTE: Please check out GitHub for latest revisions
Link: https://github.com/ScriptAutomate/SumoTools
#>

$global:SumoBaseAPIHost = Get-Content "$PSScriptRoot\SumoAPIHost" -ErrorAction SilentlyContinue

function New-SumoCredential {
<#
	.SYNOPSIS
		Creates an encrypted dump of credentials for use by the SumoTools Module agains the Sumo Logic API.

	.DESCRIPTION
		Using credentials securely dumped by New-SumoCredential, SumoTool Module functions interact with the Sumo Logic API. Use of a generated Access ID is recommended, versus using primary Sumo Logic logon credentials. Credentials are encrypted using DPAPI -- see link at end of help documentation.

	.PARAMETER  Credential
		Credentials for accessing the Sumo Logic API.

	.PARAMETER  Force
		Will overwrite any previously generated credentials.

  .INPUTS
    System.Management.Automation.PSCredential

  .OUTPUTS
    None

	.EXAMPLE
		PS C:\> New-SumoCredential -Credential $Credential
      
      Uses the credentials stored in the $Credential variable to dump to module's root path.

	.EXAMPLE
		PS C:\> $Credential | New-SumoCredential -Force
    
      Uses the credentials stored in the $Credential variable to dump to module's root path. The -Force parameter overwrites pre-existing credentials.

	.LINK
		https://github.com/ScriptAutomate/SumoTools
  .LINK
    https://github.com/SumoLogic/sumo-api-doc/wiki
  .LINK
		https://halfwaytoinfinite.wordpress.com
	.LINK
		http://msdn.microsoft.com/en-us/library/ms995355.aspx
  .LINK
    http://powershell.org/wp/2013/11/24/saving-passwords-and-preventing-other-processes-from-decrypting-them/comment-page-1/
  
  .COMPONENT
    Invoke-RestMethod
    Get-Credential
    ConvertTo-SecureString
    ConvertFrom-SecureString
    
#>
[CmdletBinding()]
Param
(
  [Parameter(Mandatory=$False,ValueFromPipeline=$True)]
  [System.Management.Automation.PSCredential]$Credential,
  [Parameter(Mandatory=$False)]
  [Switch]$Force 
)
  $ModuleLocation = (Get-Module SumoTools).Path.Replace('\SumoTools.psm1','')
  if (Test-Path "$ModuleLocation\SumoAuth1") {
    if (!$Force) {
      Write-Error "$ModuleLocation\SumoAuth* credentials already exist. Use with -Force parameter to overwrite."
      break
    }
    else { 
      Write-Warning "$ModuleLocation\SumoAuth* credentials already exist. -Force parameter was used -- overwriting..."
    }
  }
  
  try {
    if (!$Credential) {
      $Credential = Get-Credential -Message "Enter Credentials to Query Sumo Logic API"
      if (!$Credential) {break}
    }
    
    Write-Warning "Verifying credentials..."
    $global:SumoBaseAPIHost = 'https://api.sumologic.com'
    $SumoBaseAPI = "$global:SumoBaseAPIHost/api/v1/collectors"
    
    $initReq = [System.Net.WebRequest]::Create($SumoBaseAPI)
    $initReq.Credentials = $Credential
    $initReq.AllowAutoRedirect = $false
    $initRes = $initReq.GetResponse()
    if($initRes.StatusCode -eq [System.Net.HttpStatusCode]::MovedPermanently) {
      $newRegionUri = [System.Uri]$initRes.GetResponseHeader('Location')
      $global:SumoBaseAPIHost = $newRegionUri.GetLeftPart([System.UriPartial]::Authority)
      $global:SumoBaseAPIHost | Out-File "$ModuleLocation\SumoAPIHost"
      $SumoBaseAPI = "$global:SumoBaseAPIHost/api/v1/collectors"
    }
  
    $null = Invoke-RestMethod $SumoBaseAPI -Credential $Credential
    
    # If credentials worked, export secure string text
    $Credential.GetNetworkCredential().Password | 
      ConvertTo-SecureString -AsPlainText -Force | 
      ConvertFrom-SecureString | 
      Out-File "$ModuleLocation\SumoAuth1"
    $Credential.GetNetworkCredential().UserName | 
      ConvertTo-SecureString -AsPlainText -Force | 
      ConvertFrom-SecureString | 
      Out-File "$ModuleLocation\SumoAuth2"
      
    Write-Warning "Credentials successfully tested, and exported." 
    Write-Warning "All commands from the SumoTools Module will now use these credentials."
  }
  catch {
    Write-Error $_.Exception
    break
  }
}
  
function Get-SumoCollector {
<#
	.SYNOPSIS
		Uses the Sumo Logic Collector Management API to query Sumo Collector information.

	.DESCRIPTION
		Get-SumoCollector queries the Collector Management API for Collector information. The returned JSON information is converted into happy PowerShell objects.

	.PARAMETER  Name
		Name of Sumo Collector. Accepts wildcards.

	.PARAMETER  OSType
		Filters the Collectors by the OS they are installed on. Accepts either 'Windows' or 'Linux.'
    
  .PARAMETER  Active
		Filters the results to only show Collectors based on the boolean value of Active.
    
  .PARAMETER  Credential
		Credentials for accessing the Sumo Logic API. Unneccessary if New-SumoCredential has been used.

	.EXAMPLE
		PS C:\> Get-SumoCollector -Name SUMOCOLLECT01*
    
      Returns all Collectors with SUMOCOLLECT01* at the beginning of the Collector name

	.EXAMPLE
		PS C:\> Get-SumoCollector -OSType Linux -Active
    
      Returns all active Linux Collectors

  .EXAMPLE
    PS C:\> Get-SumoCollector -Name SUMOCOLLECT01 | Get-SumoCollectorSource
    
      Retrieve all sources for the Collector with the name 'SUMOCOLLECT01'

	.INPUTS
		System.String

	.OUTPUTS
		SumoTools.Collector

	.LINK
		https://github.com/ScriptAutomate/SumoTools
  .LINK
    https://github.com/SumoLogic/sumo-api-doc/wiki
  .LINK
		https://halfwaytoinfinite.wordpress.com
    
  .COMPONENT
    Invoke-RestMethod
#>

[CmdletBinding()]
Param
(
  [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True)]
  [Alias("CollectorName")]
  [String[]]$Name,
  [Parameter(Mandatory=$False)]
  [System.Management.Automation.PSCredential]$Credential,
  [Parameter(Mandatory=$False)]
  [ValidateSet('Linux','Windows')]
  [String[]]$OSType,
  [Parameter(Mandatory=$False)]
  [Switch]$Active,
  [Parameter(Mandatory=$False)]
  [Switch]$Inactive
)
  Begin {
    # Checking for credentials
    $ModuleLocation = (Get-Module SumoTools).Path.Replace('\SumoTools.psm1','')
    $SumoPass = "$ModuleLocation\SumoAuth1"
    $SumoUser = "$ModuleLocation\SumoAuth2"
    if (!$Credential) {
      if ((Test-Path "$SumoPass") -and (Test-Path "$SumoUser")) {
        $CredUserSecure = Get-Content "$ModuleLocation\SumoAuth2" | ConvertTo-SecureString
        $BSTRU = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($CredUserSecure)
        $CredUser = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTRU)
        $CredPass = Get-Content "$ModuleLocation\SumoAuth1" | ConvertTo-SecureString
        $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "$CredUser",$CredPass
      }
      else {
        Write-Error "Failure to find credentials. You must run New-SumoCredential before you can use the SumoTools Module."
        break
      }
    }
    $SumoBaseAPI = "$global:SumoBaseAPIHost/api"
    if ($Active -and $Inactive) {
      Clear-Variable Active,Inactive
    }
  }
  
  Process {
    $Retrieve = Invoke-RestMethod "$SumoBaseAPI/v1/collectors" -Credential $Credential
    if (!$Name) {$Collectors = $Retrieve.Collectors}
    else {
      foreach ($Query in $Name) {
        $Collectors += $Retrieve.Collectors | where {$_.Name -like "$Query"}
      }
    }    
    if ($Active) {$Collectors = $Collectors | where {$_.Alive -eq "True"}}
    elseif ($Inactive) {$Collectors = $Collectors | where {$_.Alive -eq "False"}}
    if ($OSType) {$Collectors = $Collectors | where {$_.OSName -like "$OSType*"}}
    foreach ($Collector in $Collectors) {
      $Collector.PSObject.TypeNames.Insert(0, "SumoTools.Collector")
      $Collector
    }
  }
}

function Set-SumoCollector {
<#
	.SYNOPSIS
		Uses the Sumo Logic Collector Management API to modify Sumo Collector information.

	.DESCRIPTION
		Set-SumoCollector modifies Sumo Collector information via the Collector Management API. The returned JSON information is converted into happy PowerShell objects.

  [Parameter(ParameterSetName='Base',Mandatory=$False)]
  [Alias("CollectorName")]
  [String]$Name,
  [Parameter(ParameterSetName='Base',Mandatory=$False)]
  [Bool]$Ephemeral,
  [Parameter(ParameterSetName='Base',Mandatory=$False)]
  [String]$TimeZone,
  [Parameter(ParameterSetName='Base',Mandatory=$False)]
  [String]$Description,
  [Parameter(ParameterSetName='Base',Mandatory=$False)]
  [String]$Category,  
  [Parameter(ParameterSetName='Base',Mandatory=$False)]
  [String]$HostName,
  [Parameter(ParameterSetName='Base',Mandatory=$False)]
  [Int64]$CutoffTimestamp

	.PARAMETER  ID
		ID of the Sumo Collector. This isn't used to modify a Collector, but rather to identify it. Piping a SumoTools.Collector object into this function will automatically pass the appropriate ID.

	.PARAMETER  Name
		Modifies the Name of the Sumo Collector.
    
  .PARAMETER  Ephemeral
		If a Collector is flagged as ephemeral, the Collector will be deleted automatically after some period being offline.
    
  .PARAMETER Description
    Modifies the Description of the Sumo Collector.
    
  .PARAMETER Category
    Modifies the default Category of Sources associated with the Sumo Collector, if no Category is given to a Source.
  
  .PARAMETER HostName
    Modifies the Host Name of a Collector agent.
  
  .PARAMETER CutoffTimestamp
    Only collect data more recent than this timestamp, specified as milliseconds since epoch. The default is to collect all, giving this a value of 0.
    
  .PARAMETER  Credential
		Credentials for accessing the Sumo Logic API. Unneccessary if New-SumoCredential has been used.

	.EXAMPLE
		PS C:\> Get-SumoCollector -Name SUMOCOLLECT01 | Set-SumoCollector -Name SUMOCOLLECT00 -Description "Test Collector" -Ephemeral $True
    
      Modifies the Name property of SUMOCOLLECT01 to be SUMOCOLLECT00, the Description property to become "Test Collector," and flags the Collector as Ephemeral. If a Collector is flagged as ephemeral, the Collector will be deleted automatically after some period being offline.

	.INPUTS
    SumoTools.Collector

	.OUTPUTS
		SumoTools.Collector

	.LINK
		https://github.com/ScriptAutomate/SumoTools
  .LINK
    https://github.com/SumoLogic/sumo-api-doc/wiki
  .LINK
		https://halfwaytoinfinite.wordpress.com
    
  .COMPONENT
    Invoke-WebRequest
    Invoke-RestMethod
#>
[CmdletBinding()]
Param
(
  [Parameter(ParameterSetName='Base',Mandatory=$True,ValueFromPipelineByPropertyName=$True)]
  [Alias("CollectorID")]
  [Int]$ID,
  
  [Parameter(ParameterSetName='Base',Mandatory=$False)]
  [System.Management.Automation.PSCredential]$Credential,
  
  [Parameter(ParameterSetName='Base',Mandatory=$False)]
  [Alias("CollectorName")]
  [String]$Name,
  [Parameter(ParameterSetName='Base',Mandatory=$False)]
  [Bool]$Ephemeral,
  [Parameter(ParameterSetName='Base',Mandatory=$False)]
  [String]$TimeZone,
  [Parameter(ParameterSetName='Base',Mandatory=$False)]
  [String]$Description,
  [Parameter(ParameterSetName='Base',Mandatory=$False)]
  [String]$Category,  
  [Parameter(ParameterSetName='Base',Mandatory=$False)]
  [String]$HostName,
  [Parameter(ParameterSetName='Base',Mandatory=$False)]
  [Int64]$CutoffTimestamp
)
  Begin {
    # Checking for credentials
    $ModuleLocation = (Get-Module SumoTools).Path.Replace('\SumoTools.psm1','')
    $SumoPass = "$ModuleLocation\SumoAuth1"
    $SumoUser = "$ModuleLocation\SumoAuth2"
    if (!$Credential) {
      if ((Test-Path "$SumoPass") -and (Test-Path "$SumoUser")) {
        $CredUserSecure = Get-Content "$ModuleLocation\SumoAuth2" | ConvertTo-SecureString
        $BSTRU = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($CredUserSecure)
        $CredUser = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTRU)
        $CredPass = Get-Content "$ModuleLocation\SumoAuth1" | ConvertTo-SecureString
        $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "$CredUser",$CredPass
      }
      else {
        Write-Error "Failure to find credentials. You must run New-SumoCredential before you can use the SumoTools Module."
        break
      }
    }
    $SumoBaseAPI = "$global:SumoBaseAPIHost/api"
    
    if ($InputObject) {
      $TypeName = $InputObject | Get-Member | select-object -ExpandProperty TypeName
      if ($TypeName -ne "SumoTools.Collector") {
          Write-Error "Illegal type name on object input for -InputObject parameter! Expected object type: SumoTools.Collector"
          break
      }  
    }
  }
  
  Process {
    if (!$ID) {$APIID = $InputObject.ID}
    else {$APIID = $ID}
    $TargetCollectorURI = "$SumoBaseAPI/v1/collectors/$APIID"
    $Retrieve = Invoke-WebRequest "$TargetCollectorURI" -Credential $Credential
    $ETAG = $Retrieve.Headers.Etag
    $ETAGHash = @{'If-Match'= "$ETAG"}
    $CollectorConfig = ($Retrieve.Content | ConvertFrom-Json).Collector
    $CollectorConfigType = $CollectorConfig.CollectorType

    $ConfigNames = ($CollectorConfig | Get-Member -MemberType NoteProperty).Name
    $ConfigsSorted = $ConfigNames | sort
    $ParamsSorted = $PSBoundParameters.Keys | sort
    $Existing = (Compare-Object $ConfigNames $ParamsSorted -ExcludeDifferent -IncludeEqual).InputObject
    
    foreach ($ConfigName in $ConfigNames) {
      if ($Existing | select-string $ConfigName) {
        New-Variable -Name "New$ConfigName" -Value (Get-Variable -Name $ConfigName).Value
      }
      else {New-Variable -Name "New$ConfigName" -Value $CollectorConfig.$ConfigName}
    }
    
    # Discovering what parameters were used in relevant parameter set
    $CommandName = $PSCmdlet.MyInvocation.InvocationName
    $ParameterList = Get-Command -Name $CommandName
    $PossibleParams = ($ParameterList.Parameters.Values).Name
    
    # Create splat of appropriate collector config items, and for Invoke-RestMethod
    foreach ($ParamUsed in $PSBoundParameters.Keys) {
      if (($ParamUsed | Select-String $PossibleParams) -and $ParamUsed -notlike "Credential") {
        if ((Compare-Object $ParamUsed $ConfigNames | where {$_.SideIndicator -eq '<='})) {
          New-Variable -Name "New$ParamUsed" -Value (Get-Variable -Name "$ParamUsed").Value
        }
      }
    }

    foreach ($ConfigSetting in (Get-Variable -Name "New*" -Scope Local).Name) {
      # Property names in JSON have first letter lowercase; converting first
      $SplatName = $ConfigSetting -replace 'new',''
      $SplatName = $SplatName -replace $SplatName.Substring(0,1),$SplatName.Substring(0,1).ToLower()
      
      # Filters are treated a little special, being hashtables
      if ($SplatName -eq "sourcesyncMode") {
        $CollectorSplat += @{'sourceSyncMode'=((Get-Variable -Name "NewSourceSyncMode").Value)}
      }
      else {
        # The other properties outside of Filters are much easier
        $CollectorSplat += @{"$SplatName"=((Get-Variable -Name "$ConfigSetting").Value)}
      }
    }
    $Props = @{'collector'=$CollectorSplat}
    $ModifiedCollectorConfig = New-Object -TypeName PSObject -Property $Props | ConvertTo-Json -Depth 3
    Remove-Variable "Props","CollectorSplat","New*" -Scope Local

    $RESTSplat = @{'Uri'="$TargetCollectorURI"
                   'Method'="Put"
                   'ContentType'="application/json"
                   'Body'="$ModifiedCollectorConfig"
                   'Headers'=$ETAGHash
                   'Credential'=$Credential}      
    Write-Verbose "Invoking REST method for modified $CollectorType source, $($CollectorConfig.Name)..."

    try {
      $Output = Invoke-RestMethod @RestSplat
      $Output.collector.PSObject.TypeNames.Insert(0, "SumoTools.Collector")
      $Output.collector
    }
    catch {
      Write-Error $_
      break
    }
  }
}

function Get-SumoCollectorSource {
<#
	.SYNOPSIS
		Uses the Sumo Logic Collector Management API to query Sumo Collector Source information.

	.DESCRIPTION
		Get-SumoCollectorSource queries the Collector Management API for Collector Source information. The returned JSON information is converted into happy PowerShell objects.

	.PARAMETER  Name
		Name of target Sumo Collector, to retrieve Collector Sources. Does NOT take wildcards. If parameter isn't used, absolutely all sources are retrieved.

  .PARAMETER  Credential
		Credentials for accessing the Sumo Logic API. Unneccessary if New-SumoCredential has been used.

	.EXAMPLE
		PS C:\> Get-SumoCollectorSource -Name SUMOCOLLECT01
    
      Returns all sources for the collector named "SUMOCOLLECT01"
      
  .EXAMPLE
		PS C:\> Get-SumoCollector -Inactive | Get-SumoCollectorSource
    
      Returns a list of all sources tied to inactive collectors.

  .EXAMPLE
    PS C:\> Get-SumoCollectorSource -Name SUMOCOLLECT01 | where {$_.Name -like "*IIS*"}
    
      Retrieve all sources from the collector, SUMOCOLLECT01, with "IIS" being found in the source name.

	.INPUTS
		System.String

	.OUTPUTS
		SumoTools.Collector.Source

	.LINK
		https://github.com/ScriptAutomate/SumoTools
  .LINK
    https://github.com/SumoLogic/sumo-api-doc/wiki
  .LINK
		https://halfwaytoinfinite.wordpress.com
    
  .COMPONENT
    Invoke-RestMethod
#>
[CmdletBinding()]
Param
(
  [Parameter(Mandatory=$False,
    ValueFromPipelineByPropertyName=$True,
    ValueFromPipeline=$True)]
  [Alias("CollectorName")]
  [String[]]$Name,
  [Parameter(Mandatory=$False)]
  [System.Management.Automation.PSCredential]$Credential
)
  Begin {
    # Checking for credentials
    $ModuleLocation = (Get-Module SumoTools).Path.Replace('\SumoTools.psm1','')
    $SumoPass = "$ModuleLocation\SumoAuth1"
    $SumoUser = "$ModuleLocation\SumoAuth2"
    if (!$Credential) {
      if ((Test-Path "$SumoPass") -and (Test-Path "$SumoUser")) {
        $CredUserSecure = Get-Content "$ModuleLocation\SumoAuth2" | ConvertTo-SecureString
        $BSTRU = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($CredUserSecure)
        $CredUser = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTRU)
        $CredPass = Get-Content "$ModuleLocation\SumoAuth1" | ConvertTo-SecureString
        $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "$CredUser",$CredPass
      }
      else {
        Write-Error "Failure to find credentials. You must run New-SumoCredential before you can use the SumoTools Module."
        break
      }
    }
    $SumoBaseAPI = "$global:SumoBaseAPIHost/api"
  }
  
  Process {
    $Retrieve = Invoke-RestMethod "$SumoBaseAPI/v1/collectors" -Credential $Credential
    if (!$Name) {$Collectors = $Retrieve.Collectors}
    else {
      foreach ($Query in $Name) {
        $Collectors += $Retrieve.Collectors | where {$_.Name -like "$Query"}
      }
    }  
    foreach ($Collector in $Collectors) {
      $SourceLink = $Collector.links.href
      $SourceConfig = Invoke-RestMethod "$SumoBaseAPI/$SourceLink" -Credential $Credential
      foreach ($Source in $SourceConfig.Sources) {
        $Source | Add-Member -MemberType NoteProperty -Name collectorName -Value $Collector.Name
        $Source | Add-Member -MemberType NoteProperty -Name collectorID -Value $Collector.ID
        $Source.PSObject.TypeNames.Insert(0, "SumoTools.Collector.Source")
        $Source
      }
    } #foreach ($Collector in $Collectors)
  } #Process block end
}

function New-SumoCollectorSource {
<#
	.SYNOPSIS
		Uses the Sumo Logic Collector Management API to add a new Source to a Collector.

	.DESCRIPTION
		Uses the Sumo Logic Collector Management API to add a new Source to a Collector. The returned JSON information is converted into happy PowerShell objects.

	.PARAMETER  Name
		Name of Sumo Collector. Does NOT take wildcards.

  .PARAMETER  Credential
		Credentials for accessing the Sumo Logic API. Unneccessary if New-SumoCredential has been used.

	.EXAMPLE
		PS C:\>Get-SumoCollector -Name SUMOCOLLECT01 | New-SumoCollectorSource -JSONFile C:\sumo\sources.json
    
      Creates a new Sumo Collector Source on the Sumo Collector, SUMOCOLLECT01, using the contents of the c:\sumo\source.json file.

	.EXAMPLE
    PS C:\>$sshpass = Read-Host "Enter SSH Key Pass" -AsSecureString
    
    
    PS C:\>$newsources = Import-Csv newsources.csv
    
    
    PS C:\>$newsources | New-SumoCollectorSource -RemoteFileV2 -KeyPassword $sshpass -MultilineProcessingEnabled $false -Verbose
    

      Using the contents of newsources.csv to fulfill all other mandatory (and otherwise) parameters for RemoteFileV2 sources, New-SumoCollectorSource adds new Sumo Collector Sources. In this case, all of them have the same KeyPassword, and have MultilineProcessing disabled. The verbose flag is being used here, for possible troubleshooting assistance.

	.EXAMPLE
    PS C:\> $Splat = @{"RemoteHosts"="SSHSOURCE01"
    >>                 "RemotePort"=22
    >>                 "RemoteUser"="sumo.serv.account"
    >>                 "KeyPassword"=$sshpass
    >>                 "KeyPath"="c:\sumokeys\sumo.srv.account"
    >>                 "PathExpression"="/var/log/messages"
    >>                 "MultilineProcessingEnabled"=$false
    >>                 "TimeZone"="America/Chicago"
    >>                 "Category"="SSH_VARLOG_MESSAGES"
    >>                 "Name"="SSHSOURCE01_LINUX_MESSAGES"}
    >>
    PS C:\> New-SumoCollectorSource -RemoteFileV2 -Verbose @Splat
    
    
      Creating a new Sumo Collector Remote File Source with splatting. This is nicer in scripts, and also in help documentation.

	.EXAMPLE
    PS C:\>New-SumoCollectorSource -RemoteFileV2 -RemoteHosts "SSHSOURCE01" -RemotePort 22 -RemoteUser "sumo.serv.account" -KeyPassword $sshpass -KeyPath "c:\sumokeys\sumo.srv.account" -PathExpression "/var/log/messages" -MultilineProcessingEnabled $false -TimeZone "America/Chicago" -Category "SSH_VARLOG_MESSAGES" -Name "SSHSOURCE01_LINUX_MESSAGES" -Verbose
    
      Creating a new Sumo Collector Remote File Source, using a Secure.String that has been stored in $sshpass for the KeyPassword parameter. Verbose flag is on.

	.INPUTS
		System.String
    SumoTools.Collector.Source.Filter

	.OUTPUTS
		SumoTools.Collector.Source

	.LINK
		https://github.com/ScriptAutomate/SumoTools
  .LINK
    https://github.com/SumoLogic/sumo-api-doc/wiki
  .LINK
		https://halfwaytoinfinite.wordpress.com
    
  .COMPONENT
    Invoke-RestMethod
#>
[CmdletBinding()]
Param
(
  [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,Position=0)]
  [Alias('ID')]
  [Int]$CollectorID,
  [Parameter(ParameterSetName="JSONFile",Mandatory=$True,Position=1)]
  [String]$JSONFile,
  [Parameter(Mandatory=$False)]
  [System.Management.Automation.PSCredential]$Credential,
  
  [Parameter(ParameterSetName="LocalFile",Mandatory=$True)]
  [Alias('LocalFileSource')]
  [Switch]$LocalFile,
  [Parameter(ParameterSetName="LocalFile",Mandatory=$True,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="RemoteFileV2",Mandatory=$True,ValueFromPipelineByPropertyName=$True)]
  [String]$PathExpression,
  [Parameter(ParameterSetName="LocalFile",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [String[]]$BlackList,
  
  [Parameter(ParameterSetName="RemoteFileV2",Mandatory=$True)]
  [Alias('RemoteFileSource')]
  [Switch]$RemoteFileV2,
  [Parameter(ParameterSetName="RemoteFileV2",Mandatory=$True,ValueFromPipelineByPropertyName=$True)]
  [String[]]$RemoteHosts,
  [Parameter(ParameterSetName="RemoteFileV2",Mandatory=$True,ValueFromPipelineByPropertyName=$True)]
  [Int]$RemotePort,
  [Parameter(ParameterSetName="RemoteFileV2",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="RemoteWindowsEventLog",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [String]$RemoteUser,
  [Parameter(ParameterSetName="RemoteFileV2",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [System.Security.SecureString]$RemotePassword,
  [Parameter(ParameterSetName="RemoteFileV2",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [String]$KeyPath,
  [Parameter(ParameterSetName="RemoteFileV2",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [System.Security.SecureString]$KeyPassword,

  [Parameter(ParameterSetName="LocalWindowsEventLog",Mandatory=$True)]
  [Alias('LocalWindowsEventLogSource')]
  [Switch]$LocalWindowsEventLog,
  
  [Parameter(ParameterSetName="RemoteWindowsEventLog",Mandatory=$True)]
  [Alias('RemoteWindowsEventLogSource')]
  [Switch]$RemoteWindowsEventLog,
  [Parameter(ParameterSetName="RemoteWindowsEventLog",Mandatory=$True,ValueFromPipelineByPropertyName=$True)]
  [String]$Domain,
  [Parameter(ParameterSetName="RemoteWindowsEventLog",Mandatory=$True)]
  [System.Security.SecureString]$Password,
  [Parameter(ParameterSetName="RemoteWindowsEventLog",Mandatory=$True,ValueFromPipelineByPropertyName=$True)]
  [String[]]$Hosts,
  [Parameter(ParameterSetName="RemoteWindowsEventLog",Mandatory=$True,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="LocalWindowsEventLog",Mandatory=$True,ValueFromPipelineByPropertyName=$True)]  
  [ValidateSet("Security","Application","System","Others")]
  [String[]]$LogNames,
  
  [Parameter(ParameterSetName="Syslog",Mandatory=$True)]
  [Alias('SysLogSource')]
  [Switch]$SysLog,
  [Parameter(ParameterSetName="Syslog",Mandatory=$True,ValueFromPipelineByPropertyName=$True)]
  [String]$Port,
  [Parameter(ParameterSetName="Syslog",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [String]$Protocol="UDP",
  
  [Parameter(ParameterSetName="HTTP",Mandatory=$True)]
  [Alias('HTTPSource')]
  [Switch]$HTTP,

  [Parameter(ParameterSetName="Script",Mandatory=$True)]
  [Alias('ScriptSource')]
  [Switch]$Script,
  [Parameter(ParameterSetName="Script",Mandatory=$True,ValueFromPipelineByPropertyName=$True)]
  [String[]]$ScriptBlock,
  [Parameter(ParameterSetName="Script",Mandatory=$True,ValueFromPipelineByPropertyName=$True)]
  [String]$ScriptFile,
  [Parameter(ParameterSetName="Script",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [String]$WorkingDirectory,
  [Parameter(ParameterSetName="Script",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Int]$TimeOutInMilliseconds,
  [Parameter(ParameterSetName="Script",Mandatory=$True,ValueFromPipelineByPropertyName=$True)]
  [String]$CronExpression,
  
  # Properties shared across all sources
  [Parameter(ParameterSetName="HTTP",Mandatory=$True,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="Script",Mandatory=$True,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="LocalFile",Mandatory=$True,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="RemoteFileV2",Mandatory=$True,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="Syslog",Mandatory=$True,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="RemoteWindowsEventLog",Mandatory=$True,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="LocalWindowsEventLog",Mandatory=$True,ValueFromPipelineByPropertyName=$True)]
  [Alias('SourceName')]
  [String]$Name,
  [Parameter(ParameterSetName="HTTP",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="Script",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="LocalFile",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="RemoteFileV2",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="Syslog",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="RemoteWindowsEventLog",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="LocalWindowsEventLog",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [String]$Description,
  [Parameter(ParameterSetName="HTTP",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="Script",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="LocalFile",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="RemoteFileV2",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="Syslog",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="RemoteWindowsEventLog",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="LocalWindowsEventLog",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [String]$Category,
  [Parameter(ParameterSetName="HTTP",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="Script",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="LocalFile",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="RemoteFileV2",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="Syslog",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="RemoteWindowsEventLog",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="LocalWindowsEventLog",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [String]$HostName,
  [Parameter(ParameterSetName="HTTP",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="Script",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="LocalFile",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="RemoteFileV2",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="Syslog",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="RemoteWindowsEventLog",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="LocalWindowsEventLog",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [String]$TimeZone,
  [Parameter(ParameterSetName="HTTP",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="Script",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="LocalFile",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="RemoteFileV2",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="Syslog",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="RemoteWindowsEventLog",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="LocalWindowsEventLog",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Bool]$AutomaticDateParsing,
  [Parameter(ParameterSetName="HTTP",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="Script",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="LocalFile",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="RemoteFileV2",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="Syslog",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="RemoteWindowsEventLog",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="LocalWindowsEventLog",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Bool]$MultilineProcessingEnabled,
  [Parameter(ParameterSetName="HTTP",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="Script",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="LocalFile",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="RemoteFileV2",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="Syslog",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="RemoteWindowsEventLog",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="LocalWindowsEventLog",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Bool]$UseAutolineMatching,
  [Parameter(ParameterSetName="HTTP",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="Script",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="LocalFile",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="RemoteFileV2",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="Syslog",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="RemoteWindowsEventLog",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="LocalWindowsEventLog",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [String]$ManualPrefixRegexp,
  [Parameter(ParameterSetName="HTTP",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="Script",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="LocalFile",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="RemoteFileV2",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="Syslog",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="RemoteWindowsEventLog",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="LocalWindowsEventLog",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Bool]$ForceTimeZone,
  [Parameter(ParameterSetName="HTTP",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="Script",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="LocalFile",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="RemoteFileV2",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="Syslog",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="RemoteWindowsEventLog",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="LocalWindowsEventLog",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [String]$DefaultDateFormat,
  [Parameter(ParameterSetName="HTTP",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="Script",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="LocalFile",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="RemoteFileV2",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="Syslog",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="RemoteWindowsEventLog",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="LocalWindowsEventLog",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [String]$CutOffTimeStamp,
  [Parameter(ParameterSetName="HTTP",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="Script",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="LocalFile",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="RemoteFileV2",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="Syslog",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="RemoteWindowsEventLog",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="LocalWindowsEventLog",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [String]$CutoffRelativeTime,
  [Parameter(ParameterSetName="HTTP",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="Script",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="LocalFile",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="RemoteFileV2",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="Syslog",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="RemoteWindowsEventLog",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Parameter(ParameterSetName="LocalWindowsEventLog",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [Object[]]$Filters
)
  Begin {
    # Checking for credentials
    $ModuleLocation = (Get-Module SumoTools).Path.Replace('\SumoTools.psm1','')
    $SumoPass = "$ModuleLocation\SumoAuth1"
    $SumoUser = "$ModuleLocation\SumoAuth2"
    if (!$Credential) {
      if ((Test-Path "$SumoPass") -and (Test-Path "$SumoUser")) {
        $CredUserSecure = Get-Content "$ModuleLocation\SumoAuth2" | ConvertTo-SecureString
        $BSTRU = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($CredUserSecure)
        $CredUser = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTRU)
        $CredPass = Get-Content "$ModuleLocation\SumoAuth1" | ConvertTo-SecureString
        $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "$CredUser",$CredPass
      }
      else {
        Write-Error "Failure to find credentials. You must run New-SumoCredential before you can use the SumoTools Module."
        break
      }
    }
    $SumoBaseAPI = "$global:SumoBaseAPIHost/api"
    
    # Confirming that -Filters input object is legal
    if ($Filters) {
      $TypeName = $Filters | Get-Member | select-object -ExpandProperty TypeName
      if ($TypeName -ne "SumoTools.Collector.Source.Filter") {
          Write-Error "Illegal type name on object input for -Filters parameter! Expected object type: SumoTools.SumoFilterObject"
          break
      }    
    }
  }
  
  Process {
    $SumoSourcesBase = "$SumoBaseAPI/v1/collectors/$CollectorID/sources"    
    Write-Verbose "Testing credentials and Collector ID..."
    $null = Invoke-WebRequest $SumoSourcesBase -Credential $Credential -ErrorVariable Failed
    if ($Failed) {break}
    if ($JSONFile) {
      Write-Verbose "Checking if file exists..."
      if (!(Test-Path $JSONFile)) {
        Write-Error "File not found: $JSONFile"
        break
      } 
      Write-Verbose "Invoking REST method for new source with $JSONFile..."
      $Output = Invoke-RestMethod -Uri $SumoSourcesBase -Method Post -ContentType "application/json" -InFile $JSONFile -Credential $Credential -ErrorVariable Failed
      if ($Failed) {break}
    }
    else {
#      if ($HTTP) {
#         $HTTPConfirm = Invoke-RestMethod "$SumoBaseAPI/v1/collectors/$CollectorID" -Credential $Credential
#        if () {
#          $SourceType = "HTTP"
#        }
#      }
      if ($LocalFile) {$SourceType = "LocalFile"}
      elseif ($Script) {$SourceType = "Script"}
      elseif ($SysLog) {$SourceType = "SysLog"}
      elseif ($LocalWindowsEventLog) {$SourceType = "LocalWindowsEventLog"}  
      elseif ($RemoteFileV2) {
        $SourceType = "RemoteFileV2"
        if (($RemotePassword -and $RemoteUser) -and !($KeyPassword -or $KeyPath)) {
          $RemotePasswordPlainText = (New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "NULL",$RemotePassword).GetNetworkCredential().Password
          $authMethod = "password"
        }
        elseif (($RemoteUser -and $KeyPath -and $KeyPassword) -and !($RemotePassword)) {
          $KeyPasswordPlainText = (New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "NULL",$KeyPassword).GetNetworkCredential().Password
          $authMethod = "key"          
        }
        elseif (($RemoteUser -and $KeyPath) -and !($RemotePassword -or $KeyPassword)) {
          $authMethod = "key" 
        }
        else {
          Write-Error "RemoteFileV2 source supports three different ways of authenticating. You must either use a combination of [ -RemoteUser / -RemotePassword ], [-KeyPath / -RemoteUser], or [-KeyPath / -KeyPassword / -RemoteUser] parameters."
          break
        }
      }
      elseif ($RemoteWindowsEventLog) {
        $SourceType = "RemoteWindowsEventLog"
        $PasswordPlainText = (New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "NULL",$Password).GetNetworkCredential().Password
      }
      $SourceSplat = [ordered]@{"sourceType"="$SourceType"}
      
      # Discovering what parameters were used in relevant parameter set
      $CommandName = $PSCmdlet.MyInvocation.InvocationName
      $ParameterList = Get-Command -Name $CommandName
      $PossibleParams = ($ParameterList.Parameters.Values | 
        where {(
          $_.ParameterSets.Keys -like "$SourceType"
          ) -or (
          $_.ParameterSets.Keys -like !"JSONFile")
        }
      ).Name
      
      # Create splat of appropriate source config items, and for Invoke-RestMethod
      foreach ($ParamUsed in $PSBoundParameters.Keys) {
        if (($ParamUsed | Select-String $PossibleParams) -and $ParamUsed -notlike "$SourceType") {
          # Property names in JSON have first letter lowercase; converting first
          $SplatProp = $ParamUsed -replace $ParamUsed.Substring(0,1),$ParamUsed.Substring(0,1).ToLower()
          if ($SplatProp -like "KeyPassword") {
            $SourceSplat += @{"$SplatProp"="$KeyPasswordPlainText"}
          }
          elseif ($SplatProp -like "RemotePassword") {
            $SourceSplat += @{"$SplatProp"="$RemotePasswordPlainText"}
          }
          elseif ($SplatProp -like "Password") {
            $SourceSplat += @{"$SplatProp"="$PasswordPlainText"}
          }
          elseif ($SplatProp -eq "filters") {
            # Filters are treated a little special
            $FilterSplatArray = @()
            foreach ($Filter in $Filters) {
              foreach ($PropertyName in (($Filter | Get-Member -MemberType NoteProperty).Name)) {
                $FilterSplat += @{$PropertyName=$Filter.$PropertyName}
              }
              $FilterSplatArray += $FilterSplat
              Clear-Variable FilterSplat
            }
            $SourceSplat += @{'filters'=$FilterSplatArray}
            Clear-Variable FilterSplatArray
          }
          else {
            $SourceSplat += @{"$SplatProp"=((Get-Variable -Name $ParamUsed).Value)}
          }
        }
      }
      # Ensure that the required "authMethod" property is included if needed
      if ($RemoteFileV2) {
        $SourceSplat += @{"authMethod"="$authMethod"}
      }
      $SourceContent = @{'source'=$SourceSplat}
      $SourceConfig = New-Object -TypeName PSObject -Property $SourceContent | ConvertTo-JSON -Depth 3
      $RESTSplat = @{'Uri'="$SumoSourcesBase";
                     'Method'="Post";
                     'ContentType'="application/json";
                     'Body'="$SourceConfig";
                     'Credential'=$Credential}
#      $RESTSplat
      Write-Verbose "Invoking REST method for new $SourceType source..."
      $Output = Invoke-RestMethod @RESTSplat
    }

    $Collector = Get-SumoCollector | where {$_.ID -eq $CollectorID}
    $Output.source | Add-Member -MemberType NoteProperty -Name collectorName -Value $Collector.Name
    $Output.source | Add-Member -MemberType NoteProperty -Name collectorID -Value $CollectorID
    $Output.source.PSObject.TypeNames.Insert(0, "SumoTools.Collector.Source")
    $Output.source
  }
}

function Remove-SumoCollectorSource {
<#
	.SYNOPSIS
		Uses the Sumo Logic Collector Management API to remove a Source from a Collector.

	.DESCRIPTION
		Uses the Sumo Logic Collector Management API to remove a Source from a Collector. Will output WARNING messages when removing a source.

	.PARAMETER  CollectorID
		ID of the target collector. You can retrieve this value with Get-SumoCollector.

	.PARAMETER  SourceID
		ID of the target Collector Source. You can retrieve this value with Get-SumoCollectorSource. "ID" can also be used as an alias for this parameter.

  .PARAMETER  Credential
		Credentials for accessing the Sumo Logic API. Unneccessary if New-SumoCredential has been used.

	.EXAMPLE
		PS C:\>Get-SumoCollector -Name SUMOCOLLECT01 | Get-SumoCollectorSource | where {$_.Name -like "DECOMSERV01"} | Remove-SumoCollectorSource
    
      Removes the Sumo Collector Source named "DECOMSERV01" from the Sumo Collector named SUMOCOLLECT01.
      
	.INPUTS
		System.String

	.OUTPUTS
		None

	.LINK
		https://github.com/ScriptAutomate/SumoTools
  .LINK
    https://github.com/SumoLogic/sumo-api-doc/wiki
  .LINK
		https://halfwaytoinfinite.wordpress.com
    
  .COMPONENT
    Invoke-RestMethod
#>
[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
Param
(
  [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True)]
  [String]$CollectorID,
  [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True)]
  [Alias("ID")]
  [String]$SourceID,
  [Parameter(Mandatory=$False)]
  [System.Management.Automation.PSCredential]$Credential
)
  Begin {
    # Checking for credentials
    $ModuleLocation = (Get-Module SumoTools).Path.Replace('\SumoTools.psm1','')
    $SumoPass = "$ModuleLocation\SumoAuth1"
    $SumoUser = "$ModuleLocation\SumoAuth2"
    if (!$Credential) {
      if ((Test-Path "$SumoPass") -and (Test-Path "$SumoUser")) {
        $CredUserSecure = Get-Content "$ModuleLocation\SumoAuth2" | ConvertTo-SecureString
        $BSTRU = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($CredUserSecure)
        $CredUser = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTRU)
        $CredPass = Get-Content "$ModuleLocation\SumoAuth1" | ConvertTo-SecureString
        $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "$CredUser",$CredPass
      }
      else {
        Write-Error "Failure to find credentials. You must run New-SumoCredential before you can use the SumoTools Module."
        break
      }
    }
    $SumoBaseAPI = "$global:SumoBaseAPIHost/api"
  }
  
  Process {
    try {
      $SourceProperties = Get-SumoCollector -Credential $Credential | 
        where {$_.ID -eq $CollectorID} | 
        Get-SumoCollectorSource -Credential $Credential | 
        where {$_.ID -eq $SourceID}
        
      # If statement is in regards to activating the -WhatIf and -Confirm common parameters
      if ($PSCmdlet.ShouldProcess($SourceID)) {
        Write-Verbose "REMOVING Sumo Collector Source $SourceID"
        Write-Verbose "Collector Name: $($SourceProperties.CollectorName)"
        Write-Verbose "Source Name: $($SourceProperties.Name)"
        $WebPageBase = "$global:SumoBaseAPIHost/api/v1/collectors/$CollectorID/sources/$SourceID"
        $null = Invoke-RestMethod -Uri $WebPageBase -Method Delete -Credential $Credential -ErrorAction Stop
        Write-Warning "REMOVED Sumo Collector Source. Source Name: $($SourceProperties.Name)"
      }
    }
    catch {Write-Error $Error[0]}
  }
}

function Remove-SumoCollector {
<#
	.SYNOPSIS
		Uses the Sumo Logic Collector Management API to remove a Sumo Collector.

	.DESCRIPTION
		Uses the Sumo Logic Collector Management API to remove a Sumo Collector. Will output WARNING messages when removing a source.

	.PARAMETER  ID
		ID of the target collector. You can retrieve this value with Get-SumoCollector. "CollectorID" can also be used as an alias for this parameter.

  .PARAMETER  Credential
		Credentials for accessing the Sumo Logic API. Unneccessary if New-SumoCredential has been used.

	.EXAMPLE
		PS C:\>Get-SumoCollector -Name SUMOCOLLECT01 | Remove-SumoCollector
    
      Removes the Sumo Collector named SUMOCOLLECT01.
      
	.INPUTS
		System.String

	.OUTPUTS
    None

	.LINK
		https://github.com/ScriptAutomate/SumoTools
  .LINK
    https://github.com/SumoLogic/sumo-api-doc/wiki
  .LINK
		https://halfwaytoinfinite.wordpress.com
    
  .COMPONENT
    Invoke-RestMethod
#>
[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
Param
(
  [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True)]
  [Alias("CollectorID")]
  [String[]]$ID,
  [Parameter(Mandatory=$False)]
  [System.Management.Automation.PSCredential]$Credential
)
  Begin {
    # Checking for credentials
    $ModuleLocation = (Get-Module SumoTools).Path.Replace('\SumoTools.psm1','')
    $SumoPass = "$ModuleLocation\SumoAuth1"
    $SumoUser = "$ModuleLocation\SumoAuth2"
    if (!$Credential) {
      if ((Test-Path "$SumoPass") -and (Test-Path "$SumoUser")) {
        $CredUserSecure = Get-Content "$ModuleLocation\SumoAuth2" | ConvertTo-SecureString
        $BSTRU = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($CredUserSecure)
        $CredUser = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTRU)
        $CredPass = Get-Content "$ModuleLocation\SumoAuth1" | ConvertTo-SecureString
        $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "$CredUser",$CredPass
      }
      else {
        Write-Error "Failure to find credentials. You must run New-SumoCredential before you can use the SumoTools Module."
        break
      }
    }
    $SumoBaseAPI = "$global:SumoBaseAPIHost/api"
  }
  
  Process {
    foreach ($Collector in $ID) {
      try {
        $CollectorName = (Get-SumoCollector -Credential $Credential | where {$_.ID -eq $ID}).Name
        # If statement is in regards to activating the -WhatIf and -Confirm common parameters
        if ($PSCmdlet.ShouldProcess($Collector)) {
          Write-Verbose "REMOVING Sumo Collector $Collector."
          Write-Verbose "Name: $CollectorName"
          $WebPageBase = "$global:SumoBaseAPIHost/api/v1/collectors/$Collector"
          $null = Invoke-RestMethod -Uri $WebPageBase -Method Delete -Credential $Credential -ErrorAction Stop
          Write-Warning "REMOVED Sumo Collector $Collector. Name: $CollectorName"
        }
      }
      catch {Write-Error $Error[0]}
    }
  }
}

function Set-SumoCollectorSource {
<#
	.SYNOPSIS
		Uses the Sumo Logic Collector Management API to modify a Sumo Collector Source.

	.DESCRIPTION
		Uses the Sumo Logic Collector Management API to modify a Sumo Collector Source. The returned JSON information is converted into happy PowerShell objects.

	.PARAMETER  ID
		ID of the target Collector Source. You can retrieve this value with Get-SumoCollectorSource. "SourceID" can also be used as an alias for this parameter.

  .PARAMETER  Credential
		Credentials for accessing the Sumo Logic API. Unneccessary if New-SumoCredential has been used.
      
	.INPUTS
		System.String
    SumoTools.Collector.Source.Filter

	.OUTPUTS
		SumoTools.Collector.Source

	.LINK
		https://github.com/ScriptAutomate/SumoTools
  .LINK
    https://github.com/SumoLogic/sumo-api-doc/wiki
  .LINK
		https://halfwaytoinfinite.wordpress.com
    
  .COMPONENT
    Invoke-RestMethod
#>
[CmdletBinding()]
Param
(
  [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True)]
  [Alias("SourceID")]
  [Int]$ID,
  [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True)]
  [Int]$CollectorID,
  [Parameter(Mandatory=$False)]
  [System.Management.Automation.PSCredential]$Credential,
  
  [Parameter(ParameterSetName="LocalFile",Mandatory=$True)]
  [Alias('LocalFileSource')]
  [Switch]$LocalFile,
  [Parameter(ParameterSetName="LocalFile",Mandatory=$False)]
  [Parameter(ParameterSetName="RemoteFileV2",Mandatory=$False)]
  [String]$PathExpression,
  [Parameter(ParameterSetName="LocalFile",Mandatory=$False)]
  [Parameter(ParameterSetName="RemoteFileV2",Mandatory=$False)]
  [String[]]$Blacklist,
  
  [Parameter(ParameterSetName="RemoteFileV2",Mandatory=$True)]
  [Alias('RemoteFileSource')]
  [Switch]$RemoteFileV2,
  [Parameter(ParameterSetName="RemoteFileV2",Mandatory=$False)]
  [String[]]$RemoteHosts,
  [Parameter(ParameterSetName="RemoteFileV2",Mandatory=$False)]
  [Int]$RemotePort,
  [Parameter(ParameterSetName="RemoteFileV2",Mandatory=$False)]
  [Parameter(ParameterSetName="RemoteWindowsEventLog",Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [String]$RemoteUser,
  [Parameter(ParameterSetName="RemoteFileV2",Mandatory=$False)]
  [System.Security.SecureString]$RemotePassword,
  [Parameter(ParameterSetName="RemoteFileV2",Mandatory=$False)]
  [String]$KeyPath,
  [Parameter(ParameterSetName="RemoteFileV2",Mandatory=$False)]
  [System.Security.SecureString]$KeyPassword,

  [Parameter(ParameterSetName="LocalWindowsEventLog",Mandatory=$True)]
  [Alias('LocalWindowsEventLogSource')]
  [Switch]$LocalWindowsEventLog,
  
  [Parameter(ParameterSetName="RemoteWindowsEventLog",Mandatory=$True)]
  [Alias('RemoteWindowsEventLogSource')]
  [Switch]$RemoteWindowsEventLog,
  [Parameter(ParameterSetName="RemoteWindowsEventLog",Mandatory=$False)]
  [String]$Domain,
  [Parameter(ParameterSetName="RemoteWindowsEventLog",Mandatory=$False)]
  [System.Security.SecureString]$Password,
  [Parameter(ParameterSetName="RemoteWindowsEventLog",Mandatory=$False)]
  [String[]]$Hosts,
  [Parameter(ParameterSetName="RemoteWindowsEventLog",Mandatory=$False)]
  [Parameter(ParameterSetName="LocalWindowsEventLog",Mandatory=$False)]  
  [ValidateSet("Security","Application","System","Others")]
  [String[]]$LogNames,
  
  [Parameter(ParameterSetName="Syslog",Mandatory=$True)]
  [Alias('SysLogSource')]
  [Switch]$SysLog,
  [Parameter(ParameterSetName="Syslog",Mandatory=$False)]
  [String]$Port,
  [Parameter(ParameterSetName="Syslog",Mandatory=$False)]
  [String]$Protocol="UDP",

  [Parameter(ParameterSetName="HTTP",Mandatory=$True)]
  [Alias('HTTPSource')]
  [Switch]$HTTP,

  [Parameter(ParameterSetName="Script",Mandatory=$True)]
  [Alias('ScriptSource')]
  [Switch]$Script,
  [Parameter(ParameterSetName="Script",Mandatory=$False)]
  [String[]]$ScriptBlock,
  [Parameter(ParameterSetName="Script",Mandatory=$False)]
  [String]$ScriptFile,
  [Parameter(ParameterSetName="Script",Mandatory=$False)]
  [String]$WorkingDirectory,
  [Parameter(ParameterSetName="Script",Mandatory=$False)]
  [Int]$TimeOutInMilliseconds,
  [Parameter(ParameterSetName="Script",Mandatory=$False)]
  [String]$CronExpression,
  
  # Properties shared across all sources
  [Parameter(ParameterSetName="HTTP",Mandatory=$False)]
  [Parameter(ParameterSetName="Script",Mandatory=$False)]
  [Parameter(ParameterSetName="LocalFile",Mandatory=$False)]
  [Parameter(ParameterSetName="RemoteFileV2",Mandatory=$False)]
  [Parameter(ParameterSetName="Syslog",Mandatory=$False)]
  [Parameter(ParameterSetName="RemoteWindowsEventLog",Mandatory=$False)]
  [Parameter(ParameterSetName="LocalWindowsEventLog",Mandatory=$False)]
  [Alias('SourceName')]
  [String]$Name,
  [Parameter(ParameterSetName="HTTP",Mandatory=$False)]
  [Parameter(ParameterSetName="Script",Mandatory=$False)]
  [Parameter(ParameterSetName="LocalFile",Mandatory=$False)]
  [Parameter(ParameterSetName="RemoteFileV2",Mandatory=$False)]
  [Parameter(ParameterSetName="Syslog",Mandatory=$False)]
  [Parameter(ParameterSetName="RemoteWindowsEventLog",Mandatory=$False)]
  [Parameter(ParameterSetName="LocalWindowsEventLog",Mandatory=$False)]
  [String]$Description,
  [Parameter(ParameterSetName="HTTP",Mandatory=$False)]
  [Parameter(ParameterSetName="Script",Mandatory=$False)]
  [Parameter(ParameterSetName="LocalFile",Mandatory=$False)]
  [Parameter(ParameterSetName="RemoteFileV2",Mandatory=$False)]
  [Parameter(ParameterSetName="Syslog",Mandatory=$False)]
  [Parameter(ParameterSetName="RemoteWindowsEventLog",Mandatory=$False)]
  [Parameter(ParameterSetName="LocalWindowsEventLog",Mandatory=$False)]
  [String]$Category,
  [Parameter(ParameterSetName="HTTP",Mandatory=$False)]
  [Parameter(ParameterSetName="Script",Mandatory=$False)]
  [Parameter(ParameterSetName="LocalFile",Mandatory=$False)]
  [Parameter(ParameterSetName="RemoteFileV2",Mandatory=$False)]
  [Parameter(ParameterSetName="Syslog",Mandatory=$False)]
  [Parameter(ParameterSetName="RemoteWindowsEventLog",Mandatory=$False)]
  [Parameter(ParameterSetName="LocalWindowsEventLog",Mandatory=$False)]
  [String]$HostName,
  [Parameter(ParameterSetName="HTTP",Mandatory=$False)]
  [Parameter(ParameterSetName="Script",Mandatory=$False)]
  [Parameter(ParameterSetName="LocalFile",Mandatory=$False)]
  [Parameter(ParameterSetName="RemoteFileV2",Mandatory=$False)]
  [Parameter(ParameterSetName="Syslog",Mandatory=$False)]
  [Parameter(ParameterSetName="RemoteWindowsEventLog",Mandatory=$False)]
  [Parameter(ParameterSetName="LocalWindowsEventLog",Mandatory=$False)]
  [String]$TimeZone,
  [Parameter(ParameterSetName="HTTP",Mandatory=$False)]
  [Parameter(ParameterSetName="Script",Mandatory=$False)]
  [Parameter(ParameterSetName="LocalFile",Mandatory=$False)]
  [Parameter(ParameterSetName="RemoteFileV2",Mandatory=$False)]
  [Parameter(ParameterSetName="Syslog",Mandatory=$False)]
  [Parameter(ParameterSetName="RemoteWindowsEventLog",Mandatory=$False)]
  [Parameter(ParameterSetName="LocalWindowsEventLog",Mandatory=$False)]
  [Bool]$AutomaticDateParsing,
  [Parameter(ParameterSetName="HTTP",Mandatory=$False)]
  [Parameter(ParameterSetName="Script",Mandatory=$False)]
  [Parameter(ParameterSetName="LocalFile",Mandatory=$False)]
  [Parameter(ParameterSetName="RemoteFileV2",Mandatory=$False)]
  [Parameter(ParameterSetName="Syslog",Mandatory=$False)]
  [Parameter(ParameterSetName="RemoteWindowsEventLog",Mandatory=$False)]
  [Parameter(ParameterSetName="LocalWindowsEventLog",Mandatory=$False)]
  [Bool]$MultilineProcessingEnabled,
  [Parameter(ParameterSetName="HTTP",Mandatory=$False)]
  [Parameter(ParameterSetName="Script",Mandatory=$False)]
  [Parameter(ParameterSetName="LocalFile",Mandatory=$False)]
  [Parameter(ParameterSetName="RemoteFileV2",Mandatory=$False)]
  [Parameter(ParameterSetName="Syslog",Mandatory=$False)]
  [Parameter(ParameterSetName="RemoteWindowsEventLog",Mandatory=$False)]
  [Parameter(ParameterSetName="LocalWindowsEventLog",Mandatory=$False)]
  [Bool]$UseAutolineMatching,
  [Parameter(ParameterSetName="HTTP",Mandatory=$False)]
  [Parameter(ParameterSetName="Script",Mandatory=$False)]
  [Parameter(ParameterSetName="LocalFile",Mandatory=$False)]
  [Parameter(ParameterSetName="RemoteFileV2",Mandatory=$False)]
  [Parameter(ParameterSetName="Syslog",Mandatory=$False)]
  [Parameter(ParameterSetName="RemoteWindowsEventLog",Mandatory=$False)]
  [Parameter(ParameterSetName="LocalWindowsEventLog",Mandatory=$False)]
  [String]$ManualPrefixRegexp,
  [Parameter(ParameterSetName="HTTP",Mandatory=$False)]
  [Parameter(ParameterSetName="Script",Mandatory=$False)]
  [Parameter(ParameterSetName="LocalFile",Mandatory=$False)]
  [Parameter(ParameterSetName="RemoteFileV2",Mandatory=$False)]
  [Parameter(ParameterSetName="Syslog",Mandatory=$False)]
  [Parameter(ParameterSetName="RemoteWindowsEventLog",Mandatory=$False)]
  [Parameter(ParameterSetName="LocalWindowsEventLog",Mandatory=$False)]
  [Bool]$ForceTimeZone,
  [Parameter(ParameterSetName="HTTP",Mandatory=$False)]
  [Parameter(ParameterSetName="Script",Mandatory=$False)]
  [Parameter(ParameterSetName="LocalFile",Mandatory=$False)]
  [Parameter(ParameterSetName="RemoteFileV2",Mandatory=$False)]
  [Parameter(ParameterSetName="Syslog",Mandatory=$False)]
  [Parameter(ParameterSetName="RemoteWindowsEventLog",Mandatory=$False)]
  [Parameter(ParameterSetName="LocalWindowsEventLog",Mandatory=$False)]
  [String]$DefaultDateFormat,
  [Parameter(ParameterSetName="HTTP",Mandatory=$False)]
  [Parameter(ParameterSetName="Script",Mandatory=$False)]
  [Parameter(ParameterSetName="LocalFile",Mandatory=$False)]
  [Parameter(ParameterSetName="RemoteFileV2",Mandatory=$False)]
  [Parameter(ParameterSetName="Syslog",Mandatory=$False)]
  [Parameter(ParameterSetName="RemoteWindowsEventLog",Mandatory=$False)]
  [Parameter(ParameterSetName="LocalWindowsEventLog",Mandatory=$False)]
  [String]$CutOffTimeStamp,
  [Parameter(ParameterSetName="HTTP",Mandatory=$False)]
  [Parameter(ParameterSetName="Script",Mandatory=$False)]
  [Parameter(ParameterSetName="LocalFile",Mandatory=$False)]
  [Parameter(ParameterSetName="RemoteFileV2",Mandatory=$False)]
  [Parameter(ParameterSetName="Syslog",Mandatory=$False)]
  [Parameter(ParameterSetName="RemoteWindowsEventLog",Mandatory=$False)]
  [Parameter(ParameterSetName="LocalWindowsEventLog",Mandatory=$False)]
  [String]$CutoffRelativeTime,
  [Parameter(ParameterSetName="HTTP",Mandatory=$False)]
  [Parameter(ParameterSetName="Script",Mandatory=$False)]
  [Parameter(ParameterSetName="LocalFile",Mandatory=$False)]
  [Parameter(ParameterSetName="RemoteFileV2",Mandatory=$False)]
  [Parameter(ParameterSetName="Syslog",Mandatory=$False)]
  [Parameter(ParameterSetName="RemoteWindowsEventLog",Mandatory=$False)]
  [Parameter(ParameterSetName="LocalWindowsEventLog",Mandatory=$False)]
  [Object[]]$Filters
)
  Begin {
    # Checking for credentials
    $ModuleLocation = (Get-Module SumoTools).Path.Replace('\SumoTools.psm1','')
    $SumoPass = "$ModuleLocation\SumoAuth1"
    $SumoUser = "$ModuleLocation\SumoAuth2"
    if (!$Credential) {
      if ((Test-Path "$SumoPass") -and (Test-Path "$SumoUser")) {
        $CredUserSecure = Get-Content "$ModuleLocation\SumoAuth2" | ConvertTo-SecureString
        $BSTRU = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($CredUserSecure)
        $CredUser = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTRU)
        $CredPass = Get-Content "$ModuleLocation\SumoAuth1" | ConvertTo-SecureString
        $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "$CredUser",$CredPass
      }
      else {
        Write-Error "Failure to find credentials. You must run New-SumoCredential before you can use the SumoTools Module."
        break
      }
    }
    $SumoBaseAPI = "$global:SumoBaseAPIHost/api"
    
    # Confirming that -Filters input object is legal
    if ($Filters) {
      $TypeName = $Filters | Get-Member | select-object -ExpandProperty TypeName
      if ($TypeName -ne "SumoTools.Collector.Source.Filter") {
          Write-Error "Illegal type name on object input for -Filters parameter! Expected object type: SumoTools.SumoFilterObject"
          break
      }    
    }
  }
  
  Process {
    $TargetSourceURI = "$SumoBaseAPI/v1/collectors/$CollectorID/sources/$ID"
    $Retrieve = Invoke-WebRequest $TargetSourceURI -Credential $Credential
    $ETAG = $Retrieve.Headers.Etag
    $ETAGHash = @{'If-Match'= "$ETAG"}
    $SourceConfig = ($Retrieve.Content | ConvertFrom-Json).Source
    $SourceConfigType = $SourceConfig.SourceType
    
    if ($LocalFile) {$SourceType = "LocalFile"}
    elseif ($Script) {$SourceType = "Script"}
    elseif ($SysLog) {$SourceType = "SysLog"}
    elseif ($HTTP) {$SourceType = "HTTP"}
    elseif ($LocalWindowsEventLog) {$SourceType = "LocalWindowsEventLog"}
    elseif ($RemoteWindowsEventLog) {
      $SourceType = "RemoteWindowsEventLog"
      if ($Password) {
        $PasswordPlainText = (New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "NULL",$Password).GetNetworkCredential().Password
      }
    }
    elseif ($RemoteFileV2) {
      $SourceType = "RemoteFileV2"
      if (($RemotePassword -and $RemoteUser) -and !($KeyPassword -or $KeyPath)) {
        $RemotePasswordPlainText = (New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "NULL",$RemotePassword).GetNetworkCredential().Password
        $authMethod = "password"
      }
      elseif (($RemoteUser -and $KeyPath -and $KeyPassword) -and !($RemotePassword)) {
        $KeyPasswordPlainText = (New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "NULL",$KeyPassword).GetNetworkCredential().Password
        $authMethod = "key"          
      }
      elseif (($RemoteUser -and $KeyPath) -and !($RemotePassword -or $KeyPassword)) {
        $authMethod = "key" 
      }
      elseif ($RemoteUser -or $RemotePassword -or $KeyPassword -or $KeyPath) {
        Write-Error "RemoteFileV2 source supports three different ways of authenticating. You must either use a combination of [ -RemoteUser / -RemotePassword ], [-KeyPath / -RemoteUser], or [-KeyPath / -KeyPassword / -RemoteUser] parameters."
        break
      }
    }
    
    if ("$SourceConfigType" -ne "$SourceType") {
      Write-Error "Source has a sourceType that is different from Set-SumoCollectorSource parameter set. $($SourcConfig.Name) sourceType: $SourceConfigType -- Parameter set selected: $SourceType"
      break
    }
    
    $ConfigNames = ($SourceConfig | Get-Member -MemberType NoteProperty).Name
    $ConfigsSorted = $ConfigNames | sort
    $ParamsSorted = $PSBoundParameters.Keys | sort
    $Existing = (Compare-Object $ConfigNames $ParamsSorted -ExcludeDifferent -IncludeEqual).InputObject
    foreach ($ConfigName in $ConfigNames) {
      if ($Existing | select-string $ConfigName) {
        switch ($ConfigName) {
          "KeyPassword"     {New-Variable -Name "New$ConfigName" -Value "$KeyPasswordPlainText"}
          "RemotePassword"  {New-Variable -Name "New$ConfigName" -Value "$RemotePasswordPlainText"}
          "Password"        {New-Variable -Name "New$ConfigName" -Value "$PasswordPlainText"}
          default           {New-Variable -Name "New$ConfigName" -Value (Get-Variable -Name $ConfigName).Value}
        }
      }
      else {New-Variable -Name "New$ConfigName" -Value $SourceConfig.$ConfigName}
    }
    
    # Discovering what parameters were used in relevant parameter set
    $CommandName = $PSCmdlet.MyInvocation.InvocationName
    $ParameterList = Get-Command -Name $CommandName
    $PossibleParams = ($ParameterList.Parameters.Values | where {($_.ParameterSets.Keys -like "$SourceType")}).Name
    
    # Create splat of appropriate source config items, and for Invoke-RestMethod
    foreach ($ParamUsed in $PSBoundParameters.Keys) {
      if (($ParamUsed | Select-String $PossibleParams) -and $ParamUsed -notlike "$SourceType") {
        if ((Compare-Object $ParamUsed $ConfigNames | where {$_.SideIndicator -eq '<='})) {
          New-Variable -Name "New$ParamUsed" -Value (Get-Variable -Name "$ParamUsed").Value
        }
      }
    }

    foreach ($ConfigSetting in (Get-Variable -Name "New*" -Scope Local).Name) {
      # Property names in JSON have first letter lowercase; converting first
      $SplatName = $ConfigSetting -replace 'new',''
      $SplatName = $SplatName -replace $SplatName.Substring(0,1),$SplatName.Substring(0,1).ToLower()
      
      # Filters are treated a little special, being hashtables
      if ($SplatName -eq "filters") {
        $FilterSplatArray = @()
        foreach ($Filter in $Filters) {
          foreach ($PropertyName in (($Filter | Get-Member -MemberType NoteProperty).Name)) {
            $FilterSplat += @{$PropertyName=$Filter.$PropertyName}
          }
          $FilterSplatArray += $FilterSplat
          Clear-Variable FilterSplat
        }
        $SourceSplat += @{'filters'=$FilterSplatArray}
        Clear-Variable FilterSplatArray
      }
      else {
        # The other properties outside of Filters are much easier
        $SourceSplat += @{"$SplatName"=((Get-Variable -Name "$ConfigSetting").Value)}
      }
    }
    $Props = @{'source'=$SourceSplat}
    $ModifiedSourceConfig = New-Object -TypeName PSObject -Property $Props | ConvertTo-Json -Depth 3
    Remove-Variable "Props","SourceSplat","New*" -Scope Local

    $RESTSplat = @{'Uri'="$TargetSourceURI"
                   'Method'="Put"
                   'ContentType'="application/json"
                   'Body'="$ModifiedSourceConfig"
                   'Headers'=$ETAGHash
                   'Credential'=$Credential}      
    Write-Verbose "Invoking REST method for modified $SourceType source, $($SourceConfig.Name)..."
    
    try {
      $Output = Invoke-RestMethod @RestSplat
      $Collector = Get-SumoCollector -Credential $Credential | where {$_.ID -eq $CollectorID}
      $Output.source | Add-Member -MemberType NoteProperty -Name collectorName -Value $Collector.Name
      $Output.source | Add-Member -MemberType NoteProperty -Name collectorID -Value $CollectorID
      $Output.source.PSObject.TypeNames.Insert(0, "SumoTools.Collector.Source")
      $Output.source
    }
    catch {
      Write-Error $_
      break
    }
  }
}

function New-SumoCollectorSourceFilter {
<#
	.SYNOPSIS
		Create filters to be used as input objects for either Set- or New-SumoCollectorSource functions, and their -Filters parameter.

	.DESCRIPTION
		Create filters to be used as input objects for either Set- or New-SumoCollectorSource functions, and their -Filters parameter. Using this function ensures that the object is in the correct format for these functions.

	.PARAMETER  Name
		The name being given to the new source filter rule.

	.PARAMETER  RegExp
		The regular expression used by the filter to discover what it should mask, hash, include, or exclude. If using the -FilterTypeMask or -FilterTypeHash parameters, this regular expression must have at least one matching group specifying the regions to be replaced by a mask or hash.

	.PARAMETER  FilterTypeMask
		Create a 'Mask' filter. These replace an expression with a mask string that you can customize—another option to protect data, such as passwords, that you wouldn't normally track.

	.PARAMETER  FilterTypeHash
		Create a 'Hash' filter. These replace an message with a unique, randomly-generated code to protect sensitive or proprietary information. You may want to hash unique identifiers, such as credit card numbers or user names. By hashing this type of data, you can still track it, even though it's fully hidden.
    
  .PARAMETER  FilterTypeInclude
		Create an 'Include' filter. These are used to send only the data you'd like in your Sumo Logic account (a "white list" filter). This type of filter can be very useful when the list of log data you want to send to Sumo Logic is easier to filter than setting up exclude filters for all of the types of messages you'd like to exclude.
    
  .PARAMETER  FilterTypeExclude
		Create an 'Exclude' filter. These are used to remove messages that you don't want to send to Sumo Logic at all (think of it as a "black list" filter). These expressions will be skipped.
    
  .PARAMETER MaskValue
    The mask string to be used when covering the matching log text. Only required when using the -FilterTypeMask parameter.

	.EXAMPLE
		PS C:\> $NewFilter = New-SumoCollectorSourceFilter -FilterTypeHash -Name 'Credit Card' -RegExp '((?:(?:4\\d{3})|(?:5[1-5]\\d{2})|6(?:011|5[0-9]{2}))(?:-?|\\040?)(?:\\d{4}(?:-?|\\040?)){3}|(?:3[4,7]\\d{2})(?:-?|\\040?)\\d{6}(?:-?|\\040?)\\d{5})'
      Creates, and saves, a filter object that will hash any value matching the regexp. This variable can now be used as input for a -Filters parameter in Set- or New-SumoCollectorSource.

	.EXAMPLE
		PS C:\> Get-SumoCollectorSource | where {$_.category -like "*PIIDATA*"} | Set-SumoCollectorSource -LocalFile -Filters $NewFilter
      The current filter property value for ALL Sumo Collector Sources, with *PIIDATA* somewhere in the name, have now been modified with $NewFilter - being either a single filter, or array of filters.

	.INPUTS
		System.String,System.Int32

	.OUTPUTS
		SumoTools.Collector.Source.Filter

	.NOTES
    ::FILTER OVERVIEW::
	
  You can create any number of filters for a Source, combining the different types of filters to generate the exact data set you want sent to Sumo Logic. It's important to consider how filters work together:

  - Exclude filters override all other filter types for a specific value. If you're excluding a value, it won't be sent to the Sumo Logic Cloud so it can't be hashed or masked.
  
  - Mask and hash filters are applied after exclusion and inclusion filters to ensure that the inclusion filter sees log lines in their original state (rather than a log line with some values hidden).

  ::INCLUDE AND EXCLUDE FILTERS::
  
  You can use include and exclude filters to specify what kind of data is sent to the Sumo Logic Cloud. If you specifically exclude a message, it will never be sent to Sumo Logic. Think of an exclude filter as a blacklist filter.
  
  Include filters are whitelist filters, which can be very useful when the list of log data you want to send to Sumo Logic is easier to filter than setting up exclude filters for all of the types of messages you'd like to exclude.
  
  When writing your regular expression rules, keep in mind:

  - Exclude rules always take precedence over include rules.
  
  - If two or more rules are listed, the assumed Boolean operator is OR.
  
  - The rule must match from the start to the end of any log message rather than addressing only a section. For example, if you want to exclude any message containing the words "secure" or "security", write the rule .*secur.*
  
  ::HASH FILTERS::
  
  With a hash filter, whatever expression you choose to hash will be replaced by a hash code generated for that value. Hashed data is completely hidden (obfuscated) before being sent to Sumo Logic. This can be very useful in situations where some type of data must not leave your premises (such as credit card numbers, social security, numbers, etc.). Each unique value will have a unique hash code.

  Please note the following:

  - Values that you want hashed must be expressed as a match group enclosed in "( )".

  - You can use an anchor to detect specific values. In addition, you can specify multiple match groups. If multiple match groups are specified, each of the values will be hashed uniquely.
    
  - If a match group isn't specified no data will be hashed.

  - Make sure you don't specify a regular expression that matches a full log line. Doing so will result in the entire log line being hashed.

  ::MASK FILTERS::
  
  When you create a mask filter, whatever expression you choose to mask will be replaced with a mask string before it's sent to Sumo Logic (you can either select the character or use the default, #).
  
  Please note the following:

  - Expressions that you want masked must be expressed as a match group enclosed in "()"

  - You can use an anchor to detect specific values. For example, if in your logs all user emails can be identified in logs as User:(user@email.com)] you could use (User:( ) as an anchor.

  - You can specify multiple match groups. Note that if multiple match groups are specified in one filter, each value will be masked the same way. So if you create one filter for users' email addresses and IP addresses both will be replaced with the same mask string.
  
  - If you'd like to use a different mask for each value, you'll need to create a separate mask rule for each value. 

  - Make sure you don't specify a regular expression that matches a full log line. Doing so will result in the entire log line being masked.

  .LINK
		https://github.com/ScriptAutomate/SumoTools
  .LINK
    https://github.com/SumoLogic/sumo-api-doc/wiki
  .LINK
		https://halfwaytoinfinite.wordpress.com
  .LINK
		https://service.sumologic.com/help/Default.htm#Filtering_Sources.htm

#>

[CmdletBinding()]
Param
(
  [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,Position=0)]
  [String]$Name,
  [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,Position=1)]
  [String]$RegExp,
  
  [Parameter(ParameterSetName="Mask",Mandatory=$True,ValueFromPipelineByPropertyName=$True)]
  [Switch]$FilterTypeMask,
  [Parameter(ParameterSetName="Mask",Mandatory=$True,ValueFromPipelineByPropertyName=$True)]
  [String]$MaskValue,
  
  [Parameter(ParameterSetName="Hash",Mandatory=$True,ValueFromPipelineByPropertyName=$True)]
  [Switch]$FilterTypeHash,
  [Parameter(ParameterSetName="Include",Mandatory=$True,ValueFromPipelineByPropertyName=$True)]
  [Switch]$FilterTypeInclude,
  [Parameter(ParameterSetName="Exclude",Mandatory=$True,ValueFromPipelineByPropertyName=$True)]
  [Switch]$FilterTypeExclude
)
  $FilterType = (Get-Variable "FilterType*" -Scope Local | where {$_.Value -eq $true}).Name
  $FilterType = $FilterType -replace "FilterType",""
  $Hashtable += @{'filterType'="$FilterType"
                 'name'="$Name"
                 'regexp'="$RegExp"}
  if ($MaskValue) {
    $Hashtable += @{"mask"="$MaskValue"}
  }
  $FilterObject = New-Object -TypeName PSObject -Property $HashTable
  $FilterObject.PSObject.TypeNames.Insert(0, "SumoTools.Collector.Source.Filter")
  $FilterObject
}


# v2 Roadmap
#function Invoke-SumoSearch {}

function Start-SumoSearchJob {
<#
	.SYNOPSIS
		Uses the Sumo Logic Collector Search Job API to query logs.

	.DESCRIPTION
		Start-SumoSearchJob queries the Collector Management API for Collector information. The returned JSON information is converted into happy PowerShell objects.

	.PARAMETER  Query
		The Sumo Logic formatted search query, just as you would use in the Sumo Logic Web UI.

	.PARAMETER  To
		ISO 8601 date of the time range to end the search. Can also be milliseconds since epoch.
    
  .PARAMETER  From
		ISO 8601 date of the time range to start the search. Can also be milliseconds since epoch.
    
  .PARAMETER  TimeZone
		The time zone if from/to is not in milliseconds.
    
  .EXAMPLE
    C:\> Start-SumoSearchJob -Query "$Query" -To '2015-01-12T12:45:18' -From '2015-01-12T11:45:18' -TimeZone CST

	.INPUTS
		System.String

	.OUTPUTS
		SumoTools.SearchJob

	.LINK
		https://github.com/ScriptAutomate/SumoTools
  .LINK
    https://github.com/SumoLogic/sumo-api-doc/wiki/Search-Job-API
  .LINK
		https://halfwaytoinfinite.wordpress.com
    
  .COMPONENT
    Invoke-RestMethod
#>

[CmdletBinding()]
Param
(
  [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True)]
  [String]$Query,
  [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [String]$To,
  [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [String]$From,
  [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [String]$TimeZone,
  
  [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
  [System.Management.Automation.PSCredential]$Credential
)
  Begin {
    # Checking for credentials
    $ModuleLocation = (Get-Module SumoTools).Path.Replace('\SumoTools.psm1','')
    $SumoPass = "$ModuleLocation\SumoAuth1"
    $SumoUser = "$ModuleLocation\SumoAuth2"
    if (!$Credential) {
      if ((Test-Path "$SumoPass") -and (Test-Path "$SumoUser")) {
        $CredUserSecure = Get-Content "$ModuleLocation\SumoAuth2" | ConvertTo-SecureString
        $BSTRU = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($CredUserSecure)
        $CredUser = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTRU)
        $CredPass = Get-Content "$ModuleLocation\SumoAuth1" | ConvertTo-SecureString
        $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "$CredUser",$CredPass
      }
      else {
        Write-Error "Failure to find credentials. You must run New-SumoCredential before you can use the SumoTools Module."
        break
      }
    }
    $SumoSearchAPI = "$global:SumoBaseAPIHost/api/v1/search/jobs"
  }
  
  Process {
    $SearchHash = @{'query'="$Query"
                    'from'=$From
                    'to'=$To
                    'timeZone'=$TimeZone}
    $SearchConfig = New-Object -TypeName PSObject -Property $SearchHash | ConvertTo-JSON -Depth 3
    $RESTSplat = @{'Uri'="$SumoSearchAPI"
                   'Method'="Post"
                   'ContentType'="application/json"
                   'Headers'=@{'Accept'='application/json'}
                   'Body'="$SearchConfig"
                   'Credential'=$Credential}
               
    Write-Verbose "Invoking REST method for search job query: $Query"
    $Output = Invoke-RestMethod @RESTSplat 
    $SearchHash += @{'id'=$Output.Id
                     'link'=$Output.link.href}
    $Obj = New-Object -TypeName PSObject -Property $SearchHash
    $Obj.PSObject.TypeNames.Insert(0, "SumoTools.SearchJob")
    $Obj
  }
}

function Get-SumoSearchJob {
<#
	.SYNOPSIS
		Uses the Sumo Logic Collector Search Job API to query logs.

	.DESCRIPTION
		Start-SumoSearchJob queries the Collector Management API for Collector information. The returned JSON information is converted into happy PowerShell objects.

	.PARAMETER  Query
		The Sumo Logic formatted search query, just as you would use in the Sumo Logic Web UI.

	.PARAMETER  To
		ISO 8601 date of the time range to end the search. Can also be milliseconds since epoch.
    
  .PARAMETER  From
		ISO 8601 date of the time range to start the search. Can also be milliseconds since epoch.
    
  .PARAMETER  TimeZone
		The time zone if from/to is not in milliseconds.

	.INPUTS
		SumoTools.SearchJob

	.OUTPUTS
		SumoTools.SearchJob.Status

	.LINK
		https://github.com/ScriptAutomate/SumoTools
  .LINK
    https://github.com/SumoLogic/sumo-api-doc/wiki/Search-Job-API
  .LINK
		https://halfwaytoinfinite.wordpress.com
    
  .COMPONENT
    Invoke-RestMethod
#>

[CmdletBinding()]
param (
  [Parameter(ParameterSetName='String',Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True)]
  [Alias('SearchJobId')]
  [String[]]$Id,
  [Parameter(ParameterSetName='Object',Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True)]
  [Object[]]$SearchJob,
  
  [Parameter(ParameterSetName='String',Mandatory=$False)]
  [Parameter(ParameterSetName='Object',Mandatory=$False)]
  [System.Management.Automation.PSCredential]$Credential
)
  Begin {
    # Checking for credentials
    $ModuleLocation = (Get-Module SumoTools).Path.Replace('\SumoTools.psm1','')
    $SumoPass = "$ModuleLocation\SumoAuth1"
    $SumoUser = "$ModuleLocation\SumoAuth2"
    if (!$Credential) {
      if ((Test-Path "$SumoPass") -and (Test-Path "$SumoUser")) {
        $CredUserSecure = Get-Content "$ModuleLocation\SumoAuth2" | ConvertTo-SecureString
        $BSTRU = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($CredUserSecure)
        $CredUser = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTRU)
        $CredPass = Get-Content "$ModuleLocation\SumoAuth1" | ConvertTo-SecureString
        $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "$CredUser",$CredPass
      }
      else {
        Write-Error "Failure to find credentials. You must run New-SumoCredential before you can use the SumoTools Module."
        break
      }
    }
    $SumoSearchAPI = "$global:SumoBaseAPIHost/api/v1/search/jobs"
    # Confirming that -Filters input object is legal
    if ($SearchJob) {
      $TypeName = $SearchJob | Get-Member | select-object -ExpandProperty TypeName
      if ($TypeName -ne "SumoTools.SearchJob") {
          Write-Error "Illegal type name on object input for -Filters parameter! Expected object type: SumoTools.SearchJob"
          break
      }
    }
  }
  
  Process {
    if ($SearchJob) {$JobId = $SearchJob.id}
    else {$JobId = $Id}
    
    $RESTSplat = @{'Uri'="$SumoSearchAPI/$JobId"
                   'Method'="Get"
                   'Headers'=@{'Accept'='application/json'}
                   'Credential'=$Credential}           
    Write-Verbose "Invoking REST method for search job query: $Query"
    $Output = Invoke-RestMethod @RESTSplat
    $Output.PSObject.TypeNames.Insert(0, "SumoTools.SearchJob.Status")
    $Output    
  } 
}

#function Remove-SumoSearchJob {}

function Receive-SumoSearchJobMessage {

}

#function Receive-SumoSearchJobRecord {}