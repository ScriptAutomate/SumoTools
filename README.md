SumoTools PowerShell Module
=========

## [NOTE] !! MODULE IS DEPRECATED !!

This module is no longer managed, and may not be in a working state. It would be better to use and contribute to the following repository in the Sumo Logic org: https://github.com/SumoLogic/sumo-powershell-sdk

## MODULE NOTES

```powershell
# Quick install
iex (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/ScriptAutomate/SumoTools/master/Install-SumoTools.ps1")
```

This is a PowerShell Module of functions running against the Sumo Logic API.
It requires version 3.0 of PowerShell, as data is returned in JSON format and the module uses the ConvertFrom-Json function. 
All commands have been tested on PowerShell 4.0, but should work on v3.0+

Please take a look at the GitHub wiki for further information:
- https://github.com/ScriptAutomate/SumoTools/wiki

These functions utilize the Sumo Logic API as documented here:
- https://github.com/SumoLogic/sumo-api-doc/wiki

I will periodically be blogging about it here:
- http://halfwaytoinfinite.wordpress.com
