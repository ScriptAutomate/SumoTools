SumoTools
=========

PowerShell functions running against the Sumo Logic API.
Requires version 3.0 of PowerShell, as data is returned in JSON format and the module uses the ConvertFrom-Json function. 
All commands have been tested on PowerShell 4.0, but should work on v3.0+

These functions utilize the Sumo Logic API as documented here:
https://github.com/SumoLogic/sumo-api-doc/wiki

Version
=========

0.1 - 09/29/14
  - WIP release
    - New-SumoCollectorSource has errors with LocalWindowsEventLog source type
      - Working with Sumo to decipher error message: "Missing required field: 'eventSources'"
        - This 'required field' is not documented anywhere
      - Have not confirmed functionality of other source types

Current Functions
=========

These are the functions currently available:
Get-SumoCollector
Get-SumoCollectorSource
New-SumoCollectorSource
New-SumoCredential
Remove-SumoCollector
Remove-SumoCollectorSource
        
To Do
=========

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