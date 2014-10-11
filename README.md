SumoTools
=========

PowerShell functions running against the Sumo Logic API.
Requires version 3.0 of PowerShell, as data is returned in JSON format and the module uses the ConvertFrom-Json function. 
All commands have been tested on PowerShell 4.0, but should work on v3.0+

These functions utilize the Sumo Logic API as documented here:
- https://github.com/SumoLogic/sumo-api-doc/wiki

Will periodically be blogging about it here:
- http://halfwaytoinfinite.wordpress.com

Version
=========

NOTE: THIS IS CURRENTLTY A PRE-RELEASE VERSION! IT WILL BE UNTIL v1.0!

0.4 - 10/10/14
  - Set-SumoCollectoSource was NOT working as expected: Fixed
    - Also expanded for better functionality
0.3 - 10/08/14
  - Set-SumoCollectorSource is working as expected
  - New-SumoCollectorSource is working as expected
  - Added a '-Credential' parameter, for those who wish to use alternate
    credentials, and/or don't want to use New-SumoCredential
  - Improved overall code of functions

0.2 - 10/07/14
  - Added a 'SumoTools.psd1' manifest
  - Standardized fashion of accessing API with Invoke-RestMethod across most functions
  - Added comment-based help for a few functions
  - Misc modifications
  
0.1 - 09/30/14
  - WIP release
    - New-SumoCollectorSource works. There was an error in the API. Reminder: JSON
        is case-sensitive. I was using 'lognames' instead of 'logNames' -- the API
        returned "Missing required field: 'eventSources'" when it meant 'logNames'
      - Have not confirmed functionality of other source types outside of WindowsEventLogs

Current Functions
=========

These are the functions currently available:
- Get-SumoCollector
- Get-SumoCollectorSource
- New-SumoCollectorSource
- New-SumoCredential
- Remove-SumoCollector
- Remove-SumoCollectorSource
- Set-SumoCollectorSource
        
To Do
=========

SumoTools PowerShell Module roadmap:
- Include comment-based help!!
- Improved error checking (especially in cases where there is no error-checking!)
- Future functions
  - Set-SumoCollector
  - Invoke-SumoSearch
  - Start-SumoSearchJob
  - Get-SumoSearchJob
  - Receive-SumoSearchJob
  - Remove-SumoSearchJob
  - Get-SumoDashBoard
  - Get-SumoDashBoardMonitor
  - Get-SumoDashBoardMonitorData