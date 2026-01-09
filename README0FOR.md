# Ghost-Glitch04's Fork - Production Modifications

## Purpose
This fork contains tested improvements for use with SentinelOne Remote Shell in our environment.

## Changes from Upstream

### OneStart-Remediation-Script.ps1
- **Fixed:** Scheduled task removal now uses `Unregister-ScheduledTask` cmdlet
- **Reason:** File-based deletion was failing when Task Scheduler service locked files
- **Tested:** Windows 10/11, SentinelOne Remote Shell
- **Status:** Production-ready ✅

## Usage
```powershell
$url = "https://raw.githubusercontent.com/Ghost-Glitch04/Threat-Remediation-Scripts/main/OneStart/OneStart-Remediation-Script.ps1"
```

## Contributing Back
Improvements marked ✅ have been submitted as Pull Requests to upstream. 