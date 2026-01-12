# Changelog - Ghost-Glitch04 Fork
## Production-Ready Modifications for SentinelOne Remote Shell

---

## [Unreleased]

## [v1.1.2] - 2026-01-012

### Changed - OneStart
**Script:** `OneStart/OneStart-Remediation-Script.ps1`  
**Issue:** Processes are hard coded which increases maintenance time. 
**Fix:** Replaced "Test-Path" with "Get-ChildItem".

**Lines Changed:** 15-21

**Code Changes:**

Replaced Lines 15-21

$process = Get-Process OneStart -ErrorAction SilentlyContinue
if ($process) {
    $process | Stop-Process -Force -ErrorAction SilentlyContinue
}
$process = Get-Process UpdaterSetup -ErrorAction SilentlyContinue
if ($process) {
    $process | Stop-Process -Force -ErrorAction SilentlyContinue

---

## [v1.1.1] - 2026-01-09

### Changed - OneStart
**Script:** `OneStart/OneStart-Remediation-Script.ps1`  
**Issue:** Ophaned Registry Keys after the script was used.  
**Fix:** Replaced "Test-Path" with "Get-CHildItem".

**Lines Changed:** 83-91 

**Code Changes:**
```diff
$process = Get-Process OneStart -ErrorAction SilentlyContinue
if ($process) {
    $process | Stop-Process -Force -ErrorAction SilentlyContinue
}
$process = Get-Process UpdaterSetup -ErrorAction SilentlyContinue
if ($process) {
    $process | Stop-Process -Force -ErrorAction SilentlyContinue
}
---
# Define target processes to terminate
$processesToKill = @(
    "OneStart",
    "UpdaterSetup"
)

# Attempt to kill each target process and verify termination
foreach ($processName in $processesToKill) {
    $process = Get-Process -Name $processName -ErrorAction SilentlyContinue
    if ($process) {
        $process | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 500
        
        # Verify the process was successfully terminated
        $stillRunning = Get-Process -Name $processName -ErrorAction SilentlyContinue
        if ($stillRunning) {
            Write-Host "Failed to kill process -> $processName"
        }
    }
}
```

---

## [v1.1.0] - 2026-01-09

### Changed - OneStart
**Script:** `OneStart/OneStart-Remediation-Script.ps1`  
**Issue:** Scheduled task removal was failing when Task Scheduler service locked task files  
**Fix:** Replaced file-based deletion with `Unregister-ScheduledTask` cmdlet  
**Testing:**
- ✅ Tested on Windows 10 21H2 (SentinelOne Remote Shell)
- ✅ Tested on Windows 11 22H2 (SentinelOne Remote Shell)
- ✅ Verified removal of:  OneStartUser, OneStartAutoLaunchTask*, PDFEditor*
- ✅ Verified orphaned registry cleanup

**Lines Changed:** 67-99  
**Commit:** [f777cd3](https://github.com/Ghost-Glitch04/Threat-Remediation-Scripts/commit/f777cd3506f1341963aef8b29e6e5ca1aac30397)  
**Status:** Production-Ready ✅  
**Deployed:** 2026-01-09  
**Endpoints:** 15 successful remediations  

**Code Changes:**
```diff
- Remove-Item $task -Force -Recurse -ErrorAction SilentlyContinue
+ Get-ScheduledTask -TaskName $pattern -ErrorAction SilentlyContinue
+ Unregister-ScheduledTask -TaskName $task. TaskName -Confirm:$false
```

**SentinelOne Considerations:**
- Session timeout: ~45 seconds (within limits)
- Requires SYSTEM privileges (confirmed working)
- Output: 10-15 lines (fits in console buffer)

---

## [v1.0.0] - 2026-01-08

### Added
- Forked from [xephora/Threat-Remediation-Scripts](https://github.com/xephora/Threat-Remediation-Scripts)
- Initial production baseline

---

## Upstream Sync History

| Date | Upstream Commit | Changes Pulled | Notes |
|------|----------------|----------------|-------|
| 2026-01-08 | `240e277` | Initial fork | Baseline version |

---

## Deployment Log

| Date | Script | Endpoints | Success Rate | Issues |
|------|--------|-----------|--------------|--------|
| 2026-01-09 | OneStart v1.1 | 1 | 100% | None |


---

## Legend
- ✅ Production-Ready - Tested and deployed successfully
- 🧪 Testing - In validation phase
- 📝 Documented - Change documented but not yet implemented
- ⚠️ Known Issue - Limitation or bug identified
- 🔄 Upstream - Change submitted as PR to original repo