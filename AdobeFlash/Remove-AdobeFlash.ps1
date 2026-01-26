<#
.SYNOPSIS
    Comprehensive Adobe Flash Player removal script with validation.

.DESCRIPTION
    Removes all traces of Adobe Flash Player from Windows systems including:
    - Adobe Flash Player installations
    - File system artifacts
    - Registry entries
    - Browser extensions
    - Scheduled tasks
    Includes validation to confirm complete removal.

.NOTES
    Requires Administrator privileges
    Author: Comprehensive Flash Removal Script
    Version: 1.0
#>

#Requires -RunAsAdministrator

# Color-coded output functions
function Write-Success { param($Message) Write-Host "[✓] $Message" -ForegroundColor Green }
function Write-Info { param($Message) Write-Host "[i] $Message" -ForegroundColor Cyan }
function Write-Warning { param($Message) Write-Host "[!] $Message" -ForegroundColor Yellow }
function Write-Failure { param($Message) Write-Host "[✗] $Message" -ForegroundColor Red }

# Initialize tracking arrays
$script:removalSuccess = @()
$script:removalFailed = @()
$script:foundItems = 0
$script:removedItems = 0

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Adobe Flash Player Removal Tool" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# ============================================================================
# STEP 1: Verify Administrator Rights
# ============================================================================
Write-Info "Checking administrator privileges..."
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

if (-not $isAdmin) {
    Write-Failure "This script must be run as Administrator"
    Write-Host "`nPlease right-click and select 'Run as Administrator'" -ForegroundColor Yellow
    exit 1
}
Write-Success "Administrator privileges confirmed"

# ============================================================================
# STEP 2: Terminate Flash-Related Processes
# ============================================================================
Write-Info "`nTerminating Flash-related processes..."
$flashProcesses = @(
    "FlashPlayerPlugin*",
    "FlashUtil*",
    "FlashPlayerApp*",
    "uninstall_flash_player"
)

$browserProcesses = @(
    "chrome",
    "firefox",
    "iexplore",
    "MicrosoftEdge",
    "msedge",
    "opera",
    "safari"
)

# Stop Flash processes
foreach ($processPattern in $flashProcesses) {
    $processes = Get-Process -Name $processPattern -ErrorAction SilentlyContinue
    if ($processes) {
        $processes | ForEach-Object {
            try {
                Stop-Process -Id $_.Id -Force -ErrorAction Stop
                Write-Success "Terminated process: $($_.Name) (PID: $($_.Id))"
            } catch {
                Write-Warning "Could not terminate: $($_.Name) (PID: $($_.Id))"
            }
        }
    }
}

# Warn about browser processes
$runningBrowsers = @()
foreach ($browser in $browserProcesses) {
    if (Get-Process -Name $browser -ErrorAction SilentlyContinue) {
        $runningBrowsers += $browser
    }
}

if ($runningBrowsers.Count -gt 0) {
    Write-Warning "The following browsers are running: $($runningBrowsers -join ', ')"
    Write-Host "It's recommended to close all browsers before continuing." -ForegroundColor Yellow
    $response = Read-Host "Close browsers automatically? (Y/N)"
    if ($response -eq 'Y' -or $response -eq 'y') {
        foreach ($browser in $runningBrowsers) {
            Get-Process -Name $browser -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
            Write-Info "Closed: $browser"
        }
    }
}

Start-Sleep -Seconds 2

# ============================================================================
# STEP 3: Download and Run Adobe's Official Uninstaller
# ============================================================================
Write-Info "`nDownloading Adobe's official Flash uninstaller..."
$uninstallerUrl = "https://fpdownload.adobe.com/get/flashplayer/current/support/uninstall_flash_player.exe"
$uninstallerPath = "$env:TEMP\uninstall_flash_player.exe"

try {
    # Remove old uninstaller if exists
    if (Test-Path $uninstallerPath) {
        Remove-Item $uninstallerPath -Force -ErrorAction SilentlyContinue
    }

    # Download uninstaller
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri $uninstallerUrl -OutFile $uninstallerPath -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
    $ProgressPreference = 'Continue'

    if (Test-Path $uninstallerPath) {
        Write-Success "Downloaded Adobe uninstaller"
        Write-Info "Running Adobe's official uninstaller (this may take a moment)..."
        
        # Run the uninstaller with -uninstall flag for silent mode
        $process = Start-Process -FilePath $uninstallerPath -ArgumentList "-uninstall" -Wait -PassThru -NoNewWindow
        
        if ($process.ExitCode -eq 0) {
            Write-Success "Adobe uninstaller completed successfully"
            $script:removalSuccess += "Adobe Official Uninstaller"
        } else {
            Write-Warning "Adobe uninstaller exited with code: $($process.ExitCode)"
        }
        
        Start-Sleep -Seconds 3
        
        # Clean up uninstaller
        Remove-Item $uninstallerPath -Force -ErrorAction SilentlyContinue
    } else {
        Write-Warning "Failed to download Adobe uninstaller, proceeding with manual removal..."
    }
} catch {
    Write-Warning "Could not run Adobe's official uninstaller: $($_.Exception.Message)"
    Write-Info "Proceeding with manual removal..."
}

# ============================================================================
# STEP 4: Remove Flash Files from System
# ============================================================================
Write-Info "`nRemoving Flash files from system directories..."

$systemPaths = @(
    "C:\Windows\system32\Macromed",
    "C:\Windows\SysWOW64\Macromed",
    "C:\Windows\system32\FlashPlayerApp.exe",
    "C:\Windows\SysWOW64\FlashPlayerApp.exe",
    "$env:SystemRoot\Downloaded Program Files\*Flash*"
)

foreach ($path in $systemPaths) {
    if (Test-Path $path) {
        $script:foundItems++
        try {
            Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
            if (-not (Test-Path $path)) {
                Write-Success "Removed: $path"
                $script:removedItems++
                $script:removalSuccess += $path
            } else {
                Write-Failure "Failed to remove: $path"
                $script:removalFailed += $path
            }
        } catch {
            Write-Failure "Error removing $path : $($_.Exception.Message)"
            $script:removalFailed += $path
        }
    }
}

# ============================================================================
# STEP 5: Remove Flash Files from User Profiles
# ============================================================================
Write-Info "`nRemoving Flash files from user profiles..."

$userProfiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne "Public" }

foreach ($userProfile in $userProfiles) {
    $userName = $userProfile.Name
    
    $userPaths = @(
        "$($userProfile.FullName)\AppData\Roaming\Adobe\Flash Player",
        "$($userProfile.FullName)\AppData\Roaming\Macromedia\Flash Player",
        "$($userProfile.FullName)\AppData\Local\Adobe\Flash Player",
        "$($userProfile.FullName)\AppData\LocalLow\Adobe\Flash Player",
        "$($userProfile.FullName)\AppData\Roaming\Adobe\AIR\ELS\*Flash*",
        "$($userProfile.FullName)\AppData\Local\Google\Chrome\User Data\*\Pepper Data\Shockwave Flash",
        "$($userProfile.FullName)\AppData\Local\Microsoft\Edge\User Data\*\Pepper Data\Shockwave Flash",
        "$($userProfile.FullName)\AppData\Roaming\Mozilla\Firefox\Profiles\*\*Flash*"
    )
    
    foreach ($path in $userPaths) {
        $items = Get-Item $path -ErrorAction SilentlyContinue
        if ($items) {
            $script:foundItems++
            try {
                $items | Remove-Item -Recurse -Force -ErrorAction Stop
                if (-not (Test-Path $path)) {
                    Write-Success "Removed: $path (User: $userName)"
                    $script:removedItems++
                    $script:removalSuccess += "$path (User: $userName)"
                } else {
                    Write-Failure "Failed to remove: $path (User: $userName)"
                    $script:removalFailed += "$path (User: $userName)"
                }
            } catch {
                Write-Failure "Error removing $path : $($_.Exception.Message)"
                $script:removalFailed += "$path (User: $userName)"
            }
        }
    }
}

# ============================================================================
# STEP 6: Remove Flash Registry Entries
# ============================================================================
Write-Info "`nRemoving Flash registry entries..."

# HKLM Registry Paths
$hklmPaths = @(
    "HKLM:\SOFTWARE\Adobe\FlashPlayer",
    "HKLM:\SOFTWARE\Macromedia\FlashPlayer",
    "HKLM:\SOFTWARE\Macromedia\FlashPlayerPlugin",
    "HKLM:\SOFTWARE\Macromedia\FlashPlayerActiveX",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Adobe Flash Player ActiveX",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Adobe Flash Player NPAPI",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Adobe Flash Player PPAPI",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Adobe Flash Player Plugin",
    "HKLM:\SOFTWARE\WOW6432Node\Adobe\FlashPlayer",
    "HKLM:\SOFTWARE\WOW6432Node\Macromedia\FlashPlayer",
    "HKLM:\SOFTWARE\Classes\ShockwaveFlash.ShockwaveFlash"
)

foreach ($regPath in $hklmPaths) {
    if (Test-Path $regPath) {
        $script:foundItems++
        try {
            Remove-Item -Path $regPath -Recurse -Force -ErrorAction Stop
            if (-not (Test-Path $regPath)) {
                Write-Success "Removed registry: $regPath"
                $script:removedItems++
                $script:removalSuccess += $regPath
            } else {
                Write-Failure "Failed to remove registry: $regPath"
                $script:removalFailed += $regPath
            }
        } catch {
            Write-Failure "Error removing $regPath : $($_.Exception.Message)"
            $script:removalFailed += $regPath
        }
    }
}

# HKCU Registry Paths - Need to check for all user hives
Write-Info "Removing Flash registry entries from user hives..."

# Ensure HKU: drive exists
if (-not (Test-Path "HKU:")) {
    New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS -ErrorAction SilentlyContinue | Out-Null
}

# Get all user SIDs
$userSids = Get-ChildItem "Registry::HKEY_USERS" -ErrorAction SilentlyContinue | 
    Where-Object { $_.PSChildName -match '^S-1-5-21-[\d\-]+$' }

foreach ($sid in $userSids) {
    $sidPath = $sid.PSChildName
    
    $hkcuPaths = @(
        "Registry::HKEY_USERS\$sidPath\SOFTWARE\Adobe\Flash Player",
        "Registry::HKEY_USERS\$sidPath\SOFTWARE\Macromedia\FlashPlayer",
        "Registry::HKEY_USERS\$sidPath\SOFTWARE\Adobe\AIR"
    )
    
    foreach ($regPath in $hkcuPaths) {
        if (Test-Path $regPath) {
            $script:foundItems++
            try {
                Remove-Item -Path $regPath -Recurse -Force -ErrorAction Stop
                if (-not (Test-Path $regPath)) {
                    Write-Success "Removed user registry: $regPath"
                    $script:removedItems++
                    $script:removalSuccess += $regPath
                } else {
                    Write-Failure "Failed to remove user registry: $regPath"
                    $script:removalFailed += $regPath
                }
            } catch {
                Write-Failure "Error removing $regPath : $($_.Exception.Message)"
                $script:removalFailed += $regPath
            }
        }
    }
}

# ============================================================================
# STEP 7: Remove Scheduled Tasks
# ============================================================================
Write-Info "`nRemoving Flash-related scheduled tasks..."

$flashTasks = @(
    "Adobe Flash Player Updater",
    "Adobe Flash Player NPAPI Notifier",
    "Adobe Flash Player PPAPI Notifier"
)

foreach ($taskName in $flashTasks) {
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($task) {
        $script:foundItems++
        try {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
            if (-not (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)) {
                Write-Success "Removed scheduled task: $taskName"
                $script:removedItems++
                $script:removalSuccess += "Scheduled Task: $taskName"
            } else {
                Write-Failure "Failed to remove scheduled task: $taskName"
                $script:removalFailed += "Scheduled Task: $taskName"
            }
        } catch {
            Write-Failure "Error removing scheduled task $taskName : $($_.Exception.Message)"
            $script:removalFailed += "Scheduled Task: $taskName"
        }
    }
}

# ============================================================================
# STEP 8: VALIDATION - Check for Remaining Flash Components
# ============================================================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "VALIDATION: Checking for Remaining Flash Components" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$validationIssues = @()

# Check for Flash processes
Write-Info "Checking for running Flash processes..."
$remainingProcesses = Get-Process | Where-Object { $_.Name -like "*Flash*" }
if ($remainingProcesses) {
    Write-Failure "Found Flash processes still running:"
    $remainingProcesses | ForEach-Object { 
        Write-Host "  - $($_.Name) (PID: $($_.Id))" -ForegroundColor Red
        $validationIssues += "Process: $($_.Name)"
    }
} else {
    Write-Success "No Flash processes detected"
}

# Check system directories
Write-Info "`nChecking system directories..."
$systemCheckPaths = @(
    "C:\Windows\system32\Macromed",
    "C:\Windows\SysWOW64\Macromed"
)

$foundInSystem = $false
foreach ($path in $systemCheckPaths) {
    if (Test-Path $path) {
        $items = Get-ChildItem $path -Recurse -ErrorAction SilentlyContinue
        if ($items) {
            Write-Failure "Found Flash files in: $path"
            $items | ForEach-Object { 
                Write-Host "  - $($_.FullName)" -ForegroundColor Red 
                $validationIssues += $_.FullName
            }
            $foundInSystem = $true
        }
    }
}
if (-not $foundInSystem) {
    Write-Success "No Flash files in system directories"
}

# Check user profiles
Write-Info "`nChecking user profiles..."
$foundInUsers = $false
foreach ($userProfile in $userProfiles) {
    $checkPaths = @(
        "$($userProfile.FullName)\AppData\Roaming\Adobe\Flash Player",
        "$($userProfile.FullName)\AppData\Roaming\Macromedia\Flash Player",
        "$($userProfile.FullName)\AppData\Local\Adobe\Flash Player"
    )
    
    foreach ($path in $checkPaths) {
        if (Test-Path $path) {
            $items = Get-ChildItem $path -ErrorAction SilentlyContinue
            if ($items) {
                Write-Failure "Found Flash files in: $path"
                $items | ForEach-Object { 
                    Write-Host "  - $($_.FullName)" -ForegroundColor Red 
                    $validationIssues += $_.FullName
                }
                $foundInUsers = $true
            }
        }
    }
}
if (-not $foundInUsers) {
    Write-Success "No Flash files in user profiles"
}

# Check registry
Write-Info "`nChecking registry entries..."
$registryCheckPaths = @(
    "HKLM:\SOFTWARE\Adobe\FlashPlayer",
    "HKLM:\SOFTWARE\Macromedia",
    "HKLM:\SOFTWARE\WOW6432Node\Adobe\FlashPlayer",
    "HKLM:\SOFTWARE\WOW6432Node\Macromedia"
)

$foundInRegistry = $false
foreach ($regPath in $registryCheckPaths) {
    if (Test-Path $regPath) {
        Write-Failure "Found Flash registry entry: $regPath"
        $validationIssues += $regPath
        $foundInRegistry = $true
    }
}
if (-not $foundInRegistry) {
    Write-Success "No Flash registry entries detected"
}

# Check scheduled tasks
Write-Info "`nChecking scheduled tasks..."
$remainingTasks = Get-ScheduledTask | Where-Object { $_.TaskName -like "*Flash*" }
if ($remainingTasks) {
    Write-Failure "Found Flash-related scheduled tasks:"
    $remainingTasks | ForEach-Object { 
        Write-Host "  - $($_.TaskName)" -ForegroundColor Red
        $validationIssues += "Scheduled Task: $($_.TaskName)"
    }
} else {
    Write-Success "No Flash scheduled tasks detected"
}

# Check browser plugins (quick check)
Write-Info "`nChecking browser plugin directories..."
$pluginPaths = @(
    "$env:LOCALAPPDATA\Google\Chrome\User Data\PepperFlash",
    "$env:LOCALAPPDATA\Microsoft\Edge\User Data\PepperFlash"
)

$foundPlugins = $false
foreach ($path in $pluginPaths) {
    if (Test-Path $path) {
        Write-Failure "Found Flash plugin directory: $path"
        $validationIssues += $path
        $foundPlugins = $true
    }
}
if (-not $foundPlugins) {
    Write-Success "No Flash browser plugins detected"
}

# ============================================================================
# FINAL SUMMARY
# ============================================================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "REMOVAL SUMMARY" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

Write-Host "Items Found:    $script:foundItems" -ForegroundColor Cyan
Write-Host "Items Removed:  $script:removedItems" -ForegroundColor Green
Write-Host "Items Failed:   $($script:removalFailed.Count)" -ForegroundColor $(if ($script:removalFailed.Count -gt 0) { "Red" } else { "Green" })

if ($validationIssues.Count -eq 0) {
    Write-Host "`n" -NoNewline
    Write-Success "✓ VALIDATION PASSED - Adobe Flash Player appears to be completely removed!"
    Write-Host "`nNo remaining Flash components detected on this system." -ForegroundColor Green
} else {
    Write-Host "`n" -NoNewline
    Write-Warning "⚠ VALIDATION ISSUES - $($validationIssues.Count) items require attention"
    Write-Host "`nThe following items could not be removed or still exist:" -ForegroundColor Yellow
    $validationIssues | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
    Write-Host "`nManual intervention may be required for complete removal." -ForegroundColor Yellow
}

if ($script:removalFailed.Count -gt 0) {
    Write-Host "`nFailed to remove the following items:" -ForegroundColor Red
    $script:removalFailed | Select-Object -Unique | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
}

# Generate detailed report
$reportPath = "$env:USERPROFILE\Desktop\FlashRemovalReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
$report = @"
Adobe Flash Player Removal Report
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Computer: $env:COMPUTERNAME
User: $env:USERNAME

SUMMARY
=======
Items Found: $script:foundItems
Items Removed: $script:removedItems
Items Failed: $($script:removalFailed.Count)
Validation Issues: $($validationIssues.Count)

SUCCESSFULLY REMOVED
====================
$($script:removalSuccess | ForEach-Object { "- $_" } | Out-String)

FAILED TO REMOVE
================
$($script:removalFailed | Select-Object -Unique | ForEach-Object { "- $_" } | Out-String)

VALIDATION ISSUES
=================
$($validationIssues | ForEach-Object { "- $_" } | Out-String)

VALIDATION STATUS
=================
$(if ($validationIssues.Count -eq 0) { "PASSED - Adobe Flash Player appears completely removed" } else { "FAILED - Manual intervention required" })
"@

try {
    $report | Out-File -FilePath $reportPath -Encoding UTF8 -ErrorAction Stop
    Write-Host "`nDetailed report saved to: $reportPath" -ForegroundColor Cyan
} catch {
    Write-Warning "Could not save report to file: $($_.Exception.Message)"
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Removal process completed!" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Recommend reboot
if ($script:removedItems -gt 0) {
    Write-Host "RECOMMENDATION: Restart your computer to complete the removal process." -ForegroundColor Yellow
    $reboot = Read-Host "`nWould you like to restart now? (Y/N)"
    if ($reboot -eq 'Y' -or $reboot -eq 'y') {
        Write-Info "Restarting computer in 10 seconds... (Press Ctrl+C to cancel)"
        Start-Sleep -Seconds 10
        Restart-Computer -Force
    }
}