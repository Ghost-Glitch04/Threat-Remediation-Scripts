<#
.SYNOPSIS
    Standalone validation script to check for Adobe Flash remnants.

.DESCRIPTION
    Scans system for any remaining Flash components without removing anything.
    Useful for verification after removal or periodic security audits.
#>

function Write-Check { param($Message) Write-Host "[?] $Message" -ForegroundColor Cyan }
function Write-Found { param($Message) Write-Host "[!] FOUND: $Message" -ForegroundColor Red }
function Write-Clear { param($Message) Write-Host "[✓] CLEAR: $Message" -ForegroundColor Green }

Write-Host "`n=== Adobe Flash Player Validation Scan ===" -ForegroundColor Cyan
Write-Host "Scanning for Flash remnants...`n" -ForegroundColor Cyan

$findings = @()

# 1. Check processes
Write-Check "Scanning for Flash processes..."
$flashProcs = Get-Process | Where-Object { $_.Name -like "*Flash*" }
if ($flashProcs) {
    foreach ($proc in $flashProcs) {
        $finding = "Process: $($proc.Name) (PID: $($proc.Id), Path: $($proc.Path))"
        Write-Found $finding
        $findings += $finding
    }
} else {
    Write-Clear "No Flash processes running"
}

# 2. Check system files
Write-Check "`nScanning system directories..."
$systemPaths = @(
    "C:\Windows\system32\Macromed",
    "C:\Windows\SysWOW64\Macromed",
    "C:\Windows\system32\FlashPlayerApp.exe",
    "C:\Windows\SysWOW64\FlashPlayerApp.exe"
)

$systemFiles = @()
foreach ($path in $systemPaths) {
    if (Test-Path $path) {
        $items = Get-ChildItem $path -Recurse -Force -ErrorAction SilentlyContinue
        $systemFiles += $items
    }
}

if ($systemFiles) {
    foreach ($file in $systemFiles) {
        $finding = "System File: $($file.FullName)"
        Write-Found $finding
        $findings += $finding
    }
} else {
    Write-Clear "No Flash files in system directories"
}

# 3. Check user profiles
Write-Check "`nScanning user profiles..."
$userProfiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne "Public" }
$userFiles = @()

foreach ($profile in $userProfiles) {
    $paths = @(
        "$($profile.FullName)\AppData\Roaming\Adobe\Flash Player",
        "$($profile.FullName)\AppData\Roaming\Macromedia\Flash Player",
        "$($profile.FullName)\AppData\Local\Adobe\Flash Player",
        "$($profile.FullName)\AppData\LocalLow\Adobe\Flash Player"
    )
    
    foreach ($path in $paths) {
        if (Test-Path $path) {
            $items = Get-ChildItem $path -Recurse -Force -ErrorAction SilentlyContinue
            foreach ($item in $items) {
                $finding = "User File: $($item.FullName) [User: $($profile.Name)]"
                Write-Found $finding
                $findings += $finding
                $userFiles += $item
            }
        }
    }
}

if ($userFiles.Count -eq 0) {
    Write-Clear "No Flash files in user profiles"
}

# 4. Check registry
Write-Check "`nScanning registry..."
$regPaths = @(
    "HKLM:\SOFTWARE\Adobe\FlashPlayer",
    "HKLM:\SOFTWARE\Macromedia",
    "HKLM:\SOFTWARE\WOW6432Node\Adobe\FlashPlayer",
    "HKLM:\SOFTWARE\WOW6432Node\Macromedia",
    "HKLM:\SOFTWARE\Classes\ShockwaveFlash.ShockwaveFlash"
)

$regFound = $false
foreach ($regPath in $regPaths) {
    if (Test-Path $regPath) {
        $finding = "Registry: $regPath"
        Write-Found $finding
        $findings += $finding
        $regFound = $true
    }
}

if (-not $regFound) {
    Write-Clear "No Flash registry entries detected"
}

# 5. Check scheduled tasks
Write-Check "`nScanning scheduled tasks..."
$tasks = Get-ScheduledTask | Where-Object { $_.TaskName -like "*Flash*" }
if ($tasks) {
    foreach ($task in $tasks) {
        $finding = "Scheduled Task: $($task.TaskName) (State: $($task.State))"
        Write-Found $finding
        $findings += $finding
    }
} else {
    Write-Clear "No Flash scheduled tasks detected"
}

# 6. Check browser plugins
Write-Check "`nScanning browser plugin directories..."
$browserPaths = @(
    "$env:LOCALAPPDATA\Google\Chrome\User Data\PepperFlash",
    "$env:LOCALAPPDATA\Microsoft\Edge\User Data\PepperFlash",
    "$env:APPDATA\Mozilla\Firefox\Profiles"
)

$pluginsFound = $false
foreach ($path in $browserPaths) {
    if (Test-Path $path) {
        if ($path -like "*Firefox*") {
            $flashFiles = Get-ChildItem $path -Recurse -Filter "*flash*" -ErrorAction SilentlyContinue
            if ($flashFiles) {
                foreach ($file in $flashFiles) {
                    $finding = "Browser Plugin: $($file.FullName)"
                    Write-Found $finding
                    $findings += $finding
                    $pluginsFound = $true
                }
            }
        } else {
            $finding = "Browser Plugin Directory: $path"
            Write-Found $finding
            $findings += $finding
            $pluginsFound = $true
        }
    }
}

if (-not $pluginsFound) {
    Write-Clear "No Flash browser plugins detected"
}

# 7. Check Windows features (Flash for Windows 8/10)
Write-Check "`nChecking Windows optional features..."
$feature = Get-WindowsOptionalFeature -Online -FeatureName "Adobe-Flash-For-Windows" -ErrorAction SilentlyContinue
if ($feature -and $feature.State -eq "Enabled") {
    $finding = "Windows Feature: Adobe-Flash-For-Windows is ENABLED"
    Write-Found $finding
    $findings += $finding
} else {
    Write-Clear "No Flash Windows features enabled"
}

# === FINAL REPORT ===
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "VALIDATION RESULTS" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

if ($findings.Count -eq 0) {
    Write-Host "✓ SYSTEM CLEAN - No Adobe Flash components detected!" -ForegroundColor Green
    Write-Host "`nYour system appears to be free of Adobe Flash Player." -ForegroundColor Green
    $status = "CLEAN"
} else {
    Write-Host "✗ FLASH DETECTED - Found $($findings.Count) Flash component(s)" -ForegroundColor Red
    Write-Host "`nThe following Flash components were detected:`n" -ForegroundColor Yellow
    $findings | ForEach-Object { Write-Host "  • $_" -ForegroundColor Yellow }
    Write-Host "`nRecommendation: Run the Flash removal script to eliminate these components." -ForegroundColor Yellow
    $status = "INFECTED"
}

# Save report
$reportPath = "C:\Windows\Temp_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
$report = @"
Adobe Flash Player Validation Report
=====================================
Scan Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Computer: $env:COMPUTERNAME
User: $env:USERNAME
Status: $status

Total Findings: $($findings.Count)

DETECTED COMPONENTS
===================
$($findings | ForEach-Object { "• $_" } | Out-String)

$(if ($findings.Count -eq 0) { "System is clean - No Flash components detected" } else { "ACTION REQUIRED: Flash components detected and should be removed" })
"@

$report | Out-File -FilePath $reportPath -Encoding UTF8
Write-Host "`nDetailed report saved to: $reportPath" -ForegroundColor Cyan
Write-Host "`n========================================`n" -ForegroundColor Cyan

# Return exit code
if ($findings.Count -eq 0) { exit 0 } else { exit 1 }