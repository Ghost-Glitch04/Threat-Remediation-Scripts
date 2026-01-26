<#
.SYNOPSIS
    Adobe Flash Player removal script with comprehensive logging
.DESCRIPTION
    Removes Adobe Flash with detailed step-by-step feedback
#>

param([switch]$Elevated)

# ============================================================================
# LOGGING FUNCTIONS
# ============================================================================
function Write-Step {
    param($Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] [STEP] $Message" -ForegroundColor Cyan
}

function Write-Success {
    param($Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] [OK]   $Message" -ForegroundColor Green
}

function Write-Fail {
    param($Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] [FAIL] $Message" -ForegroundColor Red
}

function Write-Warn {
    param($Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] [WARN] $Message" -ForegroundColor Yellow
}

function Write-Detail {
    param($Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] [INFO] $Message" -ForegroundColor Gray
}

# ============================================================================
# ADMIN CHECK WITH LOGGING
# ============================================================================
function Test-Admin {
    Write-Detail "Checking administrator privileges..."
    try {
        $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
        $isAdmin = $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
        
        if ($isAdmin) {
            Write-Success "Running with Administrator privileges"
            return $true
        } else {
            Write-Warn "NOT running as Administrator"
            return $false
        }
    }
    catch {
        Write-Fail "Failed to check admin status: $($_.Exception.Message)"
        return $false
    }
}

Write-Step "Starting Adobe Flash Player Removal Script"
Write-Detail "PowerShell Version: $($PSVersionTable.PSVersion)"
Write-Detail "Execution Policy: $(Get-ExecutionPolicy)"
Write-Detail "Current User: $env:USERNAME"
Write-Detail "Computer: $env:COMPUTERNAME"
Write-Host ""

# Check if we're admin
if ((Test-Admin) -eq $false) {
    if ($elevated) {
        Write-Fail "Attempted to elevate but still not running as Administrator"
        Write-Fail "Please right-click PowerShell and select 'Run as Administrator'"
        Read-Host "Press Enter to exit"
        exit 1
    } else {
        Write-Warn "Attempting to restart script with Administrator privileges..."
        try {
            $scriptPath = $myinvocation.MyCommand.Definition
            Write-Detail "Script path: $scriptPath"
            Start-Process powershell.exe -Verb RunAs -ArgumentList ('-noprofile -ExecutionPolicy Bypass -file "{0}" -elevated' -f $scriptPath)
            Write-Detail "Elevation prompt shown. Exiting current instance..."
            exit 0
        }
        catch {
            Write-Fail "Failed to elevate: $($_.Exception.Message)"
            Read-Host "Press Enter to exit"
            exit 1
        }
    }
}

Write-Host ""

# ============================================================================
# PROGRAM DETECTION FUNCTION WITH LOGGING
# ============================================================================
function Check-FlashInstalled {
    Write-Detail "Checking if Adobe Flash Player is installed..."
    
    try {
        $32bitApps = Get-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue
        $64bitApps = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue
        $allApps = @($64bitApps) + @($32bitApps)
        
        Write-Detail "Found $($allApps.Count) total installed programs"
        
        $flashApps = $allApps | Where-Object { $_.DisplayName -match "Flash" }
        
        if ($flashApps) {
            Write-Warn "Found Flash installations:"
            foreach ($app in $flashApps) {
                Write-Detail "  - $($app.DisplayName) (Version: $($app.DisplayVersion))"
            }
            return $true
        } else {
            Write-Success "No Flash Player found in registry uninstall keys"
            return $false
        }
    }
    catch {
        Write-Fail "Error checking registry: $($_.Exception.Message)"
        return $false
    }
}

# ============================================================================
# TERMINATE FLASH PROCESSES
# ============================================================================
Write-Step "Terminating Flash-related processes"

$processesToKill = @("FlashPlayerPlugin*", "FlashUtil*", "FlashPlayerApp*", "uninstall_flash_player")

foreach ($procName in $processesToKill) {
    Write-Detail "Checking for process: $procName"
    $procs = Get-Process -Name $procName -ErrorAction SilentlyContinue
    
    if ($procs) {
        foreach ($proc in $procs) {
            try {
                Write-Detail "Killing process: $($proc.Name) (PID: $($proc.Id))"
                Stop-Process -Id $proc.Id -Force -ErrorAction Stop
                Write-Success "Terminated: $($proc.Name)"
            }
            catch {
                Write-Fail "Could not terminate $($proc.Name): $($_.Exception.Message)"
            }
        }
    } else {
        Write-Detail "Process not running: $procName"
    }
}

Write-Host ""

# ============================================================================
# DOWNLOAD AND RUN ADOBE UNINSTALLER
# ============================================================================
Write-Step "Downloading Adobe Flash uninstaller"

$ProcName = "uninstall_flash_player.exe"
$downloadPath = "$env:TEMP\$ProcName"

# Try multiple URLs (Adobe changed their domain structure)
$downloadUrls = @(
    "https://fpdownload.macromedia.com/get/flashplayer/current/support/uninstall_flash_player.exe"
    "https://fpdownload.adobe.com/get/flashplayer/current/support/$ProcName",
    "http://fpdownload.adobe.com/get/flashplayer/current/support/$ProcName",
    "http://download.macromedia.com/get/flashplayer/current/support/$ProcName"
)

$downloadSuccess = $false

foreach ($url in $downloadUrls) {
    Write-Detail "Attempting download from: $url"
    Write-Detail "Saving to: $downloadPath"
    
    try {
        # Remove old file if exists
        if (Test-Path $downloadPath) {
            Write-Detail "Removing existing file: $downloadPath"
            Remove-Item $downloadPath -Force -ErrorAction Stop
        }
        
        # Set TLS 1.2 for compatibility
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        
        # Download with timeout
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile($url, $downloadPath)
        
        # Verify download
        if (Test-Path $downloadPath) {
            $fileSize = (Get-Item $downloadPath).Length
            Write-Success "Downloaded successfully ($fileSize bytes)"
            $downloadSuccess = $true
            break
        } else {
            Write-Fail "File not found after download"
        }
    }
    catch {
        Write-Warn "Download failed from $url : $($_.Exception.Message)"
        continue
    }
}

if (-not $downloadSuccess) {
    Write-Fail "Could not download uninstaller from any source"
    Write-Warn "Proceeding with manual cleanup only..."
} else {
    Write-Host ""
    Write-Step "Running Adobe official uninstaller"
    
    try {
        Write-Detail "Executing: $downloadPath -uninstall"
        $process = Start-Process -FilePath $downloadPath -ArgumentList "-uninstall" -Wait -PassThru -NoNewWindow
        
        Write-Detail "Uninstaller exit code: $($process.ExitCode)"
        
        if ($process.ExitCode -eq 0) {
            Write-Success "Adobe uninstaller completed successfully"
        } else {
            Write-Warn "Uninstaller exited with code: $($process.ExitCode)"
        }
        
        Start-Sleep -Seconds 2
        
        # Clean up uninstaller
        Write-Detail "Removing uninstaller file"
        Remove-Item $downloadPath -Force -ErrorAction SilentlyContinue
        Write-Success "Cleaned up temporary files"
    }
    catch {
        Write-Fail "Error running uninstaller: $($_.Exception.Message)"
    }
}

Write-Host ""

# ============================================================================
# MANUAL CLEANUP - SYSTEM FILES
# ============================================================================
Write-Step "Performing manual cleanup of system files"

$systemPaths = @(
    "C:\Windows\system32\Macromed",
    "C:\Windows\SysWOW64\Macromed",
    "C:\Windows\system32\FlashPlayerApp.exe",
    "C:\Windows\SysWOW64\FlashPlayerApp.exe"
)

foreach ($path in $systemPaths) {
    Write-Detail "Checking: $path"
    
    if (Test-Path $path) {
        Write-Warn "Found Flash files at: $path"
        try {
            Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
            
            if (Test-Path $path) {
                Write-Fail "Failed to remove: $path (still exists)"
            } else {
                Write-Success "Removed: $path"
            }
        }
        catch {
            Write-Fail "Error removing $path : $($_.Exception.Message)"
        }
    } else {
        Write-Detail "Not found (OK): $path"
    }
}

Write-Host ""

# ============================================================================
# MANUAL CLEANUP - USER PROFILES
# ============================================================================
Write-Step "Cleaning user profile directories"

try {
    $users = Get-ChildItem "C:\Users" -Directory -ErrorAction Stop | Where-Object { $_.Name -ne "Public" }
    Write-Detail "Found $($users.Count) user profiles to check"
    
    foreach ($user in $users) {
        Write-Detail "Checking user: $($user.Name)"
        
        $userPaths = @(
            "$($user.FullName)\AppData\Roaming\Adobe\Flash Player",
            "$($user.FullName)\AppData\Roaming\Macromedia\Flash Player",
            "$($user.FullName)\AppData\Local\Adobe\Flash Player",
            "$($user.FullName)\AppData\LocalLow\Adobe\Flash Player"
        )
        
        foreach ($path in $userPaths) {
            if (Test-Path $path) {
                Write-Warn "Found Flash data: $path"
                try {
                    Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
                    Write-Success "Removed: $path"
                }
                catch {
                    Write-Fail "Could not remove $path : $($_.Exception.Message)"
                }
            }
        }
    }
}
catch {
    Write-Fail "Error scanning user profiles: $($_.Exception.Message)"
}

Write-Host ""

# ============================================================================
# MANUAL CLEANUP - REGISTRY
# ============================================================================
Write-Step "Cleaning registry entries"

$regPaths = @(
    "HKLM:\SOFTWARE\Adobe\FlashPlayer",
    "HKLM:\SOFTWARE\Macromedia",
    "HKLM:\SOFTWARE\WOW6432Node\Adobe\FlashPlayer",
    "HKLM:\SOFTWARE\WOW6432Node\Macromedia"
)

foreach ($regPath in $regPaths) {
    Write-Detail "Checking registry: $regPath"
    
    if (Test-Path $regPath) {
        Write-Warn "Found Flash registry key: $regPath"
        try {
            Remove-Item -Path $regPath -Recurse -Force -ErrorAction Stop
            
            if (Test-Path $regPath) {
                Write-Fail "Failed to remove: $regPath (still exists)"
            } else {
                Write-Success "Removed: $regPath"
            }
        }
        catch {
            Write-Fail "Error removing $regPath : $($_.Exception.Message)"
        }
    } else {
        Write-Detail "Not found (OK): $regPath"
    }
}

Write-Host ""

# ============================================================================
# MANUAL CLEANUP - SCHEDULED TASKS
# ============================================================================
Write-Step "Removing scheduled tasks"

$taskNames = @(
    "Adobe Flash Player Updater",
    "Adobe Flash Player NPAPI Notifier",
    "Adobe Flash Player PPAPI Notifier"
)

foreach ($taskName in $taskNames) {
    Write-Detail "Checking for task: $taskName"
    
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    
    if ($task) {
        Write-Warn "Found scheduled task: $taskName"
        try {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
            Write-Success "Removed task: $taskName"
        }
        catch {
            Write-Fail "Could not remove task: $($_.Exception.Message)"
        }
    } else {
        Write-Detail "Task not found (OK): $taskName"
    }
}

Write-Host ""

# ============================================================================
# FINAL VALIDATION
# ============================================================================
Write-Step "Validating Flash removal"

$validationPassed = $true

# Check registry
Write-Detail "Checking registry for Flash installations..."
if (Check-FlashInstalled) {
    Write-Fail "Flash still appears in registry!"
    $validationPassed = $false
}

# Check for files
Write-Detail "Checking for Flash files..."
$foundFiles = $false

$checkPaths = @("C:\Windows\system32\Macromed", "C:\Windows\SysWOW64\Macromed")
foreach ($path in $checkPaths) {
    if (Test-Path $path) {
        $files = Get-ChildItem $path -Recurse -ErrorAction SilentlyContinue
        if ($files) {
            Write-Fail "Flash files still exist in: $path"
            foreach ($file in $files) {
                Write-Detail "  - $($file.FullName)"
            }
            $foundFiles = $true
            $validationPassed = $false
        }
    }
}

if (-not $foundFiles) {
    Write-Success "No Flash files found in system directories"
}

# Check for processes
Write-Detail "Checking for Flash processes..."
$flashProcs = Get-Process | Where-Object { $_.Name -like "*Flash*" }
if ($flashProcs) {
    Write-Fail "Flash processes still running:"
    foreach ($proc in $flashProcs) {
        Write-Detail "  - $($proc.Name) (PID: $($proc.Id))"
    }
    $validationPassed = $false
} else {
    Write-Success "No Flash processes running"
}

# Check scheduled tasks
Write-Detail "Checking for Flash scheduled tasks..."
$flashTasks = Get-ScheduledTask | Where-Object { $_.TaskName -like "*Flash*" }
if ($flashTasks) {
    Write-Fail "Flash scheduled tasks still exist:"
    foreach ($task in $flashTasks) {
        Write-Detail "  - $($task.TaskName)"
    }
    $validationPassed = $false
} else {
    Write-Success "No Flash scheduled tasks found"
}

# ============================================================================
# FINAL SUMMARY
# ============================================================================
Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "         FLASH REMOVAL SUMMARY" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan

if ($validationPassed) {
    Write-Host ""
    Write-Success "Adobe Flash Player has been successfully removed!"
    Write-Host ""
    Write-Host "All Flash components have been eliminated from this system." -ForegroundColor Green
    Write-Host ""
    exit 0
} else {
    Write-Host ""
    Write-Fail "Flash removal completed with issues"
    Write-Host ""
    Write-Host "Some Flash components could not be removed automatically." -ForegroundColor Yellow
    Write-Host "Review the log above for details on remaining items." -ForegroundColor Yellow
    Write-Host ""
    exit 1
}

Read-Host "Press Enter to exit"