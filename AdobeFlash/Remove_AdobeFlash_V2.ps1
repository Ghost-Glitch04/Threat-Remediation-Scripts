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

$failedRegKeys = @()

foreach ($regPath in $regPaths) {
    Write-Detail "Checking registry: $regPath"
    
    if (Test-Path $regPath) {
        Write-Warn "Found Flash registry key: $regPath"
        $keyRemoved = $false
        
        # Method 1: Try PowerShell Remove-Item
        try {
            Remove-Item -Path $regPath -Recurse -Force -ErrorAction Stop
            
            if (Test-Path $regPath) {
                Write-Fail "Failed to remove: $regPath (still exists)"
            } else {
                Write-Success "Removed: $regPath"
                $keyRemoved = $true
            }
        }
        catch {
            Write-Fail "PowerShell removal failed: $($_.Exception.Message)"
            Write-Detail "Attempting alternative method with reg.exe..."
            
            # Method 2: Try reg.exe
            try {
                # Convert PowerShell path to reg.exe format
                $regExePath = $regPath -replace '^HKLM:\\', 'HKEY_LOCAL_MACHINE\'
                
                Write-Detail "Executing: reg delete `"$regExePath`" /f"
                $process = Start-Process -FilePath "reg.exe" -ArgumentList "delete `"$regExePath`" /f" -Wait -PassThru -NoNewWindow
                
                if ($process.ExitCode -eq 0) {
                    Write-Success "Removed via reg.exe: $regPath"
                    $keyRemoved = $true
                } else {
                    Write-Fail "reg.exe failed with exit code: $($process.ExitCode)"
                }
                
                # Verify removal
                Start-Sleep -Milliseconds 500
                if (-not (Test-Path $regPath)) {
                    Write-Success "Verified: $regPath no longer exists"
                    $keyRemoved = $true
                } else {
                    Write-Fail "Registry key still exists after reg.exe attempt"
                }
            }
            catch {
                Write-Fail "reg.exe execution error: $($_.Exception.Message)"
            }
        }
        
        # If both methods failed, add to list for scheduled task removal
        if (-not $keyRemoved -and (Test-Path $regPath)) {
            Write-Warn "Marking for scheduled task removal: $regPath"
            $failedRegKeys += $regPath
        }
    } else {
        Write-Detail "Not found (OK): $regPath"
    }
}

# Method 3: Use scheduled task for stubborn keys
if ($failedRegKeys.Count -gt 0) {
    Write-Host ""
    Write-Step "Attempting scheduled task removal for $($failedRegKeys.Count) stubborn registry key(s)"
    
    # Create PowerShell script for the scheduled task
    $taskScriptContent = @'
# Registry cleanup script running as SYSTEM
$logFile = "$env:TEMP\FlashRegistryCleanup.log"

function Write-Log {
    param($Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] $Message"
    Add-Content -Path $logFile -Value $logMessage -Force
}

Write-Log "=== Starting Flash registry cleanup as SYSTEM ==="

$registryKeys = @(
{REGISTRY_KEYS_PLACEHOLDER}
)

foreach ($key in $registryKeys) {
    Write-Log "Processing: $key"
    
    if (Test-Path $key) {
        Write-Log "Key exists, attempting removal..."
        
        # Try PowerShell first
        try {
            Remove-Item -Path $key -Recurse -Force -ErrorAction Stop
            Write-Log "SUCCESS: Removed via PowerShell - $key"
        }
        catch {
            Write-Log "PowerShell failed: $($_.Exception.Message)"
            
            # Fallback to reg.exe
            $regPath = $key -replace '^HKLM:\\', 'HKEY_LOCAL_MACHINE\'
            Write-Log "Trying reg.exe: $regPath"
            
            try {
                $proc = Start-Process -FilePath "reg.exe" -ArgumentList "delete `"$regPath`" /f" -Wait -PassThru -NoNewWindow
                
                if ($proc.ExitCode -eq 0) {
                    Write-Log "SUCCESS: Removed via reg.exe - $key"
                } else {
                    Write-Log "FAILED: reg.exe exit code $($proc.ExitCode)"
                }
            }
            catch {
                Write-Log "FAILED: reg.exe error - $($_.Exception.Message)"
            }
        }
        
        # Verify removal
        Start-Sleep -Milliseconds 500
        if (-not (Test-Path $key)) {
            Write-Log "VERIFIED: $key no longer exists"
        } else {
            Write-Log "WARNING: $key still exists after removal attempts"
        }
    } else {
        Write-Log "Key not found (already removed): $key"
    }
}

Write-Log "=== Cleanup completed ==="
'@
    
    # Build the registry keys list for the script
    $regKeysArray = ($failedRegKeys | ForEach-Object { "    `"$_`"" }) -join ",`n"
    $taskScriptContent = $taskScriptContent -replace '\{REGISTRY_KEYS_PLACEHOLDER\}', $regKeysArray
    
    # Save the script to a temporary file
    $tempScriptPath = "$env:TEMP\RemoveFlashRegistry_$(Get-Date -Format 'yyyyMMddHHmmss').ps1"
    try {
        $taskScriptContent | Out-File -FilePath $tempScriptPath -Encoding UTF8 -Force
        Write-Detail "Created temporary script: $tempScriptPath"
    }
    catch {
        Write-Fail "Could not create temporary script: $($_.Exception.Message)"
        $tempScriptPath = $null
    }
    
    if ($tempScriptPath -and (Test-Path $tempScriptPath)) {
        # Create and run the scheduled task
        $taskName = "RemoveFlashRegistry_$(Get-Date -Format 'yyyyMMddHHmmss')"
        
        try {
            Write-Detail "Creating scheduled task: $taskName"
            
            # Define the action (run PowerShell with the script)
            $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File `"$tempScriptPath`""
            
            # Define the principal (run as SYSTEM with highest privileges)
            $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
            
            # Define settings
            $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -DontStopOnIdleEnd
            
            # Register the task
            $task = Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings -Force -ErrorAction Stop
            Write-Success "Scheduled task created successfully"
            
            # Run the task
            Write-Detail "Starting scheduled task..."
            Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
            Write-Detail "Task started, waiting for completion..."
            
            # Wait for task to complete
            $maxWait = 30
            $waited = 0
            while ($waited -lt $maxWait) {
                Start-Sleep -Seconds 1
                $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
                if ($taskInfo -and $taskInfo.LastTaskResult -ne 267009) { # 267009 = task is running
                    break
                }
                $waited++
            }
            
            # Check task result
            $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
            if ($taskInfo) {
                Write-Detail "Task completed with result code: $($taskInfo.LastTaskResult)"
                
                if ($taskInfo.LastTaskResult -eq 0) {
                    Write-Success "Scheduled task completed successfully"
                } else {
                    Write-Warn "Task completed with non-zero exit code: $($taskInfo.LastTaskResult)"
                }
            }
            
            # Display log output if available
            $logFile = "$env:TEMP\FlashRegistryCleanup.log"
            if (Test-Path $logFile) {
                Write-Detail "Reading task log output..."
                $logContent = Get-Content $logFile -ErrorAction SilentlyContinue
                foreach ($line in $logContent) {
                    Write-Detail "  $line"
                }
            }
            
            # Clean up the scheduled task
            Write-Detail "Removing scheduled task..."
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
            Write-Success "Scheduled task removed"
            
        }
        catch {
            Write-Fail "Error with scheduled task: $($_.Exception.Message)"
        }
        finally {
            # Clean up temporary script file
            if (Test-Path $tempScriptPath) {
                Remove-Item $tempScriptPath -Force -ErrorAction SilentlyContinue
                Write-Detail "Removed temporary script file"
            }
        }
        
        # Verify which keys were successfully removed
        Write-Detail "Verifying registry key removal..."
        $stillFailed = @()
        foreach ($key in $failedRegKeys) {
            if (Test-Path $key) {
                Write-Fail "Still exists: $key"
                $stillFailed += $key
            } else {
                Write-Success "Successfully removed: $key"
            }
        }
        
        if ($stillFailed.Count -eq 0) {
            Write-Success "All stubborn registry keys were removed via scheduled task!"
        } else {
            Write-Warn "$($stillFailed.Count) registry key(s) could not be removed even with scheduled task"
        }
    }
}

Write-Host ""

# ============================================================================
# MANUAL CLEANUP - REGISTRY - Nuclear Option
# ============================================================================

#Requires -RunAsAdministrator

Write-Host "=== Nuclear Option: TrustedInstaller Registry Removal ===" -ForegroundColor Cyan
Write-Host "WARNING: This uses advanced Windows internals" -ForegroundColor Yellow
Write-Host ""

$registryKeys = @(
    "HKLM:\SOFTWARE\Adobe\FlashPlayer",
    "HKLM:\SOFTWARE\Macromedia",
    "HKLM:\SOFTWARE\WOW6432Node\Adobe\FlashPlayer",
    "HKLM:\SOFTWARE\WOW6432Node\Macromedia"
)

# Method 1: Take ownership with TrustedInstaller privileges
Write-Host "[METHOD 1] Using TrustedInstaller service..." -ForegroundColor Cyan

foreach ($key in $registryKeys) {
    if (Test-Path $key) {
        Write-Host "Processing: $key" -ForegroundColor Gray
        
        $regPath = $key -replace '^HKLM:\\', 'HKLM\'
        
        # Start TrustedInstaller service
        Write-Host "  Starting TrustedInstaller service..." -ForegroundColor Gray
        $service = Get-Service -Name TrustedInstaller
        if ($service.Status -ne 'Running') {
            Start-Service -Name TrustedInstaller
            Start-Sleep -Seconds 2
        }
        
        # Use PsExec to run as TrustedInstaller (if available)
        # Or use a scheduled task with specific security context
        
        # Alternative: Use .NET reflection to enable SE_RESTORE_NAME privilege
        try {
            $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
                $regPath.Replace('HKLM\', ''),
                [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
                [System.Security.AccessControl.RegistryRights]::FullControl
            )
            
            if ($regKey) {
                # Take ownership
                $acl = $regKey.GetAccessControl()
                $admin = New-Object System.Security.Principal.NTAccount("Administrators")
                $acl.SetOwner($admin)
                $regKey.SetAccessControl($acl)
                
                # Grant full control
                $rule = New-Object System.Security.AccessControl.RegistryAccessRule(
                    $admin,
                    [System.Security.AccessControl.RegistryRights]::FullControl,
                    [System.Security.AccessControl.AccessControlType]::Allow
                )
                $acl.AddAccessRule($rule)
                $regKey.SetAccessControl($acl)
                
                $regKey.Close()
                
                Write-Host "  Permissions modified, attempting deletion..." -ForegroundColor Gray
                Remove-Item -Path $key -Recurse -Force -ErrorAction Stop
                Write-Host "  [SUCCESS] Removed: $key" -ForegroundColor Green
            }
        }
        catch {
            Write-Host "  [FAILED] $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# Method 2: Delete subkeys individually with enumeration
Write-Host "`n[METHOD 2] Individual subkey removal..." -ForegroundColor Cyan

foreach ($key in $registryKeys) {
    if (Test-Path $key) {
        Write-Host "Processing: $key" -ForegroundColor Gray
        
        # Query subkeys with reg.exe
        $regPath = $key -replace '^HKLM:\\', 'HKEY_LOCAL_MACHINE\'
        $queryResult = reg query "$regPath" 2>&1
        
        if ($queryResult -match 'HKEY_LOCAL_MACHINE') {
            $subkeys = $queryResult | Where-Object { $_ -match 'HKEY_LOCAL_MACHINE' } | ForEach-Object { $_.Trim() }
            
            Write-Host "  Found $($subkeys.Count) subkey(s)" -ForegroundColor Gray
            
            # Delete each subkey
            foreach ($subkey in $subkeys) {
                if ($subkey -ne $regPath) {
                    Write-Host "  Deleting: $subkey" -ForegroundColor Gray
                    $proc = Start-Process -FilePath "reg.exe" -ArgumentList "delete `"$subkey`" /f" -Wait -PassThru -NoNewWindow
                    if ($proc.ExitCode -eq 0) {
                        Write-Host "    [OK] Deleted" -ForegroundColor Green
                    }
                }
            }
            
            # Now try to delete parent
            $proc = Start-Process -FilePath "reg.exe" -ArgumentList "delete `"$regPath`" /f" -Wait -PassThru -NoNewWindow
            if ($proc.ExitCode -eq 0) {
                Write-Host "  [SUCCESS] Removed parent key" -ForegroundColor Green
            }
        }
    }
}

# Verification
Write-Host "`n=== VERIFICATION ===" -ForegroundColor Cyan
foreach ($key in $registryKeys) {
    if (Test-Path $key) {
        Write-Host "[STILL EXISTS] $key" -ForegroundColor Red
    } else {
        Write-Host "[REMOVED] $key" -ForegroundColor Green
    }
}

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
            Write-Fail "PowerShell removal failed: $($_.Exception.Message)"
            Write-Detail "Attempting alternative method with schtasks.exe..."
            
            try {
                $process = Start-Process -FilePath "schtasks.exe" -ArgumentList "/delete /tn `"$taskName`" /f" -Wait -PassThru -NoNewWindow
                
                if ($process.ExitCode -eq 0) {
                    Write-Success "Removed task via schtasks: $taskName"
                } else {
                    Write-Fail "schtasks failed with exit code: $($process.ExitCode)"
                }
            }
            catch {
                Write-Fail "schtasks execution error: $($_.Exception.Message)"
            }
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
$flashTasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -like "*Adobe Flash*" }
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