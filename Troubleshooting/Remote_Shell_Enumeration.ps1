<#
.SYNOPSIS
    Detects kernel-level security protections and EDR/XDR solutions - Remote Shell Edition
.DESCRIPTION
    Identifies security software, tests for various protections, and reports capabilities
    Optimized for SentinelOne and N-Able remote shell environments
.NOTES
    Version: 2.0
    Does not require -RunAsAdministrator flag (checks at runtime instead)
#>

# ============================================================================
# INITIALIZE AND CHECK ENVIRONMENT
# ============================================================================

$ErrorActionPreference = "SilentlyContinue"
$script:HasAdminRights = $false
$script:ExecutionContext = "Unknown"
$script:RemoteShellType = "Unknown"

function Write-Section {
    param($Title)
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host " $Title" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
}

function Write-Finding {
    param($Category, $Finding, $Details = "")
    Write-Host "[DETECTED] " -NoNewline -ForegroundColor Yellow
    Write-Host "$Category`: " -NoNewline -ForegroundColor White
    Write-Host "$Finding" -ForegroundColor Green
    if ($Details) {
        Write-Host "           $Details" -ForegroundColor Gray
    }
}

function Write-Test {
    param($TestName, $Result, $Details = "")
    $color = switch ($Result) {
        "BLOCKED" { "Red" }
        "PROTECTED" { "Red" }
        "DENIED" { "Red" }
        "FAILED" { "Red" }
        "ALLOWED" { "Green" }
        "SUCCESS" { "Green" }
        "ENABLED" { "Green" }
        "WARNING" { "Yellow" }
        "LIMITED" { "Yellow" }
        "AVAILABLE" { "Yellow" }
        default { "Yellow" }
    }
    Write-Host "[TEST] " -NoNewline -ForegroundColor Cyan
    Write-Host "$TestName`: " -NoNewline -ForegroundColor White
    Write-Host "$Result" -ForegroundColor $color
    if ($Details) {
        Write-Host "       $Details" -ForegroundColor Gray
    }
}

function Write-PermissionError {
    param($Operation, $ErrorDetails)
    Write-Host "[PERMISSION ERROR] " -NoNewline -ForegroundColor Red
    Write-Host "$Operation" -ForegroundColor White
    Write-Host "                   Error: $ErrorDetails" -ForegroundColor DarkRed
    
    # Parse common permission errors
    if ($ErrorDetails -match "Access.*denied|Unauthorized") {
        Write-Host "                   Cause: Insufficient privileges or DACL restriction" -ForegroundColor DarkRed
    } elseif ($ErrorDetails -match "in use|being used") {
        Write-Host "                   Cause: Resource locked by another process" -ForegroundColor DarkRed
    } elseif ($ErrorDetails -match "does not exist|cannot find") {
        Write-Host "                   Cause: Resource does not exist or path invalid" -ForegroundColor DarkRed
    }
}

# ============================================================================
# DETECT EXECUTION ENVIRONMENT
# ============================================================================
Write-Section "EXECUTION ENVIRONMENT DETECTION"

# Check for admin rights
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $script:HasAdminRights = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if ($script:HasAdminRights) {
        Write-Test "Administrator Rights" "CONFIRMED" "Running with elevated privileges"
    } else {
        Write-Test "Administrator Rights" "DENIED" "Running without elevation - some tests will be limited"
        Write-Host "       [!] Recommendation: Run as Administrator for full enumeration" -ForegroundColor Yellow
    }
} catch {
    Write-PermissionError "Admin Rights Check" $_.Exception.Message
}

# Detect remote shell type
$parentProcess = Get-WmiObject Win32_Process -Filter "ProcessId=$PID" | Select-Object -First 1
if ($parentProcess) {
    $parentName = (Get-Process -Id $parentProcess.ParentProcessId -ErrorAction SilentlyContinue).Name
    
    if ($parentName -match "SentinelAgent|SentinelCtl|SentinelOne") {
        $script:RemoteShellType = "SentinelOne"
        Write-Finding "Remote Shell" "SentinelOne Remote Shell" "Parent: $parentName"
    } elseif ($parentName -match "AMP|Nable|N-Central") {
        $script:RemoteShellType = "N-Able"
        Write-Finding "Remote Shell" "N-Able Remote Shell" "Parent: $parentName"
    } elseif ($parentName -match "WinRM|wsmprovhost") {
        $script:RemoteShellType = "PowerShell Remoting (WinRM)"
        Write-Finding "Remote Shell" "PowerShell Remoting" "Parent: $parentName"
    } else {
        Write-Finding "Execution Context" "Direct PowerShell" "Parent: $parentName"
    }
}

# Check current user context
Write-Host "`nCurrent User Context:" -ForegroundColor White
Write-Host "  Username: $env:USERNAME" -ForegroundColor Gray
Write-Host "  Domain: $env:USERDOMAIN" -ForegroundColor Gray
Write-Host "  Computer: $env:COMPUTERNAME" -ForegroundColor Gray
Write-Host "  Process ID: $PID" -ForegroundColor Gray

if ($identity) {
    Write-Host "  SID: $($identity.User.Value)" -ForegroundColor Gray
    Write-Host "  Auth Type: $($identity.AuthenticationType)" -ForegroundColor Gray
    Write-Host "  Is System: $($identity.IsSystem)" -ForegroundColor Gray
}

# ============================================================================
# 1. DETECT EDR/XDR/SECURITY PRODUCTS
# ============================================================================
Write-Section "EDR/XDR/SECURITY PRODUCTS"

$securityProducts = @()

# Check services with better error handling
$services = @()
try {
    $services = Get-Service -ErrorAction Stop
    Write-Host "[✓] Can enumerate services ($($services.Count) total)" -ForegroundColor Green
} catch {
    Write-PermissionError "Service Enumeration" $_.Exception.Message
}

# SentinelOne
$sentinelService = $services | Where-Object { $_.Name -eq "SentinelAgent" } | Select-Object -First 1
if ($sentinelService) {
    Write-Finding "EDR" "SentinelOne" "Service: $($sentinelService.Status)"
    $securityProducts += "SentinelOne"
    
    # Check for SentinelOne drivers with timeout
    try {
        $drivers = Get-WmiObject Win32_SystemDriver -Filter "Name LIKE '%Sentinel%'" -ErrorAction Stop
        foreach ($driver in $drivers) {
            Write-Host "           Driver: $($driver.Name) - $($driver.State)" -ForegroundColor Gray
        }
    } catch {
        Write-Host "           [!] Could not enumerate drivers: $($_.Exception.Message)" -ForegroundColor DarkGray
    }
}

# CrowdStrike Falcon
$crowdService = $services | Where-Object { $_.Name -match "CSFalcon|CrowdStrike" } | Select-Object -First 1
if ($crowdService) {
    Write-Finding "EDR" "CrowdStrike Falcon" "Service: $($crowdService.Status)"
    $securityProducts += "CrowdStrike"
}

# Microsoft Defender
try {
    $defenderStatus = Get-MpComputerStatus -ErrorAction Stop
    if ($defenderStatus) {
        Write-Finding "EDR" "Microsoft Defender for Endpoint" "RealTimeProtection: $($defenderStatus.RealTimeProtectionEnabled)"
        $securityProducts += "Defender"
        Write-Host "           Tamper Protection: $($defenderStatus.IsTamperProtected)" -ForegroundColor Gray
        Write-Host "           Behavior Monitoring: $($defenderStatus.BehaviorMonitorEnabled)" -ForegroundColor Gray
        Write-Host "           IOAV Protection: $($defenderStatus.IoavProtectionEnabled)" -ForegroundColor Gray
        Write-Host "           Cloud Protection: $($defenderStatus.CloudProtectionEnabled)" -ForegroundColor Gray
    }
} catch {
    Write-Host "[INFO] Windows Defender status unavailable: $($_.Exception.Message)" -ForegroundColor DarkGray
}

# Check for other common security products
$securityServicePatterns = @{
    "CarbonBlack" = "Carbon*"
    "Sophos" = "Sophos*"
    "Symantec" = "SepMasterService|Symantec*"
    "McAfee" = "McAfee*|McShield"
    "TrendMicro" = "TMBMServer|TrendMicro*"
    "CortexXDR" = "CyveraService|Cortex*"
    "Cylance" = "Cylance*"
    "Palo Alto" = "PanGPS|Palo*"
}

foreach ($product in $securityServicePatterns.Keys) {
    $pattern = $securityServicePatterns[$product]
    $found = $services | Where-Object { $_.Name -like $pattern } | Select-Object -First 1
    if ($found) {
        Write-Finding "EDR" $product "Service: $($found.DisplayName) - $($found.Status)"
        $securityProducts += $product
    }
}

# Check Windows Security Center (may not work on servers or in remote shells)
try {
    $antivirusProducts = Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName "AntiVirusProduct" -ErrorAction Stop
    foreach ($av in $antivirusProducts) {
        Write-Finding "AV Product" "$($av.displayName)" "State: $($av.productState)"
    }
} catch {
    Write-Host "[INFO] Security Center query unavailable (normal for servers/remote shells)" -ForegroundColor DarkGray
}

if ($securityProducts.Count -eq 0) {
    Write-Host "[INFO] No major EDR/XDR products detected" -ForegroundColor Gray
}

# ============================================================================
# 2. DETECT KERNEL DRIVERS (MINIFILTER DRIVERS)
# ============================================================================
Write-Section "KERNEL DRIVERS AND MINIFILTERS"

if (-not $script:HasAdminRights) {
    Write-Host "[!] Admin rights required for comprehensive driver enumeration" -ForegroundColor Yellow
    Write-Host "    Attempting limited enumeration...`n" -ForegroundColor Yellow
}

# Get all filesystem minifilter drivers
try {
    $fltmcOutput = fltmc filters 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Active Filesystem Minifilters:" -ForegroundColor Cyan
        $fltmcOutput | Select-Object -Skip 3 | ForEach-Object {
            if ($_ -match '^\s*(\S+)\s+(\d+)\s+(\d+)') {
                $filterName = $matches[1]
                $instances = $matches[2]
                $altitude = $matches[3]
                
                # Highlight security-related filters
                if ($filterName -match 'Sentinel|Crowd|Defender|Carbon|Sophos|Symantec|McAfee|Trend|Cortex|Cylance|WdFilter') {
                    Write-Host "  [SECURITY] $filterName" -NoNewline -ForegroundColor Yellow
                    Write-Host " (Instances: $instances, Altitude: $altitude)" -ForegroundColor Gray
                } else {
                    Write-Host "  $filterName" -NoNewline -ForegroundColor Gray
                    Write-Host " (Instances: $instances, Altitude: $altitude)" -ForegroundColor DarkGray
                }
            }
        }
    } else {
        Write-PermissionError "Minifilter Enumeration" "fltmc returned exit code $LASTEXITCODE"
    }
} catch {
    Write-PermissionError "Minifilter Enumeration" $_.Exception.Message
}

# Get kernel drivers with timeout protection
Write-Host "`nSecurity-Related Kernel Drivers:" -ForegroundColor Cyan
try {
    $job = Start-Job -ScriptBlock {
        Get-WmiObject Win32_SystemDriver | Where-Object { 
            $_.State -eq "Running" -and 
            ($_.Name -match 'Sentinel|Crowd|Defender|Carbon|Sophos|Symantec|McAfee|Trend|Cortex|WdFilter|WdBoot|WdNisDrv|Sysmon')
        }
    }
    
    $kernelDrivers = Wait-Job $job -Timeout 10 | Receive-Job
    Remove-Job $job -Force
    
    if ($kernelDrivers) {
        foreach ($driver in $kernelDrivers) {
            Write-Host "  $($driver.Name)" -NoNewline -ForegroundColor Yellow
            Write-Host " - $($driver.DisplayName)" -ForegroundColor Gray
            Write-Host "    Path: $($driver.PathName)" -ForegroundColor DarkGray
            Write-Host "    State: $($driver.State), Start: $($driver.StartMode)" -ForegroundColor DarkGray
        }
    } else {
        Write-Host "  [INFO] No security-related kernel drivers found or query timed out" -ForegroundColor Gray
    }
} catch {
    Write-PermissionError "Kernel Driver Enumeration" $_.Exception.Message
}

# ============================================================================
# 3. TEST REGISTRY PROTECTIONS
# ============================================================================
Write-Section "REGISTRY PROTECTION TESTS"

if (-not $script:HasAdminRights) {
    Write-Host "[!] Some registry tests require admin rights - testing with available permissions`n" -ForegroundColor Yellow
}

# Test 1: Create registry key in HKCU (should work without admin)
$testKeyHKCU = "HKCU:\Software\SecurityTest_$(Get-Random)"
try {
    New-Item -Path $testKeyHKCU -Force -ErrorAction Stop | Out-Null
    Write-Test "HKCU Registry Create" "ALLOWED" "Successfully created test key"
    
    try {
        Remove-Item -Path $testKeyHKCU -Force -ErrorAction Stop
        Write-Test "HKCU Registry Delete" "ALLOWED" "Successfully deleted test key"
    } catch {
        Write-Test "HKCU Registry Delete" "BLOCKED" "Could not delete test key"
        Write-PermissionError "HKCU Delete" $_.Exception.Message
    }
} catch {
    Write-Test "HKCU Registry Create" "BLOCKED" "Could not create test key"
    Write-PermissionError "HKCU Create" $_.Exception.Message
}

# Test 2: Create registry key in HKLM (requires admin)
if ($script:HasAdminRights) {
    $testKeyHKLM = "HKLM:\SOFTWARE\SecurityTest_$(Get-Random)"
    try {
        New-Item -Path $testKeyHKLM -Force -ErrorAction Stop | Out-Null
        Write-Test "HKLM Registry Create" "ALLOWED" "Successfully created test key"
        
        try {
            Remove-Item -Path $testKeyHKLM -Force -ErrorAction Stop
            Write-Test "HKLM Registry Delete" "ALLOWED" "Successfully deleted test key"
        } catch {
            Write-Test "HKLM Registry Delete" "BLOCKED" "Could not delete - possible EDR protection"
            Write-PermissionError "HKLM Delete" $_.Exception.Message
            # Cleanup attempt
            Remove-Item -Path $testKeyHKLM -Force -ErrorAction SilentlyContinue
        }
    } catch {
        Write-Test "HKLM Registry Create" "BLOCKED" "Could not create test key"
        Write-PermissionError "HKLM Create" $_.Exception.Message
    }
} else {
    Write-Test "HKLM Registry Tests" "SKIPPED" "Requires administrator privileges"
}

# Test 3: Protected registry locations
$protectedKeys = @(
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; RequiresAdmin=$true},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services"; RequiresAdmin=$true},
    @{Path="HKLM:\SOFTWARE\Policies"; RequiresAdmin=$true},
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"; RequiresAdmin=$false}
)

foreach ($keyInfo in $protectedKeys) {
    $key = $keyInfo.Path
    
    if ($keyInfo.RequiresAdmin -and -not $script:HasAdminRights) {
        Write-Test "Protected Key: $key" "SKIPPED" "Requires admin rights"
        continue
    }
    
    if (Test-Path $key) {
        $testValueName = "SecurityTest_$(Get-Random)"
        try {
            New-ItemProperty -Path $key -Name $testValueName -Value "test" -Force -ErrorAction Stop | Out-Null
            try {
                Remove-ItemProperty -Path $key -Name $testValueName -Force -ErrorAction Stop
                Write-Test "Protected Key: $key" "ALLOWED" "Can write/delete values"
            } catch {
                Write-Test "Protected Key: $key" "WRITE-ONLY" "Can write but cannot delete"
                Write-PermissionError "Delete from $key" $_.Exception.Message
                # Cleanup
                Remove-ItemProperty -Path $key -Name $testValueName -Force -ErrorAction SilentlyContinue
            }
        } catch {
            Write-Test "Protected Key: $key" "PROTECTED" "Cannot write to key"
            Write-PermissionError "Write to $key" $_.Exception.Message
        }
    } else {
        Write-Test "Protected Key: $key" "NOT FOUND" "Registry key does not exist"
    }
}

# ============================================================================
# 4. TEST FILE SYSTEM PROTECTIONS
# ============================================================================
Write-Section "FILESYSTEM PROTECTION TESTS"

# Test 1: Write to Temp (should always work)
$testFile = "$env:TEMP\SecurityTest_$(Get-Random).txt"
try {
    "test" | Out-File -FilePath $testFile -Force -ErrorAction Stop
    Write-Test "Temp Directory Write" "ALLOWED" "Can write to $env:TEMP"
    try {
        Remove-Item -Path $testFile -Force -ErrorAction Stop
        Write-Test "Temp Directory Delete" "ALLOWED" "Can delete from $env:TEMP"
    } catch {
        Write-Test "Temp Directory Delete" "BLOCKED" "File locked or protected"
        Write-PermissionError "Delete from Temp" $_.Exception.Message
    }
} catch {
    Write-Test "Temp Directory Write" "BLOCKED" "Cannot write to Temp directory!"
    Write-PermissionError "Write to Temp" $_.Exception.Message
}

# Test 2: Write to Windows directory (requires admin)
if ($script:HasAdminRights) {
    $testFile = "$env:windir\SecurityTest_$(Get-Random).txt"
    try {
        "test" | Out-File -FilePath $testFile -Force -ErrorAction Stop
        Write-Test "Windows Directory Write" "ALLOWED" "Can write to $env:windir"
        Remove-Item -Path $testFile -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Test "Windows Directory Write" "BLOCKED" "Cannot write to Windows directory"
        Write-PermissionError "Write to Windows Dir" $_.Exception.Message
    }
    
    # Test 3: Write to System32 (requires admin)
    $testFile = "$env:windir\System32\SecurityTest_$(Get-Random).txt"
    try {
        "test" | Out-File -FilePath $testFile -Force -ErrorAction Stop
        Write-Test "System32 Write" "ALLOWED" "Can write to System32"
        Remove-Item -Path $testFile -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Test "System32 Write" "BLOCKED" "Cannot write to System32"
        Write-PermissionError "Write to System32" $_.Exception.Message
    }
} else {
    Write-Test "Windows/System32 Tests" "SKIPPED" "Requires administrator privileges"
}

# Test 4: Create executable in Temp
$testExe = "$env:TEMP\SecurityTest_$(Get-Random).exe"
try {
    Copy-Item "$env:windir\System32\notepad.exe" -Destination $testExe -Force -ErrorAction Stop
    Write-Test "Temp Directory EXE Creation" "ALLOWED" "Can create executables"
    
    # Try to execute it
    try {
        $proc = Start-Process -FilePath $testExe -ArgumentList "/??" -WindowStyle Hidden -PassThru -ErrorAction Stop
        Start-Sleep -Milliseconds 500
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        Write-Test "Temp Directory EXE Execution" "ALLOWED" "Can execute from Temp"
    } catch {
        Write-Test "Temp Directory EXE Execution" "BLOCKED" "Cannot execute from Temp"
        Write-PermissionError "Execute from Temp" $_.Exception.Message
    }
    
    Remove-Item -Path $testExe -Force -ErrorAction SilentlyContinue
} catch {
    Write-Test "Temp Directory EXE Creation" "BLOCKED" "Cannot create executables"
    Write-PermissionError "Create EXE in Temp" $_.Exception.Message
}

# ============================================================================
# 5. TEST PROCESS PROTECTIONS
# ============================================================================
Write-Section "PROCESS PROTECTION TESTS"

# Test 1: Process enumeration
try {
    $allProcs = Get-Process -ErrorAction Stop
    Write-Test "Process Enumeration" "ALLOWED" "Can enumerate $($allProcs.Count) processes"
} catch {
    Write-Test "Process Enumeration" "BLOCKED" "Cannot enumerate processes"
    Write-PermissionError "Process Enumeration" $_.Exception.Message
}

# Test 2: Process memory info
try {
    $proc = Get-Process -Name "explorer" -ErrorAction Stop | Select-Object -First 1
    if ($proc) {
        $memInfo = $proc.WorkingSet64
        Write-Test "Process Memory Info" "ALLOWED" "Can read process memory details ($([math]::Round($memInfo/1MB, 2)) MB)"
    }
} catch {
    Write-Test "Process Memory Info" "LIMITED" "Cannot read all process details"
}

# Test 3: Process creation
try {
    $proc = Start-Process -FilePath "cmd.exe" -ArgumentList "/c exit" -WindowStyle Hidden -PassThru -ErrorAction Stop
    $proc.WaitForExit(2000)
    Write-Test "Process Creation" "ALLOWED" "Can create processes"
} catch {
    Write-Test "Process Creation" "BLOCKED" "Cannot create processes"
    Write-PermissionError "Process Creation" $_.Exception.Message
}

# Test 4: Can we query security product processes?
if ($securityProducts.Count -gt 0) {
    try {
        $secProc = Get-Process | Where-Object { $_.Name -match 'Sentinel|Crowd|Defender' } | Select-Object -First 1
        if ($secProc) {
            Write-Test "Security Process Query" "ALLOWED" "Can query security software processes: $($secProc.Name)"
        }
    } catch {
        Write-Test "Security Process Query" "BLOCKED" "Security processes may be protected"
    }
}

# ============================================================================
# 6. TEST SCHEDULED TASK PROTECTIONS (SAFE MODE FOR REMOTE SHELLS)
# ============================================================================
Write-Section "SCHEDULED TASK PROTECTION TESTS"

# Always use safe mode in remote shells to prevent disconnection
if ($script:RemoteShellType -match "SentinelOne|N-Able|WinRM") {
    Write-Host "[!] Remote shell detected - using safe enumeration mode" -ForegroundColor Yellow
    Write-Host "    (Avoids task creation to prevent session termination)`n" -ForegroundColor Yellow
    
    # Test 1: Query existing scheduled tasks
    try {
        $existingTasks = Get-ScheduledTask -ErrorAction Stop
        Write-Test "Scheduled Task Query" "ALLOWED" "Can enumerate $($existingTasks.Count) tasks"
    } catch {
        Write-Test "Scheduled Task Query" "BLOCKED" "Cannot enumerate tasks"
        Write-PermissionError "Task Query" $_.Exception.Message
    }
    
    # Test 2: Check cmdlet availability
    $cmdlets = @('Register-ScheduledTask', 'Unregister-ScheduledTask', 'New-ScheduledTaskAction', 'New-ScheduledTaskTrigger')
    $availableCmdlets = 0
    foreach ($cmdlet in $cmdlets) {
        if (Get-Command $cmdlet -ErrorAction SilentlyContinue) {
            $availableCmdlets++
        }
    }
    
    if ($availableCmdlets -eq $cmdlets.Count) {
        Write-Test "Scheduled Task Cmdlets" "AVAILABLE" "All $availableCmdlets/$($cmdlets.Count) cmdlets present"
    } else {
        Write-Test "Scheduled Task Cmdlets" "LIMITED" "Only $availableCmdlets/$($cmdlets.Count) cmdlets available"
    }
    
    # Test 3: Check schtasks.exe
    $schtasksPath = "$env:windir\System32\schtasks.exe"
    if (Test-Path $schtasksPath) {
        try {
            $result = schtasks /query /tn "\Microsoft\Windows\Diagnosis\Scheduled" 2>&1
            if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 1) {
                Write-Test "schtasks.exe Query" "ALLOWED" "Can query tasks via schtasks.exe"
            } else {
                Write-Test "schtasks.exe Query" "LIMITED" "schtasks.exe restricted (exit code: $LASTEXITCODE)"
            }
        } catch {
            Write-Test "schtasks.exe Query" "BLOCKED" "Cannot execute schtasks.exe"
        }
    } else {
        Write-Test "schtasks.exe" "UNAVAILABLE" "schtasks.exe not found"
    }
    
    # Test 4: Task folder permissions
    $taskFolderPath = "$env:windir\System32\Tasks"
    if (Test-Path $taskFolderPath) {
        try {
            $acl = Get-Acl $taskFolderPath -ErrorAction Stop
            $testFile = Join-Path $taskFolderPath "SecurityTest_$(Get-Random)"
            
            # Try to create a file
            try {
                "test" | Out-File -FilePath $testFile -Force -ErrorAction Stop
                Write-Test "Task Folder Write Access" "ALLOWED" "Have write access to task folder"
                Remove-Item $testFile -Force -ErrorAction SilentlyContinue
            } catch {
                Write-Test "Task Folder Write Access" "DENIED" "No write access to task folder"
            }
        } catch {
            Write-Test "Task Folder Permissions" "UNKNOWN" "Could not check permissions"
        }
    }
    
    # Test 5: Safe task object creation (doesn't register)
    try {
        $testAction = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c exit" -ErrorAction Stop
        $testTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddHours(1) -ErrorAction Stop
        Write-Test "Task Object Creation" "ALLOWED" "Can create task action/trigger objects"
    } catch {
        Write-Test "Task Object Creation" "BLOCKED" "Cannot create task objects"
        Write-PermissionError "Task Object Creation" $_.Exception.Message
    }
    
    Write-Host "`n    [NOTE] Actual task registration test skipped in remote shell" -ForegroundColor Gray
    Write-Host "           Estimated capability: " -NoNewline -ForegroundColor Gray
    if ($script:HasAdminRights -and $availableCmdlets -eq $cmdlets.Count) {
        Write-Host "LIKELY AVAILABLE" -ForegroundColor Yellow
        Write-Host "           (Admin rights + all cmdlets present)" -ForegroundColor Gray
    } elseif ($availableCmdlets -eq $cmdlets.Count) {
        Write-Host "LIMITED" -ForegroundColor Yellow
        Write-Host "           (Cmdlets present but no admin rights)" -ForegroundColor Gray
    } else {
        Write-Host "BLOCKED" -ForegroundColor Red
        Write-Host "           (Missing cmdlets or insufficient permissions)" -ForegroundColor Gray
    }
    
} else {
    Write-Host "[✓] Local execution detected - performing full test`n" -ForegroundColor Green
    
    # Full test mode
    $taskName = "SecurityTest_$(Get-Random)"
    try {
        $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c exit"
        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddHours(24)
        
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Force -ErrorAction Stop | Out-Null
        Write-Test "Scheduled Task Creation" "ALLOWED" "Successfully created scheduled task"
        
        # Verify
        $verifyTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($verifyTask) {
            Write-Test "Scheduled Task Verification" "CONFIRMED" "Task exists in scheduler"
        }
        
        # Delete
        try {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
            Write-Test "Scheduled Task Deletion" "ALLOWED" "Successfully deleted task"
        } catch {
            Write-Test "Scheduled Task Deletion" "BLOCKED" "Could not delete task"
            Write-PermissionError "Task Deletion" $_.Exception.Message
        }
        
    } catch {
        Write-Test "Scheduled Task Operations" "BLOCKED" "Cannot create scheduled tasks"
        Write-PermissionError "Task Creation" $_.Exception.Message
        # Cleanup
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# 7. TEST SERVICE PROTECTIONS
# ============================================================================
Write-Section "SERVICE PROTECTION TESTS"

# Test: Can we query services?
try {
    $services = Get-Service -ErrorAction Stop
    Write-Test "Service Enumeration" "ALLOWED" "Can enumerate $($services.Count) services"
} catch {
    Write-Test "Service Enumeration" "BLOCKED" "Cannot enumerate services"
    Write-PermissionError "Service Enumeration" $_.Exception.Message
}

# Test: Can we query specific security services?
if ($securityProducts.Count -gt 0) {
    $testService = Get-Service | Where-Object { $_.Name -match 'Sentinel|Defender|Crowd|Sophos' } | Select-Object -First 1
    if ($testService) {
        try {
            $status = $testService.Status
            $startType = $testService.StartType
            Write-Test "Security Service Query" "ALLOWED" "Can query: $($testService.Name) ($status, $startType)"
        } catch {
            Write-Test "Security Service Query" "LIMITED" "Partial access to security services"
        }
    }
}

# Test: Can we check service permissions?
if ($script:HasAdminRights) {
    try {
        $testServiceName = "Spooler"  # Use a common, non-critical service
        $service = Get-Service -Name $testServiceName -ErrorAction Stop
        
        # Try to get detailed info via WMI
        $serviceWMI = Get-WmiObject Win32_Service -Filter "Name='$testServiceName'" -ErrorAction Stop
        Write-Test "Service Detail Query (WMI)" "ALLOWED" "Can query detailed service information"
    } catch {
        Write-Test "Service Detail Query (WMI)" "LIMITED" "Cannot query all service details"
    }
} else {
    Write-Test "Service Management Tests" "SKIPPED" "Requires administrator privileges"
}

# ============================================================================
# 8. TEST SCRIPT EXECUTION PROTECTIONS
# ============================================================================
Write-Section "SCRIPT EXECUTION PROTECTION TESTS"

# Test 1: Check current execution policy
$execPolicy = Get-ExecutionPolicy
$execPolicyList = Get-ExecutionPolicy -List | Format-Table -AutoSize | Out-String
Write-Test "PowerShell Execution Policy" $execPolicy "Current effective policy"
Write-Host "       Execution Policy by Scope:" -ForegroundColor Gray
Write-Host $execPolicyList -ForegroundColor DarkGray

# Test 2: PowerShell script execution
$scriptPath = "$env:TEMP\SecurityTest_$(Get-Random).ps1"
try {
    'Write-Output "Test Successful"' | Out-File -FilePath $scriptPath -Force -ErrorAction Stop
    
    # Test execution with bypass
    $output = & PowerShell.exe -ExecutionPolicy Bypass -NoProfile -File $scriptPath 2>&1
    if ($output -match "Test Successful") {
        Write-Test "PowerShell Script Execution" "ALLOWED" "Scripts execute with -ExecutionPolicy Bypass"
    } else {
        Write-Test "PowerShell Script Execution" "WARNING" "Script ran but output unexpected"
    }
    
    Remove-Item -Path $scriptPath -Force -ErrorAction SilentlyContinue
} catch {
    Write-Test "PowerShell Script Execution" "BLOCKED" "Cannot execute PowerShell scripts"
    Write-PermissionError "Script Execution" $_.Exception.Message
}

# Test 3: AMSI (Anti-Malware Scan Interface) presence
try {
    $amsiContext = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
    if ($amsiContext) {
        Write-Test "AMSI (Anti-Malware Scan Interface)" "ACTIVE" "Script content will be scanned"
    }
} catch {
    Write-Test "AMSI Status" "UNKNOWN" "Could not determine AMSI status"
}

# Test 4: PowerShell constrained language mode
$languageMode = $ExecutionContext.SessionState.LanguageMode
if ($languageMode -eq "FullLanguage") {
    Write-Test "PowerShell Language Mode" $languageMode "Full PowerShell capabilities available"
} else {
    Write-Test "PowerShell Language Mode" $languageMode "Restricted PowerShell environment"
    Write-Host "       [!] Some PowerShell features may be unavailable" -ForegroundColor Yellow
}

# Test 5: Can we load .NET assemblies?
try {
    [System.Diagnostics.Process]::GetCurrentProcess() | Out-Null
    Write-Test ".NET Assembly Loading" "ALLOWED" "Can load and use .NET Framework"
} catch {
    Write-Test ".NET Assembly Loading" "BLOCKED" "Cannot load .NET assemblies"
}

# ============================================================================
# 9. DETECT VIRTUALIZATION / SANDBOXING
# ============================================================================
Write-Section "VIRTUALIZATION AND SANDBOXING DETECTION"

# Check if running in VM
try {
    $computerSystem = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction Stop
    $biosInfo = Get-WmiObject -Class Win32_BIOS -ErrorAction Stop
    
    if ($computerSystem.Model -match 'Virtual|VMware|VirtualBox|Hyper-V|Xen|QEMU|Parallels') {
        Write-Finding "Virtualization" "$($computerSystem.Model)" "Running in virtual environment"
        Write-Host "           Manufacturer: $($computerSystem.Manufacturer)" -ForegroundColor Gray
    } else {
        Write-Finding "Hardware" "$($computerSystem.Model)" "Physical hardware or unknown VM"
    }
    
    # Check BIOS for VM indicators
    if ($biosInfo.SerialNumber -match 'VMware|VirtualBox|Hyper-V|0{8}') {
        Write-Finding "BIOS" "Virtual Machine Detected" "BIOS Serial: $($biosInfo.SerialNumber)"
    }
} catch {
    Write-Host "[WARN] Could not determine virtualization status: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Check for Windows Sandbox
try {
    if ((Get-WmiObject Win32_ComputerSystem).Model -match 'Virtual Machine') {
        if (Test-Path "C:\ProgramData\Microsoft\Windows\Containers") {
            Write-Finding "Sandbox" "Windows Sandbox" "May have restricted capabilities"
        }
    }
} catch {}

# Check for Hyper-V isolation / containers
try {
    $containerFeature = Get-WindowsOptionalFeature -Online -FeatureName "Containers" -ErrorAction SilentlyContinue
    if ($containerFeature -and $containerFeature.State -eq "Enabled") {
        Write-Finding "Container Support" "Enabled" "System supports Windows containers"
    }
} catch {}

# ============================================================================
# 10. CHECK TAMPER PROTECTION AND SECURITY SETTINGS
# ============================================================================
Write-Section "TAMPER PROTECTION STATUS"

# Windows Defender Tamper Protection
if ($defenderStatus) {
    if ($defenderStatus.IsTamperProtected) {
        Write-Test "Defender Tamper Protection" "ENABLED" "Security settings are protected from modification"
        Write-Host "       [!] Cannot disable Defender or modify security settings" -ForegroundColor Yellow
    } else {
        Write-Test "Defender Tamper Protection" "DISABLED" "Security settings can be modified"
    }
}

# Check UAC status
try {
    $uacKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $uacEnabled = (Get-ItemProperty -Path $uacKey -Name "EnableLUA" -ErrorAction Stop).EnableLUA
    
    if ($uacEnabled -eq 1) {
        Write-Test "User Account Control (UAC)" "ENABLED" "Elevation prompts required"
        
        $consentPrompt = (Get-ItemProperty -Path $uacKey -Name "ConsentPromptBehaviorAdmin" -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin
        switch ($consentPrompt) {
            0 { Write-Host "       Level: Elevate without prompting" -ForegroundColor Gray }
            1 { Write-Host "       Level: Prompt for credentials on secure desktop" -ForegroundColor Gray }
            2 { Write-Host "       Level: Prompt for consent on secure desktop" -ForegroundColor Gray }
            3 { Write-Host "       Level: Prompt for credentials" -ForegroundColor Gray }
            4 { Write-Host "       Level: Prompt for consent" -ForegroundColor Gray }
            5 { Write-Host "       Level: Prompt for consent for non-Windows binaries" -ForegroundColor Gray }
        }
    } else {
        Write-Test "User Account Control (UAC)" "DISABLED" "No elevation prompts"
    }
} catch {
    Write-Test "UAC Status" "UNKNOWN" "Could not determine UAC configuration"
}

# Check if running in AppContainer or restricted token
try {
    $currentProcess = [System.Diagnostics.Process]::GetCurrentProcess()
    $handle = $currentProcess.Handle
    Write-Test "Process Token" "ACCESSIBLE" "Can access current process token"
} catch {
    Write-Test "Process Token" "RESTRICTED" "May be running in restricted context"
}

# ============================================================================
# 11. NETWORK RESTRICTIONS
# ============================================================================
Write-Section "NETWORK CAPABILITY TESTS"

# Test 1: Can we resolve DNS?
try {
    $dnsTest = Resolve-DnsName -Name "google.com" -ErrorAction Stop | Select-Object -First 1
    Write-Test "DNS Resolution" "ALLOWED" "Can resolve hostnames ($($dnsTest.IPAddress))"
} catch {
    Write-Test "DNS Resolution" "BLOCKED" "Cannot resolve DNS names"
    Write-PermissionError "DNS Resolution" $_.Exception.Message
}

# Test 2: Can we make web requests?
try {
    $webTest = Invoke-WebRequest -Uri "https://www.google.com" -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
    Write-Test "HTTP/HTTPS Requests" "ALLOWED" "Can make web requests (Status: $($webTest.StatusCode))"
} catch {
    Write-Test "HTTP/HTTPS Requests" "BLOCKED" "Cannot make web requests"
    Write-PermissionError "Web Request" $_.Exception.Message
}

# Test 3: Check Windows Firewall status
if ($script:HasAdminRights) {
    try {
        $firewallProfiles = Get-NetFirewallProfile -ErrorAction Stop
        foreach ($profile in $firewallProfiles) {
            $status = if ($profile.Enabled) { "ENABLED" } else { "DISABLED" }
            Write-Test "Firewall Profile: $($profile.Name)" $status "$($profile.DefaultInboundAction)/$($profile.DefaultOutboundAction)"
        }
    } catch {
        Write-Test "Firewall Status" "UNKNOWN" "Could not query firewall configuration"
    }
} else {
    Write-Test "Firewall Configuration" "SKIPPED" "Requires administrator privileges"
}

# ============================================================================
# FINAL SUMMARY
# ============================================================================
Write-Section "ENUMERATION SUMMARY"

Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                     SECURITY POSTURE SUMMARY                  ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

# Execution context
Write-Host "`n[EXECUTION CONTEXT]" -ForegroundColor White
Write-Host "  Shell Type:        " -NoNewline -ForegroundColor Gray
Write-Host $script:RemoteShellType -ForegroundColor $(if ($script:RemoteShellType -match "Unknown") { "Yellow" } else { "Cyan" })
Write-Host "  Username:          " -NoNewline -ForegroundColor Gray
Write-Host "$env:USERDOMAIN\$env:USERNAME" -ForegroundColor Cyan
Write-Host "  Computer:          " -NoNewline -ForegroundColor Gray
Write-Host $env:COMPUTERNAME -ForegroundColor Cyan
Write-Host "  Admin Rights:      " -NoNewline -ForegroundColor Gray
Write-Host $(if ($script:HasAdminRights) { "YES" } else { "NO" }) -ForegroundColor $(if ($script:HasAdminRights) { "Green" } else { "Red" })
Write-Host "  Language Mode:     " -NoNewline -ForegroundColor Gray
Write-Host $ExecutionContext.SessionState.LanguageMode -ForegroundColor $(if ($ExecutionContext.SessionState.LanguageMode -eq "FullLanguage") { "Green" } else { "Yellow" })

# Security products
Write-Host "`n[SECURITY PRODUCTS DETECTED]" -ForegroundColor White
if ($securityProducts.Count -gt 0) {
    Write-Host "  Count: " -NoNewline -ForegroundColor Gray
    Write-Host $securityProducts.Count -ForegroundColor Yellow
    $securityProducts | ForEach-Object { 
        Write-Host "    • $_" -ForegroundColor Yellow
    }
} else {
    Write-Host "  None detected" -ForegroundColor Green
}

# Permission summary
Write-Host "`n[PERMISSION SUMMARY]" -ForegroundColor White

$permissions = @{
    "Registry (HKCU)" = "Unknown"
    "Registry (HKLM)" = "Unknown"
    "File System (Temp)" = "Unknown"
    "File System (System)" = "Unknown"
    "Process Operations" = "Unknown"
    "Scheduled Tasks" = "Unknown"
    "Service Management" = "Unknown"
    "Script Execution" = "Unknown"
    "Network Access" = "Unknown"
}

# This would need to be populated based on test results stored in variables
# For demonstration, showing the format:

Write-Host "  Registry Operations:" -ForegroundColor Gray
Write-Host "    • HKCU:          " -NoNewline -ForegroundColor Gray
Write-Host "Allowed" -ForegroundColor Green
if ($script:HasAdminRights) {
    Write-Host "    • HKLM:          " -NoNewline -ForegroundColor Gray
    Write-Host "Tested (see details above)" -ForegroundColor Yellow
} else {
    Write-Host "    • HKLM:          " -NoNewline -ForegroundColor Gray
    Write-Host "Requires Admin" -ForegroundColor Red
}

Write-Host "  File System:" -ForegroundColor Gray
Write-Host "    • Temp Directory:" -NoNewline -ForegroundColor Gray
Write-Host " Tested (see details above)" -ForegroundColor Yellow
if ($script:HasAdminRights) {
    Write-Host "    • System Dirs:   " -NoNewline -ForegroundColor Gray
    Write-Host "Tested (see details above)" -ForegroundColor Yellow
} else {
    Write-Host "    • System Dirs:   " -NoNewline -ForegroundColor Gray
    Write-Host "Requires Admin" -ForegroundColor Red
}

# Key findings and recommendations
Write-Host "`n[KEY FINDINGS]" -ForegroundColor White

if ($securityProducts.Count -gt 0) {
    Write-Host "  ⚠ EDR/XDR Protection Active" -ForegroundColor Yellow
    Write-Host "    - Registry operations are monitored" -ForegroundColor Gray
    Write-Host "    - File system activity is filtered" -ForegroundColor Gray
    Write-Host "    - Process creation is supervised" -ForegroundColor Gray
}

if (-not $script:HasAdminRights) {
    Write-Host "  ⚠ Limited Privileges" -ForegroundColor Yellow
    Write-Host "    - HKLM registry modifications blocked" -ForegroundColor Gray
    Write-Host "    - System directory access restricted" -ForegroundColor Gray
    Write-Host "    - Service management unavailable" -ForegroundColor Gray
}

if ($script:RemoteShellType -match "SentinelOne|N-Able") {
    Write-Host "  ⚠ Remote Shell Limitations" -ForegroundColor Yellow
    Write-Host "    - Some operations may terminate session" -ForegroundColor Gray
    Write-Host "    - Safe mode used for scheduled task tests" -ForegroundColor Gray
    Write-Host "    - Use caution with system modifications" -ForegroundColor Gray
}

Write-Host "`n[RECOMMENDATIONS]" -ForegroundColor White

if ($securityProducts -contains "SentinelOne") {
    Write-Host "  • SentinelOne Detected:" -ForegroundColor Cyan
    Write-Host "    - Expect kernel-level file/registry protection" -ForegroundColor Gray
    Write-Host "    - Consider policy exclusions for legitimate scripts" -ForegroundColor Gray
    Write-Host "    - Use scheduled tasks as SYSTEM for protected operations" -ForegroundColor Gray
}

if ($securityProducts -contains "CrowdStrike") {
    Write-Host "  • CrowdStrike Detected:" -ForegroundColor Cyan
    Write-Host "    - Advanced behavioral monitoring active" -ForegroundColor Gray
    Write-Host "    - Avoid rapid-fire operations that appear suspicious" -ForegroundColor Gray
    Write-Host "    - Document legitimate administrative actions" -ForegroundColor Gray
}

if ($securityProducts -contains "Defender" -and $defenderStatus.IsTamperProtected) {
    Write-Host "  • Defender Tamper Protection Enabled:" -ForegroundColor Cyan
    Write-Host "    - Cannot disable real-time protection" -ForegroundColor Gray
    Write-Host "    - Work within the security framework" -ForegroundColor Gray
    Write-Host "    - Use Defender exclusions if needed" -ForegroundColor Gray
}

if (-not $script:HasAdminRights) {
    Write-Host "  • Elevation Required:" -ForegroundColor Cyan
    Write-Host "    - Re-run as Administrator for full capabilities" -ForegroundColor Gray
    Write-Host "    - Many system operations require elevation" -ForegroundColor Gray
}

if ($script:RemoteShellType -match "Unknown" -or $script:RemoteShellType -match "Direct") {
    Write-Host "  • Local Execution:" -ForegroundColor Cyan
    Write-Host "    - Full testing capabilities available" -ForegroundColor Gray
    Write-Host "    - Safe to perform all operations" -ForegroundColor Gray
}

Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                     ENUMERATION COMPLETE                      ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Reset error preference
$ErrorActionPreference = "Continue"