<#
.SYNOPSIS
    Detects kernel-level security protections and EDR/XDR solutions
.DESCRIPTION
    Identifies security software, tests for various protections, and reports capabilities
#>

#Requires -RunAsAdministrator

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
    $color = if ($Result -eq "BLOCKED" -or $Result -eq "PROTECTED") { "Red" } elseif ($Result -eq "ALLOWED") { "Green" } else { "Yellow" }
    Write-Host "[TEST] " -NoNewline -ForegroundColor Cyan
    Write-Host "$TestName`: " -NoNewline -ForegroundColor White
    Write-Host "$Result" -ForegroundColor $color
    if ($Details) {
        Write-Host "       $Details" -ForegroundColor Gray
    }
}

Write-Section "KERNEL-LEVEL PROTECTION DETECTION"
Write-Host "Scanning for EDR/XDR and security mechanisms...`n" -ForegroundColor Gray

# ============================================================================
# 1. DETECT EDR/XDR/SECURITY PRODUCTS
# ============================================================================
Write-Section "EDR/XDR/SECURITY PRODUCTS"

$securityProducts = @()

# SentinelOne
if (Get-Service -Name "SentinelAgent" -ErrorAction SilentlyContinue) {
    $service = Get-Service -Name "SentinelAgent"
    Write-Finding "EDR" "SentinelOne" "Service: $($service.Status)"
    $securityProducts += "SentinelOne"
    
    # Check for SentinelOne drivers
    $drivers = Get-WmiObject Win32_SystemDriver | Where-Object { $_.Name -like "*Sentinel*" }
    foreach ($driver in $drivers) {
        Write-Host "           Driver: $($driver.Name) ($($driver.State))" -ForegroundColor Gray
    }
}

# CrowdStrike Falcon
if (Get-Service -Name "CSFalconService" -ErrorAction SilentlyContinue) {
    $service = Get-Service -Name "CSFalconService"
    Write-Finding "EDR" "CrowdStrike Falcon" "Service: $($service.Status)"
    $securityProducts += "CrowdStrike"
    
    $drivers = Get-WmiObject Win32_SystemDriver | Where-Object { $_.Name -like "*CS*" -or $_.Name -like "*Falcon*" }
    foreach ($driver in $drivers) {
        Write-Host "           Driver: $($driver.Name) ($($driver.State))" -ForegroundColor Gray
    }
}

# Microsoft Defender
$defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
if ($defenderStatus) {
    Write-Finding "EDR" "Microsoft Defender for Endpoint" "RealTimeProtection: $($defenderStatus.RealTimeProtectionEnabled)"
    $securityProducts += "Defender"
    Write-Host "           Tamper Protection: $($defenderStatus.IsTamperProtected)" -ForegroundColor Gray
    Write-Host "           Behavior Monitoring: $($defenderStatus.BehaviorMonitorEnabled)" -ForegroundColor Gray
}

# Carbon Black
if (Get-Service -Name "CarbonBlack" -ErrorAction SilentlyContinue) {
    Write-Finding "EDR" "Carbon Black"
    $securityProducts += "CarbonBlack"
}

# Sophos
if (Get-Service -Name "Sophos*" -ErrorAction SilentlyContinue) {
    $sophosServices = Get-Service -Name "Sophos*"
    Write-Finding "EDR" "Sophos Intercept X" "Services: $($sophosServices.Count)"
    $securityProducts += "Sophos"
}

# Symantec/Broadcom
if (Get-Service -Name "SepMasterService" -ErrorAction SilentlyContinue) {
    Write-Finding "EDR" "Symantec Endpoint Protection"
    $securityProducts += "Symantec"
}

# McAfee
if (Get-Service -Name "McAfee*" -ErrorAction SilentlyContinue) {
    Write-Finding "EDR" "McAfee"
    $securityProducts += "McAfee"
}

# Trend Micro
if (Get-Service -Name "TMBMServer" -ErrorAction SilentlyContinue) {
    Write-Finding "EDR" "Trend Micro"
    $securityProducts += "TrendMicro"
}

# Palo Alto Cortex XDR
if (Get-Service -Name "CyveraService" -ErrorAction SilentlyContinue) {
    Write-Finding "EDR" "Palo Alto Cortex XDR"
    $securityProducts += "CortexXDR"
}

# Check Windows Security Center for registered products
try {
    $antivirusProducts = Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName "AntiVirusProduct" -ErrorAction SilentlyContinue
    foreach ($av in $antivirusProducts) {
        Write-Finding "AV Product" "$($av.displayName)" "State: $($av.productState)"
    }
} catch {
    Write-Host "[INFO] Could not query Security Center (normal on servers)" -ForegroundColor Gray
}

if ($securityProducts.Count -eq 0) {
    Write-Host "[INFO] No major EDR/XDR products detected" -ForegroundColor Gray
}

# ============================================================================
# 2. DETECT KERNEL DRIVERS (MINIFILTER DRIVERS)
# ============================================================================
Write-Section "KERNEL DRIVERS & MINIFILTERS"

Write-Host "Scanning for filesystem and registry minifilter drivers...`n" -ForegroundColor Gray

# Get all filesystem minifilter drivers
try {
    $minifilters = fltmc filters 2>$null
    if ($minifilters) {
        Write-Host "Active Filesystem Minifilters:" -ForegroundColor Cyan
        $minifilters | Select-Object -Skip 3 | ForEach-Object {
            if ($_ -match '^\s*(\S+)\s+(\d+)\s+(\d+)') {
                $filterName = $matches[1]
                # Highlight security-related filters
                if ($filterName -match 'Sentinel|Crowd|Defender|Carbon|Sophos|Symantec|McAfee|Trend|Cortex|Cylance') {
                    Write-Host "  [SECURITY] $filterName" -ForegroundColor Yellow
                } else {
                    Write-Host "  $filterName" -ForegroundColor Gray
                }
            }
        }
    }
} catch {
    Write-Host "[WARN] Could not enumerate minifilters: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Get kernel drivers that might provide protection
Write-Host "`nSecurity-Related Kernel Drivers:" -ForegroundColor Cyan
$kernelDrivers = Get-WmiObject Win32_SystemDriver | Where-Object { 
    $_.State -eq "Running" -and 
    ($_.Name -match 'Sentinel|Crowd|Defender|Carbon|Sophos|Symantec|McAfee|Trend|Cortex|WdFilter|WdBoot|WdNisDrv')
}

foreach ($driver in $kernelDrivers) {
    Write-Host "  $($driver.Name)" -NoNewline -ForegroundColor Yellow
    Write-Host " - $($driver.DisplayName)" -ForegroundColor Gray
    Write-Host "    Path: $($driver.PathName)" -ForegroundColor DarkGray
}

# ============================================================================
# 3. TEST REGISTRY PROTECTIONS
# ============================================================================
Write-Section "REGISTRY PROTECTION TESTS"

Write-Host "Testing registry write/delete capabilities...`n" -ForegroundColor Gray

# Test 1: Create registry key in HKLM
$testKey = "HKLM:\SOFTWARE\SecurityTest_$(Get-Random)"
try {
    New-Item -Path $testKey -Force -ErrorAction Stop | Out-Null
    Write-Test "HKLM Registry Create" "ALLOWED" "Successfully created test key"
    
    # Test delete
    try {
        Remove-Item -Path $testKey -Force -ErrorAction Stop
        Write-Test "HKLM Registry Delete" "ALLOWED" "Successfully deleted test key"
    } catch {
        Write-Test "HKLM Registry Delete" "BLOCKED" $_.Exception.Message
        Remove-Item -Path $testKey -Force -ErrorAction SilentlyContinue
    }
} catch {
    Write-Test "HKLM Registry Create" "BLOCKED" $_.Exception.Message
}

# Test 2: Registry protection on system keys
$protectedKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SYSTEM\CurrentControlSet\Services",
    "HKLM:\SOFTWARE\Policies"
)

foreach ($key in $protectedKeys) {
    $testValueName = "SecurityTest_$(Get-Random)"
    try {
        New-ItemProperty -Path $key -Name $testValueName -Value "test" -Force -ErrorAction Stop | Out-Null
        Remove-ItemProperty -Path $key -Name $testValueName -Force -ErrorAction Stop
        Write-Test "Protected Key: $key" "ALLOWED" "Can write/delete"
    } catch {
        Write-Test "Protected Key: $key" "PROTECTED" "Write blocked or restricted"
    }
}

# ============================================================================
# 4. TEST FILE SYSTEM PROTECTIONS
# ============================================================================
Write-Section "FILESYSTEM PROTECTION TESTS"

Write-Host "Testing filesystem write/delete capabilities...`n" -ForegroundColor Gray

# Test 1: Write to Windows directory
$testFile = "$env:windir\SecurityTest_$(Get-Random).txt"
try {
    "test" | Out-File -FilePath $testFile -Force -ErrorAction Stop
    Write-Test "Windows Directory Write" "ALLOWED" "Can write to $env:windir"
    Remove-Item -Path $testFile -Force -ErrorAction SilentlyContinue
} catch {
    Write-Test "Windows Directory Write" "BLOCKED" $_.Exception.Message
}

# Test 2: Write to System32
$testFile = "$env:windir\System32\SecurityTest_$(Get-Random).txt"
try {
    "test" | Out-File -FilePath $testFile -Force -ErrorAction Stop
    Write-Test "System32 Write" "ALLOWED" "Can write to System32"
    Remove-Item -Path $testFile -Force -ErrorAction SilentlyContinue
} catch {
    Write-Test "System32 Write" "BLOCKED" $_.Exception.Message
}

# Test 3: Create executable in Temp
$testExe = "$env:TEMP\SecurityTest_$(Get-Random).exe"
try {
    # Try to copy a benign system file as test
    Copy-Item "$env:windir\System32\notepad.exe" -Destination $testExe -Force -ErrorAction Stop
    Write-Test "Temp Directory EXE Creation" "ALLOWED" "Can create executables"
    Remove-Item -Path $testExe -Force -ErrorAction SilentlyContinue
} catch {
    Write-Test "Temp Directory EXE Creation" "BLOCKED" $_.Exception.Message
}

# ============================================================================
# 5. TEST PROCESS PROTECTIONS
# ============================================================================
Write-Section "PROCESS PROTECTION TESTS"

Write-Host "Testing process manipulation capabilities...`n" -ForegroundColor Gray

# Test 1: Can we query all processes?
try {
    $allProcs = Get-Process -ErrorAction Stop
    Write-Test "Process Enumeration" "ALLOWED" "Can enumerate $($allProcs.Count) processes"
} catch {
    Write-Test "Process Enumeration" "BLOCKED" $_.Exception.Message
}

# Test 2: Can we read process memory info?
try {
    $proc = Get-Process -Name "explorer" -ErrorAction Stop | Select-Object -First 1
    $memInfo = $proc.WorkingSet64
    Write-Test "Process Memory Info" "ALLOWED" "Can read process memory details"
} catch {
    Write-Test "Process Memory Info" "BLOCKED" $_.Exception.Message
}

# Test 3: Can we start a process?
try {
    $proc = Start-Process -FilePath "cmd.exe" -ArgumentList "/c exit" -NoNewWindow -PassThru -ErrorAction Stop
    $proc.WaitForExit(2000)
    Write-Test "Process Creation" "ALLOWED" "Can create processes"
} catch {
    Write-Test "Process Creation" "BLOCKED" $_.Exception.Message
}

# ============================================================================
# 6. TEST SCHEDULED TASK PROTECTIONS
# ============================================================================
Write-Section "SCHEDULED TASK PROTECTION TESTS"
    # ========================================================================
    # HELPER FUNCTIONS
    # ========================================================================
    function Write-Section {
        param($Title)
        Write-Host "`n========================================" -ForegroundColor Cyan
        Write-Host " $Title" -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Cyan
    }

    function Write-Test {
        param($TestName, $Result, $Details = "")
        $color = switch ($Result) {
            "ALLOWED" { "Green" }
            "BLOCKED" { "Red" }
            "AVAILABLE" { "Green" }
            "UNAVAILABLE" { "Red" }
            "LIMITED" { "Yellow" }
            "UNTESTED" { "Gray" }
            "CONFIRMED" { "Green" }
            "WRITE" { "Green" }
            "READ-ONLY" { "Yellow" }
            "UNKNOWN" { "Gray" }
            default { "Cyan" }
        }
        Write-Host "[TEST] " -NoNewline -ForegroundColor Cyan
        Write-Host "$TestName`: " -NoNewline -ForegroundColor White
        Write-Host "$Result" -ForegroundColor $color
        if ($Details) {
            Write-Host "       $Details" -ForegroundColor Gray
        }
    }

    # ========================================================================
    # SCHEDULED TASK PROTECTION TESTS (SENTINELONE-AWARE)
    # ========================================================================
    Write-Section "SCHEDULED TASK PROTECTION TESTS"

    Write-Host "Testing scheduled task manipulation...`n" -ForegroundColor Gray

    # Function to detect SentinelOne in process tree
    function Test-SentinelOnePresence {
        $currentPID = $PID
        
        for ($i = 0; $i -lt 5; $i++) {
            $proc = Get-WmiObject Win32_Process -Filter "ProcessId=$currentPID" -ErrorAction SilentlyContinue
            if (-not $proc) { break }
            
            if ($proc.Name -match 'Sentinel|S1') {
                return @{
                    Detected = $true
                    ProcessName = $proc.Name
                    ProcessID = $currentPID
                    Level = $i
                }
            }
            
            $currentPID = $proc.ParentProcessId
            if ($currentPID -eq 0 -or $null -eq $currentPID) { break }
        }
        
        return @{ Detected = $false }
    }

    # Detect execution environment
    $sentinelCheck = Test-SentinelOnePresence

    if ($sentinelCheck.Detected) {
        Write-Host "[!] SentinelOne detected in process tree: $($sentinelCheck.ProcessName)" -ForegroundColor Yellow
        Write-Host "    Using safe enumeration mode (avoids session termination)`n" -ForegroundColor Yellow
        
        # SAFE MODE: Query and check capabilities without creating tasks
        
        # Test 1: Query existing scheduled tasks
        try {
            $existingTasks = Get-ScheduledTask -ErrorAction Stop
            Write-Test "Scheduled Task Query" "ALLOWED" "Can enumerate $($existingTasks.Count) tasks"
        } catch {
            Write-Test "Scheduled Task Query" "BLOCKED" $_.Exception.Message
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
            Write-Test "Scheduled Task Cmdlets" "AVAILABLE" "All $availableCmdlets cmdlets present"
        } else {
            Write-Test "Scheduled Task Cmdlets" "LIMITED" "Only $availableCmdlets of $($cmdlets.Count) available"
        }
        
        # Test 3: Check schtasks.exe availability
        $schtasksPath = "$env:windir\System32\schtasks.exe"
        if (Test-Path $schtasksPath) {
            # Test if we can run schtasks in query mode
            try {
                $result = schtasks /query /tn "Microsoft\Windows\Diagnosis\Scheduled" 2>&1
                if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 1) {
                    Write-Test "schtasks.exe Query" "ALLOWED" "Can query tasks via schtasks.exe"
                } else {
                    Write-Test "schtasks.exe Query" "LIMITED" "schtasks.exe available but restricted"
                }
            } catch {
                Write-Test "schtasks.exe Query" "BLOCKED" "Cannot execute schtasks.exe"
            }
        } else {
            Write-Test "schtasks.exe" "UNAVAILABLE" "schtasks.exe not found"
        }
        
        # Test 4: Check task folder permissions
        $taskFolderPath = "$env:windir\System32\Tasks"
        if (Test-Path $taskFolderPath) {
            try {
                $acl = Get-Acl $taskFolderPath -ErrorAction Stop
                $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                $hasWriteAccess = $false
                
                foreach ($access in $acl.Access) {
                    if ($access.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) -eq $currentUser.User) {
                        if ($access.FileSystemRights -match 'Write|FullControl|Modify') {
                            $hasWriteAccess = $true
                            break
                        }
                    }
                }
                
                if ($hasWriteAccess) {
                    Write-Test "Task Folder Permissions" "WRITE" "Have write access to task folder"
                } else {
                    Write-Test "Task Folder Permissions" "READ-ONLY" "Limited access to task folder"
                }
            } catch {
                Write-Test "Task Folder Permissions" "UNKNOWN" "Could not check permissions"
            }
        }
        
        # Test 5: Check if we can create task objects (safe - doesn't register)
        try {
            $testAction = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c exit" -ErrorAction Stop
            $testTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddHours(1) -ErrorAction Stop
            Write-Test "Task Object Creation" "ALLOWED" "Can create task action/trigger objects"
        } catch {
            Write-Test "Task Object Creation" "BLOCKED" $_.Exception.Message
        }
        
        # Summary for SentinelOne environment
        Write-Host "`n    [NOTE] Actual task creation test skipped to prevent session termination" -ForegroundColor Gray
        Write-Host "           Based on checks above, task creation capability: " -NoNewline -ForegroundColor Gray
        if ($availableCmdlets -eq $cmdlets.Count -and (Test-Path $schtasksPath)) {
            Write-Host "LIKELY AVAILABLE" -ForegroundColor Yellow
        } else {
            Write-Host "LIMITED" -ForegroundColor Red
        }
        
    } else {
        Write-Host "[✓] Safe environment detected - performing full test`n" -ForegroundColor Green
        
        # FULL MODE: Actually create and delete a task
        $taskName = "SecurityTest_$(Get-Random)"
        try {
            $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c exit"
            $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddHours(1)
            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Force -ErrorAction Stop | Out-Null
            Write-Test "Scheduled Task Creation" "ALLOWED" "Can create scheduled tasks"
            
            # Verify task exists
            $verifyTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            if ($verifyTask) {
                Write-Test "Scheduled Task Verification" "CONFIRMED" "Task exists in scheduler"
            }
            
            # Try to delete
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
            Write-Test "Scheduled Task Deletion" "ALLOWED" "Can delete scheduled tasks"
            
        } catch {
            Write-Test "Scheduled Task Operations" "BLOCKED" $_.Exception.Message
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        }
    }

    Write-Host ""

# ============================================================================
# 7. TEST SERVICE PROTECTIONS
# ============================================================================
Write-Section "SERVICE PROTECTION TESTS"

Write-Host "Testing service manipulation...`n" -ForegroundColor Gray

# Test: Can we query services?
try {
    $services = Get-Service -ErrorAction Stop
    Write-Test "Service Enumeration" "ALLOWED" "Can enumerate $($services.Count) services"
} catch {
    Write-Test "Service Enumeration" "BLOCKED" $_.Exception.Message
}

# Test: Can we check security service status?
if ($securityProducts.Count -gt 0) {
    $testService = Get-Service | Where-Object { $_.Name -match 'Sentinel|Defender|Crowd' } | Select-Object -First 1
    if ($testService) {
        try {
            $status = $testService.Status
            Write-Test "Security Service Query" "ALLOWED" "Can query security service: $($testService.Name)"
        } catch {
            Write-Test "Security Service Query" "BLOCKED" $_.Exception.Message
        }
    }
}

# ============================================================================
# 8. TEST SCRIPT EXECUTION PROTECTIONS
# ============================================================================
Write-Section "SCRIPT EXECUTION PROTECTION TESTS"

Write-Host "Testing script execution capabilities...`n" -ForegroundColor Gray

# Test 1: PowerShell script execution
$scriptPath = "$env:TEMP\SecurityTest_$(Get-Random).ps1"
try {
    "Write-Host 'Test'" | Out-File -FilePath $scriptPath -Force -ErrorAction Stop
    $output = & PowerShell.exe -ExecutionPolicy Bypass -NoProfile -File $scriptPath 2>&1
    Write-Test "PowerShell Script Execution" "ALLOWED" "Scripts can execute"
    Remove-Item -Path $scriptPath -Force -ErrorAction SilentlyContinue
} catch {
    Write-Test "PowerShell Script Execution" "BLOCKED" $_.Exception.Message
}

# Test 2: Check execution policy
$execPolicy = Get-ExecutionPolicy
Write-Test "PowerShell Execution Policy" $execPolicy "Current policy setting"

# ============================================================================
# 9. DETECT VIRTUALIZATION / SANDBOXING
# ============================================================================
Write-Section "VIRTUALIZATION & SANDBOXING DETECTION"

Write-Host "Checking for virtualization and sandboxing...`n" -ForegroundColor Gray

# Check if running in VM
$computerSystem = Get-WmiObject -Class Win32_ComputerSystem
if ($computerSystem.Model -match 'Virtual|VMware|VirtualBox|Hyper-V|Xen|QEMU') {
    Write-Finding "Virtualization" "$($computerSystem.Model)" "Running in virtual environment"
}

# Check for Windows Sandbox
if ($computerSystem.Model -match 'Virtual Machine' -and (Test-Path "C:\ProgramData\Microsoft\Windows\Containers")) {
    Write-Finding "Sandbox" "Windows Sandbox" "May have restricted capabilities"
}

# Check for AppContainer
try {
    $token = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    if ($token.IsSystem) {
        Write-Finding "Context" "SYSTEM Account" "Running as NT AUTHORITY\SYSTEM"
    } elseif ($token.Name -match '\$') {
        Write-Finding "Context" "Machine Account" "Running as computer account"
    } else {
        Write-Finding "Context" "User Account" $token.Name
    }
} catch {
    Write-Host "[WARN] Could not determine execution context" -ForegroundColor Yellow
}

# ============================================================================
# 10. CHECK TAMPER PROTECTION
# ============================================================================
Write-Section "TAMPER PROTECTION STATUS"

Write-Host "Checking for tamper protection mechanisms...`n" -ForegroundColor Gray

# Windows Defender Tamper Protection
try {
    $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($defenderStatus) {
        if ($defenderStatus.IsTamperProtected) {
            Write-Test "Defender Tamper Protection" "ENABLED" "Security settings are protected"
        } else {
            Write-Test "Defender Tamper Protection" "DISABLED" "Security settings can be modified"
        }
    }
} catch {
    Write-Host "[INFO] Windows Defender status unavailable" -ForegroundColor Gray
}

# Check if we can modify security registry keys
$tamperTestKey = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features"
if (Test-Path $tamperTestKey) {
    try {
        $value = Get-ItemProperty -Path $tamperTestKey -Name "TamperProtection" -ErrorAction SilentlyContinue
        if ($value) {
            Write-Test "Tamper Protection Registry" "PROTECTED" "Cannot easily disable security features"
        }
    } catch {
        Write-Host "[INFO] Tamper protection registry check inconclusive" -ForegroundColor Gray
    }
}

# ============================================================================
# FINAL SUMMARY
# ============================================================================
Write-Section "DETECTION SUMMARY"

Write-Host ""
Write-Host "Security Products Found: " -NoNewline -ForegroundColor White
if ($securityProducts.Count -gt 0) {
    Write-Host "$($securityProducts.Count)" -ForegroundColor Yellow
    $securityProducts | ForEach-Object { Write-Host "  • $_" -ForegroundColor Yellow }
} else {
    Write-Host "None" -ForegroundColor Green
}

Write-Host "`nExecution Context:" -ForegroundColor White
Write-Host "  User: $env:USERNAME" -ForegroundColor Gray
Write-Host "  Computer: $env:COMPUTERNAME" -ForegroundColor Gray
Write-Host "  Admin Rights: $(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator))" -ForegroundColor Gray

Write-Host "`nKey Findings:" -ForegroundColor White
Write-Host "  • Registry operations may be monitored/blocked by EDR" -ForegroundColor $(if ($securityProducts.Count -gt 0) { "Yellow" } else { "Green" })
Write-Host "  • File system operations may be monitored/blocked by minifilters" -ForegroundColor $(if ($securityProducts.Count -gt 0) { "Yellow" } else { "Green" })
Write-Host "  • Process operations may be monitored/blocked by kernel drivers" -ForegroundColor $(if ($securityProducts.Count -gt 0) { "Yellow" } else { "Green" })

Write-Host "`nRecommendations:" -ForegroundColor White
if ($securityProducts -contains "SentinelOne") {
    Write-Host "  • SentinelOne detected: Expect registry/file protections" -ForegroundColor Cyan
    Write-Host "    - Use scheduled tasks as SYSTEM for stubborn operations" -ForegroundColor Gray
    Write-Host "    - Consider whitelisting scripts in SentinelOne console" -ForegroundColor Gray
}
if ($securityProducts -contains "CrowdStrike") {
    Write-Host "  • CrowdStrike detected: Advanced behavioral monitoring active" -ForegroundColor Cyan
    Write-Host "    - Avoid rapid file/registry operations" -ForegroundColor Gray
    Write-Host "    - Document legitimate administrative actions" -ForegroundColor Gray
}
if ($securityProducts -contains "Defender" -and $defenderStatus.IsTamperProtected) {
    Write-Host "  • Defender Tamper Protection: Cannot disable security features" -ForegroundColor Cyan
    Write-Host "    - Work within the security framework" -ForegroundColor Gray
}

Write-Host ""