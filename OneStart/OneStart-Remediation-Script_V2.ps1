# ============================================================================ #
# Malware Remediation Framework - OneStart.AI
# ============================================================================ #
# Author: sentinelrshuser
# Purpose: Centralized configuration for malware remediation
# Usage: Update the $MalwareConfig hashtable for new threats
# ============================================================================ #

#Requires -RunAsAdministrator

# ----------------------------------------------------------------------------
# LOGGING CONFIGURATION
# ----------------------------------------------------------------------------
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = Join-Path $env:TEMP "MalwareRemediation_$timestamp.log"

# ----------------------------------------------------------------------------
# MALWARE CONFIGURATION
# ----------------------------------------------------------------------------
$MalwareConfig = @{
    Name = "OneStart.AI"
    
    # Process names to terminate (without .exe extension)
    Processes = @(
        "OneStartService",
        "OneStartAutoLaunch",
        "OneStartCrashHandler",
        "OneStartUpdater",
        "OneStartBrowser",
        "OneStartNotification",
        "OneStartTray",
        "PDFEditor",
        "PDFEditorTray",
        "PDFEditorService",
        "PDFEditorUpdater",
        "UpdaterSetup"
    )
    
    # Service names to stop and remove
    Services = @(
        "OneStartService",
        "PDFEditorService"
    )
    
    # Scheduled task patterns
    TaskPatterns = @(
        "OneStartUser",
        "OneStartAutoLaunchTask*",
        "PDFEditorScheduledTask",
        "PDFEditorUScheduledTask",
        "sys_component_health_*"
    )
    
    # Registry value patterns to remove from Run keys
    RunKeyPatterns = @(
        "OneStart*",           # Catches: OneStart, OneStartUpdate, OneStartBar, etc.
        "OneStartChromium*",    # Specific entry (not caught by wildcard due to suffix)
        "OneStartUpdaterTaskUser*", # Has its own wildcard pattern
        "PDFEditor*"
    )
    
    # Registered applications patterns
    RegisteredAppPatterns = @(
        "OneStart*"
    )
    
    # User-specific paths (exact matches only)
    UserPaths = @(
        "C:\Users\{USER}\AppData\Local\OneStart.ai",
        "C:\Users\{USER}\OneStart.ai",
        "C:\Users\{USER}\Desktop\OneStart.lnk",
        "C:\Users\{USER}\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\OneStart.lnk",
        "C:\Users\{USER}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneStart.lnk",
        "C:\Users\{USER}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\PDF Editor.lnk",
        "C:\Users\{USER}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\OneStart*.lnk",
        "C:\Users\{USER}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\PDFEditor*.lnk",
        "C:\Users\{USER}\AppData\Roaming\NodeJs",
        "C:\Users\{USER}\AppData\Roaming\PDF Editor",
        "C:\Users\{USER}\AppData\Roaming\AP-2E99C4AA-3F56-48BB-A947-2EDA163E765F"
    )
    
    # Download folder patterns (specific to OneStart)
    DownloadPatterns = @(
        "OneStart*.exe",
        "*OneStart*.msi"
    )
    
    # System-level paths
    SystemPaths = @(
        "C:\WINDOWS\system32\config\systemprofile\AppData\Local\OneStart.ai",
        "C:\WINDOWS\system32\config\systemprofile\PDFEditor"
    )
    
    # Registry key patterns (HKLM) - for cleanup
    RegistryHKLM = @(
        "HKLM:\Software\WOW6432Node\Microsoft\Tracing\OneStart_RASAPI32",
        "HKLM:\Software\WOW6432Node\Microsoft\Tracing\OneStart_RASMANCS",
        "HKLM:\Software\Microsoft\MediaPlayer\ShimInclusionList\onestart.exe"
    )
    
    # Registry patterns for user hives (HKU) - for cleanup
    RegistryHKUPatterns = @(
        "Software\OneStart*",
        "Software\PDFEditor*",
        "Software\Clients\StartMenuInternet\OneStart*",
        "Software\Microsoft\Windows\CurrentVersion\Uninstall\*OneStart*",
        "Software\Classes\OneStart*",
        "Software\Classes\OSBHTML*",
        # COM Object Registrations (CLSID entries)
        "Software\Classes\CLSID\{4DAC24AB-B340-4B7E-AD01-1504A7F59EEA}", 
        "Software\Classes\CLSID\{75828ED1-7BE8-45D0-8950-AA85CBF74510}",
        "Software\Classes\CLSID\{A2C6CB58-C076-425C-ACB7-6D19D64428CD}",
        "Software\Classes\CLSID\{A45DDD96-C17C-50A3-BD69-8D064F864B24}",
        "Software\Classes\CLSID\{B5B6376D-5E59-5CB2-A34D-617C21A3A240}"
    )
    
    # Browser hijacking entries (specific patterns)
    BrowserStartMenuPatterns = @(
        "OneStart*"
    )

    # File association tracking patterns (ApplicationAssociationToasts)
    ApplicationAssociationPatterns = @(
        "OneStart*",
        "OSBHTML*",
        "PDFEditor*"
    )

    # Feature usage tracking patterns (AppBadgeUpdated, AppLaunch, etc.)
    FeatureUsagePatterns = @(
        "OneStart*",
        "PDFEditor*"
    )
}

# ----------------------------------------------------------------------------
# ENHANCED RESULTS TRACKING
# ----------------------------------------------------------------------------
$RemediationResults = @{
    # Detailed process tracking
    Processes = @{
        NotFound = @()
        Killed = @()
        Failed = @()
        Errored = @()
    }
    
    # Detailed service tracking
    Services = @{
        NotFound = @()
        Removed = @()
        Failed = @()
        Errored = @()
    }
    
    # Detailed task tracking
    Tasks = @{
        NotFound = @()
        Removed = @()
        Failed = @()
        Errored = @()
    }
    
    # Detailed TaskCache tracking
    TaskCache = @{
        NotFound = @()
        Removed = @()
        Failed = @()
        Errored = @()
    }

    # Detailed registry tracking
    Registry = @{
        NotFound = @()
        Removed = @()
        Failed = @()
        Errored = @()
    }
    
    # Detailed file/folder tracking
    Files = @{
        NotFound = @()
        Removed = @()
        Failed = @()
        Errored = @()
    }
    
    # Quick summary stats
    Summary = @{
        # Process stats
        ProcessesChecked = 0
        ProcessesFound = 0
        ProcessesKilled = 0
        ProcessesFailed = 0
        ProcessesErrored = 0
        ProcessesNotFound = 0
        
        # Service stats
        ServicesChecked = 0
        ServicesFound = 0
        ServicesRemoved = 0
        ServicesFailed = 0
        ServicesErrored = 0
        ServicesNotFound = 0
        
        # Task stats
        TasksChecked = 0
        TasksFound = 0
        TasksRemoved = 0
        TasksFailed = 0
        TasksErrored = 0
        TasksNotFound = 0

        # TaskCache stats
        TaskCacheChecked = 0
        TaskCacheFound = 0
        TaskCacheRemoved = 0
        TaskCacheFailed = 0
        TaskCacheErrored = 0
        TaskCacheNotFound = 0
        
        # Registry stats
        RegistryKeysChecked = 0
        RegistryValuesFound = 0
        RegistryValuesRemoved = 0
        RegistryValuesFailed = 0
        RegistryValuesErrored = 0
        RegistryValuesNotFound = 0
        
        # File/Folder stats
        PathsChecked = 0
        PathsFound = 0
        PathsRemoved = 0
        PathsFailed = 0
        PathsErrored = 0
        PathsNotFound = 0
    }
    
    # Global error log
    CriticalErrors = @()
    
    # Timing
    StartTime = Get-Date
    EndTime = $null
}

# ============================================================================ #
# HELPER FUNCTIONS
# ============================================================================ #

function Write-Log {
    <#
    .SYNOPSIS
    Writes timestamped log entries to file
    #>
    param(
        [string]$Message,
        [ValidateSet('INFO', 'SUCCESS', 'WARNING', 'ERROR')]
        [string]$Level = 'INFO'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    Add-Content -Path $logFile -Value $logMessage -ErrorAction SilentlyContinue
}

function New-ProcessRecord {
    <#
    .SYNOPSIS
    Creates a detailed process tracking record
    #>
    param(
        [string]$ProcessName,
        [string]$Status,
        [array]$PIDs = @(),
        [string]$ErrorMessage = $null,
        [object[]]$ProcessObjects = @()
    )
    
    $record = @{
        ProcessName = $ProcessName
        Status = $Status
        PIDs = $PIDs
        Timestamp = Get-Date
        ErrorMessage = $ErrorMessage
        Details = @()
    }
    
    # Capture detailed process info if available
    foreach ($proc in $ProcessObjects) {
        $record.Details += @{
            PID = $proc.Id
            StartTime = $proc.StartTime
            Path = $proc.Path
            CommandLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.Id)" -ErrorAction SilentlyContinue).CommandLine
            UserName = (Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.Id)" -ErrorAction SilentlyContinue).GetOwner().User
        }
    }
    
    return $record
}

function Get-ServiceDetails {
    <#
    .SYNOPSIS
    Captures detailed service information for tracking
    #>
    param(
        [Parameter(Mandatory=$true)]
        [object]$Service
    )
    
    try {
        $servicePath = (Get-CimInstance Win32_Service -Filter "Name='$($Service.Name)'" -ErrorAction SilentlyContinue).PathName
        
        return @{
            Name = $Service.Name
            DisplayName = $Service.DisplayName
            Status = $Service.Status
            StartType = $Service.StartType
            PathName = $servicePath
            CanStop = $Service.CanStop
        }
    } catch {
        return @{
            Name = $Service.Name
            DisplayName = "Unknown"
            Status = "Unknown"
            StartType = "Unknown"
            PathName = $null
            CanStop = $false
        }
    }
}

function New-ServiceRecord {
    <#
    .SYNOPSIS
    Creates a detailed service tracking record
    #>
    param(
        [string]$ServiceName,
        [string]$Status,
        [hashtable]$ServiceDetails = @{},
        [string]$ErrorMessage = $null,
        [string]$StopResult = $null,
        [string]$RemovalResult = $null
    )
    
    return @{
        ServiceName = $ServiceName
        Status = $Status
        DisplayName = $ServiceDetails.DisplayName
        InitialStatus = $ServiceDetails.Status
        InitialStartType = $ServiceDetails.StartType
        PathName = $ServiceDetails.PathName
        StopResult = $StopResult
        RemovalResult = $RemovalResult
        Timestamp = Get-Date
        ErrorMessage = $ErrorMessage
    }
}

function Get-TaskDetails {
    <#
    .SYNOPSIS
    Captures detailed task information for tracking
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$TaskName
    )
    
    try {
        $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
        
        return @{
            TaskName = $task.TaskName
            TaskPath = $task.TaskPath
            State = $task.State
            Enabled = ($task.State -ne 'Disabled')
            Actions = ($task.Actions | ForEach-Object { $_.Execute }) -join '; '
            Triggers = ($task.Triggers | ForEach-Object { $_.GetType().Name }) -join '; '
        }
    } catch {
        return @{
            TaskName = $TaskName
            TaskPath = "Unknown"
            State = "Unknown"
            Enabled = $false
            Actions = $null
            Triggers = $null
        }
    }
}

function New-TaskRecord {
    <#
    .SYNOPSIS
    Creates a detailed task tracking record
    #>
    param(
        [string]$TaskName,
        [string]$Status,
        [hashtable]$TaskDetails = @{},
        [string]$ErrorMessage = $null,
        [string]$RemovalResult = $null
    )
    
    return @{
        TaskName = $TaskName
        Status = $Status
        TaskPath = $TaskDetails.TaskPath
        InitialState = $TaskDetails.State
        Actions = $TaskDetails.Actions
        Triggers = $TaskDetails.Triggers
        RemovalResult = $RemovalResult
        Timestamp = Get-Date
        ErrorMessage = $ErrorMessage
    }
}

function New-TaskCacheRecord {
    <#
    .SYNOPSIS
    Creates a detailed TaskCache tracking record
    #>
    param(
        [string]$TaskName,
        [string]$GUID,
        [string]$CacheType,
        [string]$Status,
        [string]$ErrorMessage = $null
    )
    
    return @{
        TaskName = $TaskName
        GUID = $GUID
        CacheType = $CacheType
        Status = $Status
        Timestamp = Get-Date
        ErrorMessage = $ErrorMessage
    }
}

function New-RegistryRecord {
    <#
    .SYNOPSIS
    Creates a detailed registry tracking record (for values)
    #>
    param(
        [string]$KeyPath,
        [string]$ValueName,
        [string]$Status,
        [string]$ValueData = $null,
        [string]$ErrorMessage = $null
    )
    
    return @{
        KeyPath = $KeyPath
        ValueName = $ValueName
        ValueData = $ValueData
        Status = $Status
        Timestamp = Get-Date
        ErrorMessage = $ErrorMessage
    }
}

function New-RegistryKeyRecord {
    <#
    .SYNOPSIS
    Creates a detailed registry key tracking record (for full key removal)
    #>
    param(
        [string]$KeyPath,
        [string]$Status,
        [string]$ErrorMessage = $null,
        [int]$SubkeyCount = 0,
        [int]$ValueCount = 0
    )
    
    return @{
        KeyPath = $KeyPath
        SubkeyCount = $SubkeyCount
        ValueCount = $ValueCount
        Status = $Status
        Timestamp = Get-Date
        ErrorMessage = $ErrorMessage
    }
}

function Get-UserSIDs {
    <#
    .SYNOPSIS
    Retrieves all user SIDs from HKU hive
    #>
    try {
        $sidPattern = "S-1-5-21-\d+-\d+-\d+-\d+$"
        $sids = Get-ChildItem "Registry::HKU" -ErrorAction SilentlyContinue | 
            Where-Object { $_.PSChildName -match $sidPattern } |
            Select-Object -ExpandProperty PSChildName
        
        return $sids
    } catch {
        Write-Log "  [ERROR] Failed to enumerate user SIDs: $($_.Exception.Message)" -Level ERROR
        return @()
    }
}

function New-FileRecord {
    <#
    .SYNOPSIS
    Creates a detailed file/folder tracking record
    #>
    param(
        [string]$Path,
        [string]$Status,
        [string]$Type = "Unknown",
        [long]$Size = 0,
        [string]$ErrorMessage = $null
    )
    
    return @{
        Path = $Path
        Type = $Type
        Size = $Size
        Status = $Status
        Timestamp = Get-Date
        ErrorMessage = $ErrorMessage
    }
}

function Get-UserProfiles {
    <#
    .SYNOPSIS
    Retrieves all user profile directories
    #>
    try {
        $profiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notmatch '^(Public|Default|Default User|All Users)$' } |
            Select-Object -ExpandProperty Name
        
        return $profiles
    } catch {
        Write-Log "  [ERROR] Failed to enumerate user profiles: $($_.Exception.Message)" -Level ERROR
        return @()
    }
}

function New-BrowserRecord {
    <#
    .SYNOPSIS
    Creates a detailed browser entry tracking record
    #>
    param(
        [string]$EntryPath,
        [string]$EntryType,
        [string]$Status,
        [string]$ErrorMessage = $null
    )
    
    return @{
        EntryPath = $EntryPath
        EntryType = $EntryType
        Status = $Status
        Timestamp = Get-Date
        ErrorMessage = $ErrorMessage
    }
}

function Get-RegistryKeyDetails {
    <#
    .SYNOPSIS
    Captures registry key metadata before removal
    #>
    param(
        [string]$KeyPath
    )
    
    try {
        if (Test-Path $KeyPath) {
            $key = Get-Item $KeyPath -ErrorAction Stop
            $subkeys = Get-ChildItem $KeyPath -ErrorAction SilentlyContinue
            $values = Get-ItemProperty $KeyPath -ErrorAction SilentlyContinue
            
            return @{
                Exists = $true
                SubkeyCount = @($subkeys).Count
                ValueCount = ($values.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" }).Count
            }
        } else {
            return @{
                Exists = $false
                SubkeyCount = 0
                ValueCount = 0
            }
        }
    } catch {
        return @{
            Exists = $false
            SubkeyCount = 0
            ValueCount = 0
        }
    }
}

# ============================================================================ #
# PROCESS TERMINATION
# ============================================================================ #

function Stop-MalwareProcess {
    <#
    .SYNOPSIS
    Terminates processes with detailed tracking
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [array]$ProcessNames
    )
    
    Write-Log "========================================" -Level INFO
    Write-Log "PROCESS TERMINATION MODULE" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "Target processes: $($ProcessNames.Count)" -Level INFO
    
    foreach ($processName in $ProcessNames) {
        $RemediationResults.Summary.ProcessesChecked++
        
        Write-Log "Checking for process: $processName" -Level INFO
        
        $processes = Get-Process -Name $processName -ErrorAction SilentlyContinue
        
        if (-not $processes) {
            Write-Log "  [NOT FOUND] Process not running: $processName" -Level INFO
            
            $record = New-ProcessRecord -ProcessName $processName -Status "NOT_FOUND"
            $RemediationResults.Processes.NotFound += $record
            $RemediationResults.Summary.ProcessesNotFound++
            continue
        }
        
        $pidList = $processes.Id
        $RemediationResults.Summary.ProcessesFound++
        
        Write-Log "  [FOUND] Running instances: $($processes.Count) | PIDs: $($pidList -join ', ')" -Level WARNING
        
        try {
            $processes | Stop-Process -Force -ErrorAction Stop
            Start-Sleep -Milliseconds 500
            
            $stillRunning = Get-Process -Name $processName -ErrorAction SilentlyContinue
            
            if (-not $stillRunning) {
                Write-Log "  [SUCCESS] Terminated: $processName (PIDs: $($pidList -join ', '))" -Level SUCCESS
                
                $record = New-ProcessRecord -ProcessName $processName -Status "KILLED" `
                    -PIDs $pidList -ProcessObjects $processes
                $RemediationResults.Processes.Killed += $record
                $RemediationResults.Summary.ProcessesKilled++
                
            } else {
                $survivingPIDs = $stillRunning.Id
                Write-Log "  [FAILED] Still running: $processName (PIDs: $($survivingPIDs -join ', '))" -Level ERROR
                
                $record = New-ProcessRecord -ProcessName $processName -Status "FAILED" `
                    -PIDs $survivingPIDs -ProcessObjects $stillRunning `
                    -ErrorMessage "Process survived termination attempt"
                $RemediationResults.Processes.Failed += $record
                $RemediationResults.Summary.ProcessesFailed++
            }
            
        } catch {
            $errorMsg = $_.Exception.Message
            Write-Log "  [ERROR] Exception during termination: $processName - $errorMsg" -Level ERROR
            
            $record = New-ProcessRecord -ProcessName $processName -Status "ERROR" `
                -PIDs $pidList -ProcessObjects $processes -ErrorMessage $errorMsg
            $RemediationResults.Processes.Errored += $record
            $RemediationResults.Summary.ProcessesErrored++
            
            $RemediationResults.CriticalErrors += "Process: $processName - $errorMsg"
        }
    }
    
    Write-Log "========================================" -Level INFO
    Write-Log "PROCESS TERMINATION SUMMARY" -Level INFO
    Write-Log "  Checked: $($RemediationResults.Summary.ProcessesChecked)" -Level INFO
    Write-Log "  Found: $($RemediationResults.Summary.ProcessesFound)" -Level INFO
    Write-Log "  Killed: $($RemediationResults.Summary.ProcessesKilled)" -Level SUCCESS
    Write-Log "  Failed: $($RemediationResults.Summary.ProcessesFailed)" -Level ERROR
    Write-Log "  Errored: $($RemediationResults.Summary.ProcessesErrored)" -Level ERROR
    Write-Log "  Not Found: $($RemediationResults.Summary.ProcessesNotFound)" -Level INFO
    Write-Log "========================================" -Level INFO
}

# ============================================================================ #
# SERVICE REMEDIATION
# ============================================================================ #

function Stop-MalwareService {
    <#
    .SYNOPSIS
    Stops and removes malicious services with detailed tracking
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [array]$ServiceNames
    )
    
    Write-Log "========================================" -Level INFO
    Write-Log "SERVICE REMEDIATION MODULE" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "Target services: $($ServiceNames.Count)" -Level INFO
    
    foreach ($serviceName in $ServiceNames) {
        $RemediationResults.Summary.ServicesChecked++
        
        Write-Log "Checking for service: $serviceName" -Level INFO
        
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        
        if (-not $service) {
            Write-Log "  [NOT FOUND] Service does not exist: $serviceName" -Level INFO
            
            $record = New-ServiceRecord -ServiceName $serviceName -Status "NOT_FOUND"
            $RemediationResults.Services.NotFound += $record
            $RemediationResults.Summary.ServicesNotFound++
            continue
        }
        
        $RemediationResults.Summary.ServicesFound++
        $serviceDetails = Get-ServiceDetails -Service $service
        
        Write-Log "  [FOUND] Service exists" -Level WARNING
        Write-Log "    Display Name: $($serviceDetails.DisplayName)" -Level INFO
        Write-Log "    Status: $($serviceDetails.Status)" -Level INFO
        Write-Log "    Start Type: $($serviceDetails.StartType)" -Level INFO
        Write-Log "    Path: $($serviceDetails.PathName)" -Level INFO
        
        $stopResult = "NOT_ATTEMPTED"
        $removalResult = "NOT_ATTEMPTED"
        $overallSuccess = $true
        
        if ($service.Status -eq 'Running') {
            Write-Log "  [STOPPING] Attempting to stop service..." -Level INFO
            
            try {
                Stop-Service -Name $serviceName -Force -ErrorAction Stop
                Start-Sleep -Milliseconds 500
                
                $serviceCheck = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
                if ($serviceCheck.Status -eq 'Stopped') {
                    Write-Log "  [SUCCESS] Service stopped" -Level SUCCESS
                    $stopResult = "SUCCESS"
                } else {
                    Write-Log "  [FAILED] Service still running" -Level ERROR
                    $stopResult = "FAILED"
                    $overallSuccess = $false
                }
            } catch {
                Write-Log "  [ERROR] Failed to stop service: $($_.Exception.Message)" -Level ERROR
                $stopResult = "ERROR"
                $overallSuccess = $false
            }
        } else {
            Write-Log "  [SKIPPED] Service not running (Status: $($service.Status))" -Level INFO
            $stopResult = "NOT_RUNNING"
        }
        
        Write-Log "  [REMOVING] Attempting to delete service..." -Level INFO
        
        try {
            $null = & sc.exe delete $serviceName 2>&1
            Start-Sleep -Milliseconds 500
            
            $serviceCheck = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if (-not $serviceCheck) {
                Write-Log "  [SUCCESS] Service deleted" -Level SUCCESS
                $removalResult = "SUCCESS"
            } else {
                Write-Log "  [FAILED] Service still exists after deletion" -Level ERROR
                $removalResult = "FAILED"
                $overallSuccess = $false
            }
        } catch {
            Write-Log "  [ERROR] Failed to delete service: $($_.Exception.Message)" -Level ERROR
            $removalResult = "ERROR"
            $overallSuccess = $false
        }
        
        if ($overallSuccess -and $removalResult -eq "SUCCESS") {
            Write-Log "  [COMPLETE] Service stopped and removed: $serviceName" -Level SUCCESS
            
            $record = New-ServiceRecord -ServiceName $serviceName -Status "REMOVED" `
                -ServiceDetails $serviceDetails -StopResult $stopResult -RemovalResult $removalResult
            $RemediationResults.Services.Removed += $record
            $RemediationResults.Summary.ServicesRemoved++
            
        } elseif ($removalResult -eq "FAILED" -or $stopResult -eq "FAILED") {
            Write-Log "  [FAILED] Service remediation incomplete: $serviceName" -Level ERROR
            
            $record = New-ServiceRecord -ServiceName $serviceName -Status "FAILED" `
                -ServiceDetails $serviceDetails -StopResult $stopResult -RemovalResult $removalResult `
                -ErrorMessage "Stop: $stopResult | Removal: $removalResult"
            $RemediationResults.Services.Failed += $record
            $RemediationResults.Summary.ServicesFailed++
            
        } else {
            Write-Log "  [ERROR] Service remediation error: $serviceName" -Level ERROR
            
            $record = New-ServiceRecord -ServiceName $serviceName -Status "ERROR" `
                -ServiceDetails $serviceDetails -StopResult $stopResult -RemovalResult $removalResult `
                -ErrorMessage "Stop: $stopResult | Removal: $removalResult"
            $RemediationResults.Services.Errored += $record
            $RemediationResults.Summary.ServicesErrored++
            
            $RemediationResults.CriticalErrors += "Service: $serviceName - Stop: $stopResult | Removal: $removalResult"
        }
    }
    
    Write-Log "========================================" -Level INFO
    Write-Log "SERVICE REMEDIATION SUMMARY" -Level INFO
    Write-Log "  Checked: $($RemediationResults.Summary.ServicesChecked)" -Level INFO
    Write-Log "  Found: $($RemediationResults.Summary.ServicesFound)" -Level INFO
    Write-Log "  Removed: $($RemediationResults.Summary.ServicesRemoved)" -Level SUCCESS
    Write-Log "  Failed: $($RemediationResults.Summary.ServicesFailed)" -Level ERROR
    Write-Log "  Errored: $($RemediationResults.Summary.ServicesErrored)" -Level ERROR
    Write-Log "  Not Found: $($RemediationResults.Summary.ServicesNotFound)" -Level INFO
    Write-Log "========================================" -Level INFO
}

# ============================================================================ #
# SCHEDULED TASK REMEDIATION
# ============================================================================ #

function Remove-MalwareTask {
    param(
        [Parameter(Mandatory=$true)]
        [array]$TaskPatterns
    )
    
    Write-Log "========================================" -Level INFO
    Write-Log "SCHEDULED TASK REMEDIATION MODULE" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "Target task patterns: $($TaskPatterns.Count)" -Level INFO
    
    # Track all successfully removed task names for Phase 2
    $removedTaskNames = @()

# ========================================================================
# PHASE 1: Task Detection and Removal
# ========================================================================
    
    foreach ($pattern in $TaskPatterns) {
        $RemediationResults.Summary.TasksChecked++
        
        Write-Log "Checking for task pattern: $pattern" -Level INFO
        
        $matchingTasks = @()
        try {
            $allTasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
                $_.TaskName -like $pattern -or $_.TaskPath -like "*$pattern*"
            }
            $matchingTasks = @($allTasks)
        } catch {
            Write-Log "  [WARNING] Error searching for tasks: $($_.Exception.Message)" -Level WARNING
        }
        
        if ($matchingTasks.Count -eq 0) {
            Write-Log "  [NOT FOUND] No tasks match pattern: $pattern" -Level INFO
            
            $record = New-TaskRecord -TaskName $pattern -Status "NOT_FOUND"
            $RemediationResults.Tasks.NotFound += $record
            $RemediationResults.Summary.TasksNotFound++
            continue
        }
        
        Write-Log "  [FOUND] $($matchingTasks.Count) task(s) match pattern: $pattern" -Level WARNING
        
        foreach ($task in $matchingTasks) {
            $taskName = $task.TaskName
            $taskPath = $task.TaskPath
            $RemediationResults.Summary.TasksFound++
            
            $taskDetails = Get-TaskDetails -TaskName $taskName
            
            Write-Log "    Task: $taskPath$taskName" -Level INFO
            Write-Log "      State: $($taskDetails.State)" -Level INFO
            Write-Log "      Actions: $($taskDetails.Actions)" -Level INFO
            
            $removalResult = "NOT_ATTEMPTED"
            $overallSuccess = $true
            
            Write-Log "    [REMOVING] Attempting to unregister task..." -Level INFO
            
            try {
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
                Start-Sleep -Milliseconds 500
                
                $taskCheck = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
                if (-not $taskCheck) {
                    Write-Log "    [SUCCESS] Task unregistered" -Level SUCCESS
                    $removalResult = "SUCCESS"
                } else {
                    Write-Log "    [FAILED] Task still exists" -Level ERROR
                    $removalResult = "FAILED"
                    $overallSuccess = $false
                }
            } catch {
                Write-Log "    [ERROR] Failed to unregister: $($_.Exception.Message)" -Level ERROR
                $removalResult = "ERROR"
                $overallSuccess = $false
            }
            
            if ($overallSuccess -and $removalResult -eq "SUCCESS") {
                Write-Log "    [COMPLETE] Task removed: $taskName" -Level SUCCESS
                
                $record = New-TaskRecord -TaskName $taskName -Status "REMOVED" `
                    -TaskDetails $taskDetails -RemovalResult $removalResult
                $RemediationResults.Tasks.Removed += $record
                $RemediationResults.Summary.TasksRemoved++
                
                # Track successfully removed tasks for Phase 2
                $removedTaskNames += $taskName
                
            } elseif ($removalResult -eq "FAILED") {
                Write-Log "    [FAILED] Task removal incomplete: $taskName" -Level ERROR
                
                $record = New-TaskRecord -TaskName $taskName -Status "FAILED" `
                    -TaskDetails $taskDetails -RemovalResult $removalResult `
                    -ErrorMessage "Task still exists after removal"
                $RemediationResults.Tasks.Failed += $record
                $RemediationResults.Summary.TasksFailed++
                
            } else {
                Write-Log "    [ERROR] Task removal error: $taskName" -Level ERROR
                
                $record = New-TaskRecord -TaskName $taskName -Status "ERROR" `
                    -TaskDetails $taskDetails -RemovalResult $removalResult `
                    -ErrorMessage "Removal: $removalResult"
                $RemediationResults.Tasks.Errored += $record
                $RemediationResults.Summary.TasksErrored++
                
                $RemediationResults.CriticalErrors += "Task: $taskName - Removal: $removalResult"
            }
        }  # <-- INNER LOOP ENDS HERE (foreach $task)
    }  # <-- OUTER LOOP ENDS HERE (foreach $pattern)
    
    # ========================================================================
    # PHASE 2: TaskCache Cleanup
    # ========================================================================
    
    if ($removedTaskNames.Count -gt 0) {
        Remove-TaskCacheOrphans -TaskNames $removedTaskNames
    }
        
Write-Log "========================================" -Level INFO
Write-Log "SCHEDULED TASK REMEDIATION SUMMARY" -Level INFO
Write-Log "  Checked: $($RemediationResults.Summary.TasksChecked)" -Level INFO
Write-Log "  Found: $($RemediationResults.Summary.TasksFound)" -Level INFO
Write-Log "  Removed: $($RemediationResults.Summary.TasksRemoved)" -Level SUCCESS
Write-Log "  Failed: $($RemediationResults.Summary.TasksFailed)" -Level ERROR
Write-Log "  Errored: $($RemediationResults.Summary.TasksErrored)" -Level ERROR
Write-Log "  Not Found: $($RemediationResults.Summary.TasksNotFound)" -Level INFO
Write-Log "  ---" -Level INFO
Write-Log "  TaskCache Checked: $($RemediationResults.Summary.TaskCacheChecked)" -Level INFO
Write-Log "  TaskCache Removed: $($RemediationResults.Summary.TaskCacheRemoved)" -Level SUCCESS
Write-Log "  TaskCache Failed: $($RemediationResults.Summary.TaskCacheFailed)" -Level ERROR
Write-Log "========================================" -Level INFO
}

function Remove-TaskCacheOrphans {
    <#
    .SYNOPSIS
    Removes orphaned TaskCache registry entries
    .DESCRIPTION
    Cleans up TaskCache registry entries that may remain after task removal.
    Uses .NET Registry class for direct access.
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [array]$TaskNames
    )
    
    Write-Log "  [TASKCACHE] Checking for orphaned TaskCache entries..." -Level INFO
    
    $baseKeyPath = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache"
    
    foreach ($taskName in $TaskNames) {
        $RemediationResults.Summary.TaskCacheChecked++
        
        Write-Log "    Checking TaskCache for: $taskName" -Level INFO
        
        try {
            $treePath = "$baseKeyPath\Tree\$taskName"
            $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($treePath, $false)
            
            if (-not $regKey) {
                Write-Log "      [NOT FOUND] No TaskCache entry" -Level INFO
                
                $record = New-TaskCacheRecord -TaskName $taskName -GUID "N/A" `
                    -CacheType "Tree" -Status "NOT_FOUND"
                $RemediationResults.TaskCache.NotFound += $record
                $RemediationResults.Summary.TaskCacheNotFound++
                continue
            }
            
            $RemediationResults.Summary.TaskCacheFound++
            
            $taskId = $null
            try {
                $taskId = $regKey.GetValue("Id")
            } catch {}
            $regKey.Close()
            
            $guidString = if ($taskId) { "{$taskId}" } else { "UNKNOWN" }
            Write-Log "      [FOUND] GUID: $guidString" -Level WARNING
            
            $removalSuccess = $true
            $removedCount = 0
            
            if ($taskId) {
                $relatedSubKeys = @(
                    @{Path = "$baseKeyPath\Tasks\$guidString"; Type = "Tasks"},
                    @{Path = "$baseKeyPath\Plain\$guidString"; Type = "Plain"},
                    @{Path = "$baseKeyPath\Boot\$guidString"; Type = "Boot"},
                    @{Path = "$baseKeyPath\Logon\$guidString"; Type = "Logon"}
                )
                
                foreach ($subKey in $relatedSubKeys) {
                    try {
                        [Microsoft.Win32.Registry]::LocalMachine.DeleteSubKeyTree($subKey.Path, $false)
                        Write-Log "        [SUCCESS] Removed $($subKey.Type) entry" -Level SUCCESS
                        $removedCount++
                        
                        $record = New-TaskCacheRecord -TaskName $taskName -GUID $guidString `
                            -CacheType $subKey.Type -Status "REMOVED"
                        $RemediationResults.TaskCache.Removed += $record
                        $RemediationResults.Summary.TaskCacheRemoved++
                    } catch {
                        if ($_.Exception.Message -notlike "*cannot find*") {
                            Write-Log "        [WARNING] $($subKey.Type) entry: $($_.Exception.Message)" -Level WARNING
                        }
                    }
                }
            }
            
            try {
                [Microsoft.Win32.Registry]::LocalMachine.DeleteSubKeyTree($treePath, $false)
                Write-Log "        [SUCCESS] Removed Tree entry" -Level SUCCESS
                $removedCount++
                
                $record = New-TaskCacheRecord -TaskName $taskName -GUID $guidString `
                    -CacheType "Tree" -Status "REMOVED"
                $RemediationResults.TaskCache.Removed += $record
                $RemediationResults.Summary.TaskCacheRemoved++
            } catch {
                Write-Log "        [FAILED] Tree entry: $($_.Exception.Message)" -Level ERROR
                
                $record = New-TaskCacheRecord -TaskName $taskName -GUID $guidString `
                    -CacheType "Tree" -Status "FAILED" -ErrorMessage $_.Exception.Message
                $RemediationResults.TaskCache.Failed += $record
                $RemediationResults.Summary.TaskCacheFailed++
                $removalSuccess = $false
            }
            
            if ($removalSuccess) {
                Write-Log "      [COMPLETE] TaskCache cleaned: $removedCount entries" -Level SUCCESS
            } else {
                Write-Log "      [PARTIAL] Some entries could not be removed" -Level WARNING
            }
            
        } catch {
            Write-Log "      [ERROR] TaskCache access failed: $($_.Exception.Message)" -Level ERROR
            
            $record = New-TaskCacheRecord -TaskName $taskName -GUID "ERROR" `
                -CacheType "Unknown" -Status "ERROR" -ErrorMessage $_.Exception.Message
            $RemediationResults.TaskCache.Errored += $record
            $RemediationResults.Summary.TaskCacheErrored++
        }
    }

    # TaskCache cleanup summary
    Write-Log "  [TASKCACHE] Cleanup complete:" -Level INFO
    Write-Log "    Checked: $($RemediationResults.Summary.TaskCacheChecked)" -Level INFO
    Write-Log "    Removed: $($RemediationResults.Summary.TaskCacheRemoved)" -Level SUCCESS
    Write-Log "    Failed: $($RemediationResults.Summary.TaskCacheFailed)" -Level ERROR
}

# ============================================================================ #
# REGISTRY PERSISTENCE REMOVAL
# ============================================================================ #

function Remove-RegistryValueByPattern {
    <#
    .SYNOPSIS
    Removes registry values matching patterns from a specific key
    #>
    param(
        [string]$KeyPath,
        [array]$ValuePatterns
    )
    
    $removedCount = 0
    
    if (-not (Test-Path $KeyPath)) {
        return $removedCount
    }
    
    try {
        $keyProperties = Get-ItemProperty -Path $KeyPath -ErrorAction Stop
        
        foreach ($pattern in $ValuePatterns) {
            $matchingValues = $keyProperties.PSObject.Properties | 
                Where-Object { $_.Name -like $pattern -and $_.Name -notlike "PS*" }
            
            foreach ($value in $matchingValues) {
                $valueName = $value.Name
                $valueData = $value.Value
                
                $RemediationResults.Summary.RegistryValuesFound++
                Write-Log "    [FOUND] $KeyPath\$valueName = $valueData" -Level WARNING
                
                try {
                    Remove-ItemProperty -Path $KeyPath -Name $valueName -ErrorAction Stop
                    
                    $checkValue = Get-ItemProperty -Path $KeyPath -Name $valueName -ErrorAction SilentlyContinue
                    if (-not $checkValue) {
                        Write-Log "    [SUCCESS] Removed: $valueName" -Level SUCCESS
                        
                        $record = New-RegistryRecord -KeyPath $KeyPath -ValueName $valueName `
                            -Status "REMOVED" -ValueData $valueData
                        $RemediationResults.Registry.Removed += $record
                        $RemediationResults.Summary.RegistryValuesRemoved++
                        $removedCount++
                    } else {
                        Write-Log "    [FAILED] Still exists: $valueName" -Level ERROR
                        
                        $record = New-RegistryRecord -KeyPath $KeyPath -ValueName $valueName `
                            -Status "FAILED" -ValueData $valueData -ErrorMessage "Value still exists after removal"
                        $RemediationResults.Registry.Failed += $record
                        $RemediationResults.Summary.RegistryValuesFailed++
                    }
                } catch {
                    Write-Log "    [ERROR] Failed to remove $valueName : $($_.Exception.Message)" -Level ERROR
                    
                    $record = New-RegistryRecord -KeyPath $KeyPath -ValueName $valueName `
                        -Status "ERROR" -ValueData $valueData -ErrorMessage $_.Exception.Message
                    $RemediationResults.Registry.Errored += $record
                    $RemediationResults.Summary.RegistryValuesErrored++
                }
            }
        }
    } catch {
        Write-Log "    [ERROR] Cannot access key: $($_.Exception.Message)" -Level ERROR
    }
    
    return $removedCount
}

function Remove-MalwareRegistryPersistence {
    <#
    .SYNOPSIS
    Removes malware persistence from registry Run keys and RegisteredApplications
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [array]$RunKeyPatterns,
        
        [Parameter(Mandatory=$true)]
        [array]$RegisteredAppPatterns,

        [Parameter(Mandatory=$false)]
        [array]$FeatureUsagePatterns = @()
    )
    
    Write-Log "========================================" -Level INFO
    Write-Log "REGISTRY PERSISTENCE REMOVAL MODULE" -Level INFO
    Write-Log "========================================" -Level INFO
    
    $totalRemoved = 0
    
    Write-Log "Phase 1: Checking HKLM Run keys..." -Level INFO
    $RemediationResults.Summary.RegistryKeysChecked++
    
    $hklmRunKeys = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    
    foreach ($keyPath in $hklmRunKeys) {
        Write-Log "  Checking: $keyPath" -Level INFO
        $removed = Remove-RegistryValueByPattern -KeyPath $keyPath -ValuePatterns $RunKeyPatterns
        $totalRemoved += $removed
    }
    
    Write-Log "Phase 2: Checking per-user Run keys..." -Level INFO
    
    $userSIDs = Get-UserSIDs
    Write-Log "  Found $($userSIDs.Count) user profile(s)" -Level INFO
    
    foreach ($sid in $userSIDs) {
        Write-Log "  Processing SID: $sid" -Level INFO
        $RemediationResults.Summary.RegistryKeysChecked++
        
        $hkuRunKeys = @(
            "Registry::HKU\$sid\Software\Microsoft\Windows\CurrentVersion\Run",
            "Registry::HKU\$sid\Software\Microsoft\Windows\CurrentVersion\RunOnce"
        )
        
        foreach ($keyPath in $hkuRunKeys) {
            $removed = Remove-RegistryValueByPattern -KeyPath $keyPath -ValuePatterns $RunKeyPatterns
            $totalRemoved += $removed
        }
    }
    
    Write-Log "Phase 3: Checking RegisteredApplications..." -Level INFO
    
    $hklmRegApps = "HKLM:\Software\RegisteredApplications"
    Write-Log "  Checking: $hklmRegApps" -Level INFO
    $RemediationResults.Summary.RegistryKeysChecked++
    $removed = Remove-RegistryValueByPattern -KeyPath $hklmRegApps -ValuePatterns $RegisteredAppPatterns
    $totalRemoved += $removed
    
    foreach ($sid in $userSIDs) {
        $hkuRegApps = "Registry::HKU\$sid\Software\RegisteredApplications"
        $RemediationResults.Summary.RegistryKeysChecked++
        $removed = Remove-RegistryValueByPattern -KeyPath $hkuRegApps -ValuePatterns $RegisteredAppPatterns
        $totalRemoved += $removed
    }
    Write-Log "Phase 4: Feature Usage Tracking" -Level INFO

    if ($FeatureUsagePatterns.Count -gt 0) {
        Write-Log "Phase 4: Checking Explorer Feature Usage..." -Level INFO
        
        $userSIDs = Get-UserSIDs
        foreach ($sid in $userSIDs) {
            $featureUsagePaths = @(
                "Registry::HKU\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppBadgeUpdated",
                "Registry::HKU\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppLaunch"
            )
            
            foreach ($keyPath in $featureUsagePaths) {
                if (Test-Path $keyPath) {
                    $removed = Remove-RegistryValueByPattern -KeyPath $keyPath -ValuePatterns $FeatureUsagePatterns
                    $totalRemoved += $removed
                }
            }
        }
    }
    
    Write-Log "========================================" -Level INFO
    Write-Log "REGISTRY PERSISTENCE REMOVAL SUMMARY" -Level INFO
    Write-Log "  Keys Checked: $($RemediationResults.Summary.RegistryKeysChecked)" -Level INFO
    Write-Log "  Values Found: $($RemediationResults.Summary.RegistryValuesFound)" -Level INFO
    Write-Log "  Values Removed: $($RemediationResults.Summary.RegistryValuesRemoved)" -Level SUCCESS
    Write-Log "  Values Failed: $($RemediationResults.Summary.RegistryValuesFailed)" -Level ERROR
    Write-Log "  Values Errored: $($RemediationResults.Summary.RegistryValuesErrored)" -Level ERROR
    Write-Log "========================================" -Level INFO
}


# ============================================================================ #
# FILE & FOLDER CLEANUP
# ============================================================================ #

function Remove-PathItem {
    <#
    .SYNOPSIS
    Removes a file or folder with detailed tracking
    #>
    param(
        [string]$Path
    )
    
    if (-not (Test-Path $Path)) {
        return "NOT_FOUND"
    }
    
    try {
        $item = Get-Item $Path -Force -ErrorAction Stop
        $itemType = if ($item.PSIsContainer) { "Folder" } else { "File" }
        $itemSize = if ($item.PSIsContainer) { 
            (Get-ChildItem $Path -Recurse -Force -ErrorAction SilentlyContinue | 
                Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum 
        } else { 
            $item.Length 
        }
        
        $RemediationResults.Summary.PathsFound++
        Write-Log "    [FOUND] $itemType : $Path ($([math]::Round($itemSize/1KB, 2)) KB)" -Level WARNING
        
        Remove-Item $Path -Recurse -Force -ErrorAction Stop
        Start-Sleep -Milliseconds 200
        
        if (-not (Test-Path $Path)) {
            Write-Log "    [SUCCESS] Removed: $Path" -Level SUCCESS
            
            $record = New-FileRecord -Path $Path -Status "REMOVED" -Type $itemType -Size $itemSize
            $RemediationResults.Files.Removed += $record
            $RemediationResults.Summary.PathsRemoved++
            return "SUCCESS"
        } else {
            Write-Log "    [FAILED] Still exists: $Path" -Level ERROR
            
            $record = New-FileRecord -Path $Path -Status "FAILED" -Type $itemType -Size $itemSize `
                -ErrorMessage "Item still exists after removal attempt"
            $RemediationResults.Files.Failed += $record
            $RemediationResults.Summary.PathsFailed++
            return "FAILED"
        }
    } catch {
        Write-Log "    [ERROR] Failed to remove $Path : $($_.Exception.Message)" -Level ERROR
        
        $record = New-FileRecord -Path $Path -Status "ERROR" -ErrorMessage $_.Exception.Message
        $RemediationResults.Files.Errored += $record
        $RemediationResults.Summary.PathsErrored++
        
        $RemediationResults.CriticalErrors += "File: $Path - $($_.Exception.Message)"
        return "ERROR"
    }
}

function Remove-MalwareFiles {
    <#
    .SYNOPSIS
    Removes malware files and folders
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [array]$UserPaths,
        
        [Parameter(Mandatory=$true)]
        [array]$DownloadPatterns,
        
        [Parameter(Mandatory=$true)]
        [array]$SystemPaths
    )
    
    Write-Log "========================================" -Level INFO
    Write-Log "FILE & FOLDER CLEANUP MODULE" -Level INFO
    Write-Log "========================================" -Level INFO
    
    Write-Log "Phase 1: Removing user-specific paths..." -Level INFO
    
    $userProfiles = Get-UserProfiles
    Write-Log "  Found $($userProfiles.Count) user profile(s)" -Level INFO
    
    foreach ($user in $userProfiles) {
        Write-Log "  Processing user: $user" -Level INFO
        
        foreach ($pathTemplate in $UserPaths) {
            $RemediationResults.Summary.PathsChecked++
            
            $actualPath = $pathTemplate -replace '\{USER\}', $user
            
            $result = Remove-PathItem -Path $actualPath
            
            if ($result -eq "NOT_FOUND") {
                $record = New-FileRecord -Path $actualPath -Status "NOT_FOUND"
                $RemediationResults.Files.NotFound += $record
                $RemediationResults.Summary.PathsNotFound++
            }
        }
    }
    
    Write-Log "Phase 2: Cleaning Downloads folder..." -Level INFO
    
    foreach ($user in $userProfiles) {
        $downloadsPath = "C:\Users\$user\Downloads"
        
        if (-not (Test-Path $downloadsPath)) {
            continue
        }
        
        Write-Log "  Scanning: $downloadsPath" -Level INFO
        
        foreach ($pattern in $DownloadPatterns) {
            $files = Get-ChildItem $downloadsPath -Filter $pattern -File -Recurse -Force -ErrorAction SilentlyContinue
            
            foreach ($file in $files) {
                $RemediationResults.Summary.PathsChecked++
                $result = Remove-PathItem -Path $file.FullName
                
                if ($result -eq "NOT_FOUND") {
                    $record = New-FileRecord -Path $file.FullName -Status "NOT_FOUND"
                    $RemediationResults.Files.NotFound += $record
                    $RemediationResults.Summary.PathsNotFound++
                }
            }
        }
    }
    
    Write-Log "Phase 3: Removing system-level paths..." -Level INFO
    
    foreach ($path in $SystemPaths) {
        $RemediationResults.Summary.PathsChecked++
        
        if ($path -match '\*') {
            $parentPath = Split-Path $path -Parent
            $pattern = Split-Path $path -Leaf
            
            if (Test-Path $parentPath) {
                $items = Get-ChildItem $parentPath -Filter $pattern -Force -ErrorAction SilentlyContinue
                
                foreach ($item in $items) {
                    $result = Remove-PathItem -Path $item.FullName
                    
                    if ($result -eq "NOT_FOUND") {
                        $record = New-FileRecord -Path $item.FullName -Status "NOT_FOUND"
                        $RemediationResults.Files.NotFound += $record
                        $RemediationResults.Summary.PathsNotFound++
                    }
                }
            }
        } else {
            $result = Remove-PathItem -Path $path
            
            if ($result -eq "NOT_FOUND") {
                $record = New-FileRecord -Path $path -Status "NOT_FOUND"
                $RemediationResults.Files.NotFound += $record
                $RemediationResults.Summary.PathsNotFound++
            }
        }
    }
    
    Write-Log "========================================" -Level INFO
    Write-Log "FILE & FOLDER CLEANUP SUMMARY" -Level INFO
    Write-Log "  Paths Checked: $($RemediationResults.Summary.PathsChecked)" -Level INFO
    Write-Log "  Paths Found: $($RemediationResults.Summary.PathsFound)" -Level INFO
    Write-Log "  Paths Removed: $($RemediationResults.Summary.PathsRemoved)" -Level SUCCESS
    Write-Log "  Paths Failed: $($RemediationResults.Summary.PathsFailed)" -Level ERROR
    Write-Log "  Paths Errored: $($RemediationResults.Summary.PathsErrored)" -Level ERROR
    Write-Log "  Paths Not Found: $($RemediationResults.Summary.PathsNotFound)" -Level INFO
    Write-Log "========================================" -Level INFO
}

# ============================================================================ #
# REGISTRY CLEANUP (ARTIFACTS & CONFIGURATION)
# ============================================================================ #

function Remove-RegistryKeyRecursive {
    <#
    .SYNOPSIS
    Removes a registry key and all subkeys with detailed tracking
    #>
    param(
        [string]$KeyPath
    )
    
    $RemediationResults.Summary.RegistryKeysChecked++
    
    Write-Log "  Checking: $KeyPath" -Level INFO
    
    $keyDetails = Get-RegistryKeyDetails -KeyPath $KeyPath
    
    if (-not $keyDetails.Exists) {
        Write-Log "    [NOT FOUND] Key does not exist" -Level INFO
        
        $record = New-RegistryKeyRecord -KeyPath $KeyPath -Status "NOT_FOUND"
        $RemediationResults.Registry.NotFound += $record
        return "NOT_FOUND"
    }
    
    Write-Log "    [FOUND] Subkeys: $($keyDetails.SubkeyCount) | Values: $($keyDetails.ValueCount)" -Level WARNING
    
    try {
        Remove-Item -Path $KeyPath -Recurse -Force -ErrorAction Stop
        Start-Sleep -Milliseconds 200
        
        if (-not (Test-Path $KeyPath)) {
            Write-Log "    [SUCCESS] Key removed" -Level SUCCESS
            
            $record = New-RegistryKeyRecord -KeyPath $KeyPath -Status "REMOVED" `
                -SubkeyCount $keyDetails.SubkeyCount -ValueCount $keyDetails.ValueCount
            $RemediationResults.Registry.Removed += $record
            $RemediationResults.Summary.RegistryValuesRemoved++
            return "SUCCESS"
            
        } else {
            Write-Log "    [FAILED] Key still exists (may be kernel protected)" -Level ERROR
            
            $record = New-RegistryKeyRecord -KeyPath $KeyPath -Status "FAILED" `
                -SubkeyCount $keyDetails.SubkeyCount -ValueCount $keyDetails.ValueCount `
                -ErrorMessage "Key still exists after removal (possible kernel protection)"
            $RemediationResults.Registry.Failed += $record
            $RemediationResults.Summary.RegistryValuesFailed++
            return "FAILED"
        }
        
    } catch {
        $errorMsg = $_.Exception.Message
        Write-Log "    [ERROR] Failed to remove: $errorMsg" -Level ERROR
        
        $record = New-RegistryKeyRecord -KeyPath $KeyPath -Status "ERROR" `
            -SubkeyCount $keyDetails.SubkeyCount -ValueCount $keyDetails.ValueCount `
            -ErrorMessage $errorMsg
        $RemediationResults.Registry.Errored += $record
        $RemediationResults.Summary.RegistryValuesErrored++
        
        $RemediationResults.CriticalErrors += "Registry: $KeyPath - $errorMsg"
        return "ERROR"
    }
}

function Remove-MalwareRegistryKeys {
    <#
    .SYNOPSIS
    Removes malware registry keys (artifacts and configuration)
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [array]$HKLMPaths,
        
        [Parameter(Mandatory=$true)]
        [array]$HKUPatterns
    )
    
    Write-Log "========================================" -Level INFO
    Write-Log "REGISTRY CLEANUP MODULE (ARTIFACTS)" -Level INFO
    Write-Log "========================================" -Level INFO
    
    Write-Log "Phase 1: Removing HKLM registry keys..." -Level INFO
    
    foreach ($keyPath in $HKLMPaths) {
        $null = Remove-RegistryKeyRecursive -KeyPath $keyPath  # <-- FIX: Capture return
    }
    
    Write-Log "Phase 2: Removing per-user registry keys..." -Level INFO
    
    $userSIDs = Get-UserSIDs
    Write-Log "  Found $($userSIDs.Count) user profile(s)" -Level INFO
    
    foreach ($sid in $userSIDs) {
        Write-Log "  Processing SID: $sid" -Level INFO
        
        foreach ($pattern in $HKUPatterns) {
            $basePath = "Registry::HKU\$sid"
            $searchPath = "$basePath\$pattern"
            
            Write-Log "    Searching: $searchPath" -Level INFO
            
            if ($pattern -match '\*') {
                $parts = $pattern -split '\\'
                $currentPath = $basePath
                
                $searchFromIndex = 0
                for ($i = 0; $i -lt $parts.Count; $i++) {
                    if ($parts[$i] -match '\*') {
                        $searchFromIndex = $i
                        break
                    }
                    $currentPath = "$currentPath\$($parts[$i])"
                }
                
                if (Test-Path $currentPath) {
                    $searchPattern = $parts[$searchFromIndex]
                    
                    $matchingKeys = Get-ChildItem $currentPath -ErrorAction SilentlyContinue |
                        Where-Object { $_.PSChildName -like $searchPattern }
                    
                    if ($matchingKeys) {
                        Write-Log "      Found $($matchingKeys.Count) matching key(s)" -Level WARNING
                        foreach ($key in $matchingKeys) {
                            $null = Remove-RegistryKeyRecursive -KeyPath $key.PSPath  # <-- FIX: Capture return
                        }
                    } else {
                        Write-Log "      [NOT FOUND] No keys match pattern" -Level INFO
                        
                        $record = New-RegistryKeyRecord -KeyPath $searchPath -Status "NOT_FOUND"
                        $RemediationResults.Registry.NotFound += $record
                        $RemediationResults.Summary.RegistryKeysChecked++
                    }
                } else {
                    Write-Log "      [NOT FOUND] Base path does not exist" -Level INFO
                    
                    $record = New-RegistryKeyRecord -KeyPath $searchPath -Status "NOT_FOUND"
                    $RemediationResults.Registry.NotFound += $record
                    $RemediationResults.Summary.RegistryKeysChecked++
                }
                
            } else {
                $null = Remove-RegistryKeyRecursive -KeyPath $searchPath  # <-- FIX: Capture return
            }
        }
    }
    
    Write-Log "========================================" -Level INFO
    Write-Log "REGISTRY CLEANUP SUMMARY" -Level INFO
    Write-Log "  Keys Checked: $($RemediationResults.Summary.RegistryKeysChecked)" -Level INFO
    Write-Log "  Keys Removed: $($RemediationResults.Summary.RegistryValuesRemoved)" -Level SUCCESS
    Write-Log "  Keys Failed: $($RemediationResults.Summary.RegistryValuesFailed)" -Level ERROR
    Write-Log "  Keys Errored: $($RemediationResults.Summary.RegistryValuesErrored)" -Level ERROR
    Write-Log "========================================" -Level INFO
}

# ============================================================================ #
# BROWSER ENTRY CLEANUP
# ============================================================================ #

function Remove-BrowserEntry {
    <#
    .SYNOPSIS
    Removes a browser registry entry with detailed tracking
    #>
    param(
        [string]$KeyPath,
        [string]$EntryType
    )
    
    if (-not (Test-Path $KeyPath)) {
        return "NOT_FOUND"
    }
    
    try {
        Write-Log "    [FOUND] $EntryType : $KeyPath" -Level WARNING
        
        Remove-Item -Path $KeyPath -Recurse -Force -ErrorAction Stop
        Start-Sleep -Milliseconds 200
        
        if (-not (Test-Path $KeyPath)) {
            Write-Log "    [SUCCESS] Removed: $KeyPath" -Level SUCCESS
            
            $record = New-BrowserRecord -EntryPath $KeyPath -EntryType $EntryType -Status "REMOVED"
            $RemediationResults.Registry.Removed += $record
            $RemediationResults.Summary.RegistryValuesRemoved++
            return "SUCCESS"
        } else {
            Write-Log "    [FAILED] Still exists: $KeyPath" -Level ERROR
            
            $record = New-BrowserRecord -EntryPath $KeyPath -EntryType $EntryType `
                -Status "FAILED" -ErrorMessage "Key still exists after removal"
            $RemediationResults.Registry.Failed += $record
            $RemediationResults.Summary.RegistryValuesFailed++
            return "FAILED"
        }
    } catch {
        $errorMsg = $_.Exception.Message
        Write-Log "    [ERROR] Failed to remove: $errorMsg" -Level ERROR
        
        $record = New-BrowserRecord -EntryPath $KeyPath -EntryType $EntryType `
            -Status "ERROR" -ErrorMessage $errorMsg
        $RemediationResults.Registry.Errored += $record
        $RemediationResults.Summary.RegistryValuesErrored++
        
        $RemediationResults.CriticalErrors += "Browser Entry: $KeyPath - $errorMsg"
        return "ERROR"
    }
}

function Remove-MalwareBrowserEntries {
    <#
    .SYNOPSIS
    Removes browser hijacking registry entries
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [array]$BrowserPatterns
    )
    
    Write-Log "========================================" -Level INFO
    Write-Log "BROWSER ENTRY CLEANUP MODULE" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "Removes browser hijacking to prevent false inventory detections" -Level INFO
    
    $totalRemoved = 0
    
    Write-Log "Phase 1: Removing HKLM StartMenuInternet entries..." -Level INFO
    
    $hklmBrowserPath = "HKLM:\Software\Clients\StartMenuInternet"
    
    if (Test-Path $hklmBrowserPath) {
        foreach ($pattern in $BrowserPatterns) {
            $matchingKeys = Get-ChildItem $hklmBrowserPath -ErrorAction SilentlyContinue |
                Where-Object { $_.PSChildName -like $pattern }
            
            if ($matchingKeys) {
                Write-Log "  Found $($matchingKeys.Count) HKLM browser registration(s)" -Level WARNING
                foreach ($key in $matchingKeys) {
                    $RemediationResults.Summary.RegistryKeysChecked++
                    $result = Remove-BrowserEntry -KeyPath $key.PSPath -EntryType "HKLM Browser Registration"
                    if ($result -eq "SUCCESS") { $totalRemoved++ }
                }
            } else {
                Write-Log "  [NOT FOUND] No HKLM browser registrations match" -Level INFO
            }
        }
    }
    
    Write-Log "Phase 2: Removing per-user StartMenuInternet entries..." -Level INFO
    
    $userSIDs = Get-UserSIDs
    Write-Log "  Found $($userSIDs.Count) user profile(s)" -Level INFO
    
    foreach ($sid in $userSIDs) {
        Write-Log "  Processing SID: $sid" -Level INFO
        
        $hkuBrowserPath = "Registry::HKU\$sid\Software\Clients\StartMenuInternet"
        
        if (Test-Path $hkuBrowserPath) {
            foreach ($pattern in $BrowserPatterns) {
                $matchingKeys = Get-ChildItem $hkuBrowserPath -ErrorAction SilentlyContinue |
                    Where-Object { $_.PSChildName -like $pattern }
                
                if ($matchingKeys) {
                    Write-Log "    Found $($matchingKeys.Count) user browser registration(s)" -Level WARNING
                    foreach ($key in $matchingKeys) {
                        $RemediationResults.Summary.RegistryKeysChecked++
                        $result = Remove-BrowserEntry -KeyPath $key.PSPath -EntryType "User Browser Registration"
                        if ($result -eq "SUCCESS") { $totalRemoved++ }
                    }
                }
            }
        }
    }
    
    Write-Log "Phase 3: Removing ProgID classes..." -Level INFO
    
    foreach ($sid in $userSIDs) {
        $hkuClassesPath = "Registry::HKU\$sid\Software\Classes"
        
        if (Test-Path $hkuClassesPath) {
            foreach ($pattern in $BrowserPatterns) {
                $matchingKeys = Get-ChildItem $hkuClassesPath -ErrorAction SilentlyContinue |
                    Where-Object { $_.PSChildName -like $pattern }
                
                if ($matchingKeys) {
                    Write-Log "    Found $($matchingKeys.Count) ProgID class(es)" -Level WARNING
                    foreach ($key in $matchingKeys) {
                        $RemediationResults.Summary.RegistryKeysChecked++
                        $result = Remove-BrowserEntry -KeyPath $key.PSPath -EntryType "ProgID Class"
                        if ($result -eq "SUCCESS") { $totalRemoved++ }
                    }
                }
            }
        }
    }
    
    $hklmClassesPath = "HKLM:\Software\Classes"
    if (Test-Path $hklmClassesPath) {
        foreach ($pattern in $BrowserPatterns) {
            $matchingKeys = Get-ChildItem $hklmClassesPath -ErrorAction SilentlyContinue |
                Where-Object { $_.PSChildName -like $pattern }
            
            if ($matchingKeys) {
                Write-Log "  Found $($matchingKeys.Count) HKLM ProgID class(es)" -Level WARNING
                foreach ($key in $matchingKeys) {
                    $RemediationResults.Summary.RegistryKeysChecked++
                    $result = Remove-BrowserEntry -KeyPath $key.PSPath -EntryType "HKLM ProgID Class"
                    if ($result -eq "SUCCESS") { $totalRemoved++ }
                }
            }
        }
    }
    
    if ($FeatureUsagePatterns.Count -gt 0) {

        Write-Log "Phase 4: Checking UserChoice associations..." -Level INFO
        
        foreach ($sid in $userSIDs) {
            $userChoicePath = "Registry::HKU\$sid\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts"
            
            if (Test-Path $userChoicePath) {
                $fileExts = Get-ChildItem $userChoicePath -ErrorAction SilentlyContinue
                
                foreach ($ext in $fileExts) {
                    $userChoiceKey = Join-Path $ext.PSPath "UserChoice"
                    
                    if (Test-Path $userChoiceKey) {
                        try {
                            $progId = (Get-ItemProperty $userChoiceKey -Name ProgId -ErrorAction SilentlyContinue).ProgId
                            
                            if ($progId) {
                                foreach ($pattern in $BrowserPatterns) {
                                    if ($progId -like $pattern) {
                                        Write-Log "    [FOUND] UserChoice for $($ext.PSChildName) : $progId" -Level WARNING
                                        $RemediationResults.Summary.RegistryKeysChecked++
                                        
                                        Write-Log "    [INFO] UserChoice key is hash-protected by Windows" -Level INFO
                                        Write-Log "    [INFO] Will be reset when user changes default program" -Level INFO
                                        
                                        $record = New-BrowserRecord -EntryPath $userChoiceKey `
                                            -EntryType "UserChoice (Protected)" -Status "NOTED"
                                        $RemediationResults.Registry.NotFound += $record
                                    }
                                } # End foreach pattern
                            } # End if progId
                        } catch {
                            # Silent fail - UserChoice keys are often protected
                        }
                    } # End if Test-Path UserChoice
                } # End foreach fileExts
            } # End if Test-Path FileExts
        } # End foreach SID
        
        Write-Log "========================================" -Level INFO
        Write-Log "BROWSER ENTRY CLEANUP SUMMARY" -Level INFO
        Write-Log "  Entries Checked: $($RemediationResults.Summary.RegistryKeysChecked)" -Level INFO
        Write-Log "  Entries Removed: $totalRemoved" -Level SUCCESS
        Write-Log "  Note: UserChoice keys are Windows-protected and will reset naturally" -Level INFO
        Write-Log "========================================" -Level INFO
    } # End $FeatureUsagePatterns.Count

} # End Remove-MalwareBrowserEntries


# ============================================================================ #
# FILE ASSOCIATION CLEANUP
# ============================================================================ #

function Remove-MalwareFileAssociations {
    <#
    .SYNOPSIS
    Removes orphaned file association tracking entries
    .DESCRIPTION
    Cleans ApplicationAssociationToasts registry values that track
    whether Windows has prompted the user about file associations.
    Prevents broken "Open with" references to deleted malware.
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [array]$AssociationPatterns
    )
    
    Write-Log "========================================" -Level INFO
    Write-Log "FILE ASSOCIATION CLEANUP MODULE" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "Removes orphaned ApplicationAssociationToasts entries" -Level INFO
    
    $totalRemoved = 0
    $totalFound = 0
    
    $userSIDs = Get-UserSIDs
    Write-Log "  Found $($userSIDs.Count) user profile(s)" -Level INFO
    
    foreach ($sid in $userSIDs) {
        Write-Log "  Processing SID: $sid" -Level INFO
        
        $assocPath = "Registry::HKU\$sid\Software\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts"
        
        if (-not (Test-Path $assocPath)) {
            Write-Log "    [NOT FOUND] ApplicationAssociationToasts key does not exist" -Level INFO
            continue
        }
        
        $RemediationResults.Summary.RegistryKeysChecked++
        
        try {
            $properties = Get-ItemProperty -Path $assocPath -ErrorAction Stop
            
            foreach ($pattern in $AssociationPatterns) {
                $matchingValues = $properties.PSObject.Properties | 
                    Where-Object { $_.Name -like $pattern -and $_.Name -notlike "PS*" }
                
                foreach ($value in $matchingValues) {
                    $valueName = $value.Name
                    $valueData = $value.Value
                    $totalFound++
                    
                    Write-Log "    [FOUND] Association: $valueName = $valueData" -Level WARNING
                    
                    try {
                        Remove-ItemProperty -Path $assocPath -Name $valueName -ErrorAction Stop
                        
                        $checkValue = Get-ItemProperty -Path $assocPath -Name $valueName -ErrorAction SilentlyContinue
                        if (-not $checkValue) {
                            Write-Log "    [SUCCESS] Removed: $valueName" -Level SUCCESS
                            
                            $record = New-RegistryRecord -KeyPath $assocPath -ValueName $valueName `
                                -Status "REMOVED" -ValueData $valueData
                            $RemediationResults.Registry.Removed += $record
                            $RemediationResults.Summary.RegistryValuesRemoved++
                            $totalRemoved++
                        } else {
                            Write-Log "    [FAILED] Still exists: $valueName" -Level ERROR
                            
                            $record = New-RegistryRecord -KeyPath $assocPath -ValueName $valueName `
                                -Status "FAILED" -ValueData $valueData -ErrorMessage "Value still exists"
                            $RemediationResults.Registry.Failed += $record
                            $RemediationResults.Summary.RegistryValuesFailed++
                        }
                    } catch {
                        $errorMsg = $_.Exception.Message
                        Write-Log "    [ERROR] Failed to remove $valueName : $errorMsg" -Level ERROR
                        
                        $record = New-RegistryRecord -KeyPath $assocPath -ValueName $valueName `
                            -Status "ERROR" -ValueData $valueData -ErrorMessage $errorMsg
                        $RemediationResults.Registry.Errored += $record
                        $RemediationResults.Summary.RegistryValuesErrored++
                    }
                }
            }
        } catch {
            Write-Log "    [ERROR] Cannot access ApplicationAssociationToasts: $($_.Exception.Message)" -Level ERROR
        }
    }
    
    Write-Log "========================================" -Level INFO
    Write-Log "FILE ASSOCIATION CLEANUP SUMMARY" -Level INFO
    Write-Log "  Keys Checked: $($RemediationResults.Summary.RegistryKeysChecked)" -Level INFO
    Write-Log "  Associations Found: $totalFound" -Level INFO
    Write-Log "  Associations Removed: $totalRemoved" -Level SUCCESS
    Write-Log "  Note: Clears orphaned file association prompts" -Level INFO
    Write-Log "========================================" -Level INFO
}

# ============================================================================ #
# EXECUTION
# ============================================================================ #

Write-Log "============================================" -Level INFO
Write-Log "MALWARE REMEDIATION FRAMEWORK" -Level INFO
Write-Log "Target: $($MalwareConfig.Name)" -Level INFO
Write-Log "Started: $($RemediationResults.StartTime)" -Level INFO
Write-Log "============================================" -Level INFO

# 1. PROCESSES - Stop active threats immediately
Stop-MalwareProcess -ProcessNames $MalwareConfig.Processes
Start-Sleep -Seconds 2

# 2. SERVICES - Prevent automatic restart of processes
Stop-MalwareService -ServiceNames $MalwareConfig.Services
Start-Sleep -Seconds 2

# 3. SCHEDULED TASKS - Remove persistence (can restart services/processes)
Remove-MalwareTask -TaskPatterns $MalwareConfig.TaskPatterns
Start-Sleep -Seconds 2

# 4. REGISTRY - RUN KEYS - Remove autostart entries (another persistence layer)
Remove-MalwareRegistryPersistence -RunKeyPatterns $MalwareConfig.RunKeyPatterns `
    -RegisteredAppPatterns $MalwareConfig.RegisteredAppPatterns `
    -FeatureUsagePatterns $MalwareConfig.FeatureUsagePatterns
Start-Sleep -Seconds 2

# 5. FILES & FOLDERS - Safe to remove now (nothing using them)
Remove-MalwareFiles -UserPaths $MalwareConfig.UserPaths `
    -DownloadPatterns $MalwareConfig.DownloadPatterns `
    -SystemPaths $MalwareConfig.SystemPaths
Start-Sleep -Seconds 2

# 6. REGISTRY - CLEANUP - Remove remaining configuration/artifacts
Remove-MalwareRegistryKeys -HKLMPaths $MalwareConfig.RegistryHKLM `
    -HKUPatterns $MalwareConfig.RegistryHKUPatterns
Start-Sleep -Seconds 2

# 7. BROWSER ENTRIES - Clean up browser hijacking (ProgID, StartMenuInternet)
Remove-MalwareBrowserEntries -BrowserPatterns $MalwareConfig.BrowserStartMenuPatterns
Start-Sleep -Seconds 2

# 8. FILE ASSOCIATIONS - Remove orphaned ApplicationAssociationToasts
if ($MalwareConfig.ApplicationAssociationPatterns) {
    Remove-MalwareFileAssociations -AssociationPatterns $MalwareConfig.ApplicationAssociationPatterns
    Start-Sleep -Seconds 2
}

# ============================================================================ #
# FINAL REPORT
# ============================================================================ #

$RemediationResults.EndTime = Get-Date
$duration = $RemediationResults.EndTime - $RemediationResults.StartTime

Write-Log "============================================" -Level INFO
Write-Log "REMEDIATION COMPLETE" -Level SUCCESS
Write-Log "Duration: $($duration.TotalSeconds) seconds" -Level INFO
Write-Log "Log File: $logFile" -Level INFO
Write-Log "============================================" -Level INFO
Write-Log "" -Level INFO
Write-Log "FINAL SUMMARY" -Level INFO
Write-Log "Processes: Checked=$($RemediationResults.Summary.ProcessesChecked) Killed=$($RemediationResults.Summary.ProcessesKilled) Failed=$($RemediationResults.Summary.ProcessesFailed)" -Level INFO
Write-Log "Services: Checked=$($RemediationResults.Summary.ServicesChecked) Removed=$($RemediationResults.Summary.ServicesRemoved) Failed=$($RemediationResults.Summary.ServicesFailed)" -Level INFO
Write-Log "Tasks: Checked=$($RemediationResults.Summary.TasksChecked) Removed=$($RemediationResults.Summary.TasksRemoved) Failed=$($RemediationResults.Summary.TasksFailed)" -Level INFO
Write-Log "TaskCache: Checked=$($RemediationResults.Summary.TaskCacheChecked) Removed=$($RemediationResults.Summary.TaskCacheRemoved) Failed=$($RemediationResults.Summary.TaskCacheFailed)" -Level INFO
Write-Log "Registry: Keys Checked=$($RemediationResults.Summary.RegistryKeysChecked) Removed=$($RemediationResults.Summary.RegistryValuesRemoved) Failed=$($RemediationResults.Summary.RegistryValuesFailed)" -Level INFO
Write-Log "Files: Checked=$($RemediationResults.Summary.PathsChecked) Removed=$($RemediationResults.Summary.PathsRemoved) Failed=$($RemediationResults.Summary.PathsFailed)" -Level INFO
Write-Log "Critical Errors: $($RemediationResults.CriticalErrors.Count)" -Level ERROR
Write-Log "============================================" -Level INFO

# Add detailed breakdown if critical errors exist
if ($RemediationResults.CriticalErrors.Count -gt 0) {
    Write-Log "CRITICAL ERROR DETAILS:" -Level ERROR
    foreach ($cError in $RemediationResults.CriticalErrors) {
        Write-Log "  - $cError" -Level ERROR
    }
}

# Display log file location and contents
Write-Output ""
Write-Output "=========================================="
Write-Output "Remediation Complete!"
Write-Output "Log File: $logFile"
Write-Output "=========================================="
Write-Output ""

# Display full log contents
Get-Content $logFile