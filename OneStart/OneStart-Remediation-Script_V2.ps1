# ============================================================================ #
# Malware Remediation Framework - Configuration
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
        "PDFEditor",
        "PDFEditorService",
        "PDFEditorUpdater"
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
        "OneStart*",
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

        # Browser hijacking entries (specific patterns)
    BrowserStartMenuPatterns = @(
        "OneStart*"
    )
    
    # File type associations to clean
    FileTypeAssociations = @(
        ".htm",
        ".html",
        ".pdf",
        ".shtml",
        ".xht",
        ".xhtml"
    )
    
    # URL protocol handlers
    URLProtocols = @(
        "http",
        "https",
        "ftp"
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

# ============================================================================ #
# PROCESS TERMINATION
# ============================================================================ #

function Stop-MalwareProcess {
    <#
    .SYNOPSIS
    Terminates processes with detailed tracking
    
    .DESCRIPTION
    Attempts to stop processes, verifies termination, and logs results
    with comprehensive tracking for analysis
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
        
        # Check if process exists
        $processes = Get-Process -Name $processName -ErrorAction SilentlyContinue
        
        if (-not $processes) {
            # Process not found
            Write-Log "  [NOT FOUND] Process not running: $processName" -Level INFO
            
            $record = New-ProcessRecord -ProcessName $processName -Status "NOT_FOUND"
            $RemediationResults.Processes.NotFound += $record
            $RemediationResults.Summary.ProcessesNotFound++
            continue
        }
        
        # Process found - capture details
        $pidList = $processes.Id
        $RemediationResults.Summary.ProcessesFound++
        
        Write-Log "  [FOUND] Running instances: $($processes.Count) | PIDs: $($pidList -join ', ')" -Level WARNING
        
        try {
            # Attempt to terminate
            $processes | Stop-Process -Force -ErrorAction Stop
            Start-Sleep -Milliseconds 500
            
            # Verify termination
            $stillRunning = Get-Process -Name $processName -ErrorAction SilentlyContinue
            
            if (-not $stillRunning) {
                # Successfully killed
                Write-Log "  [SUCCESS] Terminated: $processName (PIDs: $($pidList -join ', '))" -Level SUCCESS
                
                $record = New-ProcessRecord -ProcessName $processName -Status "KILLED" `
                    -PIDs $pidList -ProcessObjects $processes
                $RemediationResults.Processes.Killed += $record
                $RemediationResults.Summary.ProcessesKilled++
                
            } else {
                # Failed to kill
                $survivingPIDs = $stillRunning.Id
                Write-Log "  [FAILED] Still running: $processName (PIDs: $($survivingPIDs -join ', '))" -Level ERROR
                
                $record = New-ProcessRecord -ProcessName $processName -Status "FAILED" `
                    -PIDs $survivingPIDs -ProcessObjects $stillRunning `
                    -ErrorMessage "Process survived termination attempt"
                $RemediationResults.Processes.Failed += $record
                $RemediationResults.Summary.ProcessesFailed++
            }
            
        } catch {
            # Unexpected error during termination
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
    
    .DESCRIPTION
    - Checks if service exists
    - Captures service details before remediation
    - Attempts to stop running services
    - Attempts to remove/delete services
    - Verifies both stop and removal
    - Tracks all states and errors
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
        
        # Check if service exists
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        
        if (-not $service) {
            # Service not found
            Write-Log "  [NOT FOUND] Service does not exist: $serviceName" -Level INFO
            
            $record = New-ServiceRecord -ServiceName $serviceName -Status "NOT_FOUND"
            $RemediationResults.Services.NotFound += $record
            $RemediationResults.Summary.ServicesNotFound++
            continue
        }
        
        # Service exists - capture details
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
        
        # STEP 1: Stop the service if running
        if ($service.Status -eq 'Running') {
            Write-Log "  [STOPPING] Attempting to stop service..." -Level INFO
            
            try {
                Stop-Service -Name $serviceName -Force -ErrorAction Stop
                Start-Sleep -Milliseconds 500
                
                # Verify stop
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
        
        # STEP 2: Remove/Delete the service
        Write-Log "  [REMOVING] Attempting to delete service..." -Level INFO
        
        try {
            # Try using sc.exe for deletion (more reliable)
            $scResult = & sc.exe delete $serviceName 2>&1
            Start-Sleep -Milliseconds 500
            
            # Verify removal
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
        
        # STEP 3: Record results
        if ($overallSuccess -and $removalResult -eq "SUCCESS") {
            # Fully remediated
            Write-Log "  [COMPLETE] Service stopped and removed: $serviceName" -Level SUCCESS
            
            $record = New-ServiceRecord -ServiceName $serviceName -Status "REMOVED" `
                -ServiceDetails $serviceDetails -StopResult $stopResult -RemovalResult $removalResult
            $RemediationResults.Services.Removed += $record
            $RemediationResults.Summary.ServicesRemoved++
            
        } elseif ($removalResult -eq "FAILED" -or $stopResult -eq "FAILED") {
            # Failed to remediate
            Write-Log "  [FAILED] Service remediation incomplete: $serviceName" -Level ERROR
            
            $record = New-ServiceRecord -ServiceName $serviceName -Status "FAILED" `
                -ServiceDetails $serviceDetails -StopResult $stopResult -RemovalResult $removalResult `
                -ErrorMessage "Stop: $stopResult | Removal: $removalResult"
            $RemediationResults.Services.Failed += $record
            $RemediationResults.Summary.ServicesFailed++
            
        } else {
            # Error during remediation
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

function Remove-MalwareTask {
    <#
    .SYNOPSIS
    Removes scheduled tasks with detailed tracking
    
    .DESCRIPTION
    - Checks if task exists (supports wildcards)
    - Captures task details before remediation
    - Attempts to unregister/delete tasks
    - Verifies removal
    - Tracks all states and errors
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [array]$TaskPatterns
    )
    
    Write-Log "========================================" -Level INFO
    Write-Log "SCHEDULED TASK REMEDIATION MODULE" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "Target task patterns: $($TaskPatterns.Count)" -Level INFO
    
    foreach ($pattern in $TaskPatterns) {
        $RemediationResults.Summary.TasksChecked++
        
        Write-Log "Checking for task pattern: $pattern" -Level INFO
        
        # Search for matching tasks
        $matchingTasks = @()
        try {
            # Get all tasks in root and search
            $allTasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
                $_.TaskName -like $pattern -or $_.TaskPath -like "*$pattern*"
            }
            $matchingTasks = @($allTasks)
        } catch {
            Write-Log "  [WARNING] Error searching for tasks: $($_.Exception.Message)" -Level WARNING
        }
        
        if ($matchingTasks.Count -eq 0) {
            # No tasks found
            Write-Log "  [NOT FOUND] No tasks match pattern: $pattern" -Level INFO
            
            $record = New-TaskRecord -TaskName $pattern -Status "NOT_FOUND"
            $RemediationResults.Tasks.NotFound += $record
            $RemediationResults.Summary.TasksNotFound++
            continue
        }
        
        # Tasks found - process each match
        Write-Log "  [FOUND] $($matchingTasks.Count) task(s) match pattern: $pattern" -Level WARNING
        
        foreach ($task in $matchingTasks) {
            $taskName = $task.TaskName
            $taskPath = $task.TaskPath
            $RemediationResults.Summary.TasksFound++
            
            # Capture task details
            $taskDetails = Get-TaskDetails -TaskName $taskName
            
            Write-Log "    Task: $taskPath$taskName" -Level INFO
            Write-Log "      State: $($taskDetails.State)" -Level INFO
            Write-Log "      Actions: $($taskDetails.Actions)" -Level INFO
            
            $removalResult = "NOT_ATTEMPTED"
            $overallSuccess = $true
            
            # Attempt to unregister task
            Write-Log "    [REMOVING] Attempting to unregister task..." -Level INFO
            
            try {
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
                Start-Sleep -Milliseconds 500
                
                # Verify removal
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
            
            # Record results
            if ($overallSuccess -and $removalResult -eq "SUCCESS") {
                # Fully remediated
                Write-Log "    [COMPLETE] Task removed: $taskName" -Level SUCCESS
                
                $record = New-TaskRecord -TaskName $taskName -Status "REMOVED" `
                    -TaskDetails $taskDetails -RemovalResult $removalResult
                $RemediationResults.Tasks.Removed += $record
                $RemediationResults.Summary.TasksRemoved++
                
            } elseif ($removalResult -eq "FAILED") {
                # Failed to remediate
                Write-Log "    [FAILED] Task removal incomplete: $taskName" -Level ERROR
                
                $record = New-TaskRecord -TaskName $taskName -Status "FAILED" `
                    -TaskDetails $taskDetails -RemovalResult $removalResult `
                    -ErrorMessage "Task still exists after removal"
                $RemediationResults.Tasks.Failed += $record
                $RemediationResults.Summary.TasksFailed++
                
            } else {
                # Error during remediation
                Write-Log "    [ERROR] Task removal error: $taskName" -Level ERROR
                
                $record = New-TaskRecord -TaskName $taskName -Status "ERROR" `
                    -TaskDetails $taskDetails -RemovalResult $removalResult `
                    -ErrorMessage "Removal: $removalResult"
                $RemediationResults.Tasks.Errored += $record
                $RemediationResults.Summary.TasksErrored++
                
                $RemediationResults.CriticalErrors += "Task: $taskName - Removal: $removalResult"
            }
        }
    }
    
    Write-Log "========================================" -Level INFO
    Write-Log "SCHEDULED TASK REMEDIATION SUMMARY" -Level INFO
    Write-Log "  Checked: $($RemediationResults.Summary.TasksChecked)" -Level INFO
    Write-Log "  Found: $($RemediationResults.Summary.TasksFound)" -Level INFO
    Write-Log "  Removed: $($RemediationResults.Summary.TasksRemoved)" -Level SUCCESS
    Write-Log "  Failed: $($RemediationResults.Summary.TasksFailed)" -Level ERROR
    Write-Log "  Errored: $($RemediationResults.Summary.TasksErrored)" -Level ERROR
    Write-Log "  Not Found: $($RemediationResults.Summary.TasksNotFound)" -Level INFO
    Write-Log "========================================" -Level INFO

}

# ============================================================================ #
# REGISTRY PERSISTENCE REMOVAL
# ============================================================================ #

function New-RegistryRecord {
    <#
    .SYNOPSIS
    Creates a detailed registry tracking record
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
                    
                    # Verify removal
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
    
    .DESCRIPTION
    Targets autostart locations:
    - HKLM Run/RunOnce keys
    - Per-user (HKU) Run/RunOnce keys
    - RegisteredApplications entries
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [array]$RunKeyPatterns,
        
        [Parameter(Mandatory=$true)]
        [array]$RegisteredAppPatterns
    )
    
    Write-Log "========================================" -Level INFO
    Write-Log "REGISTRY PERSISTENCE REMOVAL MODULE" -Level INFO
    Write-Log "========================================" -Level INFO
    
    $totalRemoved = 0
    
    # ----------------------------------------------------------------
    # PHASE 1: HKLM Run Keys (System-wide autostart)
    # ----------------------------------------------------------------
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
    
    # ----------------------------------------------------------------
    # PHASE 2: Per-User Run Keys (HKU hive)
    # ----------------------------------------------------------------
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
    
    # ----------------------------------------------------------------
    # PHASE 3: RegisteredApplications (Browser/App registration)
    # ----------------------------------------------------------------
    Write-Log "Phase 3: Checking RegisteredApplications..." -Level INFO
    
    # HKLM RegisteredApplications
    $hklmRegApps = "HKLM:\Software\RegisteredApplications"
    Write-Log "  Checking: $hklmRegApps" -Level INFO
    $RemediationResults.Summary.RegistryKeysChecked++
    $removed = Remove-RegistryValueByPattern -KeyPath $hklmRegApps -ValuePatterns $RegisteredAppPatterns
    $totalRemoved += $removed
    
    # Per-user RegisteredApplications
    foreach ($sid in $userSIDs) {
        $hkuRegApps = "Registry::HKU\$sid\Software\RegisteredApplications"
        $RemediationResults.Summary.RegistryKeysChecked++
        $removed = Remove-RegistryValueByPattern -KeyPath $hkuRegApps -ValuePatterns $RegisteredAppPatterns
        $totalRemoved += $removed
    }
    
    # ----------------------------------------------------------------
    # SUMMARY
    # ----------------------------------------------------------------
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
        
        # Verify removal
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
    
    .DESCRIPTION
    All patterns pulled from $MalwareConfig for centralized maintenance
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
    
    # PHASE 1: User-Specific Paths
    Write-Log "Phase 1: Removing user-specific paths..." -Level INFO
    
    $userProfiles = Get-UserProfiles
    Write-Log "  Found $($userProfiles.Count) user profile(s)" -Level INFO
    
    foreach ($user in $userProfiles) {
        Write-Log "  Processing user: $user" -Level INFO
        
        foreach ($pathTemplate in $UserPaths) {
            $RemediationResults.Summary.PathsChecked++
            
            # Replace {USER} token with actual username
            $actualPath = $pathTemplate -replace '\{USER\}', $user
            
            $result = Remove-PathItem -Path $actualPath
            
            if ($result -eq "NOT_FOUND") {
                $record = New-FileRecord -Path $actualPath -Status "NOT_FOUND"
                $RemediationResults.Files.NotFound += $record
                $RemediationResults.Summary.PathsNotFound++
            }
        }
    }
    
    # PHASE 2: Download Folder Patterns
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
    
    # PHASE 3: System-Level Paths
    Write-Log "Phase 3: Removing system-level paths..." -Level INFO
    
    foreach ($path in $SystemPaths) {
        $RemediationResults.Summary.PathsChecked++
        
        # Handle wildcards in system paths
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
    
    # SUMMARY
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
    
    # Check if key exists and get details
    $keyDetails = Get-RegistryKeyDetails -KeyPath $KeyPath
    
    if (-not $keyDetails.Exists) {
        Write-Log "    [NOT FOUND] Key does not exist" -Level INFO
        
        $record = New-RegistryKeyRecord -KeyPath $KeyPath -Status "NOT_FOUND"
        $RemediationResults.Registry.NotFound += $record
        return "NOT_FOUND"
    }
    
    # Key exists - log details
    Write-Log "    [FOUND] Subkeys: $($keyDetails.SubkeyCount) | Values: $($keyDetails.ValueCount)" -Level WARNING
    
    try {
        # Attempt removal
        Remove-Item -Path $KeyPath -Recurse -Force -ErrorAction Stop
        Start-Sleep -Milliseconds 200
        
        # Verify removal
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
    
    .DESCRIPTION
    Removes registry keys AFTER files are deleted to avoid file lock issues
    - HKLM specific paths (exact matches)
    - HKU pattern-based searches (per-user artifacts)
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
    
    # ----------------------------------------------------------------
    # PHASE 1: HKLM Specific Paths
    # ----------------------------------------------------------------
    Write-Log "Phase 1: Removing HKLM registry keys..." -Level INFO
    
    foreach ($keyPath in $HKLMPaths) {
        Remove-RegistryKeyRecursive -KeyPath $keyPath
    }
    
    # ----------------------------------------------------------------
    # PHASE 2: Per-User (HKU) Pattern-Based Cleanup
    # ----------------------------------------------------------------
    Write-Log "Phase 2: Removing per-user registry keys..." -Level INFO
    
    $userSIDs = Get-UserSIDs
    Write-Log "  Found $($userSIDs.Count) user profile(s)" -Level INFO
    
    foreach ($sid in $userSIDs) {
        Write-Log "  Processing SID: $sid" -Level INFO
        
        foreach ($pattern in $HKUPatterns) {
            # Build full path with SID
            $basePath = "Registry::HKU\$sid"
            $searchPath = "$basePath\$pattern"
            
            Write-Log "    Searching: $searchPath" -Level INFO
            
            # Handle wildcard patterns
            if ($pattern -match '\*') {
                # Get parent path and search pattern
                $parts = $pattern -split '\\'
                $currentPath = $basePath
                
                # Navigate to the deepest non-wildcard path
                $searchFromIndex = 0
                for ($i = 0; $i -lt $parts.Count; $i++) {
                    if ($parts[$i] -match '\*') {
                        $searchFromIndex = $i
                        break
                    }
                    $currentPath = "$currentPath\$($parts[$i])"
                }
                
                # Check if base path exists
                if (Test-Path $currentPath) {
                    # Build search pattern
                    $searchPattern = $parts[$searchFromIndex]
                    
                    # Find matching keys
                    $matchingKeys = Get-ChildItem $currentPath -ErrorAction SilentlyContinue |
                        Where-Object { $_.PSChildName -like $searchPattern }
                    
                    if ($matchingKeys) {
                        Write-Log "      Found $($matchingKeys.Count) matching key(s)" -Level WARNING
                        foreach ($key in $matchingKeys) {
                            Remove-RegistryKeyRecursive -KeyPath $key.PSPath
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
                # Exact path match
                Remove-RegistryKeyRecursive -KeyPath $searchPath
            }
        }
    }
    
    # ----------------------------------------------------------------
    # SUMMARY
    # ----------------------------------------------------------------
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
    
    .DESCRIPTION
    Targets browser registration to prevent false positives in software inventory:
    - StartMenuInternet registrations (appears in Default Apps)
    - UserChoice associations (file type handlers)
    - ProgID classes (application classes)
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
    
    # ----------------------------------------------------------------
    # PHASE 1: HKLM StartMenuInternet (System-wide browser registration)
    # ----------------------------------------------------------------
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
    
    # ----------------------------------------------------------------
    # PHASE 2: Per-User StartMenuInternet (HKU)
    # ----------------------------------------------------------------
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
    
    # ----------------------------------------------------------------
    # PHASE 3: ProgID Classes (Application identifiers)
    # ----------------------------------------------------------------
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
    
    # Also check HKLM Classes
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
    
    # ----------------------------------------------------------------
    # PHASE 4: UserChoice Associations (Default program overrides)
    # ----------------------------------------------------------------
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
                                    
                                    # UserChoice keys are protected - note but don't force remove
                                    Write-Log "    [INFO] UserChoice key is hash-protected by Windows" -Level INFO
                                    Write-Log "    [INFO] Will be reset when user changes default program" -Level INFO
                                    
                                    $record = New-BrowserRecord -EntryPath $userChoiceKey `
                                        -EntryType "UserChoice (Protected)" -Status "NOTED"
                                    $RemediationResults.Registry.NotFound += $record
                                }
                            }
                        }
                    } catch {
                        # Silent fail - UserChoice keys are often protected
                    }
                }
            }
        }
    }
    
    # ----------------------------------------------------------------
    # SUMMARY
    # ----------------------------------------------------------------
    Write-Log "========================================" -Level INFO
    Write-Log "BROWSER ENTRY CLEANUP SUMMARY" -Level INFO
    Write-Log "  Entries Checked: $($RemediationResults.Summary.RegistryKeysChecked)" -Level INFO
    Write-Log "  Entries Removed: $totalRemoved" -Level SUCCESS
    Write-Log "  Note: UserChoice keys are Windows-protected and will reset naturally" -Level INFO
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

# Execute process termination
Stop-MalwareProcess -ProcessNames $MalwareConfig.Processes
Start-Sleep -Seconds 2

# Execute service remediation
Stop-MalwareService -ServiceNames $MalwareConfig.Services
Start-Sleep -Seconds 2

# Execute scheduled task removal
Remove-MalwareTask -TaskPatterns $MalwareConfig.TaskPatterns
Start-Sleep -Seconds 2

# Execute registry persistence removal
Remove-MalwareRegistryPersistence -RunKeyPatterns $MalwareConfig.RunKeyPatterns `
    -RegisteredAppPatterns $MalwareConfig.RegisteredAppPatterns
Start-Sleep -Seconds 2

# Execute file and folder cleanup
Remove-MalwareFiles -UserPaths $MalwareConfig.UserPaths `
    -DownloadPatterns $MalwareConfig.DownloadPatterns `
    -SystemPaths $MalwareConfig.SystemPaths
Start-Sleep -Seconds 2

# Execute registry cleanup (artifacts)
Remove-MalwareRegistryKeys -HKLMPaths $MalwareConfig.RegistryHKLM `
    -HKUPatterns $MalwareConfig.RegistryHKUPatterns
Start-Sleep -Seconds 2

# Execute browser entry cleanup (LAST - most visible to users)
Remove-MalwareBrowserEntries -BrowserPatterns $MalwareConfig.BrowserStartMenuPatterns
Start-Sleep -Seconds 2