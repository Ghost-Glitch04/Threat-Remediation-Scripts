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

    # ----------------------------------------------------------------------------
    # MALWARE CONFIGURATION - Metadata
    # ----------------------------------------------------------------------------

    # Metadata
    Metadata = @{
        Version = "2.0.0"
        LastUpdated = "2024-01-15"
        Author = "sentinelrshuser"
        ThreatFamily = "OneStart.AI"
        FirstSeen = "2023-10"
        Severity = "HIGH"
        Description = "Browser hijacker and PUP that installs unwanted certificates and modifies browser settings"
    }

    Name = "OneStart.AI"
    
    # ----------------------------------------------------------------------------
    # MALWARE CONFIGURATION - Processes
    # ----------------------------------------------------------------------------

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
        "UpdaterSetup",
        "ManualFinderApp"
    )
    
    # ----------------------------------------------------------------------------
    # MALWARE CONFIGURATION - Services
    # ----------------------------------------------------------------------------

    # Service names to stop and remove
    Services = @(
        "OneStartService",
        "PDFEditorService"
    )
    
    # ----------------------------------------------------------------------------
    # MALWARE CONFIGURATION - Certificates
    # ----------------------------------------------------------------------------

    # Certificate Configuration
    Certificates = @{
        # Known malicious certificate thumbprints (PRIORITY 1 - REMOVE)
        MaliciousThumbprints = @(
            "612DE7BA0369AFF3507DFF7A39DF2F4F7A82E51D"  # OneStart Technologies LLC
        )
        
        # Known malicious certificate serial numbers (PRIORITY 2 - REMOVE)
        MaliciousSerialNumbers = @(
            "09561E1A16C2BE16570AC67471 2B 56 F1"  # OneStart Technologies LLC
        )
        
        # Suspicious keywords in Subject/Issuer (PRIORITY 3 - ANALYZE)
        SuspiciousKeywords = @(
            "OneStart",
            "OneStart.AI",
            "One Start",
            "Glint",
            "Electron",
            "DO_NOT_TRUST",
            "Test",
            "Development",
            "Debug"
        )
        
        # Protected keywords - REPORT ONLY, DO NOT DELETE
        ProtectedKeywords = @(
            "Microsoft",
            "Windows",
            "Apple",
            "Google",
            "Adobe",
            "Oracle",
            "VeriSign",
            "DigiCert",
            "Thawte",
            "GeoTrust",
            "Comodo"
        )
        
        # Certificate stores to scan (ordered by risk level)
        Stores = @(
            @{Location = "LocalMachine"; Store = "Root"; Risk = "CRITICAL"},
            @{Location = "LocalMachine"; Store = "TrustedPublisher"; Risk = "HIGH"},
            @{Location = "LocalMachine"; Store = "CA"; Risk = "MEDIUM"},
            @{Location = "CurrentUser"; Store = "Root"; Risk = "CRITICAL"},
            @{Location = "CurrentUser"; Store = "TrustedPublisher"; Risk = "HIGH"},
            @{Location = "CurrentUser"; Store = "CA"; Risk = "MEDIUM"}
        )
        
        # Analysis thresholds
        RecentlyInstalledDays = 90    # Flag certs installed in last 90 days
        SuspiciousValidityYears = 20  # Flag certs valid for over 20 years
    }
    
    # ----------------------------------------------------------------------------
    # MALWARE CONFIGURATION - Scheduled Tasks
    # ----------------------------------------------------------------------------

    # Scheduled task patterns
    TaskPatterns = @(
        "OneStartUser",
        "OneStartAutoLaunchTask*",
        "PDFEditorScheduledTask",
        "PDFEditorUScheduledTask",
        "sys_component_health_*"
    )
    
    # ----------------------------------------------------------------------------
    # MALWARE CONFIGURATION - Run Keys
    # ----------------------------------------------------------------------------

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
        "C:\Users\{USER}\AppData\Roaming\AP-2E99C4AA-3F56-48BB-A947-2EDA163E765F",
        "C:\Users\{USER}\AppData\Roaming\PDF Editor\*.node",
        "C:\Users\{USER}\AppData\Local\OneStart.ai\*.node"
    )
    
    # ----------------------------------------------------------------------------
    # MALWARE CONFIGURATION - Files and Folders
    # ----------------------------------------------------------------------------

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
    
    # ----------------------------------------------------------------------------
    # MALWARE CONFIGURATION - Registry Keys
    # ----------------------------------------------------------------------------

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
    
    # ----------------------------------------------------------------------------
    # MALWARE CONFIGURATION - Browser Entries
    # ----------------------------------------------------------------------------
    
    # Browser hijacking entries (specific patterns)
    BrowserStartMenuPatterns = @(
        "OneStart*"
    )

    # ----------------------------------------------------------------------------
    # MALWARE CONFIGURATION - Usage Tracking
    # ----------------------------------------------------------------------------

    # File association tracking patterns (ApplicationAssociationToasts)
    ApplicationAssociationPatterns = @(
        "OneStart*",
        "OSBHTML*",
        "PDFEditor*"
    )

    # ----------------------------------------------------------------------------
    # MALWARE CONFIGURATION - File Association Tracking
    # ----------------------------------------------------------------------------

    # Feature usage tracking patterns (AppBadgeUpdated, AppLaunch, etc.)
    FeatureUsagePatterns = @(
        "OneStart*",
        "PDFEditor*"
    )
}

# ----------------------------------------------------------------------------
# RESULTS TRACKING
# ----------------------------------------------------------------------------

$RemediationResults = @{

    # ----------------------------------------------------------------------------
    # RESULTS TRACKING - Processes
    # ----------------------------------------------------------------------------

    # Module timing
    ModuleTiming = @{
        Processes = $null
        Services = $null
        Certificates = $null
        Tasks = $null
        RegistryPersistence = $null
        Files = $null
        RegistryCleanup = $null
        BrowserEntries = $null
        FileAssociations = $null
    }

    # ----------------------------------------------------------------------------
    # RESULTS TRACKING - Processes
    # ----------------------------------------------------------------------------

    # Detailed process tracking
    Processes = @{
        NotFound = @()
        Terminated = @()
        Failed = @()
        Errored = @()
    }
    
    # ----------------------------------------------------------------------------
    # RESULTS TRACKING - Services
    # ----------------------------------------------------------------------------

    # Detailed service tracking
    Services = @{
        NotFound = @()
        Removed = @()
        Failed = @()
        Errored = @()
    }
    
    # ----------------------------------------------------------------------------
    # RESULTS TRACKING - Certificates
    # ----------------------------------------------------------------------------

    # Detailed certificate tracking
    Certificates = @{
        NotFound = @()
        Removed = @()
        Failed = @()
        Errored = @()
        Flagged = @()  # Suspicious but not removed
        Protected = @()  # Items we WON'T remove (by design)
        Noted = @()  # UserChoice entries (protected by Windows)
    }

    # ----------------------------------------------------------------------------
    # RESULTS TRACKING - Scheduled Tasks
    # ----------------------------------------------------------------------------

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

    # ----------------------------------------------------------------------------
    # RESULTS TRACKING - Registry Keys/Values
    # ----------------------------------------------------------------------------

    # Detailed registry tracking
    Registry = @{
        NotFound = @()
        Removed = @()
        Failed = @()
        Errored = @()
    }
    
    # ----------------------------------------------------------------------------
    # RESULTS TRACKING - Files/Folders
    # ----------------------------------------------------------------------------

    # Detailed file/folder tracking
    Files = @{
        NotFound = @()
        Removed = @()
        Failed = @()
        Errored = @()
    }

    # ----------------------------------------------------------------------------
    # RESULTS TRACKING - Browser Entries
    # ----------------------------------------------------------------------------

    # Detailed browser entry tracking
    BrowserEntries = @{
        NotFound = @()
        Removed = @()
        Failed = @()
        Errored = @()
        Noted = @()  # For UserChoice protected entries
        Protected = @()  # Items we WON'T remove (by design)
    }

    # ----------------------------------------------------------------------------
    # RESULTS TRACKING - File Associations tracking
    # ----------------------------------------------------------------------------

    # Detailed file association tracking
    FileAssociations = @{
        NotFound = @()
        Removed = @()
        Failed = @()
        Errored = @()
    }

    # ----------------------------------------------------------------------------
    # RESULTS TRACKING - Failed Actions
    # ----------------------------------------------------------------------------

    # Actions which need further review
    ActionItems = @{
        SuspiciousCertificates = @()  # Certs that need review
        ProtectedItems = @()          # Items that couldn't be removed due to protection
        FailedRemovals = @()          # Items that failed to remove
        UnexpectedFindings = @()      # Items found that weren't expected
    }
    
    # Quick summary stats
    Summary = @{

        # ----------------------------------------------------------------------------
        # SUMMARY STATS - Processes
        # ----------------------------------------------------------------------------

        # Process stats
        ProcessesChecked = 0
        ProcessesFound = 0
        ProcessesTerminated = 0
        ProcessesFailed = 0
        ProcessesErrored = 0
        ProcessesNotFound = 0

        # ----------------------------------------------------------------------------
        # SUMMARY STATS - Services
        # ----------------------------------------------------------------------------
        
        # Service stats
        ServicesChecked = 0
        ServicesFound = 0
        ServicesRemoved = 0
        ServicesFailed = 0
        ServicesErrored = 0
        ServicesNotFound = 0

        # ----------------------------------------------------------------------------
        # SUMMARY STATS - Certificates
        # ----------------------------------------------------------------------------

        # Certificate stats
        CertStoresChecked = 0
        CertificatesScanned = 0
        CertificatesNotFound = 0
        CertificatesFlagged = 0
        CertificatesRemoved = 0
        CertificatesFailed = 0
        CertificatesErrored = 0
        

        # ----------------------------------------------------------------------------
        # SUMMARY STATS - Scheduled Tasks
        # ----------------------------------------------------------------------------
        
        # Task stats
        TasksChecked = 0
        TasksFound = 0
        TasksRemoved = 0
        TasksFailed = 0
        TasksErrored = 0
        TasksNotFound = 0

        # ----------------------------------------------------------------------------
        # SUMMARY STATS - Cached Scheduled Tasks
        # ----------------------------------------------------------------------------

        # TaskCache stats
        TaskCacheChecked = 0
        TaskCacheFound = 0
        TaskCacheRemoved = 0
        TaskCacheFailed = 0
        TaskCacheErrored = 0
        TaskCacheNotFound = 0
        
        # ----------------------------------------------------------------------------
        # SUMMARY STATS - Registry Keys/Values
        # ----------------------------------------------------------------------------

        # Registry stats
        RegistryKeysChecked = 0
        RegistryValuesFound = 0
        RegistryValuesRemoved = 0
        RegistryValuesFailed = 0
        RegistryValuesErrored = 0
        RegistryValuesNotFound = 0
        
        # ----------------------------------------------------------------------------
        # SUMMARY STATS - Files and Folders
        # ----------------------------------------------------------------------------

        # File/Folder stats
        PathsChecked = 0
        PathsFound = 0
        PathsRemoved = 0
        PathsFailed = 0
        PathsErrored = 0
        PathsNotFound = 0

        # ----------------------------------------------------------------------------
        # SUMMARY STATS - Browser Entries
        # ----------------------------------------------------------------------------

         # Browser entry stats
        BrowserEntriesChecked = 0
        BrowserEntriesFound = 0
        BrowserEntriesRemoved = 0
        BrowserEntriesFailed = 0
        BrowserEntriesErrored = 0
        BrowserEntriesNotFound = 0

        # ----------------------------------------------------------------------------
        # SUMMARY STATS - File Associations
        # ----------------------------------------------------------------------------

        FileAssociationsChecked = 0
        FileAssociationsFound = 0
        FileAssociationsRemoved = 0
        FileAssociationsFailed = 0
        FileAssociationsErrored = 0
        FileAssociationsNotFound = 0

        # ----------------------------------------------------------------------------
        # SUMMARY STATS - Overall Summary of Actions Performed
        # ----------------------------------------------------------------------------

        # Overall totals (calculated at end)
        TotalActionsAttempted = 0
        TotalActionsSuccessful = 0
        TotalActionsFailed = 0

    }
    
    # Global error log
    CriticalErrors = @()
    
    # Timing
    StartTime = Get-Date
    EndTime = $null
}

# Add after $RemediationResults definition (around line 400)
$StatusLevels = @{
    NotApplicable = "NOT_APPLICABLE"  # Component doesn't exist
    NotFound = "NOT_FOUND"            # Searched but not present
    Success = "SUCCESS"               # Action completed successfully
    PartialSuccess = "PARTIAL"        # Some items succeeded, others failed
    Failed = "FAILED"                 # Action attempted but failed (item still exists)
    Protected = "PROTECTED"           # Item protected/locked (expected failure)
    Error = "ERROR"                   # Unexpected exception
    Skipped = "SKIPPED"               # Intentionally not processed
    ManualReview = "MANUAL_REVIEW"    # Requires human review
}

# ============================================================================ #
# HELPER FUNCTIONS
# ============================================================================ #

# ============================================================================ #
# HELPER FUNCTIONS - General
# ============================================================================ #

# ============================================================================ #
# HELPER FUNCTIONS - General - Write-Log
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

# ============================================================================ #
# HELPER FUNCTIONS - Processes
# ============================================================================ #

# ============================================================================ #
# HELPER FUNCTIONS - Processes - New-ProcessRecord
# ============================================================================ #

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

# ============================================================================ #
# HELPER FUNCTIONS - Services
# ============================================================================ #

# ============================================================================ #
# HELPER FUNCTIONS - Services - Get-ServiceDetails
# ============================================================================ #

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

# ============================================================================ #
# HELPER FUNCTIONS - General - Module Timing
# ============================================================================ #

function Write-ModuleTiming {
    <#
    .SYNOPSIS
    Records module execution time in results tracking
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$ModuleName,
        
        [Parameter(Mandatory=$true)]
        [datetime]$StartTime,
        
        [Parameter(Mandatory=$true)]
        [datetime]$EndTime
    )
    
    $duration = ($EndTime - $StartTime).TotalSeconds
    $RemediationResults.ModuleTiming[$ModuleName] = $duration
    Write-Log "Module '$ModuleName' completed in $duration seconds" -Level INFO
}

# ============================================================================ #
# HELPER FUNCTIONS - Services - New-ServiceRecord
# ============================================================================ #

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

# ============================================================================ #
# HELPER FUNCTIONS - Certificates
# ============================================================================ #

# ============================================================================ #
# HELPER FUNCTIONS - Certificates - Get-CertificateAge
# ============================================================================ #

function Get-CertificateAge {
    <#
    .SYNOPSIS
    Calculates certificate age in days
    #>
    param([DateTime]$NotBefore)
    
    $age = (Get-Date) - $NotBefore
    return [Math]::Round($age.TotalDays, 0)
}

# ============================================================================ #
# HELPER FUNCTIONS - Certificates - Get-CertificateValidityPeriod
# ============================================================================ #

function Get-CertificateValidityPeriod {
    <#
    .SYNOPSIS
    Calculates certificate validity period in years
    #>
    param(
        [DateTime]$NotBefore,
        [DateTime]$NotAfter
    )
    
    $validity = $NotAfter - $NotBefore
    return [Math]::Round($validity.TotalDays / 365.25, 1)
}

# ============================================================================ #
# HELPER FUNCTIONS - Certificates - Test-SuspiciousSubject
# ============================================================================ #

function Test-SuspiciousSubject {
    <#
    .SYNOPSIS
    Checks if certificate subject contains suspicious keywords
    #>
    param(
        [string]$Subject,
        [array]$Keywords
    )
    
    foreach ($keyword in $Keywords) {
        if ($Subject -like "*$keyword*") {
            return $true
        }
    }
    return $false
}

# ============================================================================ #
# HELPER FUNCTIONS - Certificates - New-CertificateRecord
# ============================================================================ #

function New-CertificateRecord {
    <#
    .SYNOPSIS
    Creates a detailed certificate tracking record
    #>
    param(
        [string]$StoreLocation,
        [string]$StoreName,
        [string]$Subject,
        [string]$Thumbprint,
        [string]$Status,
        [hashtable]$Details = @{},
        [string]$ErrorMessage = $null,
        [array]$FlagReasons = @()
    )
    
    return @{
        StoreLocation = $StoreLocation
        StoreName = $StoreName
        Subject = $Subject
        Thumbprint = $Thumbprint
        Issuer = $Details.Issuer
        SerialNumber = $Details.SerialNumber
        NotBefore = $Details.NotBefore
        NotAfter = $Details.NotAfter
        AgeDays = $Details.AgeDays
        ValidityYears = $Details.ValidityYears
        IsSelfSigned = $Details.IsSelfSigned
        RiskLevel = $Details.RiskLevel
        FlagReasons = $FlagReasons
        Status = $Status
        Timestamp = Get-Date
        ErrorMessage = $ErrorMessage
    }
}

# ============================================================================ #
# HELPER FUNCTIONS - Scheduled Tasks
# ============================================================================ #

# ============================================================================ #
# HELPER FUNCTIONS - Scheduled Tasks - Get-TaskDetails
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

# ============================================================================ #
# HELPER FUNCTIONS - Scheduled Tasks - New-TaskRecord
# ============================================================================ #

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

# ============================================================================ #
# HELPER FUNCTIONS - Scheduled Tasks - New-TaskCacheRecord
# ============================================================================ #

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

# ============================================================================ #
# HELPER FUNCTIONS - Registry Keys/Values
# ============================================================================ #

# ============================================================================ #
# HELPER FUNCTIONS - Registry Keys/Values - New-RegistryRecord
# ============================================================================ #

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

# ============================================================================ #
# HELPER FUNCTIONS - Registry Keys/Values - New-RegistryKeyRecord
# ============================================================================ #

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
# HELPER FUNCTIONS - Registry Keys/Values - Get-RegistryKeyDetails
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

# ============================================================================ #
# HELPER FUNCTIONS - Registry Keys/Values - Get-UserSIDs
# ============================================================================ #

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

# ============================================================================ #
# HELPER FUNCTIONS - Files/Folders
# ============================================================================ #

# ============================================================================ #
# HELPER FUNCTIONS - Files/Folders - New-FileRecord
# ============================================================================ #

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

# ============================================================================ #
# HELPER FUNCTIONS - Files/Folders - Get-UserProfiles
# ============================================================================ #

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

# ============================================================================ #
# HELPER FUNCTIONS - Browser Entries
# ============================================================================ #

# ============================================================================ #
# HELPER FUNCTIONS - Browser Entries - New-BrowserRecord
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
        [string]$ErrorMessage = $null,
        [string]$ProgId = $null,
        [string]$Extension = $null
    )
    
    return @{
        EntryPath = $EntryPath
        EntryType = $EntryType
        Status = $Status
        ProgId = $ProgId
        Extension = $Extension
        Timestamp = Get-Date
        ErrorMessage = $ErrorMessage
    }
}

# ============================================================================ #
# HELPER FUNCTIONS - File Associations - New-FileAssociationRecord
# ============================================================================ #

function New-FileAssociationRecord {
    <#
    .SYNOPSIS
    Creates a detailed file association tracking record
    #>
    param(
        [string]$AssociationPath,
        [string]$ValueName,
        [string]$Status,
        [string]$ValueData = $null,
        [string]$ErrorMessage = $null
    )
    
    return @{
        AssociationPath = $AssociationPath
        ValueName = $ValueName
        ValueData = $ValueData
        Status = $Status
        Timestamp = Get-Date
        ErrorMessage = $ErrorMessage
    }
}

# ============================================================================ #
# PRIMARY FUNCTIONS
# ============================================================================ #

# ============================================================================ #
#  PRIMARY FUNCTIONS - PROCESS TERMINATION
# ============================================================================ #

# ============================================================================ #
#  PRIMARY FUNCTIONS - PROCESS TERMINATION - Stop-MalwareProcess
# ============================================================================ #

function Stop-MalwareProcess {
    <#
    .SYNOPSIS
    Terminates processes with detailed tracking
    .DESCRIPTION
    Stops malicious processes and captures detailed information including:
    - Process IDs (PIDs)
    - Process paths and command lines
    - Termination success/failure status
    - Module execution timing
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [array]$ProcessNames
    )
    
    # Module timing start
    $moduleStartTime = Get-Date
    
    Write-Log "========================================" -Level INFO
    Write-Log "PROCESS TERMINATION MODULE" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "Target processes: $($ProcessNames.Count)" -Level INFO
    
    foreach ($processName in $ProcessNames) {
        $RemediationResults.Summary.ProcessesChecked++
        
        Write-Log "Checking for process: $processName" -Level INFO
        
        # Check if process is running
        $processes = Get-Process -Name $processName -ErrorAction SilentlyContinue
        
        if (-not $processes) {
            Write-Log "  [NOT FOUND] Process not running: $processName" -Level INFO
            
            $record = New-ProcessRecord -ProcessName $processName -Status $StatusLevels.NotFound
            $RemediationResults.Processes.NotFound += $record
            $RemediationResults.Summary.ProcessesNotFound++
            continue
        }
        
        # Process found - capture details
        $pidList = $processes.Id
        $RemediationResults.Summary.ProcessesFound++
        
        Write-Log "  [FOUND] Running instances: $($processes.Count) | PIDs: $($pidList -join ', ')" -Level WARNING
        
        # Attempt termination
        try {
            $processes | Stop-Process -Force -ErrorAction Stop
            Start-Sleep -Milliseconds 500
            
            # Verify termination
            $stillRunning = Get-Process -Name $processName -ErrorAction SilentlyContinue
            
            if (-not $stillRunning) {
                Write-Log "  [SUCCESS] Terminated: $processName (PIDs: $($pidList -join ', '))" -Level SUCCESS
                
                $record = New-ProcessRecord -ProcessName $processName -Status $StatusLevels.Success `
                    -PIDs $pidList -ProcessObjects $processes
                $RemediationResults.Processes.Terminated += $record
                $RemediationResults.Summary.ProcessesTerminated++
                
            } else {
                # Process survived termination
                $survivingPIDs = $stillRunning.Id
                Write-Log "  [FAILED] Still running: $processName (PIDs: $($survivingPIDs -join ', '))" -Level ERROR
                
                $record = New-ProcessRecord -ProcessName $processName -Status $StatusLevels.Failed `
                    -PIDs $survivingPIDs -ProcessObjects $stillRunning `
                    -ErrorMessage "Process survived termination attempt"
                $RemediationResults.Processes.Failed += $record
                $RemediationResults.Summary.ProcessesFailed++
            }
            
        } catch {
            # Exception during termination
            $errorMsg = $_.Exception.Message
            Write-Log "  [ERROR] Exception during termination: $processName - $errorMsg" -Level ERROR
            
            $record = New-ProcessRecord -ProcessName $processName -Status $StatusLevels.Error `
                -PIDs $pidList -ProcessObjects $processes -ErrorMessage $errorMsg
            $RemediationResults.Processes.Errored += $record
            $RemediationResults.Summary.ProcessesErrored++
            
            $RemediationResults.CriticalErrors += "Process: $processName - $errorMsg"
        }
    }
    
    # Module timing end
    $moduleEndTime = Get-Date
    Write-ModuleTiming -ModuleName "Processes" -StartTime $moduleStartTime -EndTime $moduleEndTime
    
    # Module summary
    Write-Log "========================================" -Level INFO
    Write-Log "PROCESS TERMINATION SUMMARY" -Level INFO
    Write-Log "  Checked: $($RemediationResults.Summary.ProcessesChecked)" -Level INFO
    Write-Log "  Found: $($RemediationResults.Summary.ProcessesFound)" -Level INFO
    Write-Log "  Terminated: $($RemediationResults.Summary.ProcessesTerminated)" -Level SUCCESS
    Write-Log "  Failed: $($RemediationResults.Summary.ProcessesFailed)" -Level ERROR
    Write-Log "  Errored: $($RemediationResults.Summary.ProcessesErrored)" -Level ERROR
    Write-Log "  Not Found: $($RemediationResults.Summary.ProcessesNotFound)" -Level INFO
    Write-Log "========================================" -Level INFO
}
# ============================================================================ #
#  PRIMARY FUNCTIONS - SERVICE REMEDIATION
# ============================================================================ #

# ============================================================================ #
#  PRIMARY FUNCTIONS - SERVICE REMEDIATION - Stop-MalwareService
# ============================================================================ #

function Stop-MalwareService {
    <#
    .SYNOPSIS
    Stops and removes malicious services with detailed tracking
    .DESCRIPTION
    Removes malicious Windows services by:
    - Stopping running services
    - Deleting service registration
    - Capturing detailed service information
    - Tracking success/failure rates
    - Module execution timing
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [array]$ServiceNames
    )
    
    # Module timing start
    $moduleStartTime = Get-Date
    
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
            Write-Log "  [NOT FOUND] Service does not exist: $serviceName" -Level INFO
            
            $record = New-ServiceRecord -ServiceName $serviceName -Status $StatusLevels.NotFound
            $RemediationResults.Services.NotFound += $record
            $RemediationResults.Summary.ServicesNotFound++
            continue
        }
        
        # Service found - capture details
        $RemediationResults.Summary.ServicesFound++
        $serviceDetails = Get-ServiceDetails -Service $service
        
        Write-Log "  [FOUND] Service exists" -Level WARNING
        Write-Log "    Display Name: $($serviceDetails.DisplayName)" -Level INFO
        Write-Log "    Status: $($serviceDetails.Status)" -Level INFO
        Write-Log "    Start Type: $($serviceDetails.StartType)" -Level INFO
        Write-Log "    Path: $($serviceDetails.PathName)" -Level INFO
        
        # Track results for this service
        $stopResult = "NOT_ATTEMPTED"
        $removalResult = "NOT_ATTEMPTED"
        $overallSuccess = $true
        
        # Phase 1: Stop service if running
        if ($service.Status -eq 'Running') {
            Write-Log "  [STOPPING] Attempting to stop service..." -Level INFO
            
            try {
                Stop-Service -Name $serviceName -Force -ErrorAction Stop
                Start-Sleep -Milliseconds 500
                
                # Verify service stopped
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
                $errorMsg = $_.Exception.Message
                Write-Log "  [ERROR] Failed to stop service: $errorMsg" -Level ERROR
                $stopResult = "ERROR"
                $overallSuccess = $false
            }
        } else {
            Write-Log "  [SKIPPED] Service not running (Status: $($service.Status))" -Level INFO
            $stopResult = "NOT_RUNNING"
        }
        
        # Phase 2: Delete service registration
        Write-Log "  [REMOVING] Attempting to delete service..." -Level INFO
        
        try {
            # Use sc.exe for service deletion (more reliable than Remove-Service)
            $null = & sc.exe delete $serviceName 2>&1
            Start-Sleep -Milliseconds 500
            
            # Verify service removed
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
            $errorMsg = $_.Exception.Message
            Write-Log "  [ERROR] Failed to delete service: $errorMsg" -Level ERROR
            $removalResult = "ERROR"
            $overallSuccess = $false
        }
        
        # Phase 3: Record results and update tracking
        if ($overallSuccess -and $removalResult -eq "SUCCESS") {
            # Complete success - service stopped and removed
            Write-Log "  [COMPLETE] Service stopped and removed: $serviceName" -Level SUCCESS
            
            $record = New-ServiceRecord -ServiceName $serviceName -Status $StatusLevels.Success `
                -ServiceDetails $serviceDetails -StopResult $stopResult -RemovalResult $removalResult
            $RemediationResults.Services.Removed += $record
            $RemediationResults.Summary.ServicesRemoved++
            
        } elseif ($removalResult -eq "FAILED" -or $stopResult -eq "FAILED") {
            # Service exists but couldn't be fully removed
            Write-Log "  [FAILED] Service remediation incomplete: $serviceName" -Level ERROR
            
            $record = New-ServiceRecord -ServiceName $serviceName -Status $StatusLevels.Failed `
                -ServiceDetails $serviceDetails -StopResult $stopResult -RemovalResult $removalResult `
                -ErrorMessage "Stop: $stopResult | Removal: $removalResult"
            $RemediationResults.Services.Failed += $record
            $RemediationResults.Summary.ServicesFailed++
            
            # Add to action items for manual review
            $RemediationResults.ActionItems.FailedRemovals += @{
                Type = "Service"
                Name = $serviceName
                Details = $serviceDetails
                StopResult = $stopResult
                RemovalResult = $removalResult
            }
            
        } else {
            # Unexpected error during remediation
            Write-Log "  [ERROR] Service remediation error: $serviceName" -Level ERROR
            
            $record = New-ServiceRecord -ServiceName $serviceName -Status $StatusLevels.Error `
                -ServiceDetails $serviceDetails -StopResult $stopResult -RemovalResult $removalResult `
                -ErrorMessage "Stop: $stopResult | Removal: $removalResult"
            $RemediationResults.Services.Errored += $record
            $RemediationResults.Summary.ServicesErrored++
            
            # Log critical error for final report
            $RemediationResults.CriticalErrors += "Service: $serviceName - Stop: $stopResult | Removal: $removalResult"
        }
    }
    
    # Module timing end
    $moduleEndTime = Get-Date
    Write-ModuleTiming -ModuleName "Services" -StartTime $moduleStartTime -EndTime $moduleEndTime
    
    # Module summary
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
# PRIMARY FUNCTIONS - CERTIFICATE ANALYSIS & REMEDIATION
# ============================================================================ #

# ============================================================================ #
#  PRIMARY FUNCTIONS - CERTIFICATE ANALYSIS & REMEDIATION - Test-ProtectedCertificate
# ============================================================================ #

function Test-ProtectedCertificate {
    <#
    .SYNOPSIS
    Checks if certificate SUBJECT contains protected keywords
    .DESCRIPTION
    Only checks Subject field, not Issuer.
    Malicious certs can be issued by legitimate CAs like DigiCert.
    We want to protect "Microsoft Corporation" certs, not malicious
    certs that happen to be issued by trusted CAs.
    #>
    param(
        [string]$Subject,
        [array]$ProtectedKeywords
    )
    
    foreach ($keyword in $ProtectedKeywords) {
        if ($Subject -like "*$keyword*") {
            return @{
                IsProtected = $true
                Keyword = $keyword
            }
        }
    }
    return @{
        IsProtected = $false
        Keyword = $null
    }
}

# ============================================================================ #
# PRIMARY FUNCTIONS - CERTIFICATE ANALYSIS & REMEDIATION - Remove-MalwareCertificates
# ============================================================================ #

function Remove-MalwareCertificates {
    <#
    .SYNOPSIS
    Analyzes and removes malicious certificates with enhanced detection
    .DESCRIPTION
    Searches for certificates in priority order:
    1. Known malicious thumbprints (immediate removal)
    2. Known malicious serial numbers (immediate removal)
    3. Suspicious keywords in Subject (analysis + removal)
    
    Includes guardrails for protected vendors (Microsoft, etc.)
    Reports unexpected certificates matching keywords but not in known lists
    Tracks detailed metrics including module execution timing
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$CertConfig
    )
    
    # Module timing start
    $moduleStartTime = Get-Date
    
    Write-Log "========================================" -Level INFO
    Write-Log "CERTIFICATE ANALYSIS & REMEDIATION (ENHANCED)" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "Certificate stores to scan: $($CertConfig.Stores.Count)" -Level INFO
    Write-Log "" -Level INFO
    Write-Log "DETECTION PRIORITY:" -Level INFO
    Write-Log "  1. Known Thumbprints: $($CertConfig.MaliciousThumbprints.Count) signatures" -Level INFO
    Write-Log "  2. Known Serial Numbers: $($CertConfig.MaliciousSerialNumbers.Count) signatures" -Level INFO
    Write-Log "  3. Suspicious Keywords: $($CertConfig.SuspiciousKeywords.Count) patterns" -Level INFO
    Write-Log "" -Level INFO
    Write-Log "GUARDRAILS:" -Level INFO
    Write-Log "  * Protected vendors (e.g., Microsoft) will NOT be removed" -Level INFO
    Write-Log "  * Unexpected certificates matching keywords will be reported" -Level INFO
    Write-Log "" -Level INFO
    
    # Classification buckets
    $knownMaliciousThumbprint = @()
    $knownMaliciousSerial = @()
    $suspiciousUnknown = @()
    $protectedCertificates = @()
    
    # ========================================================================
    # PHASE 1: ENUMERATION & CLASSIFICATION
    # ========================================================================
    
    Write-Log "Phase 1: Certificate Enumeration & Classification" -Level INFO
    
    foreach ($storeConfig in $CertConfig.Stores) {
        $location = $storeConfig.Location
        $storeName = $storeConfig.Store
        $riskLevel = $storeConfig.Risk
        
        $RemediationResults.Summary.CertStoresChecked++
        
        Write-Log "  Scanning: $location\$storeName (Risk: $riskLevel)" -Level INFO
        
        try {
            $store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
                $storeName,
                $location
            )
            $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
            
            $certificates = $store.Certificates
            Write-Log "    Found $($certificates.Count) certificate(s)" -Level INFO
            
            foreach ($cert in $certificates) {
                $RemediationResults.Summary.CertificatesScanned++
                
                # Calculate metrics
                $certAge = Get-CertificateAge -NotBefore $cert.NotBefore
                $validityYears = Get-CertificateValidityPeriod -NotBefore $cert.NotBefore -NotAfter $cert.NotAfter
                $isSelfSigned = ($cert.Subject -eq $cert.Issuer)
                
                $certDetails = @{
                    Issuer = $cert.Issuer
                    SerialNumber = $cert.SerialNumber
                    NotBefore = $cert.NotBefore
                    NotAfter = $cert.NotAfter
                    AgeDays = $certAge
                    ValidityYears = $validityYears
                    IsSelfSigned = $isSelfSigned
                    RiskLevel = $riskLevel
                }
                
                $certInfo = @{
                    Certificate = $cert
                    Location = $location
                    StoreName = $storeName
                    Subject = $cert.Subject
                    Thumbprint = $cert.Thumbprint
                    SerialNumber = $cert.SerialNumber
                    Details = $certDetails
                    FlagReasons = @()
                    ClassificationReason = ""
                }
                
                # ------------------------------------------------------------
                # PRIORITY 1: Check for known malicious THUMBPRINT
                # ------------------------------------------------------------
                if ($CertConfig.MaliciousThumbprints -contains $cert.Thumbprint) {
                    $certInfo.FlagReasons += "Matches known malicious thumbprint"
                    $certInfo.ClassificationReason = "KNOWN_THUMBPRINT"
                    $knownMaliciousThumbprint += $certInfo
                    
                    $subjectPreview = $cert.Subject.Substring(0, [Math]::Min(60, $cert.Subject.Length))
                    Write-Log "    [!] KNOWN MALICIOUS (Thumbprint): $subjectPreview" -Level ERROR
                    Write-Log "      Thumbprint: $($cert.Thumbprint)" -Level ERROR
                    
                    $RemediationResults.Summary.CertificatesFlagged++
                    continue
                }
                
                # ------------------------------------------------------------
                # PRIORITY 2: Check for known malicious SERIAL NUMBER
                # ------------------------------------------------------------
                if ($CertConfig.MaliciousSerialNumbers -contains $cert.SerialNumber) {
                    $certInfo.FlagReasons += "Matches known malicious serial number"
                    $certInfo.ClassificationReason = "KNOWN_SERIAL"
                    $knownMaliciousSerial += $certInfo
                    
                    $subjectPreview = $cert.Subject.Substring(0, [Math]::Min(60, $cert.Subject.Length))
                    Write-Log "    [!] KNOWN MALICIOUS (Serial): $subjectPreview" -Level ERROR
                    Write-Log "      Serial: $($cert.SerialNumber)" -Level ERROR
                    
                    $RemediationResults.Summary.CertificatesFlagged++
                    continue
                }
                
                # ------------------------------------------------------------
                # PRIORITY 3: Check for SUSPICIOUS KEYWORDS
                # ------------------------------------------------------------
                $hasSuspiciousKeyword = $false
                $matchedKeyword = $null
                
                foreach ($keyword in $CertConfig.SuspiciousKeywords) {
                    if ($cert.Subject -like "*$keyword*") {
                        $hasSuspiciousKeyword = $true
                        $matchedKeyword = $keyword
                        break
                    }
                }
                
                if ($hasSuspiciousKeyword) {
                    # ------------------------------------------------------------
                    # GUARDRAIL: Check if certificate is PROTECTED
                    # ------------------------------------------------------------
                    $protectionCheck = Test-ProtectedCertificate -Subject $cert.Subject `
                        -ProtectedKeywords $CertConfig.ProtectedKeywords
                    
                    if ($protectionCheck.IsProtected) {
                        $certInfo.FlagReasons += "Contains suspicious keyword '$matchedKeyword' but protected by '$($protectionCheck.Keyword)'"
                        $certInfo.ClassificationReason = "PROTECTED"
                        $protectedCertificates += $certInfo
                        
                        $subjectPreview = $cert.Subject.Substring(0, [Math]::Min(60, $cert.Subject.Length))
                        Write-Log "    [PROTECTED] Contains '$matchedKeyword' but issued by $($protectionCheck.Keyword)" -Level WARNING
                        Write-Log "      Subject: $subjectPreview" -Level WARNING
                        Write-Log "      Action: REPORT ONLY - NOT REMOVED" -Level WARNING
                        
                        $RemediationResults.Summary.CertificatesFlagged++
                        continue
                    }
                    
                    # ------------------------------------------------------------
                    # SUSPICIOUS UNKNOWN: Has keyword but not in known lists
                    # ------------------------------------------------------------
                    $certInfo.FlagReasons += "Contains suspicious keyword '$matchedKeyword' (not in known malicious list)"
                    $certInfo.ClassificationReason = "SUSPICIOUS_UNKNOWN"
                    
                    # Add additional suspicious indicators
                    if ($isSelfSigned) {
                        $certInfo.FlagReasons += "Self-signed certificate"
                    }
                    if ($certAge -le $CertConfig.RecentlyInstalledDays) {
                        $certInfo.FlagReasons += "Recently installed ($certAge days ago)"
                    }
                    if ($validityYears -ge $CertConfig.SuspiciousValidityYears) {
                        $certInfo.FlagReasons += "Unusually long validity period ($validityYears years)"
                    }
                    
                    $suspiciousUnknown += $certInfo
                    
                    $subjectPreview = $cert.Subject.Substring(0, [Math]::Min(60, $cert.Subject.Length))
                    Write-Log "    [SUSPICIOUS UNKNOWN] Contains '$matchedKeyword': $subjectPreview" -Level WARNING
                    Write-Log "      Thumbprint: $($cert.Thumbprint)" -Level WARNING
                    Write-Log "      Serial: $($cert.SerialNumber)" -Level WARNING
                    Write-Log "      Reasons: $($certInfo.FlagReasons -join ', ')" -Level WARNING
                    
                    $RemediationResults.Summary.CertificatesFlagged++
                }
            }
            
            $store.Close()
            
        } catch {
            Write-Log "    [ERROR] Failed to scan $location\$storeName - $($_.Exception.Message)" -Level ERROR
            $RemediationResults.CriticalErrors += "Certificate Store: $location\$storeName - $($_.Exception.Message)"
        }
    }
    
    # ========================================================================
    # PHASE 2: ANALYSIS SUMMARY
    # ========================================================================
    
    Write-Log "" -Level INFO
    Write-Log "Phase 2: Classification Summary" -Level INFO
    Write-Log "  Total Certificates Scanned: $($RemediationResults.Summary.CertificatesScanned)" -Level INFO
    Write-Log "  Total Flagged: $($RemediationResults.Summary.CertificatesFlagged)" -Level WARNING
    Write-Log "" -Level INFO
    Write-Log "  Classification Breakdown:" -Level INFO
    Write-Log "    Known Malicious (Thumbprint): $($knownMaliciousThumbprint.Count)" -Level ERROR
    Write-Log "    Known Malicious (Serial): $($knownMaliciousSerial.Count)" -Level ERROR
    Write-Log "    Suspicious Unknown: $($suspiciousUnknown.Count)" -Level WARNING
    Write-Log "    Protected (Do Not Remove): $($protectedCertificates.Count)" -Level INFO
    
    # ========================================================================
    # PHASE 3: DETAILED REPORTING
    # ========================================================================
    
    Write-Log "" -Level INFO
    Write-Log "Phase 3: Detailed Findings" -Level INFO
    
    if ($protectedCertificates.Count -gt 0) {
        Write-Log "" -Level INFO
        Write-Log "  [PROTECTED CERTIFICATES - NOT REMOVED]" -Level INFO
        foreach ($cert in $protectedCertificates) {
            Write-Log "    ---" -Level INFO
            Write-Log "    Subject: $($cert.Subject)" -Level INFO
            Write-Log "    Issuer: $($cert.Details.Issuer)" -Level INFO
            Write-Log "    Location: $($cert.Location)\$($cert.StoreName)" -Level INFO
            Write-Log "    Thumbprint: $($cert.Thumbprint)" -Level INFO
            Write-Log "    Serial: $($cert.SerialNumber)" -Level INFO
            Write-Log "    Reason: $($cert.FlagReasons -join ', ')" -Level INFO
            Write-Log "    Action: REPORTED ONLY" -Level INFO
            
            $record = New-CertificateRecord -StoreLocation $cert.Location `
                -StoreName $cert.StoreName -Subject $cert.Subject `
                -Thumbprint $cert.Thumbprint -Status $StatusLevels.Protected `
                -Details $cert.Details -FlagReasons $cert.FlagReasons
            $RemediationResults.Certificates.Protected += $record
        }
    }
    
    if ($suspiciousUnknown.Count -gt 0) {
        Write-Log "" -Level WARNING
        Write-Log "  [SUSPICIOUS UNKNOWN CERTIFICATES]" -Level WARNING
        Write-Log "  These match keywords but are NOT in your known malicious lists" -Level WARNING
        Write-Log "  RECOMMENDATION: Review and add to MaliciousThumbprints/SerialNumbers if confirmed malicious" -Level WARNING
        
        foreach ($cert in $suspiciousUnknown) {
            Write-Log "    ---" -Level WARNING
            Write-Log "    Subject: $($cert.Subject)" -Level WARNING
            Write-Log "    Issuer: $($cert.Details.Issuer)" -Level WARNING
            Write-Log "    Location: $($cert.Location)\$($cert.StoreName)" -Level WARNING
            Write-Log "    Thumbprint: $($cert.Thumbprint)" -Level WARNING
            Write-Log "    Serial: $($cert.SerialNumber)" -Level WARNING
            Write-Log "    Age: $($cert.Details.AgeDays) days | Validity: $($cert.Details.ValidityYears) years" -Level WARNING
            Write-Log "    Self-Signed: $($cert.Details.IsSelfSigned)" -Level WARNING
            Write-Log "    Reasons: $($cert.FlagReasons -join ', ')" -Level WARNING
            
            $record = New-CertificateRecord -StoreLocation $cert.Location `
                -StoreName $cert.StoreName -Subject $cert.Subject `
                -Thumbprint $cert.Thumbprint -Status "SUSPICIOUS_UNKNOWN" `
                -Details $cert.Details -FlagReasons $cert.FlagReasons
            $RemediationResults.Certificates.Flagged += $record
        }
    }
    
    # ========================================================================
    # PHASE 4: REMOVAL OF KNOWN MALICIOUS CERTIFICATES
    # ========================================================================
    
    $allKnownMalicious = $knownMaliciousThumbprint + $knownMaliciousSerial
    
    if ($allKnownMalicious.Count -eq 0 -and $suspiciousUnknown.Count -eq 0 -and $protectedCertificates.Count -eq 0) {
        Write-Log "" -Level SUCCESS
        Write-Log "  [OK] No malicious or suspicious certificates detected" -Level SUCCESS
        
        # Module timing end
        $moduleEndTime = Get-Date
        Write-ModuleTiming -ModuleName "Certificates" -StartTime $moduleStartTime -EndTime $moduleEndTime
        
        Write-Log "========================================" -Level INFO
        return
    }
    
    Write-Log "" -Level INFO
    Write-Log "Phase 4: Certificate Removal" -Level WARNING
    Write-Log "  Removing KNOWN malicious certificates: $($allKnownMalicious.Count)" -Level WARNING
    Write-Log "  Removing SUSPICIOUS UNKNOWN certificates: $($suspiciousUnknown.Count)" -Level WARNING
    Write-Log "  Protected certificates will NOT be removed: $($protectedCertificates.Count)" -Level INFO
    
    # Combine removal targets (known malicious + suspicious unknown)
    $removalTargets = $allKnownMalicious + $suspiciousUnknown
    
    foreach ($certInfo in $removalTargets) {
        Write-Log "" -Level INFO
        Write-Log "  Processing [$($certInfo.ClassificationReason)]: $($certInfo.Subject.Substring(0, [Math]::Min(60, $certInfo.Subject.Length)))" -Level INFO
        Write-Log "    Thumbprint: $($certInfo.Thumbprint)" -Level INFO
        Write-Log "    Location: $($certInfo.Location)\$($certInfo.StoreName)" -Level INFO
        
        try {
            $store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
                $certInfo.StoreName,
                $certInfo.Location
            )
            $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
            
            $certToRemove = $store.Certificates | Where-Object { $_.Thumbprint -eq $certInfo.Thumbprint }
            
            if ($certToRemove) {
                $store.Remove($certToRemove)
                Start-Sleep -Milliseconds 500
                
                $checkCert = $store.Certificates | Where-Object { $_.Thumbprint -eq $certInfo.Thumbprint }
                
                if (-not $checkCert) {
                    Write-Log "    [SUCCESS] Certificate removed" -Level SUCCESS
                    
                    $record = New-CertificateRecord -StoreLocation $certInfo.Location `
                        -StoreName $certInfo.StoreName -Subject $certInfo.Subject `
                        -Thumbprint $certInfo.Thumbprint -Status $StatusLevels.Success `
                        -Details $certInfo.Details -FlagReasons $certInfo.FlagReasons
                    $RemediationResults.Certificates.Removed += $record
                    $RemediationResults.Summary.CertificatesRemoved++
                } else {
                    Write-Log "    [FAILED] Certificate still present after removal" -Level ERROR
                    
                    $record = New-CertificateRecord -StoreLocation $certInfo.Location `
                        -StoreName $certInfo.StoreName -Subject $certInfo.Subject `
                        -Thumbprint $certInfo.Thumbprint -Status $StatusLevels.Failed `
                        -Details $certInfo.Details -FlagReasons $certInfo.FlagReasons `
                        -ErrorMessage "Certificate still present after removal"
                    $RemediationResults.Certificates.Failed += $record
                    $RemediationResults.Summary.CertificatesFailed++
                }
            } else {
                Write-Log "    [NOT FOUND] Certificate not found (may have been removed already)" -Level WARNING
                
                $record = New-CertificateRecord -StoreLocation $certInfo.Location `
                    -StoreName $certInfo.StoreName -Subject $certInfo.Subject `
                    -Thumbprint $certInfo.Thumbprint -Status $StatusLevels.NotFound `
                    -Details $certInfo.Details -FlagReasons $certInfo.FlagReasons
                $RemediationResults.Certificates.NotFound += $record
                $RemediationResults.Summary.CertificatesNotFound++
            }
            
            $store.Close()
            
        } catch {
            $errorMsg = $_.Exception.Message
            Write-Log "    [ERROR] Failed to remove certificate: $errorMsg" -Level ERROR
            
            if ($errorMsg -like "*Access is denied*" -or $errorMsg -like "*protected*") {
                Write-Log "    [!] Certificate may be kernel-level protected" -Level ERROR
                Write-Log "    [!] Manual removal may be required" -Level ERROR
            }
            
            $record = New-CertificateRecord -StoreLocation $certInfo.Location `
                -StoreName $certInfo.StoreName -Subject $certInfo.Subject `
                -Thumbprint $certInfo.Thumbprint -Status $StatusLevels.Error `
                -Details $certInfo.Details -FlagReasons $certInfo.FlagReasons `
                -ErrorMessage $errorMsg
            $RemediationResults.Certificates.Errored += $record
            $RemediationResults.Summary.CertificatesErrored++
            
            $RemediationResults.CriticalErrors += "Certificate: $($certInfo.Thumbprint) - $errorMsg"
        }
    }
    
    # Module timing end
    $moduleEndTime = Get-Date
    Write-ModuleTiming -ModuleName "Certificates" -StartTime $moduleStartTime -EndTime $moduleEndTime
    
    # Module summary
    Write-Log "" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "CERTIFICATE REMEDIATION SUMMARY" -Level INFO
    Write-Log "  Stores Checked: $($RemediationResults.Summary.CertStoresChecked)" -Level INFO
    Write-Log "  Certificates Scanned: $($RemediationResults.Summary.CertificatesScanned)" -Level INFO
    Write-Log "  ---" -Level INFO
    Write-Log "  Known Malicious (Thumbprint): $($knownMaliciousThumbprint.Count)" -Level ERROR
    Write-Log "  Known Malicious (Serial): $($knownMaliciousSerial.Count)" -Level ERROR
    Write-Log "  Suspicious Unknown: $($suspiciousUnknown.Count)" -Level WARNING
    Write-Log "  Protected (Not Removed): $($protectedCertificates.Count)" -Level INFO
    Write-Log "  ---" -Level INFO
    Write-Log "  Certificates Removed: $($RemediationResults.Summary.CertificatesRemoved)" -Level SUCCESS
    Write-Log "  Certificates Failed: $($RemediationResults.Summary.CertificatesFailed)" -Level ERROR
    Write-Log "  Certificates Errored: $($RemediationResults.Summary.CertificatesErrored)" -Level ERROR
    Write-Log "  Not Found: $($RemediationResults.Summary.CertificatesNotFound)" -Level INFO
    Write-Log "========================================" -Level INFO
}

# ============================================================================ #
#  PRIMARY FUNCTIONS - SCHEDULED TASK REMEDIATION
# ============================================================================ #

# ============================================================================ #
#  PRIMARY FUNCTIONS - SCHEDULED TASK REMEDIATION - Remove-MalwareTask
# ============================================================================ #

function Remove-MalwareTask {
    <#
    .SYNOPSIS
    Removes malicious scheduled tasks with detailed tracking
    .DESCRIPTION
    Unregisters scheduled tasks matching patterns and cleans up TaskCache registry:
    - Searches for tasks by pattern
    - Unregisters matched tasks
    - Cleans orphaned TaskCache registry entries
    - Module execution timing
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [array]$TaskPatterns
    )
    
    # Module timing start
    $moduleStartTime = Get-Date
    
    Write-Log "========================================" -Level INFO
    Write-Log "SCHEDULED TASK REMEDIATION MODULE" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "Target task patterns: $($TaskPatterns.Count)" -Level INFO
    
    # Track all successfully removed task names for Phase 2
    $removedTaskNames = @()

    # ========================================================================
    # PHASE 1: Task Detection and Removal
    # ========================================================================
    
    Write-Log "" -Level INFO
    Write-Log "Phase 1: Task Detection and Removal" -Level INFO
    
    foreach ($pattern in $TaskPatterns) {
        $RemediationResults.Summary.TasksChecked++
        
        Write-Log "Checking for task pattern: $pattern" -Level INFO
        
        # Search for matching tasks
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
            
            $record = New-TaskRecord -TaskName $pattern -Status $StatusLevels.NotFound
            $RemediationResults.Tasks.NotFound += $record
            $RemediationResults.Summary.TasksNotFound++
            continue
        }
        
        Write-Log "  [FOUND] $($matchingTasks.Count) task(s) match pattern: $pattern" -Level WARNING
        
        # Process each matched task
        foreach ($task in $matchingTasks) {
            $taskName = $task.TaskName
            $taskPath = $task.TaskPath
            $RemediationResults.Summary.TasksFound++
            
            # Capture task details before removal
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
                $errorMsg = $_.Exception.Message
                Write-Log "    [ERROR] Failed to unregister: $errorMsg" -Level ERROR
                $removalResult = "ERROR"
                $overallSuccess = $false
            }
            
            # Track results
            if ($overallSuccess -and $removalResult -eq "SUCCESS") {
                Write-Log "    [COMPLETE] Task removed: $taskName" -Level SUCCESS
                
                $record = New-TaskRecord -TaskName $taskName -Status $StatusLevels.Success `
                    -TaskDetails $taskDetails -RemovalResult $removalResult
                $RemediationResults.Tasks.Removed += $record
                $RemediationResults.Summary.TasksRemoved++
                
                # Track successfully removed tasks for Phase 2
                $removedTaskNames += $taskName
                
            } elseif ($removalResult -eq "FAILED") {
                Write-Log "    [FAILED] Task removal incomplete: $taskName" -Level ERROR
                
                $record = New-TaskRecord -TaskName $taskName -Status $StatusLevels.Failed `
                    -TaskDetails $taskDetails -RemovalResult $removalResult `
                    -ErrorMessage "Task still exists after removal"
                $RemediationResults.Tasks.Failed += $record
                $RemediationResults.Summary.TasksFailed++
                
            } else {
                Write-Log "    [ERROR] Task removal error: $taskName" -Level ERROR
                
                $record = New-TaskRecord -TaskName $taskName -Status $StatusLevels.Error `
                    -TaskDetails $taskDetails -RemovalResult $removalResult `
                    -ErrorMessage "Removal: $removalResult"
                $RemediationResults.Tasks.Errored += $record
                $RemediationResults.Summary.TasksErrored++
                
                $RemediationResults.CriticalErrors += "Task: $taskName - Removal: $removalResult"
            }
        }
    }
    
    # ========================================================================
    # PHASE 2: TaskCache Cleanup
    # ========================================================================
    
    Write-Log "" -Level INFO
    Write-Log "Phase 2: TaskCache Cleanup" -Level INFO
    
    if ($removedTaskNames.Count -gt 0) {
        Write-Log "Cleaning TaskCache for $($removedTaskNames.Count) removed task(s)..." -Level INFO
        Remove-TaskCacheOrphans -TaskNames $removedTaskNames
    } else {
        Write-Log "No tasks were removed - TaskCache cleanup skipped" -Level INFO
    }
    
    # Module timing end
    $moduleEndTime = Get-Date
    Write-ModuleTiming -ModuleName "Tasks" -StartTime $moduleStartTime -EndTime $moduleEndTime
    
    # Summary
    Write-Log "" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "SCHEDULED TASK REMEDIATION SUMMARY" -Level INFO
    Write-Log "  Patterns Checked: $($RemediationResults.Summary.TasksChecked)" -Level INFO
    Write-Log "  Tasks Found: $($RemediationResults.Summary.TasksFound)" -Level INFO
    Write-Log "  Tasks Removed: $($RemediationResults.Summary.TasksRemoved)" -Level SUCCESS
    Write-Log "  Tasks Failed: $($RemediationResults.Summary.TasksFailed)" -Level ERROR
    Write-Log "  Tasks Errored: $($RemediationResults.Summary.TasksErrored)" -Level ERROR
    Write-Log "  Tasks Not Found: $($RemediationResults.Summary.TasksNotFound)" -Level INFO
    Write-Log "  ---" -Level INFO
    Write-Log "  TaskCache Checked: $($RemediationResults.Summary.TaskCacheChecked)" -Level INFO
    Write-Log "  TaskCache Removed: $($RemediationResults.Summary.TaskCacheRemoved)" -Level SUCCESS
    Write-Log "  TaskCache Failed: $($RemediationResults.Summary.TaskCacheFailed)" -Level ERROR
    Write-Log "========================================" -Level INFO
}

# ============================================================================ #
#  PRIMARY FUNCTIONS - SCHEDULED TASK REMEDIATION - Remove-TaskCacheOrphans
# ============================================================================ #

function Remove-TaskCacheOrphans {
    <#
    .SYNOPSIS
    Removes orphaned TaskCache registry entries
    .DESCRIPTION
    Cleans up TaskCache registry entries that may remain after task removal.
    Uses .NET Registry class for direct access to:
    - Tree entries (task metadata)
    - Tasks entries (task binaries)
    - Plain entries (plaintext triggers)
    - Boot/Logon entries (startup triggers)
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [array]$TaskNames
    )
    
    Write-Log "  Checking for orphaned TaskCache entries..." -Level INFO
    
    $baseKeyPath = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache"
    
    foreach ($taskName in $TaskNames) {
        $RemediationResults.Summary.TaskCacheChecked++
        
        Write-Log "    Checking TaskCache for: $taskName" -Level INFO
        
        try {
            # Check Tree entry first to get GUID
            $treePath = "$baseKeyPath\Tree\$taskName"
            $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($treePath, $false)
            
            if (-not $regKey) {
                Write-Log "      [NOT FOUND] No TaskCache entry" -Level INFO
                
                $record = New-TaskCacheRecord -TaskName $taskName -GUID "N/A" `
                    -CacheType "Tree" -Status $StatusLevels.NotFound
                $RemediationResults.TaskCache.NotFound += $record
                $RemediationResults.Summary.TaskCacheNotFound++
                continue
            }
            
            $RemediationResults.Summary.TaskCacheFound++
            
            # Get task GUID
            $taskId = $null
            try {
                $taskId = $regKey.GetValue("Id")
            } catch {
                Write-Log "      [WARNING] Could not read task GUID" -Level WARNING
            }
            $regKey.Close()
            
            $guidString = if ($taskId) { "{$taskId}" } else { "UNKNOWN" }
            Write-Log "      [FOUND] GUID: $guidString" -Level WARNING
            
            $removalSuccess = $true
            $removedCount = 0
            
            # Remove related TaskCache entries
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
                            -CacheType $subKey.Type -Status $StatusLevels.Success
                        $RemediationResults.TaskCache.Removed += $record
                        $RemediationResults.Summary.TaskCacheRemoved++
                    } catch {
                        if ($_.Exception.Message -notlike "*cannot find*") {
                            Write-Log "        [WARNING] $($subKey.Type) entry: $($_.Exception.Message)" -Level WARNING
                        }
                    }
                }
            }
            
            # Remove Tree entry last
            try {
                [Microsoft.Win32.Registry]::LocalMachine.DeleteSubKeyTree($treePath, $false)
                Write-Log "        [SUCCESS] Removed Tree entry" -Level SUCCESS
                $removedCount++
                
                $record = New-TaskCacheRecord -TaskName $taskName -GUID $guidString `
                    -CacheType "Tree" -Status $StatusLevels.Success
                $RemediationResults.TaskCache.Removed += $record
                $RemediationResults.Summary.TaskCacheRemoved++
            } catch {
                $errorMsg = $_.Exception.Message
                Write-Log "        [FAILED] Tree entry: $errorMsg" -Level ERROR
                
                $record = New-TaskCacheRecord -TaskName $taskName -GUID $guidString `
                    -CacheType "Tree" -Status $StatusLevels.Failed -ErrorMessage $errorMsg
                $RemediationResults.TaskCache.Failed += $record
                $RemediationResults.Summary.TaskCacheFailed++
                $removalSuccess = $false
            }
            
            # Final status
            if ($removalSuccess) {
                Write-Log "      [COMPLETE] TaskCache cleaned: $removedCount entries" -Level SUCCESS
            } else {
                Write-Log "      [PARTIAL] Some entries could not be removed" -Level WARNING
            }
            
        } catch {
            $errorMsg = $_.Exception.Message
            Write-Log "      [ERROR] TaskCache access failed: $errorMsg" -Level ERROR
            
            $record = New-TaskCacheRecord -TaskName $taskName -GUID "ERROR" `
                -CacheType "Unknown" -Status $StatusLevels.Error -ErrorMessage $errorMsg
            $RemediationResults.TaskCache.Errored += $record
            $RemediationResults.Summary.TaskCacheErrored++
        }
    }

    # TaskCache cleanup summary
    Write-Log "  TaskCache cleanup complete:" -Level INFO
    Write-Log "    Checked: $($RemediationResults.Summary.TaskCacheChecked)" -Level INFO
    Write-Log "    Found: $($RemediationResults.Summary.TaskCacheFound)" -Level INFO
    Write-Log "    Removed: $($RemediationResults.Summary.TaskCacheRemoved)" -Level SUCCESS
    Write-Log "    Failed: $($RemediationResults.Summary.TaskCacheFailed)" -Level ERROR
    Write-Log "    Not Found: $($RemediationResults.Summary.TaskCacheNotFound)" -Level INFO
}

# ============================================================================ #
#  PRIMARY FUNCTIONS - REGISTRY PERSISTENCE REMOVAL
# ============================================================================ #

# ============================================================================ #
#  PRIMARY FUNCTIONS - REGISTRY PERSISTENCE REMOVAL - Remove-MalwareRegistryPersistence
# ============================================================================ #

function Remove-RegistryValueByPattern {
    <#
    .SYNOPSIS
    Removes registry values matching patterns from a specific key
    .DESCRIPTION
    Helper function that scans a registry key for values matching
    specified patterns and removes them with detailed tracking
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
            # Find matching values (exclude PowerShell meta-properties)
            $matchingValues = $keyProperties.PSObject.Properties | 
                Where-Object { $_.Name -like $pattern -and $_.Name -notlike "PS*" }
            
            foreach ($value in $matchingValues) {
                $valueName = $value.Name
                $valueData = $value.Value
                
                $RemediationResults.Summary.RegistryValuesFound++
                Write-Log "    [FOUND] $KeyPath\$valueName = $valueData" -Level WARNING
                
                try {
                    # Attempt removal
                    Remove-ItemProperty -Path $KeyPath -Name $valueName -ErrorAction Stop
                    Start-Sleep -Milliseconds 200
                    
                    # Verify removal
                    $checkValue = Get-ItemProperty -Path $KeyPath -Name $valueName -ErrorAction SilentlyContinue
                    
                    if (-not $checkValue) {
                        Write-Log "    [SUCCESS] Removed: $valueName" -Level SUCCESS
                        
                        $record = New-RegistryRecord -KeyPath $KeyPath -ValueName $valueName `
                            -Status $StatusLevels.Success -ValueData $valueData
                        $RemediationResults.Registry.Removed += $record
                        $RemediationResults.Summary.RegistryValuesRemoved++
                        $removedCount++
                        
                    } else {
                        Write-Log "    [FAILED] Still exists: $valueName" -Level ERROR
                        
                        $record = New-RegistryRecord -KeyPath $KeyPath -ValueName $valueName `
                            -Status $StatusLevels.Failed -ValueData $valueData `
                            -ErrorMessage "Value still exists after removal"
                        $RemediationResults.Registry.Failed += $record
                        $RemediationResults.Summary.RegistryValuesFailed++
                    }
                    
                } catch {
                    $errorMsg = $_.Exception.Message
                    Write-Log "    [ERROR] Failed to remove $valueName : $errorMsg" -Level ERROR
                    
                    $record = New-RegistryRecord -KeyPath $KeyPath -ValueName $valueName `
                        -Status $StatusLevels.Error -ValueData $valueData -ErrorMessage $errorMsg
                    $RemediationResults.Registry.Errored += $record
                    $RemediationResults.Summary.RegistryValuesErrored++
                    
                    $RemediationResults.CriticalErrors += "Registry Value: $KeyPath\$valueName - $errorMsg"
                }
            }
        }
        
    } catch {
        Write-Log "    [ERROR] Cannot access key: $($_.Exception.Message)" -Level ERROR
    }
    
    return $removedCount
}

# ============================================================================ #
#  PRIMARY FUNCTIONS - REGISTRY PERSISTENCE REMOVAL - Remove-MalwareRegistryPersistence
# ============================================================================ #

function Remove-MalwareRegistryPersistence {
    <#
    .SYNOPSIS
    Removes malware persistence from registry Run keys and RegisteredApplications
    .DESCRIPTION
    Scans and removes persistence mechanisms including:
    - HKLM Run/RunOnce keys (system-wide autostart)
    - Per-user Run/RunOnce keys (user-specific autostart)
    - RegisteredApplications (Start Menu integration)
    - Feature Usage tracking (optional cleanup)
    Tracks timing, success/failure rates, and detailed removal status
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [array]$RunKeyPatterns,
        
        [Parameter(Mandatory=$true)]
        [array]$RegisteredAppPatterns,

        [Parameter(Mandatory=$false)]
        [array]$FeatureUsagePatterns = @()
    )
    
    # Module timing start
    $moduleStartTime = Get-Date
    
    Write-Log "========================================" -Level INFO
    Write-Log "REGISTRY PERSISTENCE REMOVAL MODULE" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "Run Key Patterns: $($RunKeyPatterns.Count)" -Level INFO
    Write-Log "Registered App Patterns: $($RegisteredAppPatterns.Count)" -Level INFO
    if ($FeatureUsagePatterns.Count -gt 0) {
        Write-Log "Feature Usage Patterns: $($FeatureUsagePatterns.Count)" -Level INFO
    }
    
    $totalRemoved = 0
    $phaseResults = @{
        HKLMRun = 0
        UserRun = 0
        HKLMRegApps = 0
        UserRegApps = 0
        FeatureUsage = 0
    }
    
    # ========================================================================
    # PHASE 1: HKLM Run Keys (System-wide Autostart)
    # ========================================================================
    
    Write-Log "" -Level INFO
    Write-Log "Phase 1: Checking HKLM Run keys..." -Level INFO
    
    $hklmRunKeys = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    
    foreach ($keyPath in $hklmRunKeys) {
        $RemediationResults.Summary.RegistryKeysChecked++
        Write-Log "  Checking: $keyPath" -Level INFO
        
        $removed = Remove-RegistryValueByPattern -KeyPath $keyPath -ValuePatterns $RunKeyPatterns
        $phaseResults.HKLMRun += $removed
        $totalRemoved += $removed
    }
    
    Write-Log "  Phase 1 Complete: Removed $($phaseResults.HKLMRun) HKLM Run entries" -Level INFO
    
    # ========================================================================
    # PHASE 2: Per-User Run Keys (User-specific Autostart)
    # ========================================================================
    
    Write-Log "" -Level INFO
    Write-Log "Phase 2: Checking per-user Run keys..." -Level INFO
    
    $userSIDs = Get-UserSIDs
    Write-Log "  Found $($userSIDs.Count) user profile(s)" -Level INFO
    
    if ($userSIDs.Count -eq 0) {
        Write-Log "  [WARNING] No user SIDs found - skipping per-user Run keys" -Level WARNING
    }
    
    foreach ($sid in $userSIDs) {
        Write-Log "  Processing SID: $sid" -Level INFO
        
        $hkuRunKeys = @(
            "Registry::HKU\$sid\Software\Microsoft\Windows\CurrentVersion\Run",
            "Registry::HKU\$sid\Software\Microsoft\Windows\CurrentVersion\RunOnce"
        )
        
        foreach ($keyPath in $hkuRunKeys) {
            $RemediationResults.Summary.RegistryKeysChecked++
            $removed = Remove-RegistryValueByPattern -KeyPath $keyPath -ValuePatterns $RunKeyPatterns
            $phaseResults.UserRun += $removed
            $totalRemoved += $removed
        }
    }
    
    Write-Log "  Phase 2 Complete: Removed $($phaseResults.UserRun) user Run entries" -Level INFO
    
    # ========================================================================
    # PHASE 3: HKLM RegisteredApplications (System Start Menu Integration)
    # ========================================================================
    
    Write-Log "" -Level INFO
    Write-Log "Phase 3: Checking HKLM RegisteredApplications..." -Level INFO
    
    $hklmRegApps = "HKLM:\Software\RegisteredApplications"
    $RemediationResults.Summary.RegistryKeysChecked++
    Write-Log "  Checking: $hklmRegApps" -Level INFO
    
    $removed = Remove-RegistryValueByPattern -KeyPath $hklmRegApps -ValuePatterns $RegisteredAppPatterns
    $phaseResults.HKLMRegApps += $removed
    $totalRemoved += $removed
    
    Write-Log "  Phase 3 Complete: Removed $($phaseResults.HKLMRegApps) HKLM RegisteredApp entries" -Level INFO
    
    # ========================================================================
    # PHASE 4: Per-User RegisteredApplications (User Start Menu Integration)
    # ========================================================================
    
    Write-Log "" -Level INFO
    Write-Log "Phase 4: Checking per-user RegisteredApplications..." -Level INFO
    
    foreach ($sid in $userSIDs) {
        $hkuRegApps = "Registry::HKU\$sid\Software\RegisteredApplications"
        $RemediationResults.Summary.RegistryKeysChecked++
        
        $removed = Remove-RegistryValueByPattern -KeyPath $hkuRegApps -ValuePatterns $RegisteredAppPatterns
        $phaseResults.UserRegApps += $removed
        $totalRemoved += $removed
    }
    
    Write-Log "  Phase 4 Complete: Removed $($phaseResults.UserRegApps) user RegisteredApp entries" -Level INFO
    
    # ========================================================================
    # PHASE 5: Feature Usage Tracking (Optional Cleanup)
    # ========================================================================
    
    if ($FeatureUsagePatterns.Count -gt 0) {
        Write-Log "" -Level INFO
        Write-Log "Phase 5: Checking Explorer Feature Usage..." -Level INFO
        
        foreach ($sid in $userSIDs) {
            $featureUsagePaths = @(
                "Registry::HKU\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppBadgeUpdated",
                "Registry::HKU\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppLaunch"
            )
            
            foreach ($keyPath in $featureUsagePaths) {
                if (Test-Path $keyPath) {
                    $RemediationResults.Summary.RegistryKeysChecked++
                    $removed = Remove-RegistryValueByPattern -KeyPath $keyPath -ValuePatterns $FeatureUsagePatterns
                    $phaseResults.FeatureUsage += $removed
                    $totalRemoved += $removed
                }
            }
        }
        
        Write-Log "  Phase 5 Complete: Removed $($phaseResults.FeatureUsage) Feature Usage entries" -Level INFO
    }
    
    # ========================================================================
    # MODULE TIMING & SUMMARY
    # ========================================================================
    
    $moduleEndTime = Get-Date
    Write-ModuleTiming -ModuleName "RegistryPersistence" -StartTime $moduleStartTime -EndTime $moduleEndTime
    
    Write-Log "" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "REGISTRY PERSISTENCE REMOVAL SUMMARY" -Level INFO
    Write-Log "  Keys Checked: $($RemediationResults.Summary.RegistryKeysChecked)" -Level INFO
    Write-Log "  Values Found: $($RemediationResults.Summary.RegistryValuesFound)" -Level INFO
    Write-Log "  ---" -Level INFO
    Write-Log "  Phase Breakdown:" -Level INFO
    Write-Log "    HKLM Run Keys: $($phaseResults.HKLMRun)" -Level INFO
    Write-Log "    User Run Keys: $($phaseResults.UserRun)" -Level INFO
    Write-Log "    HKLM RegisteredApps: $($phaseResults.HKLMRegApps)" -Level INFO
    Write-Log "    User RegisteredApps: $($phaseResults.UserRegApps)" -Level INFO
    if ($FeatureUsagePatterns.Count -gt 0) {
        Write-Log "    Feature Usage: $($phaseResults.FeatureUsage)" -Level INFO
    }
    Write-Log "  ---" -Level INFO
    Write-Log "  Values Removed: $($RemediationResults.Summary.RegistryValuesRemoved)" -Level SUCCESS
    Write-Log "  Values Failed: $($RemediationResults.Summary.RegistryValuesFailed)" -Level ERROR
    Write-Log "  Values Errored: $($RemediationResults.Summary.RegistryValuesErrored)" -Level ERROR
    Write-Log "  Values Not Found: $($RemediationResults.Summary.RegistryValuesNotFound)" -Level INFO
    Write-Log "========================================" -Level INFO
}

# ============================================================================ #
# PRIMARY FUNCTIONS - FILE & FOLDER CLEANUP
# ============================================================================ #

# ============================================================================ #
# PRIMARY FUNCTIONS - FILE & FOLDER CLEANUP - Remove-PathItem
# ============================================================================ #

function Remove-PathItem {
    <#
    .SYNOPSIS
    Removes a file or folder with detailed tracking
    .DESCRIPTION
    Attempts to remove a file or folder, captures detailed metadata,
    and tracks the outcome in the remediation results.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path
    )
    
    if (-not (Test-Path $Path)) {
        return $StatusLevels.NotFound
    }
    
    try {
        $item = Get-Item $Path -Force -ErrorAction Stop
        $itemType = if ($item.PSIsContainer) { "Folder" } else { "File" }
        
        # Calculate size
        $itemSize = 0
        if ($item.PSIsContainer) {
            $folderItems = Get-ChildItem $Path -Recurse -Force -ErrorAction SilentlyContinue
            $itemSize = ($folderItems | Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
            $fileCount = ($folderItems | Where-Object { -not $_.PSIsContainer }).Count
            Write-Log "    [FOUND] $itemType : $Path" -Level WARNING
            Write-Log "      Size: $([math]::Round($itemSize/1KB, 2)) KB | Files: $fileCount" -Level INFO
        } else {
            $itemSize = $item.Length
            Write-Log "    [FOUND] $itemType : $Path ($([math]::Round($itemSize/1KB, 2)) KB)" -Level WARNING
        }
        
        $RemediationResults.Summary.PathsFound++
        
        # Attempt removal
        Remove-Item $Path -Recurse -Force -ErrorAction Stop
        Start-Sleep -Milliseconds 200
        
        # Verify removal
        if (-not (Test-Path $Path)) {
            Write-Log "    [SUCCESS] Removed: $([math]::Round($itemSize/1KB, 2)) KB freed" -Level SUCCESS
            
            $record = New-FileRecord -Path $Path -Status $StatusLevels.Success `
                -Type $itemType -Size $itemSize
            $RemediationResults.Files.Removed += $record
            $RemediationResults.Summary.PathsRemoved++
            return $StatusLevels.Success
            
        } else {
            Write-Log "    [FAILED] Still exists: $Path" -Level ERROR
            Write-Log "      This may indicate file/folder lock or protection" -Level ERROR
            
            $record = New-FileRecord -Path $Path -Status $StatusLevels.Failed `
                -Type $itemType -Size $itemSize `
                -ErrorMessage "Item still exists after removal attempt (may be locked)"
            $RemediationResults.Files.Failed += $record
            $RemediationResults.Summary.PathsFailed++
            return $StatusLevels.Failed
        }
        
    } catch {
        $errorMsg = $_.Exception.Message
        Write-Log "    [ERROR] Failed to remove $Path" -Level ERROR
        Write-Log "      Error: $errorMsg" -Level ERROR
        
        # Identify common error types
        if ($errorMsg -like "*Access is denied*") {
            Write-Log "      Reason: Access denied (may require elevated permissions)" -Level ERROR
        } elseif ($errorMsg -like "*being used by another process*") {
            Write-Log "      Reason: File is in use by another process" -Level ERROR
        }
        
        $record = New-FileRecord -Path $Path -Status $StatusLevels.Error `
            -ErrorMessage $errorMsg
        $RemediationResults.Files.Errored += $record
        $RemediationResults.Summary.PathsErrored++
        
        $RemediationResults.CriticalErrors += "File: $Path - $errorMsg"
        return $StatusLevels.Error
    }
}

# ============================================================================ #
# PRIMARY FUNCTIONS - FILE & FOLDER CLEANUP - Remove-MalwareFiles
# ============================================================================ #

function Remove-MalwareFiles {
    <#
    .SYNOPSIS
    Removes malware files and folders with comprehensive tracking
    .DESCRIPTION
    Systematically removes malware files in three phases:
    1. User-specific paths (AppData, Desktop, etc.)
    2. Downloads folder cleanup (installers, etc.)
    3. System-level paths
    
    Tracks all operations with detailed metrics and timing.
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [array]$UserPaths,
        
        [Parameter(Mandatory=$true)]
        [array]$DownloadPatterns,
        
        [Parameter(Mandatory=$true)]
        [array]$SystemPaths
    )
    
    # Module timing start
    $moduleStartTime = Get-Date
    
    Write-Log "========================================" -Level INFO
    Write-Log "FILE & FOLDER CLEANUP MODULE" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "Target user paths: $($UserPaths.Count)" -Level INFO
    Write-Log "Download patterns: $($DownloadPatterns.Count)" -Level INFO
    Write-Log "System paths: $($SystemPaths.Count)" -Level INFO
    
    # Phase counters
    $phase1Removed = 0
    $phase2Removed = 0
    $phase3Removed = 0
    
    # ========================================================================
    # PHASE 1: USER-SPECIFIC PATHS
    # ========================================================================
    
    Write-Log "" -Level INFO
    Write-Log "Phase 1: User-Specific Paths" -Level INFO
    Write-Log "  Targeting AppData, Desktop, Start Menu, etc." -Level INFO
    
    $userProfiles = Get-UserProfiles
    
    if ($userProfiles.Count -eq 0) {
        Write-Log "  [WARNING] No user profiles found" -Level WARNING
    } else {
        Write-Log "  Found $($userProfiles.Count) user profile(s)" -Level INFO
    }
    
    foreach ($user in $userProfiles) {
        Write-Log "  ---" -Level INFO
        Write-Log "  Processing user: $user" -Level INFO
        
        $userItemsChecked = 0
        $userItemsRemoved = 0
        
        foreach ($pathTemplate in $UserPaths) {
            $RemediationResults.Summary.PathsChecked++
            $userItemsChecked++
            
            # Replace {USER} placeholder
            $actualPath = $pathTemplate -replace '\{USER\}', $user
            
            # Handle wildcard patterns
            if ($actualPath -match '\*') {
                $parentPath = Split-Path $actualPath -Parent
                $pattern = Split-Path $actualPath -Leaf
                
                if (Test-Path $parentPath) {
                    $matchingItems = Get-ChildItem $parentPath -Filter $pattern -Force -ErrorAction SilentlyContinue
                    
                    if ($matchingItems) {
                        Write-Log "    Pattern: $pattern matched $($matchingItems.Count) item(s)" -Level INFO
                        foreach ($item in $matchingItems) {
                            $result = Remove-PathItem -Path $item.FullName
                            if ($result -eq $StatusLevels.Success) { 
                                $phase1Removed++
                                $userItemsRemoved++
                            } elseif ($result -eq $StatusLevels.NotFound) {
                                $record = New-FileRecord -Path $item.FullName -Status $StatusLevels.NotFound
                                $RemediationResults.Files.NotFound += $record
                                $RemediationResults.Summary.PathsNotFound++
                            }
                        }
                    }
                }
            } else {
                # Exact path match
                $result = Remove-PathItem -Path $actualPath
                
                if ($result -eq $StatusLevels.Success) {
                    $phase1Removed++
                    $userItemsRemoved++
                } elseif ($result -eq $StatusLevels.NotFound) {
                    $record = New-FileRecord -Path $actualPath -Status $StatusLevels.NotFound
                    $RemediationResults.Files.NotFound += $record
                    $RemediationResults.Summary.PathsNotFound++
                }
            }
        }
        
        Write-Log "  Summary for $user : Checked=$userItemsChecked Removed=$userItemsRemoved" -Level INFO
    }
    
    Write-Log "  Phase 1 Complete: $phase1Removed item(s) removed" -Level SUCCESS
    
    # ========================================================================
    # PHASE 2: DOWNLOADS FOLDER
    # ========================================================================
    
    Write-Log "" -Level INFO
    Write-Log "Phase 2: Downloads Folder Cleanup" -Level INFO
    Write-Log "  Searching for malware installers and packages" -Level INFO
    
    foreach ($user in $userProfiles) {
        $downloadsPath = "C:\Users\$user\Downloads"
        
        if (-not (Test-Path $downloadsPath)) {
            Write-Log "  No Downloads folder for: $user" -Level INFO
            continue
        }
        
        Write-Log "  ---" -Level INFO
        Write-Log "  Scanning: $downloadsPath" -Level INFO
        
        $downloadItemsFound = 0
        $downloadItemsRemoved = 0
        
        foreach ($pattern in $DownloadPatterns) {
            try {
                $files = Get-ChildItem $downloadsPath -Filter $pattern -File -Recurse -Force -ErrorAction SilentlyContinue
                
                if ($files) {
                    Write-Log "    Pattern '$pattern' matched $($files.Count) file(s)" -Level WARNING
                    $downloadItemsFound += $files.Count
                }
                
                foreach ($file in $files) {
                    $RemediationResults.Summary.PathsChecked++
                    $result = Remove-PathItem -Path $file.FullName
                    
                    if ($result -eq $StatusLevels.Success) {
                        $phase2Removed++
                        $downloadItemsRemoved++
                    } elseif ($result -eq $StatusLevels.NotFound) {
                        $record = New-FileRecord -Path $file.FullName -Status $StatusLevels.NotFound
                        $RemediationResults.Files.NotFound += $record
                        $RemediationResults.Summary.PathsNotFound++
                    }
                }
            } catch {
                Write-Log "    [ERROR] Pattern search failed: $pattern - $($_.Exception.Message)" -Level ERROR
            }
        }
        
        if ($downloadItemsFound -eq 0) {
            Write-Log "    [OK] No malware installers found" -Level SUCCESS
        } else {
            Write-Log "    Found=$downloadItemsFound Removed=$downloadItemsRemoved" -Level INFO
        }
    }
    
    Write-Log "  Phase 2 Complete: $phase2Removed item(s) removed" -Level SUCCESS
    
    # ========================================================================
    # PHASE 3: SYSTEM-LEVEL PATHS
    # ========================================================================
    
    Write-Log "" -Level INFO
    Write-Log "Phase 3: System-Level Paths" -Level INFO
    Write-Log "  Targeting system profile and protected directories" -Level INFO
    
    foreach ($path in $SystemPaths) {
        $RemediationResults.Summary.PathsChecked++
        
        # Handle wildcard patterns
        if ($path -match '\*') {
            $parentPath = Split-Path $path -Parent
            $pattern = Split-Path $path -Leaf
            
            if (Test-Path $parentPath) {
                Write-Log "  Searching: $parentPath\$pattern" -Level INFO
                $items = Get-ChildItem $parentPath -Filter $pattern -Force -ErrorAction SilentlyContinue
                
                if ($items) {
                    Write-Log "    Found $($items.Count) matching item(s)" -Level WARNING
                    foreach ($item in $items) {
                        $result = Remove-PathItem -Path $item.FullName
                        
                        if ($result -eq $StatusLevels.Success) {
                            $phase3Removed++
                        } elseif ($result -eq $StatusLevels.NotFound) {
                            $record = New-FileRecord -Path $item.FullName -Status $StatusLevels.NotFound
                            $RemediationResults.Files.NotFound += $record
                            $RemediationResults.Summary.PathsNotFound++
                        }
                    }
                } else {
                    Write-Log "    [NOT FOUND] No matches for: $pattern" -Level INFO
                }
            } else {
                Write-Log "  [NOT FOUND] Parent path does not exist: $parentPath" -Level INFO
                $record = New-FileRecord -Path $path -Status $StatusLevels.NotFound
                $RemediationResults.Files.NotFound += $record
                $RemediationResults.Summary.PathsNotFound++
            }
        } else {
            # Exact path
            Write-Log "  Checking: $path" -Level INFO
            $result = Remove-PathItem -Path $path
            
            if ($result -eq $StatusLevels.Success) {
                $phase3Removed++
            } elseif ($result -eq $StatusLevels.NotFound) {
                Write-Log "    [NOT FOUND] Path does not exist" -Level INFO
                $record = New-FileRecord -Path $path -Status $StatusLevels.NotFound
                $RemediationResults.Files.NotFound += $record
                $RemediationResults.Summary.PathsNotFound++
            }
        }
    }
    
    Write-Log "  Phase 3 Complete: $phase3Removed item(s) removed" -Level SUCCESS
    
    # ========================================================================
    # MODULE SUMMARY
    # ========================================================================
    
    # Module timing end
    $moduleEndTime = Get-Date
    Write-ModuleTiming -ModuleName "Files" -StartTime $moduleStartTime -EndTime $moduleEndTime
    
    Write-Log "" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "FILE & FOLDER CLEANUP SUMMARY" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "PHASE BREAKDOWN:" -Level INFO
    Write-Log "  Phase 1 (User Paths): $phase1Removed removed" -Level INFO
    Write-Log "  Phase 2 (Downloads): $phase2Removed removed" -Level INFO
    Write-Log "  Phase 3 (System): $phase3Removed removed" -Level INFO
    Write-Log "  ---" -Level INFO
    Write-Log "OVERALL STATISTICS:" -Level INFO
    Write-Log "  Paths Checked: $($RemediationResults.Summary.PathsChecked)" -Level INFO
    Write-Log "  Paths Found: $($RemediationResults.Summary.PathsFound)" -Level INFO
    Write-Log "  Paths Removed: $($RemediationResults.Summary.PathsRemoved)" -Level SUCCESS
    Write-Log "  Paths Failed: $($RemediationResults.Summary.PathsFailed)" -Level ERROR
    Write-Log "  Paths Errored: $($RemediationResults.Summary.PathsErrored)" -Level ERROR
    Write-Log "  Paths Not Found: $($RemediationResults.Summary.PathsNotFound)" -Level INFO
    
    if ($RemediationResults.Summary.PathsFailed -gt 0 -or $RemediationResults.Summary.PathsErrored -gt 0) {
        Write-Log "  ---" -Level WARNING
        Write-Log "  WARNING: Some items could not be removed" -Level WARNING
        Write-Log "  Common causes: File locks, permissions, or active processes" -Level WARNING
        Write-Log "  Recommendation: Review Critical Errors in final report" -Level WARNING
    }
    
    Write-Log "========================================" -Level INFO
}

# ============================================================================ #
#  PRIMARY FUNCTIONS - REGISTRY CLEANUP (ARTIFACTS & CONFIGURATION)
# ============================================================================ #

# ============================================================================ #
#  PRIMARY FUNCTIONS - REGISTRY CLEANUP (ARTIFACTS & CONFIGURATION) - Remove-RegistryKeyRecursive
# ============================================================================ #

function Remove-RegistryKeyRecursive {
    <#
    .SYNOPSIS
    Removes a registry key and all subkeys with detailed tracking
    #>
    param(
        [string]$KeyPath
    )
    
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
            return "SUCCESS"
            
        } else {
            Write-Log "    [FAILED] Key still exists (may be kernel protected)" -Level ERROR
            
            $record = New-RegistryKeyRecord -KeyPath $KeyPath -Status "FAILED" `
                -SubkeyCount $keyDetails.SubkeyCount -ValueCount $keyDetails.ValueCount `
                -ErrorMessage "Key still exists after removal (possible kernel protection)"
            $RemediationResults.Registry.Failed += $record
            return "FAILED"
        }
        
    } catch {
        $errorMsg = $_.Exception.Message
        Write-Log "    [ERROR] Failed to remove: $errorMsg" -Level ERROR
        
        if ($errorMsg -like "*Access is denied*" -or $errorMsg -like "*protected*") {
            Write-Log "    [!] Key may be kernel-level protected" -Level ERROR
            Write-Log "    [!] Manual removal or specialized tools may be required" -Level ERROR
        }
        
        $record = New-RegistryKeyRecord -KeyPath $KeyPath -Status "ERROR" `
            -SubkeyCount $keyDetails.SubkeyCount -ValueCount $keyDetails.ValueCount `
            -ErrorMessage $errorMsg
        $RemediationResults.Registry.Errored += $record
        
        $RemediationResults.CriticalErrors += "Registry: $KeyPath - $errorMsg"
        return "ERROR"
    }
}

# ============================================================================ #
#  PRIMARY FUNCTIONS - REGISTRY CLEANUP (ARTIFACTS & CONFIGURATION) - Remove-MalwareRegistryKeys
# ============================================================================ #

function Remove-MalwareRegistryKeys {
    <#
    .SYNOPSIS
    Removes malware registry keys (artifacts and configuration)
    .DESCRIPTION
    Cleans up registry keys left behind by malware, including:
    - HKLM system-wide configuration
    - Per-user settings in HKU hives
    - COM object registrations
    - Uninstall entries
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [array]$HKLMPaths,
        
        [Parameter(Mandatory=$true)]
        [array]$HKUPatterns
    )
    
    # Start timing
    $moduleStart = Get-Date
    
    Write-Log "========================================" -Level INFO
    Write-Log "REGISTRY CLEANUP MODULE (ARTIFACTS)" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "Target HKLM paths: $($HKLMPaths.Count)" -Level INFO
    Write-Log "Target HKU patterns: $($HKUPatterns.Count)" -Level INFO
    
    # ========================================================================
    # PHASE 1: HKLM (Local Machine) Registry Keys
    # ========================================================================
    
    Write-Log "" -Level INFO
    Write-Log "Phase 1: Removing HKLM registry keys..." -Level INFO
    
    $phase1Results = @{
        Checked = 0
        Found = 0
        Removed = 0
        Failed = 0
        Errored = 0
        NotFound = 0
    }
    
    foreach ($keyPath in $HKLMPaths) {
        $phase1Results.Checked++
        $RemediationResults.Summary.RegistryKeysChecked++
        
        $result = Remove-RegistryKeyRecursive -KeyPath $keyPath
        
        switch ($result) {
            "SUCCESS" { 
                $phase1Results.Found++
                $phase1Results.Removed++
                $RemediationResults.Summary.RegistryValuesRemoved++
            }
            "FAILED" {
                $phase1Results.Found++
                $phase1Results.Failed++
                $RemediationResults.Summary.RegistryValuesFailed++
            }
            "ERROR" {
                $phase1Results.Found++
                $phase1Results.Errored++
                $RemediationResults.Summary.RegistryValuesErrored++
            }
            "NOT_FOUND" {
                $phase1Results.NotFound++
                $RemediationResults.Summary.RegistryValuesNotFound++
            }
        }
    }
    
    Write-Log "" -Level INFO
    Write-Log "Phase 1 Results:" -Level INFO
    Write-Log "  Checked: $($phase1Results.Checked) | Found: $($phase1Results.Found) | Removed: $($phase1Results.Removed) | Failed: $($phase1Results.Failed)" -Level INFO
    
    # ========================================================================
    # PHASE 2: HKU (Per-User) Registry Keys
    # ========================================================================
    
    Write-Log "" -Level INFO
    Write-Log "Phase 2: Removing per-user registry keys..." -Level INFO
    
    $userSIDs = Get-UserSIDs
    Write-Log "  Found $($userSIDs.Count) user profile(s)" -Level INFO
    
    if ($userSIDs.Count -eq 0) {
        Write-Log "  [WARNING] No user SIDs found - skipping HKU cleanup" -Level WARNING
    }
    
    $phase2Results = @{
        Checked = 0
        Found = 0
        Removed = 0
        Failed = 0
        Errored = 0
        NotFound = 0
        PatternsWithMatches = 0
    }
    
    foreach ($sid in $userSIDs) {
        Write-Log "" -Level INFO
        Write-Log "  Processing SID: $sid" -Level INFO
        
        foreach ($pattern in $HKUPatterns) {
            $basePath = "Registry::HKU\$sid"
            $searchPath = "$basePath\$pattern"
            
            # ----------------------------------------------------------------
            # Handle wildcard patterns
            # ----------------------------------------------------------------
            if ($pattern -match '\*') {
                Write-Log "    Searching pattern: $pattern" -Level INFO
                
                # Split pattern to find where wildcard starts
                $parts = $pattern -split '\\'
                $currentPath = $basePath
                
                # Build path up to first wildcard
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
                    
                    try {
                        $matchingKeys = Get-ChildItem $currentPath -ErrorAction SilentlyContinue |
                            Where-Object { $_.PSChildName -like $searchPattern }
                        
                        if ($matchingKeys) {
                            $phase2Results.PatternsWithMatches++
                            Write-Log "      [FOUND] $($matchingKeys.Count) key(s) match pattern '$searchPattern'" -Level WARNING
                            
                            foreach ($key in $matchingKeys) {
                                $phase2Results.Checked++
                                $RemediationResults.Summary.RegistryKeysChecked++
                                
                                $result = Remove-RegistryKeyRecursive -KeyPath $key.PSPath
                                
                                switch ($result) {
                                    "SUCCESS" { 
                                        $phase2Results.Found++
                                        $phase2Results.Removed++
                                        $RemediationResults.Summary.RegistryValuesRemoved++
                                    }
                                    "FAILED" {
                                        $phase2Results.Found++
                                        $phase2Results.Failed++
                                        $RemediationResults.Summary.RegistryValuesFailed++
                                    }
                                    "ERROR" {
                                        $phase2Results.Found++
                                        $phase2Results.Errored++
                                        $RemediationResults.Summary.RegistryValuesErrored++
                                    }
                                }
                            }
                        } else {
                            Write-Log "      [NOT FOUND] No keys match pattern '$searchPattern'" -Level INFO
                            $phase2Results.NotFound++
                            
                            $record = New-RegistryKeyRecord -KeyPath $searchPath -Status "NOT_FOUND"
                            $RemediationResults.Registry.NotFound += $record
                        }
                    } catch {
                        Write-Log "      [ERROR] Failed to search pattern: $($_.Exception.Message)" -Level ERROR
                        $phase2Results.Errored++
                        $RemediationResults.Summary.RegistryValuesErrored++
                    }
                } else {
                    Write-Log "      [NOT FOUND] Base path does not exist: $currentPath" -Level INFO
                    $phase2Results.NotFound++
                    
                    $record = New-RegistryKeyRecord -KeyPath $searchPath -Status "NOT_FOUND"
                    $RemediationResults.Registry.NotFound += $record
                }
                
            } else {
                # ----------------------------------------------------------------
                # Handle exact path (no wildcards)
                # ----------------------------------------------------------------
                $phase2Results.Checked++
                $RemediationResults.Summary.RegistryKeysChecked++
                
                $result = Remove-RegistryKeyRecursive -KeyPath $searchPath
                
                switch ($result) {
                    "SUCCESS" { 
                        $phase2Results.Found++
                        $phase2Results.Removed++
                        $RemediationResults.Summary.RegistryValuesRemoved++
                    }
                    "FAILED" {
                        $phase2Results.Found++
                        $phase2Results.Failed++
                        $RemediationResults.Summary.RegistryValuesFailed++
                    }
                    "ERROR" {
                        $phase2Results.Found++
                        $phase2Results.Errored++
                        $RemediationResults.Summary.RegistryValuesErrored++
                    }
                    "NOT_FOUND" {
                        $phase2Results.NotFound++
                        $RemediationResults.Summary.RegistryValuesNotFound++
                    }
                }
            }
        } # End foreach pattern
    } # End foreach SID
    
    Write-Log "" -Level INFO
    Write-Log "Phase 2 Results:" -Level INFO
    Write-Log "  Patterns with matches: $($phase2Results.PatternsWithMatches)" -Level INFO
    Write-Log "  Checked: $($phase2Results.Checked) | Found: $($phase2Results.Found) | Removed: $($phase2Results.Removed) | Failed: $($phase2Results.Failed)" -Level INFO
    
    # ========================================================================
    # MODULE SUMMARY & TIMING
    # ========================================================================
    
    $moduleEnd = Get-Date
    Write-ModuleTiming -ModuleName "RegistryCleanup" -StartTime $moduleStart -EndTime $moduleEnd
    
    Write-Log "" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "REGISTRY CLEANUP SUMMARY" -Level INFO
    Write-Log "  Keys Checked: $($RemediationResults.Summary.RegistryKeysChecked)" -Level INFO
    Write-Log "  Keys Removed: $($RemediationResults.Summary.RegistryValuesRemoved)" -Level SUCCESS
    Write-Log "  Keys Failed: $($RemediationResults.Summary.RegistryValuesFailed)" -Level ERROR
    Write-Log "  Keys Errored: $($RemediationResults.Summary.RegistryValuesErrored)" -Level ERROR
    Write-Log "  Keys Not Found: $($RemediationResults.Summary.RegistryValuesNotFound)" -Level INFO
    
    if ($RemediationResults.Summary.RegistryValuesFailed -gt 0) {
        Write-Log "" -Level WARNING
        Write-Log "  [!] Some registry keys could not be removed" -Level WARNING
        Write-Log "  [!] These may be kernel-level protected" -Level WARNING
        Write-Log "  [!] Review detailed log for specific keys" -Level WARNING
    }
    
    Write-Log "========================================" -Level INFO
}

# ============================================================================ #
#  PRIMARY FUNCTIONS - BROWSER ENTRY CLEANUP
# ============================================================================ #

# ============================================================================ #
# PRIMARY FUNCTIONS - BROWSER ENTRY CLEANUP - Remove-BrowserEntry
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
    
    $RemediationResults.Summary.BrowserEntriesFound++
    
    try {
        Write-Log "    [FOUND] $EntryType : $KeyPath" -Level WARNING
        
        Remove-Item -Path $KeyPath -Recurse -Force -ErrorAction Stop
        Start-Sleep -Milliseconds 200
        
        if (-not (Test-Path $KeyPath)) {
            Write-Log "    [SUCCESS] Removed: $KeyPath" -Level SUCCESS
            
            $record = New-BrowserRecord -EntryPath $KeyPath -EntryType $EntryType -Status "REMOVED"
            $RemediationResults.BrowserEntries.Removed += $record
            $RemediationResults.Summary.BrowserEntriesRemoved++
            return "SUCCESS"
        } else {
            Write-Log "    [FAILED] Still exists: $KeyPath" -Level ERROR
            
            $record = New-BrowserRecord -EntryPath $KeyPath -EntryType $EntryType `
                -Status "FAILED" -ErrorMessage "Key still exists after removal"
            $RemediationResults.BrowserEntries.Failed += $record
            $RemediationResults.Summary.BrowserEntriesFailed++
            return "FAILED"
        }
    } catch {
        $errorMsg = $_.Exception.Message
        Write-Log "    [ERROR] Failed to remove: $errorMsg" -Level ERROR
        
        $record = New-BrowserRecord -EntryPath $KeyPath -EntryType $EntryType `
            -Status "ERROR" -ErrorMessage $errorMsg
        $RemediationResults.BrowserEntries.Errored += $record
        $RemediationResults.Summary.BrowserEntriesErrored++
        
        $RemediationResults.CriticalErrors += "Browser Entry: $KeyPath - $errorMsg"
        return "ERROR"
    }
}

# ============================================================================ #
# PRIMARY FUNCTIONS - BROWSER ENTRY CLEANUP - Remove-MalwareBrowserEntries
# ============================================================================ #

function Remove-MalwareBrowserEntries {
    <#
    .SYNOPSIS
    Removes browser hijacking registry entries
    .DESCRIPTION
    Cleans up:
    - StartMenuInternet registrations (HKLM and per-user)
    - ProgID classes (HKLM\Software\Classes and per-user)
    - UserChoice associations (noted but not removed - Windows protected)
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [array]$BrowserPatterns,
        
        [Parameter(Mandatory=$false)]
        [array]$FeatureUsagePatterns = @()
    )
    
    $moduleStartTime = Get-Date
    
    Write-Log "========================================" -Level INFO
    Write-Log "BROWSER ENTRY CLEANUP MODULE" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "Removes browser hijacking to prevent false inventory detections" -Level INFO
    Write-Log "Target patterns: $($BrowserPatterns.Count)" -Level INFO
    
    # ========================================================================
    # PHASE 1: HKLM StartMenuInternet Registrations
    # ========================================================================
    
    Write-Log "" -Level INFO
    Write-Log "Phase 1: Removing HKLM StartMenuInternet entries..." -Level INFO
    
    $hklmBrowserPath = "HKLM:\Software\Clients\StartMenuInternet"
    
    if (Test-Path $hklmBrowserPath) {
        foreach ($pattern in $BrowserPatterns) {
            $matchingKeys = Get-ChildItem $hklmBrowserPath -ErrorAction SilentlyContinue |
                Where-Object { $_.PSChildName -like $pattern }
            
            if ($matchingKeys) {
                Write-Log "  Found $($matchingKeys.Count) HKLM browser registration(s) matching '$pattern'" -Level WARNING
                foreach ($key in $matchingKeys) {
                    $RemediationResults.Summary.BrowserEntriesChecked++
                    $RemediationResults.Summary.BrowserEntriesFound++
                    
                    $result = Remove-BrowserEntry -KeyPath $key.PSPath -EntryType "HKLM Browser Registration"
                }
            } else {
                Write-Log "  [NOT FOUND] No HKLM browser registrations match '$pattern'" -Level INFO
            }
        }
    } else {
        Write-Log "  [NOT FOUND] HKLM StartMenuInternet path does not exist" -Level INFO
    }
    
    # ========================================================================
    # PHASE 2: Per-User StartMenuInternet Registrations
    # ========================================================================
    
    Write-Log "" -Level INFO
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
                        $RemediationResults.Summary.BrowserEntriesChecked++
                        $RemediationResults.Summary.BrowserEntriesFound++
                        
                        $result = Remove-BrowserEntry -KeyPath $key.PSPath -EntryType "User Browser Registration"
                    }
                }
            }
        }
    }
    
    # ========================================================================
    # PHASE 3: ProgID Classes (HKLM and Per-User)
    # ========================================================================
    
    Write-Log "" -Level INFO
    Write-Log "Phase 3: Removing ProgID classes..." -Level INFO
    
    # HKLM ProgID Classes
    $hklmClassesPath = "HKLM:\Software\Classes"
    if (Test-Path $hklmClassesPath) {
        foreach ($pattern in $BrowserPatterns) {
            $matchingKeys = Get-ChildItem $hklmClassesPath -ErrorAction SilentlyContinue |
                Where-Object { $_.PSChildName -like $pattern }
            
            if ($matchingKeys) {
                Write-Log "  Found $($matchingKeys.Count) HKLM ProgID class(es)" -Level WARNING
                foreach ($key in $matchingKeys) {
                    $RemediationResults.Summary.BrowserEntriesChecked++
                    $RemediationResults.Summary.BrowserEntriesFound++
                    
                    $result = Remove-BrowserEntry -KeyPath $key.PSPath -EntryType "HKLM ProgID Class"
                }
            }
        }
    }
    
    # Per-User ProgID Classes
    foreach ($sid in $userSIDs) {
        $hkuClassesPath = "Registry::HKU\$sid\Software\Classes"
        
        if (Test-Path $hkuClassesPath) {
            foreach ($pattern in $BrowserPatterns) {
                $matchingKeys = Get-ChildItem $hkuClassesPath -ErrorAction SilentlyContinue |
                    Where-Object { $_.PSChildName -like $pattern }
                
                if ($matchingKeys) {
                    Write-Log "    Found $($matchingKeys.Count) user ProgID class(es)" -Level WARNING
                    foreach ($key in $matchingKeys) {
                        $RemediationResults.Summary.BrowserEntriesChecked++
                        $RemediationResults.Summary.BrowserEntriesFound++
                        
                        $result = Remove-BrowserEntry -KeyPath $key.PSPath -EntryType "User ProgID Class"
                    }
                }
            }
        }
    }
    
    # ========================================================================
    # PHASE 4: UserChoice Associations (PROTECTED - REPORT ONLY)
    # ========================================================================
    
    if ($FeatureUsagePatterns.Count -gt 0) {
        Write-Log "" -Level INFO
        Write-Log "Phase 4: Checking UserChoice associations..." -Level INFO
        Write-Log "  Note: UserChoice keys are hash-protected by Windows" -Level INFO
        Write-Log "  These entries will be reported but NOT removed" -Level INFO
        
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
                                        $RemediationResults.Summary.BrowserEntriesChecked++
                                        $RemediationResults.Summary.BrowserEntriesFound++
                                        
                                        Write-Log "    [FOUND] UserChoice for $($ext.PSChildName) : $progId" -Level WARNING
                                        Write-Log "      Status: PROTECTED (hash-protected by Windows)" -Level INFO
                                        Write-Log "      Action: REPORT ONLY - Will reset when user changes default" -Level INFO
                                        
                                        $details = @{
                                            Extension = $ext.PSChildName
                                            ProgId = $progId
                                            Protection = "Windows UserChoice Hash"
                                        }
                                        
                                        $record = New-BrowserRecord -EntryPath $userChoiceKey `
                                            -EntryType "UserChoice (Protected)" -Status $StatusLevels.Protected `
                                            -Details $details
                                        $RemediationResults.BrowserEntries.Noted += $record
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
    }
    
    # ========================================================================
    # MODULE COMPLETION & TIMING
    # ========================================================================
    
    $moduleEndTime = Get-Date
    Write-ModuleTiming -ModuleName "BrowserEntries" -StartTime $moduleStartTime -EndTime $moduleEndTime
    
    Write-Log "" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "BROWSER ENTRY CLEANUP SUMMARY" -Level INFO
    Write-Log "  Entries Checked: $($RemediationResults.Summary.BrowserEntriesChecked)" -Level INFO
    Write-Log "  Entries Found: $($RemediationResults.Summary.BrowserEntriesFound)" -Level INFO
    Write-Log "  Entries Removed: $($RemediationResults.Summary.BrowserEntriesRemoved)" -Level SUCCESS
    Write-Log "  Entries Failed: $($RemediationResults.Summary.BrowserEntriesFailed)" -Level ERROR
    Write-Log "  Entries Errored: $($RemediationResults.Summary.BrowserEntriesErrored)" -Level ERROR
    Write-Log "  UserChoice (Protected): $($RemediationResults.BrowserEntries.Noted.Count)" -Level INFO
    Write-Log "  Note: UserChoice keys are Windows-protected and will reset naturally" -Level INFO
    Write-Log "========================================" -Level INFO
}


# ============================================================================ #
# PRIMARY FUNCTIONS - FILE ASSOCIATION CLEANUP
# ============================================================================ #

# ============================================================================ #
# PRIMARY FUNCTIONS - FILE ASSOCIATION CLEANUP - Remove-MalwareFileAssociations
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
Write-Log "Version: $($MalwareConfig.Metadata.Version)" -Level INFO
Write-Log "Threat Family: $($MalwareConfig.Metadata.ThreatFamily)" -Level INFO
Write-Log "Severity: $($MalwareConfig.Metadata.Severity)" -Level INFO
Write-Log "Started: $($RemediationResults.StartTime)" -Level INFO
Write-Log "============================================" -Level INFO

# 1. PROCESSES - Stop active threats immediately
Stop-MalwareProcess -ProcessNames $MalwareConfig.Processes
Start-Sleep -Seconds 2

# 2. SERVICES - Prevent automatic restart of processes
Stop-MalwareService -ServiceNames $MalwareConfig.Services
Start-Sleep -Seconds 2

# 3. CERTIFICATES - Remove malicious trust anchors (prevents re-trust)
Remove-MalwareCertificates -CertConfig $MalwareConfig.Certificates
Start-Sleep -Seconds 2

# 4. SCHEDULED TASKS - Remove persistence (can restart services/processes)
Remove-MalwareTask -TaskPatterns $MalwareConfig.TaskPatterns
Start-Sleep -Seconds 2

# 5. REGISTRY - RUN KEYS - Remove autostart entries (another persistence layer)
Remove-MalwareRegistryPersistence -RunKeyPatterns $MalwareConfig.RunKeyPatterns `
    -RegisteredAppPatterns $MalwareConfig.RegisteredAppPatterns `
    -FeatureUsagePatterns $MalwareConfig.FeatureUsagePatterns
Start-Sleep -Seconds 2

# 6. FILES & FOLDERS - Safe to remove now (nothing using them)
Remove-MalwareFiles -UserPaths $MalwareConfig.UserPaths `
    -DownloadPatterns $MalwareConfig.DownloadPatterns `
    -SystemPaths $MalwareConfig.SystemPaths
Start-Sleep -Seconds 2

# 7. REGISTRY - CLEANUP - Remove remaining configuration/artifacts
Remove-MalwareRegistryKeys -HKLMPaths $MalwareConfig.RegistryHKLM `
    -HKUPatterns $MalwareConfig.RegistryHKUPatterns
Start-Sleep -Seconds 2

# 8. BROWSER ENTRIES - Clean up browser hijacking (ProgID, StartMenuInternet)
Remove-MalwareBrowserEntries -BrowserPatterns $MalwareConfig.BrowserStartMenuPatterns `
    -FeatureUsagePatterns $MalwareConfig.FeatureUsagePatterns
Start-Sleep -Seconds 2

# 9. FILE ASSOCIATIONS - Remove orphaned ApplicationAssociationToasts
if ($MalwareConfig.ApplicationAssociationPatterns) {
    Remove-MalwareFileAssociations -AssociationPatterns $MalwareConfig.ApplicationAssociationPatterns
    Start-Sleep -Seconds 2
}

# ============================================================================ #
# CALCULATIONS FOR FINAL REPORT
# ============================================================================ #

# Calculate overall totals
$RemediationResults.Summary.TotalActionsAttempted = 
    $RemediationResults.Summary.ProcessesChecked +
    $RemediationResults.Summary.ServicesChecked +
    $RemediationResults.Summary.TasksChecked +
    $RemediationResults.Summary.RegistryKeysChecked +
    $RemediationResults.Summary.PathsChecked +
    $RemediationResults.Summary.FileAssociationsChecked

$RemediationResults.Summary.TotalActionsSuccessful = 
    $RemediationResults.Summary.ProcessesTerminated +
    $RemediationResults.Summary.ServicesRemoved +
    $RemediationResults.Summary.TasksRemoved +
    $RemediationResults.Summary.RegistryValuesRemoved +
    $RemediationResults.Summary.PathsRemoved

$RemediationResults.Summary.TotalActionsFailed = 
    $RemediationResults.Summary.ProcessesFailed +
    $RemediationResults.Summary.ServicesFailed +
    $RemediationResults.Summary.TasksFailed +
    $RemediationResults.Summary.RegistryValuesFailed +
    $RemediationResults.Summary.PathsFailed

# ============================================================================ #
# FINAL REPORT
# ============================================================================ #

$RemediationResults.EndTime = Get-Date
$duration = $RemediationResults.EndTime - $RemediationResults.StartTime

Write-Log "============================================" -Level INFO
Write-Log "REMEDIATION COMPLETE" -Level SUCCESS
Write-Log "Threat: $($MalwareConfig.Name) ($($MalwareConfig.Metadata.ThreatFamily))" -Level INFO
Write-Log "Severity: $($MalwareConfig.Metadata.Severity)" -Level INFO
Write-Log "Script Version: $($MalwareConfig.Metadata.Version)" -Level INFO
Write-Log "Duration: $($duration.TotalSeconds) seconds" -Level INFO
Write-Log "Log File: $logFile" -Level INFO
Write-Log "============================================" -Level INFO
Write-Log "" -Level INFO
Write-Log "FINAL SUMMARY" -Level INFO
Write-Log "Processes: Checked=$($RemediationResults.Summary.ProcessesChecked) Terminated=$($RemediationResults.Summary.ProcessesTerminated) Failed=$($RemediationResults.Summary.ProcessesFailed)" -Level INFO
Write-Log "Services: Checked=$($RemediationResults.Summary.ServicesChecked) Removed=$($RemediationResults.Summary.ServicesRemoved) Failed=$($RemediationResults.Summary.ServicesFailed)" -Level INFO
Write-Log "Certificates: Scanned=$($RemediationResults.Summary.CertificatesScanned) Flagged=$($RemediationResults.Summary.CertificatesFlagged) Removed=$($RemediationResults.Summary.CertificatesRemoved) Failed=$($RemediationResults.Summary.CertificatesFailed)" -Level INFO
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