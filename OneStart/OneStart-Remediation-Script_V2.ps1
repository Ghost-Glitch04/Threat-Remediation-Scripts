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
        Version = "2.1.0"  # UPDATED
        LastUpdated = "2026-02-05"  # UPDATED
        Author = "sentinelrshuser"
        ThreatFamily = "OneStart.AI"
        FirstSeen = "2023-10"
        Severity = "HIGH"
        Description = "Browser hijacker and PUP that installs unwanted certificates and modifies browser settings. Distributed via rebranded PDF utilities."
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
        "ManualFinderApp",
        "AppSuites",
        "AppSuitesPDF",
        "AppSuitesService",
        # NEW - PDF Rebranding Variants (from VT report)
        "pdfzonepro",
        "viewpdftools",
        "SmartPDFPro",
        "easypdfbox",
        "thepdfonestart",
        "smartonestartpdf",
        "smartviewpdf",
        "pdfguruhub",
        "allpdfpro",
        "proonestarthub",
        "proonestartpdf",
        "SmartEasyPDF",
        "onestartpdfdirect",
        "getonestartpdf",
        "PDFSmartKit"
    )
    
    # ----------------------------------------------------------------------------
    # MALWARE CONFIGURATION - Services
    # ----------------------------------------------------------------------------

    # Service names to stop and remove
    Services = @(
        "OneStartService",
        "PDFEditorService",
        "AppSuitesService"  # Added for completeness
    )
    
    # ----------------------------------------------------------------------------
    # MALWARE CONFIGURATION - Certificates
    # ----------------------------------------------------------------------------

    # Certificate Configuration
    Certificates = @{
        # Known malicious certificate thumbprints (PRIORITY 1 - REMOVE)
        MaliciousThumbprints = @(
            "612DE7BA0369AFF3507DFF7A39DF2F4F7A82E51D",  # OneStart Technologies LLC
            "BCBAA4F693051D69280D19D69DE73832B77B1C25",  # OneStart Technologies LLC
            "A2278EB6A438DC528F3EBFEB238028C474401BEF",  # Echo Infini Sdn. Bhd.
            "B515DF656EE4C27ED1F9FEBC2CE6F9756E6F023B"   # NEW - Apollo Technologies Inc. (REVOKED)
        )
        
        # Known malicious certificate serial numbers (PRIORITY 2 - REMOVE)
        MaliciousSerialNumbers = @(
            "0333EAFBA707AABFD12644AEDC2E8C4E",                    # OneStart Technologies LLC
            "03 33 EA FB A7 07 AA BF D1 26 44 AE DC 2E 8C 4E",     # OneStart Technologies LLC (formatted)
            "582C3A4B9934B7EC1028B638",                            # Echo Infini Sdn. Bhd.
            "58 2C 3A 4B 99 34 B7 EC 10 28 B6 38",                 # Echo Infini Sdn. Bhd. (formatted)
            "7209B6BCFD61AFA5A476DBF0",                            # NEW - Apollo Technologies Inc.
            "72 09 B6 BC FD 61 AF A5 A4 76 DB F0"                  # NEW - Apollo Technologies Inc. (formatted)
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
            "Debug",
            "Echo Infini",
            "Apollo Technologies"  # NEW - Certificate holder name
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
            "Comodo",
            "GlobalSign"  # Added legitimate CA (note: GlobalSign issued the malicious cert but is itself legitimate)
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
        "sys_component_health_*",
        "AppSuitesTask*"  # Added for AppSuites variant
    )
    
    # ----------------------------------------------------------------------------
    # MALWARE CONFIGURATION - Run Keys
    # ----------------------------------------------------------------------------

    # Registry value patterns to remove from Run keys
    RunKeyPatterns = @(
        "OneStart*",                      # Catches: OneStart, OneStartUpdate, OneStartBar, etc.
        "OneStartChromium*",              # Specific entry from VT report
        "OneStartUpdate*",                # Specific entry from VT report
        "OneStartAutoLaunch*",            # NEW - Catches GUID-based variants like OneStartAutoLaunch_1F8E33510187504C724E98C50417C6C3
        "OneStartUpdaterTaskUser*",
        "AppSuites*",
        "AppSuitesPDF*",
        "PDFEditor*",
        # NEW - PDF Utility Rebrands (may have their own Run keys)
        "pdfzonepro*",
        "viewpdftools*",
        "SmartPDFPro*",
        "PDFSmartKit*"
    )
    
    # Registered applications patterns
    RegisteredAppPatterns = @(
        "OneStart*",
        "AppSuites*",
        "PDFZonePro*",      # NEW
        "SmartPDFPro*",     # NEW
        "ViewPDFTools*"     # NEW
    )
    
    # User-specific paths (exact matches only)
    UserPaths = @(
        "C:\Users\{USER}\AppData\Local\OneStart.ai",
        "C:\Users\{USER}\OneStart.ai",
        "C:\Users\{USER}\AppData\Local\AppSuites",
        "C:\Users\{USER}\AppData\Roaming\AppSuites",
        # NEW - OneStart Installer temp folder (from VT report behavior)
        "C:\Users\{USER}\AppData\Local\OneStart.ai\OneStart Installer",
        "C:\Users\{USER}\Desktop\OneStart.lnk",
        "C:\Users\{USER}\Desktop\AppSuites*.lnk",
        "C:\Users\{USER}\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\OneStart.lnk",
        "C:\Users\{USER}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneStart.lnk",
        "C:\Users\{USER}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\PDF Editor.lnk",
        "C:\Users\{USER}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\AppSuites*.lnk",
        "C:\Users\{USER}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\OneStart*.lnk",
        "C:\Users\{USER}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\PDFEditor*.lnk",
        "C:\Users\{USER}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\AppSuites*.lnk",
        "C:\Users\{USER}\AppData\Roaming\NodeJs",
        "C:\Users\{USER}\AppData\Roaming\PDF Editor",
        "C:\Users\{USER}\AppData\Roaming\AP-2E99C4AA-3F56-48BB-A947-2EDA163E765F",
        "C:\Users\{USER}\AppData\Roaming\PDF Editor\*.node",
        "C:\Users\{USER}\AppData\Local\OneStart.ai\*.node",
        # Communication/Temp Files
        "C:\Users\{USER}\AppData\Roaming\Microsoft\Templates\~$Normal.dotm",
        "C:\Users\{USER}\AppData\Local\Temp\nw*_*.tmp",
        "C:\Users\{USER}\AppData\Local\Temp\OneStart*",
        "C:\Users\{USER}\AppData\Local\Temp\AppSuites*",
        "C:\Users\{USER}\AppData\Roaming\PDF Editor\Cache",
        "C:\Users\{USER}\AppData\Local\OneStart.ai\Cache",
        "C:\Users\{USER}\AppData\Local\OneStart.ai\OneStart\Application"  # NEW - Main installation path from VT report
    )
    
    # ----------------------------------------------------------------------------
    # MALWARE CONFIGURATION - Files and Folders
    # ----------------------------------------------------------------------------

    # Download folder patterns (specific to OneStart)
    DownloadPatterns = @(
        "OneStart*.exe",
        "*OneStart*.msi",
        "*AppSuites*.msi",
        "AppSuites-PDF*.msi",
        "*2005578.msi",
        "PDFEditor*.msi",
        # NEW - Rebranded PDF installer patterns (from VT report file names)
        "pdfzonepro*.msi",
        "viewpdftools*.msi",
        "SmartPDFPro*.msi",
        "easypdfbox*.msi",
        "thepdfonestart*.msi",
        "smartonestartpdf*.msi",
        "smartviewpdf*.msi",
        "pdfguruhub*.msi",
        "PDFOneStartLive*.msi",
        "allpdfpro*.msi",
        "proonestarthub*.msi",
        "proonestartpdf*.msi",
        "SmartEasyPDF*.msi",
        "onestartpdfdirect*.msi",
        "getonestartpdf*.msi",
        "PDFSmartKit*.msi",
        "smartpdfpro*.msi",
        # Installers that may be downloaded
        "onestart_installer*.exe",  # NEW - From VT network activity
        "*41def9.msi",               # NEW - Obfuscated name variant
        "OneStartPDF-v*.msi"         # NEW - Versioned installers
    )
    
    # System-level paths
    SystemPaths = @(
        "C:\WINDOWS\system32\config\systemprofile\AppData\Local\OneStart.ai",
        "C:\WINDOWS\system32\config\systemprofile\PDFEditor",
        "C:\WINDOWS\system32\config\systemprofile\AppData\Local\AppSuites",
        "C:\Program Files\AppSuites",
        "C:\Program Files (x86)\AppSuites",
        "C:\Program Files\OneStart*",       # NEW - Potential installation location
        "C:\Program Files (x86)\OneStart*"  # NEW - Potential installation location
    )
    
    # ----------------------------------------------------------------------------
    # MALWARE CONFIGURATION - Registry Keys
    # ----------------------------------------------------------------------------

    # Registry key patterns (HKLM) - for cleanup
    RegistryHKLM = @(
        "HKLM:\Software\WOW6432Node\Microsoft\Tracing\OneStart_RASAPI32",
        "HKLM:\Software\WOW6432Node\Microsoft\Tracing\OneStart_RASMANCS",
        "HKLM:\Software\WOW6432Node\Microsoft\Tracing\AppSuites_RASAPI32",
        "HKLM:\Software\WOW6432Node\Microsoft\Tracing\AppSuites_RASMANCS",
        "HKLM:\Software\Microsoft\MediaPlayer\ShimInclusionList\onestart.exe",
        "HKLM:\Software\Microsoft\MediaPlayer\ShimInclusionList\appsuites.exe"
    )
    
    # Registry patterns for user hives (HKU) - for cleanup
    RegistryHKUPatterns = @(
        "Software\OneStart*",
        "Software\PDFEditor*",
        "Software\AppSuites*",
        "Software\Clients\StartMenuInternet\OneStart*",
        "Software\Clients\StartMenuInternet\AppSuites*",
        "Software\Microsoft\Windows\CurrentVersion\Uninstall\*OneStart*",
        "Software\Microsoft\Windows\CurrentVersion\Uninstall\*AppSuites*",
        "Software\Microsoft\Windows\CurrentVersion\Uninstall\*PDFZonePro*",     # NEW
        "Software\Microsoft\Windows\CurrentVersion\Uninstall\*SmartPDFPro*",    # NEW
        "Software\Microsoft\Windows\CurrentVersion\Uninstall\*ViewPDFTools*",   # NEW
        "Software\Classes\OneStart*",
        "Software\Classes\OSBHTML*",
        "Software\Classes\AppSuites*",  # NEW
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
        "OneStart*",
        "AppSuites*",
        "PDFZonePro*",      # NEW
        "SmartPDFPro*",     # NEW
        "ViewPDFTools*"     # NEW
    )

    # ----------------------------------------------------------------------------
    # MALWARE CONFIGURATION - Usage Tracking
    # ----------------------------------------------------------------------------

    # File association tracking patterns (ApplicationAssociationToasts)
    ApplicationAssociationPatterns = @(
        "OneStart*",
        "OSBHTML*",
        "AppSuites*",
        "PDFEditor*",
        "PDFZonePro*",      # NEW
        "SmartPDFPro*",     # NEW
        "ViewPDFTools*"     # NEW
    )

    # ----------------------------------------------------------------------------
    # MALWARE CONFIGURATION - File Association Tracking
    # ----------------------------------------------------------------------------

    # Feature usage tracking patterns (AppBadgeUpdated, AppLaunch, etc.)
    FeatureUsagePatterns = @(
        "OneStart*",
        "AppSuites*",
        "PDFEditor*",
        "PDFZonePro*",      # NEW
        "SmartPDFPro*",     # NEW
        "ViewPDFTools*"     # NEW
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
        $stopResult = $StatusLevels.Skipped
        $removalResult = $StatusLevels.Skipped
        $overallSuccess = $true
        
        # ====================================================================
        # PHASE 1: Stop Service (if running)
        # ====================================================================
    
        if ($service.Status -eq 'Running') {
            Write-Log "  [STOPPING] Attempting to stop service..." -Level INFO
            
            try {
                Stop-Service -Name $serviceName -Force -ErrorAction Stop
                Start-Sleep -Milliseconds 500
                
                # Verify service stopped
                $serviceCheck = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
                if ($serviceCheck.Status -eq 'Stopped') {
                    Write-Log "  [SUCCESS] Service stopped" -Level SUCCESS
                    $stopResult = $StatusLevels.Success

                } else {
                    Write-Log "  [FAILED] Service still running" -Level ERROR
                    $stopResult = $StatusLevels.Failed
                    $overallSuccess = $false
                }
            } catch {
                $errorMsg = $_.Exception.Message
                Write-Log "  [ERROR] Failed to stop service: $($_.Exception.Message)" -Level ERROR
                $stopResult = $StatusLevels.NotApplicable
                $overallSuccess = $false
            }
        } else {
            Write-Log "  [SKIPPED] Service not running (Status: $($service.Status))" -Level INFO
            $stopResult = "NOT_RUNNING"
        }
        
        # ====================================================================
        # PHASE 2: Remove Service
        # ====================================================================   

        Write-Log "  [REMOVING] Attempting to delete service..." -Level INFO
        
        try {
            # Use sc.exe for service deletion (more reliable than Remove-Service)
            $null = & sc.exe delete $serviceName 2>&1
            Start-Sleep -Milliseconds 500
            
            # Verify service removed
            $serviceCheck = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if (-not $serviceCheck) {
                Write-Log "  [SUCCESS] Service deleted" -Level SUCCESS
                $removalResult = $StatusLevels.Success
            } else {
                Write-Log "  [FAILED] Service still exists after deletion" -Level ERROR
                $removalResult = "FAILED"
                $overallSuccess = $false
            }
        } catch {
            $errorMsg = $_.Exception.Message
            Write-Log "  [ERROR] Failed to delete service: $($_.Exception.Message)" -Level ERROR
            $removalResult = $StatusLevels.Error
            $overallSuccess = $false
        }
        
        # ====================================================================
        # PHASE 3: Record Results
        # ====================================================================
        
        if ($overallSuccess -and $removalResult -eq $StatusLevels.Success) {

            # Complete success - service stopped and removed
            Write-Log "  [COMPLETE] Service stopped and removed: $serviceName" -Level SUCCESS
            
            $record = New-ServiceRecord -ServiceName $serviceName -Status $StatusLevels.Success `
                -ServiceDetails $serviceDetails -StopResult $stopResult -RemovalResult $removalResult
            $RemediationResults.Services.Removed += $record
            $RemediationResults.Summary.ServicesRemoved++
            
        } elseif ($removalResult -eq $StatusLevels.Failed -or $stopResult -eq $StatusLevels.Failed) {
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
        
    .PARAMETER CertConfig
    Hashtable containing certificate detection rules and store locations

    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$CertConfig
    )
    
    # ========================================================================
    # MODULE INITIALIZATION
    # ========================================================================
    
    # Module timing start
    $moduleStartTime = Get-Date
    
    Write-Log "========================================" -Level INFO
    Write-Log "CERTIFICATE ANALYSIS & REMEDIATION MODULE" -Level INFO
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
    
    # Classification buckets for different certificate types
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
        
        # Track each store checked
        $RemediationResults.Summary.CertStoresChecked++
        
        Write-Log "  Scanning: $location\$storeName (Risk: $riskLevel)" -Level INFO
        
        try {
            # Open certificate store for reading
            $store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
                $storeName,
                $location
            )
            $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
            
            $certificates = $store.Certificates
            Write-Log "    Found $($certificates.Count) certificate(s)" -Level INFO
            
            foreach ($cert in $certificates) {
                # Track each certificate scanned
                $RemediationResults.Summary.CertificatesScanned++
                
                # Calculate certificate metrics for analysis
                $certAge = Get-CertificateAge -NotBefore $cert.NotBefore
                $validityYears = Get-CertificateValidityPeriod -NotBefore $cert.NotBefore -NotAfter $cert.NotAfter
                $isSelfSigned = ($cert.Subject -eq $cert.Issuer)
                
                # Build detailed certificate information object
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
                
                # Create tracking object for this certificate
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
                # Highest priority - exact match means definite malware
                # ------------------------------------------------------------
                if ($CertConfig.MaliciousThumbprints -contains $cert.Thumbprint) {
                    $certInfo.FlagReasons += "Matches known malicious thumbprint"
                    $certInfo.ClassificationReason = "KNOWN_THUMBPRINT"
                    $knownMaliciousThumbprint += $certInfo
                    
                    $subjectPreview = $cert.Subject.Substring(0, [Math]::Min(60, $cert.Subject.Length))
                    Write-Log "    [!] KNOWN MALICIOUS (Thumbprint): $subjectPreview" -Level ERROR
                    Write-Log "      Thumbprint: $($cert.Thumbprint)" -Level ERROR
                    
                    $RemediationResults.Summary.CertificatesFlagged++
                    continue  # Skip further checks for this cert
                }
                
                # ------------------------------------------------------------
                # PRIORITY 2: Check for known malicious SERIAL NUMBER
                # Second priority - serial number match means known threat
                # ------------------------------------------------------------
                if ($CertConfig.MaliciousSerialNumbers -contains $cert.SerialNumber) {
                    $certInfo.FlagReasons += "Matches known malicious serial number"
                    $certInfo.ClassificationReason = "KNOWN_SERIAL"
                    $knownMaliciousSerial += $certInfo
                    
                    $subjectPreview = $cert.Subject.Substring(0, [Math]::Min(60, $cert.Subject.Length))
                    Write-Log "    [!] KNOWN MALICIOUS (Serial): $subjectPreview" -Level ERROR
                    Write-Log "      Serial: $($cert.SerialNumber)" -Level ERROR
                    
                    $RemediationResults.Summary.CertificatesFlagged++
                    continue  # Skip further checks for this cert
                }
                
                # ------------------------------------------------------------
                # PRIORITY 3: Check for SUSPICIOUS KEYWORDS in Subject
                # Lowest priority - keyword match needs additional validation
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
                    # Some certs may match keywords but belong to trusted vendors
                    # ------------------------------------------------------------
                    $protectionCheck = Test-ProtectedCertificate -Subject $cert.Subject `
                        -ProtectedKeywords $CertConfig.ProtectedKeywords
                    
                    if ($protectionCheck.IsProtected) {
                        # Certificate matches suspicious keyword BUT is from protected vendor
                        $certInfo.FlagReasons += "Contains suspicious keyword '$matchedKeyword' but protected by '$($protectionCheck.Keyword)'"
                        $certInfo.ClassificationReason = "PROTECTED"
                        $protectedCertificates += $certInfo
                        
                        $subjectPreview = $cert.Subject.Substring(0, [Math]::Min(60, $cert.Subject.Length))
                        Write-Log "    [PROTECTED] Contains '$matchedKeyword' but issued by $($protectionCheck.Keyword)" -Level WARNING
                        Write-Log "      Subject: $subjectPreview" -Level WARNING
                        Write-Log "      Action: REPORT ONLY - NOT REMOVED" -Level WARNING
                        
                        $RemediationResults.Summary.CertificatesFlagged++
                        continue  # Don't remove protected certificates
                    }
                    
                    # ------------------------------------------------------------
                    # SUSPICIOUS UNKNOWN: Has keyword but not in known lists
                    # Requires review - may be new malware variant
                    # ------------------------------------------------------------
                    $certInfo.FlagReasons += "Contains suspicious keyword '$matchedKeyword' (not in known malicious list)"
                    $certInfo.ClassificationReason = "SUSPICIOUS_UNKNOWN"
                    
                    # Add additional suspicious indicators for analysis
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
            } # End foreach certificate
            
            $store.Close()
            
        } catch {
            # Error accessing certificate store
            Write-Log "    [ERROR] Failed to scan $location\$storeName - $($_.Exception.Message)" -Level ERROR
            $RemediationResults.CriticalErrors += "Certificate Store: $location\$storeName - $($_.Exception.Message)"
        }
    }
    
    # ========================================================================
    # PHASE 2: CLASSIFICATION SUMMARY
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
    
    # Report protected certificates (for transparency)
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
            
            # Track protected certificate
            $record = New-CertificateRecord -StoreLocation $cert.Location `
                -StoreName $cert.StoreName -Subject $cert.Subject `
                -Thumbprint $cert.Thumbprint -Status $StatusLevels.Protected `
                -Details $cert.Details -FlagReasons $cert.FlagReasons
            $RemediationResults.Certificates.Protected += $record
        }
    }
    
    # Report suspicious unknown certificates (need review)
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
            
            # Track suspicious certificate for reporting
            $record = New-CertificateRecord -StoreLocation $cert.Location `
                -StoreName $cert.StoreName -Subject $cert.Subject `
                -Thumbprint $cert.Thumbprint -Status "SUSPICIOUS_UNKNOWN" `
                -Details $cert.Details -FlagReasons $cert.FlagReasons
            $RemediationResults.Certificates.Flagged += $record
        }
    }
    
    # ========================================================================
    # PHASE 4: REMOVAL OF MALICIOUS CERTIFICATES
    # ========================================================================
    
    # Combine all certificates to be removed (known malicious + suspicious unknown)
    $allKnownMalicious = $knownMaliciousThumbprint + $knownMaliciousSerial
    
    # Early exit if no threats found
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
            # Open certificate store for writing
            $store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
                $certInfo.StoreName,
                $certInfo.Location
            )
            $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
            
            # Find certificate by thumbprint
            $certToRemove = $store.Certificates | Where-Object { $_.Thumbprint -eq $certInfo.Thumbprint }
            
            if ($certToRemove) {
                # Attempt removal
                $store.Remove($certToRemove)
                Start-Sleep -Milliseconds 500
                
                # Verify removal
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
                    # Removal failed - certificate still present
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
                # Certificate not found (may have been removed already)
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
            # Error during removal
            $errorMsg = $_.Exception.Message
            Write-Log "    [ERROR] Failed to remove certificate: $errorMsg" -Level ERROR
            
            # Check for common protection mechanisms
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
    } # End foreach removal target
    
    # ========================================================================
    # MODULE SUMMARY
    # ========================================================================

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

    # Record module timing
    $moduleEndTime = Get-Date
    Write-ModuleTiming -ModuleName "Certificates" -StartTime $moduleStartTime -EndTime $moduleEndTime
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
    Removes malicious scheduled tasks with detailed tracking and cleanup

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
    
    # Track all successfully removed task names for Phase 2 cleanup
    $removedTaskNames = @()

    # ========================================================================
    # PHASE 1: Task Detection and Removal
    # ========================================================================
    
    Write-Log "Phase 1: Task Detection and Removal" -Level INFO
    
    foreach ($pattern in $TaskPatterns) {
        # Increment checked counter for each pattern searched
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
        
        # Handle case where no tasks match the pattern
        if ($matchingTasks.Count -eq 0) {
            Write-Log "  [$($StatusLevels.NotFound)] No tasks match pattern: $pattern" -Level INFO
            
            # Create tracking record for not found task
            $record = New-TaskRecord -TaskName $pattern -Status $StatusLevels.NotFound
            $RemediationResults.Tasks.NotFound += $record
            $RemediationResults.Summary.TasksNotFound++
            continue
        }
        
        Write-Log "  [FOUND] $($matchingTasks.Count) task(s) match pattern: $pattern" -Level WARNING
        
        # Process each matching task
        foreach ($task in $matchingTasks) {
            $taskName = $task.TaskName
            $taskPath = $task.TaskPath
            $RemediationResults.Summary.TasksFound++
            
            # Capture detailed task information before removal
            $taskDetails = Get-TaskDetails -TaskName $taskName
            
            Write-Log "    Task: $taskPath$taskName" -Level INFO
            Write-Log "      State: $($taskDetails.State)" -Level INFO
            Write-Log "      Actions: $($taskDetails.Actions)" -Level INFO
            
            # Attempt task removal
            
            Write-Log "    [REMOVING] Attempting to unregister task..." -Level INFO
            
            try {
                # Unregister the scheduled task
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
                Start-Sleep -Milliseconds 500
                
                # Verify removal
                $taskCheck = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
                if (-not $taskCheck) {
                    # Task successfully removed
                    Write-Log "    [$($StatusLevels.Success)] Task unregistered" -Level SUCCESS
                    
                    $record = New-TaskRecord -TaskName $taskName -Status $StatusLevels.Success `
                        -TaskDetails $taskDetails -RemovalResult $StatusLevels.Success
                    $RemediationResults.Tasks.Removed += $record
                    $RemediationResults.Summary.TasksRemoved++
                    
                    # Track successfully removed tasks for Phase 2 cleanup
                    $removedTaskNames += $taskName
                    

                } else {
                    # Task still exists after removal attempt
                    Write-Log "    [$($StatusLevels.Failed)] Task still exists" -Level ERROR
                    
                    $record = New-TaskRecord -TaskName $taskName -Status $StatusLevels.Failed `
                        -TaskDetails $taskDetails -RemovalResult $StatusLevels.Failed `
                        -ErrorMessage "Task still exists after removal"
                    $RemediationResults.Tasks.Failed += $record
                    $RemediationResults.Summary.TasksFailed++
                }

            } catch {
                # Exception occurred during removal
                $errorMsg = $_.Exception.Message

                Write-Log "    [$($StatusLevels.Error)] Failed to unregister: $errorMsg" -Level ERROR
                
                $record = New-TaskRecord -TaskName $taskName -Status $StatusLevels.Error `
                    -TaskDetails $taskDetails -RemovalResult $StatusLevels.Error `
                    -ErrorMessage $errorMsg
                $RemediationResults.Tasks.Errored += $record
                $RemediationResults.Summary.TasksErrored++
                
                $RemediationResults.CriticalErrors += "Task: $taskName - $errorMsg"
            }
        }  # End foreach $task
    }  # End foreach $pattern
    
    # ========================================================================
    # PHASE 2: TaskCache Cleanup
    # ========================================================================
    
    # Only run TaskCache cleanup if we successfully removed any tasks
    
    if ($removedTaskNames.Count -gt 0) {
        Write-Log "" -Level INFO
        Write-Log "Phase 2: TaskCache Cleanup" -Level INFO
        Remove-TaskCacheOrphans -TaskNames $removedTaskNames
    } else {
        Write-Log "" -Level INFO
        Write-Log "Phase 2: TaskCache Cleanup - Skipped (no tasks removed)" -Level INFO
    }
    
    
    # ========================================================================
    # MODULE SUMMARY
    # ========================================================================

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

    # Record module execution time
    $moduleEndTime = Get-Date
    Write-ModuleTiming -ModuleName "Tasks" -StartTime $moduleStartTime -EndTime $moduleEndTime

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
    Windows Task Scheduler maintains cache entries in the registry that can
    persist even after tasks are unregistered, causing orphaned references.
    
    Uses .NET Registry class for direct access to handle complex GUID-based paths.
    
    TaskCache structure:
    - Tree\TaskName: Contains task GUID and metadata
    - Tasks\{GUID}: Contains task definition
    - Plain\{GUID}: For tasks triggered manually
    - Boot\{GUID}: For tasks triggered at boot
    - Logon\{GUID}: For tasks triggered at logon
    
    .PARAMETER TaskNames
    Array of task names that were successfully removed in Phase 1
    
    .EXAMPLE
    Remove-TaskCacheOrphans -TaskNames @("OneStartUser", "PDFEditorTask")
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [array]$TaskNames
    )
    
    Write-Log "  [TASKCACHE] Checking for orphaned TaskCache entries..." -Level INFO
    
    # Base registry path for Task Scheduler cache
    $baseKeyPath = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache"
    
    foreach ($taskName in $TaskNames) {
        # Increment checked counter for each task cache lookup
        $RemediationResults.Summary.TaskCacheChecked++
        
        Write-Log "    Checking TaskCache for: $taskName" -Level INFO
        
        try {
            # Check if Tree entry exists for this task
            $treePath = "$baseKeyPath\Tree\$taskName"
            $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($treePath, $false)
            
            if (-not $regKey) {
                # No TaskCache entry exists (already cleaned or never existed)
                Write-Log "      [$($StatusLevels.NotFound)] No TaskCache entry" -Level INFO
               
                $record = New-TaskCacheRecord -TaskName $taskName -GUID "N/A" `
                    -CacheType "Tree" -Status $StatusLevels.NotFound
                $RemediationResults.TaskCache.NotFound += $record
                $RemediationResults.Summary.TaskCacheNotFound++
                continue
            }
            
            $RemediationResults.Summary.TaskCacheFound++
            
            # Retrieve the task GUID from the Tree entry
            $taskId = $null
            try {
                $taskId = $regKey.GetValue("Id")
            } catch {
                # Some tasks may not have a valid GUID
                Write-Log "      [WARNING] Could not read task GUID" -Level WARNING
            }
            $regKey.Close()
            
            # Format GUID with curly braces for path construction
            $guidString = if ($taskId) { "{$taskId}" } else { "UNKNOWN" }
            Write-Log "      [FOUND] GUID: $guidString" -Level WARNING
            
            $removalSuccess = $true
            $removedCount = 0
            
            # If we have a valid GUID, remove related subkeys
            if ($taskId) {
                # TaskCache subkey locations that may contain this GUID
                $relatedSubKeys = @(
                    @{Path = "$baseKeyPath\Tasks\$guidString"; Type = "Tasks"},
                    @{Path = "$baseKeyPath\Plain\$guidString"; Type = "Plain"},
                    @{Path = "$baseKeyPath\Boot\$guidString"; Type = "Boot"},
                    @{Path = "$baseKeyPath\Logon\$guidString"; Type = "Logon"}
                )
                
                foreach ($subKey in $relatedSubKeys) {
                    try {
                        # Attempt to delete the subkey tree
                        [Microsoft.Win32.Registry]::LocalMachine.DeleteSubKeyTree($subKey.Path, $false)
                        Write-Log "        [SUCCESS] Removed $($subKey.Type) entry" -Level SUCCESS
                        $removedCount++
                        
                        $record = New-TaskCacheRecord -TaskName $taskName -GUID $guidString `
                            -CacheType $subKey.Type -Status $StatusLevels.Success
                        $RemediationResults.TaskCache.Removed += $record
                        $RemediationResults.Summary.TaskCacheRemoved++

                    } catch {
                        # Only log errors for actual failures (not "key doesn't exist")
                        if ($_.Exception.Message -notlike "*cannot find*") {
                            Write-Log "        [WARNING] $($subKey.Type) entry: $($_.Exception.Message)" -Level WARNING
                        }
                    }
                }
            }
            
            # Remove the Tree entry last (this is the main reference)
            try {
                [Microsoft.Win32.Registry]::LocalMachine.DeleteSubKeyTree($treePath, $false)
                Write-Log "        [$($StatusLevels.Success)] Removed Tree entry" -Level SUCCESS
                $removedCount++
                
                $record = New-TaskCacheRecord -TaskName $taskName -GUID $guidString `
                    -CacheType "Tree" -Status $StatusLevels.Success
                $RemediationResults.TaskCache.Removed += $record
                $RemediationResults.Summary.TaskCacheRemoved++
            } catch {
                # Tree entry removal failed
                Write-Log "        [$($StatusLevels.Failed)] Tree entry: $($_.Exception.Message)" -Level ERROR
                
                $record = New-TaskCacheRecord -TaskName $taskName -GUID $guidString `
                    -CacheType "Tree" -Status $StatusLevels.Failed -ErrorMessage $_.Exception.Message
                $RemediationResults.TaskCache.Failed += $record
                $RemediationResults.Summary.TaskCacheFailed++
                $removalSuccess = $false
            }
            
            # Log cleanup summary for this task
            if ($removedCount -gt 0) {
                Write-Log "      [COMPLETE] TaskCache cleaned: $removedCount entries" -Level SUCCESS
            } else {
                Write-Log "      [PARTIAL] Some entries could not be removed" -Level WARNING
            }
            
        } catch {
            # General error accessing TaskCache
            Write-Log "      [$($StatusLevels.Error)] TaskCache access failed: $($_.Exception.Message)" -Level ERROR
            
            $record = New-TaskCacheRecord -TaskName $taskName -GUID "ERROR" `
                -CacheType "Unknown" -Status $StatusLevels.Error -ErrorMessage $_.Exception.Message
            $RemediationResults.TaskCache.Errored += $record
            $RemediationResults.Summary.TaskCacheErrored++
        }
    }

    # TaskCache cleanup summary
    Write-Log "  [TASKCACHE] Cleanup complete:" -Level INFO
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
    Helper function that searches for and removes registry values matching
    wildcard patterns. Used by Remove-MalwareRegistryPersistence to clean
    Run keys and RegisteredApplications.
    .PARAMETER KeyPath
    Full registry path to search (e.g., "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run")
    .PARAMETER ValuePatterns
    Array of wildcard patterns to match against value names (e.g., "OneStart*")
    .OUTPUTS
    Returns count of successfully removed values

    #>
    param(
        [string]$KeyPath,
        [array]$ValuePatterns
    )
    
    $removedCount = 0
    
    # Check if registry key exists
    if (-not (Test-Path $KeyPath)) {
        return $removedCount
    }
    
    try {
        # Get all properties from the registry key
        $keyProperties = Get-ItemProperty -Path $KeyPath -ErrorAction Stop
        
        # Loop through each pattern to find matching values
        foreach ($pattern in $ValuePatterns) {
            # Find values matching this pattern (exclude PowerShell metadata properties)
            $matchingValues = $keyProperties.PSObject.Properties | 
                Where-Object { $_.Name -like $pattern -and $_.Name -notlike "PS*" }
            
            foreach ($value in $matchingValues) {
                $valueName = $value.Name
                $valueData = $value.Value
                
                # Track that we found a malicious value
                $RemediationResults.Summary.RegistryValuesFound++
                Write-Log "    [FOUND] $KeyPath\$valueName = $valueData" -Level WARNING
                
                try {
                    # Attempt to remove the registry value
                    Remove-ItemProperty -Path $KeyPath -Name $valueName -ErrorAction Stop
                    Start-Sleep -Milliseconds 200
                    
                    # Verify removal was successful
                    $checkValue = Get-ItemProperty -Path $KeyPath -Name $valueName -ErrorAction SilentlyContinue
                    
                    if (-not $checkValue) {
                        Write-Log "    [SUCCESS] Removed: $valueName" -Level SUCCESS
                        
                        # Create detailed tracking record
                        $record = New-RegistryRecord -KeyPath $KeyPath -ValueName $valueName `
                            -Status $StatusLevels.Success -ValueData $valueData
                        $RemediationResults.Registry.Removed += $record
                        $RemediationResults.Summary.RegistryValuesRemoved++
                        $removedCount++
                        
                    } else {

                        # Value still exists after removal attempt
                        Write-Log "    [FAILED] Still exists: $valueName" -Level ERROR
                        
                        $record = New-RegistryRecord -KeyPath $KeyPath -ValueName $valueName `
                            -Status $StatusLevels.Failed -ValueData $valueData `
                            -ErrorMessage "Value still exists after removal"
                        $RemediationResults.Registry.Failed += $record
                        $RemediationResults.Summary.RegistryValuesFailed++
                    }
                    
                } catch {
                    # Exception occurred during removal
                    Write-Log "    [ERROR] Failed to remove $valueName : $($_.Exception.Message)" -Level ERROR
                    
                        -Status $StatusLevels.Error -ValueData $valueData `
                        -ErrorMessage $_.Exception.Message
                    $RemediationResults.Registry.Errored += $record
                    $RemediationResults.Summary.RegistryValuesErrored++
                    
                }
            }
        }
        
    } catch {
        # Cannot access the registry key
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
    Comprehensive removal of registry-based persistence mechanisms:
    - HKLM and HKU Run/RunOnce keys (system and per-user autostart)
    - RegisteredApplications (application registration for default programs)
    - Explorer Feature Usage tracking (hides malware from Windows telemetry)
    
    Searches both system-wide (HKLM) and per-user (HKU) registry hives.
    .PARAMETER RunKeyPatterns
    Array of wildcard patterns for Run key value names (e.g., "OneStart*")
    .PARAMETER RegisteredAppPatterns
    Array of wildcard patterns for RegisteredApplications entries
    .PARAMETER FeatureUsagePatterns
    Array of wildcard patterns for Explorer Feature Usage tracking

    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [array]$RunKeyPatterns,
        
        [Parameter(Mandatory=$true)]
        [array]$RegisteredAppPatterns,

        [Parameter(Mandatory=$false)]
        [array]$FeatureUsagePatterns = @()
    )
    
    # --------------------------------------------------------------------
    # Module Initialization
    # --------------------------------------------------------------------

    $moduleStartTime = Get-Date
    
    Write-Log "========================================" -Level INFO
    Write-Log "REGISTRY PERSISTENCE REMOVAL MODULE" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "Target Run key patterns: $($RunKeyPatterns.Count)" -Level INFO
    Write-Log "Target RegisteredApp patterns: $($RegisteredAppPatterns.Count)" -Level INFO
    Write-Log "Target Feature Usage patterns: $($FeatureUsagePatterns.Count)" -Level INFO

    
    $totalRemoved = 0
    
    # ========================================================================
    # PHASE 1: HKLM Run Keys (System-wide Autostart)
    # ========================================================================
    
    Write-Log "" -Level INFO
    Write-Log "Phase 1: Checking HKLM Run keys..." -Level INFO
    
    # Define all HKLM Run key locations (including WOW6432Node for 32-bit on 64-bit)
    $hklmRunKeys = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    
    foreach ($keyPath in $hklmRunKeys) {
        
        Write-Log "  Checking: $keyPath" -Level INFO
        $RemediationResults.Summary.RegistryKeysChecked++
        
        # Remove matching values from this key
        $removed = Remove-RegistryValueByPattern -KeyPath $keyPath -ValuePatterns $RunKeyPatterns
        $phaseResults.HKLMRun += $removed
        $totalRemoved += $removed

        if ($removed -eq 0) {
            Write-Log "    [NOT FOUND] No matching entries" -Level INFO
            $RemediationResults.Summary.RegistryValuesNotFound++
        }

    }
   
    # ========================================================================
    # PHASE 2: Per-User Run Keys (User-specific Autostart)
    # ========================================================================
    
    Write-Log "" -Level INFO
    Write-Log "Phase 2: Checking per-user Run keys..." -Level INFO
    
    # Get all user SIDs from HKU registry hive
    $userSIDs = Get-UserSIDs
    Write-Log "  Found $($userSIDs.Count) user profile(s)" -Level INFO
   
    foreach ($sid in $userSIDs) {
        Write-Log "  Processing SID: $sid" -Level INFO
        
        # Define per-user Run key locations
        $hkuRunKeys = @(
            "Registry::HKU\$sid\Software\Microsoft\Windows\CurrentVersion\Run",
            "Registry::HKU\$sid\Software\Microsoft\Windows\CurrentVersion\RunOnce"
        )
        
        foreach ($keyPath in $hkuRunKeys) {
            $RemediationResults.Summary.RegistryKeysChecked++
            # Remove matching values from this user's Run keys
            $removed = Remove-RegistryValueByPattern -KeyPath $keyPath -ValuePatterns $RunKeyPatterns
            $phaseResults.UserRun += $removed
            $totalRemoved += $removed
                        
            if ($removed -eq 0) {
                $RemediationResults.Summary.RegistryValuesNotFound++
            }

        }
    }
    
    # ====================================================================
    # PHASE 3: RegisteredApplications (System-wide)
    # ====================================================================
    
    Write-Log "" -Level INFO
    Write-Log "Phase 3: Checking RegisteredApplications..." -Level INFO
    
    # HKLM RegisteredApplications (system-wide application registration)
    $hklmRegApps = "HKLM:\Software\RegisteredApplications"
    Write-Log "  Checking: $hklmRegApps" -Level INFO
    $RemediationResults.Summary.RegistryKeysChecked++
    
    $removed = Remove-RegistryValueByPattern -KeyPath $hklmRegApps -ValuePatterns $RegisteredAppPatterns
    $totalRemoved += $removed
    
    Write-Log "  Phase 3 Complete: Removed $($phaseResults.HKLMRegApps) HKLM RegisteredApp entries" -Level INFO
    
    if ($removed -eq 0) {
        Write-Log "    [NOT FOUND] No matching entries" -Level INFO
        $RemediationResults.Summary.RegistryValuesNotFound++
    }

    # Per-user RegisteredApplications
    foreach ($sid in $userSIDs) {
        $hkuRegApps = "Registry::HKU\$sid\Software\RegisteredApplications"
        $RemediationResults.Summary.RegistryKeysChecked++
        
        $removed = Remove-RegistryValueByPattern -KeyPath $hkuRegApps -ValuePatterns $RegisteredAppPatterns
        $totalRemoved += $removed
                
        if ($removed -eq 0) {
            $RemediationResults.Summary.RegistryValuesNotFound++
        }

    }
    
    
    # ====================================================================
    # PHASE 4: Explorer Feature Usage Tracking (Optional)
    # ====================================================================
    # This removes telemetry tracking that Windows uses to show recently
    # used apps. Prevents malware from appearing in user's history.

    
    if ($FeatureUsagePatterns.Count -gt 0) {
        Write-Log "" -Level INFO
        Write-Log "Phase 4: Checking Explorer Feature Usage..." -Level INFO
        
        foreach ($sid in $userSIDs) {
            # Feature Usage tracking locations
            $featureUsagePaths = @(
                "Registry::HKU\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppBadgeUpdated",
                "Registry::HKU\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppLaunch"
            )
            
            foreach ($keyPath in $featureUsagePaths) {
                if (Test-Path $keyPath) {
                    $RemediationResults.Summary.RegistryKeysChecked++
                    $removed = Remove-RegistryValueByPattern -KeyPath $keyPath -ValuePatterns $FeatureUsagePatterns
                    $totalRemoved += $removed
                                        
                    if ($removed -eq 0) {
                        $RemediationResults.Summary.RegistryValuesNotFound++
                    }

                }
            }
        }
        
    }
    
    # --------------------------------------------------------------------
    # Module Completion and Timing
    # --------------------------------------------------------------------
    
    $moduleEndTime = Get-Date
    Write-ModuleTiming -ModuleName "RegistryPersistence" -StartTime $moduleStartTime -EndTime $moduleEndTime
    
    Write-Log "========================================" -Level INFO
    Write-Log "REGISTRY PERSISTENCE REMOVAL SUMMARY" -Level INFO
    Write-Log "  Keys Checked: $($RemediationResults.Summary.RegistryKeysChecked)" -Level INFO
    Write-Log "  Values Found: $($RemediationResults.Summary.RegistryValuesFound)" -Level INFO
    Write-Log "  Values Removed: $($RemediationResults.Summary.RegistryValuesRemoved)" -Level SUCCESS
    Write-Log "  Values Failed: $($RemediationResults.Summary.RegistryValuesFailed)" -Level ERROR
    Write-Log "  Values Errored: $($RemediationResults.Summary.RegistryValuesErrored)" -Level ERROR
    Write-Log "  Values Not Found: $($RemediationResults.Summary.RegistryValuesNotFound)" -Level INFO
    Write-Log "  Duration: $((($moduleEndTime - $moduleStartTime).TotalSeconds)) seconds" -Level INFO
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
    Attempts to remove a file system item (file or folder) and tracks the result.
    Captures item metadata before removal for reporting purposes.
    Returns status using $StatusLevels constants for consistency.

    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path
    )
    
    # Check if path exists before attempting removal
    if (-not (Test-Path $Path)) {
        return $StatusLevels.NotFound
    }
    
    try {
        # Capture metadata before removal for tracking
        $item = Get-Item $Path -Force -ErrorAction Stop
        $itemType = if ($item.PSIsContainer) { "Folder" } else { "File" }
        
        # Calculate size (recursive for folders, direct for files)
        $itemSize = if ($item.PSIsContainer) { 
            (Get-ChildItem $Path -Recurse -Force -ErrorAction SilentlyContinue | 
                Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum 
        } else { 
            $item.Length 
        }
        
        # Update summary stats - item found
        $RemediationResults.Summary.PathsFound++
        Write-Log "    [FOUND] $itemType : $Path ($([math]::Round($itemSize/1KB, 2)) KB)" -Level WARNING

        # Attempt removal with -Force to handle hidden/system files
        Remove-Item $Path -Recurse -Force -ErrorAction Stop
        Start-Sleep -Milliseconds 200  # Brief pause to ensure filesystem updates
        
        # Verify removal was successful
        if (-not (Test-Path $Path)) {
            Write-Log "    [SUCCESS] Removed: $Path" -Level SUCCESS
            
            # Create detailed tracking record
            $record = New-FileRecord -Path $Path -Status $StatusLevels.Success `
                -Type $itemType -Size $itemSize
            $RemediationResults.Files.Removed += $record
            $RemediationResults.Summary.PathsRemoved++

            return $StatusLevels.Success
            
        } else {
            # Item still exists after removal attempt (may be locked/protected)
            Write-Log "    [FAILED] Still exists: $Path" -Level ERROR
            
            $record = New-FileRecord -Path $Path -Status $StatusLevels.Failed `
                -Type $itemType -Size $itemSize `
                -ErrorMessage "Item still exists after removal attempt (may be locked or in use)"
            $RemediationResults.Files.Failed += $record
            $RemediationResults.Summary.PathsFailed++

            return $StatusLevels.Failed
        }
        
    } catch {
        # Exception occurred during removal attempt
        $errorMsg = $_.Exception.Message
        Write-Log "    [ERROR] Failed to remove $Path" -Level ERROR
        Write-Log "    [ERROR] Failed to remove $Path : $errorMsg" -Level ERROR

        $record = New-FileRecord -Path $Path -Status $StatusLevels.Error `
            -ErrorMessage $errorMsg
        $RemediationResults.Files.Errored += $record
        $RemediationResults.Summary.PathsErrored++
        
        # Track as critical error for final report
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
    Removes malware files and folders from the system
    .DESCRIPTION
    Orchestrates file system cleanup in three phases:
    1. User-specific paths (per user profile)
    2. Downloads folder cleanup (malware installers)
    3. System-level paths (shared/system locations)
    
    Tracks all actions and generates detailed summary report.
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
    Write-Log "" -Level INFO
    
    # ========================================================================
    # PHASE 1: User-Specific Paths
    # ========================================================================
    # Removes malware from individual user profile directories.
    # Uses {USER} placeholder which gets replaced with actual username.

    Write-Log "Phase 1: Removing user-specific paths..." -Level INFO

    # Get all user profiles on the system
    $userProfiles = Get-UserProfiles
    Write-Log "  Found $($userProfiles.Count) user profile(s)" -Level INFO
    
    foreach ($user in $userProfiles) {
        Write-Log "  Processing user: $user" -Level INFO
        
        foreach ($pathTemplate in $UserPaths) {
            # Increment paths checked counter
            $RemediationResults.Summary.PathsChecked++
            
            # Replace {USER} placeholder with actual username
            $actualPath = $pathTemplate -replace '\{USER\}', $user
            
            # Attempt to remove the path
            $result = Remove-PathItem -Path $actualPath
            
            # Track items not found (not an error, just means already clean)
            if ($result -eq $StatusLevels.NotFound) {
                $record = New-FileRecord -Path $actualPath -Status $StatusLevels.NotFound
                $RemediationResults.Files.NotFound += $record
                $RemediationResults.Summary.PathsNotFound++
            }
        }
    }
        
    # ========================================================================
    # PHASE 2: Downloads Folder Cleanup
    # ========================================================================
    # Removes malware installer files from each user's Downloads folder.
    # Uses pattern matching to find files (e.g., "OneStart*.exe").

    Write-Log "" -Level INFO
    Write-Log "Phase 2: Cleaning Downloads folders..." -Level INFO

    foreach ($user in $userProfiles) {
        $downloadsPath = "C:\Users\$user\Downloads"
        
        # Skip if Downloads folder doesn't exist
        if (-not (Test-Path $downloadsPath)) {
            Write-Log "  [SKIPPED] Downloads folder not found for user: $user" -Level INFO
            continue
        }
        
        Write-Log "  ---" -Level INFO
        Write-Log "  Scanning: $downloadsPath" -Level INFO
        
        # Process each download pattern (e.g., "OneStart*.exe", "*OneStart*.msi")
        foreach ($pattern in $DownloadPatterns) {
            # Find all files matching the pattern (recursive search)
            $files = Get-ChildItem $downloadsPath -Filter $pattern -File -Recurse `
                -Force -ErrorAction SilentlyContinue
            
            if ($files) {
                Write-Log "    Found $($files.Count) file(s) matching pattern: $pattern" -Level WARNING
            }
            
            foreach ($file in $files) {
                # Increment paths checked counter
                $RemediationResults.Summary.PathsChecked++
                
                # Attempt to remove the file
                $result = Remove-PathItem -Path $file.FullName
                
                # Track items not found (edge case: removed between scan and action)
                if ($result -eq $StatusLevels.NotFound) {
                    $record = New-FileRecord -Path $file.FullName -Status $StatusLevels.NotFound
                    $RemediationResults.Files.NotFound += $record
                    $RemediationResults.Summary.PathsNotFound++
                }
            }
        }
    }
     
    # ========================================================================
    # PHASE 3: System-Level Paths
    # ========================================================================
    # Removes malware from system-wide locations (all users affected).
    # Handles both exact paths and wildcard patterns.

    Write-Log "" -Level INFO
    Write-Log "Phase 3: Removing system-level paths..." -Level INFO
    
    foreach ($path in $SystemPaths) {
        # Increment paths checked counter
        $RemediationResults.Summary.PathsChecked++
        
        # Check if path contains wildcard (requires pattern matching)
        if ($path -match '\*') {
            Write-Log "  Processing wildcard path: $path" -Level INFO

            # Split path into parent directory and pattern
            $parentPath = Split-Path $path -Parent
            $pattern = Split-Path $path -Leaf
            
            # Only process if parent directory exists
            if (Test-Path $parentPath) {
                # Find all items matching the pattern
                $items = Get-ChildItem $parentPath -Filter $pattern -Force `
                    -ErrorAction SilentlyContinue

                if ($items) {
                    Write-Log "    Found $($items.Count) item(s) matching pattern" -Level WARNING
                }
                
                foreach ($item in $items) {
                    # Attempt to remove each matching item
                    $result = Remove-PathItem -Path $item.FullName
                    
                    # Track items not found
                    if ($result -eq $StatusLevels.NotFound) {
                        $record = New-FileRecord -Path $item.FullName -Status $StatusLevels.NotFound
                        $RemediationResults.Files.NotFound += $record
                        $RemediationResults.Summary.PathsNotFound++
                    }
                }
            } else {
                # Parent directory doesn't exist (path already clean)
                Write-Log "    [NOT FOUND] Parent directory does not exist: $parentPath" -Level INFO
                $record = New-FileRecord -Path $path -Status $StatusLevels.NotFound
                $RemediationResults.Files.NotFound += $record
                $RemediationResults.Summary.PathsNotFound++
            }
        } else {
            # Exact path (no wildcard) - attempt direct removal
            Write-Log "  Processing exact path: $path" -Level INFO

            $result = Remove-PathItem -Path $path

            # Track items not found
            if ($result -eq $StatusLevels.NotFound) {
                $record = New-FileRecord -Path $path -Status $StatusLevels.NotFound
                $RemediationResults.Files.NotFound += $record
                $RemediationResults.Summary.PathsNotFound++
            }
        }
    }
      
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

    Write-Log "  Paths Checked: $($RemediationResults.Summary.PathsChecked)" -Level INFO
    Write-Log "  Paths Found: $($RemediationResults.Summary.PathsFound)" -Level INFO
    Write-Log "  Paths Removed: $($RemediationResults.Summary.PathsRemoved)" -Level SUCCESS
    Write-Log "  Paths Failed: $($RemediationResults.Summary.PathsFailed)" -Level ERROR
    Write-Log "  Paths Errored: $($RemediationResults.Summary.PathsErrored)" -Level ERROR
    Write-Log "  Paths Not Found: $($RemediationResults.Summary.PathsNotFound)" -Level INFO
    Write-Log "========================================" -Level INFO
}

# ============================================================================ #
#  PRIMARY FUNCTIONS - REGISTRY CLEANUP (ARTIFACTS)
# ============================================================================ #

# ============================================================================ #
#  PRIMARY FUNCTIONS - REGISTRY CLEANUP (ARTIFACTS) - Remove-RegistryKeyRecursive
# ============================================================================ #

function Remove-RegistryKeyRecursive {
    <#
    .SYNOPSIS
    Removes a registry key and all subkeys with detailed tracking

    .DESCRIPTION
    Attempts to remove a registry key recursively. Captures detailed metadata
    before removal and tracks the outcome. Uses $StatusLevels constants for
    consistent status reporting.
    
    .PARAMETER KeyPath
    Full registry path to the key (e.g., "HKLM:\Software\Malware")
    
    .RETURNS
    Status string from $StatusLevels (Success, NotFound, Failed, Error)
    
    .NOTES
    Some registry keys may be protected at the kernel level and cannot be removed
    without specialized tools or safe mode.

    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$KeyPath
    )

    # Increment counter for each key we check
    $RemediationResults.Summary.RegistryKeysChecked++
    
    Write-Log "  Checking: $KeyPath" -Level INFO
    
    # Capture key metadata before attempting removal
    $keyDetails = Get-RegistryKeyDetails -KeyPath $KeyPath
    
    # If key doesn't exist, record and return
    if (-not $keyDetails.Exists) {
        Write-Log "    [$($StatusLevels.NotFound)] Key does not exist" -Level INFO
        
        $record = New-RegistryKeyRecord -KeyPath $KeyPath -Status $StatusLevels.NotFound
        $RemediationResults.Registry.NotFound += $record
        return $StatusLevels.NotFound
    }
    
    # Key exists - log what we found
    Write-Log "    [FOUND] Subkeys: $($keyDetails.SubkeyCount) | Values: $($keyDetails.ValueCount)" -Level WARNING
    
    try {
        # Attempt recursive removal
        Remove-Item -Path $KeyPath -Recurse -Force -ErrorAction Stop
        Start-Sleep -Milliseconds 200  # Brief pause to allow filesystem sync
        
        # Verify removal was successful
        if (-not (Test-Path $KeyPath)) {
            Write-Log "    [$($StatusLevels.Success)] Key removed" -Level SUCCESS

            # Create detailed record of successful removal
            $record = New-RegistryKeyRecord -KeyPath $KeyPath -Status $StatusLevels.Success `
                -SubkeyCount $keyDetails.SubkeyCount -ValueCount $keyDetails.ValueCount
            $RemediationResults.Registry.Removed += $record
            $RemediationResults.Summary.RegistryValuesRemoved++
            return $StatusLevels.Success
            
        } else {
            # Removal command executed but key still exists (likely kernel protection)
            Write-Log "    [$($StatusLevels.Failed)] Key still exists (may be kernel protected)" -Level ERROR
            
            $record = New-RegistryKeyRecord -KeyPath $KeyPath -Status $StatusLevels.Failed `
                -SubkeyCount $keyDetails.SubkeyCount -ValueCount $keyDetails.ValueCount `
                -ErrorMessage "Key still exists after removal (possible kernel protection)"
            $RemediationResults.Registry.Failed += $record
            $RemediationResults.Summary.RegistryValuesFailed++
            return $StatusLevels.Failed
        }
        
    } catch {
        # Exception occurred during removal attempt
        $errorMsg = $_.Exception.Message
        Write-Log "    [$($StatusLevels.Error)] Failed to remove: $errorMsg" -Level ERROR

        # Check for specific error conditions
        if ($errorMsg -like "*Access is denied*" -or $errorMsg -like "*protected*") {
            Write-Log "    [!] Registry key appears to be kernel-level protected" -Level ERROR
            Write-Log "    [!] Manual removal may be required" -Level ERROR
        }
        
        $record = New-RegistryKeyRecord -KeyPath $KeyPath -Status $StatusLevels.Error `
            -SubkeyCount $keyDetails.SubkeyCount -ValueCount $keyDetails.ValueCount `
            -ErrorMessage $errorMsg
        $RemediationResults.Registry.Errored += $record
        $RemediationResults.Summary.RegistryValuesErrored++
        # Log to critical errors for final report
        $RemediationResults.CriticalErrors += "Registry: $KeyPath - $errorMsg"
        return $StatusLevels.Error
    }
}

# ============================================================================ #
#  PRIMARY FUNCTIONS - REGISTRY CLEANUP (ARTIFACTS) - Remove-MalwareRegistryKeys
# ============================================================================ #

function Remove-MalwareRegistryKeys {
    <#
    .SYNOPSIS
    Removes malware registry keys (artifacts and configuration)
    .DESCRIPTION
    Cleans up registry keys left behind by malware including:
    - HKLM system-wide configuration keys
    - Per-user HKU registry artifacts
    - Supports wildcard patterns for dynamic key discovery
    
    REMOVAL ORDER:
    Phase 1: HKLM keys (machine-wide artifacts)
    Phase 2: HKU keys (per-user artifacts, including wildcards)
    
    .PARAMETER HKLMPaths
    Array of HKLM registry paths to remove (exact paths)
    
    .PARAMETER HKUPatterns
    Array of HKU registry path patterns (supports wildcards)
    
    .NOTES
    This runs AFTER persistence removal to clean up remaining traces.
    Wildcards in HKUPatterns allow matching multiple keys (e.g., "Software\Classes\OneStart*")


    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [array]$HKLMPaths,
        
        [Parameter(Mandatory=$true)]
        [array]$HKUPatterns
    )
    
    # ========================================================================
    # MODULE INITIALIZATION
    # ========================================================================
    
    # Start module timing

    $moduleStartTime = Get-Date
    
    Write-Log "========================================" -Level INFO
    Write-Log "REGISTRY CLEANUP MODULE (ARTIFACTS & CONFIGURATION)" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "Target HKLM paths: $($HKLMPaths.Count)" -Level INFO
    Write-Log "Target HKU patterns: $($HKUPatterns.Count)" -Level INFO
    
    # ========================================================================
    # PHASE 1: REMOVE HKLM (System-Wide) REGISTRY KEYS
    # ========================================================================
    
    Write-Log "Phase 1: Removing HKLM registry keys..." -Level INFO
    
    Write-Log "  These are system-wide configuration entries" -Level INFO

    
    foreach ($keyPath in $HKLMPaths) {
        # Remove key and capture result (but don't need to process it further)
        $null = Remove-RegistryKeyRecursive -KeyPath $keyPath

    }
    
    # ========================================================================
    # PHASE 2: REMOVE PER-USER (HKU) REGISTRY KEYS
    # ========================================================================
    
    Write-Log "" -Level INFO
    Write-Log "Phase 2: Removing per-user registry keys..." -Level INFO
    Write-Log "  These are user-specific configuration entries" -Level INFO
    
    # Enumerate all user SIDs on the system
    $userSIDs = Get-UserSIDs
    Write-Log "  Found $($userSIDs.Count) user profile(s)" -Level INFO
   
    foreach ($sid in $userSIDs) {
        Write-Log "  Processing SID: $sid" -Level INFO

        # Process each HKU pattern for this user
        foreach ($pattern in $HKUPatterns) {
            # Build the search path
            $basePath = "Registry::HKU\$sid"
            $searchPath = "$basePath\$pattern"
            
            Write-Log "    Searching: $searchPath" -Level INFO
            
            # ------------------------------------------------------------
            # WILDCARD PATTERN HANDLING
            # ------------------------------------------------------------
            # If pattern contains wildcards, we need to search and match

            if ($pattern -match '\*') {
                Write-Log "    Searching pattern: $pattern" -Level INFO
                
                # Split pattern into path components
                $parts = $pattern -split '\\'
                $currentPath = $basePath
                
                # Find the first component with a wildcard
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
                    
                    # Find all child keys matching the wildcard pattern
                    $matchingKeys = Get-ChildItem $currentPath -ErrorAction SilentlyContinue |
                        Where-Object { $_.PSChildName -like $searchPattern }
                    
                    if ($matchingKeys) {
                        Write-Log "      Found $($matchingKeys.Count) matching key(s)" -Level WARNING
                        
                        # Remove each matching key
                        foreach ($key in $matchingKeys) {
                            $null = Remove-RegistryKeyRecursive -KeyPath $key.PSPath
                        }
                    } else {
                        # No keys match the wildcard pattern
                        Write-Log "      [$($StatusLevels.NotFound)] No keys match pattern" -Level INFO
                        
                        $record = New-RegistryKeyRecord -KeyPath $searchPath -Status $StatusLevels.NotFound
                        $RemediationResults.Registry.NotFound += $record
                        $RemediationResults.Summary.RegistryKeysChecked++
                    }
                } else {
                    # Base path doesn't exist (expected if malware not installed for this user)
                    Write-Log "      [$($StatusLevels.NotFound)] Base path does not exist" -Level INFO
                    
                    $record = New-RegistryKeyRecord -KeyPath $searchPath -Status $StatusLevels.NotFound
                    $RemediationResults.Registry.NotFound += $record
                    $RemediationResults.Summary.RegistryKeysChecked++
                }
                
            } else {
                # ------------------------------------------------------------
                # EXACT PATH HANDLING (No Wildcards)
                # ------------------------------------------------------------
                $null = Remove-RegistryKeyRecursive -KeyPath $searchPath
            }
        }
    }
    
    # ========================================================================
    # MODULE SUMMARY
    # ========================================================================
    
    
    # Display summary
    Write-Log "" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "REGISTRY CLEANUP SUMMARY" -Level INFO
    Write-Log "  Keys Checked: $($RemediationResults.Summary.RegistryKeysChecked)" -Level INFO
    Write-Log "  Keys Removed: $($RemediationResults.Summary.RegistryValuesRemoved)" -Level SUCCESS
    Write-Log "  Keys Failed: $($RemediationResults.Summary.RegistryValuesFailed)" -Level ERROR
    Write-Log "  Keys Errored: $($RemediationResults.Summary.RegistryValuesErrored)" -Level ERROR
    Write-Log "  Keys Not Found: $($RemediationResults.Registry.NotFound.Count)" -Level INFO
    Write-Log "========================================" -Level INFO

    # End module timing and record duration
    $moduleEndTime = Get-Date
    Write-ModuleTiming -ModuleName "RegistryCleanup" -StartTime $moduleStartTime -EndTime $moduleEndTime

}

# ============================================================================ #
# PRIMARY FUNCTIONS - BROWSER ENTRY CLEANUP
# ============================================================================ #

# ============================================================================ #
# PRIMARY FUNCTIONS - BROWSER ENTRY CLEANUP - Remove-BrowserEntry
# ============================================================================ #
# Purpose: Removes browser hijacking registry entries that cause false 
#          inventory detections and prevent proper browser selection
# Scope: 
#   - HKLM/HKU StartMenuInternet registrations
#   - ProgID classes (Software\Classes)
#   - UserChoice associations (read-only, Windows-protected)
#   - Explorer FeatureUsage tracking

function Remove-BrowserEntry {
    <#
    .SYNOPSIS
    Removes a single browser registry entry with detailed tracking
    
    .DESCRIPTION
    Attempts to remove a browser-related registry key and verifies removal.
    Tracks success, failure, or errors with detailed logging.
    
    .PARAMETER KeyPath
    Full registry path to remove (e.g., HKLM:\Software\Clients\StartMenuInternet\OneStart)
    
    .PARAMETER EntryType
    Descriptive type for logging (e.g., "Browser Registration", "ProgID Class")
    
    .OUTPUTS
    String status: SUCCESS, FAILED, ERROR, or NOT_FOUND

    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$KeyPath,
        [Parameter(Mandatory=$true)]
        [string]$EntryType
    )
    
    # Check if entry exists before attempting removal
    if (-not (Test-Path $KeyPath)) {
        Write-Log "    [NOT FOUND] Entry does not exist: $KeyPath" -Level INFO
        return $StatusLevels.NotFound
    }
    
    try {
        Write-Log "    [FOUND] $EntryType : $KeyPath" -Level WARNING
        
        # Attempt removal with force and recursion
        Remove-Item -Path $KeyPath -Recurse -Force -ErrorAction Stop
        Start-Sleep -Milliseconds 200  # Allow registry to settle
        
        # Verify removal was successful
        if (-not (Test-Path $KeyPath)) {
            Write-Log "    [SUCCESS] Removed: $KeyPath" -Level SUCCESS
            
            # Track successful removal
            $record = New-BrowserRecord -EntryPath $KeyPath -EntryType $EntryType `
                -Status $StatusLevels.Success
            $RemediationResults.BrowserEntries.Removed += $record
            $RemediationResults.Summary.BrowserEntriesRemoved++
            
            return $StatusLevels.Success
            
        } else {
            # Key still exists after removal attempt
            Write-Log "    [FAILED] Still exists: $KeyPath" -Level ERROR
            
            $record = New-BrowserRecord -EntryPath $KeyPath -EntryType $EntryType `
                -Status $StatusLevels.Failed -ErrorMessage "Key still exists after removal"
            $RemediationResults.BrowserEntries.Failed += $record
            $RemediationResults.Summary.BrowserEntriesFailed++
            
            return $StatusLevels.Failed
        }
    } catch {
        $errorMsg = $_.Exception.Message
        Write-Log "    [ERROR] Failed to remove: $errorMsg" -Level ERROR
        
        $record = New-BrowserRecord -EntryPath $KeyPath -EntryType $EntryType `
            -Status $StatusLevels.Error -ErrorMessage $errorMsg
        $RemediationResults.BrowserEntries.Errored += $record
        $RemediationResults.Summary.BrowserEntriesErrored++
        
        $RemediationResults.CriticalErrors += "Browser Entry: $KeyPath - $errorMsg"
        return $StatusLevels.Error
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
    Comprehensive browser entry cleanup across:
    1. HKLM StartMenuInternet (system-wide browser registrations)
    2. Per-user HKU StartMenuInternet (user-specific registrations)
    3. ProgID classes (file type handlers)
    4. UserChoice associations (Windows-protected, read-only)
    5. Explorer FeatureUsage (usage tracking)
    
    .PARAMETER BrowserPatterns
    Wildcard patterns matching malicious browser entries (e.g., "OneStart*")
    
    .PARAMETER FeatureUsagePatterns
    Wildcard patterns matching usage tracking entries (optional)
    
    .NOTES
    UserChoice entries are Windows-protected and cannot be directly modified.
    They are noted but not removed (will reset when user changes defaults).

    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [array]$BrowserPatterns,
        
        [Parameter(Mandatory=$false)]
        [array]$FeatureUsagePatterns = @()
    )
    
    # Start module timing
    $moduleStartTime = Get-Date
    
    Write-Log "========================================" -Level INFO
    Write-Log "BROWSER ENTRY CLEANUP MODULE" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "Purpose: Removes browser hijacking entries to prevent false inventory" -Level INFO
    Write-Log "Browser patterns: $($BrowserPatterns.Count)" -Level INFO
    Write-Log "Feature patterns: $($FeatureUsagePatterns.Count)" -Level INFO
    
    $totalRemoved = 0
    
    # ========================================================================
    # PHASE 1: HKLM StartMenuInternet Entries
    # ========================================================================
    
    # System-wide browser registrations that appear in Windows default apps

    Write-Log "" -Level INFO
    Write-Log "Phase 1: Checking HKLM StartMenuInternet entries..." -Level INFO
    
    $hklmBrowserPath = "HKLM:\Software\Clients\StartMenuInternet"
    
    if (Test-Path $hklmBrowserPath) {
        foreach ($pattern in $BrowserPatterns) {
            # Find all matching browser registrations
            $matchingKeys = Get-ChildItem $hklmBrowserPath -ErrorAction SilentlyContinue |
                Where-Object { $_.PSChildName -like $pattern }
            
            if ($matchingKeys) {
                Write-Log "  [FOUND] $($matchingKeys.Count) HKLM browser registration(s) matching '$pattern'" -Level WARNING

                foreach ($key in $matchingKeys) {
                    $RemediationResults.Summary.BrowserEntriesChecked++
                    $RemediationResults.Summary.BrowserEntriesFound++
                    
                    $result = Remove-BrowserEntry -KeyPath $key.PSPath `
                        -EntryType "HKLM Browser Registration"
                    
                    if ($result -eq $StatusLevels.Success) { $totalRemoved++ }
                }
            } else {
                Write-Log "  [NOT FOUND] No HKLM browser registrations match '$pattern'" -Level INFO
            }
        }
    } else {
        Write-Log "  [NOT FOUND] HKLM StartMenuInternet key does not exist" -Level INFO
    }
    
    # ========================================================================
    # PHASE 2: Per-User StartMenuInternet Entries
    # ========================================================================
    
    # User-specific browser registrations (less common but possible)

    Write-Log "" -Level INFO
    Write-Log "Phase 2: Checking per-user StartMenuInternet entries..." -Level INFO
    
    $userSIDs = Get-UserSIDs
    Write-Log "  Processing $($userSIDs.Count) user profile(s)" -Level INFO
    
    foreach ($sid in $userSIDs) {
        Write-Log "  Checking SID: $sid" -Level INFO
        
        $hkuBrowserPath = "Registry::HKU\$sid\Software\Clients\StartMenuInternet"
        
        if (Test-Path $hkuBrowserPath) {
            foreach ($pattern in $BrowserPatterns) {
                $matchingKeys = Get-ChildItem $hkuBrowserPath -ErrorAction SilentlyContinue |
                    Where-Object { $_.PSChildName -like $pattern }
                
                if ($matchingKeys) {
                    Write-Log "    [FOUND] $($matchingKeys.Count) user browser registration(s) matching '$pattern'" -Level WARNING
                    
                    foreach ($key in $matchingKeys) {
                        $RemediationResults.Summary.BrowserEntriesChecked++
                        $RemediationResults.Summary.BrowserEntriesFound++
                        
                        $result = Remove-BrowserEntry -KeyPath $key.PSPath `
                            -EntryType "User Browser Registration"
                        
                        if ($result -eq $StatusLevels.Success) { $totalRemoved++ }
                    }
                }
            }
        }
    }
    
    # ========================================================================
    # PHASE 3: ProgID Classes (File Type Handlers)
    # ========================================================================
    
    # These define how file types open (e.g., .html, .pdf)

    Write-Log "" -Level INFO
    Write-Log "Phase 3: Checking ProgID classes..." -Level INFO
    
    # Check HKLM Classes (system-wide)
    $hklmClassesPath = "HKLM:\Software\Classes"
    if (Test-Path $hklmClassesPath) {
        Write-Log "  Checking HKLM\Software\Classes..." -Level INFO
        
        foreach ($pattern in $BrowserPatterns) {
            $matchingKeys = Get-ChildItem $hklmClassesPath -ErrorAction SilentlyContinue |
                Where-Object { $_.PSChildName -like $pattern }
            
            if ($matchingKeys) {
                Write-Log "    [FOUND] $($matchingKeys.Count) HKLM ProgID class(es) matching '$pattern'" -Level WARNING
                
                foreach ($key in $matchingKeys) {
                    $RemediationResults.Summary.BrowserEntriesChecked++
                    $RemediationResults.Summary.BrowserEntriesFound++
                    
                    $result = Remove-BrowserEntry -KeyPath $key.PSPath `
                        -EntryType "HKLM ProgID Class"
                    
                    if ($result -eq $StatusLevels.Success) { $totalRemoved++ }
                }
            }
        }
    }
    
    # Check per-user Classes
    foreach ($sid in $userSIDs) {
        
        $hkuClassesPath = "Registry::HKU\$sid\Software\Classes"
        
        if (Test-Path $hkuClassesPath) {

            Write-Log "  Checking HKU\$sid\Software\Classes..." -Level INFO   

            foreach ($pattern in $BrowserPatterns) {
                $matchingKeys = Get-ChildItem $hkuClassesPath -ErrorAction SilentlyContinue |
                    Where-Object { $_.PSChildName -like $pattern }
                
                if ($matchingKeys) {
                    Write-Log "    [FOUND] $($matchingKeys.Count) user ProgID class(es) matching '$pattern'" -Level WARNING
                    
                    foreach ($key in $matchingKeys) {
                        $RemediationResults.Summary.BrowserEntriesChecked++
                        $RemediationResults.Summary.BrowserEntriesFound++
                        
                        $result = Remove-BrowserEntry -KeyPath $key.PSPath `
                            -EntryType "User ProgID Class"
                        
                        if ($result -eq $StatusLevels.Success) { $totalRemoved++ }
                    }
                }
            }
        }
    }
    
    # ========================================================================
    # PHASE 4: UserChoice Associations (Read-Only)
    # ========================================================================
    # Windows 10+ protects these with hash validation - we can only note them
    
    Write-Log "" -Level INFO
    Write-Log "Phase 4: Checking UserChoice associations (Windows-protected)..." -Level INFO
    Write-Log "  Note: UserChoice entries are hash-protected and cannot be modified" -Level INFO
    Write-Log "  These will automatically reset when user changes default programs" -Level INFO
    
    foreach ($sid in $userSIDs) {
        $userChoicePath = "Registry::HKU\$sid\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts"
        
        if (Test-Path $userChoicePath) {
            # Enumerate all file extensions (.html, .pdf, etc.)
            $fileExts = Get-ChildItem $userChoicePath -ErrorAction SilentlyContinue
            
            foreach ($ext in $fileExts) {
                $userChoiceKey = Join-Path $ext.PSPath "UserChoice"
                
                if (Test-Path $userChoiceKey) {
                    try {
                        # Read the ProgId value (which program handles this extension)
                        $progId = (Get-ItemProperty $userChoiceKey -Name ProgId -ErrorAction SilentlyContinue).ProgId
                        
                        if ($progId) {
                            # Check if this ProgId matches our malware patterns
                            foreach ($pattern in $BrowserPatterns) {
                                if ($progId -like $pattern) {
                                    Write-Log "    [NOTED] UserChoice for $($ext.PSChildName) : $progId" -Level WARNING
                                    Write-Log "      Status: Windows-protected (hash validation)" -Level INFO
                                    Write-Log "      Action: Read-only (will reset on user change)" -Level INFO
                                    
                                    $RemediationResults.Summary.BrowserEntriesChecked++
                                    $RemediationResults.Summary.BrowserEntriesFound++
                                    
                                    # Track as "Noted" since we can't remove it
                                    $record = New-BrowserRecord -EntryPath $userChoiceKey `
                                        -EntryType "UserChoice (Protected)" `
                                        -Status $StatusLevels.Protected
                                    $RemediationResults.BrowserEntries.Noted += $record
                                    
                                    break  # Found match, move to next extension
                                }
                            }
                        }
                    } catch {
                        # Silent fail - UserChoice keys are often inaccessible
                    }
                }
            }
        }
    }
    
    # ========================================================================
    # PHASE 5: Explorer FeatureUsage Tracking (Optional)
    # ========================================================================
    # Windows tracks which apps are used for various features
    
    if ($FeatureUsagePatterns.Count -gt 0) {
        Write-Log "" -Level INFO
        Write-Log "Phase 5: Checking Explorer FeatureUsage tracking..." -Level INFO
        
        foreach ($sid in $userSIDs) {
            $featureUsagePaths = @(
                "Registry::HKU\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppBadgeUpdated",
                "Registry::HKU\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppLaunch"
            )
            
            foreach ($keyPath in $featureUsagePaths) {
                if (Test-Path $keyPath) {
                    Write-Log "  Checking: $keyPath" -Level INFO
                    
                    # Use existing helper function to remove matching values
                    $removed = Remove-RegistryValueByPattern -KeyPath $keyPath `
                        -ValuePatterns $FeatureUsagePatterns
                    
                    if ($removed -gt 0) {
                        Write-Log "    [SUCCESS] Removed $removed feature usage value(s)" -Level SUCCESS
                        $totalRemoved += $removed
                    }
                }
            }
        }
    }
    
    # ========================================================================
    # MODULE COMPLETION
    # ========================================================================
    
    # Stop module timing
    $moduleEndTime = Get-Date
    Write-ModuleTiming -ModuleName "BrowserEntries" -StartTime $moduleStartTime -EndTime $moduleEndTime
    
    # Log summary
    Write-Log "" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "BROWSER ENTRY CLEANUP SUMMARY" -Level INFO
    Write-Log "  Entries Checked: $($RemediationResults.Summary.BrowserEntriesChecked)" -Level INFO
    Write-Log "  Entries Found: $($RemediationResults.Summary.BrowserEntriesFound)" -Level INFO
    Write-Log "  Entries Removed: $($RemediationResults.Summary.BrowserEntriesRemoved)" -Level SUCCESS
    Write-Log "  Entries Failed: $($RemediationResults.Summary.BrowserEntriesFailed)" -Level ERROR
    Write-Log "  Entries Errored: $($RemediationResults.Summary.BrowserEntriesErrored)" -Level ERROR
    Write-Log "  Entries Noted (Protected): $($RemediationResults.BrowserEntries.Noted.Count)" -Level INFO
    Write-Log "" -Level INFO
    Write-Log "  Note: UserChoice entries are Windows-protected and will reset naturally" -Level INFO
    Write-Log "  when the user changes default program associations." -Level INFO
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

    These registry values store Windows' memory of which file associations
    it has already prompted the user about. When malware is removed,
    these entries can become orphaned and cause confusion in the file
    association UI.

    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [array]$AssociationPatterns
    )
    
    # --------------------------------------------------------------------
    # Module Initialization
    # --------------------------------------------------------------------
    
    # Start timing for this module
    $moduleStartTime = Get-Date
    
    Write-Log "========================================" -Level INFO
    Write-Log "FILE ASSOCIATION CLEANUP MODULE" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "Removes orphaned ApplicationAssociationToasts entries" -Level INFO
    Write-Log "Target patterns: $($AssociationPatterns.Count)" -Level INFO
    Write-Log "" -Level INFO
        
    # --------------------------------------------------------------------
    # Phase 1: Enumerate User Profiles
    # --------------------------------------------------------------------

    # Get all user SIDs from the registry to process each user's associations
  
    $userSIDs = Get-UserSIDs
    Write-Log "Found $($userSIDs.Count) user profile(s) to process" -Level INFO
    
    # --------------------------------------------------------------------
    # Phase 2: Process Each User Profile
    # --------------------------------------------------------------------
    
    foreach ($sid in $userSIDs) {
        Write-Log "" -Level INFO
        Write-Log "Processing SID: $sid" -Level INFO

        # Build the full registry path to ApplicationAssociationToasts
        # This key stores Windows' memory of which file associations
        # it has already prompted the user about (prevents repeated prompts)
        
        $assocPath = "Registry::HKU\$sid\Software\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts"

        # Increment the counter for keys checked

        $RemediationResults.Summary.FileAssociationsChecked++
        
        # ------------------------------------------------------------
        # Check if the registry key exists
        # ------------------------------------------------------------

        if (-not (Test-Path $assocPath)) {
            Write-Log "  [NOT FOUND] ApplicationAssociationToasts key does not exist" -Level INFO
            
            # Create a tracking record for this missing key
            $record = New-RegistryRecord -KeyPath $assocPath -ValueName "N/A" `
                -Status $StatusLevels.NotFound
            $RemediationResults.FileAssociations.NotFound += $record
            $RemediationResults.Summary.FileAssociationsNotFound++
            continue
        }
        
        Write-Log "  [FOUND] ApplicationAssociationToasts key exists" -Level INFO
        
        # ------------------------------------------------------------
        # Access the registry key and enumerate values
        # ------------------------------------------------------------
        
        try {
            # Get all property values from the registry key
            # Each value represents a file association prompt Windows has shown
            $properties = Get-ItemProperty -Path $assocPath -ErrorAction Stop
            
            # ------------------------------------------------------------
            # Process each association pattern
            # ------------------------------------------------------------
            
            foreach ($pattern in $AssociationPatterns) {
                Write-Log "  Checking pattern: $pattern" -Level INFO
                
                # Find registry values that match the current pattern
                # Filter out PowerShell metadata properties (they start with "PS")
                $matchingValues = $properties.PSObject.Properties | 
                    Where-Object { $_.Name -like $pattern -and $_.Name -notlike "PS*" }

                # Check if any values matched the pattern
                if ($matchingValues.Count -eq 0) {
                    Write-Log "    [NOT FOUND] No values match pattern: $pattern" -Level INFO
                    continue
                }
                
                Write-Log "    [FOUND] $($matchingValues.Count) value(s) match pattern" -Level WARNING
                
                # ----------------------------------------------------
                # Process each matching registry value
                # ----------------------------------------------------
                
                foreach ($value in $matchingValues) {
                    $valueName = $value.Name
                    $valueData = $value.Value
                    
                    # Increment the counter for associations found

                    $RemediationResults.Summary.FileAssociationsFound++
                    
                    Write-Log "      Value: $valueName = $valueData" -Level WARNING
                    
                    # ------------------------------------------------
                    # Attempt to remove the registry value
                    # ------------------------------------------------
                    
                    try {
                        # Remove the registry value
                        Remove-ItemProperty -Path $assocPath -Name $valueName -ErrorAction Stop
                        
                        # Brief pause to allow registry to commit changes
                        Start-Sleep -Milliseconds 200
                        
                        # Verify the value was actually removed
                        $checkValue = Get-ItemProperty -Path $assocPath -Name $valueName -ErrorAction SilentlyContinue
                        
                        if (-not $checkValue) {
                            # Success - value no longer exists
                            Write-Log "      [SUCCESS] Removed association value" -Level SUCCESS
                            
                            # Create tracking record for successful removal
                            $record = New-RegistryRecord -KeyPath $assocPath -ValueName $valueName `
                                -Status $StatusLevels.Success -ValueData $valueData
                            $RemediationResults.FileAssociations.Removed += $record
                            $RemediationResults.Summary.FileAssociationsRemoved++
                            
                        } else {
                            # Failed - value still exists after removal attempt
                            Write-Log "      [FAILED] Value still exists after removal" -Level ERROR
                            
                            $record = New-RegistryRecord -KeyPath $assocPath -ValueName $valueName `
                                -Status $StatusLevels.Failed -ValueData $valueData `
                                -ErrorMessage "Value still exists after removal attempt"
                            $RemediationResults.FileAssociations.Failed += $record
                            $RemediationResults.Summary.FileAssociationsFailed++
                        }
                        
                    } catch {
                        # Exception occurred during removal attempt

                        $errorMsg = $_.Exception.Message
                        Write-Log "      [ERROR] Failed to remove: $errorMsg" -Level ERROR
                        
                        # Create tracking record for error
                        $record = New-RegistryRecord -KeyPath $assocPath -ValueName $valueName `
                            -Status $StatusLevels.Error -ValueData $valueData -ErrorMessage $errorMsg
                        $RemediationResults.FileAssociations.Errored += $record
                        $RemediationResults.Summary.FileAssociationsErrored++
                        
                        $RemediationResults.CriticalErrors += "FileAssociation: $valueName - $errorMsg"
                    }
                }
            }
                      
        } catch {
            # Exception occurred while accessing the registry key
            $errorMsg = $_.Exception.Message
            Write-Log "  [ERROR] Cannot access ApplicationAssociationToasts: $errorMsg" -Level ERROR
            
            # Create tracking record for key access error
            $record = New-RegistryRecord -KeyPath $assocPath -ValueName "N/A" `
                -Status $StatusLevels.Error -ErrorMessage $errorMsg
            $RemediationResults.FileAssociations.Errored += $record
            $RemediationResults.Summary.FileAssociationsErrored++
            
            # Add to critical errors list
            $RemediationResults.CriticalErrors += "FileAssociation Key: $assocPath - $errorMsg"
        }
    }
    
    # --------------------------------------------------------------------
    # Module Completion
    # --------------------------------------------------------------------
    
    Write-Log "" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "FILE ASSOCIATION CLEANUP SUMMARY" -Level INFO
    Write-Log "  Keys Checked: $($RemediationResults.Summary.FileAssociationsChecked)" -Level INFO
    Write-Log "  Values Found: $($RemediationResults.Summary.FileAssociationsFound)" -Level INFO
    Write-Log "  Values Removed: $($RemediationResults.Summary.FileAssociationsRemoved)" -Level SUCCESS
    Write-Log "  Values Failed: $($RemediationResults.Summary.FileAssociationsFailed)" -Level ERROR
    Write-Log "  Values Errored: $($RemediationResults.Summary.FileAssociationsErrored)" -Level ERROR
    Write-Log "  Values Not Found: $($RemediationResults.Summary.FileAssociationsNotFound)" -Level INFO
    Write-Log "  ---" -Level INFO
    Write-Log "  Note: Clears orphaned file association prompts" -Level INFO
    Write-Log "  Note: Users may see file association prompts again for affected types" -Level INFO
    Write-Log "========================================" -Level INFO

    # End timing and record module execution duration
    $moduleEndTime = Get-Date
    Write-ModuleTiming -ModuleName "FileAssociations" -StartTime $moduleStartTime -EndTime $moduleEndTime

}

# ============================================================================ #
# EXECUTION
# ============================================================================ #

# ----------------------------------------------------------------------------
# Execution Start
# ----------------------------------------------------------------------------

Write-Log "============================================" -Level INFO
Write-Log "MALWARE REMEDIATION FRAMEWORK" -Level INFO
Write-Log "Target: $($MalwareConfig.Metadata.ThreatFamily)" -Level INFO
Write-Log "Version: $($MalwareConfig.Metadata.Version)" -Level INFO
Write-Log "Severity: $($MalwareConfig.Metadata.Severity)" -Level INFO
Write-Log "Started: $($RemediationResults.StartTime)" -Level INFO
Write-Log "============================================" -Level INFO
Write-Log "" -Level INFO

# ----------------------------------------------------------------------------
# EXECUTION ORDER (CRITICAL - DO NOT CHANGE WITHOUT CAREFUL CONSIDERATION)
# ----------------------------------------------------------------------------
# The order of remediation steps is designed to prevent malware from
# restarting or re-establishing persistence during cleanup:
#
# 1. PROCESSES - Kill active malware immediately (stops current execution)
# 2. SERVICES - Remove service entries (prevents process auto-restart)
# 3. CERTIFICATES - Remove malicious trust anchors (prevents re-trust/re-download)
# 4. SCHEDULED TASKS - Remove task persistence (prevents scheduled restarts)
# 5. REGISTRY PERSISTENCE - Remove Run keys (prevents boot/login restarts)
# 6. FILES & FOLDERS - Safe to delete now (nothing using them)
# 7. REGISTRY CLEANUP - Remove configuration/artifacts (cleanup phase)
# 8. BROWSER ENTRIES - Remove browser hijacking entries (prevent false inventory)
# 9. FILE ASSOCIATIONS - Remove orphaned association tracking (cleanup phase)
# ----------------------------------------------------------------------------

# ----------------------------------------------------------------------------
# MODULE 1: PROCESS TERMINATION
# ----------------------------------------------------------------------------
# Purpose: Stop all active malware processes immediately
# Critical: Must be first to stop active execution
# ----------------------------------------------------------------------------

$moduleStartTime = Get-Date
Write-Log "" -Level INFO
Write-Log "MODULE 1/9: PROCESS TERMINATION" -Level INFO
Write-Log "--------------------------------------------" -Level INFO

try {
    Stop-MalwareProcess -ProcessNames $MalwareConfig.Processes
    
    $moduleEndTime = Get-Date
    Write-ModuleTiming -ModuleName "Processes" -StartTime $moduleStartTime -EndTime $moduleEndTime
    
    Write-Log "  Status: COMPLETE" -Level SUCCESS
} catch {
    $moduleEndTime = Get-Date
    Write-ModuleTiming -ModuleName "Processes" -StartTime $moduleStartTime -EndTime $moduleEndTime
    
    Write-Log "  Status: ERROR - $($_.Exception.Message)" -Level ERROR
    $RemediationResults.CriticalErrors += "Process Termination Module: $($_.Exception.Message)"
}

Start-Sleep -Seconds 2

# ----------------------------------------------------------------------------
# MODULE 2: SERVICE REMEDIATION
# ----------------------------------------------------------------------------
# Purpose: Stop and remove malware services
# Critical: Prevents automatic restart of processes
# ----------------------------------------------------------------------------

$moduleStartTime = Get-Date
Write-Log "" -Level INFO
Write-Log "MODULE 2/9: SERVICE REMEDIATION" -Level INFO
Write-Log "--------------------------------------------" -Level INFO

try {
    Stop-MalwareService -ServiceNames $MalwareConfig.Services
    
    $moduleEndTime = Get-Date
    Write-ModuleTiming -ModuleName "Services" -StartTime $moduleStartTime -EndTime $moduleEndTime
    
    Write-Log "  Status: COMPLETE" -Level SUCCESS
} catch {
    $moduleEndTime = Get-Date
    Write-ModuleTiming -ModuleName "Services" -StartTime $moduleStartTime -EndTime $moduleEndTime
    
    Write-Log "  Status: ERROR - $($_.Exception.Message)" -Level ERROR
    $RemediationResults.CriticalErrors += "Service Remediation Module: $($_.Exception.Message)"
}

Start-Sleep -Seconds 2

# ----------------------------------------------------------------------------
# MODULE 3: CERTIFICATE ANALYSIS & REMEDIATION
# ----------------------------------------------------------------------------
# Purpose: Remove malicious certificates from trust stores
# Critical: Prevents malware from re-establishing trust or downloading updates
# Note: Uses enhanced detection with known malicious + suspicious unknown
# ----------------------------------------------------------------------------

$moduleStartTime = Get-Date
Write-Log "" -Level INFO
Write-Log "MODULE 3/9: CERTIFICATE ANALYSIS & REMEDIATION" -Level INFO
Write-Log "--------------------------------------------" -Level INFO

try {
    Remove-MalwareCertificates -CertConfig $MalwareConfig.Certificates
    
    $moduleEndTime = Get-Date
    Write-ModuleTiming -ModuleName "Certificates" -StartTime $moduleStartTime -EndTime $moduleEndTime
    
    Write-Log "  Status: COMPLETE" -Level SUCCESS
} catch {
    $moduleEndTime = Get-Date
    Write-ModuleTiming -ModuleName "Certificates" -StartTime $moduleStartTime -EndTime $moduleEndTime
    
    Write-Log "  Status: ERROR - $($_.Exception.Message)" -Level ERROR
    $RemediationResults.CriticalErrors += "Certificate Remediation Module: $($_.Exception.Message)"
}

Start-Sleep -Seconds 2

# ----------------------------------------------------------------------------
# MODULE 4: SCHEDULED TASK REMEDIATION
# ----------------------------------------------------------------------------
# Purpose: Remove scheduled tasks and TaskCache entries
# Critical: Prevents persistence via Task Scheduler
# Note: Includes two-phase cleanup (tasks + TaskCache orphans)
# ----------------------------------------------------------------------------

$moduleStartTime = Get-Date
Write-Log "" -Level INFO
Write-Log "MODULE 4/9: SCHEDULED TASK REMEDIATION" -Level INFO
Write-Log "--------------------------------------------" -Level INFO

try {
    Remove-MalwareTask -TaskPatterns $MalwareConfig.TaskPatterns
    
    $moduleEndTime = Get-Date
    Write-ModuleTiming -ModuleName "Tasks" -StartTime $moduleStartTime -EndTime $moduleEndTime
    
    Write-Log "  Status: COMPLETE" -Level SUCCESS
} catch {
    $moduleEndTime = Get-Date
    Write-ModuleTiming -ModuleName "Tasks" -StartTime $moduleStartTime -EndTime $moduleEndTime
    
    Write-Log "  Status: ERROR - $($_.Exception.Message)" -Level ERROR
    $RemediationResults.CriticalErrors += "Scheduled Task Remediation Module: $($_.Exception.Message)"
}

Start-Sleep -Seconds 2

# ----------------------------------------------------------------------------
# MODULE 5: REGISTRY PERSISTENCE REMOVAL
# ----------------------------------------------------------------------------
# Purpose: Remove Run keys, RegisteredApplications, and Feature Usage tracking
# Critical: Prevents autostart at boot/login
# Note: Covers HKLM and per-user hives (HKU)
# ----------------------------------------------------------------------------

$moduleStartTime = Get-Date
Write-Log "" -Level INFO
Write-Log "MODULE 5/9: REGISTRY PERSISTENCE REMOVAL" -Level INFO
Write-Log "--------------------------------------------" -Level INFO

try {
    Remove-MalwareRegistryPersistence -RunKeyPatterns $MalwareConfig.RunKeyPatterns `
        -RegisteredAppPatterns $MalwareConfig.RegisteredAppPatterns `
        -FeatureUsagePatterns $MalwareConfig.FeatureUsagePatterns
    
    $moduleEndTime = Get-Date
    Write-ModuleTiming -ModuleName "RegistryPersistence" -StartTime $moduleStartTime -EndTime $moduleEndTime
    
    Write-Log "  Status: COMPLETE" -Level SUCCESS
} catch {
    $moduleEndTime = Get-Date
    Write-ModuleTiming -ModuleName "RegistryPersistence" -StartTime $moduleStartTime -EndTime $moduleEndTime
    
    Write-Log "  Status: ERROR - $($_.Exception.Message)" -Level ERROR
    $RemediationResults.CriticalErrors += "Registry Persistence Removal Module: $($_.Exception.Message)"
}

Start-Sleep -Seconds 2

# ----------------------------------------------------------------------------
# MODULE 6: FILE & FOLDER CLEANUP
# ----------------------------------------------------------------------------
# Purpose: Remove malware files and installation directories
# Safe: No processes/services using these files (already terminated)
# Note: Covers user profiles, Downloads, and system-level paths
# ----------------------------------------------------------------------------

$moduleStartTime = Get-Date
Write-Log "" -Level INFO
Write-Log "MODULE 6/9: FILE & FOLDER CLEANUP" -Level INFO
Write-Log "--------------------------------------------" -Level INFO

try {
    Remove-MalwareFiles -UserPaths $MalwareConfig.UserPaths `
        -DownloadPatterns $MalwareConfig.DownloadPatterns `
        -SystemPaths $MalwareConfig.SystemPaths
    
    $moduleEndTime = Get-Date
    Write-ModuleTiming -ModuleName "Files" -StartTime $moduleStartTime -EndTime $moduleEndTime
    
    Write-Log "  Status: COMPLETE" -Level SUCCESS
} catch {
    $moduleEndTime = Get-Date
    Write-ModuleTiming -ModuleName "Files" -StartTime $moduleStartTime -EndTime $moduleEndTime
    
    Write-Log "  Status: ERROR - $($_.Exception.Message)" -Level ERROR
    $RemediationResults.CriticalErrors += "File & Folder Cleanup Module: $($_.Exception.Message)"
}

Start-Sleep -Seconds 2

# ----------------------------------------------------------------------------
# MODULE 7: REGISTRY CLEANUP (ARTIFACTS & CONFIGURATION)
# ----------------------------------------------------------------------------
# Purpose: Remove remaining registry artifacts and configuration
# Note: Covers HKLM paths and per-user patterns (HKU)
# Includes: Tracing, MediaPlayer, uninstall entries, COM objects
# ----------------------------------------------------------------------------

$moduleStartTime = Get-Date
Write-Log "" -Level INFO
Write-Log "MODULE 7/9: REGISTRY CLEANUP (ARTIFACTS)" -Level INFO
Write-Log "--------------------------------------------" -Level INFO

try {
    Remove-MalwareRegistryKeys -HKLMPaths $MalwareConfig.RegistryHKLM `
        -HKUPatterns $MalwareConfig.RegistryHKUPatterns
    
    $moduleEndTime = Get-Date
    Write-ModuleTiming -ModuleName "RegistryCleanup" -StartTime $moduleStartTime -EndTime $moduleEndTime
    
    Write-Log "  Status: COMPLETE" -Level SUCCESS
} catch {
    $moduleEndTime = Get-Date
    Write-ModuleTiming -ModuleName "RegistryCleanup" -StartTime $moduleStartTime -EndTime $moduleEndTime
    
    Write-Log "  Status: ERROR - $($_.Exception.Message)" -Level ERROR
    $RemediationResults.CriticalErrors += "Registry Cleanup Module: $($_.Exception.Message)"
}

Start-Sleep -Seconds 2

# ----------------------------------------------------------------------------
# MODULE 8: BROWSER ENTRY CLEANUP
# ----------------------------------------------------------------------------
# Purpose: Remove browser hijacking entries to prevent false inventory
# Note: Covers StartMenuInternet, ProgID classes, and Feature Usage
# Special: Reports UserChoice keys (Windows-protected, cannot be removed)
# ----------------------------------------------------------------------------

$moduleStartTime = Get-Date
Write-Log "" -Level INFO
Write-Log "MODULE 8/9: BROWSER ENTRY CLEANUP" -Level INFO
Write-Log "--------------------------------------------" -Level INFO

try {
    Remove-MalwareBrowserEntries -BrowserPatterns $MalwareConfig.BrowserStartMenuPatterns `
        -FeatureUsagePatterns $MalwareConfig.FeatureUsagePatterns
    
    $moduleEndTime = Get-Date
    Write-ModuleTiming -ModuleName "BrowserEntries" -StartTime $moduleStartTime -EndTime $moduleEndTime
    
    Write-Log "  Status: COMPLETE" -Level SUCCESS
} catch {
    $moduleEndTime = Get-Date
    Write-ModuleTiming -ModuleName "BrowserEntries" -StartTime $moduleStartTime -EndTime $moduleEndTime
    
    Write-Log "  Status: ERROR - $($_.Exception.Message)" -Level ERROR
    $RemediationResults.CriticalErrors += "Browser Entry Cleanup Module: $($_.Exception.Message)"
}

Start-Sleep -Seconds 2

# ----------------------------------------------------------------------------
# MODULE 9: FILE ASSOCIATION CLEANUP
# ----------------------------------------------------------------------------
# Purpose: Remove orphaned ApplicationAssociationToasts entries
# Note: Prevents broken "Open with" references to deleted malware
# Safe: Final cleanup phase, no functional impact
# ----------------------------------------------------------------------------

$moduleStartTime = Get-Date
Write-Log "" -Level INFO
Write-Log "MODULE 9/9: FILE ASSOCIATION CLEANUP" -Level INFO
Write-Log "--------------------------------------------" -Level INFO

try {
    if ($MalwareConfig.ApplicationAssociationPatterns -and $MalwareConfig.ApplicationAssociationPatterns.Count -gt 0) {
        Remove-MalwareFileAssociations -AssociationPatterns $MalwareConfig.ApplicationAssociationPatterns
        
        $moduleEndTime = Get-Date
        Write-ModuleTiming -ModuleName "FileAssociations" -StartTime $moduleStartTime -EndTime $moduleEndTime
        
        Write-Log "  Status: COMPLETE" -Level SUCCESS
    } else {
        Write-Log "  Status: SKIPPED (No patterns configured)" -Level INFO
        $RemediationResults.ModuleTiming.FileAssociations = 0
    }
} catch {
    $moduleEndTime = Get-Date
    Write-ModuleTiming -ModuleName "FileAssociations" -StartTime $moduleStartTime -EndTime $moduleEndTime
    
    Write-Log "  Status: ERROR - $($_.Exception.Message)" -Level ERROR
    $RemediationResults.CriticalErrors += "File Association Cleanup Module: $($_.Exception.Message)"
}

# ----------------------------------------------------------------------------
# Execution Complete
# ----------------------------------------------------------------------------

$RemediationResults.EndTime = Get-Date
$totalDuration = $RemediationResults.EndTime - $RemediationResults.StartTime

Write-Log "" -Level INFO
Write-Log "============================================" -Level INFO
Write-Log "REMEDIATION COMPLETE" -Level SUCCESS
Write-Log "============================================" -Level INFO
Write-Log "Total Duration: $([math]::Round($totalDuration.TotalSeconds, 2)) seconds" -Level INFO
Write-Log "Log File: $logFile" -Level INFO
Write-Log "============================================" -Level INFO

# ============================================================================ #
# FINAL REPORT
# ============================================================================ #

Write-Log "" -Level INFO
Write-Log "============================================" -Level INFO
Write-Log "FINAL SUMMARY REPORT" -Level INFO
Write-Log "============================================" -Level INFO
Write-Log "" -Level INFO

# ----------------------------------------------------------------------------
# Module Timing Summary
# ----------------------------------------------------------------------------

Write-Log "MODULE TIMING BREAKDOWN:" -Level INFO
Write-Log "  1. Processes:            $($RemediationResults.ModuleTiming.Processes) sec" -Level INFO
Write-Log "  2. Services:             $($RemediationResults.ModuleTiming.Services) sec" -Level INFO
Write-Log "  3. Certificates:         $($RemediationResults.ModuleTiming.Certificates) sec" -Level INFO
Write-Log "  4. Scheduled Tasks:      $($RemediationResults.ModuleTiming.Tasks) sec" -Level INFO
Write-Log "  5. Registry Persistence: $($RemediationResults.ModuleTiming.RegistryPersistence) sec" -Level INFO
Write-Log "  6. Files & Folders:      $($RemediationResults.ModuleTiming.Files) sec" -Level INFO
Write-Log "  7. Registry Cleanup:     $($RemediationResults.ModuleTiming.RegistryCleanup) sec" -Level INFO
Write-Log "  8. Browser Entries:      $($RemediationResults.ModuleTiming.BrowserEntries) sec" -Level INFO
Write-Log "  9. File Associations:    $($RemediationResults.ModuleTiming.FileAssociations) sec" -Level INFO
Write-Log "" -Level INFO

# ----------------------------------------------------------------------------
# Detailed Results Summary
# ----------------------------------------------------------------------------

Write-Log "DETAILED RESULTS:" -Level INFO
Write-Log "" -Level INFO

# Processes
Write-Log "PROCESSES:" -Level INFO
Write-Log "  Checked:    $($RemediationResults.Summary.ProcessesChecked)" -Level INFO
Write-Log "  Found:      $($RemediationResults.Summary.ProcessesFound)" -Level INFO
Write-Log "  Terminated: $($RemediationResults.Summary.ProcessesTerminated)" -Level SUCCESS
Write-Log "  Failed:     $($RemediationResults.Summary.ProcessesFailed)" -Level ERROR
Write-Log "  Errored:    $($RemediationResults.Summary.ProcessesErrored)" -Level ERROR
Write-Log "  Not Found:  $($RemediationResults.Summary.ProcessesNotFound)" -Level INFO
Write-Log "" -Level INFO

# Services
Write-Log "SERVICES:" -Level INFO
Write-Log "  Checked:    $($RemediationResults.Summary.ServicesChecked)" -Level INFO
Write-Log "  Found:      $($RemediationResults.Summary.ServicesFound)" -Level INFO
Write-Log "  Removed:    $($RemediationResults.Summary.ServicesRemoved)" -Level SUCCESS
Write-Log "  Failed:     $($RemediationResults.Summary.ServicesFailed)" -Level ERROR
Write-Log "  Errored:    $($RemediationResults.Summary.ServicesErrored)" -Level ERROR
Write-Log "  Not Found:  $($RemediationResults.Summary.ServicesNotFound)" -Level INFO
Write-Log "" -Level INFO

# Certificates
Write-Log "CERTIFICATES:" -Level INFO
Write-Log "  Stores Checked:  $($RemediationResults.Summary.CertStoresChecked)" -Level INFO
Write-Log "  Total Scanned:   $($RemediationResults.Summary.CertificatesScanned)" -Level INFO
Write-Log "  Flagged:         $($RemediationResults.Summary.CertificatesFlagged)" -Level WARNING
Write-Log "  Removed:         $($RemediationResults.Summary.CertificatesRemoved)" -Level SUCCESS
Write-Log "  Failed:          $($RemediationResults.Summary.CertificatesFailed)" -Level ERROR
Write-Log "  Errored:         $($RemediationResults.Summary.CertificatesErrored)" -Level ERROR
Write-Log "  Not Found:       $($RemediationResults.Summary.CertificatesNotFound)" -Level INFO
Write-Log "" -Level INFO

# Scheduled Tasks
Write-Log "SCHEDULED TASKS:" -Level INFO
Write-Log "  Checked:    $($RemediationResults.Summary.TasksChecked)" -Level INFO
Write-Log "  Found:      $($RemediationResults.Summary.TasksFound)" -Level INFO
Write-Log "  Removed:    $($RemediationResults.Summary.TasksRemoved)" -Level SUCCESS
Write-Log "  Failed:     $($RemediationResults.Summary.TasksFailed)" -Level ERROR
Write-Log "  Errored:    $($RemediationResults.Summary.TasksErrored)" -Level ERROR
Write-Log "  Not Found:  $($RemediationResults.Summary.TasksNotFound)" -Level INFO
Write-Log "" -Level INFO

# TaskCache
Write-Log "TASKCACHE:" -Level INFO
Write-Log "  Checked:    $($RemediationResults.Summary.TaskCacheChecked)" -Level INFO
Write-Log "  Found:      $($RemediationResults.Summary.TaskCacheFound)" -Level INFO
Write-Log "  Removed:    $($RemediationResults.Summary.TaskCacheRemoved)" -Level SUCCESS
Write-Log "  Failed:     $($RemediationResults.Summary.TaskCacheFailed)" -Level ERROR
Write-Log "  Errored:    $($RemediationResults.Summary.TaskCacheErrored)" -Level ERROR
Write-Log "  Not Found:  $($RemediationResults.Summary.TaskCacheNotFound)" -Level INFO
Write-Log "" -Level INFO

# Registry
Write-Log "REGISTRY:" -Level INFO
Write-Log "  Keys Checked:    $($RemediationResults.Summary.RegistryKeysChecked)" -Level INFO
Write-Log "  Values Found:    $($RemediationResults.Summary.RegistryValuesFound)" -Level INFO
Write-Log "  Values Removed:  $($RemediationResults.Summary.RegistryValuesRemoved)" -Level SUCCESS
Write-Log "  Values Failed:   $($RemediationResults.Summary.RegistryValuesFailed)" -Level ERROR
Write-Log "  Values Errored:  $($RemediationResults.Summary.RegistryValuesErrored)" -Level ERROR
Write-Log "  Values Not Found: $($RemediationResults.Summary.RegistryValuesNotFound)" -Level INFO
Write-Log "" -Level INFO

# Files & Folders
Write-Log "FILES & FOLDERS:" -Level INFO
Write-Log "  Paths Checked:  $($RemediationResults.Summary.PathsChecked)" -Level INFO
Write-Log "  Paths Found:    $($RemediationResults.Summary.PathsFound)" -Level INFO
Write-Log "  Paths Removed:  $($RemediationResults.Summary.PathsRemoved)" -Level SUCCESS
Write-Log "  Paths Failed:   $($RemediationResults.Summary.PathsFailed)" -Level ERROR
Write-Log "  Paths Errored:  $($RemediationResults.Summary.PathsErrored)" -Level ERROR
Write-Log "  Paths Not Found: $($RemediationResults.Summary.PathsNotFound)" -Level INFO
Write-Log "" -Level INFO

# Browser Entries
Write-Log "BROWSER ENTRIES:" -Level INFO
Write-Log "  Checked:    $($RemediationResults.Summary.BrowserEntriesChecked)" -Level INFO
Write-Log "  Found:      $($RemediationResults.Summary.BrowserEntriesFound)" -Level INFO
Write-Log "  Removed:    $($RemediationResults.Summary.BrowserEntriesRemoved)" -Level SUCCESS
Write-Log "  Failed:     $($RemediationResults.Summary.BrowserEntriesFailed)" -Level ERROR
Write-Log "  Errored:    $($RemediationResults.Summary.BrowserEntriesErrored)" -Level ERROR
Write-Log "  Not Found:  $($RemediationResults.Summary.BrowserEntriesNotFound)" -Level INFO
Write-Log "" -Level INFO

# File Associations
Write-Log "FILE ASSOCIATIONS:" -Level INFO
Write-Log "  Checked:    $($RemediationResults.Summary.FileAssociationsChecked)" -Level INFO
Write-Log "  Found:      $($RemediationResults.Summary.FileAssociationsFound)" -Level INFO
Write-Log "  Removed:    $($RemediationResults.Summary.FileAssociationsRemoved)" -Level SUCCESS
Write-Log "  Failed:     $($RemediationResults.Summary.FileAssociationsFailed)" -Level ERROR
Write-Log "  Errored:    $($RemediationResults.Summary.FileAssociationsErrored)" -Level ERROR
Write-Log "  Not Found:  $($RemediationResults.Summary.FileAssociationsNotFound)" -Level INFO
Write-Log "" -Level INFO

# ----------------------------------------------------------------------------
# Overall Totals Calculation
# ----------------------------------------------------------------------------

$RemediationResults.Summary.TotalActionsAttempted = (
    $RemediationResults.Summary.ProcessesChecked +
    $RemediationResults.Summary.ServicesChecked +
    $RemediationResults.Summary.CertStoresChecked +
    $RemediationResults.Summary.TasksChecked +
    $RemediationResults.Summary.TaskCacheChecked +
    $RemediationResults.Summary.RegistryKeysChecked +
    $RemediationResults.Summary.PathsChecked +
    $RemediationResults.Summary.BrowserEntriesChecked +
    $RemediationResults.Summary.FileAssociationsChecked
)

$RemediationResults.Summary.TotalActionsSuccessful = (
    $RemediationResults.Summary.ProcessesTerminated +
    $RemediationResults.Summary.ServicesRemoved +
    $RemediationResults.Summary.CertificatesRemoved +
    $RemediationResults.Summary.TasksRemoved +
    $RemediationResults.Summary.TaskCacheRemoved +
    $RemediationResults.Summary.RegistryValuesRemoved +
    $RemediationResults.Summary.PathsRemoved +
    $RemediationResults.Summary.BrowserEntriesRemoved +
    $RemediationResults.Summary.FileAssociationsRemoved
)

$RemediationResults.Summary.TotalActionsFailed = (
    $RemediationResults.Summary.ProcessesFailed +
    $RemediationResults.Summary.ServicesFailed +
    $RemediationResults.Summary.CertificatesFailed +
    $RemediationResults.Summary.TasksFailed +
    $RemediationResults.Summary.TaskCacheFailed +
    $RemediationResults.Summary.RegistryValuesFailed +
    $RemediationResults.Summary.PathsFailed +
    $RemediationResults.Summary.BrowserEntriesFailed +
    $RemediationResults.Summary.FileAssociationsFailed
)

# ----------------------------------------------------------------------------
# Overall Summary
# ----------------------------------------------------------------------------

Write-Log "OVERALL TOTALS:" -Level INFO
Write-Log "  Actions Attempted:  $($RemediationResults.Summary.TotalActionsAttempted)" -Level INFO
Write-Log "  Actions Successful: $($RemediationResults.Summary.TotalActionsSuccessful)" -Level SUCCESS
Write-Log "  Actions Failed:     $($RemediationResults.Summary.TotalActionsFailed)" -Level ERROR
Write-Log "" -Level INFO

# Calculate success rate
if ($RemediationResults.Summary.TotalActionsAttempted -gt 0) {
    $successRate = [math]::Round(($RemediationResults.Summary.TotalActionsSuccessful / $RemediationResults.Summary.TotalActionsAttempted) * 100, 2)
    Write-Log "SUCCESS RATE: $successRate%" -Level INFO
} else {
    Write-Log "SUCCESS RATE: N/A (No actions attempted)" -Level INFO
}

Write-Log "" -Level INFO

# ----------------------------------------------------------------------------
# Critical Errors Report
# ----------------------------------------------------------------------------

if ($RemediationResults.CriticalErrors.Count -gt 0) {
    Write-Log "============================================" -Level ERROR
    Write-Log "CRITICAL ERRORS DETECTED: $($RemediationResults.CriticalErrors.Count)" -Level ERROR
    Write-Log "============================================" -Level ERROR
    Write-Log "" -Level ERROR
    
    foreach ($errorCrit in $RemediationResults.CriticalErrors) {
        Write-Log "  * $errorCrit" -Level ERROR
    }
    
    Write-Log "" -Level ERROR
    Write-Log "ACTION REQUIRED: Review critical errors above" -Level ERROR
    Write-Log "Some items may require manual removal" -Level ERROR
    Write-Log "============================================" -Level ERROR
} else {
    Write-Log "============================================" -Level SUCCESS
    Write-Log "NO CRITICAL ERRORS" -Level SUCCESS
    Write-Log "============================================" -Level SUCCESS
}

Write-Log "" -Level INFO
Write-Log "============================================" -Level INFO
Write-Log "END OF REPORT" -Level INFO
Write-Log "============================================" -Level INFO

# ----------------------------------------------------------------------------
# Display Results to Console
# ----------------------------------------------------------------------------

Write-Output ""
Write-Output "=========================================="
Write-Output "REMEDIATION COMPLETE"
Write-Output "=========================================="
Write-Output "Target:          $($MalwareConfig.Metadata.ThreatFamily)"
Write-Output "Duration:        $([math]::Round($totalDuration.TotalSeconds, 2)) seconds"
Write-Output "Success Rate:    $successRate%"
Write-Output "Critical Errors: $($RemediationResults.CriticalErrors.Count)"
Write-Output ""
Write-Output "Log File: $logFile"
Write-Output "=========================================="
Write-Output ""

# Display full log contents for SentinelOne Remote Shell
Write-Output ""
Write-Output "=========================================="
Write-Output "FULL LOG OUTPUT"
Write-Output "=========================================="
Get-Content $logFile
Write-Output ""
Write-Output "=========================================="
Write-Output "END OF LOG"
Write-Output "=========================================="