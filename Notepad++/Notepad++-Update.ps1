#Requires -Version 5.1

<#
.SYNOPSIS
    Detects Notepad++ version and updates if necessary using WinGet PowerShell module.
    
.DESCRIPTION
    This script checks for Notepad++ installation, verifies the version,
    and updates to the latest version if it's 8.8.7 or older.
    Uses the Microsoft.WinGet.Client PowerShell module for reliability.
    Designed for use with SentinelOne Remote Shell.
#>

# Suppress progress bars for faster downloads
$ProgressPreference = 'SilentlyContinue'

# Function to get Notepad++ version from registry
function Get-NotepadPlusPlusVersion {
    $registryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Notepad++",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Notepad++",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Notepad++"
    )
    
    foreach ($path in $registryPaths) {
        if (Test-Path $path) {
            $version = (Get-ItemProperty -Path $path -ErrorAction SilentlyContinue).DisplayVersion
            if ($version) {
                return $version
            }
        }
    }
    
    # Alternative: Check executable version
    $nppPaths = @(
        "${env:ProgramFiles}\Notepad++\notepad++.exe",
        "${env:ProgramFiles(x86)}\Notepad++\notepad++.exe"
    )
    
    foreach ($exePath in $nppPaths) {
        if (Test-Path $exePath) {
            $versionInfo = (Get-Item $exePath).VersionInfo
            return $versionInfo.ProductVersion
        }
    }
    
    return $null
}

# Function to compare versions
function Compare-NotepadVersion {
    param (
        [string]$CurrentVersion,
        [string]$TargetVersion
    )
    
    $current = [version]$CurrentVersion
    $target = [version]$TargetVersion
    
    return $current.CompareTo($target)
}

# Function to ensure NuGet PackageProvider is installed
function Install-NuGetIfRequired {
    Write-Host "INFO: Checking for NuGet PackageProvider..."
    
    if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue)) {
        Write-Host "INFO: Installing NuGet PackageProvider..."
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction Stop | Out-Null
            Write-Host "SUCCESS: NuGet PackageProvider installed"
        } catch {
            Write-Host "WARNING: Failed to install NuGet PackageProvider: $($_.Exception.Message)"
        }
    } else {
        Write-Host "INFO: NuGet PackageProvider already installed"
    }
}

# Function to install Microsoft.WinGet.Client module
function Install-WinGetModule {
    Write-Host "INFO: Checking for Microsoft.WinGet.Client module..."
    
    if (-not (Get-Module -ListAvailable -Name Microsoft.WinGet.Client)) {
        Write-Host "INFO: Installing Microsoft.WinGet.Client module..."
        try {
            # Ensure TLS 1.2
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            
            # Ensure NuGet is installed first
            Install-NuGetIfRequired
            
            # Install the module
            Install-Module -Name Microsoft.WinGet.Client -Force -AllowClobber -Repository PSGallery -Scope AllUsers -ErrorAction Stop
            Write-Host "SUCCESS: Microsoft.WinGet.Client module installed"
            return $true
        } catch {
            Write-Host "ERROR: Failed to install Microsoft.WinGet.Client module: $($_.Exception.Message)"
            return $false
        }
    } else {
        Write-Host "INFO: Microsoft.WinGet.Client module already installed"
        return $true
    }
}

# Function to ensure WinGet is installed using the module
function Repair-WinGet {
    Write-Host "INFO: Ensuring WinGet is installed and functional..."
    
    try {
        # Import the module
        Import-Module Microsoft.WinGet.Client -ErrorAction Stop
        
        # Repair/Install WinGet
        Write-Host "INFO: Running Repair-WinGetPackageManager (this may take a minute)..."
        Repair-WinGetPackageManager -AllUsers -Force -Latest -ErrorAction Stop | Out-Null
        
        Write-Host "SUCCESS: WinGet is installed and ready"
        return $true
    } catch {
        Write-Host "ERROR: Failed to repair/install WinGet: $($_.Exception.Message)"
        return $false
    }
}

# Main script execution
try {
    Write-Host "======================================"
    Write-Host "Notepad++ Version Check and Update"
    Write-Host "======================================"
    Write-Host ""
    
    # Check if Notepad++ is installed
    Write-Host "INFO: Checking for Notepad++ installation..."
    $currentVersion = Get-NotepadPlusPlusVersion
    
    if (-not $currentVersion) {
        Write-Host "ERROR: Notepad++ is not installed on this system."
        exit 1
    }
    
    Write-Host "INFO: Notepad++ version detected: $currentVersion"
    
    # Check if version is 8.8.8 (secured)
    if ($currentVersion -eq "8.8.8") {
        Write-Host ""
        Write-Host "SUCCESS: Notepad++ is SECURED - Version 8.8.8 is installed"
        Write-Host ""
        exit 0
    }
    
    # Check if version is 8.8.7 or older
    $versionComparison = Compare-NotepadVersion -CurrentVersion $currentVersion -TargetVersion "8.8.8"
    
    if ($versionComparison -lt 0) {
        Write-Host "WARNING: Notepad++ version $currentVersion is outdated (older than 8.8.8)"
        Write-Host "INFO: Initiating update process..."
        Write-Host ""
        
        # Step 1: Install WinGet module
        Write-Host "======================================"
        Write-Host "Step 1: Installing WinGet Module"
        Write-Host "======================================"
        if (-not (Install-WinGetModule)) {
            Write-Host "ERROR: Failed to install Microsoft.WinGet.Client module"
            exit 1
        }
        Write-Host ""
        
        # Step 2: Ensure WinGet is installed
        Write-Host "======================================"
        Write-Host "Step 2: Installing/Repairing WinGet"
        Write-Host "======================================"
        if (-not (Repair-WinGet)) {
            Write-Host "ERROR: Failed to install/repair WinGet"
            exit 1
        }
        Write-Host ""
        
        # Step 3: Update Notepad++
        Write-Host "======================================"
        Write-Host "Step 3: Updating Notepad++"
        Write-Host "======================================"
        
        try {
            Write-Host "INFO: Importing Microsoft.WinGet.Client module..."
            Import-Module Microsoft.WinGet.Client -ErrorAction Stop
            
            Write-Host "INFO: Updating Notepad++ using WinGet module..."
            $updateResult = Update-WinGetPackage -Id Notepad++.Notepad++ -Mode Silent -ErrorAction Stop
            
            if ($updateResult) {
                Write-Host "SUCCESS: Notepad++ update completed"
                
                # Wait for installation to finalize
                Start-Sleep -Seconds 5
                
                # Validate the update
                Write-Host "INFO: Validating update..."
                $newVersion = Get-NotepadPlusPlusVersion
                
                if ($newVersion) {
                    Write-Host "INFO: New version detected: $newVersion"
                    
                    $postUpdateComparison = Compare-NotepadVersion -CurrentVersion $newVersion -TargetVersion "8.8.8"
                    
                    if ($postUpdateComparison -ge 0) {
                        Write-Host ""
                        Write-Host "SUCCESS: UPDATE SUCCESSFUL - Notepad++ is now SECURED (Version: $newVersion)"
                        Write-Host ""
                        exit 0
                    } else {
                        Write-Host "WARNING: Update completed but version is still below 8.8.8 (Current: $newVersion)"
                        exit 1
                    }
                } else {
                    Write-Host "ERROR: Unable to verify new version after update"
                    exit 1
                }
            } else {
                Write-Host "WARNING: Update command completed but returned no result"
                
                # Still try to validate
                Start-Sleep -Seconds 5
                $newVersion = Get-NotepadPlusPlusVersion
                
                if ($newVersion -and (Compare-NotepadVersion -CurrentVersion $newVersion -TargetVersion "8.8.8") -ge 0) {
                    Write-Host "SUCCESS: Notepad++ is now SECURED (Version: $newVersion)"
                    exit 0
                } else {
                    Write-Host "ERROR: Update may have failed"
                    exit 1
                }
            }
            
        } catch {
            Write-Host "ERROR: Failed to update Notepad++ using WinGet module"
            Write-Host "Error details: $($_.Exception.Message)"
            
            # Fallback: Try using winget.exe directly
            Write-Host ""
            Write-Host "INFO: Attempting fallback method using winget.exe..."
            
            try {
                $wingetResult = & winget upgrade Notepad++.Notepad++ --silent --accept-source-agreements --accept-package-agreements 2>&1
                
                if ($LASTEXITCODE -eq 0 -or $wingetResult -match "Successfully installed") {
                    Write-Host "SUCCESS: Fallback method succeeded"
                    
                    Start-Sleep -Seconds 5
                    $newVersion = Get-NotepadPlusPlusVersion
                    
                    if ($newVersion -and (Compare-NotepadVersion -CurrentVersion $newVersion -TargetVersion "8.8.8") -ge 0) {
                        Write-Host "SUCCESS: Notepad++ is now SECURED (Version: $newVersion)"
                        exit 0
                    }
                }
            } catch {
                Write-Host "ERROR: Fallback method also failed"
            }
            
            exit 1
        }
        
    } else {
        Write-Host ""
        Write-Host "SUCCESS: Notepad++ is SECURED - Version $currentVersion is equal to or newer than 8.8.8"
        Write-Host ""
        exit 0
    }
    
} catch {
    Write-Host ""
    Write-Host "ERROR: An unexpected error occurred:"
    Write-Host $_.Exception.Message
    Write-Host $_.ScriptStackTrace
    exit 1
}