#Requires -Version 5.1

<#
.SYNOPSIS
    Detects Notepad++ version and updates if necessary using winget.
    
.DESCRIPTION
    This script checks for Notepad++ installation, verifies the version,
    and updates to the latest version if it's 8.8.7 or older.
    Designed for use with SentinelOne Remote Shell.
#>

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
        
        # Check if winget is available
        Write-Host "INFO: Checking for winget availability..."
        $wingetPath = Get-Command winget -ErrorAction SilentlyContinue
        
        if (-not $wingetPath) {
            Write-Host "ERROR: Winget is not available on this system."
            Write-Host "INFO: Please install App Installer from Microsoft Store or install winget manually."
            exit 1
        }
        
        Write-Host "INFO: Winget found. Proceeding with update..."
        Write-Host ""
        
        # Update Notepad++ using winget
        Write-Host "INFO: Executing winget upgrade command..."
        $updateResult = & winget upgrade Notepad++.Notepad++ --silent --accept-source-agreements --accept-package-agreements 2>&1
        
        # Check if update was successful
        if ($LASTEXITCODE -eq 0 -or $updateResult -match "Successfully installed") {
            Write-Host ""
            Write-Host "SUCCESS: Notepad++ update completed."
            
            # Wait a moment for installation to complete
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
                Write-Host "ERROR: Unable to verify new version after update."
                exit 1
            }
        } else {
            Write-Host ""
            Write-Host "ERROR: Failed to update Notepad++."
            Write-Host "Error details:"
            Write-Host $updateResult
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