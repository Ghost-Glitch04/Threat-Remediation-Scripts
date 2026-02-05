#Requires -Version 5.1

<#
.SYNOPSIS
    Detects Notepad++ version and updates if necessary by direct download.
    
.DESCRIPTION
    This script checks for Notepad++ installation, verifies the version,
    and updates to the latest version if it's 8.8.7 or older.
    Downloads and installs directly from official sources.
    Designed for use with SentinelOne Remote Shell (SYSTEM context compatible).
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

# Function to get OS architecture
function Get-OSArchitecture {
    if ([System.Environment]::Is64BitOperatingSystem) {
        return "x64"
    } else {
        return "x86"
    }
}

# Function to get latest Notepad++ version and download URL
function Get-NotepadPlusPlusLatestInfo {
    param([string]$Architecture)
    
    try {
        Write-Host "INFO: Checking for latest Notepad++ version..."
        
        # Use GitHub API to get latest release
        $apiUrl = "https://api.github.com/repos/notepad-plus-plus/notepad-plus-plus/releases/latest"
        $release = Invoke-RestMethod -Uri $apiUrl -UseBasicParsing -ErrorAction Stop
        
        $latestVersion = $release.tag_name -replace '^v', ''
        Write-Host "INFO: Latest Notepad++ version: $latestVersion"
        
        # Find the installer for the correct architecture
        $installerPattern = if ($Architecture -eq "x64") {
            "*.Installer.x64.exe$"
        } else {
            "*.Installer.exe$"
        }
        
        $asset = $release.assets | Where-Object { 
            $_.name -match $installerPattern -and $_.name -notlike "*arm64*"
        } | Select-Object -First 1
        
        if ($null -eq $asset) {
            throw "Could not find installer for architecture: $Architecture"
        }
        
        return @{
            Version = $latestVersion
            DownloadUrl = $asset.browser_download_url
            FileName = $asset.name
        }
        
    } catch {
        Write-Host "ERROR: Failed to get latest Notepad++ info: $($_.Exception.Message)"
        return $null
    }
}

# Function to download file
function Download-File {
    param(
        [string]$Url,
        [string]$OutputPath
    )
    
    try {
        Write-Host "INFO: Downloading from $Url"
        Write-Host "INFO: Saving to $OutputPath"
        
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $Url -OutFile $OutputPath -UseBasicParsing -ErrorAction Stop
        
        if (Test-Path $OutputPath) {
            Write-Host "SUCCESS: Download completed"
            return $true
        } else {
            Write-Host "ERROR: Downloaded file not found"
            return $false
        }
    } catch {
        Write-Host "ERROR: Download failed: $($_.Exception.Message)"
        return $false
    }
}

# Function to install Notepad++
function Install-NotepadPlusPlus {
    param([string]$InstallerPath)
    
    try {
        Write-Host "INFO: Installing Notepad++..."
        Write-Host "INFO: Running silent installation..."
        
        # Run installer with silent parameters
        $processArgs = @{
            FilePath = $InstallerPath
            ArgumentList = "/S"
            Wait = $true
            PassThru = $true
            NoNewWindow = $true
        }
        
        $process = Start-Process @processArgs
        
        if ($process.ExitCode -eq 0) {
            Write-Host "SUCCESS: Installation completed successfully"
            return $true
        } else {
            Write-Host "WARNING: Installation exited with code: $($process.ExitCode)"
            return $false
        }
        
    } catch {
        Write-Host "ERROR: Installation failed: $($_.Exception.Message)"
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
        Write-Host "INFO: Initiating direct download and update..."
        Write-Host ""
        
        # Get system architecture
        $arch = Get-OSArchitecture
        Write-Host "INFO: System architecture: $arch"
        
        # Get latest version info
        $latestInfo = Get-NotepadPlusPlusLatestInfo -Architecture $arch
        
        if ($null -eq $latestInfo) {
            Write-Host "ERROR: Could not retrieve latest Notepad++ information"
            exit 1
        }
        
        Write-Host "INFO: Target version: $($latestInfo.Version)"
        
        # Check if target version meets requirement
        $targetComparison = Compare-NotepadVersion -CurrentVersion $latestInfo.Version -TargetVersion "8.8.8"
        
        if ($targetComparison -lt 0) {
            Write-Host "WARNING: Latest available version $($latestInfo.Version) is still below 8.8.8"
            Write-Host "WARNING: This may indicate version 8.8.8 is not yet released or available"
        }
        
        # Create temporary directory for download
        $tempDir = Join-Path $env:TEMP "NotepadPlusPlus_Update_$(Get-Date -Format 'yyyyMMddHHmmss')"
        New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
        Write-Host "INFO: Created temporary directory: $tempDir"
        
        # Download installer
        $installerPath = Join-Path $tempDir $latestInfo.FileName
        $downloadSuccess = Download-File -Url $latestInfo.DownloadUrl -OutputPath $installerPath
        
        if (-not $downloadSuccess) {
            Write-Host "ERROR: Failed to download Notepad++ installer"
            Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
            exit 1
        }
        
        # Install Notepad++
        $installSuccess = Install-NotepadPlusPlus -InstallerPath $installerPath
        
        if ($installSuccess) {
            Write-Host ""
            Write-Host "INFO: Waiting for installation to finalize..."
            Start-Sleep -Seconds 5
            
            # Validate the update
            Write-Host "INFO: Validating installation..."
            $newVersion = Get-NotepadPlusPlusVersion
            
            if ($newVersion) {
                Write-Host "INFO: New version detected: $newVersion"
                
                $postUpdateComparison = Compare-NotepadVersion -CurrentVersion $newVersion -TargetVersion "8.8.8"
                
                if ($postUpdateComparison -ge 0) {
                    Write-Host ""
                    Write-Host "SUCCESS: UPDATE SUCCESSFUL - Notepad++ is now SECURED (Version: $newVersion)"
                    Write-Host ""
                    
                    # Cleanup
                    Write-Host "INFO: Cleaning up temporary files..."
                    Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
                    exit 0
                } elseif ($newVersion -ne $currentVersion) {
                    Write-Host ""
                    Write-Host "SUCCESS: Notepad++ was updated to version $newVersion"
                    Write-Host "WARNING: Version is still below 8.8.8 (Current: $newVersion)"
                    Write-Host ""
                    
                    # Cleanup
                    Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
                    exit 1
                } else {
                    Write-Host "WARNING: Version unchanged after installation (Current: $newVersion)"
                    
                    # Cleanup
                    Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
                    exit 1
                }
            } else {
                Write-Host "ERROR: Unable to verify new version after installation"
                
                # Cleanup
                Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
                exit 1
            }
        } else {
            Write-Host "ERROR: Installation failed"
            
            # Cleanup
            Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
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