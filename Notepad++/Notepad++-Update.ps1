#Requires -Version 5.1

<#
.SYNOPSIS
    Detects Notepad++ version and updates if necessary using winget.
    
.DESCRIPTION
    This script checks for Notepad++ installation, verifies the version,
    and updates to the latest version if it's 8.8.7 or older.
    If WinGet is not installed, it will be installed automatically.
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

# Function to check if WinGet is available
function Test-WinGetAvailable {
    $wingetCmd = Get-Command winget -ErrorAction SilentlyContinue
    if ($wingetCmd) {
        try {
            $testOutput = & winget --version 2>&1
            if ($LASTEXITCODE -eq 0) {
                return $true
            }
        }
        catch {
            return $false
        }
    }
    return $false
}

# Function to install WinGet
function Install-WinGet {
    Write-Host "INFO: WinGet is not installed. Beginning installation..."
    Write-Host ""
    
    try {
        # Create temporary directory
        $tempDir = Join-Path $env:TEMP "WinGetInstall_$(Get-Date -Format 'yyyyMMddHHmmss')"
        New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
        Write-Host "INFO: Created temporary directory: $tempDir"
        
        # Define download URLs
        $wingetUrl = "https://github.com/microsoft/winget-cli/releases/latest/download/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
        $vcLibsUrl = "https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx"
        $uiXamlUrl = "https://github.com/microsoft/microsoft-ui-xaml/releases/download/v2.8.6/Microsoft.UI.Xaml.2.8.x64.appx"
        
        # Download files
        Write-Host "INFO: Downloading VCLibs dependency..."
        $vcLibsPath = Join-Path $tempDir "Microsoft.VCLibs.x64.14.00.Desktop.appx"
        Invoke-WebRequest -Uri $vcLibsUrl -OutFile $vcLibsPath -UseBasicParsing
        
        Write-Host "INFO: Downloading UI.Xaml dependency..."
        $uiXamlPath = Join-Path $tempDir "Microsoft.UI.Xaml.2.8.x64.appx"
        Invoke-WebRequest -Uri $uiXamlUrl -OutFile $uiXamlPath -UseBasicParsing
        
        Write-Host "INFO: Downloading WinGet..."
        $wingetPath = Join-Path $tempDir "Microsoft.DesktopAppInstaller.msixbundle"
        Invoke-WebRequest -Uri $wingetUrl -OutFile $wingetPath -UseBasicParsing
        
        # Install dependencies and WinGet
        Write-Host "INFO: Installing VCLibs..."
        Add-AppxPackage -Path $vcLibsPath -ErrorAction Stop
        
        Write-Host "INFO: Installing UI.Xaml..."
        Add-AppxPackage -Path $uiXamlPath -ErrorAction Stop
        
        Write-Host "INFO: Installing WinGet..."
        Add-AppxPackage -Path $wingetPath -ErrorAction Stop
        
        # Clean up
        Write-Host "INFO: Cleaning up temporary files..."
        Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        
        # Wait for installation to complete
        Start-Sleep -Seconds 5
        
        # Refresh environment
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
        
        Write-Host "SUCCESS: WinGet installation completed"
        Write-Host ""
        return $true
        
    }
    catch {
        Write-Host "ERROR: Failed to install WinGet"
        Write-Host "Error details: $($_.Exception.Message)"
        
        # Clean up on failure
        if (Test-Path $tempDir) {
            Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
        
        return $false
    }
}

# Function to validate WinGet installation
function Test-WinGetInstallation {
    Write-Host "INFO: Validating WinGet installation..."
    
    # Refresh PATH
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
    
    # Try multiple times as WinGet might need a moment to register
    for ($i = 1; $i -le 5; $i++) {
        if (Test-WinGetAvailable) {
            $version = & winget --version 2>&1
            Write-Host "SUCCESS: WinGet is available (Version: $version)"
            return $true
        }
        
        Write-Host "INFO: Validation attempt $i of 5..."
        Start-Sleep -Seconds 2
    }
    
    Write-Host "ERROR: WinGet validation failed after 5 attempts"
    return $false
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
        
        if (-not (Test-WinGetAvailable)) {
            Write-Host "WARNING: WinGet is not available on this system."
            Write-Host ""
            
            # Attempt to install WinGet
            $installSuccess = Install-WinGet
            
            if (-not $installSuccess) {
                Write-Host "ERROR: Failed to install WinGet automatically."
                Write-Host "INFO: Please install App Installer from Microsoft Store or install WinGet manually."
                exit 1
            }
            
            # Validate WinGet installation
            if (-not (Test-WinGetInstallation)) {
                Write-Host "ERROR: WinGet installation validation failed."
                exit 1
            }
        } else {
            $wingetVersion = & winget --version 2>&1
            Write-Host "INFO: WinGet is already installed (Version: $wingetVersion)"
        }
        
        Write-Host "INFO: Proceeding with Notepad++ update..."
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