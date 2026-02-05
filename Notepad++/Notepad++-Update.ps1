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

# Function to create temporary file (PowerShell 5.1 compatible)
function New-TemporaryFile2 {
    $tempPath = [System.IO.Path]::GetTempPath()
    $tempFile = [System.IO.Path]::Combine($tempPath, [System.IO.Path]::GetRandomFileName())
    $null = New-Item -Path $tempFile -ItemType File -Force
    return $tempFile
}

# Function to safely remove files
function Remove-FileIfExists {
    param([string]$FilePath)
    try {
        if (Test-Path -Path $FilePath) {
            Remove-Item -Path $FilePath -ErrorAction SilentlyContinue -Force
        }
    } catch {}
}

# Function to get OS architecture
function Get-OSArchitecture {
    $arch = $env:PROCESSOR_ARCHITECTURE
    if ($arch -eq "AMD64") {
        return "x64"
    } elseif ($arch -eq "ARM64") {
        return "arm64"
    } else {
        return "x86"
    }
}

# Function to get WinGet download URL
function Get-WingetDownloadUrl {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Match
    )
    
    try {
        $uri = "https://api.github.com/repos/microsoft/winget-cli/releases/latest"
        $release = Invoke-RestMethod -Uri $uri -ErrorAction Stop
        
        $data = $release.assets | Where-Object { $_.name -match $Match } | Select-Object -First 1
        
        if ($null -ne $data -and $null -ne $data.browser_download_url) {
            return [string]$data.browser_download_url
        } else {
            throw "Could not find asset matching '$Match'"
        }
    } catch {
        throw "Failed to get WinGet download URL: $($_.Exception.Message)"
    }
}

# Function to install WinGet
function Install-WinGet {
    Write-Host "INFO: WinGet is not installed. Beginning installation..."
    Write-Host ""
    
    try {
        $arch = Get-OSArchitecture
        Write-Host "INFO: Detected architecture: $arch"
        
        # ============================================================================
        # Step 1: Download and install dependencies
        # ============================================================================
        Write-Host "INFO: Downloading WinGet dependencies..."
        
        $depsZipPath = New-TemporaryFile2
        $depsUrl = Get-WingetDownloadUrl -Match 'DesktopAppInstaller_Dependencies.zip'
        
        Write-Host "INFO: Downloading from $depsUrl"
        Invoke-WebRequest -Uri $depsUrl -OutFile $depsZipPath -UseBasicParsing
        
        # Extract and install dependencies
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $tempExtractPath = Join-Path $env:TEMP "WinGetDeps_$(Get-Date -Format 'yyyyMMddHHmmss')"
        New-Item -ItemType Directory -Path $tempExtractPath -Force | Out-Null
        
        [System.IO.Compression.ZipFile]::ExtractToDirectory($depsZipPath, $tempExtractPath)
        
        # Find and install architecture-specific dependencies
        $depFiles = Get-ChildItem -Path $tempExtractPath -Filter "*${arch}*.appx" -Recurse
        
        foreach ($depFile in $depFiles) {
            Write-Host "INFO: Installing dependency: $($depFile.Name)"
            try {
                Add-AppxPackage -Path $depFile.FullName -ErrorAction Stop
            } catch {
                Write-Host "WARNING: Failed to install $($depFile.Name) - may already be installed"
            }
        }
        
        # Cleanup dependencies
        Remove-FileIfExists $depsZipPath
        Remove-Item -Path $tempExtractPath -Recurse -Force -ErrorAction SilentlyContinue
        
        # ============================================================================
        # Step 2: Download and install WinGet license
        # ============================================================================
        Write-Host "INFO: Downloading WinGet license..."
        
        $licensePath = New-TemporaryFile2
        $licenseUrl = Get-WingetDownloadUrl -Match "License1.xml"
        
        Write-Host "INFO: Downloading from $licenseUrl"
        Invoke-WebRequest -Uri $licenseUrl -OutFile $licensePath -UseBasicParsing
        
        # ============================================================================
        # Step 3: Download and install WinGet
        # ============================================================================
        Write-Host "INFO: Downloading WinGet..."
        
        $wingetPath = New-TemporaryFile2
        $wingetUrl = Get-WingetDownloadUrl -Match 'Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle'
        
        Write-Host "INFO: Downloading from $wingetUrl"
        Invoke-WebRequest -Uri $wingetUrl -OutFile $wingetPath -UseBasicParsing
        
        Write-Host "INFO: Installing WinGet..."
        Add-AppxProvisionedPackage -Online -PackagePath $wingetPath -LicensePath $licensePath -ErrorAction Stop | Out-Null
        
        # Cleanup
        Remove-FileIfExists $wingetPath
        Remove-FileIfExists $licensePath
        
        # Wait for installation to complete
        Start-Sleep -Seconds 5
        
        # Refresh environment PATH
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
        
        Write-Host "SUCCESS: WinGet installation completed"
        Write-Host ""
        return $true
        
    } catch {
        Write-Host "ERROR: Failed to install WinGet"
        Write-Host "Error details: $($_.Exception.Message)"
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