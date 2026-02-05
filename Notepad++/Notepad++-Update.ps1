<#
.SYNOPSIS
    Silently installs Notepad++ from GitHub release.

.DESCRIPTION
    Downloads and installs Notepad++ v8.9.1 silently without user interaction.
    All operations are logged to $env:TEMP.

.NOTES
    Author: Ghost-Glitch04
    Date: 2026-02-05
    Version: 8.9.1
    Designed for SentinelOne Remote Shell execution
#>

# Initialize variables
$notepadVersion = "8.9.1"
$downloadUrl = "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.9.1/npp.8.9.1.Installer.x64.exe"
$installerFileName = "npp.$notepadVersion.Installer.x64.exe"
$installerPath = "$env:TEMP\$installerFileName"
$logFile = "$env:TEMP\NotepadPlusPlus-Install-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
$ErrorActionPreference = "Continue"

# Function to write log entries
function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -FilePath $logFile -Append -Force
}

# Start logging
Write-Log "=== Notepad++ Silent Installation Script ==="
Write-Log "Version: $notepadVersion"
Write-Log "User: $env:USERNAME"
Write-Log "Computer: $env:COMPUTERNAME"
Write-Log ""

# Check if Notepad++ is already installed
Write-Log "Checking for existing Notepad++ installation..."
$existingInstall = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -like "Notepad++*" }

if ($existingInstall) {
    Write-Log "[INFO] Notepad++ is already installed."
    Write-Log "    Current Version: $($existingInstall.DisplayVersion)"
    Write-Log "    Install Location: $($existingInstall.InstallLocation)"
}
else {
    Write-Log "[INFO] Notepad++ is NOT currently installed."
}

# Download the installer
Write-Log ""
Write-Log "[ACTION] Downloading Notepad++ installer from GitHub..."
Write-Log "    URL: $downloadUrl"
Write-Log "    Destination: $installerPath"

try {
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri $downloadUrl -OutFile $installerPath -UseBasicParsing -ErrorAction Stop
    Write-Log "[SUCCESS] Installer downloaded successfully."
    
    # Verify download
    if (Test-Path $installerPath) {
        $fileSize = (Get-Item $installerPath).Length / 1MB
        Write-Log "    File Size: $([math]::Round($fileSize, 2)) MB"
    }
}
catch {
    Write-Log "[ERROR] Failed to download installer: $($_.Exception.Message)"
    Get-Content $logFile
    exit 1
}

# Install Notepad++ silently
Write-Log ""
Write-Log "[ACTION] Installing Notepad++ v$notepadVersion silently..."
Write-Log "    Installer: $installerPath"
Write-Log "    Parameters: /S (silent installation)"

try {
    # Start the installation process with silent parameter
    $installProcess = Start-Process -FilePath $installerPath -ArgumentList "/S" -Wait -PassThru -NoNewWindow
    
    if ($installProcess.ExitCode -eq 0) {
        Write-Log "[SUCCESS] Notepad++ installation completed successfully!"
        Write-Log "    Exit Code: $($installProcess.ExitCode)"
    }
    else {
        Write-Log "[WARNING] Installation completed with exit code: $($installProcess.ExitCode)"
    }
}
catch {
    Write-Log "[ERROR] Failed to install Notepad++: $($_.Exception.Message)"
    Get-Content $logFile
    exit 1
}

# Wait for installation to complete (registry update)
Write-Log ""
Write-Log "[INFO] Waiting for installation to finalize..."
Start-Sleep -Seconds 5

# Verify installation
Write-Log ""
Write-Log "Verifying installation..."
$verifyInstall = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -like "Notepad++*" }

if ($verifyInstall) {
    Write-Log "[SUCCESS] Notepad++ installation verified!"
    Write-Log "    Version: $($verifyInstall.DisplayVersion)"
    Write-Log "    Install Location: $($verifyInstall.InstallLocation)"
    Write-Log "    Publisher: $($verifyInstall.Publisher)"
    $installSuccess = $true
}
else {
    Write-Log "[ERROR] Installation verification failed - Notepad++ not found in registry!"
    $installSuccess = $false
}

# Clean up installer
Write-Log ""
Write-Log "[ACTION] Cleaning up installer file..."
try {
    if (Test-Path $installerPath) {
        Remove-Item $installerPath -Force -ErrorAction Stop
        Write-Log "[SUCCESS] Installer file removed successfully."
    }
}
catch {
    Write-Log "[WARNING] Failed to remove installer file: $($_.Exception.Message)"
}

# Summary
Write-Log ""
Write-Log "=== SUMMARY ==="
if ($installSuccess) {
    Write-Log "Status: SUCCESS"
    Write-Log "Notepad++ v$notepadVersion installed successfully"
}
else {
    Write-Log "Status: FAILED"
    Write-Log "Installation could not be verified"
}
Write-Log "Log File: $logFile"
Write-Log "Script completed at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Log "=== END OF LOG ==="

# Display log contents
Get-Content $logFile

# Display installation confirmation on terminal
Write-Host ""
Write-Host "=========================================="
Write-Host "   NOTEPAD++ INSTALLATION CONFIRMATION"
Write-Host "=========================================="
Write-Host ""

$finalCheck = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -like "Notepad++*" }

if ($finalCheck) {
    Write-Host "[OK] Notepad++ is installed on this system"
    Write-Host ""
    Write-Host "Application: $($finalCheck.DisplayName)"
    Write-Host "Version:     $($finalCheck.DisplayVersion)"
    Write-Host "Publisher:   $($finalCheck.Publisher)"
    Write-Host "Location:    $($finalCheck.InstallLocation)"
}
else {
    Write-Host "[FAILED] Notepad++ installation could not be confirmed"
    Write-Host "Please review the log file for details: $logFile"
}

Write-Host ""
Write-Host "=========================================="