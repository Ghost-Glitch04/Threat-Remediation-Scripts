# Remove-McAfeeWebAvisor.ps1
# This script is designed to remove McAfee WebAdvisor from a Windows system.
# This version is is manually ran and will output text via "Write-Host" to indicate the status of the script.

# Define the path to McAfee WebAdvisor
$webAdvisorPath = "C:\Program Files\McAfee\WebAdvisor"

# Test for Presence of McAfee WebAdvisor
if (-not (Test-Path -Path $webAdvisorPath)) {
    Write-Output "McAfee WebAdvisor is not installed on this system."
    exit 0
}

# Define the Uninstaller Name for McAfee WebAdvisor
$uninstallerName = "uninstaller.exe"

# Test for Presence of Uninstaller
$uninstallerPath = Join-Path -Path $webAdvisorPath -ChildPath $uninstallerName
if (-not (Test-Path -Path $uninstallerPath)) {
    Write-Output "McAfee WebAdvisor uninstaller is not found."
    exit 0
}

# Execute the Uninstaller
try {
    Start-Process -FilePath $uninstallerPath -ArgumentList "/s" -Wait -NoNewWindow
    
    # Check the exit code
    if ($LASTEXITCODE -eq 0) {
        Write-Output "McAfee WebAdvisor uninstallation completed successfully."
        exit 0
    } else {
        Write-Output "McAfee WebAdvisor uninstaller returned error code: $LASTEXITCODE"
        exit 1
    }
} catch {
    Write-Output "Failed to execute the McAfee WebAdvisor uninstaller: $_"
    exit 1
}