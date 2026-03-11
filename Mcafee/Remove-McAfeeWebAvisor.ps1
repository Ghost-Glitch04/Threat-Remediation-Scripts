# Remove-McAfeeWebAvisor.ps1
# This script is designed to remove McAfee WebAdvisor from a Windows system.

# Define the path to McAfee WebAdvisor
$webAdvisorPath = "C:\Program Files\McAfee\WebAdvisor"

# Test for Presence of McAfee WebAdvisor
if ( -not (Test-Path -Path $webAdvisorPath) ) {
    Write-Output "McAfee WebAdvisor is not installed on this system."
    exit 0
}

# Define the Uninstaller Name for McAfee WebAdvisor.
$uninstallerName = "uninstaller.exe"

# Test for Presence of Uninstaller
$uninstallerPath = Join-Path -Path $webAdvisorPath -ChildPath $uninstallerName
if ( -not (Test-Path -Path $uninstallerPath) ) {
    Write-Output "McAfee WebAdvisor uninstaller is not found."
    exit 0
}

# Execute the Uninstaller
try {
    Start-Process -FilePath $uninstallerPath -ArgumentList "/s" -Wait -NoNewWindow
    Write-Output "McAfee WebAdvisor uninstallation initiated."
} catch {
    Write-Output "Failed to execute the McAfee WebAdvisor uninstaller: $_"
    exit 1
}
