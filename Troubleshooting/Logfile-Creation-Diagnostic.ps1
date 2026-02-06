# Diagnostic Script - Run this first
# Purpose: Test if Logfiles can be created on endpoint.
Write-Output "====================================="
Write-Output "DIAGNOSTIC TEST"
Write-Output "====================================="
Write-Output "User: $env:USERNAME"
Write-Output "Temp: $env:TEMP"
Write-Output "Admin: $([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"
Write-Output ""

# Test log file creation
$testLog = Join-Path $env:TEMP "test_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Write-Output "Attempting to create: $testLog"

try {
    "Test" | Out-File -FilePath $testLog -ErrorAction Stop
    Write-Output "[OK] Log file created successfully"
    
    # Test append
    Add-Content -Path $testLog -Value "Append test" -ErrorAction Stop
    Write-Output "[OK] Append successful"
    
    # Read back
    $content = Get-Content $testLog
    Write-Output "[OK] Content: $($content -join ', ')"
    
    # Cleanup
    Remove-Item $testLog -Force
    Write-Output "[OK] Cleanup successful"
    
} catch {
    Write-Output "[ERROR] Failed: $($_.Exception.Message)"
}

Write-Output "====================================="
Write-Output "DIAGNOSTIC COMPLETE"
Write-Output "====================================="