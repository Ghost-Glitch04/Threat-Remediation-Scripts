$process = Get-Process OneStart -ErrorAction SilentlyContinue
if ($process) {
    $process | Stop-Process -Force -ErrorAction SilentlyContinue
}
$process = Get-Process UpdaterSetup -ErrorAction SilentlyContinue
if ($process) {
    $process | Stop-Process -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Seconds 2

$user_list = Get-Item C:\users\* | Select-Object Name -ExpandProperty Name
foreach ($user in $user_list) {
    $installers = @(Get-ChildItem "C:\users\$user\Downloads" -Recurse -Filter "OneStart*.exe" | ForEach-Object { $_.FullName })
    foreach ($install in $installers) {
        if (Test-Path -Path $install) {
            Remove-Item $install -ErrorAction SilentlyContinue
            if (Test-Path -Path $install) {
                Write-Host "Failed to remove OneStart installer -> $install"
            }
        }
    }

    $installers = @(Get-ChildItem "C:\users\$user\Downloads" -Recurse -Filter "*OneStart*.msi" | ForEach-Object { $_.FullName })
    foreach ($install in $installers) {
        if (Test-Path -Path $install) {
            Remove-Item $install -ErrorAction SilentlyContinue
            if (Test-Path -Path $install) {
                Write-Host "Failed to remove OneStart installer -> $install"
            }
        }
    }

    $paths = @(
        "C:\Users\$user\AppData\Local\OneStart.ai",
        "C:\Users\$user\OneStart.ai",
        "C:\Users\$user\Desktop\OneStart.lnk",
        "C:\Users\$user\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\OneStart.lnk",
        "C:\Users\$user\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneStart.lnk",
        "C:\Users\$user\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\PDF Editor.lnk",
        "C:\Users\$user\AppData\Roaming\NodeJs",
        "C:\Users\$user\AppData\Roaming\PDF Editor"
    )
    foreach ($path in $paths) {
        if (Test-Path -Path $path) {
            Remove-Item $path -Force -Recurse -ErrorAction SilentlyContinue
            if (Test-Path -Path $path) {
                Write-Host "Failed to remove OneStart -> $path"
            }
        }
    }
}

$paths = @(
    "C:\WINDOWS\system32\config\systemprofile\AppData\Local\OneStart.ai",
    "C:\WINDOWS\system32\config\systemprofile\PDFEditor"
)
foreach ($path in $paths) {
    if (test-path -Path $path) {
        Remove-Item $path -Force -Recurse -ErrorAction SilentlyContinue
            if (Test-Path -Path $path) {
                Write-Host "Failed to remove OneStart -> $path"
            }
    }
}    

$tasks = @(
    "C:\Windows\System32\Tasks\OneStartUser",
    "C:\windows\system32\tasks\OneStartAutoLaunchTask*",
    "C:\Windows\System32\Tasks\PDFEditorScheduledTask",
    "C:\Windows\System32\Tasks\PDFEditorUScheduledTask",
    "C:\Windows\System32\Tasks\sys_component_health_*"
)
foreach ($task in $tasks) {
    if (Test-Path -Path $task) {
        Remove-Item $task -Force -Recurse -ErrorAction SilentlyContinue
        if (Test-Path -Path $task) {
            Write-Host "Failed to remove OneStart task -> $task"
        }
    }
}

# Optional: Clean up orphaned TaskCache registry entries with permission handling
function Remove-TaskCacheEntry {
    param([string]$TaskName)
    
    $baseKey = "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache"
    $treePath = "$baseKey\TREE\$TaskName"
    
    # Check if the key exists
    if (Test-Path "Registry::$treePath") {
        # Get the GUID for related entries
        $taskId = $null
        try {
            $taskId = (Get-ItemProperty -Path "Registry::$treePath" -Name "Id" -ErrorAction SilentlyContinue).Id
        } catch {}
        
        # Take ownership and grant permissions using reg.exe and takeown
        takeown /f "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\TREE\$TaskName" /r /d Y 2>$null | Out-Null
        
        # Grant full control to Administrators
        icacls "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\TREE\$TaskName" /grant Administrators:F /t 2>$null | Out-Null
        
        # Remove associated GUID entries first if found
        if ($taskId) {
            $guidString = "{$taskId}"
            $relatedPaths = @(
                "$baseKey\Tasks\$guidString",
                "$baseKey\Plain\$guidString",
                "$baseKey\Boot\$guidString",
                "$baseKey\Logon\$guidString"
            )
            foreach ($relPath in $relatedPaths) {
                takeown /f "$relPath" /r /d Y 2>$null | Out-Null
                icacls "$relPath" /grant Administrators:F /t 2>$null | Out-Null
                reg delete "$relPath" /f 2>$null | Out-Null
            }
        }
        
        # Now delete the TREE entry
        reg delete "$treePath" /f 2>$null | Out-Null
        
        # Verify removal
        if (Test-Path "Registry::$treePath") {
            Write-Host "Warning: Failed to remove orphaned registry key -> $TaskName"
        }
    }
}

$taskCacheBasePath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache"
$taskNamePatterns = @("OneStart*", "PDFEditor*", "sys_component_health_*")

foreach ($pattern in $taskNamePatterns) {
    $matchingKeys = Get-ChildItem -Path "$taskCacheBasePath\TREE" -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -like $pattern }
    foreach ($key in $matchingKeys) {
        Remove-TaskCacheEntry -TaskName $key.PSChildName
    }
}

$registryKeys = @(
    'Registry::HKLM\Software\WOW6432Node\Microsoft\Tracing\OneStart_RASAPI32',
    'Registry::HKLM\Software\WOW6432Node\Microsoft\Tracing\OneStart_RASMANCS',
    'Registry::HKLM\Software\Microsoft\MediaPlayer\ShimInclusionList\onestart.exe'
)
foreach ($key in $registryKeys) {
    if (Test-Path -Path $key) {
        Remove-Item $key -Recurse -ErrorAction SilentlyContinue
        if (Test-Path -Path $key) {
            Write-Host "Failed to remove OneStart -> $key"
        }
    }
}

$sid_list = Get-Item -Path "Registry::HKU\S-*" | Select-String -Pattern "S-\d-(?:\d+-){5,14}\d+" | ForEach-Object { $_.ToString().Trim() }
foreach ($sid in $sid_list) {
    if ($sid -notlike "*_Classes*") {
        $registryPaths = @(
            "Registry::$sid\Software\Clients\StartMenuInternet\OneStart.IOZDYLUF4W5Y3MM3N77XMXEX6A",
            "Registry::$sid\Software\OneStart.ai",
            "Registry::$sid\Software\Microsoft\Windows\CurrentVersion\Uninstall\OneStart.ai OneStart",
            "Registry::$sid\Software\PDFEditor",
            "Registry::$sid\Software\Clients\StartMenuInternet\OneStart.25VKDQVMIQGWARCLC23VYGDER4",
            "Registry::$sid\Software\Classes\CLSID\{4DAC24AB-B340-4B7E-AD01-1504A7F59EEA}\LocalServer32",
            "Registry::$sid\Software\Classes\CLSID\{75828ED1-7BE8-45D0-8950-AA85CBF74510}\LocalServer32",
            "Registry::$sid\Software\Classes\CLSID\{A2C6CB58-C076-425C-ACB7-6D19D64428CD}\LocalServer32",
            "Registry::$sid\Software\Classes\CLSID\{A45DDD96-C17C-50A3-BD69-8D064F864B24}\LocalServer32",
            "Registry::$sid\Software\Classes\CLSID\{B5B6376D-5E59-5CB2-A34D-617C21A3A240}\LocalServer32",
            "Registry::$sid\Software\Classes\OneStart.aiUpdate.Update3WebUser",
            "Registry::$sid\Software\Software\Classes\OSBHTML.25VKDQVMIQGWARCLC23VYGDER4"
        )
        foreach ($regPath in $registryPaths) {
            if (Test-Path -Path $regPath) {
                Remove-Item $regPath -Recurse -ErrorAction SilentlyContinue
                if (Test-Path -Path $regPath) {
                    Write-Host "Failed to remove OneStart -> $regPath"
                }
            }
        }
        $runKeys = @("OneStartUpdate", "OneStartBarUpdate","OneStartBar","OneStart", "OneStartChromium","OneStartUpdaterTaskUser*","PDFEditor*")
        foreach ($runKey in $runKeys) {
            $keypath = "Registry::$sid\Software\Microsoft\Windows\CurrentVersion\Run"
            if ((Get-ItemProperty -Path $keypath -Name $runKey -ErrorAction SilentlyContinue)) {
                Remove-ItemProperty -Path $keypath -Name $runKey -ErrorAction SilentlyContinue
                if ((Get-ItemProperty -Path $keypath -Name $runKey -ErrorAction SilentlyContinue)) {
                    Write-Host "Failed to remove OneStart -> $keypath.$runKey"
                }
            }
        }
        $runKeys = @("OneStart*")
        foreach ($runKey in $runKeys) {
            $keypath = "Registry::$sid\Software\RegisteredApplications"
            if ((Get-ItemProperty -Path $keypath -Name $runKey -ErrorAction SilentlyContinue)) {
                Remove-ItemProperty -Path $keypath -Name $runKey -ErrorAction SilentlyContinue
                if ((Get-ItemProperty -Path $keypath -Name $runKey -ErrorAction SilentlyContinue)) {
                    Write-Host "Failed to remove OneStart -> $keypath.$runKey"
                }
            }
        }
    }
}
