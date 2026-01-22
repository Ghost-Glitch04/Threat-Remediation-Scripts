# ============================================================ #
# %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% #
# <><><><><><><><><><><><><><><><><><><><><><><><><><><><><><> #
# << --- OneStart Remediation Script --- >> #
# <><><><><><><><><><><><><><><><><><><><><><><><><><><><><><> #
# %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% #
# ============================================================ #

# %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% #
# <><><><><><><><><><><><><><><><><><><><><><><><><><><><><><> #
# --- Kill Processes --- #
# <><><><><><><><><><><><><><><><><><><><><><><><><><><><><><> #
# %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% #

# &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&
# -- Define Variables --
# &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&

# Define an array of strings to be used when searching through likely locations of Indicators of Compromise.
[array]$stringArray =@(
    "OneStartService",
    "OneStartAutoLaunch",
    "OneStartCrashHandler",
    "OneStartUpdater",
    "OneStartBrowser",
    "PDFEditor",
    "PDFEditorService",
    "PDFEditorUpdater"
)



# Define target processes to terminate
$processesToKill = @(
    "OneStartService",
    "OneStartAutoLaunch",
    "OneStartCrashHandler",
    "OneStartUpdater",
    "OneStartBrowser",
    "PDFEditor",
    "PDFEditorService",
    "PDFEditorUpdater"
)

# &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&
# -- Kill Target Processes --
# &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&

# Attempt to kill each target process and verify termination
foreach ($processName in $processesToKill) {
    $process = Get-Process -Name $processName -ErrorAction SilentlyContinue
    if ($process) {
        $process | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 500
        
        # Verify the process was successfully terminated
        $stillRunning = Get-Process -Name $processName -ErrorAction SilentlyContinue
        if ($stillRunning) {
            Write-Host "Failed to kill process -> $processName"
        }
    }
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

# Optional: Clean up orphaned TaskCache registry entries with proper permission handling
function Remove-TaskCacheEntry {
    param([string]$TaskName)
    
    try {
        $baseKeyPath = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache"
        $treePath = "$baseKeyPath\TREE\$TaskName"
        
        # Open the registry key with HKLM
        $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("$baseKeyPath\TREE\$TaskName", $false)
        
        if ($regKey) {
            # Get the GUID for related entries
            $taskId = $null
            try {
                $taskId = $regKey.GetValue("Id")
            } catch {}
            $regKey.Close()
            
            # Remove associated GUID entries first if found
            if ($taskId) {
                $guidString = "{$taskId}"
                $relatedSubKeys = @(
                    "$baseKeyPath\Tasks\$guidString",
                    "$baseKeyPath\Plain\$guidString",
                    "$baseKeyPath\Boot\$guidString",
                    "$baseKeyPath\Logon\$guidString"
                )
                foreach ($subKey in $relatedSubKeys) {
                    try {
                        [Microsoft.Win32.Registry]::LocalMachine.DeleteSubKeyTree($subKey, $false)
                    } catch {}
                }
            }
            
            # Now delete the TREE entry
            try {
                [Microsoft.Win32.Registry]::LocalMachine.DeleteSubKeyTree($treePath, $false)
            } catch {
                Write-Host "Warning: Failed to remove orphaned registry key -> $TaskName (Access Denied - requires SYSTEM privileges)"
            }
        }
    } catch {
        # Silently continue if key doesn't exist or can't be accessed
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
        # Dynamically remove OneStart browser registrations in StartMenuInternet
        $startMenuPath = "Registry::$sid\Software\Clients\StartMenuInternet"
        if (Test-Path $startMenuPath) {
            Get-ChildItem $startMenuPath -ErrorAction SilentlyContinue | 
                Where-Object { $_.PSChildName -like "OneStart.*" } |
                ForEach-Object {
                    Remove-Item $_.PSPath -Recurse -ErrorAction SilentlyContinue
                    if (Test-Path $_.PSPath) {
                        Write-Host "Failed to remove OneStart -> $($_.PSPath)"
                    }
                }
        }

        # Remove static base paths
        $staticPaths = @(
            "Registry::$sid\Software\OneStart.ai",
            "Registry::$sid\Software\PDFEditor"
        )
        foreach ($path in $staticPaths) {
            if (Test-Path $path) {
                Remove-Item $path -Recurse -ErrorAction SilentlyContinue
                if (Test-Path $path) {
                    Write-Host "Failed to remove OneStart -> $path"
                }
            }
        }

        # Dynamically remove OneStart uninstall entries
        $uninstallPath = "Registry::$sid\Software\Microsoft\Windows\CurrentVersion\Uninstall"
        if (Test-Path $uninstallPath) {
            Get-ChildItem $uninstallPath -ErrorAction SilentlyContinue |
                Where-Object { $_.PSChildName -like "*OneStart*" } |
                ForEach-Object {
                    Remove-Item $_.PSPath -Recurse -ErrorAction SilentlyContinue
                    if (Test-Path $_.PSPath) {
                        Write-Host "Failed to remove OneStart -> $($_.PSPath)"
                    }
                }
        }

        # Dynamically find and remove CLSIDs associated with OneStart/PDFEditor
        $clsidPath = "Registry::$sid\Software\Classes\CLSID"
        if (Test-Path $clsidPath) {
            $clsids = Get-ChildItem $clsidPath -ErrorAction SilentlyContinue
            foreach ($clsid in $clsids) {
                $localServerPath = "$($clsid.PSPath)\LocalServer32"
                if (Test-Path $localServerPath) {
                    $localServer = Get-ItemProperty -Path $localServerPath -Name "(default)" -ErrorAction SilentlyContinue
                    if ($localServer.'(default)' -like "*OneStart*" -or $localServer.'(default)' -like "*PDFEditor*") {
                        Remove-Item $clsid.PSPath -Recurse -ErrorAction SilentlyContinue
                        if (Test-Path $clsid.PSPath) {
                            Write-Host "Failed to remove OneStart CLSID -> $($clsid.PSPath)"
                        }
                    }
                }
            }
        }

        # Dynamically remove OneStart-related Classes entries
        $classesPath = "Registry::$sid\Software\Classes"
        if (Test-Path $classesPath) {
            Get-ChildItem $classesPath -ErrorAction SilentlyContinue |
                Where-Object { $_.PSChildName -like "OneStart*" -or $_.PSChildName -like "OSBHTML.*" } |
                ForEach-Object {
                    Remove-Item $_.PSPath -Recurse -ErrorAction SilentlyContinue
                    if (Test-Path $_.PSPath) {
                        Write-Host "Failed to remove OneStart -> $($_.PSPath)"
                    }
                }
        }

        # Clean up Run keys with pattern matching
        $runKeyPath = "Registry::$sid\Software\Microsoft\Windows\CurrentVersion\Run"
        if (Test-Path $runKeyPath) {
            $runKeyPatterns = @("OneStart*", "PDFEditor*")
            $runProps = Get-ItemProperty -Path $runKeyPath -ErrorAction SilentlyContinue
            if ($runProps) {
                $runProps.PSObject.Properties | Where-Object { 
                    $propName = $_.Name
                    $runKeyPatterns | Where-Object { $propName -like $_ }
                } | ForEach-Object {
                    Remove-ItemProperty -Path $runKeyPath -Name $_.Name -ErrorAction SilentlyContinue
                    if ((Get-ItemProperty -Path $runKeyPath -Name $_.Name -ErrorAction SilentlyContinue)) {
                        Write-Host "Failed to remove OneStart -> $runKeyPath.$($_.Name)"
                    }
                }
            }
        }

        # Clean up RegisteredApplications with pattern matching
        $regAppsPath = "Registry::$sid\Software\RegisteredApplications"
        if (Test-Path $regAppsPath) {
            $regAppsProps = Get-ItemProperty -Path $regAppsPath -ErrorAction SilentlyContinue
            if ($regAppsProps) {
                $regAppsProps.PSObject.Properties | Where-Object { $_.Name -like "OneStart*" } | ForEach-Object {
                    Remove-ItemProperty -Path $regAppsPath -Name $_.Name -ErrorAction SilentlyContinue
                    if ((Get-ItemProperty -Path $regAppsPath -Name $_.Name -ErrorAction SilentlyContinue)) {
                        Write-Host "Failed to remove OneStart -> $regAppsPath.$($_.Name)"
                    }
                }
            }
        }
    }
}
