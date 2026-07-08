$processes = @("AceLauncher", "AceLauncherDock", "AceLauncherUpdater", "Update")
foreach ($proc in $processes) {
    $process = Get-Process $proc -ErrorAction SilentlyContinue
    if ($process) {
        $process | Stop-Process -Force -ErrorAction SilentlyContinue
    }
}
Start-Sleep -Seconds 2

$user_list = Get-Item C:\Users\* | Select-Object -ExpandProperty Name
foreach ($user in $user_list) {
    if ($user -notlike "*Public*" -and $user -notlike "*Default*") {

        # Recursively sweep Downloads for the installer (catches nested/renamed copies)
        $installers = @(Get-ChildItem "C:\Users\$user\Downloads" -Recurse -Filter "*acelauncher*.exe" -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
        foreach ($install in $installers) {
            if (Test-Path -Path $install) {
                Remove-Item $install -Force -ErrorAction SilentlyContinue
                if (Test-Path -Path $install) {
                    "Failed to remove AceLauncher installer -> $install"
                }
            }
        }

        # Nested Velopack folders first (VelopackTemp can be locked by the updater), then parent as fallback
        $paths = @(
            "C:\Users\$user\AppData\Local\AceLauncherDock\VelopackTemp",
            "C:\Users\$user\AppData\Local\AceLauncherDock\packages",
            "C:\Users\$user\AppData\Local\AceLauncherDock\current",
            "C:\Users\$user\AppData\Local\AceLauncherDock",
            "C:\Users\$user\AppData\Local\AceLauncher",
            "C:\Users\$user\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Web AceLauncher.lnk",
            "C:\Users\$user\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Web AceLauncher.lnk"
        )

        foreach ($path in $paths) {
            if (Test-Path -Path $path) {
                # Bounded retry: the Velopack updater may hold a lock on VelopackTemp briefly after being killed
                $retries = 0
                while ((Test-Path -Path $path) -and $retries -lt 5) {
                    Remove-Item $path -Force -Recurse -ErrorAction SilentlyContinue
                    if (Test-Path -Path $path) {
                        Start-Sleep -Milliseconds 500
                    }
                    $retries++
                }

                if (Test-Path -Path $path) {
                    "Failed to remove AceLauncher -> $path"
                }
            }
        }
    }
}

$regHKLM = @(
    "Registry::HKLM\SOFTWARE\Microsoft\Wow64\x86\AceLauncher.exe",
    "Registry::HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\ShellCompatibility\Applications\AceLauncher.tmp"
)

foreach ($reg in $regHKLM) {
    if (Test-Path -Path $reg) {
        Remove-Item $reg -Force -Recurse -ErrorAction SilentlyContinue

        if (Test-Path -Path $reg) {
            "Failed to remove AceLauncher -> $reg"
        }
    }
}

# Scheduled tasks (task files + TaskCache TREE entries) used for auto-update / persistence
$tasks = @(
    "C:\Windows\System32\Tasks\AceLauncher*",
    "Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\TREE\AceLauncher*"
)
foreach ($task in $tasks) {
    if (Test-Path -Path $task) {
        Remove-Item $task -Force -Recurse -ErrorAction SilentlyContinue
        if (Test-Path -Path $task) {
            "Failed to remove AceLauncher task -> $task"
        }
    }
}

$sid_list = Get-Item -Path "Registry::HKU\S-*" | Select-String -Pattern "S-\d-(?:\d+-){5,14}\d+" | ForEach-Object { $_.ToString().Trim() }
foreach ($sid in $sid_list) {
    if ($sid -notlike "*_Classes*") {
        $regHKU = @(
            "Registry::$sid\Software\AceLauncherUpdater",
            "Registry::$sid\SOFTWARE\AceLauncher",
            "Registry::$sid\Software\Microsoft\Windows\CurrentVersion\Uninstall\AceLauncher"
        )

        foreach ($regPath in $regHKU) {
            if (Test-Path -Path $regPath) {
                Remove-Item -Path $regPath -Force -Recurse -ErrorAction SilentlyContinue

                if (Test-Path -Path $regPath) {
                    "Failed to remove AceLauncher -> $regPath"
                }
            }
        }

        # Autostart Run keys registered by the Velopack variant
        $runKeys = @("AceLauncher", "AceLauncherDock", "AceLauncherUpdater")
        $keypath = "Registry::$sid\Software\Microsoft\Windows\CurrentVersion\Run"
        foreach ($runKey in $runKeys) {
            if (Get-ItemProperty -Path $keypath -Name $runKey -ErrorAction SilentlyContinue) {
                Remove-ItemProperty -Path $keypath -Name $runKey -ErrorAction SilentlyContinue
                if (Get-ItemProperty -Path $keypath -Name $runKey -ErrorAction SilentlyContinue) {
                    "Failed to remove AceLauncher -> $keypath.$runKey"
                }
            }
        }
    }
}
