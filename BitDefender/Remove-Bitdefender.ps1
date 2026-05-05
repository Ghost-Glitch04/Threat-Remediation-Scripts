#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Unattended removal of all Bitdefender consumer components from a Windows endpoint.

.DESCRIPTION
    Downloads the official Bitdefender 2023 Uninstall Tool from Bitdefender's CDN,
    executes it silently, then validates removal of all three Bitdefender components:
      - Bitdefender Total Security
      - Bitdefender Agent
      - Bitdefender VPN

    Designed for execution via N-Able Take Control (SYSTEM context, PowerShell 5.1).
    Does NOT trigger a reboot — caller schedules reboot separately via N-Able.

.NOTES
    Author  : Ghost
    Version : 1.0
    Date    : 2026-05-05
    Context : N-Able Take Control — SYSTEM, PowerShell 5.1

    Tested against:
      - Bitdefender Total Security  26.0.7.34
      - Bitdefender Agent           27.1.1.38
      - Bitdefender VPN             27.2.3.8

.PARAMETER DryRun
    Traces full execution without downloading or running the uninstall tool.
    All validation logic still executes.

.PARAMETER DebugMode
    Promotes DEBUG log entries to console. Default: file only.

.PARAMETER StopAfterPhase
    Stop cleanly after the named phase: Preflight, Download, Removal, Validation.

.PARAMETER LogPath
    Path to write the log file. Defaults to C:\Windows\Temp\Remove-Bitdefender.log

.PARAMETER ToolPath
    Local destination path for the downloaded uninstall tool.
    Defaults to C:\Windows\Temp\BD_Uninstall_Tool.exe

.EXAMPLE
    # Dry run — confirm what would happen without executing
    .\Remove-Bitdefender.ps1 -DryRun

    # Live run
    .\Remove-Bitdefender.ps1

    # Stop after download to verify tool landed correctly
    .\Remove-Bitdefender.ps1 -StopAfterPhase Download
#>

# ============================================================
# EXIT CODE REFERENCE
# ============================================================
# 0  = Success / clean phase gate stop
# 10 = Preflight failure — prerequisite not met
# 20 = Download failed — tool could not be retrieved
# 30 = Removal tool execution failed — non-zero exit or timeout
# 40 = Validation failure — one or more components still present after removal
# 50 = Retry exhausted — transient download failure did not resolve
# 99 = Unexpected / unhandled error

[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$DebugMode,
    [string]$StopAfterPhase = '',
    [string]$LogPath   = 'C:\Windows\Temp\Remove-Bitdefender.log',
    [string]$ToolPath  = 'C:\Windows\Temp\BD_Uninstall_Tool.exe'
)

# ============================================================
# CONFIGURATION
# ============================================================
$ToolUrl         = 'https://www.bitdefender.com/files/KnowledgeBase/file/Bitdefender_2023_Uninstall_Tool.exe'
$ToolTimeoutSec  = 300      # Max seconds to wait for uninstall tool to complete
$DownloadRetries = 3        # Download retry attempts
$RetryDelaySec   = 5        # Initial retry delay (doubles each attempt)

# Registry paths to check for installed components
$BDRegistryRoots = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)

# Components expected to be present BEFORE removal (used for pre-check)
# and absent AFTER removal (used for validation)
$BDComponents = @(
    [PSCustomObject]@{ Name = 'Bitdefender Total Security'; MatchPattern = 'Bitdefender Total Security' },
    [PSCustomObject]@{ Name = 'Bitdefender Agent';          MatchPattern = 'Bitdefender Agent' },
    [PSCustomObject]@{ Name = 'Bitdefender VPN';            MatchPattern = 'Bitdefender VPN' }
)

$ScriptVersion   = '1.0'
$ScriptStartTime = Get-Date

# ============================================================
# HELPERS
# ============================================================

#region --------------------------------------------------------
# HELPER: Write-Log
# Purpose : Structured log writer with level, timestamp, console filtering
# Inputs  : Level (string), Message (string)
# Outputs : Writes to $LogPath always; conditionally to console
#endregion -------------------------------------------------------
function Write-Log {
    param(
        [ValidateSet('DEBUG','INFO','WARN','ERROR','FATAL')]
        [string]$Level,
        [string]$Message
    )
    $ts   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[$ts] [$Level] $Message"

    # Always write to file
    try { Add-Content -Path $LogPath -Value $line -Encoding UTF8 } catch {}

    # Console output — suppress DEBUG unless DebugMode active
    if ($Level -eq 'DEBUG' -and -not $DebugMode) { return }

    $color = switch ($Level) {
        'DEBUG' { 'DarkGray' }
        'INFO'  { 'Cyan'     }
        'WARN'  { 'Yellow'   }
        'ERROR' { 'Red'      }
        'FATAL' { 'Magenta'  }
        default { 'White'    }
    }
    Write-Host $line -ForegroundColor $color
}

#region --------------------------------------------------------
# HELPER: Invoke-PhaseGate
# Purpose : Stop cleanly at a phase boundary if requested
# Inputs  : PhaseName (string), Summary (string)
#endregion -------------------------------------------------------
function Invoke-PhaseGate {
    param([string]$PhaseName, [string]$Summary = '')
    $elapsed = [math]::Round(((Get-Date) - $ScriptStartTime).TotalSeconds, 1)
    Write-Log INFO "PHASE_END: $PhaseName | Total Duration: ${elapsed}s"
    if ($Summary) { Write-Log INFO "PHASE_SUMMARY: $PhaseName | $Summary" }

    if ($StopAfterPhase -and $StopAfterPhase -ieq $PhaseName) {
        Write-Log INFO "PHASE_GATE: Stopping cleanly after phase '$PhaseName' | Total Duration: ${elapsed}s"
        exit 0
    }
}

#region --------------------------------------------------------
# HELPER: Get-BDInstalledComponents
# Purpose : Query registry for currently installed Bitdefender components
# Inputs  : None (uses $BDRegistryRoots and $BDComponents from config)
# Outputs : Array of PSCustomObjects with Name and DisplayVersion
#endregion -------------------------------------------------------
function Get-BDInstalledComponents {
    $installed = Get-ItemProperty $BDRegistryRoots -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName } |
        Where-Object { $bd = $_; ($BDComponents | Where-Object { $bd.DisplayName -like "*$($_.MatchPattern)*" }) } |
        Select-Object DisplayName, DisplayVersion, UninstallString

    return $installed
}

#region --------------------------------------------------------
# HELPER: Invoke-WithRetry
# Purpose : Retry a scriptblock on failure with exponential backoff
# Inputs  : ScriptBlock, MaxAttempts, InitialDelaySec, OperationName
# Outputs : Result of scriptblock, or throws on exhaustion
#endregion -------------------------------------------------------
function Invoke-WithRetry {
    param(
        [scriptblock]$ScriptBlock,
        [int]$MaxAttempts = $DownloadRetries,
        [int]$InitialDelaySec = $RetryDelaySec,
        [string]$OperationName = 'Operation'
    )
    $attempt = 0
    $delay   = $InitialDelaySec

    while ($attempt -lt $MaxAttempts) {
        $attempt++
        Write-Log DEBUG "RETRY: $OperationName attempt $attempt of $MaxAttempts"
        try {
            $result = & $ScriptBlock
            return $result
        } catch {
            if ($attempt -lt $MaxAttempts) {
                Write-Log WARN "RETRY_WAIT: $OperationName attempt $attempt failed — waiting ${delay}s before retry | Error: $($_.Exception.Message)"
                Start-Sleep -Seconds $delay
                $delay *= 2
            } else {
                Write-Log ERROR "RETRY_EXHAUSTED: $OperationName failed after $MaxAttempts attempts | Last error: $($_.Exception.Message)"
                throw
            }
        }
    }
}

# ============================================================
# MAIN
# ============================================================

# Ensure log directory exists
$logDir = Split-Path $LogPath
if ($logDir -and -not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}

Write-Log INFO "SCRIPT_START: Remove-Bitdefender.ps1 v$ScriptVersion | User: $env:USERNAME | Host: $env:COMPUTERNAME"

if ($DryRun)    { Write-Log WARN 'DRY-RUN MODE ACTIVE — no changes will be made' }
if ($DebugMode) { Write-Log INFO 'DEBUG MODE ACTIVE' }

# ENV_SNAPSHOT
Write-Log INFO "ENV_SNAPSHOT: OS=$([System.Environment]::OSVersion.VersionString) | PS=$($PSVersionTable.PSVersion) | WorkDir=$(Get-Location) | Script=$($MyInvocation.MyCommand.Path)"
Write-Log INFO "PARAMS: DryRun=$DryRun | DebugMode=$DebugMode | StopAfterPhase='$StopAfterPhase' | LogPath=$LogPath | ToolPath=$ToolPath"

# ================================================================
# PHASE 1: PREFLIGHT
# ================================================================
Write-Log INFO 'PHASE_START: Preflight'
$phaseStart = Get-Date

#region ============================================================
# UNIT: Verify-RunningAsSystem
# Purpose : Confirm the script is running with SYSTEM or Administrator rights
# Inputs  : Current process identity
# Outputs : Passes or exits 10
#endregion ==========================================================
Write-Log INFO 'UNIT_START: Verify-RunningAsSystem'
$unitStart = Get-Date
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $isSystem = ($identity.Name -eq 'NT AUTHORITY\SYSTEM')

    if (-not $isAdmin -and -not $isSystem) {
        Write-Log FATAL "Verify-RunningAsSystem: Not running as Administrator or SYSTEM (identity: $($identity.Name))"
        exit 10
    }
    Write-Log INFO "VERIFY_OK: Running as $($identity.Name)"
} catch {
    Write-Log FATAL "UNIT_FAILED: Verify-RunningAsSystem | Error: $($_.Exception.Message) | Line: $($_.InvocationInfo.ScriptLineNumber)"
    exit 10
} finally {
    $dur = [math]::Round(((Get-Date) - $unitStart).TotalSeconds, 2)
    Write-Log INFO "UNIT_END: Verify-RunningAsSystem | Duration: ${dur}s"
}

#region ============================================================
# UNIT: Inventory-BDComponents
# Purpose : Enumerate installed Bitdefender components from registry
#           Warn if fewer than expected are present (may already be partially removed)
# Inputs  : Registry (via Get-BDInstalledComponents helper)
# Outputs : $preRemovalComponents — used for removal confirmation later
#endregion ==========================================================
Write-Log INFO 'UNIT_START: Inventory-BDComponents'
$unitStart = Get-Date
try {
    $preRemovalComponents = Get-BDInstalledComponents

    if ($preRemovalComponents.Count -eq 0) {
        Write-Log WARN 'Inventory-BDComponents: No Bitdefender components found in registry — endpoint may already be clean'
        Write-Log WARN 'VERIFY_WARN: Proceeding with tool execution anyway in case components are partially installed'
    } else {
        Write-Log INFO "VERIFY_OK: Found $($preRemovalComponents.Count) Bitdefender component(s) in registry:"
        foreach ($c in $preRemovalComponents) {
            Write-Log INFO "  -> $($c.DisplayName) | Version: $($c.DisplayVersion)"
        }
    }
} catch {
    Write-Log ERROR "UNIT_FAILED: Inventory-BDComponents | Error: $($_.Exception.Message) | Line: $($_.InvocationInfo.ScriptLineNumber)"
    exit 10
} finally {
    $dur = [math]::Round(((Get-Date) - $unitStart).TotalSeconds, 2)
    Write-Log INFO "UNIT_END: Inventory-BDComponents | Duration: ${dur}s"
}

#region ============================================================
# UNIT: Verify-NetworkAccess
# Purpose : Confirm the tool download URL is reachable before committing to download
# Inputs  : $ToolUrl
# Outputs : Passes or exits 10
#endregion ==========================================================
Write-Log INFO 'UNIT_START: Verify-NetworkAccess'
$unitStart = Get-Date
try {
    if ($DryRun) {
        Write-Log INFO "[DRY-RUN] Would test HTTP HEAD to $ToolUrl"
    } else {
        $req = [System.Net.WebRequest]::Create($ToolUrl)
        $req.Method = 'HEAD'
        $req.Timeout = 15000
        $resp = $req.GetResponse()
        $statusCode = [int]$resp.StatusCode
        $resp.Close()

        if ($statusCode -ne 200) {
            Write-Log ERROR "Verify-NetworkAccess: URL returned HTTP $statusCode — expected 200"
            exit 10
        }
        Write-Log INFO "VERIFY_OK: $ToolUrl is reachable (HTTP $statusCode)"
    }
} catch {
    Write-Log FATAL "UNIT_FAILED: Verify-NetworkAccess | URL unreachable: $ToolUrl | Error: $($_.Exception.Message)"
    exit 10
} finally {
    $dur = [math]::Round(((Get-Date) - $unitStart).TotalSeconds, 2)
    Write-Log INFO "UNIT_END: Verify-NetworkAccess | Duration: ${dur}s"
}

Invoke-PhaseGate -PhaseName 'Preflight' -Summary "Identity: $($identity.Name) | BD components found: $($preRemovalComponents.Count)"

# ================================================================
# PHASE 2: DOWNLOAD
# ================================================================
Write-Log INFO 'PHASE_START: Download'
$phaseStart = Get-Date

#region ============================================================
# UNIT: Download-UninstallTool
# Purpose : Download the Bitdefender 2023 Uninstall Tool to local disk
#           Retries up to $DownloadRetries times with exponential backoff
# Inputs  : $ToolUrl, $ToolPath
# Outputs : $ToolPath populated on disk
#endregion ==========================================================
Write-Log INFO "UNIT_START: Download-UninstallTool | Destination: $ToolPath"
$unitStart = Get-Date
try {
    # Remove stale copy if present
    if (Test-Path $ToolPath) {
        Write-Log INFO "Download-UninstallTool: Removing stale tool at $ToolPath"
        if (-not $DryRun) { Remove-Item $ToolPath -Force }
    }

    if ($DryRun) {
        Write-Log INFO "[DRY-RUN] Would download $ToolUrl -> $ToolPath"
    } else {
        Invoke-WithRetry -OperationName 'BD Tool Download' -ScriptBlock {
            $wc = New-Object System.Net.WebClient
            $wc.DownloadFile($ToolUrl, $ToolPath)
        }

        if (-not (Test-Path $ToolPath)) {
            Write-Log ERROR "Download-UninstallTool: File not present at $ToolPath after download"
            exit 20
        }

        $fileSize = (Get-Item $ToolPath).Length
        if ($fileSize -lt 100KB) {
            Write-Log ERROR "Download-UninstallTool: File suspiciously small ($fileSize bytes) — download may be corrupt"
            exit 20
        }

        Write-Log INFO "VERIFY_OK: Tool downloaded successfully | Path: $ToolPath | Size: $([math]::Round($fileSize / 1MB, 2)) MB"
    }
} catch {
    Write-Log ERROR "UNIT_FAILED: Download-UninstallTool | Error: $($_.Exception.Message) | Line: $($_.InvocationInfo.ScriptLineNumber)"
    exit 20
} finally {
    $dur = [math]::Round(((Get-Date) - $unitStart).TotalSeconds, 2)
    Write-Log INFO "UNIT_END: Download-UninstallTool | Duration: ${dur}s"
}

Invoke-PhaseGate -PhaseName 'Download' -Summary "Tool: $ToolPath"

# ================================================================
# PHASE 3: REMOVAL
# ================================================================
Write-Log INFO 'PHASE_START: Removal'
$phaseStart = Get-Date

#region ============================================================
# UNIT: Execute-UninstallTool
# Purpose : Run the Bitdefender uninstall tool silently and wait for completion
#           Tool handles all three components (Total Security, Agent, VPN)
# Inputs  : $ToolPath
# Outputs : Exit code from tool process; logs outcome
# Notes   : /bdparams /silent suppresses all UI; tool may request a reboot
#           but will NOT force one — caller handles reboot scheduling
#endregion ==========================================================
Write-Log INFO 'UNIT_START: Execute-UninstallTool'
$unitStart = Get-Date
try {
    if ($DryRun) {
        Write-Log INFO "[DRY-RUN] Would execute: $ToolPath /bdparams /silent"
        Write-Log INFO '[DRY-RUN] Would wait up to $ToolTimeoutSec seconds for completion'
        $toolExitCode = 0
    } else {
        Write-Log INFO "Execute-UninstallTool: Launching $ToolPath /bdparams /silent"

        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName  = $ToolPath
        $psi.Arguments = '/bdparams /silent'
        $psi.UseShellExecute = $false

        $proc = [System.Diagnostics.Process]::Start($psi)

        $completed = $proc.WaitForExit($ToolTimeoutSec * 1000)

        if (-not $completed) {
            Write-Log ERROR "Execute-UninstallTool: Tool did not complete within ${ToolTimeoutSec}s — killing process"
            try { $proc.Kill() } catch {}
            exit 30
        }

        $toolExitCode = $proc.ExitCode
        Write-Log INFO "Execute-UninstallTool: Tool exited with code $toolExitCode"

        # BD uninstall tool returns 0 (success) or 3010 (success, reboot required)
        # Any other code is treated as a failure
        if ($toolExitCode -notin @(0, 3010)) {
            Write-Log ERROR "Execute-UninstallTool: Unexpected exit code $toolExitCode from uninstall tool"
            exit 30
        }

        if ($toolExitCode -eq 3010) {
            Write-Log WARN 'Execute-UninstallTool: Tool signaled reboot required (exit 3010) — schedule reboot via N-Able'
        } else {
            Write-Log INFO 'VERIFY_OK: Uninstall tool completed successfully (exit 0)'
        }
    }
} catch {
    Write-Log ERROR "UNIT_FAILED: Execute-UninstallTool | Error: $($_.Exception.Message) | Line: $($_.InvocationInfo.ScriptLineNumber)"
    exit 30
} finally {
    $dur = [math]::Round(((Get-Date) - $unitStart).TotalSeconds, 2)
    Write-Log INFO "UNIT_END: Execute-UninstallTool | Duration: ${dur}s"
}

Invoke-PhaseGate -PhaseName 'Removal' -Summary "Tool exit code: $toolExitCode"

# ================================================================
# PHASE 4: VALIDATION
# ================================================================
Write-Log INFO 'PHASE_START: Validation'
$phaseStart = Get-Date

#region ============================================================
# UNIT: Validate-BDRemoval
# Purpose : Re-query registry and confirm all three Bitdefender components
#           are absent. Checks each component individually and logs pass/fail.
# Inputs  : Registry (via Get-BDInstalledComponents helper)
# Outputs : Per-component VERIFY_OK or VERIFY_FAILED; exits 40 on any failure
#endregion ==========================================================
Write-Log INFO 'UNIT_START: Validate-BDRemoval'
$unitStart = Get-Date
$validationFailed = $false
try {
    # Brief pause — some uninstallers finish async cleanup after the main process exits
    if (-not $DryRun) {
        Write-Log INFO 'Validate-BDRemoval: Waiting 10 seconds for registry cleanup to settle...'
        Start-Sleep -Seconds 10
    }

    if ($DryRun) {
        Write-Log INFO '[DRY-RUN] Would re-query registry for Bitdefender components'
        Write-Log INFO '[DRY-RUN] Would verify each component is absent'
    } else {
        $postRemovalComponents = Get-BDInstalledComponents

        foreach ($expected in $BDComponents) {
            $stillPresent = $postRemovalComponents | Where-Object { $_.DisplayName -like "*$($expected.MatchPattern)*" }

            if ($stillPresent) {
                Write-Log ERROR "VERIFY_FAILED: $($expected.Name) still present after removal | Version: $($stillPresent.DisplayVersion)"
                Write-Log ERROR "  UninstallString: $($stillPresent.UninstallString)"
                $validationFailed = $true
            } else {
                Write-Log INFO "VERIFY_OK: $($expected.Name) — not found in registry (removal confirmed)"
            }
        }

        # Secondary check: confirm BD processes are not running
        $bdProcesses = Get-Process | Where-Object { $_.Name -match 'bdagent|bdservicehost|bdwtxag|bdupdater|bdvpn' } -ErrorAction SilentlyContinue
        if ($bdProcesses) {
            Write-Log WARN "VERIFY_WARN: Bitdefender processes still running after removal (may clear on reboot):"
            foreach ($p in $bdProcesses) {
                Write-Log WARN "  -> PID $($p.Id) | $($p.Name)"
            }
        } else {
            Write-Log INFO 'VERIFY_OK: No Bitdefender processes detected'
        }

        # Secondary check: BD service entries
        $bdServices = Get-Service | Where-Object { $_.Name -match 'VSSERV|bdredline|bdntdrv|EPProtectedService' } -ErrorAction SilentlyContinue
        if ($bdServices) {
            Write-Log WARN "VERIFY_WARN: Bitdefender services still registered (may clear on reboot):"
            foreach ($svc in $bdServices) {
                Write-Log WARN "  -> Service: $($svc.Name) | Status: $($svc.Status)"
            }
        } else {
            Write-Log INFO 'VERIFY_OK: No Bitdefender services detected'
        }
    }

    if ($validationFailed) {
        Write-Log ERROR 'VERIFY_FAILED: One or more Bitdefender components remain — manual follow-up required'
        exit 40
    }

} catch {
    Write-Log ERROR "UNIT_FAILED: Validate-BDRemoval | Error: $($_.Exception.Message) | Line: $($_.InvocationInfo.ScriptLineNumber)"
    exit 40
} finally {
    $dur = [math]::Round(((Get-Date) - $unitStart).TotalSeconds, 2)
    Write-Log INFO "UNIT_END: Validate-BDRemoval | Duration: ${dur}s"
}

#region ============================================================
# UNIT: Cleanup-ToolArtifact
# Purpose : Remove the downloaded uninstall tool from disk after successful validation
# Inputs  : $ToolPath
# Outputs : Tool file removed; logged
#endregion ==========================================================
Write-Log INFO 'UNIT_START: Cleanup-ToolArtifact'
$unitStart = Get-Date
try {
    if (Test-Path $ToolPath) {
        if ($DryRun) {
            Write-Log INFO "[DRY-RUN] Would remove tool artifact: $ToolPath"
        } else {
            Remove-Item $ToolPath -Force
            Write-Log INFO "VERIFY_OK: Tool artifact removed: $ToolPath"
        }
    } else {
        Write-Log INFO "Cleanup-ToolArtifact: Tool artifact already absent at $ToolPath — nothing to remove"
    }
} catch {
    # Non-fatal — log and continue
    Write-Log WARN "Cleanup-ToolArtifact: Could not remove tool artifact | Error: $($_.Exception.Message)"
} finally {
    $dur = [math]::Round(((Get-Date) - $unitStart).TotalSeconds, 2)
    Write-Log INFO "UNIT_END: Cleanup-ToolArtifact | Duration: ${dur}s"
}

$validationSummary = if ($DryRun) { 'DRY-RUN: no changes made' } else { 'All components removed and verified' }
Invoke-PhaseGate -PhaseName 'Validation' -Summary $validationSummary

# ================================================================
# COMPLETE
# ================================================================
$totalDuration = [math]::Round(((Get-Date) - $ScriptStartTime).TotalSeconds, 1)
Write-Log INFO "SCRIPT_COMPLETE: Remove-Bitdefender.ps1 | Total Duration: ${totalDuration}s | Log: $LogPath"

if ($toolExitCode -eq 3010) {
    Write-Log WARN 'ACTION REQUIRED: Reboot is needed to complete Bitdefender removal. Schedule via N-Able.'
}

exit 0