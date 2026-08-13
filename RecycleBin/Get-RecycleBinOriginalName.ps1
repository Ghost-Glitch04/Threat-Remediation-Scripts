#Requires -Version 5.0
<#
================================================================================
 SCRIPT   : Get-RecycleBinOriginalName.ps1
 PURPOSE  : Recover the original filename/path/deletion-time for ANY file
            found in the Windows Recycle Bin ($R-named artifact), by locating
            and parsing its paired $I metadata file.
 SCOPE    : READ-ONLY. No files are moved, restored, deleted, or modified.
 AUTHOR   : Ghost (IR triage)
 VERSION  : 4.0 — script-invocable via PowerShell.exe -File (download-and-run
            framework); function is retained internally and dot-sourcing is
            still supported for the interactive-paste workflow.

 v4 CHANGE LOG:
   - Added a top-level `param()` block as the script's true first statement.
     v3 was function-definition-only and could not receive arguments from
     `PowerShell.exe -File script.ps1 -ThreatFileName ... -ExpectedSHA1 ...`
     -- those arguments had nowhere to bind, so the script silently did
     nothing. This restores direct -File invocability.
   - `exit $result.ExitCode` is used at the bottom of the direct-run path.
     This is safe in THIS context specifically because `-File` always spawns
     a separate child PowerShell.exe process -- exiting it does not
     terminate a parent interactive remote-shell session the way it would
     if this were pasted line-by-line into a live console.
   - Dot-sourcing still works for the interactive-paste-and-reuse workflow:
     `. .\Get-RecycleBinOriginalName.ps1` with no arguments loads the
     function without running the direct-invoke path or exiting your
     session, exactly like v3 did. Direct execution (double-click, `.\`,
     or `-File`) runs the full lookup and exits with a status code.

 USAGE — via the download-and-run framework (this is the primary path now):

     $ThreatFileName  = '$RSOMENAME.exe'
     $ExpectedSHA1    = '<sha1 from alert>'
     $url             = 'https://raw.githubusercontent.com/<org>/<repo>/<branch>/RecycleBin/Get-RecycleBinOriginalName.ps1'
     $scriptPath      = "$env:TEMP\Get-RecycleBinOriginalName.ps1"
     Invoke-WebRequest -Uri $url -OutFile $scriptPath -UseBasicParsing
     Test-Path -Path $scriptPath
     PowerShell.exe -ExecutionPolicy Bypass -File $scriptPath -ThreatFileName $ThreatFileName -ExpectedSHA1 $ExpectedSHA1
     Remove-Item $scriptPath -Force -ErrorAction SilentlyContinue

 USAGE — interactive paste-and-reuse (dot-source, no direct exit/run):

     # paste the whole file prefixed with ". " to dot-source it, e.g. in a
     # remote shell that supports it, or save+dot-source from disk:
     . $scriptPath
     $result = Invoke-RecycleBinLookup -ThreatFileName '$RSOMENAME.exe' -ExpectedSHA1 '<sha1>'
     $result | Format-List

 ERROR CODE REFERENCE (returned as $result.ExitCode; also used as the
 process exit code when run directly via -File):
   0  = Success
   10 = $R (target) file not found under Recycle Bin root
   11 = $I metadata file not found, or target does not match $R naming pattern
   12 = $I metadata file unreadable / too short to contain a valid header
   20 = $I header parse failure (unrecognized version / malformed structure)
   40 = SHA1 corroboration mismatch (parsed correctly, but hash does not match
        -ExpectedSHA1 -- non-fatal, flagged VERIFY_WARN, still exits 40 so
        automation can distinguish "ran fine but hash didn't match")
   99 = Unexpected / unhandled error
================================================================================
#>

param(
    # Root of the Recycle Bin to search. Default covers the standard case
    # (system volume). Override for other volumes, e.g. 'D:\$Recycle.Bin'.
    [string]$RecycleBinRoot = 'C:\$Recycle.Bin',

    # The $R-prefixed file name exactly as shown in the SentinelOne alert
    # (or however it was discovered).
    [string]$ThreatFileName,

    # Optional: SHA1 to corroborate the recovered metadata matches the SAME
    # file the alert fired on. Leave blank to skip.
    [string]$ExpectedSHA1 = "",

    # Where to write the log file. Defaults to a timestamped file in TEMP.
    [string]$LogPath = "$env:TEMP\RecycleBin_Lookup_$(Get-Date -Format 'yyyyMMdd_HHmmss_fff').log",

    # Promotes DEBUG-level entries to console.
    [switch]$DebugMode
)

# ============================================================
# HELPERS
# ============================================================

function Write-Log {
    param(
        [ValidateSet("DEBUG","INFO","WARN","ERROR","FATAL")]
        [string]$Level,
        [string]$Message
    )
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $line = "[$ts] [$Level] $Message"
    try { Add-Content -Path $LogPath -Value $line -Encoding UTF8 -ErrorAction Stop }
    catch { Write-Host "[$ts] [WARN] Could not write to log file '$LogPath': $($_.Exception.Message)" -ForegroundColor Yellow }

    if ($Level -ne "DEBUG" -or $DebugMode) {
        switch ($Level) {
            "DEBUG" { Write-Host $line -ForegroundColor DarkGray }
            "INFO"  { Write-Host $line -ForegroundColor Gray }
            "WARN"  { Write-Host $line -ForegroundColor Yellow }
            "ERROR" { Write-Host $line -ForegroundColor Red }
            "FATAL" { Write-Host $line -ForegroundColor Red }
        }
    }
}

function Read-RecycleBinMetadata {
    param([string]$IFilePath)

    try {
        $bytes = [System.IO.File]::ReadAllBytes($IFilePath)
    }
    catch {
        Write-Log -Level ERROR -Message "UNIT_FAILED: Read-RecycleBinMetadata | Could not read bytes from '$IFilePath' | $($_.Exception.Message) | ExitCode=12"
        return $null
    }

    if ($bytes.Length -lt 24) {
        Write-Log -Level ERROR -Message "UNIT_FAILED: Read-RecycleBinMetadata | File too short ($($bytes.Length) bytes) to contain a valid `$I header | ExitCode=12"
        return $null
    }

    $version = [BitConverter]::ToInt64($bytes, 0)
    $fileSize = [BitConverter]::ToInt64($bytes, 8)
    $fileTimeRaw = [BitConverter]::ToInt64($bytes, 16)

    try {
        $deletionTimeUtc = [DateTime]::FromFileTimeUtc($fileTimeRaw)
    }
    catch {
        Write-Log -Level WARN -Message "VERIFY_WARN: Deletion FILETIME value ($fileTimeRaw) did not convert cleanly; leaving as `$null"
        $deletionTimeUtc = $null
    }

    $originalPath = $null

    switch ($version) {
        1 {
            # Fixed-width: 260 WCHAR (520 bytes) starting at offset 24, null-terminated
            if ($bytes.Length -lt (24 + 520)) {
                Write-Log -Level ERROR -Message "UNIT_FAILED: Read-RecycleBinMetadata | Version 1 header truncated (expected >= 544 bytes, got $($bytes.Length)) | ExitCode=20"
                return $null
            }
            $rawPath = [System.Text.Encoding]::Unicode.GetString($bytes, 24, 520)
            $originalPath = $rawPath.Split([char]0)[0]
        }
        2 {
            # Variable-length: 4-byte path length (UTF-16 code units) at offset 24,
            # path bytes follow starting at offset 28.
            if ($bytes.Length -lt 28) {
                Write-Log -Level ERROR -Message "UNIT_FAILED: Read-RecycleBinMetadata | Version 2 header missing path-length field | ExitCode=20"
                return $null
            }
            $pathLenChars = [BitConverter]::ToInt32($bytes, 24)
            $pathByteLen = $pathLenChars * 2
            if ($bytes.Length -lt (28 + $pathByteLen)) {
                Write-Log -Level ERROR -Message "UNIT_FAILED: Read-RecycleBinMetadata | Version 2 path field truncated (declared $pathLenChars chars, only $($bytes.Length - 28) bytes available) | ExitCode=20"
                return $null
            }
            $rawPath = [System.Text.Encoding]::Unicode.GetString($bytes, 28, $pathByteLen)
            $originalPath = $rawPath.TrimEnd([char]0)
        }
        default {
            Write-Log -Level ERROR -Message "UNIT_FAILED: Read-RecycleBinMetadata | Unrecognized `$I header version '$version' | ExitCode=20"
            return $null
        }
    }

    return [PSCustomObject]@{
        Version         = $version
        OriginalPath    = $originalPath
        FileSizeBytes   = $fileSize
        DeletionTimeUtc = $deletionTimeUtc
    }
}

function Invoke-RecycleBinLookup {
    <#
        Purpose : Core lookup logic. Kept as a standalone, argument-driven
                  function (rather than inlined into the top-level script
                  body) so it stays independently callable if this file is
                  dot-sourced for interactive reuse across multiple lookups
                  in one session, per the original v3 design.
        Inputs  : -RecycleBinRoot, -ThreatFileName, -ExpectedSHA1, -LogPath, -DebugMode
        Outputs : PSCustomObject with ExitCode + recovered fields
        Depends : Write-Log, Read-RecycleBinMetadata
    #>
    param(
        [string]$RecycleBinRoot = 'C:\$Recycle.Bin',
        [Parameter(Mandatory = $true)]
        [string]$ThreatFileName,
        [string]$ExpectedSHA1 = "",
        [string]$LogPath = "$env:TEMP\RecycleBin_Lookup_$(Get-Date -Format 'yyyyMMdd_HHmmss_fff').log",
        [switch]$DebugMode
    )

    # ============================================================
    # UNIT: Initialize
    # ============================================================
    $scriptStart = Get-Date
    Write-Log -Level INFO -Message "SCRIPT_START: Invoke-RecycleBinLookup v4.0"
    Write-Log -Level INFO -Message "ENV_SNAPSHOT: Host=$env:COMPUTERNAME | User=$env:USERNAME | PSVersion=$($PSVersionTable.PSVersion) | OS=$([System.Environment]::OSVersion.VersionString)"
    Write-Log -Level INFO -Message "PARAMS: RecycleBinRoot='$RecycleBinRoot' | ThreatFileName='$ThreatFileName' | ExpectedSHA1='$ExpectedSHA1' | DebugMode=$($DebugMode.IsPresent)"
    if ($DebugMode) { Write-Log -Level INFO -Message "DEBUG MODE ACTIVE" }

    # ============================================================
    # UNIT: Locate-TargetFile
    # ============================================================
    $unitStart = Get-Date
    Write-Log -Level INFO -Message "UNIT_START: Locate-TargetFile | Searching '$RecycleBinRoot' for '$ThreatFileName'"

    if (-not (Test-Path -Path $RecycleBinRoot)) {
        Write-Log -Level FATAL -Message "SCRIPT_FAILED: Recycle Bin root '$RecycleBinRoot' does not exist or is not accessible | ExitCode=10"
        return [PSCustomObject]@{ ExitCode = 10; Error = "RecycleBinRoot not found: $RecycleBinRoot" }
    }

    $rFile = Get-ChildItem -Path $RecycleBinRoot -Recurse -Force -Filter $ThreatFileName -ErrorAction SilentlyContinue | Select-Object -First 1

    if (-not $rFile) {
        Write-Log -Level ERROR -Message "VERIFY_FAILED: Target file '$ThreatFileName' not found anywhere under '$RecycleBinRoot'. It may have already been purged/restored. | ExitCode=10"
        return [PSCustomObject]@{ ExitCode = 10; Error = "Target file not found: $ThreatFileName" }
    }

    Write-Log -Level INFO -Message "VERIFY_OK: Located target file at '$($rFile.FullName)' | SizeBytes=$($rFile.Length)"
    Write-Log -Level INFO -Message "UNIT_END: Locate-TargetFile | Duration: $((Get-Date) - $unitStart)"

    # ============================================================
    # UNIT: Locate-MetadataPair
    # ============================================================
    $unitStart = Get-Date

    if ($rFile.Name.Length -lt 3 -or $rFile.Name.Substring(0,2) -ne '$R') {
        Write-Log -Level ERROR -Message "VERIFY_FAILED: '$($rFile.Name)' does not follow the expected `$R<suffix> Recycle Bin naming pattern | ExitCode=11"
        return [PSCustomObject]@{ ExitCode = 11; Error = "File does not match `$R naming pattern: $($rFile.Name)" }
    }

    $expectedIName = '$I' + $rFile.Name.Substring(2)
    Write-Log -Level INFO -Message "UNIT_START: Locate-MetadataPair | Expecting metadata file '$expectedIName' in '$($rFile.DirectoryName)'"

    $iFile = Get-ChildItem -Path $rFile.DirectoryName -Force -Filter $expectedIName -ErrorAction SilentlyContinue | Select-Object -First 1

    if (-not $iFile) {
        Write-Log -Level ERROR -Message "VERIFY_FAILED: No paired metadata file '$expectedIName' found alongside target file. Recycle Bin entry may be corrupted or partially purged. | ExitCode=11"
        return [PSCustomObject]@{ ExitCode = 11; Error = "Metadata file not found: $expectedIName" }
    }

    Write-Log -Level INFO -Message "VERIFY_OK: Located metadata file at '$($iFile.FullName)' | SizeBytes=$($iFile.Length)"
    Write-Log -Level INFO -Message "UNIT_END: Locate-MetadataPair | Duration: $((Get-Date) - $unitStart)"

    # ============================================================
    # UNIT: Parse-Metadata
    # ============================================================
    $unitStart = Get-Date
    Write-Log -Level INFO -Message "UNIT_START: Parse-Metadata | Parsing '$($iFile.FullName)'"

    $metadata = Read-RecycleBinMetadata -IFilePath $iFile.FullName

    if (-not $metadata) {
        Write-Log -Level FATAL -Message "SCRIPT_FAILED: Unable to parse `$I metadata header | ExitCode=20"
        return [PSCustomObject]@{ ExitCode = 20; Error = "Metadata header parse failed" }
    }

    Write-Log -Level INFO -Message "VERIFY_OK: Parsed `$I header successfully | HeaderVersion=$($metadata.Version)"
    Write-Log -Level INFO -Message "UNIT_END: Parse-Metadata | Duration: $((Get-Date) - $unitStart)"

    # ============================================================
    # UNIT: Verify-Corroboration (optional, non-fatal)
    # ============================================================
    $unitStart = Get-Date
    $corroborated = $null

    if ([string]::IsNullOrWhiteSpace($ExpectedSHA1)) {
        Write-Log -Level INFO -Message "UNIT_START: Verify-Corroboration | Skipped -- no -ExpectedSHA1 provided"
    }
    else {
        Write-Log -Level INFO -Message "UNIT_START: Verify-Corroboration | Hashing live file to compare against provided SHA1"
        try {
            $liveHash = (Get-FileHash -Path $rFile.FullName -Algorithm SHA1 -ErrorAction Stop).Hash
            if ($liveHash -ieq $ExpectedSHA1) {
                Write-Log -Level INFO -Message "VERIFY_OK: Live file SHA1 ($liveHash) matches provided SHA1. Metadata recovered corresponds to the correct file."
                $corroborated = $true
            }
            else {
                Write-Log -Level WARN -Message "VERIFY_WARN: Live file SHA1 ($liveHash) does NOT match provided SHA1 ($ExpectedSHA1). Recovered name/path may belong to a different file with a colliding `$R suffix -- treat result with caution. | ExitCode=40"
                $corroborated = $false
            }
        }
        catch {
            Write-Log -Level ERROR -Message "RECORD_FAILED: Verify-Corroboration | Could not hash '$($rFile.FullName)' | $($_.Exception.Message)"
            $corroborated = $null
        }
    }
    Write-Log -Level INFO -Message "UNIT_END: Verify-Corroboration | Duration: $((Get-Date) - $unitStart)"

    # ============================================================
    # Build result
    # ============================================================
    $totalDuration = (Get-Date) - $scriptStart

    $result = [PSCustomObject]@{
        ExitCode            = if ($corroborated -eq $false) { 40 } else { 0 }
        ThreatFileName      = $rFile.Name
        RecoveredFileName   = if ($metadata.OriginalPath) { Split-Path -Path $metadata.OriginalPath -Leaf } else { $null }
        OriginalFullPath    = $metadata.OriginalPath
        OriginalFileSizeB   = $metadata.FileSizeBytes
        DeletionTimeUtc     = $metadata.DeletionTimeUtc
        RecycleBinLocation  = $rFile.FullName
        MetadataFile        = $iFile.FullName
        HeaderVersion       = $metadata.Version
        SHA1Corroborated    = $corroborated
        LogPath             = $LogPath
    }

    Write-Log -Level INFO -Message "RESULT: OriginalFullPath='$($result.OriginalFullPath)' | RecoveredFileName='$($result.RecoveredFileName)' | DeletionTimeUtc='$($result.DeletionTimeUtc)' | OriginalFileSizeBytes=$($result.OriginalFileSizeB) | SHA1Corroborated=$($result.SHA1Corroborated)"
    Write-Log -Level INFO -Message "SCRIPT_COMPLETE: Total Duration: $totalDuration"

    return $result
}

# ================================================================
# MAIN — direct-run path
#
# Only executes the lookup (and exits) when the script actually received
# -ThreatFileName as an argument, i.e. it was launched directly (-File,
# `.\script.ps1`, double-click). If dot-sourced with no arguments purely
# to load the functions above for interactive reuse, $ThreatFileName is
# empty, this block is skipped, and no exit is called -- matching the
# v3 behavior for that workflow.
# ================================================================
if (-not [string]::IsNullOrWhiteSpace($ThreatFileName)) {
    $result = Invoke-RecycleBinLookup -RecycleBinRoot $RecycleBinRoot -ThreatFileName $ThreatFileName -ExpectedSHA1 $ExpectedSHA1 -LogPath $LogPath -DebugMode:$DebugMode

    $result | Format-List
    Write-Host "`nLog file: $($result.LogPath)" -ForegroundColor Cyan

    exit $result.ExitCode
}