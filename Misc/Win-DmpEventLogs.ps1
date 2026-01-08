$csharpCode = @"
using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Text;
using System.IO;
using System.Text.RegularExpressions;

public class EventLogAnalyzer
{
    public class EventLogEntry
    {
        public string LogName { get; set; }
        public DateTime TimeCreated { get; set; }
        public int EventId { get; set; }
        public string Level { get; set; }
        public string ProviderName { get; set; }
        public string MachineName { get; set; }
        public string UserId { get; set; }
        public string Message { get; set; }
        public string CorrelationTag { get; set; }
    }

    public static void WriteLog(StringBuilder log, string logFile, string msg)
    {
        if (log != null)
        {
            var ts = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
            log.AppendLine(string.Format("[{0}] {1}", ts, msg));
            try { File.AppendAllText(logFile, string.Format("[{0}] {1}\r\n", ts, msg), new System.Text.UTF8Encoding(false)); } catch { }
        }
    }

    public static Dictionary<string, object> ParseEventLogs(string[] logNames, DateTime? startTime = null, DateTime? endTime = null, StringBuilder logBuffer = null, string logFile = null)
    {
        var entries = new List<EventLogEntry>();
        var accessResults = new Dictionary<string, string>();
        var start = DateTime.Now;
        
        if (logBuffer != null)
            WriteLog(logBuffer, logFile, "ParseEventLogs started");
        
        foreach (var logName in logNames)
        {
            int eventCount = 0;
            int errorCount = 0;
            var logStart = DateTime.Now;
            
            if (logBuffer != null)
                WriteLog(logBuffer, logFile, string.Format("Processing: {0}", logName));
            
            try
            {
                using (var session = new EventLogSession())
                {
                    if (logBuffer != null)
                        WriteLog(logBuffer, logFile, string.Format("{0}: Creating reader", logName));
                    
                    EventLogReader reader = null;
                    if (startTime.HasValue || endTime.HasValue)
                    {
                        var xpath = new StringBuilder();
                        if (startTime.HasValue && endTime.HasValue)
                        {
                            xpath.AppendFormat("*[System[TimeCreated[@SystemTime >= '{0}' and @SystemTime <= '{1}']]]",
                                startTime.Value.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
                                endTime.Value.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ"));
                        }
                        else if (startTime.HasValue)
                        {
                            xpath.AppendFormat("*[System[TimeCreated[@SystemTime >= '{0}']]]",
                                startTime.Value.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ"));
                        }
                        else if (endTime.HasValue)
                        {
                            xpath.AppendFormat("*[System[TimeCreated[@SystemTime <= '{0}']]]",
                                endTime.Value.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ"));
                        }
                        var query = new EventLogQuery(logName, PathType.LogName, xpath.ToString());
                        reader = new EventLogReader(query);
                        if (logBuffer != null)
                            WriteLog(logBuffer, logFile, string.Format("{0}: Using time filter", logName));
                    }
                    else
                    {
                        reader = new EventLogReader(logName, PathType.LogName);
                    }
                    
                    using (reader)
                    {
                        if (logBuffer != null)
                            WriteLog(logBuffer, logFile, string.Format("{0}: Reading events", logName));
                        
                        EventRecord eventRecord;
                        int readAttempts = 0;
                        
                        while ((eventRecord = reader.ReadEvent()) != null)
                        {
                            readAttempts++;
                            if (readAttempts == 1 && logBuffer != null)
                                WriteLog(logBuffer, logFile, string.Format("{0}: First ReadEvent() call", logName));
                            
                            try
                            {
                                string message = "N/A";
                                try
                                {
                                    message = eventRecord.FormatDescription() ?? "N/A";
                                }
                                catch (System.IO.FileNotFoundException)
                                {
                                    message = string.Format("Event {0} - Message file not available", eventRecord.Id);
                                }
                                catch
                                {
                                    message = "N/A";
                                }
                                
                                var entry = new EventLogEntry
                                {
                                    LogName = logName,
                                    TimeCreated = eventRecord.TimeCreated ?? DateTime.MinValue,
                                    EventId = eventRecord.Id,
                                    Level = eventRecord.LevelDisplayName ?? eventRecord.Level.ToString(),
                                    ProviderName = eventRecord.ProviderName ?? "Unknown",
                                    MachineName = eventRecord.MachineName ?? Environment.MachineName,
                                    UserId = eventRecord.UserId != null ? eventRecord.UserId.ToString() : "N/A",
                                    Message = message,
                                    CorrelationTag = AnalyzeEvent(eventRecord)
                                };
                                entries.Add(entry);
                                eventCount++;
                                
                                if (eventCount % 1000 == 0 && logBuffer != null)
                                    WriteLog(logBuffer, logFile, string.Format("{0}: {1} events processed", logName, eventCount));
                            }
                            catch (Exception ex)
                            {
                                errorCount++;
                                if (errorCount <= 5 && logBuffer != null && !(ex is System.IO.FileNotFoundException))
                                    WriteLog(logBuffer, logFile, string.Format("{0}: Event error: {1}", logName, ex.Message));
                            }
                            finally
                            {
                                eventRecord.Dispose();
                            }
                        }
                        
                        if (logBuffer != null)
                            WriteLog(logBuffer, logFile, string.Format("{0}: Finished reading (null returned)", logName));
                    }
                }
                var dur = (DateTime.Now - logStart).TotalSeconds;
                accessResults[logName] = string.Format("Success - {0} events in {1:F1}s (Errors: {2})", eventCount, dur, errorCount);
                if (logBuffer != null)
                    WriteLog(logBuffer, logFile, string.Format("{0}: {1}", logName, accessResults[logName]));
            }
            catch (Exception ex)
            {
                accessResults[logName] = string.Format("Error - {0}", ex.Message);
                if (logBuffer != null)
                    WriteLog(logBuffer, logFile, string.Format("{0}: EXCEPTION - {1}: {2}", logName, ex.GetType().Name, ex.Message));
            }
        }

        var totalDur = (DateTime.Now - start).TotalSeconds;
        if (logBuffer != null)
            WriteLog(logBuffer, logFile, string.Format("ParseEventLogs completed in {0:F1}s, {1} total entries", totalDur, entries.Count));

        return new Dictionary<string, object>
        {
            { "Entries", entries.OrderBy(e => e.TimeCreated).ToList() },
            { "AccessResults", accessResults }
        };
    }

    private static string AnalyzeEvent(EventRecord eventRecord)
    {
        var tags = new List<string>();
        int eventId = eventRecord.Id;
        string provider = eventRecord.ProviderName ?? "";
        string level = eventRecord.LevelDisplayName ?? "";

        if (provider.Contains("Microsoft-Windows-Security-Auditing") || eventRecord.LogName == "Security")
        {
            if (eventId == 4625) tags.Add("FailedLogon");
            if (eventId == 4624) tags.Add("SuccessfulLogon");
            if (eventId == 4740) tags.Add("AccountLockout");
            if (eventId == 4672) tags.Add("PrivilegeEscalation");
            if (eventId == 4688) tags.Add("ProcessCreation");
            if (eventId == 4697) tags.Add("ServiceInstallation");
            if (eventId == 4698 || eventId == 4702) tags.Add("ScheduledTask");
            if (eventId == 4624)
            {
                try
                {
                    var xml = eventRecord.ToXml();
                    if (xml.Contains("LogonType") && xml.Contains("LogonType>3</"))
                        tags.Add("NetworkLogon");
                }
                catch { }
            }
        }

        if (eventRecord.LogName == "System")
        {
            if (eventId == 7045) tags.Add("ServiceModified");
            if (eventId == 219) tags.Add("DriverLoad");
            if (eventId == 1074 || eventId == 1076) tags.Add("SystemShutdown");
        }

        if (eventRecord.LogName == "Application")
        {
            if (level.Contains("Error") || level.Contains("Critical"))
                tags.Add("ApplicationError");
        }

        if (eventId >= 1100 && eventId <= 1102)
            tags.Add("EventLogManipulation");

        return tags.Count > 0 ? string.Join(";", tags) : "Normal";
    }

    private static string SanitizeMessage(string message)
    {
        if (string.IsNullOrEmpty(message)) return "";
        var sb = new StringBuilder(message.Length);
        foreach (char c in message)
        {
            if (c == '\r' || c == '\n' || c == '\t') sb.Append(' ');
            else if (char.IsControl(c) && c != '\r' && c != '\n' && c != '\t') continue;
            else if (c >= 0x200B && c <= 0x200D) continue;
            else if (c == 0xFEFF) continue;
            else if (c >= 0x200E && c <= 0x200F) continue;
            else if (c >= 0x202A && c <= 0x202E) continue;
            else sb.Append(c);
        }
        string result = sb.ToString();
        result = Regex.Replace(result, @"\s+", " ");
        return result.Trim();
    }

    public static string ExportToCsv(List<EventLogEntry> entries, string outputPath = null, StringBuilder logBuffer = null, string logFile = null)
    {
        var start = DateTime.Now;
        if (logBuffer != null)
            WriteLog(logBuffer, logFile, string.Format("ExportToCsv started - {0} entries", entries.Count));
        
        var csv = new StringBuilder();
        csv.AppendLine("LogName,TimeCreated,EventId,Level,ProviderName,MachineName,UserId,CorrelationTag,Message");

        int rowCount = 0;
        foreach (var entry in entries)
        {
            try
            {
                var message = SanitizeMessage(entry.Message ?? "");
                message = message.Replace("\"", "\"\"");
                csv.AppendFormat("\"{0}\",\"{1}\",\"{2}\",\"{3}\",\"{4}\",\"{5}\",\"{6}\",\"{7}\",\"{8}\"",
                    entry.LogName ?? "", entry.TimeCreated.ToString("yyyy-MM-ddTHH:mm:ss.fff"), entry.EventId,
                    entry.Level ?? "", entry.ProviderName ?? "", entry.MachineName ?? "",
                    entry.UserId ?? "", entry.CorrelationTag ?? "", message);
                csv.AppendLine();
                rowCount++;
                
                if (rowCount % 10000 == 0 && logBuffer != null)
                    WriteLog(logBuffer, logFile, string.Format("CSV: {0} rows written", rowCount));
            }
            catch (Exception ex)
            {
                if (logBuffer != null && rowCount < 10)
                    WriteLog(logBuffer, logFile, string.Format("CSV row error: {0}", ex.Message));
            }
        }

        if (logBuffer != null)
            WriteLog(logBuffer, logFile, string.Format("CSV: All {0} rows formatted, writing file...", rowCount));

        if (!string.IsNullOrEmpty(outputPath))
        {
            try
            {
                File.WriteAllText(outputPath, csv.ToString(), new System.Text.UTF8Encoding(false));
                var dur = (DateTime.Now - start).TotalSeconds;
                var result = string.Format("CSV exported: {0} rows in {1:F2}s", rowCount, dur);
                if (logBuffer != null)
                    WriteLog(logBuffer, logFile, result);
                return string.Format("CSV exported to: {0}", outputPath);
            }
            catch (Exception ex)
            {
                if (logBuffer != null)
                    WriteLog(logBuffer, logFile, string.Format("CSV write FAILED: {0}", ex.Message));
                throw;
            }
        }
        return csv.ToString();
    }
}
"@

Add-Type -TypeDefinition $csharpCode -Language CSharp

# ===============================================================
# CONFIGURATION - Modify the value below to change the time range
# ===============================================================
$Days = 1  # Number of days to look back (e.g., 1 = last 24 hours, 7 = last week, 30 = last month, 0 = all events)

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$logFile = "C:\windows\temp\EventLogAnalysis_${timestamp}.log"
$outputFile = "C:\windows\temp\EventLogAnalysis_${timestamp}.csv"
$logBuffer = New-Object System.Text.StringBuilder

Write-Host "[*] Starting Event Log Analysis..." -ForegroundColor Cyan
Write-Host "[*] Log file: $logFile" -ForegroundColor Cyan
Write-Host "[*] Time range: Last $Days days" -ForegroundColor Cyan

$logNames = @("Security", "System", "Application")
$startTime = (Get-Date).AddDays(-$Days)
$endTime = Get-Date

[void]$logBuffer.AppendLine("=== Event Log Analysis Started ===")
[void]$logBuffer.AppendLine("Time Range: $($startTime.ToString('yyyy-MM-dd HH:mm:ss')) to $($endTime.ToString('yyyy-MM-dd HH:mm:ss'))")
[System.IO.File]::WriteAllText($logFile, $logBuffer.ToString(), [System.Text.UTF8Encoding]::new($false))

Write-Host "[*] Parsing event logs..." -ForegroundColor Yellow
try {
    $result = [EventLogAnalyzer]::ParseEventLogs($logNames, $startTime, $endTime, $logBuffer, $logFile)
    [EventLogAnalyzer]::WriteLog($logBuffer, $logFile, "ParseEventLogs returned successfully")
    $entries = $result["Entries"]
    $accessResults = $result["AccessResults"]
    [EventLogAnalyzer]::WriteLog($logBuffer, $logFile, "Extracted $($entries.Count) entries from result")
}
catch {
    [EventLogAnalyzer]::WriteLog($logBuffer, $logFile, "ParseEventLogs ERROR: $($_.Exception.Message)")
    throw
}

Write-Host "`n[*] Log Access Results:" -ForegroundColor Cyan
foreach ($log in $logNames) {
    $status = $accessResults[$log]
    if ($status -match "Success") {
        Write-Host "  [+] $log : $status" -ForegroundColor Green
    } else {
        Write-Host "  [!] $log : $status" -ForegroundColor Yellow
    }
}

Write-Host "`n[+] Found $($entries.Count) total events" -ForegroundColor Green

$correlationSummary = $entries | Where-Object { $_.CorrelationTag -ne "Normal" } | 
    Group-Object CorrelationTag | 
    Select-Object Name, Count | 
    Sort-Object Count -Descending

if ($correlationSummary) {
    Write-Host "`n[*] Correlation Summary:" -ForegroundColor Cyan
    $correlationSummary | Format-Table -AutoSize
}

[EventLogAnalyzer]::WriteLog($logBuffer, $logFile, "Starting CSV export...")
Write-Host "`n[*] Exporting to CSV..." -ForegroundColor Yellow

try {
    $exportResult = [EventLogAnalyzer]::ExportToCsv($entries, $outputFile, $logBuffer, $logFile)
    [EventLogAnalyzer]::WriteLog($logBuffer, $logFile, "CSV export completed successfully")
    Write-Host "[+] $exportResult" -ForegroundColor Green
    Write-Host "[+] CSV file location: $outputFile" -ForegroundColor Green
}
catch {
    [EventLogAnalyzer]::WriteLog($logBuffer, $logFile, "CSV export ERROR: $($_.Exception.Message)")
    Write-Host "[!] CSV export failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "[+] Log file location: $logFile" -ForegroundColor Green

[EventLogAnalyzer]::WriteLog($logBuffer, $logFile, "=== Analysis Complete ===")
[System.IO.File]::WriteAllText($logFile, $logBuffer.ToString(), [System.Text.UTF8Encoding]::new($false))

return @{
    Success = $true
    TotalEvents = $entries.Count
    OutputFile = $outputFile
    LogFile = $logFile
    CorrelationSummary = $correlationSummary
    AccessResults = $accessResults
}

# ==================================================================
# CONFIGURATION – Update the value below to modify the time range. 
# To change the overall scope, scroll up in the script. By default,
# the time range is set to 1 day.
# $Days = 1
# ==================================================================
# log file location: C:\windows\temp\EventLogAnalysis_(date).log
# csv file location: C:\windows\temp\EventLogAnalysis_(date).csv
