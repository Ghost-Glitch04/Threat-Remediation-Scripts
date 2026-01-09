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
        public string ThreatLevel { get; set; }
        public string SigmaRuleMatch { get; set; }
        public string MitreAttack { get; set; }
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

    private static Dictionary<string, string> CreateRule(string title, string mitre, string level)
    {
        return new Dictionary<string, string> { { "RuleTitle", title }, { "MitreAttack", mitre }, { "ThreatLevel", level } };
    }

    public static Dictionary<string, object> ParseEventLogs(string[] logNames, DateTime? startTime = null, DateTime? endTime = null, StringBuilder logBuffer = null, string logFile = null)
    {
        var entries = new List<EventLogEntry>();
        var accessResults = new Dictionary<string, string>();
        var start = DateTime.Now;
        
        foreach (var logName in logNames)
        {
            int eventCount = 0;
            int errorCount = 0;
            var logStart = DateTime.Now;
            
            try
            {
                using (var session = new EventLogSession())
                {
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
                    }
                    else
                    {
                        reader = new EventLogReader(logName, PathType.LogName);
                    }
                    
                    using (reader)
                    {
                        EventRecord eventRecord;
                        
                        while ((eventRecord = reader.ReadEvent()) != null)
                        {
                            
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
                                
                                var analysis = AnalyzeEvent(eventRecord, message);
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
                                    CorrelationTag = analysis["Tags"],
                                    ThreatLevel = analysis["ThreatLevel"],
                                    SigmaRuleMatch = analysis["SigmaRule"],
                                    MitreAttack = analysis["MitreAttack"]
                                };
                                entries.Add(entry);
                                eventCount++;
                            }
                            catch
                            {
                                errorCount++;
                            }
                            finally
                            {
                                eventRecord.Dispose();
                            }
                        }
                    }
                }
                var dur = (DateTime.Now - logStart).TotalSeconds;
                accessResults[logName] = string.Format("Success - {0} events in {1:F1}s (Errors: {2})", eventCount, dur, errorCount);
            }
            catch (Exception ex)
            {
                accessResults[logName] = string.Format("Error - {0}", ex.Message);
            }
        }

        return new Dictionary<string, object>
        {
            { "Entries", entries.OrderBy(e => e.TimeCreated).ToList() },
            { "AccessResults", accessResults }
        };
    }

    private static Dictionary<string, string> AnalyzeEvent(EventRecord eventRecord, string message)
    {
        var tags = new List<string>();
        var sigmaRules = new List<string>();
        var mitreTags = new List<string>();
        string threatLevel = "Normal";
        int eventId = eventRecord.Id;
        string provider = eventRecord.ProviderName ?? "";
        string level = eventRecord.LevelDisplayName ?? "";
        string eventXml = "";
        
        try { eventXml = eventRecord.ToXml(); } catch { }

        if (provider.Contains("Microsoft-Windows-Security-Auditing") || eventRecord.LogName == "Security")
        {
            if (eventId == 4625) { tags.Add("FailedLogon"); threatLevel = "Suspicious"; }
            if (eventId == 4624) tags.Add("SuccessfulLogon");
            if (eventId == 4740) { tags.Add("AccountLockout"); threatLevel = "Suspicious"; }
            if (eventId == 4672) { tags.Add("PrivilegeEscalation"); threatLevel = "Suspicious"; }
            if (eventId == 4688) tags.Add("ProcessCreation");
            if (eventId == 4697) { tags.Add("ServiceInstallation"); threatLevel = "Suspicious"; }
            if (eventId == 4698 || eventId == 4702) { tags.Add("ScheduledTask"); threatLevel = "Suspicious"; }
            if (eventId == 4648) { tags.Add("ExplicitCredentialUse"); threatLevel = "Suspicious"; }
            if (eventId == 4673) { tags.Add("SensitivePrivilegeUse"); threatLevel = "Suspicious"; }
            if (eventId == 4703) { tags.Add("TokenRightAdjusted"); threatLevel = "Suspicious"; }
            if (eventId == 4719) { tags.Add("SystemAuditPolicyChanged"); threatLevel = "Malicious"; }
            if (eventId == 4720) { tags.Add("UserAccountCreated"); threatLevel = "Suspicious"; }
            if (eventId == 4724) { tags.Add("PasswordResetAttempt"); threatLevel = "Suspicious"; }
            if (eventId == 4728) { tags.Add("SecurityGroupMemberAdded"); threatLevel = "Suspicious"; }
            if (eventId == 4732) { tags.Add("SecurityGroupMemberRemoved"); threatLevel = "Suspicious"; }
            if (eventId == 4738) { tags.Add("UserAccountChanged"); threatLevel = "Suspicious"; }
            if (eventId == 4741) { tags.Add("ComputerAccountCreated"); threatLevel = "Suspicious"; }
            if (eventId == 4742) { tags.Add("ComputerAccountChanged"); threatLevel = "Suspicious"; }
            if (eventId == 4756) { tags.Add("SecurityGroupCreated"); threatLevel = "Suspicious"; }
            if (eventId == 4757) { tags.Add("SecurityGroupChanged"); threatLevel = "Suspicious"; }
            if (eventId == 4767) { tags.Add("UserAccountUnlocked"); threatLevel = "Suspicious"; }
            if (eventId == 4768) { tags.Add("KerberosAuthTicketRequested"); threatLevel = "Suspicious"; }
            if (eventId == 4769) { tags.Add("KerberosServiceTicketRequested"); threatLevel = "Suspicious"; }
            if (eventId == 4776) { tags.Add("CredentialValidation"); threatLevel = "Suspicious"; }
            if (eventId == 4798) { tags.Add("UserAccountEnumeration"); threatLevel = "Suspicious"; }
            if (eventId == 5140) { tags.Add("NetworkShareAccessed"); threatLevel = "Suspicious"; }
            if (eventId == 5142) { tags.Add("NetworkShareAdded"); threatLevel = "Suspicious"; }
            if (eventId == 5143) { tags.Add("NetworkShareModified"); threatLevel = "Suspicious"; }
            if (eventId == 5144) { tags.Add("NetworkShareRemoved"); threatLevel = "Suspicious"; }
            if (eventId == 5145) { tags.Add("NetworkShareObjectChecked"); threatLevel = "Suspicious"; }
            if (eventId == 5156) { tags.Add("WindowsFilteringPlatformConnectionAllowed"); }
            if (eventId == 5157) { tags.Add("WindowsFilteringPlatformConnectionBlocked"); threatLevel = "Suspicious"; }
            if (eventId == 5158) { tags.Add("WindowsFilteringPlatformConnectionPermitted"); }
            if (eventId == 4624)
            {
                try
                {
                    var xml = eventRecord.ToXml();
                    if (xml.Contains("LogonType") && xml.Contains("LogonType>3</"))
                    {
                        tags.Add("NetworkLogon");
                        if (threatLevel == "Normal") threatLevel = "Suspicious";
                    }
                }
                catch { }
            }
        }

        if (eventRecord.LogName == "System")
        {
            if (eventId == 7045) { tags.Add("ServiceModified"); threatLevel = "Suspicious"; }
            if (eventId == 219) { tags.Add("DriverLoad"); threatLevel = "Suspicious"; }
            if (eventId == 1074 || eventId == 1076) tags.Add("SystemShutdown");
            if (eventId == 6008) { tags.Add("UnexpectedShutdown"); threatLevel = "Suspicious"; }
            if (eventId == 7034) { tags.Add("ServiceCrashed"); threatLevel = "Suspicious"; }
            if (eventId == 7035) { tags.Add("ServiceStarted"); }
            if (eventId == 7036) { tags.Add("ServiceStateChanged"); }
        }

        if (eventRecord.LogName == "Application")
        {
            if (level.Contains("Error") || level.Contains("Critical"))
                tags.Add("ApplicationError");
        }

        if (eventId >= 1100 && eventId <= 1102)
        {
            tags.Add("EventLogManipulation");
            threatLevel = "Malicious";
        }

        var sigmaMatch = MatchSigmaRules(eventRecord, message, eventXml);
        if (sigmaMatch != null)
        {
            sigmaRules.Add(sigmaMatch["RuleTitle"]);
            if (sigmaMatch.ContainsKey("MitreAttack"))
            {
                mitreTags.Add(sigmaMatch["MitreAttack"]);
            }
            if (sigmaMatch.ContainsKey("ThreatLevel"))
            {
                string sigmaThreat = sigmaMatch["ThreatLevel"];
                if (sigmaThreat == "Malicious" || (sigmaThreat == "Suspicious" && threatLevel == "Normal"))
                {
                    threatLevel = sigmaThreat;
                }
            }
        }

        return new Dictionary<string, string>
        {
            { "Tags", tags.Count > 0 ? string.Join(";", tags) : "Normal" },
            { "ThreatLevel", threatLevel },
            { "SigmaRule", sigmaRules.Count > 0 ? string.Join(";", sigmaRules) : "" },
            { "MitreAttack", mitreTags.Count > 0 ? string.Join(";", mitreTags) : "" }
        };
    }

    private static Dictionary<string, string> MatchSigmaRules(EventRecord eventRecord, string message, string eventXml)
    {
        int eventId = eventRecord.Id;
        string logName = eventRecord.LogName ?? "";
        string provider = eventRecord.ProviderName ?? "";
        string msgLower = (message ?? "").ToLower();
        string xmlLower = (eventXml ?? "").ToLower();

        if (logName == "Security" || provider.Contains("Microsoft-Windows-Security-Auditing"))
        {
            if (eventId == 4688)
            {
                if (xmlLower.Contains("commandline") || msgLower.Contains("command line"))
                {
                    string cmdLine = ExtractXmlValue(eventXml, "CommandLine") ?? "";
                    string processName = ExtractXmlValue(eventXml, "NewProcessName") ?? "";
                    cmdLine = cmdLine.ToLower();
                    processName = processName.ToLower();

                    if (processName.EndsWith("\\net.exe") || cmdLine.Contains("net "))
                    {
                        if (cmdLine.Contains("user") || cmdLine.Contains("group")) return CreateRule("Net User/Group", "T1136", "Suspicious");
                        if (cmdLine.Contains("share") || cmdLine.Contains("use")) return CreateRule("Net Share", "T1135", "Suspicious");
                        return CreateRule("Net.exe Execution", "T1018", "Suspicious");
                    }
                    if (processName.EndsWith("\\whoami.exe") || cmdLine.Contains("whoami")) return CreateRule("Whoami Execution", "T1033", "Suspicious");
                    if (processName.EndsWith("\\systeminfo.exe") || cmdLine.Contains("systeminfo")) return CreateRule("Systeminfo Execution", "T1082", "Suspicious");
                    if (processName.EndsWith("\\tasklist.exe") || cmdLine.Contains("tasklist")) return CreateRule("Tasklist Execution", "T1057", "Suspicious");
                    if (processName.EndsWith("\\nslookup.exe") || cmdLine.Contains("nslookup")) return CreateRule("Nslookup Execution", "T1018", "Suspicious");
                    if (processName.EndsWith("\\ping.exe") && (cmdLine.Contains(" -n ") || cmdLine.Contains(" -t "))) return CreateRule("Ping Sweep", "T1018", "Suspicious");
                    if (processName.EndsWith("\\powershell.exe") || processName.EndsWith("\\pwsh.exe"))
                    {
                        if (cmdLine.Contains("-encodedcommand") || cmdLine.Contains("-enc ") || cmdLine.Contains("-e ")) return CreateRule("PowerShell Encoded", "T1059.001", "Malicious");
                        if (cmdLine.Contains("bypass") || cmdLine.Contains("-nop")) return CreateRule("PowerShell Bypass", "T1059.001", "Suspicious");
                        if (cmdLine.Contains("downloadstring") || cmdLine.Contains("downloadfile")) return CreateRule("PowerShell Download", "T1059.001;T1105", "Malicious");
                    }
                    if (processName.EndsWith("\\cmd.exe") && (cmdLine.Contains("/c") || cmdLine.Contains("/k")))
                    {
                        if (cmdLine.Contains("certutil") && (cmdLine.Contains("-urlcache") || cmdLine.Contains("-decode"))) return CreateRule("Certutil Download", "T1105", "Malicious");
                        if (cmdLine.Contains("bitsadmin") && (cmdLine.Contains("/transfer") || cmdLine.Contains("/download"))) return CreateRule("BITSAdmin Download", "T1105", "Malicious");
                    }
                    if ((processName.EndsWith("\\wmic.exe") || processName.EndsWith("\\wmic")) && (cmdLine.Contains("process call create") || cmdLine.Contains("get process"))) return CreateRule("WMIC Process", "T1047", "Suspicious");
                    if ((processName.EndsWith("\\schtasks.exe") || cmdLine.Contains("schtasks")) && (cmdLine.Contains("/create") || cmdLine.Contains("/run"))) return CreateRule("Scheduled Task", "T1053.005", "Suspicious");
                    if ((processName.EndsWith("\\reg.exe") || cmdLine.Contains("reg ")) && (cmdLine.Contains("add") || cmdLine.Contains("delete"))) return CreateRule("Registry Modification", "T1112", "Suspicious");
                    if ((processName.EndsWith("\\sc.exe") || cmdLine.Contains("sc ")) && (cmdLine.Contains("create") || cmdLine.Contains("start"))) return CreateRule("Service Creation", "T1543.003", "Suspicious");
                }
            }

            if (eventId == 4624)
            {
                string lt = ExtractXmlValue(eventXml, "LogonType") ?? "";
                string un = ExtractXmlValue(eventXml, "TargetUserName") ?? "";
                if (lt == "3" && un.ToLower() != "system" && un.ToLower() != "local service" && un.ToLower() != "network service") return CreateRule("Network Logon", "T1078", "Suspicious");
            }
            if (eventId == 4625)
            {
                string un = ExtractXmlValue(eventXml, "TargetUserName") ?? "";
                if (un.ToLower() == "administrator" || un.ToLower() == "admin") return CreateRule("Failed Admin Logon", "T1078", "Suspicious");
            }
            if (eventId == 4648) return CreateRule("Explicit Credential Use", "T1078", "Suspicious");
            if (eventId == 4672) return CreateRule("Privilege Escalation", "T1078", "Suspicious");
            if (eventId == 4697) return CreateRule("Service Installation", "T1543.003", "Suspicious");
            if (eventId == 4698 || eventId == 4702) return CreateRule("Scheduled Task", "T1053.005", "Suspicious");
            if (eventId == 4719) return CreateRule("Audit Policy Change", "T1562.008", "Malicious");
            if (eventId == 4720) return CreateRule("User Account Created", "T1136", "Suspicious");
            if (eventId == 4728) return CreateRule("Group Member Added", "T1078", "Suspicious");
            if (eventId == 5142) return CreateRule("Network Share Added", "T1135", "Suspicious");
            if (eventId == 5157) return CreateRule("WFP Blocked", "T1562.004", "Suspicious");
        }

        if (logName == "System")
        {
            if (eventId == 7045) return CreateRule("Service Modified", "T1543.003", "Suspicious");
            if (eventId == 219) return CreateRule("Driver Load", "T1547.009", "Suspicious");
        }

        return null;
    }

    private static string ExtractXmlValue(string xml, string tagName)
    {
        if (string.IsNullOrEmpty(xml)) return null;
        try
        {
            int startIdx = xml.IndexOf(string.Format("<{0}>", tagName), StringComparison.OrdinalIgnoreCase);
            if (startIdx < 0) return null;
            startIdx += tagName.Length + 2;
            int endIdx = xml.IndexOf(string.Format("</{0}>", tagName), startIdx, StringComparison.OrdinalIgnoreCase);
            if (endIdx < 0) return null;
            return xml.Substring(startIdx, endIdx - startIdx);
        }
        catch { }
        return null;
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
        var csv = new StringBuilder();
        csv.AppendLine("LogName,TimeCreated,EventId,Level,ProviderName,MachineName,UserId,ThreatLevel,CorrelationTag,SigmaRuleMatch,MitreAttack,Message");
        foreach (var entry in entries)
        {
            try
            {
                var msg = SanitizeMessage(entry.Message ?? "").Replace("\"", "\"\"");
                csv.AppendFormat("\"{0}\",\"{1}\",\"{2}\",\"{3}\",\"{4}\",\"{5}\",\"{6}\",\"{7}\",\"{8}\",\"{9}\",\"{10}\",\"{11}\"\r\n",
                    entry.LogName ?? "", entry.TimeCreated.ToString("yyyy-MM-ddTHH:mm:ss.fff"), entry.EventId,
                    entry.Level ?? "", entry.ProviderName ?? "", entry.MachineName ?? "",
                    entry.UserId ?? "", entry.ThreatLevel ?? "Normal", entry.CorrelationTag ?? "",
                    entry.SigmaRuleMatch ?? "", entry.MitreAttack ?? "", msg);
            }
            catch { }
        }
        if (!string.IsNullOrEmpty(outputPath))
        {
            File.WriteAllText(outputPath, csv.ToString(), new System.Text.UTF8Encoding(false));
            return string.Format("CSV exported to: {0}", outputPath);
        }
        return csv.ToString();
    }
}
"@

Add-Type -TypeDefinition $csharpCode -Language CSharp

$Days = 3

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
    $entries = $result["Entries"]
    $accessResults = $result["AccessResults"]
}
catch {
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

$sigmaSummary = $entries | Where-Object { $_.SigmaRuleMatch -and $_.SigmaRuleMatch -ne "" } | 
    Group-Object SigmaRuleMatch | 
    Select-Object Name, Count | 
    Sort-Object Count -Descending

if ($sigmaSummary) {
    Write-Host "`n[*] Sigma Rule Matches:" -ForegroundColor Cyan
    $sigmaSummary | Format-Table -AutoSize
}

$mitreSummary = $entries | Where-Object { $_.MitreAttack -and $_.MitreAttack -ne "" } | 
    ForEach-Object { $_.MitreAttack -split ';' } | 
    Group-Object | 
    Select-Object Name, Count | 
    Sort-Object Count -Descending

if ($mitreSummary) {
    Write-Host "`n[*] MITRE ATT&CK Techniques Detected:" -ForegroundColor Cyan
    $mitreSummary | Format-Table -AutoSize
}

Write-Host "`n[*] Exporting to CSV..." -ForegroundColor Yellow
try {
    $exportResult = [EventLogAnalyzer]::ExportToCsv($entries, $outputFile, $logBuffer, $logFile)
    Write-Host "[+] $exportResult" -ForegroundColor Green
}
catch {
    Write-Host "[!] CSV export failed: $($_.Exception.Message)" -ForegroundColor Red
}
[System.IO.File]::WriteAllText($logFile, $logBuffer.ToString(), [System.Text.UTF8Encoding]::new($false))

return @{
    Success = $true
    TotalEvents = $entries.Count
    OutputFile = $outputFile
    LogFile = $logFile
    CorrelationSummary = $correlationSummary
    SigmaSummary = $sigmaSummary
    MitreSummary = $mitreSummary
    AccessResults = $accessResults
}

# log file location: C:\windows\temp\EventLogAnalysis_(date).log
# csv file location: C:\windows\temp\EventLogAnalysis_(date).csv
