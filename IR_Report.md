# Incident Response Report
**Incident ID:** IR-2026-001  
**Date:** 26 June 2026  
**Analyst:** Mukul Kumar  
**Severity:** High  
**Status:** Contained  

---

## 1. Executive Summary

On 26 June 2026, a simulated phishing attack was conducted in a controlled 
lab environment. The victim machine (Windows 10, 192.168.149.128) executed 
a malicious payload named `invoice (1).exe`, which established a Meterpreter 
reverse shell connection to the attacker machine (Kali Linux, 192.168.149.129) 
on port 4444. The attack was detected via Sysmon logs and Wireshark capture. 
The malicious process was terminated, the payload deleted, and the victim 
machine isolated from the network within the same session.

---

## 2. Attack Timeline

| Time (IST) | Event |
|---|---|
| 11:52:30 | `invoice (1).exe` executed by user mucool via explorer.exe |
| 11:52:32 | Outbound TCP connection established to 192.168.149.129:4444 |
| 11:52:32 | Meterpreter session active on Kali Linux |
| 12:19:35 | Analyst detected C2 traffic in Wireshark (port 4444) |
| 12:19:35 | Sysmon Event ID 1 and 3 confirmed execution and C2 |
| 12:21:00 | Process 6212 terminated via taskkill |
| 12:21:00 | Payload file deleted, Test-Path returned False |
| 12:21:23 | VMware NIC disconnected — network isolation complete |

---

## 3. Affected Systems

| Hostname | IP | Role | Status |
|---|---|---|---|
| DESKTOP-0Q0BDCB | 192.168.149.128 | Victim (Windows 10) | Contained |
| Kali Linux | 192.168.149.129 | Attacker / C2 | Simulated |

---

## 4. IOC Table

| Type | Value | Context |
|---|---|---|
| IP | 192.168.149.129 | Kali C2 server |
| File | invoice (1).exe | Meterpreter payload |
| Path | C:\Users\cyber\Downloads\invoice (1).exe | Execution path |
| Port | 4444 | Reverse shell port |
| MD5 | 90F4CEDCFCEAFF8DED55FCA5313A1A43 | Payload hash |
| SHA256 | 181E1ADCE252CA605CA78E1F70FBDF744278B672657BE5DCA74F22294A29E48D | Payload hash |
| PID | 6212 | Malicious process ID |
| User | DESKTOP-0Q0BDCB\mucool | Compromised account |

---

## 5. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Evidence |
|---|---|---|---|
| Initial Access | T1566.001 | Spearphishing Attachment | invoice.exe via HTTP |
| Execution | T1204.002 | User Execution | Launched via explorer.exe |
| Command & Control | T1071.001 | Application Layer Protocol | TCP C2 traffic |
| Command & Control | T1571 | Non-Standard Port | Port 4444 used |
| Defense Evasion | T1027 | Obfuscated Files | No file metadata present |

---

## 6. Containment Actions

1. Malicious process (PID 6212) terminated using `taskkill /PID 6212 /F`
2. Payload file deleted using `Remove-Item` — confirmed via `Test-Path` (False)
3. Victim VM network adapter disconnected in VMware settings
4. Meterpreter session dropped on Kali side as a result

---

## 7. Recommendations

| # | Recommendation | Priority |
|---|---|---|
| 1 | Block outbound connections on non-standard ports (4444) at firewall | High |
| 2 | Enable Windows Defender real-time protection | High |
| 3 | Alert on Sysmon Event ID 3 with DestinationPort 4444 | High |
| 4 | User awareness training on phishing emails with attachments | Medium |
| 5 | Implement application whitelisting — block unsigned executables | Medium |

---

## 8. Detection Rule (Sysmon)

Alert trigger: Any process making outbound TCP connection to port 4444.

```xml
<RuleGroup name="C2 Detection" groupRelation="or">
  <NetworkConnect onmatch="include">
    <DestinationPort condition="is">4444</DestinationPort>
  </NetworkConnect>
</RuleGroup>
```

---

## 9. Lessons Learned

- Sysmon with SwiftOnSecurity config captured full attack chain 
  (process create + network connect) within 2 seconds
- Port 4444 is a well-known Metasploit default — easy to detect 
  with basic firewall rules
- VirusTotal did not detect the payload as it was locally generated 
  — signature-based detection alone is insufficient
- Behavior-based detection (Sysmon Event ID 3 + unusual parent process) 
  is more reliable than hash matching for custom payloads

---

*Report prepared as part of SOC Analyst portfolio project.*  
*GitHub: github.com/mukulkumar-labs*
