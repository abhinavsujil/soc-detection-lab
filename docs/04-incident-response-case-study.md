# Part 4: Incident Response Case Study (NIST SP 800-61)

**Incident Reference:** INC-2026-1025-01  
**Severity:** HIGH / P1  
**Lead Investigator:** SOC Tier 1 / Incident Response Analyst  
**Impacted Assets:** `WIN-CORP-01` (`192.168.56.10`)  
**Threat Actor Profile:** Simulated Credential Theft & Persistence Campaign  

---

## 1. Executive Summary

On October 25, 2026 at 14:22 UTC, the Security Operations Center (SOC) detected high-severity alerts indicating an unauthorized credential dumping attempt and subsequent defense tampering on endpoint `WIN-CORP-01`.

Telemetry correlated from Microsoft Sysmon and Windows Event logs confirmed an adversary executed an obfuscated PowerShell script to tamper with Windows Defender settings before abusing a native Living-off-the-Land binary (`rundll32.exe`) to extract LSASS process memory.

The SOC successfully initiated host network containment at 14:38 UTC (16-minute Mean Time to Contain - MTTC). No corporate data was exfiltrated beyond the isolated boundary, and active accounts on the impacted endpoint were revoked and rotated.

---

## 2. Incident Timeline

| Timestamp (UTC) | Event Description | Telemetry Artifact | MITRE Technique |
|---|---|---|---|
| **14:18:05** | Ingress execution: PowerShell invoked with Base64 payload | Sysmon Event ID 1 (`powershell.exe -Enc ...`) | T1059.001 |
| **14:19:12** | Defense Evasion: Windows Defender Real-Time Protection disabled | Sysmon Event ID 13 (`HKLM\...DisableRealtimeMonitoring = 1`) | T1562.001 |
| **14:22:40** | **ALERT FIRED:** Custom Rule 100101 triggered by memory access to LSASS | Sysmon Event ID 10 (`rundll32.exe -> lsass.exe`) | T1003.001 |
| **14:23:15** | Persistence established via Scheduled Task creation | Sysmon Event ID 1 (`schtasks.exe /create ...`) | T1053.005 |
| **14:26:00** | SOC Analyst accepted alert ticket in queue; initiated triage | ServiceNow Ticket #SEC-8921 | N/A |
| **14:38:00** | Endpoint isolated from network via Wazuh Active Response | Network adapter disabled | Containment |
| **15:10:00** | Forensic artifacts collected; malicious task purged | Volatility dump & memory triage | Eradication |

---

## 3. Indicators of Compromise (IoCs)

### File & Hash Artifacts
| Artifact Type | File Path | SHA256 Hash | Verdict |
|---|---|---|---|
| Process Dump | `C:\Windows\Temp\lsass_dump.dmp` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | Malicious Memory Dump |
| Script File | `C:\Users\Public\payload.ps1` | `5f4dcc3b5aa765d61d8327deb882cf992b95990a9151374ced8b53d601284eb1` | Stager / Cradle |

### Network Indicators
| Indicator | Type | ASN / Context | Status |
|---|---|---|---|
| `192.168.56.20` | IPv4 | Internal Attack Subnet (Simulated C2) | Blocked at perimeter firewall |

---

## 4. NIST SP 800-61 Incident Handling Phases

### Phase 1: Identification & Scoping
* **Trigger:** Alert ID `100101` received on Wazuh Dashboard.
* **Process Tree Analysis:**
  ```text
  explorer.exe (PID 4112)
    └── cmd.exe (PID 5840)
         └── powershell.exe (PID 6012) [-NoP -W Hidden -Enc ...]
              ├── reg.exe (PID 6108) [Disabling Defender]
              └── rundll32.exe (PID 6224) [Calling comsvcs.dll MiniDump on LSASS]
  ```
* **Scope:** Validated only `WIN-CORP-01` was accessed; neighboring subnet scans showed zero lateral movement.

### Phase 2: Containment (Egress & Lateral Isolation)
1. **Host Isolation:** Issued Wazuh active response command to disconnect host interface.
2. **Account Lockdown:** Locked local administrator and impacted user Active Directory accounts.

### Phase 3: Eradication
1. Removed malicious scheduled task:
   ```cmd
   schtasks.exe /delete /tn "EnterpriseSecurityUpdate" /f
   ```
2. Securely deleted dumped credential file (`lsass_dump.dmp`) and temporary script cradle.
3. Re-enabled Windows Defender and updated Antivirus signatures:
   ```powershell
   Set-MpPreference -DisableRealtimeMonitoring $false
   Update-MpSignature
   ```

### Phase 4: Recovery
1. Re-joined `WIN-CORP-01` to network in a monitored quarantine VLAN for 24 hours.
2. Reset credentials for all users logged into the host during the incident window.
3. Verified Sysmon telemetry returned to standard baseline volume.

### Phase 5: Lessons Learned & Strategic Recommendations
1. **Implement Attack Surface Reduction (ASR) Rules:** Deploy Microsoft ASR rule `Block credential stealing from the Windows local security authority subsystem (lsass.exe)` (GUID: `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2`).
2. **PowerShell Constrained Language Mode:** Enforce Constrained Language Mode via AppLocker/WDAC to prevent arbitrary API and COM object calls.
3. **Privilege Restructuring:** Remove standard workstation users from the local Administrators group.
