# Enterprise SOC Detection Lab & Threat Emulation Project

[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v14-orange.svg)](https://attack.mitre.org/)
[![SIEM: Wazuh](https://img.shields.io/badge/SIEM-Wazuh%204.x-blue.svg)](https://wazuh.com/)
[![Telemetry: Sysmon](https://img.shields.io/badge/Telemetry-Sysmon%20v15-success.svg)](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
[![Language: Python 3.x](https://img.shields.io/badge/Language-Python%203-brightgreen.svg)](https://www.python.org/)

An enterprise-grade Security Operations Center (SOC) home lab demonstrating **end-to-end detection engineering, adversary emulation, log telemetry ingestion, and incident response triage**.

Designed and authored as practical proof of work for corporate Security Analyst / SOC Tier 1 & Tier 2 roles.

---

## 🎯 Project Objectives

1. **Telemetry Pipeline Architecture:** Deploy a centralized SIEM infrastructure ingesting normalized telemetry from Windows (Sysmon + Security Event Logs) and Linux (`auditd` + auth logs).
2. **Adversary Emulation:** Execute realistic attacker techniques mapped directly to the **MITRE ATT&CK Framework** using Atomic Red Team and offensive CLI tooling.
3. **Detection Engineering:** Author custom Wazuh XML detection rules and alert decoders to detect post-exploitation activity with zero default vendor signature coverage.
4. **Security Automation:** Build a standalone Python-based Threat Intelligence and IoC triage tool that queries VirusTotal and AbuseIPDB APIs to automate analyst triage.
5. **Incident Response & Reporting:** Document an enterprise-standard Incident Response Case Study following the **NIST SP 800-61** lifecycle.

---

## 🏗️ Lab Architecture & Topology

```mermaid
flowchart TD
    subgraph Emulation_Zone["Adversary / Emulation Engine"]
        Attacker["Kali Linux / Atomic Red Team<br/>IP: 192.168.56.20"]
    end

    subgraph Monitored_Endpoints["Corporate Endpoint Zone (Telemetry Sources)"]
        Win10["Windows 10 / 11 Enterprise<br/>IP: 192.168.56.10<br/>• Sysmon (SwiftOnSecurity config)<br/>• Wazuh Agent v4.x<br/>• Atomic Red Team Executor"]
        LinuxSrv["Ubuntu Server 22.04 LTS<br/>IP: 192.168.56.15<br/>• Wazuh Agent v4.x<br/>• Auditd & Syslog"]
    end

    subgraph SOC_Core["Central Security Operations Hub"]
        WazuhMgr["Wazuh Manager & Indexer<br/>IP: 192.168.56.5<br/>• Real-time Rule Engine<br/>• Decoder & Vulnerability Detector"]
        WazuhUI["Wazuh Dashboard (Kibana/OpenSearch Fork)<br/>Port: 443 (HTTPS)<br/>• Custom MITRE Dashboards<br/>• Real-time Alert Triage View"]
    end

    subgraph Automation_Tools["Analyst Automation & Threat Intel"]
        PythonTriage["ioc_threat_intel_triage.py<br/>Automated Hash / IP / Domain Enrichment<br/>• VirusTotal API<br/>• AbuseIPDB API"]
    end

    Attacker -->|Simulated Attacks: T1003, T1059, T1053, T1110| Win10
    Attacker -->|SSH Brute Force & Exploitation| LinuxSrv
    Win10 -->|Encrypted Agent Channel (Port 1514/TCP)| WazuhMgr
    LinuxSrv -->|Encrypted Agent Channel (Port 1514/TCP)| WazuhMgr
    WazuhMgr -->|Indexed JSON Telemetry| WazuhUI
    WazuhUI -.->|Alert IoCs Exported for Analysis| PythonTriage
```

---

## 🔬 Adversary Techniques Emulated & Detected

| MITRE ATT&CK ID | Technique Name | Emulated Action | Telemetry Source | Detection Severity |
|---|---|---|---|---|
| **T1003.001** | OS Credential Dumping: LSASS Memory | `procdump.exe` / `rundll32.exe comsvcs.dll` targeting `lsass.exe` | Sysmon Event ID 10 (ProcessAccess) | **High (Level 12)** |
| **T1059.001** | Command & Scripting: PowerShell Obfuscation | Encoded command execution (`-EncodedCommand`) & Web Client download cradle | Sysmon Event ID 1 (Process Create) + Script Block 4104 | **High (Level 10)** |
| **T1053.005** | Scheduled Task Creation | Command-line task persistence (`schtasks.exe /create /tn Backdoor`) | Sysmon Event ID 1 & Windows Security Event 4698 | **Medium (Level 8)** |
| **T1562.001** | Impair Defenses: Disable Windows Defender | Registry modification disabling Real-Time Monitoring (`Set-MpPreference`) | Sysmon Event ID 13 (RegistryValue) | **Critical (Level 14)** |
| **T1110.001** | Brute Force: Password Guessing | Automated hydra/scripted SSH and RDP brute force attempts | Linux `/var/log/auth.log` (Event 5551) & Win Event 4625 | **Medium (Level 7)** |

---

## 📂 Repository Contents & Navigation

* [`MASTER_LAB_MEMORY.md`](MASTER_LAB_MEMORY.md): **Master Operations Log & Memory** — complete chronological record of all lab environments (SOC SIEM, Kali weaponization, microservices, and ESP32-S3 hardware multi-tool).
* [`docs/01-architecture-and-setup.md`](docs/01-architecture-and-setup.md): Complete deployment walkthrough for VirtualBox/VMware/Cloud, installing Wazuh Server and configuring Windows/Linux agents.
* [`docs/02-adversary-emulation-and-attacks.md`](docs/02-adversary-emulation-and-attacks.md): Exact attack commands, PowerShell payloads, and Atomic Red Team procedures executed.
* [`docs/03-detection-engineering-rules.md`](docs/03-detection-engineering-rules.md): Custom Wazuh detection XML rules and Sysmon configurations with tuning logic.
* [`docs/04-incident-response-case-study.md`](docs/04-incident-response-case-study.md): A full enterprise incident response report (Executive Summary + Technical Analysis + PICERL containment) for a simulated credential access breach.
* [`scripts/ioc_threat_intel_triage.py`](scripts/ioc_threat_intel_triage.py): Production-grade Python automation script for automated IoC verification via VirusTotal and AbuseIPDB APIs.
* [`config/custom_wazuh_rules.xml`](config/custom_wazuh_rules.xml): Ready-to-deploy custom Wazuh ruleset file.
* [`config/sysmonconfig-export.xml`](config/sysmonconfig-export.xml): High-fidelity Sysmon schema configured to log process tampering, memory injection, and network connections.

---

## 🛠️ Tools & Technologies Used

* **SIEM / XDR:** Wazuh Manager, OpenSearch/Wazuh Indexer, Wazuh Dashboard
* **Endpoint Telemetry:** Microsoft Sysmon v15, Windows Event Viewer, Linux `auditd`, `rsyslog`
* **Emulation & Testing:** Atomic Red Team (Invoke-AtomicRedTeam), Kali Linux, Mimikatz (lab environment only)
* **Automation & Scripting:** Python 3.10+, PowerShell 5.1/7+, Bash
* **Threat Intelligence Feeds:** VirusTotal Public API v3, AbuseIPDB API v2, AlienVault OTX
* **Frameworks & Methodologies:** MITRE ATT&CK Framework, NIST SP 800-61 Rev. 2, Cyber Kill Chain
