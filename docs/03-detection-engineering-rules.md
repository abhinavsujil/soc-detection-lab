# Part 3: Detection Engineering & Rule Authoring

Detection engineering is the process of translating raw system telemetry into high-confidence, actionable security alerts while suppressing operational noise and false positives.

This document breaks down the engineering rationale, regex patterns, and validation workflows for the custom rules deployed in this lab.

---

## 1. Rule Architecture & Wazuh Rule Anatomy

Custom rules are added to `/var/ossec/etc/rules/local_rules.xml` on the Wazuh Manager. Wazuh processes rules hierarchically using parent-child dependency trees via `<if_sid>` and `<if_matched_sid>` tags.

### Standard Severity Scale
* **Level 0–3:** Low/Informational (normal operating behavior, successful logons).
* **Level 4–7:** Minor Security Anomaly (isolated login failure, benign script execution).
* **Level 8–11:** High Priority Incident (multiple failed logins, unauthorized persistence creation).
* **Level 12–15:** Critical Threat Action (LSASS memory dumping, defense tampering, active ransomware behavior).

---

## 2. In-Depth Rule Analysis

### Rule 100101: LSASS Memory Access (MITRE T1003.001)

#### Detection Strategy:
* **Telemetry Trigger:** Sysmon Event ID 10 (ProcessAccess).
* **Attacker Behavior:** Dumping `lsass.exe` process memory to harvest credentials requires opening a handle to LSASS with high-privilege access masks (`0x1FFFFF` or `0x1010`).
* **Logic:**
  ```xml
  <field name="win.eventdata.targetImage">.*\\lsass\.exe</field>
  <field name="win.eventdata.sourceImage">.*(rundll32\.exe|procdump.*\.exe|comsvcs\.dll)</field>
  ```
* **False Positive Reduction:** Legitimate administrative tools like antivirus products (`MsMpEng.exe`) or endpoint agents regularly query LSASS. By scoping the `sourceImage` explicitly to known abused Living-off-the-Land Binaries (LOLBins) like `rundll32.exe` invoking `comsvcs.dll` or standalone dumpers like `procdump`, false positives are virtually zero.

---

### Rule 100102: PowerShell Encoded Command Execution (MITRE T1059.001)

#### Detection Strategy:
* **Telemetry Trigger:** Sysmon Event ID 1 (Process Create).
* **Attacker Behavior:** Attackers pass Base64-encoded strings to PowerShell using `-Enc`, `-EncodedCommand`, or single-character shorthand `-e` to obscure payloads from simple string matching.
* **Logic:**
  ```xml
  <field name="win.eventdata.image">.*\\powershell\.exe</field>
  <field name="win.eventdata.commandLine">(?i).*\s(-enc|-encodedcommand|-e)\s+.*</field>
  ```
* **Tuning Note:** Legitimate enterprise management tools (like Microsoft Intune, SCCM, or Chocolatey) occasionally execute encoded PowerShell. If seen in a corporate setting, white-list the specific parent process hash or Intune service directory.

---

### Rule 100104: Windows Defender Tampering (MITRE T1562.001)

#### Detection Strategy:
* **Telemetry Trigger:** Sysmon Event ID 13 (RegistryValue Modification).
* **Attacker Behavior:** Once local administrator access is achieved, adversaries often disable Defender Real-Time Protection via `Set-MpPreference` or direct registry tampering.
* **Logic:**
  ```xml
  <field name="win.eventdata.targetObject">.*Microsoft\\Windows\sDefender\\Real-Time\sProtection\\DisableRealtimeMonitoring</field>
  <field name="win.eventdata.details">^DWORD\s\(0x00000001\)$</field>
  ```
* **Alert Severity:** Level 14 (Critical). In a corporate environment, this warrants immediate host containment.

---

### Rule 100201: State-Correlated SSH Brute Force (MITRE T1110.001)

#### Detection Strategy:
* **Telemetry Trigger:** Linux PAM / SSH authentication failures (`/var/log/auth.log`).
* **Correlation Logic:**
  ```xml
  <rule id="100201" level="10" frequency="6" timeframe="120">
    <if_matched_sid>5503</if_matched_sid>
    <same_source_ip />
  ```
* **Behavior:** A single SSH failure is normal human error. Six failed attempts originating from the **exact same source IP** within 120 seconds constitutes an automated credential brute-force attack.

---

## 3. Testing & Validating Rules with `wazuh-logtest`

Before deploying rules into production, test them against sample log strings using the built-in testing utility on the Wazuh Manager:

```bash
/var/ossec/bin/wazuh-logtest
```
Paste a simulated Sysmon Event JSON/string into the prompt. The utility will output:
1. **Phase 1: Pre-decoding** (timestamp, agent identification).
2. **Phase 2: Decoding** (extracted fields like `win.eventdata.targetImage`).
3. **Phase 3: Rule Evaluation** (shows matched rule ID `100101`, level `12`, and MITRE mapping `T1003.001`).
