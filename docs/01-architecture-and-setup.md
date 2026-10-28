# Part 1: Lab Architecture, Sizing & Deployment Guide

This guide details the exact step-by-step procedure to build the SOC detection lab on a local hypervisor (VirtualBox or VMware Workstation) or within a private cloud VPC (AWS / Azure / Proxmox).

---

## 1. Hardware & System Prerequisites

* **Host Machine:** Windows 10/11, macOS, or Linux with minimum 16 GB RAM (32 GB recommended) and 80 GB free SSD disk space.
* **Hypervisor:** VirtualBox 7.x (free) or VMware Workstation Pro / Player.
* **Virtual Network:** Host-Only Adapter or Internal NAT Network (`192.168.56.0/24`) to isolate attack traffic from your primary home LAN.

### Virtual Machine Sizing Matrix

| Machine Role | OS Specification | vCPUs | RAM | Disk | Network Adapter |
|---|---|---|---|---|---|
| **Wazuh SIEM Manager** | Ubuntu Server 22.04 LTS | 2 | 4 GB | 30 GB | Host-Only (`192.168.56.5`) |
| **Windows Endpoint** | Windows 10 / 11 Enterprise (Eval) | 2 | 4 GB | 40 GB | Host-Only (`192.168.56.10`) |
| **Linux Target** | Ubuntu 22.04 LTS Desktop/Server | 1 | 2 GB | 20 GB | Host-Only (`192.168.56.15`) |
| **Attacker Machine** | Kali Linux 2024.x | 2 | 2 GB | 25 GB | Host-Only (`192.168.56.20`) |

---

## 2. Deploying the Wazuh All-in-One SIEM Server

The Wazuh all-in-one installation bundles the **Wazuh Manager, Indexer, and Dashboard** onto a single Ubuntu host.

### Step 2.1: System Updates & Dependencies
```bash
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install -y curl apt-transport-https lsb-release gnupg2 tar
```

### Step 2.2: Automated All-in-One Wazuh Installer
Execute the official automated Wazuh installation script:
```bash
curl -sO https://packages.wazuh.com/4.8/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.8/config.yml
sudo bash ./wazuh-install.sh -a
```
*Note the administrative password printed at the end of the installation process. Keep this saved securely.*

### Step 2.3: Verify All Services are Running
```bash
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-indexer
sudo systemctl status wazuh-dashboard
```

### Step 2.4: Accessing the Web Dashboard
Open your host browser and navigate to:
```text
https://192.168.56.5
```
Log in using username `admin` and the generated password.

---

## 3. Configuring the Windows Endpoint with Sysmon & Wazuh Agent

### Step 3.1: Download and Deploy Sysmon
Standard Windows Event Logs miss critical process ancestry and memory injection events. **Microsoft Sysmon (System Monitor)** fills this gap.

1. Download Sysmon from Microsoft Sysinternals:
   ```powershell
   Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$env:TEMP\Sysmon.zip"
   Expand-Archive -Path "$env:TEMP\Sysmon.zip" -DestinationPath "C:\Tools\Sysmon"
   ```
2. Download a battle-tested modular configuration (SwiftOnSecurity or Olaf Hartong):
   ```powershell
   Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "C:\Tools\Sysmon\sysmonconfig.xml"
   ```
3. Install Sysmon as a Windows Service:
   ```powershell
   cd C:\Tools\Sysmon
   .\Sysmon64.exe -i sysmonconfig.xml -accepteula
   ```
4. Verify Sysmon is logging under:  
   `Applications and Services Logs -> Microsoft -> Windows -> Sysmon -> Operational`

### Step 3.2: Install and Register the Wazuh Agent on Windows
1. In the Wazuh Dashboard, go to **Management -> Agents -> Deploy new agent**.
2. Select **Windows**, enter the Wazuh Server IP (`192.168.56.5`), and assign an agent name (e.g., `WIN-CORP-01`).
3. Copy and run the generated PowerShell registration command:
   ```powershell
   Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.8.0-1.msi -OutFile "$env:TEMP\wazuh-agent.msi"
   msiexec.exe /i "$env:TEMP\wazuh-agent.msi" /q WAZUH_MANAGER='192.168.56.5' WAZUH_REGISTRATION_SERVER='192.168.56.5' WAZUH_AGENT_NAME='WIN-CORP-01'
   NET START WazuhSvc
   ```

### Step 3.3: Ingest Sysmon Events into Wazuh
Edit `C:\Program Files (x86)\ossec-agent\ossec.conf` on the Windows machine to ensure Sysmon channels are forwarded to the manager:
```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```
Restart the Wazuh agent service:
```powershell
Restart-Service -Name WazuhSvc
```

---

## 4. Configuring the Linux Target

### Step 4.1: Install Auditd and Wazuh Agent
```bash
sudo apt-get install -y auditd
wget -qO - https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee -a /etc/apt/sources.list.d/wazuh.list
sudo apt-get update
sudo WAZUH_MANAGER="192.168.56.5" apt-get install wazuh-agent
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

---

## 5. Deployment Verification Checklist

- [ ] All virtual machines pingable on the isolated subnet (`192.168.56.0/24`).
- [ ] Wazuh Dashboard accessible over HTTPS with zero SSL crash errors.
- [ ] Windows agent `WIN-CORP-01` showing status **Active** in the Wazuh console.
- [ ] Linux agent `UBUNTU-SRV-01` showing status **Active**.
- [ ] Sysmon operational logs actively streaming into Wazuh Security Events view.
