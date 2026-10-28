# Master Home Lab Memory & Technical Operations Log
**Repository:** `C:\Users\abhin\.gemini\antigravity\scratch\soc-detection-lab`  
**Last Updated:** October 26, 2026  
**Status:** Active & Persistent

---

## 1. Executive Summary & Mission Objective
* **Candidate Profile:** Certified Ethical Hacker (CEH) & Google Cybersecurity Professional.
* **Core Career Objective:** Secure a high-impact corporate role as a **Tier 1/2 SOC Analyst**, **Incident Responder**, or **Junior Penetration Tester**.
* **Methodology & Philosophy:** *"Train the brain to think"* — deep, first-principles understanding of every network packet, protocol vulnerability, forensic log, and operating system mechanism. No hand-waving, no blind script-kiddie tools.
* **Lab Standard:** Modern 2024–2026 tooling (Nuclei v3, Ffuf, NetExec, Wazuh, Sysmon v15, Tor SOCKS5, ESP32-S3 hardware auditing). Zero-cost infrastructure.

---

## 2. Infrastructure Inventory & Topology

```
                                  [ PHYSICAL WINDOWS 11 HOST ]
                                                │
         ┌──────────────────────────────────────┼──────────────────────────────────────┐
         ▼                                      ▼                                      ▼
[ WSL2 Ubuntu Environment ]           [ VirtualBox NatNetwork ]             [ ESP32-S3 Hardware Lab ]
• Native Docker Engine v29.1.3         • Subnet: 10.0.2.0/24                 • Firmware: Bruce v1.16.1
• OWASP Juice Shop (:3000)             • Kali Linux: 10.0.2.15               • Control: Phone Web UI (:4.1)
• DVGA GraphQL Target (:5013)          • Metasploitable 2: 10.0.2.5          • Modules: NRF24, PN532, IR, CC1101
• Direct API & Container Audit         • Tor SOCKS5 + Proxychains4           • Native USB HID (BadUSB)
```

---

## 3. Detailed Progress by Domain

### Domain A: SOC Detection Engineering & Incident Response
* **Repository:** `C:\Users\abhin\.gemini\antigravity\scratch\soc-detection-lab`
* **Artifacts Created:**
  1. `README.md`: High-visibility portfolio landing page presenting architecture, MITRE ATT&CK mappings, and lab objectives.
  2. `RESUME_TEMPLATE.md`: ATS-optimized master resume highlighting real detection engineering metrics.
  3. `config/custom_wazuh_rules.xml`: Custom SIEM detection rules targeting brute-force, web shells, and privilege escalation.
  4. `config/sysmonconfig-export.xml`: Tuned Sysmon v15 XML for granular process creation (`Event ID 1`), network connections (`Event ID 3`), and file creation (`Event ID 11`).
  5. `docs/01-architecture-and-setup.md`: Network isolation, SIEM forwarder design, and log pipeline documentation.
  6. `docs/02-adversary-emulation-and-attacks.md`: Attack scenarios executed against targets.
  7. `docs/03-detection-engineering-rules.md`: Rule logic explanation, false-positive handling, and log source mapping.
  8. `docs/04-incident-response-case-study.md`: Complete NIST SP 800-61 Rev. 2 incident triage report.
  9. `scripts/ioc_threat_intel_triage.py`: Automated triage script checking IOCs against threat feeds.

### Domain B: Modern Microservices Target Environment (WSL2)
* **Engine:** Native Ubuntu Docker daemon (`v29.1.3`).
* **Active Stack:** `~/modern-targets/docker-compose.yml`
  * `bkimminich/juice-shop`: Node.js / Angular microservice web application on port `3000`.
  * `dweebd/dvga`: Damn Vulnerable GraphQL Application running on port `5013`.
* **Verified:** Verified container execution, Docker socket permissions, and bridge networking.

### Domain C: Network Penetration Testing & Metasploitable Lab
* **Virtualization:** Oracle VirtualBox with dedicated `NatNetwork` (`10.0.2.0/24`).
* **Kali Linux Weaponization (`10.0.2.15`):**
  * Tor SOCKS5 background daemon active on `127.0.0.1:9050`.
  * `proxychains4` configured (dynamic chain, DNS leak prevention verified with exit node `2001:67c:e60:c0c:192:42:116:66`).
  * Installed SecLists (`/usr/share/seclists`), `ffuf`, `nuclei v3` (8,000+ templates updated), `katana`, `netexec` (`nxc`), `bloodhound.py`, and `impacket-scripts`.
  * TryHackMe VPN tunnel verified (`tun0` interface).
* **Live Breach Executed:**
  * Target: Metasploitable 2 (`10.0.2.5`).
  * Vector: Port 21 `vsftpd 2.3.4` smiley-face backdoor (`:)`).
  * Execution: Netcat manual trigger on port 21 $\rightarrow$ reverse root shell caught on port 6200 (`uid=0(root)`).

### Domain D: Hardware Multi-Tool (ESP32-S3 & Bruce v1.16.1)
* **Hardware:** ESP32-S3 (QFN56 revision v0.2, 8MB Embedded PSRAM, 40MHz crystal).
* **Firmware:** Flashed `Bruce-esp32-s3-devkitc-1.bin` at offset `0x0` via Espressif Web Flasher.
* **Critical Hardware Diagnostics Solved:**
  1. *Serial Port Busy Error:* Windows exclusive COM locking by Google Chrome WebSerial resolved by disconnecting browser session.
  2. *Boot Hang at `entry 0x403c00b0`:* Discovered ESP32-S3 dual-port architecture. Board switched console output from hardware UART bridge to native USB-CDC port upon application launch. Moving cable to native `USB` port restored full communications.
* **Control Interface:** Headless Web Controller operating at `http://192.168.4.1` on local Wi-Fi, using smartphone as virtual display and navigator.
* **Project Directory:** `C:\Users\abhin\.gemini\antigravity\scratch\esp32-s3-multitool`
  * `brucePins.conf`: Pre-configured for shared SPI and I2C buses.
  * `wiring_guide.md`: Complete pinout mapping and DIP switch configurations.
  * `payloads/test_notepad.txt`: Safe BadUSB keystroke injection test payload.

---

## 4. Hardware Expansion Architecture & Sourcing

### Module & Bus Pinout Mapping
* **Shared SPI Bus:**
  * `SCK` $\rightarrow$ GPIO 12
  * `MOSI` $\rightarrow$ GPIO 11
  * `MISO` $\rightarrow$ GPIO 13
* **Module Chip Selects & Direct Pins:**
  * **NRF24L01+ PA/LNA:** `CSN` = GPIO 10, `CE` = GPIO 9, `VCC` = **3.3V ONLY**. (Unlocks 2.4GHz MouseJack keystroke injection).
  * **CC1101 (433MHz):** `CSN` = GPIO 14, `GDO0` = GPIO 21, `VCC` = 3.3V. (Unlocks Sub-GHz car/gate remotes).
  * **PN532 NFC/RFID:** `SDA` = GPIO 4, `SCL` = GPIO 5 (DIP Switch 1=ON, 2=OFF for I2C). (Unlocks 13.56MHz badge/keycard cloning).
  * **Infrared Pair:** `IR RX` = GPIO 1, `IR TX` = GPIO 2. (Unlocks TV-B-Gone & remote learning).

### Verified Shopping Cart Details
* **Robocraze:**
  * `NRF24L01+PA+LNA Wireless Module with Antenna` (Item #2, ₹179)
  * `PN532 NFC-Near Field Communication Module V3` (Item #3, ₹269)
  * `Infrared IR Wireless Remote Control Module` (Item #3, ₹63)
  * `20CM Female-to-Female DuPont Jumper Wires (40 pcs)` (~₹59)
* **Flyrobo:**
  * `433MHz CC1101 Wireless RF Transceiver Module` (In Stock, ₹323)

---

## 5. Next Planned Milestones

1. **Hardware Verification:**
   * Run BadUSB `test_notepad.txt` over native USB cable.
   * Test BLE advertising spam on local test devices.
   * Wire breakout modules on breadboard upon package arrival and verify `brucePins.conf`.
2. **Web Exploitation & Linux Privilege Escalation (Metasploitable):**
   * Multi-stage attack on Port 80 (DVWA / Mutillidae).
   * Obtain low-privilege `www-data` shell.
   * Perform manual Linux privilege escalation to root via SUID binaries, misconfigured cron jobs, and kernel exploits.
3. **Enterprise Windows Detection Lab:**
   * Import Windows 11 Enterprise into VirtualBox `NatNetwork`.
   * Deploy Sysmon v15 and link Wazuh agent for real-time SIEM alert generation.
