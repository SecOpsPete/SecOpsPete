# 🛡️ Cybersecurity Projects & Technical Labs by Peter Van Rossum

📍 [Connect on LinkedIn](https://www.linkedin.com/in/vanr/)

---

🚀 **Cybersecurity Analyst | Sales Engineering**

Driven by curiosity and a hands-on mindset, I specialize in securing systems and enhancing operational resilience. My work focuses on applying cybersecurity tools, frameworks, and analytical techniques to strengthen threat detection, streamline vulnerability management, and translate complex security challenges into practical solutions.

---

## 🧠 Agentic AI (Agentic AI Cybersecurity Agent) [🔗](https://github.com/SecOpsPete/agentic-ai-cybersecurity-agent)

- 🤖 **[Agentic AI Cybersecurity Agent](https://github.com/SecOpsPete/agentic-ai-cybersecurity-agent)**  
  An AI-powered, Python-based autonomous threat-hunting agent that integrates with **Azure Sentinel** and **Defender for Endpoint** to analyze telemetry from 1,000+ endpoints using **KQL**.

  Custom improvements/enhancements include: hardened guardrails: password-protected isolation, PII redaction, row/byte caps, time-window enforcement, input validation, and robust error handling. Roadmap items include OWASP LLM hardening and MITRE ATLAS mapping.

<h3 align="center">🎬 Watch the Video:</h3>
<p align="center">
  <a href="https://www.youtube.com/watch?v=tms3dnZih4U&t=33s">
    <img src="https://img.youtube.com/vi/tms3dnZih4U/maxresdefault.jpg" width="300" alt="Watch the video">
  </a>
</p>

--- 

## 🏗️ Active Directory [🔗](https://github.com/SecOpsPete/active-directory-labs)

- 🛡️ **[Active Directory Detection Lab](https://github.com/SecOpsPete/active-directory-labs/tree/main/active-directory-detection-lab)**  
  Builds a domain environment with Windows Server and a client, wires telemetry with Sysmon + Splunk Universal Forwarder, and simulates adversary techniques (Kali brute force, Atomic Red Team) to generate real logs. Includes SPL queries, dashboards, and alerts drawn from common SOC playbooks to practice detection engineering in a safe home lab.

---


## 🛡️ DISA STIG Compliance

- 📋 **[Windows 10 STIG Remediation Scripts](https://github.com/SecOpsPete/disa-stig-compliance-labs)**  
  A growing collection of PowerShell scripts designed to automate remediation of DISA STIG findings on Windows systems. Each lab follows a standardized structure and includes clear metadata, usage instructions, and STIG traceability (e.g., `WN10-AU-000500`).  
  Ideal for compliance hardening, audit preparation, or RMF/ATO alignment in federal and defense environments.

---

## 🔎 Threat Hunting [🔗](https://github.com/SecOpsPete/threat-hunting-scenarios)

- 🛡️ **[Remote Support Backdoor - CTF](https://github.com/SecOpsPete/threat-hunting-scenarios/blob/main/remote-support-backdoor/README.md)**  
  Reconstructs a routine-looking remote support session that was actually a staged misdirection: I trace initial script execution (ExecutionPolicy bypass), short-lived clipboard probes, file staging in public folders, network reachability checks, and layered persistence (scheduled tasks + autorun). The write-up provides KQL pivots, investigation notes, and evidence images.

- 🛡️ **[RDP Breach Hunt - CTF](https://github.com/SecOpsPete/threat-hunting-scenarios/blob/main/rdp-breach-hunt)**  
  Reconstructs a full compromise triggered by an external password spray attack against host **flare**, exposing attacker persistence via scheduled tasks, beaconing attempts, and lateral movement activity mapped to MITRE ATT&CK.

- 🕵️‍♂️ **[The Invisible RDP](https://github.com/SecOpsPete/threat-hunting-scenarios/blob/main/the-invisible-rdp)**  
  Investigates a suspicious RDP connection from a public IP that bypassed standard logging. Uncovers abuse of `svchost.exe`, persistent execution of `wermgr.exe -upload`, and stealthy HTTPS exfiltration activity using native Windows binaries.

- 🕵️‍♂️ **[Unauthorized TOR Activity Detection](https://github.com/SecOpsPete/threat-hunting-scenarios/blob/main/unauthorized-tor-activity)**  
  Investigates unsanctioned installation and usage of the TOR browser using endpoint telemetry and network activity. Demonstrates detection of silent installation, anonymous traffic over TOR relay ports, and artifacts suggesting user concealment attempts.

- 🛡️ **[Zero-Day Ransomware Detection](https://github.com/SecOpsPete/threat-hunting-scenarios/blob/main/pwncrypt-ransomware-detection/README.md)**  
  Detects file encryption activity, delivery via PowerShell, and execution of the `pwncrypt.ps1` ransomware script using Microsoft Defender telemetry and MITRE ATT&CK mapping.

- 🧪 **[Insider Data Exfiltration](https://github.com/SecOpsPete/threat-hunting-scenarios/tree/main/insider-data-exfil)**  
  Investigates potential insider threat activity using Microsoft Defender for Endpoint, correlating file, process, and network telemetry to detect staged data exfiltration.

- 🌐 **[Brute Force Detection](https://github.com/SecOpsPete/threat-hunting-scenarios/tree/main/brute-force-detection)**  
  Detection of suspicious authentication failures and patterns indicating password guessing or brute force attacks.

- 🔎 **[Internal PowerShell Port Scanning](https://github.com/SecOpsPete/threat-hunting-scenarios/tree/main/port-scanning-detection)**  
  Detection and investigation of internal lateral movement using obfuscated scripts.

---

## 🧪 Incident Response Labs [🔗](https://github.com/SecOpsPete/incident-response-sentinel)

- 🌍 **[Impossible Travel Detection with Microsoft Sentinel](https://github.com/SecOpsPete/incident-response-sentinel/tree/main/impossible-travel-detection-sentinel)**  
  Detects anomalous sign-in behavior across distant geographic locations in short timeframes. Implements a Sentinel analytics rule and KQL-based investigation to identify potential account compromise. Follows the NIST IR framework for containment, validation, and closure.

- ⚡ **[PowerShell Suspicious Web Request Detection](https://github.com/SecOpsPete/incident-response-sentinel/tree/main/ps-suspicious-web-request)**  
  Simulates post-exploitation behavior where PowerShell downloads remote payloads using `Invoke-WebRequest`. Includes Sentinel rule creation, incident triage, and MDE-based containment following the NIST IR framework.

- 🔐 **[Brute Force Detection with Microsoft Sentinel](https://github.com/SecOpsPete/incident-response-sentinel/tree/main/brute-force-detection-sentinel)**  
  Detects multiple failed login attempts from the same remote IP using KQL and Microsoft Sentinel analytics rules.

- 🗺️ **[Sentinel Log Visualizations & Attack Maps](https://github.com/SecOpsPete/incident-response-sentinel/tree/main/log-visualizations)**  
  Leverages Microsoft Sentinel to map failed logins, malicious flows, and Azure resource creation activity using KQL, custom watchlists, and Workbook-based heatmaps. Visualizes geolocated attack data across Entra ID, VM authentication, and NSG traffic using real telemetry.

- 🧠 **[UnInstDaemon.exe High CPU Incident Response](https://github.com/SecOpsPete/incident-response-sentinel/tree/main/the-daemon-that-wouldnt-quit)**  
  Investigates a Microsoft-signed binary (`UnInstDaemon.exe`) that remained active in the Temp directory, consuming excessive CPU after a failed cleanup routine. This lab walks through full process triage, digital signature verification, VirusTotal analysis, correlation with Microsoft Update Health Tools, and post-incident validation. A realistic Windows IR scenario demonstrating calm           decision-making and forensic precision.


---

## ⚠️ Vulnerability Management Projects [🔗](https://github.com/SecOpsPete/vulnerability-management-projects)

- 🔧 **[Vulnerability Management Program Implementation](https://github.com/SecOpsPete/vulnerability-management-projects/tree/main/vulnerability-management-program)**  
  A complete documentation-based approach to launching an internal vulnerability management program.

- 💻 **[Programmatic Remediation Scripts (PowerShell)](https://github.com/SecOpsPete/vulnerability-management-projects/tree/main/programmatic-remediation-scripts)**  
  Automated scripts for common CVE remediation and configuration hardening.

- 💬 **[Prompt Engineering References](https://github.com/SecOpsPete/vulnerability-management-projects/tree/main/prompt-engineering-references)**  
  ChatGPT prompts used to generate and refine PowerShell remediation scripts, demonstrating structured problem-solving and AI-assisted development.

---

## 🛠️ Cybersecurity Tools [🔗](https://github.com/SecOpsPete/cybersecurity-tools)

- 🛡️ **[Windows Threat Audit & Cleanup Automation](https://github.com/SecOpsPete/cybersecurity-tools/blob/main/win-threat-audit-cleanup-automation)**  
  Perform scheduled system audits and temp folder cleanup using PowerShell. Enhance visibility into autoruns, services, TCP connections, and missing security logging.

- 🔒 **[Microsoft Defender Attack Surface Reduction](https://github.com/SecOpsPete/cybersecurity-tools/blob/main/microsoft-defender-attack-surface-reduction)**  
  Block macro-based payloads by enabling ASR rules in Microsoft Defender. Prevent Office apps from spawning child processes like PowerShell to reduce common malware techniques.

- 🛠️ **[Process Investigation with PowerShell](https://github.com/SecOpsPete/cybersecurity-tools/blob/main/process-investigation-windows)**
  Identify, analyze, and validate suspicious Windows processes using native PowerShell tools and reputation checks.

- 🔐 **[GPG Signature Verification Guide](https://github.com/SecOpsPete/cybersecurity-tools/blob/main/gpg-verification-guide)**  
  A step-by-step guide for verifying file authenticity and integrity using GPG with real-world examples.

- 🧪 **[File Integrity Verification (SHA256)](https://github.com/SecOpsPete/cybersecurity-tools/tree/main/file-integrity-verification)**  
  Validates that a downloaded file hasn’t been altered using SHA256 hash checking in PowerShell.

- 🔐 **[SSH Key Authentication](https://github.com/SecOpsPete/cybersecurity-tools/tree/main/ssh-key-authentication-lab)**  
  A hands-on guide to configuring and using SSH key-based authentication.

- 🔐 **[Microsoft 365 DKIM Setup & Verification](https://github.com/SecOpsPete/cybersecurity-tools/tree/main/DKIM-setup-guide)**  
  Step-by-step guide for publishing DKIM CNAME records at your DNS host, enabling DKIM in Microsoft 365 Defender, and verifying authentication via Gmail headers and DMARC aggregate reports.

- 💾 **[RoboCopy Automated File Backup](https://github.com/SecOpsPete/cybersecurity-tools/tree/main/robocopy-auto-backup)**  
  Batch script for selectively backing up key OneDrive folders to a secondary drive with RoboCopy, including logging, retry logic, and Task Scheduler integration.


---

## 🏠 Professional-Grade Home Lab for Cybersecurity Research & Network Hardening [🔗](https://github.com/SecOpsPete/secure-soho-network)

- 🔐 **[Secure Home Lab Network for Cybersecurity Testing & Network Defense](https://github.com/SecOpsPete/secure-soho-network/blob/main/secure-soho-network-lab)**  
  Documents the design and implementation of a secure small office/home office (SOHO) network. Features include IoT segmentation, guest SSID isolation, firewall configuration, endpoint protection with Malwarebytes, NordVPN, BitLocker encryption, and a Raspberry Pi syslog server for centralized logging.

- 📡 **[Windows-to-Raspberry Pi Syslog Pipeline](https://github.com/SecOpsPete/secure-soho-network/blob/main/log-forwarding-pipeline)**  
  Demonstrates log forwarding from a Windows 10 system to a Raspberry Pi syslog server using PowerShell and Task Scheduler. Logs are parsed and visualized via a Dockerized Elastic Stack on the Windows host—no NXLog or Filebeat required.

- 📊 **[Practical KQL Queries for Detecting SSH & Linux Intrusions](https://github.com/SecOpsPete/secure-soho-network/tree/main/kql-linux-threat-queries)**  
  A curated set of Kibana Query Language (KQL) filters for detecting suspicious Linux activity including SSH brute force attempts, failed privilege escalation, reverse shell behavior, cron job tampering, and unexpected service starts. Designed for home labs or SOC environments leveraging syslog data and the ELK stack.

- 💽 **[Isolated USB Malware Checking Station](https://github.com/SecOpsPete/secure-soho-network/blob/main/USB-malware-checking-station/README.md)**  
  A Raspberry Pi–based lab for safely screening USB drives before they touch trusted systems. The workflow mounts drives read-only, scans with ClamAV, and saves logs to an external SSD. If malware is detected, the process escalates to forensic imaging and offline analysis in Autopsy, preserving evidence integrity while preventing accidental execution.

- 🖨️ **[Printer Firewall Hardening](https://github.com/SecOpsPete/cybersecurity-tools/blob/main/printer-firewall-hardening)**  
  Secure a network printer by applying precise Windows Defender Firewall rules to block public exposure while preserving vendor updating & management functionality.
  
- 🛡️ **[Secure Network Security Profile](https://github.com/SecOpsPete/secure-soho-network/tree/main/network-security-profile)**  
  Evaluates and documents the security posture of a SOHO network with layered defenses including VLAN segmentation, endpoint hardening, router firewall rules, BitLocker encryption, and syslog integration via Raspberry Pi. Includes visual diagrams and implementation walkthrough.

---

## 🧰 Tools


| **Network** | **Endpoint & Virtualization** | **Security Testing & SIEM** |
|-------------|-------------------------------|-----------------------------|
| <img src="https://img.shields.io/badge/Active%20Directory-0078D4?style=for-the-badge&logo=windows&logoColor=white" alt="Active Directory"> | <img src="https://img.shields.io/badge/Microsoft%20Defender%20for%20Endpoint-0066B8?style=for-the-badge&logo=microsoft&logoColor=white" alt="Microsoft Defender for Endpoint"> | <img src="https://img.shields.io/badge/Burp%20Suite-F47F24?style=for-the-badge&logo=portswigger&logoColor=white" alt="Burp Suite"> |
| <img src="https://img.shields.io/badge/Wireshark-1679A7?style=for-the-badge&logo=wireshark&logoColor=white" alt="Wireshark"> | <img src="https://img.shields.io/badge/VirtualBox-183A61?style=for-the-badge&logo=virtualbox&logoColor=white" alt="VirtualBox"> | <img src="https://img.shields.io/badge/Metasploit-4E4E4E?style=for-the-badge&logo=metasploit&logoColor=white" alt="Metasploit"> |
| <img src="https://img.shields.io/badge/Cisco%20IOS-1BA0D7?style=for-the-badge&logo=cisco&logoColor=white" alt="Cisco IOS"> | <img src="https://img.shields.io/badge/Kali%20Linux-557C94?style=for-the-badge&logo=kalilinux&logoColor=white" alt="Kali Linux"> | <img src="https://img.shields.io/badge/PowerShell-5391FE?style=for-the-badge&logo=powershell&logoColor=white" alt="PowerShell"> |
| <img src="https://img.shields.io/badge/Splunk-000000?style=for-the-badge&logo=splunk&logoColor=white" alt="Splunk"> | <img src="https://img.shields.io/badge/Sysmon-808080?style=for-the-badge&logo=windows&logoColor=white" alt="Sysmon"> | <img src="https://img.shields.io/badge/Atomic%20Red%20Team-CC0000?style=for-the-badge&logo=redhat&logoColor=white" alt="Atomic Red Team"> |
| <img src="https://img.shields.io/badge/Elastic%20Stack-005571?style=for-the-badge&logo=elasticstack&logoColor=white" alt="Elastic Stack"> |  | <img src="https://img.shields.io/badge/Bash-4EAA25?style=for-the-badge&logo=gnubash&logoColor=white" alt="Bash"> |


🔹🔹🔹

| **Log Management & Detection** | **Vulnerability Management** | **Cloud & DevOps** |
|-------------------------------|------------------------------|--------------------|
| <img src="https://img.shields.io/badge/ELK%20Stack-005571?style=for-the-badge&logo=elasticstack&logoColor=white" alt="ELK Stack"> | <img src="https://img.shields.io/badge/Nessus-5E67EB?style=for-the-badge&logoColor=white" alt="Nessus"> | <img src="https://img.shields.io/badge/Microsoft%20Azure-0078D4?style=for-the-badge&logo=microsoftazure&logoColor=white" alt="Microsoft Azure"> |
| <img src="https://img.shields.io/badge/Syslog-F47F24?style=for-the-badge&logo=linux&logoColor=white" alt="Syslog"> |  |  |

- More tools coming soon: remediation automations, network analysis helpers, and more.

---
## 🤝 Connect With Me

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?logo=linkedin&logoColor=white)](https://www.linkedin.com/in/vanr/)

📫 I’m always open to collaborate or discuss how to bring security into solution design.

