# 🏗️ Active Directory Labs

**Analyst:** Peter Van Rossum  
**Repo Purpose:** Central hub for all my Active Directory–focused home labs, combining domain setup, telemetry collection, attack simulation, and detection engineering.  

---

## 🎯 Overview

This repo serves as an **umbrella project** for multiple Active Directory labs. Each lab folder explores a different dimension of enterprise Windows environments — from domain setup and detection engineering to hardening and incident response.  

I’m using these labs to strengthen my skills in:  
- Active Directory administration & security  
- Endpoint telemetry (Sysmon, Windows Event Logs)  
- SIEM integration (Splunk, Elastic Stack)  
- Detection engineering with adversary simulation (Kali Linux, Atomic Red Team)  
- Hands-on SOC analysis workflows  

---

## 📂 Lab Index

- 🛡️ **[Active Directory Detection Lab](https://github.com/SecOpsPete/active-directory-labs/tree/main/active-directory-detection-lab)**  
  Builds a domain environment with Windows Server and a client, wires telemetry with Sysmon + Splunk Universal Forwarder, and simulates adversary techniques (Kali brute force, Atomic Red Team) to generate real logs. Includes SPL queries, dashboards, and alerts drawn from common SOC playbooks to practice detection engineering in a safe home lab.

*(More labs coming soon: hardening, incident response, and advanced red team detection scenarios.)*  

---

## ⚠️ Disclaimer

All labs are conducted in a **safe, isolated home network** with no internet exposure. Techniques shown here are for **educational and professional development purposes only**.  

---

_Report generated and maintained by Peter Van Rossum_  
