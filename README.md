# Ajit Nayak
### **SOC Analyst | Threat Detection | SIEM Engineering | Incident Response**
📍 **Bangalore, India** (Open to Relocation / Remote) &nbsp;|&nbsp; 🟢 **Immediate Joiner**  
📧 **[ajit.nayak.028@gmail.com](mailto:ajit.nayak.028@gmail.com)** &nbsp;|&nbsp; 💼 **[linkedin.com/in/ajit028](https://linkedin.com/in/ajit028)** &nbsp;|&nbsp; 🌐 **[ajit028.github.io](https://ajit028.github.io)**

> *"I detect, investigate, and contain enterprise cyber threats through hands-on SIEM telemetry analysis, KQL/SPL detection engineering, and deep packet forensics."*

---

### 💼 Recruiter Quick-Scan (Core Metrics & Readiness)
- **Primary Focus**: Tier 1 / Tier 2 SOC Analyst, Incident Triage, Blue Teaming
- **Telemetry Ingested & Analyzed**: 14,000+ authentication events, 50+ network PCAPs
- **Detection Engineering**: 20+ production-grade detection rules (**KQL**, **SPL**, **Sigma**, **Snort/Suricata**)
- **Education & Certs**: B.Tech CSE (2021–2025, CGPA 7.44) | Certified in Advanced Cybersecurity & Threat Hunting (Career247)

```
[Target Roles]      SOC Analyst (L1/L2) | Threat Hunter | Information Security Associate
[Notice Period]      Immediate (0 Days)
[Work Authorization] India Citizen / Ready to deploy in Bangalore or Remote
```

---

## 🛡️ Featured Projects & Case Studies

### 1. [Azure Sentinel Cloud Honeypot & Global Threat Map](https://github.com/ajit028/azure-sentinel-honeypot)
*Cloud SIEM engineering, live attack telemetry ingestion, and geo-enrichment.*
- **Problem**: Lack of real-world adversary telemetry for calibrating cloud SIEM alert thresholds.
- **Setup**: Deployed an exposed Windows Server VM in Azure monitored via Log Analytics Workspace and Microsoft Sentinel, provisioned with Terraform.
- **Attack Observed**: 14,000+ global RDP brute-force attempts from 40+ countries within 24 hours (**MITRE T1110.001 - Password Guessing**).
- **Detection Rule (KQL)**:
  ```kql
  SecurityEvent
  | where EventID == 4625
  | summarize FailedCount = count() by IpAddress, TargetAccount, bin(TimeGenerated, 5m)
  | where FailedCount > 10
  | project TimeGenerated, SourceIP=IpAddress, TargetAccount, FailedCount
  ```
- **Outcome**: Automated IP geolocation enrichment via PowerShell pipeline and visualized global attack origins in interactive Sentinel Workbooks.

---

### 2. [Active Directory Security Auditing & Enterprise Hardening](https://github.com/ajit028/active-directory-hardening-lab)
*Adversary simulation, Kerberos abuse detection, and identity perimeter defense.*
- **Problem**: Enterprise networks frequently fall to lateral movement via unhardened Kerberos delegations and weak service account tickets.
- **Setup**: Multi-tier Windows Server Active Directory lab with domain joined clients and a dedicated attacker machine.
- **Attack Observed**: Simulated Kerberoasting (**MITRE T1558.003**), AS-REP Roasting (**T1558.004**), and DCSync rights discovery.
- **Detection Method**: Authored custom Sigma rules and KQL queries flagging high volumes of RC4-encrypted TGS ticket requests (`EventID 4769` with `TicketEncryptionType == "0x17"`).
- **Outcome**: Hardened domain baseline by enforcing AES-256 Kerberos encryption, eliminating legacy RC4 ciphers, enabling LSASS RunAsPPL protection, and drafting an AD Compromise Incident Response Playbook.

---

### 3. [Automated Threat Intel & IOC Scanner Pipeline](https://github.com/ajit028/automated-threat-intel-scanner)
*Security automation, multi-threaded triage, and threat intel sharing.*
- **Problem**: Manual IOC extraction and validation during incident triage adds 15–20 minutes of latency per alert for Tier 1 SOC analysts.
- **Setup**: Python 3 asynchronous pipeline containerized with Docker, featuring a FastAPI REST API and SQLite caching layer (24h TTL).
- **Attack Observed**: Triage of multi-vector incident logs containing obfuscated IP addresses, SHA-256 hashes, and C2 URLs (**MITRE T1071**).
- **Detection / Enrichment**: Concurrent querying against VirusTotal and AbuseIPDB APIs with automated risk scoring (0–100) and STIX 2.1 / MISP format export.
- **Outcome**: Reduced IOC triage latency from 15 minutes to under 2 seconds per batch at ~65,000 IOCs/second parsing throughput.

---

### 4. [Enterprise PCAP Malware & C2 Beaconing Forensics](https://github.com/ajit028/network-forensics-c2-beaconing)
*Deep packet inspection (DPI), jitter analysis, and NIDS signature engineering.*
- **Problem**: Covert C2 channels bypass signature-only perimeter firewalls through HTTP/HTTPS and DNS tunneling.
- **Setup**: Network analysis lab utilizing Wireshark, tcpdump, and Scapy packet dissectors.
- **Attack Observed**: Periodic Cobalt Strike C2 beaconing and Shannon high-entropy DNS query exfiltration (**MITRE T1071.004 / T1048**).
- **Detection Method**: Developed statistical timing scripts measuring Inter-Arrival Time (IAT) and Coefficient of Variation (CV < 0.20), plus custom Snort/Suricata rules.
- **Outcome**: Produced full forensic incident reports detailing packet streams, decoded HTTP payloads, and engineered 10+ high-fidelity Suricata rules.

---

## 🧪 Detection Engineering & Rules Repository

| Rule Name | Detection Target | Format | MITRE ATT&CK | Source Repo |
|---|---|---|---|---|
| **RDP Brute Force Threshold** | High-volume Event ID 4625 within 5 min | KQL | T1110.001 | [azure-sentinel-honeypot](https://github.com/ajit028/azure-sentinel-honeypot) |
| **Kerberoasting RC4 Abuse** | Event ID 4769 with Encryption Type `0x17` | Sigma / KQL | T1558.003 | [active-directory-hardening-lab](https://github.com/ajit028/active-directory-hardening-lab) |
| **AS-REP Roasting Triage** | Event ID 4768 missing pre-authentication | Sigma / SPL | T1558.004 | [active-directory-hardening-lab](https://github.com/ajit028/active-directory-hardening-lab) |
| **DNS Tunneling / High Entropy** | Shannon entropy > 3.8 on subdomain queries | Python / Suricata | T1071.004 | [network-forensics-c2-beaconing](https://github.com/ajit028/network-forensics-c2-beaconing) |
| **Cobalt Strike Malleable C2** | Specific URI pattern and custom User-Agents | Snort / Suricata | T1071.001 | [network-forensics-c2-beaconing](https://github.com/ajit028/network-forensics-c2-beaconing) |

---

## 🧰 Technical Skills & Tools

```
[SIEM & Analytics]       Microsoft Sentinel, Splunk, Wazuh, Log Analytics
[Query & Detection]      KQL (Kusto Query Language), SPL (Splunk Search), Sigma Rules, Regex
[Network & Forensics]    Wireshark, tcpdump, Snort, Suricata, NetworkMiner, Scapy
[Identity & Systems]     Active Directory, Group Policy (GPO), Sysmon, Windows Event Logs, Linux auth.log
[Threat Intelligence]    MITRE ATT&CK Framework, VirusTotal API, AbuseIPDB, MISP, STIX/TAXII
[Scripting & DevSecOps]  Python 3, PowerShell, Bash, Terraform, Docker, Git / CI Pipelines
```

---

## 📄 Incident Response Playbooks & Documentation
- 📘 **[NIST/SANS 6-Step RDP Brute Force IR Playbook](https://github.com/ajit028/azure-sentinel-honeypot/blob/main/playbooks/incident-response-playbook.md)**
- 📕 **[Active Directory Compromise & Forest Recovery SOP](https://github.com/ajit028/active-directory-hardening-lab/blob/main/playbooks/ad-compromise-ir.md)**
- 📒 **[Network Forensics & Packet Investigation Playbook](https://github.com/ajit028/network-forensics-c2-beaconing/blob/main/analysis/investigation-playbook.md)**

---

## 📬 Contact & Availability

I am actively interviewing for **SOC Analyst (L1/L2)** and **Threat Detection** roles.

- **Email**: [ajit.nayak.028@gmail.com](mailto:ajit.nayak.028@gmail.com)
- **LinkedIn**: [linkedin.com/in/ajit028](https://linkedin.com/in/ajit028)
- **Interactive Portfolio**: [ajit028.github.io](https://ajit028.github.io)
- **Location**: Bangalore (or Remote) | **Notice**: Available Immediately
