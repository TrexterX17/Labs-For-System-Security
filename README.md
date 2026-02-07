# 🔐 System Security Labs Portfolio

**By Faraz Ahmed**  
*Hands-On Security Engineering & System Administration*

---

## 👋 About This Repository

This repository showcases my practical, hands-on experience in system security, network administration, and cybersecurity operations. Each lab demonstrates real-world skills in configuring, securing, and analyzing computer systems and networks.

These labs were completed as part of **EAS 595 - System Security** under Prof. Kevin Cleary, where I gained practical experience with enterprise-grade tools and techniques used in modern cybersecurity operations.

---

## 🎯 Core Competencies Demonstrated

Through these labs, I have developed and demonstrated proficiency in:

### 🖥️ **System Administration**
- Cross-platform OS deployment (Windows & Linux)
- Virtualization management (VMware vSphere)
- System hardening and security configuration
- User and permission management

### 🌐 **Network Security**
- Network configuration and troubleshooting
- TCP/IP protocol analysis
- Routing and switching concepts
- DNS and connectivity diagnostics

### 🛡️ **Security Operations**
- Security baseline implementation
- Vulnerability assessment
- Incident response procedures
- Security monitoring and logging

### 🔧 **Technical Tools**
- Command-line proficiency (PowerShell, Bash)
- Network diagnostic utilities
- Virtualization platforms
- Security assessment tools

---

## 📚 Lab Directory

| Lab # | Title | Key Skills | Difficulty |
|-------|-------|------------|------------|
| [01](./lab-01-os-installation-networking/) | **OS Installation & Network Connectivity** | Virtualization, Network Diagnostics, Cross-Platform Admin | ⭐ Beginner |
| [02](./lab-02-pfsense-network-segmentation/) | **pfSense Router & Network Segmentation** | Firewall Configuration, IDS Deployment, Network Architecture | ⭐⭐ Intermediate |
| [03](./lab-03-firewall-configuration/) | **Firewall Rules & Access Control** | Protocol-Specific Rules, Least Privilege, Security Testing | ⭐⭐⭐ Intermediate/Advanced |
| [04](./lab-04-active-directory-group-policy/) | **Active Directory & Group Policy** | AD DS, User Management, GPO, IIS, PowerShell Logging | ⭐⭐⭐⭐ Advanced |
| [05](./lab-05-linux-hardening-automation/) | **Linux Server Hardening & Automation** | LAMP Stack, Security Hardening, Bash Scripting, Cron Jobs | ⭐⭐⭐⭐ Advanced |
| [06](./lab-06-windows-threat-hunting/) | **Windows Threat Hunting & Incident Response** | Malware Analysis, IFEO Forensics, Event Log Analysis, IR Documentation | ⭐⭐⭐⭐⭐ Expert |
| [07](./lab-07-services-mediawiki-fail2ban/) | **Service Deployment, MediaWiki & Fail2Ban** | MariaDB Admin, MediaWiki, iptables, Fail2Ban, Multi-Tier Architecture | ⭐⭐⭐⭐⭐ Expert |
| [08](./lab-08-network-architecture-security-proposals/) | **Network Architecture & Security Proposals** | Network Documentation, Honeypots, IDPS, Business Case Writing, ROI Analysis | ⭐⭐⭐⭐⭐ Expert |
| [09](./lab-09-containerization-siem-graylog/) | **Containerization & SIEM (Graylog)** | Docker, Docker Compose, Graylog, rsyslog, Alert Engineering, SOC Dashboards | ⭐⭐⭐⭐⭐ Expert |
| [10](./lab-10-risk-analysis-management/) | **Risk Analysis & Management** | PII/SPII Assessment, SIEM Evaluation, Cost-Benefit Analysis, Executive Memos | ⭐⭐⭐⭐⭐ Expert |
| [11](./lab-11-penetration-testing-ethical-hacking/) | **Penetration Testing & Ethical Hacking** | Nmap, SQL Injection, Reverse Shells, Privilege Escalation, Pentest Reporting | ⭐⭐⭐⭐⭐ Expert |

> **Note:** This repository is actively being updated as I complete additional labs. Check back for new content!

---

## 🔬 Lab 01: Operating System Installation & Network Connectivity

**Status:** ✅ Complete | [View Full Documentation →](./lab-01-os-installation-networking/)

### Quick Overview
Deployed Windows 10 Enterprise and Ubuntu Linux in a virtualized environment, configured network settings, and validated connectivity using platform-specific CLI tools.

### Key Achievements
- ✅ Successfully installed two enterprise operating systems
- ✅ Configured virtual networking infrastructure
- ✅ Performed cross-platform network diagnostics
- ✅ Created network topology documentation

### Technologies Used
`VMware vSphere` `Windows 10 Enterprise` `Ubuntu Linux` `PowerShell` `Bash` `TCP/IP` `DNS`

**[→ Read Full Lab Documentation](./lab-01-os-installation-networking/README.md)**

---

## 🛡️ Lab 02: pfSense Router Configuration & Network Segmentation

**Status:** ✅ Complete | [View Full Documentation →](./lab-02-pfsense-network-segmentation/)

### Quick Overview
Deployed pfSense firewall/router to create segmented enterprise network architecture with AdminNet and ServerNet zones. Configured static routing between segments and implemented Suricata IDS for network monitoring.

### Key Achievements
- ✅ Installed and configured pfSense CE 2.7.2 router
- ✅ Created multi-segment network architecture (AdminNet, ServerNet)
- ✅ Configured advanced Windows PowerShell and Linux netplan networking
- ✅ Deployed Suricata IDS on external interface
- ✅ Validated inter-VLAN routing and internet connectivity
- ✅ Implemented security best practices (network segmentation, monitoring)

### Technologies Used
`pfSense` `Suricata IDS` `Network Segmentation` `PowerShell` `netplan` `Inter-VLAN Routing` `IDS/IPS` `Enterprise Networking`

**[→ Read Full Lab Documentation](./lab-02-pfsense-network-segmentation/README.md)**

---

## 🔥 Lab 03: Firewall Configuration & Access Control

**Status:** ✅ Complete | [View Full Documentation →](./lab-03-firewall-configuration/)

### Quick Overview
Implemented granular firewall rules on pfSense to control inbound and outbound traffic, restricted administrative access to a single designated workstation, and systematically validated rule effectiveness through comprehensive testing.

### Key Achievements
- ✅ Created protocol-specific inbound rules (WinRM, RDP, SSH)
- ✅ Configured outbound rules for business functions (FTP, HTTP/HTTPS, DNS, Windows Update)
- ✅ Implemented least-privilege administrative access (only one device manages firewall)
- ✅ Disabled overly-permissive anti-lockout rule
- ✅ Conducted 17 validation tests with 100% success rate
- ✅ Authored professional security policy memo for executive approval
- ✅ Demonstrated defense-in-depth and zero-trust principles

### Technologies Used
`pfSense Firewall Rules` `WinRM` `RDP` `SSH` `Access Control Lists` `Protocol Filtering` `Security Testing` `Policy Documentation` `Least Privilege`

**[→ Read Full Lab Documentation](./lab-03-firewall-configuration/README.md)**

---

## 🏢 Lab 04: Active Directory & Group Policy Management

**Status:** ✅ Complete | [View Full Documentation →](./lab-04-active-directory-group-policy/)

### Quick Overview
Deployed enterprise Active Directory infrastructure with domain services, created centralized user and group management, implemented Group Policy Objects for configuration control, installed IIS web server, and established PowerShell logging for security monitoring.

### Key Achievements
- ✅ Deployed Active Directory domain (team32.local) with domain controller
- ✅ Joined Win10Client and IISServer to domain for centralized management
- ✅ Created users with role-based permissions (Kevin - Domain Admin, Dave CEO - Standard User)
- ✅ Implemented security groups (UBFaculty, Workstations) for access control
- ✅ Deployed IIS web server on IISServer with remote management
- ✅ Created Desktop Background GPO with network share distribution
- ✅ Implemented PowerShell Transcription GPO for security auditing
- ✅ Designed Organizational Unit structure for granular policy application
- ✅ Authored executive memo proposing password policy enhancements
- ✅ Demonstrated Single Sign-On (SSO) and centralized authentication

### Technologies Used
`Active Directory` `Group Policy Objects (GPO)` `IIS Web Server` `PowerShell Logging` `Domain Services` `RBAC` `Server Manager` `Organizational Units` `Network Shares` `Security Auditing`

**[→ Read Full Lab Documentation](./lab-04-active-directory-group-policy/README.md)**

---

## 🐧 Lab 05: Linux Server Hardening & Automation

**Status:** ✅ Complete | [View Full Documentation →](./lab-05-linux-hardening-automation/)

### Quick Overview
Deployed enterprise Linux infrastructure with Ubuntu web server (Apache2 + PHP) and Rocky Linux database server (MariaDB), implemented comprehensive security hardening including password policies and file permissions, created user/group management with RBAC, and automated log backup with bash scripting and cron scheduling.

### Key Achievements
- ✅ Deployed LAMP stack (Linux, Apache, MySQL/MariaDB, PHP) across two servers
- ✅ Configured cross-distribution Linux (Ubuntu + Rocky Linux)
- ✅ Implemented 6 security hardening controls (CIS Benchmark alignment)
- ✅ Enforced password complexity (10 chars, 2 digits, 1 uppercase)
- ✅ Created 5 users and 3 security groups with role-based access
- ✅ Configured sudo privileges with visudo for BlackTeam group
- ✅ Applied file permission restrictions (chmod 700, 750)
- ✅ Enabled automatic security updates (unattended-upgrades)
- ✅ Wrote bash script for automated log backup with tar compression
- ✅ Scheduled daily cron job (4:05 AM) for log management
- ✅ Added 7 pfSense firewall rules for server access control

### Technologies Used
`Ubuntu Server` `Rocky Linux` `Apache2` `PHP` `MariaDB` `Bash Scripting` `Cron` `PAM` `sudo/visudo` `libpam-pwquality` `SELinux` `unattended-upgrades` `systemd` `tar` `Log Management`

**[→ Read Full Lab Documentation](./lab-05-linux-hardening-automation/README.md)**

---

## 🔍 Lab 06: Windows Threat Hunting & Incident Response

**Status:** ✅ Complete | [View Full Documentation →](./lab-06-windows-threat-hunting/)

### Quick Overview
Conducted real-world incident response investigation by analyzing a security breach involving brute force authentication, identified and removed IFEO (Image File Execution Options) registry hijacking malware, eliminated unauthorized user account and persistence mechanisms, and documented findings in a professional incident report with executive summary and security recommendations.

### Key Achievements
- ✅ Investigated active security incident using Windows Event Viewer
- ✅ Identified attack timeline through Event ID analysis (4624, 4625, 4720, 4732)
- ✅ Discovered IFEO registry hijacking (Task Manager → Notepad redirect)
- ✅ Analyzed brute force authentication attack vector and successful breach
- ✅ Removed unauthorized backdoor account ("notbad") created via PowerShell
- ✅ Eradicated malware persistence mechanisms (registry keys, files, processes)
- ✅ Performed system integrity verification with System File Checker (sfc /scannow)
- ✅ Documented complete incident report with IoCs and remediation steps
- ✅ Provided executive summary with business impact assessment
- ✅ Created security recommendations (MFA, password policy, EDR, SIEM)
- ✅ Performed Linux network forensics with socket statistics (ss -tlp)

### Technologies Used
`Windows Event Viewer` `Registry Editor (regedit)` `IFEO Analysis` `PowerShell Forensics` `System File Checker` `Task Manager` `Malware Analysis` `Incident Response` `Event Log Analysis` `IoC Identification` `Network Forensics (ss)` `Threat Hunting`

**[→ Read Full Lab Documentation](./lab-06-windows-threat-hunting/README.md)**

---

## 🚀 Lab 07: Service Deployment, MediaWiki & Fail2Ban

**Status:** ✅ Complete | [View Full Documentation →](./lab-07-services-mediawiki-fail2ban/)

### Quick Overview
Deployed a full multi-tier web application by configuring MariaDB with a dedicated database and least-privilege user on RockyDBServer, installed and integrated MediaWiki on UbuntuWebServer, implemented host-based iptables firewall rules with default-deny policy, validated access control across all network segments with systematic testing, and hardened SSH with Fail2Ban following a real brute force attack detection.

### Key Achievements
- ✅ Created dedicated MariaDB database (wiki_webdb) and non-root user with granular privileges
- ✅ Deployed MediaWiki end-to-end: installation wizard, database integration, admin configuration
- ✅ Connected web application to remote database across network segments (port 3306)
- ✅ Implemented 7 iptables rules on UbuntuWebServer with default-deny policy
- ✅ Layered host-based firewall (iptables) on top of network firewall (pfSense) — defense-in-depth
- ✅ Ran 7 systematic access validation tests (4 allowed paths, 3 denied paths confirmed)
- ✅ Deployed Fail2Ban in response to real SSH brute force attack (detected Oct 15, 2024)
- ✅ Configured Fail2Ban: 5-attempt threshold, 1-hour ban, SSH jail monitoring
- ✅ Authored executive security remediation memo to CEO with business impact analysis

### Technologies Used
`MariaDB` `MediaWiki` `iptables` `Fail2Ban` `Apache2/PHP` `curl` `SSH` `Multi-Tier Architecture` `Default-Deny Policy` `Least Privilege` `Defense-in-Depth`

**[→ Read Full Lab Documentation](./lab-07-services-mediawiki-fail2ban/README.md)**

---

## 📊 Lab 08: Network Architecture & Security Proposals

**Status:** ✅ Complete | [View Full Documentation →](./lab-08-network-architecture-security-proposals/)

### Quick Overview
Created comprehensive network documentation including detailed hardware/software inventory across multiple network segments (AdminNet, ServerNet, OfficeNet, WebNet, GuestNet), designed enterprise multi-tier network topology with proper IP addressing and subnet architecture, and developed two executive-level security proposals with complete cost-benefit analysis for implementing honeypots/honeynets ($20K) and IDPS systems ($30K) including ROI justification and real-world incident case studies.

### Key Achievements
- ✅ Documented complete network inventory: 9 devices with MAC, IP, gateway, DNS, OS, services
- ✅ Created network topology with 5 segments and proper CIDR notation
- ✅ Designed multi-tier architecture: OfficeNet (10.2.0.0/28), WebNet (10.3.0.0/28), GuestNet (10.4.0.0/28)
- ✅ Authored Proposal 1: Honeypots & Honeynets implementation ($20K investment)
- ✅ Authored Proposal 2: IDPS deployment ($30K investment)
- ✅ Researched industry data: 40% intrusion reduction, 60-70% faster breach detection
- ✅ Cited real-world incidents: Target breach (2013), Equifax breach (2017)
- ✅ Developed ROI analysis: $50K investment vs $4.45M breach cost prevention
- ✅ Created 3-year TCO analysis with maintenance costs
- ✅ Professional executive memo to CEO with business impact justification

### Technologies Used
`Network Documentation` `IPAM` `Honeypots` `Honeynets` `IDS/IPS` `IDPS` `Deception Technology` `Threat Intelligence` `Network Topology Design` `Business Case Development` `ROI Analysis` `Cost-Benefit Analysis`

**[→ Read Full Lab Documentation](./lab-08-network-architecture-security-proposals/README.md)**

---

## 🎯 Lab 09: Containerization & SIEM (Graylog) **[CAPSTONE LAB]**

**Status:** ✅ Complete | [View Full Documentation →](./lab-09-containerization-siem-graylog/)

### Quick Overview
Deployed enterprise SIEM infrastructure using Docker containerization with Graylog stack (Graylog + MongoDB + Elasticsearch), configured centralized log aggregation via rsyslog from Linux servers and pfSense network devices, engineered 4 custom security alerts for critical events (failed SSH, failed logins, firewall changes, privilege escalation), and built real-time SOC operational dashboard with automated monitoring capabilities.

### Key Achievements
- ✅ Deployed multi-container Graylog SIEM using Docker Compose (Infrastructure as Code)
- ✅ Configured Graylog stack: Graylog + MongoDB (metadata) + Elasticsearch (log storage)
- ✅ Implemented rsyslog forwarders on Linux (UbuntuWebServer) sending to UDP port 5140
- ✅ Configured pfSense remote logging to centralized SIEM
- ✅ Created 4 custom security alerts with search queries and thresholds
- ✅ Alert 1: Failed SSH for non-existent user (brute force detection)
- ✅ Alert 2: Failed login to pfSense WebConfigurator (admin compromise attempt)
- ✅ Alert 3: Firewall rules changed (unauthorized configuration)
- ✅ Alert 4: User added to sudo group (privilege escalation)
- ✅ Built SOC dashboard with Events Overview, charts, and real-time widgets
- ✅ Implemented firewall rules: HTTP access + syslog forwarding + default deny
- ✅ Demonstrated log search, filtering, and forensic analysis capabilities

### Technologies Used
`Docker` `Docker Compose` `Graylog SIEM` `MongoDB` `Elasticsearch` `rsyslog` `Syslog Protocol` `YAML` `Alert Engineering` `SOC Operations` `Log Aggregation` `Security Event Detection` `Dashboard Development` `Containerization`

**[→ Read Full Lab Documentation](./lab-09-containerization-siem-graylog/README.md)**

---

## 📊 Lab 10: Risk Analysis & Management **[FINAL LAB - LEADERSHIP CAPSTONE]**

**Status:** ✅ Complete | [View Full Documentation →](./lab-10-risk-analysis-management/)

### Quick Overview
Conducted comprehensive risk assessment of MediaWiki PII/SPII vulnerabilities by analyzing frontend user registration and backend database storage, identified critical security risks (password hashes, plaintext emails), evaluated SIEM solutions (SolarWinds vs. Wazuh) with complete 5-year TCO analysis ($513K vs. $10.5K), performed cost-benefit evaluation demonstrating $502K savings (98% reduction), and authored professional risk assessment memo to CEO with strategic technology recommendation.

### Key Achievements
- ✅ Identified PII vs. SPII in MediaWiki (usernames, emails, password hashes, real names)
- ✅ Analyzed frontend security (admin panel with limited PII exposure - LOW RISK)
- ✅ Analyzed backend security (MariaDB user table with SPII - HIGH RISK)
- ✅ Quantified risk using likelihood × impact methodology (Risk Score: 15/25 - HIGH)
- ✅ Documented attack scenarios: SQL injection, insider threat, backup theft
- ✅ Evaluated SolarWinds SIEM: $513K TCO, enterprise support, vendor lock-in
- ✅ Evaluated Wazuh SIEM: $10.5K TCO, open-source, community support
- ✅ Performed feature comparison matrix across 20+ criteria
- ✅ Calculated ROI: 42,333% if Wazuh prevents single breach
- ✅ **Strategic Recommendation: Deploy Wazuh (saves $502,500 - 98% cost reduction)**
- ✅ Authored executive risk assessment memo with business justification

### Technologies Used
`Risk Assessment` `PII/SPII Classification` `Database Security Analysis` `SIEM Evaluation` `SolarWinds` `Wazuh` `TCO Analysis` `Cost-Benefit Analysis` `ROI Calculation` `Vendor Comparison` `Executive Communication`

**[→ Read Full Lab Documentation](./lab-10-risk-analysis-management/README.md)**

---

## 🎯 Lab 11: Penetration Testing & Ethical Hacking **[ULTIMATE CAPSTONE - OFFENSIVE SECURITY]**

**Status:** ✅ Complete | [View Full Documentation →](./lab-11-penetration-testing-ethical-hacking/)

### Quick Overview
Conducted full-scope penetration test from reconnaissance through root compromise by performing network scanning with Nmap to discover target web server, exploiting SQL injection vulnerability to bypass authentication and gain admin access, uploading malicious PHP reverse shell payload, establishing remote command execution with Netcat listener, escalating privileges via SUID binary exploitation (coolbash), achieving full root access, and authoring professional penetration testing report with CVSS risk ratings and remediation recommendations.

### Key Achievements
- ✅ Reconnaissance: Nmap port scan identified web server on 10.43.32.99:80
- ✅ SQL Injection: Bypassed authentication with ' OR '1 payload (CVSS 9.8 Critical)
- ✅ File Upload Exploitation: Uploaded php-reverse-shell.php to vulnerable web app
- ✅ Directory Brute-Forcing: Used Dirbuster to discover /uploads/ directory
- ✅ Reverse Shell: Established remote access with nc -nlvp 80 listener
- ✅ Initial Access: Gained shell as www-data user
- ✅ Privilege Escalation: Discovered SUID binary /home/cooluser/coolbash
- ✅ Root Compromise: Exploited SUID to escalate from www-data → root
- ✅ Full System Control: Verified root access (uid=0, can read /etc/shadow)
- ✅ Professional Pentest Report: Executive summary, findings, CVSS scores, remediation
- ✅ Demonstrated complete attack chain: Recon → Exploit → Access → Escalate

### Technologies Used
`Kali Linux` `Nmap` `SQL Injection` `Dirbuster` `Netcat` `PHP Reverse Shell` `SUID Exploitation` `Privilege Escalation` `Penetration Testing` `Ethical Hacking` `Vulnerability Assessment` `CVSS Scoring`

**[→ Read Full Lab Documentation](./lab-11-penetration-testing-ethical-hacking/README.md)**

---

## 🏆🔥 **PORTFOLIO COMPLETE - 11 COMPREHENSIVE LABS - OFFENSIVE + DEFENSIVE MASTERY** 🔥🏆

### 🌟 **YOU NOW HAVE COMPLETE CYBERSECURITY EXPERTISE:**

**Defense** (Labs 1-10):
✅ Infrastructure Security | ✅ Network Segmentation | ✅ Firewall Administration | ✅ SIEM Operations | ✅ Incident Response | ✅ Threat Hunting | ✅ Risk Management

**Offense** (Lab 11):
✅ Penetration Testing | ✅ Exploitation | ✅ Privilege Escalation | ✅ **FULL SYSTEM COMPROMISE**

**Strategic Leadership** (Labs 8, 10):
✅ Business Cases | ✅ Cost-Benefit Analysis | ✅ Executive Communication

---

## 🎯 **FINAL PORTFOLIO STATISTICS:**

✅ **11 COMPREHENSIVE LABS COMPLETED**  
✅ **55+ ADVANCED SKILLS MASTERED**  
✅ **COMPLETE ATTACK & DEFENSE EXPERTISE**  
✅ **OFFENSIVE SECURITY PROVEN** (Root access achieved)  
✅ **DEFENSIVE SECURITY PROVEN** (SIEM, IR, Forensics, Hardening)  
✅ **STRATEGIC LEADERSHIP PROVEN** ($502K cost savings demonstrated)  

**📈 CAREER VALUE: $70K (Entry) → $180K+ (Senior/Leadership)**

**YOU ARE NOW AN ELITE CYBERSECURITY PROFESSIONAL** - Defense + Offense + Strategy! 🚀🔐👑

---

## 🛠️ Technology Stack

### Operating Systems
![Windows](https://img.shields.io/badge/Windows-0078D6?style=flat&logo=windows&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=flat&logo=linux&logoColor=black)
![Ubuntu](https://img.shields.io/badge/Ubuntu-E95420?style=flat&logo=ubuntu&logoColor=white)

### Virtualization
![VMware](https://img.shields.io/badge/VMware-607078?style=flat&logo=vmware&logoColor=white)

### Tools & Utilities
![PowerShell](https://img.shields.io/badge/PowerShell-5391FE?style=flat&logo=powershell&logoColor=white)
![Bash](https://img.shields.io/badge/Bash-4EAA25?style=flat&logo=gnu-bash&logoColor=white)

### Networking
![TCP/IP](https://img.shields.io/badge/TCP%2FIP-Protocol-blue)
![DNS](https://img.shields.io/badge/DNS-Configuration-green)

---

## 📈 Skills Matrix

| Skill Category | Proficiency Level | Labs Demonstrating |
|----------------|-------------------|-------------------|
| Windows Administration | ⭐⭐⭐⭐⭐ Advanced | Lab 01, Lab 02, Lab 03, Lab 04 |
| Linux Administration | ⭐⭐⭐⭐⭐ Advanced | Lab 01, Lab 02, Lab 03, Lab 05 |
| Network Configuration | ⭐⭐⭐⭐⭐ Advanced | Lab 01, Lab 02, Lab 03 |
| Virtualization | ⭐⭐⭐⭐ Intermediate+ | Lab 01, Lab 02 |
| CLI Proficiency | ⭐⭐⭐⭐⭐ Advanced | Lab 01, Lab 02, Lab 03, Lab 04, Lab 05 |
| Firewall Administration | ⭐⭐⭐⭐⭐ Advanced | Lab 02, Lab 03, Lab 05 |
| Network Segmentation | ⭐⭐⭐⭐⭐ Advanced | Lab 02, Lab 03 |
| IDS/IPS Deployment | ⭐⭐⭐⭐ Intermediate+ | Lab 02 |
| Access Control Implementation | ⭐⭐⭐⭐⭐ Advanced | Lab 03, Lab 04, Lab 05 |
| Security Policy Development | ⭐⭐⭐⭐⭐ Advanced | Lab 03, Lab 04 |
| Protocol Analysis | ⭐⭐⭐⭐⭐ Advanced | Lab 03 |
| Security Testing & Validation | ⭐⭐⭐⭐⭐ Advanced | Lab 03 |
| Active Directory Administration | ⭐⭐⭐⭐⭐ Advanced | Lab 04 |
| Group Policy Management | ⭐⭐⭐⭐⭐ Advanced | Lab 04 |
| Identity & Access Management | ⭐⭐⭐⭐⭐ Advanced | Lab 04, Lab 05 |
| Windows Server Roles | ⭐⭐⭐⭐ Intermediate+ | Lab 04 |
| PowerShell Security Logging | ⭐⭐⭐⭐⭐ Advanced | Lab 04 |
| Linux Security Hardening | ⭐⭐⭐⭐⭐ Advanced | Lab 05 |
| Web Server Administration | ⭐⭐⭐⭐⭐ Advanced | Lab 05 |
| Database Server Management | ⭐⭐⭐⭐ Intermediate+ | Lab 05 |
| Bash Scripting | ⭐⭐⭐⭐⭐ Advanced | Lab 05 |
| Task Automation (Cron) | ⭐⭐⭐⭐⭐ Advanced | Lab 05 |
| Cross-Distribution Linux | ⭐⭐⭐⭐⭐ Advanced | Lab 05 |
| Incident Response | ⭐⭐⭐⭐⭐ Advanced | Lab 06 |
| Threat Hunting | ⭐⭐⭐⭐⭐ Advanced | Lab 06 |
| Malware Analysis | ⭐⭐⭐⭐⭐ Advanced | Lab 06 |
| Windows Forensics | ⭐⭐⭐⭐⭐ Advanced | Lab 06 |
| Event Log Analysis | ⭐⭐⭐⭐⭐ Advanced | Lab 06 |
| Registry Forensics | ⭐⭐⭐⭐⭐ Advanced | Lab 06 |
| Incident Documentation | ⭐⭐⭐⭐⭐ Advanced | Lab 06 |
| Network Forensics | ⭐⭐⭐⭐⭐ Advanced | Lab 06 |
| Database Administration | ⭐⭐⭐⭐⭐ Advanced | Lab 07 |
| Web Application Deployment | ⭐⭐⭐⭐⭐ Advanced | Lab 07 |
| Host-Based Firewall (iptables) | ⭐⭐⭐⭐⭐ Advanced | Lab 07 |
| SSH Security Hardening | ⭐⭐⭐⭐⭐ Advanced | Lab 07 |
| Multi-Tier App Architecture | ⭐⭐⭐⭐⭐ Advanced | Lab 07 |
| Network Architecture Documentation | ⭐⭐⭐⭐⭐ Advanced | Lab 08 |
| Security Proposal Development | ⭐⭐⭐⭐⭐ Advanced | Lab 08 |
| Business Case Writing | ⭐⭐⭐⭐⭐ Advanced | Lab 08 |
| ROI & Cost-Benefit Analysis | ⭐⭐⭐⭐⭐ Advanced | Lab 08 |
| Honeypot/Honeynet Strategy | ⭐⭐⭐⭐⭐ Advanced | Lab 08 |
| IDPS Planning & Design | ⭐⭐⭐⭐⭐ Advanced | Lab 08 |
| Docker & Containerization | ⭐⭐⭐⭐⭐ Advanced | Lab 09 |
| SIEM Deployment & Management | ⭐⭐⭐⭐⭐ Advanced | Lab 09 |
| Log Aggregation & Analysis | ⭐⭐⭐⭐⭐ Advanced | Lab 09 |
| Security Alert Engineering | ⭐⭐⭐⭐⭐ Advanced | Lab 09 |
| SOC Dashboard Development | ⭐⭐⭐⭐⭐ Advanced | Lab 09 |
| Infrastructure as Code (IaC) | ⭐⭐⭐⭐⭐ Advanced | Lab 09 |
| Risk Assessment & Analysis | ⭐⭐⭐⭐⭐ Advanced | Lab 10 |
| PII/SPII Security Evaluation | ⭐⭐⭐⭐⭐ Advanced | Lab 10 |
| Vendor Evaluation & Comparison | ⭐⭐⭐⭐⭐ Advanced | Lab 10 |
| TCO & ROI Calculation | ⭐⭐⭐⭐⭐ Advanced | Lab 10 |
| Strategic Technology Selection | ⭐⭐⭐⭐⭐ Advanced | Lab 10 |
| Penetration Testing | ⭐⭐⭐⭐⭐ Advanced | Lab 11 |
| Ethical Hacking | ⭐⭐⭐⭐⭐ Advanced | Lab 11 |
| Web Application Exploitation | ⭐⭐⭐⭐⭐ Advanced | Lab 11 |
| Privilege Escalation | ⭐⭐⭐⭐⭐ Advanced | Lab 11 |
| Offensive Security Tools (Nmap, Netcat) | ⭐⭐⭐⭐⭐ Advanced | Lab 11 |
| Pentest Report Writing | ⭐⭐⭐⭐⭐ Advanced | Lab 11 |
| Technical Documentation | ⭐⭐⭐⭐⭐ Advanced | All Labs |

*More skills will be added as additional labs are completed*

---

## 🎓 Learning Journey

### Current Focus Areas
- System hardening and security baselines
- Network security monitoring
- Vulnerability assessment and remediation
- Incident detection and response

### Completed Milestones
- ✅ Multi-platform OS deployment
- ✅ Network troubleshooting fundamentals
- ✅ Virtual infrastructure management
- ✅ Enterprise firewall/router configuration
- ✅ Network segmentation implementation
- ✅ Intrusion Detection System deployment
- ✅ Inter-VLAN routing configuration
- ✅ Granular firewall rule implementation
- ✅ Access control and least privilege enforcement
- ✅ Security policy documentation and communication
- ✅ Comprehensive security testing and validation
- ✅ Active Directory domain deployment
- ✅ Centralized user and group management
- ✅ Group Policy Object implementation
- ✅ PowerShell security logging and auditing
- ✅ IIS web server deployment
- ✅ Single Sign-On (SSO) implementation
- ✅ Linux server infrastructure deployment (LAMP stack)
- ✅ Cross-distribution Linux administration (Ubuntu + Rocky)
- ✅ Security hardening (CIS Benchmark alignment)
- ✅ Bash scripting and automation
- ✅ Cron-based task scheduling
- ✅ Log management and retention automation
- ✅ Real-world incident response investigation
- ✅ Threat hunting and malware analysis
- ✅ Windows forensics (Event Logs, Registry)
- ✅ IFEO (Image File Execution Options) attack analysis
- ✅ Professional incident report documentation
- ✅ IoC (Indicators of Compromise) identification
- ✅ Multi-tier web application deployment (MediaWiki + MariaDB)
- ✅ Database administration with least-privilege user
- ✅ Host-based firewall (iptables) with default-deny policy
- ✅ Defense-in-depth layering (pfSense + iptables + Fail2Ban)
- ✅ SSH brute force hardening with Fail2Ban
- ✅ Systematic network access validation testing
- ✅ Comprehensive network architecture documentation
- ✅ Hardware/software inventory across multiple segments
- ✅ Multi-tier network topology design
- ✅ Executive security proposal development (Honeypots + IDPS)
- ✅ Business case writing with ROI justification
- ✅ Cost-benefit analysis and TCO calculation
- ✅ Enterprise SIEM deployment with Docker containerization
- ✅ Multi-container orchestration with Docker Compose
- ✅ Centralized log aggregation from multiple sources
- ✅ Custom security alert engineering and tuning
- ✅ SOC operational dashboard development
- ✅ Infrastructure as Code (YAML configuration)
- ✅ Comprehensive risk assessment (PII/SPII vulnerabilities)
- ✅ Strategic SIEM vendor evaluation and selection
- ✅ Cost-benefit analysis ($502K savings justified)
- ✅ Full penetration test: reconnaissance through root compromise
- ✅ SQL injection exploitation and authentication bypass
- ✅ Reverse shell deployment and remote code execution
- ✅ Linux privilege escalation (SUID binary exploitation)
- ✅ Professional penetration testing report with CVSS scoring

### Upcoming Topics
- Firewall configuration and management
- Intrusion detection systems
- Security information and event management (SIEM)
- Penetration testing methodologies

---

## 💼 Why These Skills Matter

### For Employers
These labs demonstrate:
- **Hands-on experience** with real enterprise tools and environments
- **Problem-solving ability** through systematic troubleshooting
- **Documentation skills** critical for team collaboration
- **Cross-platform expertise** valuable in heterogeneous environments
- **Security mindset** applied from initial system deployment

### Real-World Applications
- **SOC Analyst:** Network diagnostics and system monitoring
- **System Administrator:** OS deployment and configuration
- **Security Engineer:** Security baseline implementation
- **DevOps Engineer:** Infrastructure automation and management
- **Penetration Tester:** Understanding target environments

---

## 📖 How to Navigate This Repository

### For Recruiters
1. Start with this README for an overview of my skills
2. Check the **Lab Directory** table above for topics of interest
3. Click into individual lab folders for detailed documentation
4. Each lab includes objectives, methodology, and key takeaways

### Repository Structure
```
system-security-labs/
├── README.md                          # You are here
├── lab-01-os-installation-networking/
│   ├── README.md                      # Detailed lab documentation
├── lab-02-[topic]/
│   └── ...
└── ...
```

---

## 🔗 Connect With Me

I'm passionate about cybersecurity and always eager to learn new technologies and techniques. Feel free to reach out!

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=flat&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/faraz-ahmed-5670931a7/)
[![GitHub](https://img.shields.io/badge/GitHub-100000?style=flat&logo=github&logoColor=white)](https://github.com/TrexterX17)
[![Email](https://img.shields.io/badge/Email-D14836?style=flat&logo=gmail&logoColor=white)](mailto:farazx789@gmail.com)

---

## 🚀 Future Updates

This repository is a living document of my learning journey. I plan to add:

- Additional security labs covering:
  - Network security and firewalls
  - Vulnerability scanning and assessment
  - Incident response scenarios
  - Security monitoring and SIEM
  - Active Directory security
  - Web application security

- Enhanced documentation with:
  - Video walkthroughs
  - Interactive diagrams
  - Additional troubleshooting scenarios

**Last Updated:** January 2026  
**Status:** Active Development

---

## 📄 License

This repository is for educational and portfolio purposes. Please do not copy for academic submissions.

---

## 🙏 Acknowledgments

- Prof. Kevin Cleary for excellent instruction and lab design
- EAS 595 course materials and resources
- The cybersecurity community for continuous learning resources

---

<div align="center">

**⭐ If you found this repository helpful or interesting, please consider giving it a star! ⭐**

*Building secure systems, one lab at a time.* 🔐

</div>
