# Lab 07: Service Deployment, MediaWiki & Security Hardening

## 📋 Lab Overview

**Course:** EAS 595 - System Security  
**Lab Title:** Services (MediaWiki Deployment & Fail2Ban)  
**Difficulty Level:** Advanced  
**Completion Date:** October 16th, 2024

### Objective
This lab demonstrates end-to-end web application deployment by configuring a MariaDB database backend on Rocky Linux, deploying and integrating MediaWiki on Ubuntu, implementing host-based firewall rules with iptables, validating network access controls across all segments, and hardening SSH with Fail2Ban. This simulates a real enterprise application deployment with proper database separation, security validation, and incident-driven remediation.

---

## 🎯 Learning Outcomes

By completing this lab, I demonstrated proficiency in:

- **Database Administration:** Creating databases, users, and granular privilege grants in MariaDB
- **Web Application Deployment:** Full MediaWiki installation and integration with a remote database
- **Multi-Tier Application Architecture:** Connecting a web application layer to a separated database layer
- **Host-Based Firewall (iptables):** Implementing Linux-native access control rules on the web server
- **Network Access Validation:** Systematically testing connectivity and access denial across network segments
- **SSH Security Hardening:** Deploying Fail2Ban to mitigate brute force attacks
- **Security Remediation Documentation:** Writing a professional memo identifying and remediating vulnerabilities
- **Defense-in-Depth:** Layering pfSense firewall rules with host-based iptables rules

---

## 🛠️ Tools & Technologies Used

### Database & Web Application
| Tool | Role | Server |
|------|------|--------|
| **MariaDB** | Relational database engine | RockyDBServer |
| **MediaWiki** | Open-source wiki platform | UbuntuWebServer |
| **Apache2 + PHP** | Web server stack (deployed in Lab 05) | UbuntuWebServer |
| **LocalSettings.php** | MediaWiki configuration file | UbuntuWebServer |

### Security & Firewall Tools
| Tool | Role | Server |
|------|------|--------|
| **iptables** | Host-based Linux firewall | UbuntuWebServer |
| **Fail2Ban** | SSH brute force mitigation | UbuntuWebServer |
| **pfSense** | Network-level firewall | Router |

### Validation & Testing
- **curl** - HTTP connectivity testing from command line
- **ssh** - Secure Shell for remote access testing
- **Browser** - Web-based access verification from multiple network segments

---

## 🏗️ Lab Environment Architecture

### Network Topology

```
                        [Internet]
                            |
                      [pfSense Router]
                   (Network Firewall Rules)
                            |
            +---------------+---------------+
            |                               |
        [AdminNet]                     [ServerNet]
        10.42.32.0/24                 10.43.32.0/24
            |                               |
     +------+------+           +-----------+-----------+
     |      |      |           |           |           |
[Win10] [Ubuntu] [Other]  [ADServer] [Ubuntu]    [Rocky]
 .12     .7               10.43.32.10 WebServer   DBServer
                                    10.43.32.20  10.43.32.30

                        [External Network - Gretzky Red]
                                    |
                              [OutsideDevice]
                           (Simulated External)

APPLICATION FLOW:
  Browser → UbuntuWebServer (Apache/PHP/MediaWiki) → RockyDBServer (MariaDB)
  Port 80/443                                        Port 3306
```

### Application Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    CLIENT LAYER                          │
│  Win10Client    UbuntuClient    OutsideDevice           │
│  (AdminNet)     (AdminNet)      (Gretzky Red)           │
└───────────────────────┬─────────────────────────────────┘
                        │  HTTP (Port 80)
                        ▼
┌─────────────────────────────────────────────────────────┐
│              PRESENTATION / APPLICATION LAYER            │
│  UbuntuWebServer (10.43.32.20)                          │
│  ├── Apache2 (Web Server)                               │
│  ├── PHP (Application Runtime)                          │
│  ├── MediaWiki (Wiki Application)                       │
│  ├── iptables (Host Firewall)                           │
│  └── Fail2Ban (SSH Protection)                          │
└───────────────────────┬─────────────────────────────────┘
                        │  MySQL Protocol (Port 3306)
                        ▼
┌─────────────────────────────────────────────────────────┐
│                    DATA LAYER                            │
│  RockyDBServer (10.43.32.30)                            │
│  └── MariaDB                                            │
│       ├── Database: wiki_webdb                          │
│       └── User: wiki_nonuser (remote access)            │
└─────────────────────────────────────────────────────────┘
```

### Access Control Summary

| Source | Destination | Access | Method |
|--------|-------------|--------|--------|
| AdminNet | pfSense WebUI | ✅ Allowed | pfSense rule (HTTPS 443) |
| AdminNet | UbuntuWebServer | ✅ Allowed | pfSense + iptables (HTTP, SSH) |
| OutsideDevice | MediaWiki | ✅ Allowed | pfSense rule (HTTP 80) |
| ServerNet → AdminNet | Any | ❌ Blocked | pfSense rule |
| OutsideDevice → ServerNet | SSH/Admin | ❌ Blocked | pfSense rule |
| OutsideDevice → AdminNet | SSH/Admin | ❌ Blocked | pfSense rule |
| UbuntuWebServer → RockyDBServer | MariaDB | ✅ Allowed | iptables (port 3306) |

---

## 📝 Methodology & Implementation

### Phase 1: Database Configuration on RockyDBServer

#### Understanding the Database Layer

**Why a Separate Database Server?**
Separating web and database services is a foundational enterprise architecture principle:
- **Security:** Database not directly exposed to client networks
- **Performance:** Dedicated CPU/memory for query processing
- **Scalability:** Scale web and database tiers independently
- **Compliance:** Isolate sensitive data behind additional network controls
- **Fault Isolation:** Web server failure does not affect database

**MariaDB Key Concepts:**
- **Database:** Container for tables and application data
- **User:** Account that connects to MariaDB with specific privileges
- **Privileges:** Granular permissions (SELECT, INSERT, UPDATE, DELETE, etc.)
- **Remote Access:** Users can connect from other servers using `@'%'` or specific IP

#### Task 1.1: Create the Wiki Database

**Command:**
```sql
CREATE DATABASE wiki_webdb;
```

**What This Does:**
- Creates a new, empty database named `wiki_webdb`
- This is the dedicated container where MediaWiki stores all its data
- Tables (pages, users, revisions, etc.) will be created automatically by MediaWiki during setup

**Verification:**
```sql
SHOW DATABASES;
-- Output includes: wiki_webdb
```

**Naming Convention Best Practice:**
- Descriptive: `wiki_webdb` clearly identifies purpose
- Underscore separated: Readable and portable
- Avoid spaces or special characters
- Production: Consider prefixing with environment (`prod_wiki_db`, `dev_wiki_db`)

#### Task 1.2: Create a Non-Root Database User

**Command:**
```sql
CREATE USER 'wiki_nonuser'@'%' IDENTIFIED BY 'password';
```

**Breakdown:**
- **wiki_nonuser** - Username for MediaWiki to authenticate with
- **@'%'** - The `%` wildcard means this user can connect from ANY host
  - More secure alternative: `@'10.43.32.20'` (restrict to UbuntuWebServer IP only)
- **IDENTIFIED BY 'password'** - Sets the account password

**Why Not Use Root?**
This is a critical application of the **Principle of Least Privilege**:
- Root has full access to ALL databases on the server
- A compromised web application would give attacker full database control
- `wiki_nonuser` will only have access to `wiki_webdb`
- If the web app is breached, damage is limited to one database

**Production Hardening:**
```sql
-- Restrict to specific source IP (more secure than %)
CREATE USER 'wiki_nonuser'@'10.43.32.20' IDENTIFIED BY 'StrongP@ssw0rd!2024';

-- Use a strong password (not 'password')
-- Rotate credentials regularly
-- Use SSL for database connections
```

#### Task 1.3: Grant Privileges to the User

**Command:**
```sql
GRANT ALL PRIVILEGES ON wiki_webdb.* TO 'wiki_nonuser'@'%';
```

**Breakdown:**
- **GRANT ALL PRIVILEGES** - Grants full access (SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, etc.)
- **ON wiki_webdb.*** - Only on the `wiki_webdb` database (the `*` means all tables within it)
- **TO 'wiki_nonuser'@'%'** - Applied to the user we just created

**Why ALL PRIVILEGES?**
MediaWiki needs full database access to:
- CREATE tables during installation
- INSERT/UPDATE/DELETE wiki content
- CREATE indexes for search
- Manage its own schema

**Production: Granular Privileges (Best Practice):**
```sql
-- More restrictive (production recommended)
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, DROP
  ON wiki_webdb.* TO 'wiki_nonuser'@'10.43.32.20';

-- Apply changes
FLUSH PRIVILEGES;
```

**Verify Privileges:**
```sql
SHOW GRANTS FOR 'wiki_nonuser'@'%';
-- Output: GRANT ALL PRIVILEGES ON `wiki_webdb`.* TO `wiki_nonuser`@`%`
```

---

### Phase 2: MediaWiki Deployment on UbuntuWebServer

#### Understanding MediaWiki

**What is MediaWiki?**
- The same software that powers Wikipedia
- Open-source, PHP-based wiki platform
- Supports collaborative content creation and editing
- Used by enterprises for internal knowledge bases
- Requires: PHP, Apache (or Nginx), MySQL/MariaDB

**Use Cases:**
- Internal company knowledge base
- Technical documentation
- Team collaboration platform
- Project wikis
- Training materials

#### Task 2.1: Access MediaWiki Installation Wizard

**From any client browser (Win10Client used):**
```
http://<UbuntuWebServer IP>/mediawiki?useskin=vector
```
```
http://10.43.32.20/mediawiki?useskin=vector
```

**What `useskin=vector` Does:**
- Forces the Vector theme (Wikipedia's default skin)
- Clean, modern interface
- Better user experience than default theme

**Prerequisites Already Met (from Lab 05):**
- Apache2 running ✅
- PHP installed with all required modules ✅
- MediaWiki files deployed to web root ✅

#### Task 2.2: Configure Database Connection

**MediaWiki Installation Wizard - Database Settings:**

| Field | Value | Purpose |
|-------|-------|---------|
| Database Server | `10.43.32.30` | IP of RockyDBServer |
| Database Name | `wiki_webdb` | Database created in Task 1.1 |
| Database Username | `wiki_nonuser` | User created in Task 1.2 |
| Database Password | `password` | Password set in Task 1.2 |

**What Happens Behind the Scenes:**
1. MediaWiki connects to MariaDB on port 3306
2. Authenticates with `wiki_nonuser` credentials
3. Verifies access to `wiki_webdb`
4. Creates all required tables (page, revision, user, etc.)
5. Stores configuration in database

**Connection Flow:**
```
MediaWiki (PHP) → TCP Port 3306 → MariaDB Authentication → wiki_webdb
```

**Troubleshooting Connection Issues:**
- Verify RockyDBServer IP is correct
- Confirm MariaDB is listening on 0.0.0.0 (not just localhost)
- Check firewall rules allow port 3306 between servers
- Verify user credentials match exactly (case-sensitive)

#### Task 2.3: Configure MediaWiki Admin Account

**MediaWiki Installation Wizard - Admin Settings:**

| Field | Value | Purpose |
|-------|-------|---------|
| Wiki Name | `fahmed29` | Name displayed on wiki (UBIT name) |
| Admin Username | `sysadmin` | MediaWiki administrator account |
| Admin Password | `Change.me!` | Admin account password |

**Admin Account Privileges:**
- Full control over wiki content
- User management (create/delete wiki users)
- Configuration changes
- Page protection and deletion
- Wiki statistics and logs

**Production Security:**
- Use strong, unique admin password
- Enable two-factor authentication
- Limit admin accounts to necessary personnel
- Audit admin actions regularly

#### Task 2.4: Complete Installation and Deploy Configuration

**Post-Installation:**
- Congratulation page confirms successful setup
- **LocalSettings.php** file downloads automatically

**What is LocalSettings.php?**
- MediaWiki's main configuration file
- Contains database credentials, site settings, extensions
- **MUST be uploaded to web server** for MediaWiki to function
- Location: `/var/www/html/mediawiki/LocalSettings.php`

**Uploading LocalSettings.php:**
```bash
# Copy downloaded file to web server
scp LocalSettings.php sysadmin@10.43.32.20:/var/www/html/mediawiki/

# Set correct permissions
sudo chown www-data:www-data /var/www/html/mediawiki/LocalSettings.php
sudo chmod 640 /var/www/html/mediawiki/LocalSettings.php
```

**Security Note:**
LocalSettings.php contains database passwords. Never:
- Expose it via web browser
- Store it in version control
- Share it via unencrypted channels

#### Task 2.5: Verify MediaWiki is Functional

**Edit the Main Page:**
1. Log in with admin credentials (sysadmin / Change.me!)
2. Navigate to Main Page
3. Click Edit
4. Change title to `fahmed29` (UBIT name)
5. Save changes

**Purpose:**
Confirms:
- Full read/write access to wiki ✅
- Database connection working ✅
- PHP processing functional ✅
- Authentication system operational ✅

---

### Phase 3: Network Access Validation

#### Understanding the Validation Strategy

**Why Systematic Testing?**
- Confirms firewall rules work as intended
- Identifies misconfigurations before production
- Documents security posture for compliance
- Provides evidence of access control enforcement

**Testing Matrix:**
Every access path must be tested for both:
- ✅ **Allowed paths** (confirm access works)
- ❌ **Denied paths** (confirm access is blocked)

#### Task 3.1: Verify OutsideDevice Can Access MediaWiki

**Test:** Browser on OutsideDevice → MediaWiki

**URL:**
```
http://10.43.32.20/mediawiki?useskin=vector
```

**Expected Result:** ✅ MediaWiki homepage displays

**Why This Should Work:**
- pfSense rule allows HTTP (port 80) from external networks to ServerNet
- OutsideDevice simulates a legitimate external user accessing the wiki

**Security Implication:**
MediaWiki is intentionally exposed for public/external access, similar to Wikipedia itself.

#### Task 3.2: Verify AdminNet Can Access pfSense WebUI

**Test:** Win10Client browser → pfSense WebConfigurator

**URL:**
```
https://<pfSense IP>
```

**Expected Result:** ✅ pfSense login page displays

**Why This Should Work:**
- pfSense rule allows HTTPS (port 443) from AdminNet to firewall
- Administrative access restricted to trusted internal network

#### Task 3.3: Verify AdminNet Can Access UbuntuWebServer via HTTP

**Test:** Win10Client PowerShell → curl

**Command:**
```powershell
curl http://10.43.32.20
```

**Expected Result:** ✅ HTML response (Apache default or MediaWiki page)

**What curl Returns:**
- HTTP response headers
- HTML page source code
- Confirms port 80 is open and responding

#### Task 3.4: Verify AdminNet Can Access UbuntuWebServer via SSH

**Test:** Win10Client → SSH to UbuntuWebServer

**Command:**
```powershell
ssh sysadmin@10.43.32.20
```

**Expected Result:** ✅ SSH session established

**Why SSH Access Matters:**
- Administrators need remote management capability
- SSH provides encrypted command-line access
- Essential for server maintenance and troubleshooting

#### Task 3.5: Verify ServerNet CANNOT Access AdminNet

**Test:** UbuntuWebServer → SSH to Win10Client

**Command (from UbuntuWebServer):**
```bash
sudo ssh sysadmin@10.42.32.12
```

**Expected Result:** ❌ Connection denied/blocked

**Why This Should Be Blocked:**
- Servers should not initiate connections back to client workstations
- Prevents compromised server from attacking internal network
- Defense-in-depth: Even if server is breached, lateral movement is blocked

**Security Implication:**
If this test PASSED (connection succeeded), it would indicate a firewall misconfiguration allowing reverse connections — a significant security gap.

#### Task 3.6: Verify OutsideDevice CANNOT Access ServerNet via SSH

**Test:** OutsideDevice → SSH to pfSense/ServerNet

**Command (from OutsideDevice):**
```bash
ssh sysadmin@10.43.32.1
```

**Expected Result:** ❌ Connection blocked

**Why This Should Be Blocked:**
- External devices must not SSH directly into server infrastructure
- SSH brute force from internet is one of the most common attacks
- Only AdminNet should have SSH access to servers

#### Task 3.7: Verify OutsideDevice CANNOT Access AdminNet via SSH

**Test:** OutsideDevice → SSH to AdminNet

**Command (from OutsideDevice):**
```bash
ssh sysadmin@10.42.32.1
```

**Expected Result:** ❌ Connection blocked

**Why This Should Be Blocked:**
- External attackers must not reach internal workstations
- AdminNet contains sensitive systems (domain controller access)
- Network perimeter must be enforced

#### Access Validation Summary

```
✅ ALLOWED (Verified):
   OutsideDevice  → MediaWiki (HTTP)     ✅ Public wiki access
   AdminNet       → pfSense WebUI (HTTPS) ✅ Firewall management
   AdminNet       → WebServer (HTTP)      ✅ Web access
   AdminNet       → WebServer (SSH)       ✅ Server management

❌ BLOCKED (Verified):
   ServerNet      → AdminNet (SSH)        ❌ No reverse connections
   OutsideDevice  → ServerNet (SSH)       ❌ No external server access
   OutsideDevice  → AdminNet (SSH)        ❌ No external workstation access
```

---

### Phase 4: Host-Based Firewall (iptables) on UbuntuWebServer

#### Understanding iptables vs. pfSense

**Two-Layer Firewall Model (Defense-in-Depth):**

```
Internet → [pfSense] → Network → [iptables on server] → Application
           Layer 1                  Layer 2
           Network Firewall        Host Firewall
```

- **pfSense:** Controls traffic between network segments
- **iptables:** Controls traffic at the individual server level
- **Benefit:** Even if pfSense rule is misconfigured, iptables provides backup protection

**iptables Concepts:**

| Concept | Description |
|---------|-------------|
| **Chain** | Sequence of rules (INPUT, OUTPUT, FORWARD) |
| **INPUT** | Controls incoming traffic to this host |
| **OUTPUT** | Controls outgoing traffic from this host |
| **FORWARD** | Controls traffic passing through (routing) |
| **Rule** | Match criteria + action |
| **Target** | Action to take: ACCEPT, DROP, REJECT |
| **-A** | Append rule to end of chain |
| **-I** | Insert rule at beginning of chain |

#### Task 4.1: Allow HTTP Inbound (Port 80)

**Command:**
```bash
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
```

**Breakdown:**
- **-A INPUT** - Append to INPUT chain (incoming traffic)
- **-p tcp** - Match TCP protocol
- **--dport 80** - Destination port 80 (HTTP)
- **-j ACCEPT** - Allow the traffic

**Purpose:**
Allows web traffic to reach Apache/MediaWiki from any source that passes pfSense.

#### Task 4.2: Allow HTTPS Inbound (Port 443)

**Command:**
```bash
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT
```

**Purpose:**
Allows encrypted HTTPS traffic. Even if not currently configured with SSL certificate, this prepares for future HTTPS deployment.

#### Task 4.3: Allow Outbound MySQL to RockyDBServer

**Command:**
```bash
sudo iptables -A OUTPUT -p tcp -d 10.43.32.30 --dport 3306 -j ACCEPT
```

**Breakdown:**
- **-A OUTPUT** - Append to OUTPUT chain (outgoing traffic)
- **-d 10.43.32.30** - Destination IP: RockyDBServer only
- **--dport 3306** - MySQL/MariaDB port
- **-j ACCEPT** - Allow

**Purpose:**
MediaWiki needs to communicate with the database. This rule explicitly permits only the necessary outbound connection — to the specific database server on the specific port.

**Security Benefit:**
If the web server is compromised, the attacker cannot establish outbound connections to arbitrary destinations. Only port 3306 to 10.43.32.30 is allowed.

#### Task 4.4: Allow HTTP from Gretzky Core-Red Subnet

**Command:**
```bash
sudo iptables -A INPUT -p tcp -s 192.168.0.1/255.255.240.0 --dport 80 -j ACCEPT
```

**Breakdown:**
- **-s 192.168.0.1/255.255.240.0** - Source: Gretzky Core-Red subnet
- The subnet mask `255.255.240.0` = `/20` CIDR
- Matches source IPs in range: 192.168.0.0 - 192.168.15.255

**Purpose:**
Explicitly allows HTTP requests from the external Gretzky network (where OutsideDevice resides) to reach MediaWiki.

#### Task 4.5: Allow HTTP from Win10Client

**Command:**
```bash
sudo iptables -A INPUT -p tcp -s 10.42.32.12 --dport 80 -j ACCEPT
```

**Purpose:**
Specifically allows HTTP from the Win10Client workstation in AdminNet.

#### Task 4.6: Allow HTTP from UbuntuClient

**Command:**
```bash
sudo iptables -A INPUT -p tcp -s 10.42.32.7 --dport 80 -j ACCEPT
```

**Purpose:**
Specifically allows HTTP from the UbuntuClient workstation in AdminNet.

#### Task 4.7: Default Deny All (DROP)

**Command:**
```bash
sudo iptables -A INPUT -j DROP
```

**Purpose:**
This is the **critical final rule** — drops ALL traffic that does not match any previous ACCEPT rule.

**Why This Must Be Last:**
iptables processes rules top-to-bottom, sequentially:
1. Rule 1: Allow HTTP (80) → match? → ACCEPT
2. Rule 2: Allow HTTPS (443) → match? → ACCEPT
3. ...
4. **Final Rule: DROP everything else**

If DROP were first, ALL traffic would be blocked before reaching any ACCEPT rules.

**Security Principle:**
Default-deny with explicit allow = most secure posture. Only whitelisted traffic passes.

#### Task 4.8: Verify All iptables Rules

**Command:**
```bash
sudo iptables -L -v
```

**Output Format:**
```
Chain INPUT (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination
    0     0 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:80
    0     0 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:443
    0     0 ACCEPT     tcp  --  *      *       192.168.0.0/20       0.0.0.0/0            tcp dpt:80
    0     0 ACCEPT     tcp  --  *      *       10.42.32.12          0.0.0.0/0            tcp dpt:80
    0     0 ACCEPT     tcp  --  *      *       10.42.32.7           0.0.0.0/0            tcp dpt:80
    0     0 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0

Chain OUTPUT (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination
    0     0 ACCEPT     tcp  --  *      *       0.0.0.0/0            10.43.32.30          tcp dpt:3306
```

**Flags Explanation:**
- **-L** - List all rules
- **-v** - Verbose (show packet/byte counters, interface, source/destination)

**Production: Persist iptables Rules:**
```bash
# Save rules (Ubuntu)
sudo iptables-save > /etc/iptables/rules.v4

# Rules will be automatically restored on reboot
# Or manually restore:
sudo iptables-restore < /etc/iptables/rules.v4
```

---

### Phase 5: SSH Hardening with Fail2Ban

#### Understanding the Threat

**SSH Brute Force Attack:**
- Attacker repeatedly tries username/password combinations
- Automated tools (Hydra, Medusa) can try thousands of combinations per minute
- If successful: full shell access to server
- One of the most common attacks against internet-facing servers

**Evidence of Attack:**
- Recorded at 10:30 AM, October 15th, 2024
- Multiple failed SSH login attempts detected in auth.log
- UbuntuWebServer targeted specifically

**Log Evidence:**
```bash
sudo cat /var/log/auth.log | grep "Failed password"
# Output shows repeated attempts from attacker IP
```

#### Task 5.1: Install Fail2Ban

**Commands:**
```bash
sudo apt update
sudo apt install fail2ban
```

**What is Fail2Ban?**
- Intrusion prevention software
- Monitors log files for suspicious patterns
- Automatically bans IPs after repeated failures
- Works by adding temporary iptables rules
- Configurable per-service (SSH, Apache, etc.)

**How Fail2Ban Works:**
```
1. Attacker tries SSH login → FAIL
2. Fail2Ban monitors /var/log/auth.log
3. Detects failed attempt, increments counter
4. After maxretry failures → adds iptables DROP rule for attacker IP
5. Attacker blocked for bantime duration
6. After bantime expires → rule automatically removed
```

#### Task 5.2: Configure Fail2Ban for SSH

**Configuration File:**
```bash
sudo nano /etc/fail2ban/jail.local
```

**Why jail.local (not jail.conf)?**
- `jail.conf` - Default configuration (overwritten on updates)
- `jail.local` - User overrides (preserved during updates)
- Always edit `jail.local` for custom settings

**Configuration Added:**
```ini
[sshd]
enabled = true
port = 22
logpath = /var/log/auth.log
maxretry = 5
bantime = 3600
```

**Parameter Explanation:**

| Parameter | Value | Meaning |
|-----------|-------|---------|
| **enabled** | true | Activates SSH protection |
| **port** | 22 | Monitors standard SSH port |
| **logpath** | /var/log/auth.log | Log file to monitor for failures |
| **maxretry** | 5 | Ban IP after 5 failed attempts |
| **bantime** | 3600 | Ban duration: 3600 seconds (1 hour) |

**Additional Recommended Settings:**
```ini
[sshd]
enabled = true
port = 22
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
bantime = 3600
findtime = 600          # Detection window: 10 minutes
action = sendmail+whois[name=sshd, dest=admin@example.com]
                        # Email notification on ban
```

**Parameter Deep Dive:**
- **findtime = 600:** If 5 failures occur within 10 minutes → ban
- **action:** What to do when banning (block IP + send email)
- **filter = sshd:** Use the built-in SSH failure detection pattern

#### Task 5.3: Start and Enable Fail2Ban

**Commands:**
```bash
sudo systemctl start fail2ban
sudo systemctl enable fail2ban
```

- **start:** Begins monitoring immediately
- **enable:** Ensures Fail2Ban runs automatically on every reboot

#### Task 5.4: Verify Fail2Ban Status

**Command:**
```bash
sudo fail2ban-client status sshd
```

**Expected Output:**
```
Status for the SSHD jail:
|- Filter:
|  |- Currently failed: 0
|  |- Total failures: 12
|  `- Recently blocked: 0
`- Actions:
   |- Currently banned: 0
   |- Total number of bans: 2
   `- Banned IP list:
```

**Output Explanation:**
- **Currently failed:** Active failed attempts in current window
- **Total failures:** All-time failed attempts detected
- **Currently banned:** IPs actively blocked right now
- **Total bans:** All-time ban count
- **Banned IP list:** IPs currently blocked

**Additional Monitoring Commands:**
```bash
# Overall Fail2Ban status (all jails)
sudo fail2ban-client status

# View Fail2Ban logs
sudo cat /var/log/fail2ban.log

# Manually unban an IP (if needed)
sudo fail2ban-client set sshd unbanip 192.168.1.100

# Test by checking iptables for Fail2Ban rules
sudo iptables -L fail2ban-sshd -v
```

---

## 📝 Security Remediation Memo

### Memo to CEO: Security Deficiency Remediation Report

**To:** David Murray, CEO, UBNetDef
**From:** Faraz Ahmed, Security Engineer, UBNetDef SysSec
**Date:** October 16th, 2024
**Subject:** Security Deficiency Remediation Report

**Executive Summary:**
UBNetDef SysSec identified SSH brute force vulnerability on UbuntuWebServer at 10:30 AM on October 15th, 2024. Fail2Ban was deployed to automatically block repeated failed login attempts, limiting attacker access and protecting all systems connected to the infrastructure.

**Business Impact of SSH Brute Force:**
- Unauthorized access to web and database servers
- Potential data exfiltration or modification
- Service disruption (massive downtime)
- Compromise of sensitive organizational data
- Reputational damage

**Remediation Implemented:**
- Installed and configured Fail2Ban
- Set 5-attempt lockout threshold
- 1-hour ban duration for offending IPs
- Service enabled for automatic startup

**Ongoing Recommendations:**
- Monitor Fail2Ban logs regularly
- Consider changing SSH port from default 22
- Implement SSH key-based authentication (disable passwords)
- Deploy intrusion detection system (IDS) for broader monitoring

---

## 🎓 Key Takeaways & Skills Demonstrated

### Technical Skills

1. **Full-Stack Web Application Deployment**
   - Database backend configuration
   - Web application installation and integration
   - Multi-server application architecture
   - End-to-end connectivity validation

2. **Database Administration**
   - Created databases and users
   - Implemented granular privilege grants
   - Configured remote access controls
   - Applied principle of least privilege

3. **Host-Based Firewall Administration (iptables)**
   - Implemented INPUT and OUTPUT rules
   - Applied source/destination filtering
   - Implemented default-deny policy
   - Layered with network-level pfSense rules

4. **SSH Security Hardening**
   - Identified brute force vulnerability
   - Deployed Fail2Ban countermeasure
   - Configured detection and response parameters
   - Verified protection is active

5. **Network Access Control Validation**
   - Systematic testing of allowed and denied paths
   - Cross-segment access verification
   - Documented security posture comprehensively

6. **Professional Security Communication**
   - Executive memo with business impact
   - Technical findings with remediation steps
   - Referenced external resources

### Enterprise Architecture Concepts

**Defense-in-Depth:**
```
Layer 1: pfSense (network firewall)
Layer 2: iptables (host firewall)
Layer 3: Fail2Ban (application-level protection)
Layer 4: Least Privilege (database user permissions)
```

**Multi-Tier Application Architecture:**
- Presentation/Application tier separated from Data tier
- Each tier on isolated network segment
- Firewall rules govern inter-tier communication
- Independent scaling and failure domains

---

## 🔐 Security Implications & Real-World Impact

### Attack Scenarios Mitigated

**Scenario 1: SSH Brute Force (Mitigated by Fail2Ban)**
- Attacker sends thousands of login attempts
- After 5 failures, IP automatically banned for 1 hour
- Attack rendered ineffective

**Scenario 2: Compromised Web Server (Mitigated by iptables)**
- If attacker gains control of web server
- iptables OUTPUT rules restrict outbound connections
- Only allowed connection: MariaDB on port 3306
- Lateral movement blocked

**Scenario 3: SQL Injection (Mitigated by least privilege)**
- Attacker exploits MediaWiki vulnerability
- wiki_nonuser only has access to wiki_webdb
- Cannot access other databases or system tables
- Damage is contained to wiki data only

**Scenario 4: External Network Intrusion (Mitigated by pfSense)**
- OutsideDevice can only access MediaWiki (HTTP)
- Cannot SSH into servers or workstations
- Cannot access AdminNet or ServerNet management

### Compliance Mapping

| Framework | Requirement | How Addressed |
|-----------|-------------|---------------|
| **PCI-DSS** | Req 1.3: Inbound/outbound filtering | ✅ pfSense + iptables |
| **PCI-DSS** | Req 2.2: Harden system configurations | ✅ Fail2Ban + iptables |
| **PCI-DSS** | Req 7: Restrict access by business need | ✅ Least privilege DB user |
| **HIPAA** | Access Control (§164.312) | ✅ Multi-layer access control |
| **NIST** | PR.AC-4: Access permissions | ✅ Granular iptables + DB privileges |
| **CIS** | Benchmark 4.1: SSH hardening | ✅ Fail2Ban deployed |

---

## 🚀 Real-World Applications

### Career Roles Demonstrated

**Web Application Security Engineer ($90K-$130K):**
- Secure application deployment architecture
- Database access control and privilege management
- Host-based firewall implementation
- Application-level security hardening

**DevOps / Site Reliability Engineer ($95K-$140K):**
- Multi-tier application deployment
- Infrastructure security configuration
- Automated protection (Fail2Ban)
- Service monitoring and validation

**Cloud Security Engineer ($110K-$160K):**
- Security group configuration (equivalent to iptables)
- Network ACLs and segmentation
- Application-layer security
- IAM (equivalent to DB user privileges)

---

## 📚 Commands Reference

### MariaDB

```sql
-- Database management
CREATE DATABASE dbname;
SHOW DATABASES;
DROP DATABASE dbname;
USE dbname;

-- User management
CREATE USER 'user'@'%' IDENTIFIED BY 'password';
CREATE USER 'user'@'10.43.32.20' IDENTIFIED BY 'password';  -- IP-restricted
DROP USER 'user'@'%';
ALTER USER 'user'@'%' IDENTIFIED BY 'newpassword';

-- Privilege management
GRANT ALL PRIVILEGES ON dbname.* TO 'user'@'%';
GRANT SELECT, INSERT ON dbname.* TO 'user'@'%';  -- Granular
REVOKE ALL PRIVILEGES ON dbname.* FROM 'user'@'%';
SHOW GRANTS FOR 'user'@'%';
FLUSH PRIVILEGES;
```

### iptables

```bash
# View rules
sudo iptables -L -v              # Verbose listing
sudo iptables -L -v --line-numbers  # With line numbers

# INPUT rules (incoming)
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT     # Allow HTTP
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT    # Allow HTTPS
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT     # Allow SSH
sudo iptables -A INPUT -p tcp -s 10.42.32.0/24 --dport 22 -j ACCEPT  # SSH from subnet only
sudo iptables -A INPUT -j DROP                          # Default deny

# OUTPUT rules (outgoing)
sudo iptables -A OUTPUT -p tcp -d 10.43.32.30 --dport 3306 -j ACCEPT  # Allow MySQL

# Delete rules
sudo iptables -D INPUT 3                 # Delete rule #3
sudo iptables -F                         # Flush (clear) all rules

# Save and restore
sudo iptables-save > /etc/iptables/rules.v4
sudo iptables-restore < /etc/iptables/rules.v4
```

### Fail2Ban

```bash
# Installation
sudo apt install fail2ban

# Service management
sudo systemctl start fail2ban
sudo systemctl enable fail2ban
sudo systemctl status fail2ban

# Monitoring
sudo fail2ban-client status              # All jails
sudo fail2ban-client status sshd         # SSH jail only
sudo cat /var/log/fail2ban.log           # Fail2Ban log

# Management
sudo fail2ban-client set sshd unbanip 1.2.3.4  # Unban IP
sudo fail2ban-client reload                     # Reload config
```

---

## 💡 Lessons Learned

1. **Multi-Tier Architecture Requires Careful Connectivity Planning**
   - Web server must reach database (port 3306)
   - Clients must reach web server (port 80/443)
   - Each connection requires rules at multiple layers

2. **Default-Deny is the Gold Standard**
   - iptables DROP as final rule blocks everything not explicitly allowed
   - Most secure posture possible
   - Requires careful planning of all needed connections

3. **Defense-in-Depth Works in Practice**
   - pfSense blocks external SSH
   - iptables restricts outbound connections
   - Fail2Ban stops brute force attempts
   - DB least privilege limits breach impact
   - Each layer provides independent protection

4. **Systematic Validation is Essential**
   - Test every allowed path (confirm it works)
   - Test every denied path (confirm it's blocked)
   - Document results for compliance evidence

5. **SSH Brute Force is an Immediate Threat**
   - Real attack detected during lab
   - Fail2Ban deployment was incident-driven
   - Demonstrates real-world security operations

---

## 📸 Lab Evidence

All screenshots documented in original lab report:

**Database Configuration:**
- ✅ CREATE DATABASE wiki_webdb
- ✅ CREATE USER wiki_nonuser
- ✅ GRANT ALL PRIVILEGES

**MediaWiki Deployment:**
- ✅ Installation wizard (database settings)
- ✅ Admin account configuration
- ✅ LocalSettings.php download
- ✅ Main page edited to UBIT name

**Access Validation:**
- ✅ OutsideDevice accessing MediaWiki
- ✅ AdminNet accessing pfSense WebUI
- ✅ curl HTTP test to UbuntuWebServer
- ✅ SSH access from AdminNet
- ✅ SSH denied: ServerNet → AdminNet
- ✅ SSH denied: OutsideDevice → ServerNet
- ✅ SSH denied: OutsideDevice → AdminNet

**iptables Configuration:**
- ✅ All 7 firewall rules implemented
- ✅ Default DROP rule applied
- ✅ Rule verification (iptables -L -v)

**Fail2Ban:**
- ✅ Installation and configuration
- ✅ Service enabled and running
- ✅ Status verification

---

## 🏆 Lab Status

**Completion Status:** ✅ Successfully Completed  
**Database:** ✅ wiki_webdb created with non-root user  
**MediaWiki:** ✅ Fully deployed and functional  
**Access Validation:** ✅ 7 tests passed (4 allowed, 3 denied)  
**iptables:** ✅ 7 rules + default deny implemented  
**Fail2Ban:** ✅ SSH protection active  
**Security Memo:** ✅ Executive report delivered  

---

## 🔍 Troubleshooting Guide

**Issue 1: MediaWiki Cannot Connect to Database**
```
Solution:
- Verify MariaDB bind-address includes 0.0.0.0 (not just 127.0.0.1)
  sudo nano /etc/mysql/mariadb.conf.d/50-server.cnf
  bind-address = 0.0.0.0
- Confirm iptables allows port 3306 outbound
- Test connectivity: mysql -h 10.43.32.30 -u wiki_nonuser -p
- Check firewall logs on pfSense
```

**Issue 2: iptables Blocks Legitimate Traffic**
```
Solution:
- Review rules: sudo iptables -L -v --line-numbers
- Check if ACCEPT rule exists for needed port
- If missing, add before DROP rule:
  sudo iptables -I INPUT <line_number> -p tcp --dport <port> -j ACCEPT
- Flush and rebuild if severely misconfigured: sudo iptables -F
```

**Issue 3: Fail2Ban Bans Legitimate Admin**
```
Solution:
- Check banned IPs: sudo fail2ban-client status sshd
- Unban your IP: sudo fail2ban-client set sshd unbanip <your_IP>
- Add whitelist in jail.local:
  ignoreip = 127.0.0.1/8 10.42.32.0/24
- This prevents AdminNet IPs from ever being banned
```

**Issue 4: OutsideDevice Cannot Access MediaWiki**
```
Solution:
- Verify pfSense rule allows HTTP from external to ServerNet
- Check iptables on UbuntuWebServer allows source IP
- Test with curl from OutsideDevice: curl http://10.43.32.20
- Verify Apache is running: sudo systemctl status apache2
```

---

**Lab Completed By:** Faraz Ahmed  
**Institution:** University at Buffalo  
**Course:** EAS 595 - System Security  
**Instructor:** Prof. Kevin Cleary  
**Date:** October 16th, 2024