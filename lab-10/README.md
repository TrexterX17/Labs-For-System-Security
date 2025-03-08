# Lab 10: Containerization & SIEM (Graylog)

## 📋 Lab Overview
 
**Difficulty Level:** Expert  

### Objective
This lab demonstrates enterprise security operations center (SOC) capabilities by deploying Graylog SIEM using Docker containerization, configuring centralized log aggregation from Linux servers and network devices, creating custom security alerts for critical events, building operational dashboards for real-time monitoring, and implementing comprehensive firewall rules for SIEM infrastructure protection. This simulates a production SOC environment with automated threat detection and incident alerting.

---

## 🎯 Learning Outcomes

By completing this lab, I demonstrated proficiency in:

- **Containerization:** Deploying enterprise applications using Docker and Docker Compose
- **SIEM (Security Information and Event Management):** Graylog deployment and configuration
- **Centralized Logging:** Configuring rsyslog forwarders on Linux and pfSense
- **Log Analysis:** Searching and filtering logs for security events
- **Alert Engineering:** Creating custom security alerts for critical events
- **Dashboard Development:** Building operational dashboards for SOC monitoring
- **Security Event Detection:** Identifying failed SSH, failed logins, privilege escalation, configuration changes
- **Infrastructure as Code:** Using YAML for declarative container deployment
- **SOC Operations:** Real-world security monitoring workflows

---

## 🛠️ Tools & Technologies Used

### Containerization Stack
| Tool | Purpose | Version |
|------|---------|---------|
| **Docker** | Container runtime engine | Latest |
| **Docker Compose** | Multi-container orchestration | Latest |
| **YAML** | Infrastructure as Code configuration | - |

### SIEM & Logging
| Component | Role | Protocol/Port |
|-----------|------|---------------|
| **Graylog** | SIEM platform (log aggregation, analysis, alerting) | HTTP (9000), Syslog (5140) |
| **MongoDB** | Graylog metadata storage | Internal (27017) |
| **Elasticsearch** | Log storage and search engine | Internal (9200) |
| **rsyslog** | Log forwarder (Linux) | Syslog UDP/TCP (514, 5140) |

### Infrastructure
- **GraylogServer** - Ubuntu Server hosting Graylog stack (10.43.32.50)
- **UbuntuWebServer** - Log source (10.43.32.7)
- **pfSenseRouter** - Network device log source (10.42.32.1)
- **UbuntuClient** - SOC analyst workstation for dashboard access

---

## 🏗️ Lab Architecture

### SIEM Infrastructure Topology

```
                        [Internet]
                            |
                      [pfSense Router]
                      10.42.32.1 / 10.43.32.1
                      (Logs: firewall rules, auth)
                            |
                            |
            +---------------+---------------+
            |                               |
        [AdminNet]                     [ServerNet]
        10.42.32.0/24                 10.43.32.0/24
            |                               |
      [UbuntuClient]                  [GraylogServer]
       10.42.32.7                      10.43.32.50
       (SOC Analyst                    (SIEM Platform)
        Dashboard Access)                    |
                                      +-Docker Stack-+
                                      | Graylog      |
                                      | MongoDB      |
                                      | Elasticsearch|
                                      +--------------+
                                             ▲
                                             │ Syslog (UDP 5140)
                                             │
                                    +--------+--------+
                                    |                 |
                            [UbuntuWebServer]    [pfSense]
                             10.43.32.7          (forwarding logs)
                             (rsyslog)
```

### Graylog Architecture (Docker Compose)

```
┌─────────────────────────────────────────────────────┐
│              GraylogServer (10.43.32.50)            │
├─────────────────────────────────────────────────────┤
│                                                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────┐ │
│  │   Graylog    │  │  MongoDB     │  │ Elastic- │ │
│  │   Container  │◄─┤  Container   │  │ search   │ │
│  │              │  │              │  │ Container│ │
│  │ Port: 9000   │  │ Port: 27017  │  │ Port:9200│ │
│  │ (Web UI)     │  │ (Metadata)   │  │ (Logs)   │ │
│  └──────┬───────┘  └──────────────┘  └────▲─────┘ │
│         │                                   │       │
│         │                                   │       │
│         ▼                                   │       │
│  ┌──────────────────────────────────────────────┐  │
│  │  UDP Input 5140 (Syslog)                     │  │
│  │  Receives logs from rsyslog forwarders       │  │
│  └──────────────────────────────────────────────┘  │
│                                                     │
└─────────────────────────────────────────────────────┘
         ▲                           ▲
         │ Syslog                    │ Syslog
         │                           │
  [Linux Servers]            [Network Devices]
  (UbuntuWebServer)          (pfSenseRouter)
```

### Data Flow

```
1. Event occurs on monitored system
   (e.g., failed SSH login on UbuntuWebServer)
        ↓
2. rsyslog captures event from /var/log/auth.log
        ↓
3. rsyslog forwards to Graylog (UDP 5140)
        ↓
4. Graylog receives and parses syslog message
        ↓
5. Graylog stores in Elasticsearch
        ↓
6. Graylog evaluates against alert rules
        ↓
7. Alert triggered if conditions met
        ↓
8. Dashboard updated in real-time
        ↓
9. SOC analyst reviews on UbuntuClient browser
```

---

## 📝 Methodology & Implementation

### Phase 1: GraylogServer Deployment

#### Task 1.1: Initial Server Configuration

**Verify Network Configuration:**
```bash
ip r
```

**Expected Output:**
```
default via 10.43.32.1 dev ens33
10.43.32.0/24 dev ens33 proto kernel scope link src 10.43.32.50
```

**Configuration Details:**
- **IP Address:** 10.43.32.50/24
- **Gateway:** 10.43.32.1 (pfSense ServerNet interface)
- **Subnet:** ServerNet (10.43.32.0/24)
- **Purpose:** Centralized log collection from all infrastructure

**Update System:**
```bash
sudo apt update
sudo apt upgrade -y
```

**Why Update First:**
- Ensures latest security patches
- Prevents package conflicts
- Required for Docker installation

#### Task 1.2: VMware Tools Installation

**Install Open-VM-Tools:**
```bash
sudo apt install open-vm-tools
sudo systemctl enable --now open-vm-tools
```

**Verify Service Status:**
```bash
systemctl status open-vm-tools
```

**Expected Output:**
```
● open-vm-tools.service - Service for virtual machines hosted on VMware
   Active: active (running)
```

**Benefits:**
- Better VM performance
- Time synchronization with host
- Improved network and disk I/O
- Essential for production deployments

#### Task 1.3: Docker Installation

**Install Docker Engine:**
```bash
# Add Docker's official GPG key
sudo apt install ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

# Add Docker repository
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker
sudo apt update
sudo apt install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

**Verify Docker Installation:**
```bash
sudo docker --version
# Output: Docker version 24.0.x

sudo docker compose version
# Output: Docker Compose version v2.x.x
```

**Enable Docker Service:**
```bash
sudo systemctl enable docker
sudo systemctl start docker
```

**Add User to Docker Group (Optional):**
```bash
sudo usermod -aG docker $USER
# Log out and back in for group changes to take effect
```

#### Understanding Docker & Containerization

**What is Docker?**
- Platform for developing, shipping, and running applications in containers
- Containers = lightweight, portable, isolated environments
- Similar to VMs but share host OS kernel (more efficient)

**Container vs. Virtual Machine:**

```
Virtual Machine:
┌─────────────────────────┐
│   Application           │
│   Guest OS              │
├─────────────────────────┤
│   Hypervisor            │
├─────────────────────────┤
│   Host OS               │
│   Hardware              │
└─────────────────────────┘

Container:
┌─────────────────────────┐
│   Application           │
├─────────────────────────┤
│   Docker Engine         │
├─────────────────────────┤
│   Host OS               │
│   Hardware              │
└─────────────────────────┘
```

**Benefits of Containers:**
- Faster startup (seconds vs. minutes)
- Lower resource overhead
- Portable (run anywhere Docker runs)
- Version control (images)
- Easy scaling and orchestration

**Why Docker for Graylog?**
- Simplified deployment (no manual Java, MongoDB, Elasticsearch setup)
- Consistent environment across systems
- Easy upgrades (pull new image)
- Isolated dependencies
- Reproducible infrastructure (Infrastructure as Code)

#### Task 1.4: Graylog Deployment with Docker Compose

**Create Docker Compose File:**
```bash
mkdir -p ~/graylog
cd ~/graylog
nano docker-compose.yml
```

**Docker Compose Configuration (docker-compose.yml):**
```yaml
version: '3'
services:
  # MongoDB - Stores Graylog metadata
  mongodb:
    image: mongo:5.0
    container_name: graylog-mongodb
    restart: always
    networks:
      - graylog
    volumes:
      - mongo_data:/data/db

  # Elasticsearch - Stores log messages
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch-oss:7.10.2
    container_name: graylog-elasticsearch
    environment:
      - http.host=0.0.0.0
      - transport.host=localhost
      - network.host=0.0.0.0
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
    restart: always
    networks:
      - graylog
    volumes:
      - es_data:/usr/share/elasticsearch/data

  # Graylog - SIEM platform
  graylog:
    image: graylog/graylog:5.0
    container_name: graylog-server
    environment:
      # Password: admin
      - GRAYLOG_PASSWORD_SECRET=somepasswordpepper
      - GRAYLOG_ROOT_PASSWORD_SHA2=8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918
      - GRAYLOG_HTTP_EXTERNAL_URI=http://10.43.32.50:9000/
    depends_on:
      - mongodb
      - elasticsearch
    restart: always
    networks:
      - graylog
    ports:
      - "9000:9000"    # Web interface
      - "5140:5140/udp" # Syslog UDP input
      - "5140:5140/tcp" # Syslog TCP input
    volumes:
      - graylog_data:/usr/share/graylog/data

networks:
  graylog:
    driver: bridge

volumes:
  mongo_data:
    driver: local
  es_data:
    driver: local
  graylog_data:
    driver: local
```

**YAML File Breakdown:**

**Services Defined:**

**1. MongoDB:**
- **Purpose:** Stores Graylog configuration and metadata
- **Image:** mongo:5.0 (official MongoDB image)
- **Persistent Storage:** `mongo_data` volume
- **Network:** Internal `graylog` network

**2. Elasticsearch:**
- **Purpose:** Stores and indexes log messages for fast searching
- **Image:** elasticsearch-oss:7.10.2 (open-source version)
- **Memory:** 512MB min/max (adjust based on log volume)
- **Persistent Storage:** `es_data` volume

**3. Graylog:**
- **Purpose:** Main SIEM application
- **Image:** graylog/graylog:5.0
- **Dependencies:** Waits for MongoDB and Elasticsearch to start
- **Exposed Ports:**
  - 9000: Web UI
  - 5140: Syslog input (UDP and TCP)
- **Environment Variables:**
  - `GRAYLOG_PASSWORD_SECRET`: Encryption key
  - `GRAYLOG_ROOT_PASSWORD_SHA2`: Admin password (SHA256 hash of "admin")
  - `GRAYLOG_HTTP_EXTERNAL_URI`: External access URL

**Networks:**
- **graylog:** Private network for container communication

**Volumes:**
- **Persistent storage** ensures data survives container restarts
- Mapped to Docker-managed volumes on host

**Start Graylog Stack:**
```bash
sudo docker compose up -d
```

**Flags Explained:**
- **up:** Start services
- **-d:** Detached mode (run in background)

**Verify Containers Running:**
```bash
sudo docker ps
```

**Expected Output:**
```
CONTAINER ID   IMAGE                              STATUS      PORTS                              NAMES
abc123...      graylog/graylog:5.0               Up 2 min    0.0.0.0:9000->9000/tcp            graylog-server
def456...      docker.elastic.co/elasticsearch   Up 2 min    9200/tcp, 9300/tcp                graylog-elasticsearch
ghi789...      mongo:5.0                         Up 2 min    27017/tcp                         graylog-mongodb
```

**View Container Logs:**
```bash
# All services
sudo docker compose logs -f

# Specific service
sudo docker compose logs -f graylog
```

#### Task 1.5: Access Graylog Web Interface

**URL:**
```
http://10.43.32.50:9000
```

**Default Credentials:**
- **Username:** `admin`
- **Password:** `admin`

**First Login:**
- Graylog Welcome page displays
- Prompts to create Inputs (syslog receivers)
- Dashboard shows "Getting Started" guide

**Security Note:**
Change default password immediately in production:
- Navigate to: System → Users → admin → Edit
- Set strong password
- Enable MFA if available

---

### Phase 2: Configure Log Forwarders

#### Understanding Syslog

**What is Syslog?**
- Standard protocol for logging system messages
- RFC 5424 specification
- Used by Unix/Linux systems and network devices
- Messages include: timestamp, hostname, application, severity, message

**Syslog Message Format:**
```
<Priority>Timestamp Hostname Application[PID]: Message

Example:
<34>Oct 30 14:23:45 UbuntuWebServer sshd[12345]: Failed password for invalid user admin from 192.168.1.100
```

**Syslog Severity Levels:**
| Level | Name | Meaning |
|-------|------|---------|
| 0 | Emergency | System unusable |
| 1 | Alert | Immediate action required |
| 2 | Critical | Critical conditions |
| 3 | Error | Error conditions |
| 4 | Warning | Warning conditions |
| 5 | Notice | Normal but significant |
| 6 | Informational | Informational messages |
| 7 | Debug | Debug-level messages |

#### Task 2.1: Configure rsyslog on Linux (UbuntuWebServer)

**Install rsyslog:**
```bash
sudo apt install rsyslog
```

**rsyslog** is pre-installed on most Linux distributions, but verify with:
```bash
dpkg -l | grep rsyslog
systemctl status rsyslog
```

**Edit rsyslog Configuration:**
```bash
sudo nano /etc/rsyslog.conf
```

**Add Forwarding Rule (at end of file):**
```
*.* @10.43.32.50:5140;RSYSLOG_SyslogProtocol23Format
```

**Configuration Breakdown:**

| Part | Meaning |
|------|---------|
| `*.*` | All facilities (auth, cron, mail, etc.) and all severities |
| `@` | UDP protocol (use `@@` for TCP) |
| `10.43.32.50:5140` | Graylog server IP and port |
| `;RSYSLOG_SyslogProtocol23Format` | RFC 5424 format (structured data) |

**Alternative Configurations:**

**Forward only authentication logs:**
```
auth,authpriv.* @10.43.32.50:5140;RSYSLOG_SyslogProtocol23Format
```

**Forward only errors and above:**
```
*.err @10.43.32.50:5140;RSYSLOG_SyslogProtocol23Format
```

**Use TCP instead of UDP (more reliable):**
```
*.* @@10.43.32.50:5140;RSYSLOG_SyslogProtocol23Format
```

**Restart rsyslog Service:**
```bash
sudo systemctl restart rsyslog
```

**Verify Service Status:**
```bash
sudo systemctl status rsyslog
```

**Expected Output:**
```
● rsyslog.service - System Logging Service
   Active: active (running)
```

**Test Log Forwarding:**
```bash
# Generate a test log entry
logger "Test message from UbuntuWebServer to Graylog"

# Check local syslog
sudo tail /var/log/syslog

# Verify in Graylog Web UI
# Navigate to: Search → should see test message
```

**Troubleshooting:**

**Issue: Logs not appearing in Graylog**
```bash
# Check rsyslog is running
systemctl status rsyslog

# Check for errors
sudo tail -f /var/log/syslog | grep rsyslog

# Verify network connectivity to Graylog
nc -zvu 10.43.32.50 5140

# Check firewall rules allow UDP 5140
sudo iptables -L -v | grep 5140
```

#### Task 2.2: Configure rsyslog on pfSense

**Access pfSense Web Interface:**
```
https://10.42.32.1 (from AdminNet)
```

**Navigate to Remote Logging:**
```
Status → System Logs → Settings
```

**Configure Remote Logging Options:**

1. **Enable Remote Logging:** ✅ Check
2. **Remote Log Servers:**
   - **IP Address:** `10.43.32.50`
   - **Port:** `5140`
   - **Protocol:** UDP (or TCP if configured)

3. **Remote Syslog Contents:**
   - ✅ Everything (or select specific logs)
   - Options: Firewall Events, DHCP, Authentication, etc.

4. Click **Save**

**What pfSense Logs Include:**
- Firewall rule matches/blocks
- VPN connections
- DHCP leases
- Authentication attempts (WebConfigurator, SSH)
- Interface status changes
- System events

**Verification:**

**Test by changing firewall rule:**
1. Add a temporary firewall rule in pfSense
2. Check Graylog: Search → "firewall"
3. Should see log entry: "rule added" or "rule modified"

**Test by failed login:**
1. Attempt to log into pfSense with wrong password
2. Check Graylog: Search → "webConfigurator"
3. Should see: "authentication failed"

---

### Phase 3: Firewall Rules for SIEM Access

#### Understanding SIEM Security

**SIEM as a High-Value Target:**
- Contains logs from entire infrastructure
- Reveals security posture and vulnerabilities
- Shows incident response capabilities
- Can be used to cover attacker tracks

**Access Control Requirements:**
- Only SOC analysts should access dashboards
- Only monitored systems should send logs
- All other access denied (default deny)

#### Task 3.1: Create Firewall Rules

**Rule 1: Allow HTTP from UbuntuClient to GraylogServer**
- **Interface:** AdminNet
- **Action:** Pass
- **Protocol:** TCP
- **Source:** UbuntuClient (10.42.32.7)
- **Destination:** GraylogServer (10.43.32.50)
- **Destination Port:** HTTP (9000)
- **Description:** "Allow SOC analyst workstation to access Graylog dashboard"

**Rule 2: Allow Syslog from All AdminNet Devices to GraylogServer**
- **Interface:** AdminNet
- **Action:** Pass
- **Protocol:** UDP
- **Source:** AdminNet subnet (10.42.32.0/24)
- **Destination:** GraylogServer (10.43.32.50)
- **Destination Port:** 5140
- **Description:** "Allow AdminNet devices to send logs to Graylog"

**Rule 3: Block All Other Traffic to GraylogServer (Implicit)**
- Default deny rule already in place
- Ensures only authorized access

**Firewall Rule Order:**
```
1. Allow UbuntuClient → Graylog (HTTP 9000)
2. Allow AdminNet → Graylog (Syslog 5140)
3. Allow ServerNet → Graylog (Syslog 5140) - if needed
4. [Implicit Deny All]
```

**Security Considerations:**

**Production Recommendations:**
1. **HTTPS Only:** Configure SSL certificate, disable HTTP
2. **VPN Access:** Require VPN for dashboard access
3. **IP Whitelisting:** Restrict to specific SOC workstations
4. **MFA:** Enable multi-factor authentication for Graylog users
5. **Read-Only Dashboards:** Create limited-privilege accounts for viewing only

---

### Phase 4: Security Alert Engineering

#### Understanding Graylog Alerts

**Alert Components:**

**1. Condition:**
- What to look for in logs
- Search query or filter

**2. Threshold:**
- How many events trigger alert
- Time window for evaluation

**3. Notification:**
- How to notify (email, webhook, etc.)
- Who to notify

**Alert Types in Graylog:**
- **Message Count:** Alert when X messages match in Y time
- **Field Value:** Alert when field contains specific value
- **Field Content Value:** Alert on statistical anomaly

#### Task 4.1: Alert - Failed SSH for Non-Existent User

**Purpose:**
Detect brute force attacks or reconnaissance attempts using invalid usernames.

**Create Alert Rule:**

**Navigate:** Alerts → Events → Event Definitions → Create Event Definition

**Configuration:**

**Title:** `SSH Failed for Non-Existent User on UbuntuWebServer`

**Description:** `Detects failed SSH login attempts for users that don't exist on the system`

**Priority:** High

**Condition Type:** Filter & Aggregation

**Search Query:**
```
source:"UbuntuWebServer" AND sshd AND "Invalid user"
```

**Query Explanation:**
- **source:"UbuntuWebServer":** Only from this host
- **sshd:** SSH daemon logs
- **"Invalid user":** Specific message text

**Threshold:**
- Execute search every: 1 minute
- Alert when: more than 3 messages in the last 5 minutes

**Example Log Message Matched:**
```
Oct 30 14:23:45 UbuntuWebServer sshd[12345]: Invalid user admin from 192.168.1.100 port 54321
```

**Why This Matters:**
- Attackers often try common usernames: admin, root, test, oracle
- Multiple attempts = automated attack
- Early detection prevents account compromise

#### Task 4.2: Alert - Failed Login to pfSense GUI

**Purpose:**
Detect unauthorized access attempts to firewall management interface.

**Configuration:**

**Title:** `Failed Login Attempt to pfSense WebConfigurator`

**Description:** `Detects failed authentication to pfSense admin interface`

**Priority:** Critical

**Search Query:**
```
source:"pfSense" AND webConfigurator AND "authentication failed"
```

**Threshold:**
- Execute search every: 1 minute
- Alert when: more than 2 failures in 5 minutes

**Why This Matters:**
- pfSense has full network control
- Compromise = entire network at risk
- Should have very few failed attempts (admins use password manager)

#### Task 4.3: Alert - Firewall Rule Changed

**Purpose:**
Detect unauthorized firewall configuration changes.

**Configuration:**

**Title:** `Firewall Rules Changed on pfSenseRouter`

**Description:** `Alerts when firewall rules are added, modified, or deleted`

**Priority:** High

**Search Query:**
```
source:"pfSense" AND (filter AND (added OR modified OR deleted))
```

**Threshold:**
- Execute search every: 1 minute
- Alert immediately on any occurrence

**Example Log Messages:**
```
pfSense filter: rule added: AdminNet → ServerNet allow HTTP
pfSense filter: rule modified: AdminNet → Internet block Facebook
pfSense filter: rule deleted: GuestNet → ServerNet deny all
```

**Why This Matters:**
- Firewall changes can create security gaps
- Attackers may disable rules to enable their access
- Configuration changes should be tracked and audited

**Best Practice:**
- Require change approval process
- Document all firewall changes
- Review Graylog alerts before approving changes

#### Task 4.4: Alert - User Added to sudo Group

**Purpose:**
Detect privilege escalation attempts on Linux systems.

**Configuration:**

**Title:** `User Added to sudo Group on Linux Device`

**Description:** `Alerts when a user is granted sudo/administrative privileges`

**Priority:** Critical

**Search Query:**
```
"usermod" AND "sudo" AND "added"
```

**Alternative Query:**
```
/var/log/auth.log AND "usermod" AND "-aG sudo"
```

**Threshold:**
- Execute search every: 1 minute
- Alert immediately on any occurrence

**Example Log Message:**
```
Oct 30 15:30:12 UbuntuWebServer sudo: sysadmin : TTY=pts/0 ; PWD=/home/sysadmin ; USER=root ; COMMAND=/usr/sbin/usermod -aG sudo newuser
```

**Why This Matters:**
- sudo group = root-equivalent privileges
- Attackers escalate privileges to gain full control
- Should be rare event (new admin hires only)
- Insider threat indicator

**Recommended Response:**
1. Verify with IT management: Was this change authorized?
2. If unauthorized: Remove user from sudo group immediately
3. Investigate: How did attacker gain initial access?
4. Review all actions by this user account

---

### Phase 5: Dashboard Development

#### Understanding SOC Dashboards

**Purpose:**
- Real-time visibility into security posture
- At-a-glance status for SOC analysts
- Historical trending for reporting
- Incident prioritization

**Dashboard Best Practices:**
- **Top of Dashboard:** Most critical alerts/metrics
- **Color Coding:** Red (critical), yellow (warning), green (normal)
- **Time Range Selector:** Last hour, 24h, 7d, 30d
- **Auto-Refresh:** Every 30-60 seconds
- **Widgets:** Charts, graphs, tables, statistics

#### Task 5.1: Create Security Operations Dashboard

**Navigate:** Dashboards → Create Dashboard

**Dashboard Configuration:**

**Name:** `Security Operations Center - Real-Time Monitoring`

**Description:** `Central dashboard for SOC analysts to monitor security events across infrastructure`

**Widgets to Add:**

**1. Events Overview Widget**
- **Type:** Events
- **Purpose:** Shows all triggered alerts
- **Time Range:** Last 24 hours
- **Refresh:** Every 30 seconds
- **Visualization:** List with severity colors

**2. Failed SSH Attempts - Last Hour**
- **Type:** Quick Values
- **Query:** `sshd AND failed`
- **Field:** `source` (shows which server)
- **Time Range:** Last hour
- **Visualization:** Pie chart

**3. Failed pfSense Logins - Timeline**
- **Type:** Histogram
- **Query:** `source:"pfSense" AND "authentication failed"`
- **Time Range:** Last 24 hours
- **Visualization:** Timeline bar chart

**4. Top Firewall Denies**
- **Type:** Quick Values
- **Query:** `source:"pfSense" AND filter AND block`
- **Field:** `source_ip`
- **Time Range:** Last hour
- **Visualization:** Table (top 10 IPs)

**5. Privilege Escalation Events**
- **Type:** Message Count
- **Query:** `usermod AND sudo`
- **Time Range:** Last 24 hours
- **Visualization:** Single number (should be 0)

**6. Log Volume by Source**
- **Type:** Stacked Chart
- **Query:** `*`
- **Field:** `source`
- **Time Range:** Last 24 hours
- **Purpose:** Identify logging gaps or spikes

**Dashboard Layout:**
```
┌─────────────────────────────────────────────┐
│  Security Operations Center - Dashboard    │
├─────────────────────────────────────────────┤
│  [Events Overview - Triggered Alerts]       │
├─────────────────┬───────────────────────────┤
│ Failed SSH      │  Failed pfSense Logins    │
│ (Pie Chart)     │  (Timeline)               │
├─────────────────┼───────────────────────────┤
│ Top Firewall    │  Privilege Escalation     │
│ Denies (Table)  │  (Count - Should be 0)    │
├─────────────────┴───────────────────────────┤
│  Log Volume by Source (Stacked Chart)       │
└─────────────────────────────────────────────┘
```

**Access Dashboard:**
- Navigate to: Dashboards → Select created dashboard
- Set auto-refresh: 30 seconds
- Full-screen mode for NOC/SOC wall displays

---

## 🎓 Key Takeaways & Skills Demonstrated

### Technical Skills

1. **Containerization with Docker**
   - Deployed multi-container application with Docker Compose
   - Managed container lifecycle (start, stop, logs)
   - Configured persistent volumes for data retention
   - Used YAML for infrastructure as code

2. **SIEM Deployment & Configuration**
   - Installed Graylog stack (Graylog, MongoDB, Elasticsearch)
   - Created syslog inputs for log reception
   - Configured log forwarders on Linux and network devices
   - Built centralized logging infrastructure

3. **Log Analysis & Search**
   - Wrote search queries to find specific events
   - Used filters and boolean operators
   - Identified security events in logs
   - Performed root cause analysis

4. **Security Alert Engineering**
   - Created 4 custom alert rules for critical events
   - Configured thresholds and time windows
   - Prioritized alerts by severity
   - Aligned alerts with security monitoring best practices

5. **Dashboard Development**
   - Built operational dashboard for SOC analysts
   - Selected relevant widgets and visualizations
   - Configured time ranges and auto-refresh
   - Organized information for quick decision-making

6. **SOC Operations**
   - Implemented real-world security monitoring
   - Detected failed authentication, privilege escalation
   - Monitored configuration changes
   - Created actionable alerts for incident response

### Enterprise Security Operations Concepts

**SIEM Capabilities Demonstrated:**
- **Log Aggregation:** Centralized collection from multiple sources
- **Normalization:** Standardized format for analysis
- **Correlation:** Connecting related events
- **Alerting:** Automated notification of security events
- **Visualization:** Dashboards for real-time monitoring
- **Compliance:** Log retention and audit trail

**Defense-in-Depth Integration:**
```
Layer 1: Preventive Controls (Firewall, IPS)
Layer 2: Detective Controls (SIEM Alerts) ← This Lab
Layer 3: Responsive Controls (Incident Response)
```

**Kill Chain Detection:**
```
Attacker Kill Chain:
1. Reconnaissance → SIEM detects port scans
2. Initial Access → SIEM detects failed SSH
3. Privilege Escalation → SIEM detects sudo addition
4. Lateral Movement → SIEM detects unusual network traffic
5. Exfiltration → SIEM detects large data transfers
```

---

## 🔐 Security Implications & Real-World Impact

### SIEM in Enterprise Security

**Why SIEM is Critical:**
- Average breach detection time: 287 days (IBM 2023)
- SIEM reduces detection time to hours/days
- Required for compliance (PCI-DSS, HIPAA, SOX)
- Provides forensic evidence for investigations
- Enables proactive threat hunting

**Use Cases:**

**1. Insider Threat Detection**
```
Scenario: Disgruntled employee attempts to steal data
SIEM Detection:
- Alert: User accessed sensitive files outside normal hours
- Alert: Large data transfer to personal cloud storage
- Alert: USB device connected to workstation
SOC Response: Disable account, investigate activity, preserve evidence
```

**2. Brute Force Attack**
```
Scenario: Attacker attempts to guess SSH password
SIEM Detection:
- Alert: 50 failed SSH attempts in 2 minutes from 45.67.89.10
- Alert: Invalid usernames attempted (admin, root, oracle)
SOC Response: Block source IP at firewall, review for successful logins
```

**3. Ransomware Outbreak**
```
Scenario: Ransomware spreads across network
SIEM Detection:
- Alert: Mass file modification on file server
- Alert: Unusual outbound connection to known C2 server
- Alert: System process spawned from suspicious location
SOC Response: Isolate affected systems, initiate incident response
```

**4. Configuration Tampering**
```
Scenario: Attacker modifies firewall rules to enable backdoor
SIEM Detection:
- Alert: Firewall rule added allowing RDP from internet
- Alert: pfSense login from unfamiliar IP address
SOC Response: Revert firewall changes, investigate compromised account
```

### Compliance & Governance

| Framework | Requirement | Graylog Fulfillment |
|-----------|-------------|---------------------|
| **PCI-DSS** | Req 10.1: Audit logging | ✅ Centralized log collection |
| **PCI-DSS** | Req 10.6: Log review | ✅ Dashboards and alerts |
| **HIPAA** | §164.312(b) Audit Controls | ✅ Access logs and authentication tracking |
| **SOX** | Section 404: IT Controls | ✅ Change monitoring and alerting |
| **NIST** | DE.CM-1: Network monitoring | ✅ Continuous log analysis |
| **GDPR** | Article 32: Security monitoring | ✅ Breach detection capabilities |

---

## 🚀 Real-World Applications

### Career Roles Demonstrated

**SOC Analyst (Tier 1/2/3) ($65K-$120K):**
- Monitor SIEM dashboards for security events
- Investigate and triage alerts
- Create and tune alert rules
- Perform log analysis during incidents
- Document findings in tickets

**Security Engineer ($95K-$145K):**
- Deploy and maintain SIEM infrastructure
- Design alert logic for threat detection
- Integrate new log sources
- Optimize SIEM performance and storage
- Develop automation and orchestration

**Security Architect ($130K-$190K):**
- Design enterprise logging architecture
- Select SIEM platform and technologies
- Plan for scalability (TB/day log ingestion)
- Define retention policies and compliance requirements
- Create SOC operational procedures

**Incident Responder ($90K-$135K):**
- Use SIEM for forensic investigations
- Correlate events across multiple sources
- Build timeline of attacker activity
- Identify indicators of compromise (IoCs)
- Create post-incident reports

---

## 📚 Commands Reference

### Docker & Docker Compose

```bash
# Container Management
sudo docker ps                    # List running containers
sudo docker ps -a                 # List all containers
sudo docker stop       # Stop container
sudo docker start      # Start container
sudo docker restart    # Restart container
sudo docker rm         # Remove container

# Docker Compose
sudo docker compose up -d         # Start all services
sudo docker compose down          # Stop and remove all services
sudo docker compose logs -f       # Follow logs (all services)
sudo docker compose logs -f graylog   # Follow specific service logs
sudo docker compose ps            # List containers from compose file
sudo docker compose restart       # Restart all services

# Images
sudo docker images                # List images
sudo docker pull graylog/graylog:5.0  # Download image
sudo docker rmi            # Remove image

# Volumes
sudo docker volume ls             # List volumes
sudo docker volume inspect   # Inspect volume
sudo docker volume rm     # Remove volume

# System
sudo docker system prune -a       # Clean up unused containers, images, volumes
```

### rsyslog Configuration

```bash
# Service Management
sudo systemctl status rsyslog
sudo systemctl start rsyslog
sudo systemctl stop rsyslog
sudo systemctl restart rsyslog
sudo systemctl enable rsyslog

# Configuration
sudo nano /etc/rsyslog.conf
sudo rsyslogd -N1                 # Validate configuration syntax

# Testing
logger "Test message"             # Send test log
tail -f /var/log/syslog           # Watch local syslog
```

### Graylog Search Queries

```
# Basic searches
source:"UbuntuWebServer"
message:"failed password"
sshd

# Boolean operators
source:"pfSense" AND "authentication failed"
sshd OR ssh
NOT source:"GraylogServer"

# Field searches
source_ip:192.168.1.100
level:error
facility:auth

# Wildcards
message:fail*
source:Ubuntu*

# Time ranges
timestamp:[2024-10-30T00:00:00 TO 2024-10-30T23:59:59]

# Numeric ranges
bytes:[1000 TO 10000]

# Regular expressions
message:/invalid user \w+/
```

---

## 💡 Lessons Learned

### Technical Insights

1. **Containerization Simplifies Complex Deployments**
   - Graylog requires Java, MongoDB, Elasticsearch
   - Docker Compose deploys all in minutes
   - No dependency conflicts or version issues
   - Easy to replicate across environments

2. **Centralized Logging is Essential**
   - Cannot monitor what you cannot see
   - Local logs only accessible on individual systems
   - SIEM provides single pane of glass
   - Attackers often delete local logs (SIEM preserves copy)

3. **Alert Tuning is Continuous Process**
   - Too sensitive = alert fatigue
   - Too permissive = missed threats
   - Requires understanding of normal vs. abnormal
   - Regular review and adjustment essential

4. **Dashboards Must Be Actionable**
   - Show information analysts need to make decisions
   - Avoid vanity metrics (total log count)
   - Focus on security-relevant events
   - Design for your audience (SOC vs. executives)

5. **Docker Volumes Ensure Data Persistence**
   - Without volumes, container restart = data loss
   - Critical for databases and logs
   - Named volumes easier to manage than bind mounts

### Professional Practices

1. **Infrastructure as Code (IaC) Provides Reproducibility**
   - Docker Compose YAML is version-controlled
   - Can recreate environment exactly
   - Disaster recovery: redeploy from YAML
   - Documentation embedded in configuration

2. **Log Retention Policies Required**
   - Compliance mandates: 90 days (PCI), 7 years (SOX)
   - Balance: Storage cost vs. retention need
   - Graylog supports index rotation and archival
   - Plan capacity: GB/day × retention days

3. **Security Monitoring is 24/7 Responsibility**
   - Alerts must be reviewed promptly
   - Dashboards should be displayed in SOC
   - On-call rotation for after-hours
   - Escalation procedures for critical alerts

---

## 📸 Lab Evidence

All screenshots documented in original lab report:

**GraylogServer Setup:**
- ✅ Network configuration (ip r)
- ✅ System update (apt update)
- ✅ VMware Tools installation and status
- ✅ Graylog web interface access (http://10.43.32.50:9000)

**Log Forwarder Configuration:**
- ✅ rsyslog installation on Linux
- ✅ rsyslog.conf edit with forwarding rule
- ✅ rsyslog service restart and status
- ✅ pfSense remote logging configuration

**Firewall Rules:**
- ✅ HTTP access from UbuntuClient to GraylogServer
- ✅ Syslog traffic from AdminNet to GraylogServer
- ✅ Block rule for unauthorized access

**Security Alerts:**
- ✅ Alert: SSH failed for non-existent user
- ✅ Alert: Failed login to pfSense GUI
- ✅ Alert: Firewall rules changed
- ✅ Alert: User added to sudo group

**Dashboard:**
- ✅ Events Overview widget
- ✅ Time range selector
- ✅ Custom security operations dashboard

---

## 🏆 Lab Status

**Completion Status:** ✅ Successfully Completed  
**SIEM Deployment:** ✅ Graylog stack fully operational  
**Log Sources:** ✅ 2 configured (Linux + pfSense)  
**Security Alerts:** ✅ 4 custom rules created  
**Dashboard:** ✅ SOC monitoring dashboard deployed  
**Containerization:** ✅ Docker Compose infrastructure as code  

---

## 🔍 Troubleshooting Guide

### Common Issues

**Issue 1: Graylog Containers Won't Start**
```bash
# Check Docker service
sudo systemctl status docker

# View logs
sudo docker compose logs

# Common cause: Port already in use
sudo netstat -tulpn | grep 9000
sudo lsof -i :9000

# Solution: Kill process or change port in docker-compose.yml
```

**Issue 2: Logs Not Appearing in Graylog**
```bash
# Verify rsyslog forwarding
sudo tail -f /var/log/syslog | grep rsyslog

# Test connectivity
nc -zvu 10.43.32.50 5140

# Check Graylog input
# Navigate to: System → Inputs → Check "running" status

# Verify firewall allows UDP 5140
sudo iptables -L -v | grep 5140
```

**Issue 3: Elasticsearch Unhealthy**
```bash
# Common cause: Insufficient memory
# Check container logs
sudo docker logs graylog-elasticsearch

# Increase memory in docker-compose.yml
ES_JAVA_OPTS=-Xms1g -Xmx1g

# Restart services
sudo docker compose restart
```

**Issue 4: MongoDB Connection Failed**
```bash
# Check MongoDB container
sudo docker ps | grep mongo

# View MongoDB logs
sudo docker logs graylog-mongodb

# Verify network
sudo docker network inspect graylog_graylog
```

---