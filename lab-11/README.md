# Lab 11: Risk Analysis & Management

## 📋 Lab Overview
  
**Difficulty Level:** Expert  

### Objective
This lab demonstrates enterprise risk management and SIEM cost-benefit analysis by assessing Personally Identifiable Information (PII) vulnerabilities in MediaWiki, evaluating SolarWinds SIEM feasibility, conducting comparative analysis of SIEM solutions (SolarWinds vs. Wazuh), and authoring an executive risk assessment memo with technical recommendations. This simulates real-world security leadership responsibilities including risk evaluation, vendor comparison, and strategic technology selection.

---

## 🎯 Learning Outcomes

By completing this lab, I demonstrated proficiency in:

- **Risk Assessment:** Identifying and evaluating PII/SPII vulnerabilities in web applications
- **Data Classification:** Understanding PII vs. SPII and associated risk levels
- **SIEM Evaluation:** Comparing enterprise SIEM solutions with cost-benefit analysis
- **Vendor Analysis:** SolarWinds (commercial) vs. Wazuh (open-source) comparison
- **Database Security:** Identifying backend vulnerabilities in MariaDB
- **Executive Communication:** Writing risk assessment memos for C-level stakeholders
- **Cost-Benefit Analysis:** Evaluating ROI and TCO for security solutions
- **Strategic Decision Making:** Recommending technology based on organizational needs
- **Compliance Awareness:** Understanding PII/SPII protection requirements

---

## 🛠️ Tools & Technologies Analyzed

### SIEM Solutions Compared
| Solution | Type | Cost Model | Key Strengths |
|----------|------|------------|---------------|
| **SolarWinds SIEM** | Commercial Enterprise | Licensing fees | Dedicated support, structured updates, enterprise scalability |
| **Wazuh** | Open-Source | Free (hardware only ~$300) | Cost-effective, comprehensive features, community-driven |

### Security Assessment Tools Used
- **MediaWiki** - Web application analyzed for PII vulnerabilities
- **MariaDB** - Database backend examined for SPII exposure
- **MySQL Client** - Database query and analysis
- **Web Browser** - Frontend security testing

### Data Classification
| Type | Definition | Risk Level | Examples |
|------|------------|------------|----------|
| **PII** | Personally Identifiable Information | Medium | Name, email, phone, IP address, DOB |
| **SPII** | Sensitive PII | High | SSN, passport #, bank account #, biometric data, passwords |

---

## 📝 Risk Analysis Methodology

### Phase 1: PII Security Assessment

#### Understanding PII vs. SPII

**PII (Personally Identifiable Information):**
Information that can identify or track an individual:
- Full name
- Email address
- Phone number
- IP address
- Date of birth
- Physical address
- Employment information
- Educational records

**Impact of PII Breach:** Moderate
- Identity theft (moderate difficulty)
- Targeted phishing attacks
- Social engineering attempts
- Privacy violations

**SPII (Sensitive Personally Identifiable Information):**
Sensitive information that, if compromised, causes substantial harm:
- Social Security Number (SSN)
- Passport numbers
- Driver's license numbers
- Bank account numbers
- Credit/debit card numbers
- Biometric data (fingerprints, facial recognition)
- **Passwords (hashed or plaintext)**
- Medical records

**Impact of SPII Breach:** Severe
- Financial fraud
- Identity theft (immediate)
- Unauthorized account access
- Emotional/psychological harm
- Legal liability for organization

**Regulatory Requirements:**
| Regulation | PII/SPII Protection Mandate |
|------------|----------------------------|
| **GDPR** | Right to erasure, data minimization, encryption |
| **CCPA** | Consumer data privacy rights, disclosure requirements |
| **HIPAA** | PHI (Protected Health Information) encryption and access control |
| **PCI-DSS** | Cardholder data encryption, access restrictions |

#### Task 1.1: Frontend PII Assessment (MediaWiki User Registration)

**Access MediaWiki:**
```
http://<UbuntuWebServer IP>/mediawiki?useskin=vector
```

**Create Test Account:**
Navigate to: Create Account

**Data Collected During Registration:**

| Field | Data Type | Classification | Risk Level |
|-------|-----------|----------------|------------|
| **Username** | User-chosen identifier | PII | Low |
| **Password** | Authentication credential | **SPII** | **Critical** |
| **Email Address** | Contact information | PII | Medium |
| **Real Name** (optional) | Personal identifier | PII | Medium |

**Frontend Visibility (Admin View):**
From admin control panel, visible data:
- Username
- Last activity date/time
- Edit count

**Finding:**
Frontend admin interface shows LIMITED information. Only activity metadata visible, not sensitive credentials or personal details.

**Risk Assessment:** ✅ Low Risk
- No SPII exposed in frontend
- Activity metadata alone cannot compromise user
- Admin UI follows principle of least privilege

#### Task 1.2: Backend PII Assessment (Database Analysis)

**Access MariaDB on RockyDBServer:**
```bash
sudo mysql -u root -p
```

**Database Investigation:**
```sql
SHOW DATABASES;
-- Output includes: wiki_webdb

USE wiki_webdb;

SHOW TABLES;
-- Output includes: user (among many others)

SELECT * FROM user;
```

**Data Exposed in Database Backend:**

| Column | Data Type | Classification | Stored Format | Risk Level |
|--------|-----------|----------------|---------------|------------|
| `user_name` | VARCHAR | PII | Plaintext | Low |
| `user_password` | VARCHAR | **SPII** | **Hashed** (but stored) | **High** |
| `user_email` | VARCHAR | PII | Plaintext | Medium |
| `user_real_name` | VARCHAR | PII | Plaintext | Medium |
| `user_registration` | TIMESTAMP | PII | Plaintext | Low |

**Critical Finding:**
```sql
mysql> SELECT user_name, user_password, user_email, user_real_name FROM user;
+----------------+-----------------------------------+----------------------+----------------+
| user_name      | user_password                     | user_email           | user_real_name |
+----------------+-----------------------------------+----------------------+----------------+
| testuser       | :pbkdf2:sha512:30000$...(hash)   | test@example.com     | Test User      |
| sysadmin       | :pbkdf2:sha512:30000$...(hash)   | admin@ubnetdef.org   | Admin User     |
+----------------+-----------------------------------+----------------------+----------------+
```

**Security Analysis:**

**Positive Findings:**
✅ Passwords are hashed (not plaintext)
✅ Using PBKDF2-SHA512 (strong algorithm)
✅ 30,000 iterations (adequate key stretching)

**Vulnerabilities Identified:**
❌ Email addresses stored in plaintext (PII exposure)
❌ Real names stored in plaintext (PII exposure)
❌ Password hashes accessible (offline cracking possible)
❌ No encryption at rest for database
❌ Username + email combination enables targeted attacks

#### Task 1.3: Threat Analysis

**Attack Scenario 1: Database Breach via SQL Injection**
```
Attacker exploits SQL injection vulnerability in MediaWiki
    ↓
Gains access to wiki_webdb database
    ↓
Exfiltrates user table with hashes
    ↓
Offline password cracking with hashcat/john
    ↓
Obtains plaintext passwords for weak passwords
    ↓
Credential stuffing attacks on other services (reused passwords)
```

**Impact:**
- User accounts compromised (MediaWiki access)
- Lateral credential reuse (email + weak password on Gmail, banking, etc.)
- Privacy violation (real names + emails exposed)
- Reputational damage to UBNetDef

**Attack Scenario 2: Insider Threat (Rogue Admin)**
```
Malicious administrator with database access
    ↓
Directly queries user table
    ↓
Exports all user data (usernames, emails, hashes)
    ↓
Sells data on dark web or uses for phishing campaigns
```

**Impact:**
- Targeted phishing against UBNetDef users
- Spear phishing using real names
- Credential harvesting attempts

**Attack Scenario 3: Backup Theft**
```
Attacker gains access to database backups (unencrypted)
    ↓
Restores backup to own server
    ↓
Full access to all historical user data
```

**Impact:**
- Even deleted accounts compromised (if in backups)
- Long-term credential exposure

#### Task 1.4: Risk Quantification

**Risk Formula:**
```
Risk = Likelihood × Impact
```

**Likelihood Assessment:**

| Threat | Likelihood (1-5) | Justification |
|--------|------------------|---------------|
| SQL Injection | 3 (Medium) | MediaWiki is mature, but custom extensions may have vulnerabilities |
| Insider Threat | 2 (Low) | Requires privileged access, but possible |
| Backup Theft | 2 (Low) | Depends on backup security practices |

**Impact Assessment:**

| Data Type | Impact (1-5) | Justification |
|-----------|--------------|---------------|
| Password Hashes (SPII) | 5 (Critical) | Credential compromise, account takeover |
| Email Addresses (PII) | 3 (Medium) | Phishing, spam, privacy violation |
| Real Names (PII) | 3 (Medium) | Targeted attacks, doxxing |

**Overall Risk Scores:**

| Threat | Likelihood | Impact | Risk Score | Priority |
|--------|-----------|--------|------------|----------|
| **SQL Injection** | 3 | 5 | **15** | **High** |
| **Insider Threat** | 2 | 5 | **10** | Medium |
| **Backup Theft** | 2 | 5 | **10** | Medium |

**Risk Prioritization:**
1. **High Priority:** SQL Injection mitigation (input validation, parameterized queries, WAF)
2. **Medium Priority:** Database access control (least privilege, audit logging)
3. **Medium Priority:** Backup encryption (AES-256, secure storage)

#### Task 1.5: Mitigation Recommendations

**Immediate Actions (0-30 days):**

**1. Database Encryption at Rest**
```sql
-- Enable encryption for wiki_webdb
ALTER TABLE user ENCRYPTION='Y';
```
- Protects against backup theft
- Requires encryption key management

**2. Implement Web Application Firewall (WAF)**
- Deploy ModSecurity or commercial WAF
- Block SQL injection attempts
- Monitor for attack patterns

**3. Audit Database Access**
```sql
-- Enable audit logging
SET GLOBAL general_log = 'ON';
SET GLOBAL log_output = 'TABLE';
```
- Track all database queries
- Detect suspicious SELECT * FROM user queries

**Short-Term Actions (30-90 days):**

**4. Implement MFA (Multi-Factor Authentication)**
- MediaWiki extension: OATHAuth
- Prevents account takeover even if password compromised

**5. Data Minimization**
- Remove "real_name" field requirement
- Hash email addresses (for password reset, use tokenized approach)

**6. Rate Limiting**
- Limit login attempts (prevent brute force)
- Limit registration attempts (prevent bot accounts)

**Long-Term Actions (90+ days):**

**7. Database Access Segmentation**
- MediaWiki application: Read-only user (SELECT, INSERT, UPDATE)
- Admin tasks: Separate privileged account
- Monitoring: Read-only analytics user

**8. Regular Penetration Testing**
- Annual SQL injection testing
- OWASP Top 10 vulnerability scanning

**9. Incident Response Plan**
- Data breach notification procedures
- GDPR compliance (72-hour notification)

---

### Phase 2: SIEM Solution Evaluation

#### Understanding SIEM Business Value

**What Problem Does SIEM Solve?**
- **Visibility:** Can't protect what you can't see
- **Detection:** Identify security incidents in real-time
- **Compliance:** Meet regulatory log retention requirements
- **Forensics:** Investigate incidents with centralized logs

**SIEM ROI Calculation:**
```
Cost of SIEM: $X/year
Average breach cost without SIEM: $4.45M (IBM 2023)
Breach detection time reduction: 287 days → 3 days (with SIEM)
Cost reduction from faster detection: ~60% ($2.67M savings)

ROI = (Cost Avoided - SIEM Cost) / SIEM Cost × 100%
```

#### Task 2.1: SolarWinds SIEM Analysis

**SolarWinds Security Event Manager**

**Strengths:**
1. **Enterprise-Grade Support**
   - 24/7 customer support
   - Dedicated account managers
   - SLA-backed response times
   - Regular training and webinars

2. **Structured Updates**
   - Scheduled security patches
   - Quarterly feature releases
   - Compatibility testing
   - Rollback support

3. **Scalability**
   - Supports 1,000+ endpoints
   - Distributed deployment options
   - High-availability configurations
   - Performance optimization

4. **Compliance Features**
   - Pre-built reports (PCI-DSS, HIPAA, SOX)
   - Audit trail documentation
   - Compliance dashboards
   - Regulatory update notifications

5. **Integration Ecosystem**
   - 300+ pre-built integrations
   - Active Directory integration
   - Cloud platform support (AWS, Azure)
   - Third-party SIEM tool compatibility

**Weaknesses:**
1. **High Cost**
   - Licensing: $10,000 - $50,000/year (depending on endpoints)
   - Implementation: $5,000 - $15,000 (professional services)
   - Training: $2,000 - $5,000
   - Annual maintenance: 20% of license cost

2. **Vendor Lock-In**
   - Proprietary format for stored data
   - Difficult migration to other SIEM
   - Dependency on vendor for updates

3. **Overhead**
   - Requires dedicated hardware (server specs: 16GB RAM, 500GB storage minimum)
   - Ongoing management (dedicated SOC analyst)

**Total Cost of Ownership (5 years):**
```
Licensing: $50,000/year × 5 = $250,000
Implementation: $10,000 (one-time)
Training: $5,000 (one-time)
Hardware: $3,000 (one-time)
Maintenance: $10,000/year × 5 = $50,000
Staff time: 10 hours/week × 52 weeks × 5 years × $75/hour = $195,000

Total 5-Year TCO: $513,000
```

**Is SolarWinds Justified for UBNetDef?**

**UBNetDef Profile:**
- Small-medium organization
- Limited IT budget
- Small attack surface (internal wiki)
- Low volume of security events
- Limited staff (part-time security engineer)

**Analysis:**
❌ **NOT JUSTIFIED**
- Cost ($513K over 5 years) exceeds benefit for organization size
- Features like 24/7 support unnecessary (no 24/7 operations)
- Enterprise scalability not needed (< 50 endpoints)
- ROI negative for small organization

#### Task 2.2: Wazuh SIEM Analysis

**Wazuh - Open-Source XDR & SIEM**

**Overview:**
- Open-source platform (GPL license)
- Integrates SIEM + XDR (Extended Detection and Response)
- Community of 10M+ users
- Professional support available (optional)

**Strengths:**
1. **Cost-Effective**
   - Software: $0 (open-source)
   - Hardware: ~$300 (modest server)
   - Implementation: 7-8 hours (in-house, 2 engineers)
   - Total Year 1: ~$1,500 (hardware + labor)

2. **Comprehensive Features**
   - Log collection and analysis
   - Threat detection (signature + behavior)
   - Vulnerability detection
   - File integrity monitoring (FIM)
   - Incident response automation
   - Compliance reporting (PCI-DSS, HIPAA, GDPR)

3. **Scalability**
   - Supports 1,000s of endpoints
   - Elastic Stack backend (scales horizontally)
   - Agent-based or agentless

4. **Active Development**
   - Weekly updates
   - GitHub repository (8,000+ stars)
   - Responsive community
   - CVE database integration

5. **Integration**
   - Elastic Stack (Elasticsearch, Logstash, Kibana)
   - Cloud platforms (AWS, Azure, GCP)
   - Container environments (Docker, Kubernetes)
   - Threat intelligence feeds

**Weaknesses:**
1. **Community Support**
   - No SLA (unless paid support)
   - Forum-based assistance
   - Delayed responses for complex issues

2. **Implementation Complexity**
   - Requires Linux expertise
   - Manual configuration (no GUI installer)
   - Steeper learning curve

3. **Documentation Gaps**
   - Some features under-documented
   - Community-contributed guides (variable quality)

**Total Cost of Ownership (5 years):**
```
Software: $0
Hardware: $300 (one-time)
Implementation: 8 hours × 2 engineers × $75/hour = $1,200 (one-time)
Annual maintenance: 2 hours/month × 12 × $75/hour × 5 years = $9,000
Optional support: $0 (using community) or $3,000/year (enterprise support)

Total 5-Year TCO: $10,500 (community) or $25,500 (with support)
```

**Comparison:**
- **SolarWinds TCO:** $513,000
- **Wazuh TCO:** $10,500
- **Savings:** $502,500 (98% reduction)

#### Task 2.3: Feature Comparison Matrix

| Feature | SolarWinds | Wazuh | Winner |
|---------|-----------|-------|--------|
| **Core SIEM** | | | |
| Log Collection | ✅ Excellent | ✅ Excellent | Tie |
| Real-time Analysis | ✅ Yes | ✅ Yes | Tie |
| Threat Detection | ✅ Advanced | ✅ Good | SolarWinds |
| Incident Response | ✅ Yes | ✅ Yes | Tie |
| **Extended Features** | | | |
| Vulnerability Scanning | ✅ Yes | ✅ Yes | Tie |
| File Integrity Monitoring | ✅ Yes | ✅ Yes | Tie |
| Compliance Reports | ✅ Extensive | ✅ Good | SolarWinds |
| Cloud Integration | ✅ Extensive | ✅ Good | SolarWinds |
| **Operations** | | | |
| Ease of Deployment | ✅ GUI installer | ⚠️ Manual | SolarWinds |
| Ease of Use | ✅ Polished UI | ⚠️ Learning curve | SolarWinds |
| Scalability | ✅ Enterprise | ✅ Very Good | Tie |
| **Support** | | | |
| Documentation | ✅ Professional | ⚠️ Community | SolarWinds |
| Support SLA | ✅ 24/7 | ❌ None (free) | SolarWinds |
| Updates | ✅ Scheduled | ✅ Frequent | Tie |
| **Cost** | | | |
| Initial Cost | ❌ $18,000 | ✅ $1,500 | **Wazuh** |
| 5-Year TCO | ❌ $513,000 | ✅ $10,500 | **Wazuh** |
| ROI | ⚠️ High cost | ✅ Excellent | **Wazuh** |

**Recommendation:** ✅ **Wazuh**
- 98% cost savings
- Feature parity for UBNetDef's needs
- Acceptable support trade-off (community vs. 24/7)
- Better fit for small-medium organization

#### Task 2.4: Risk Mitigation Capabilities

**How Wazuh Addresses UBNetDef PII Risks:**

**1. Enhanced Threat Detection**
```yaml
# Wazuh Rule: Detect SQL Injection Attempts

  31100
  SELECT|UNION|INSERT|DELETE|DROP
  SQL injection attempt detected
  attack,sql_injection,

```
- Monitors web server logs for SQL injection patterns
- Alerts SOC within seconds
- Enables rapid response

**2. Database Access Monitoring**
```
# Wazuh Agent on RockyDBServer
# Monitors MariaDB logs for:
- Unauthorized SELECT FROM user queries
- Large data exports (exfiltration)
- Failed authentication attempts
```

**3. File Integrity Monitoring (FIM)**
```yaml
# Wazuh FIM: Monitor MediaWiki Configuration

  /var/www/html/mediawiki
  yes

```
- Detects unauthorized code changes (backdoors)
- Monitors LocalSettings.php (database credentials)

**4. Vulnerability Detection**
```
# Wazuh Vulnerability Detector
- Scans MediaWiki for known CVEs
- Checks PHP version for vulnerabilities
- Identifies unpatched OS packages
```

**5. Automated Response**
```python
# Wazuh Active Response: Block SQL Injection Source IP

  firewall-drop
  local
  31103
  3600

```
- Automatically blocks attacker IP for 1 hour
- Reduces threat window from hours to seconds

---

## 🎓 Key Takeaways & Skills Demonstrated

### Technical Skills

1. **Risk Assessment & Analysis**
   - Identified PII vs. SPII in web application
   - Quantified risk (likelihood × impact)
   - Prioritized vulnerabilities by severity

2. **Database Security Analysis**
   - Examined backend data storage
   - Assessed encryption and hashing
   - Identified SPII exposure risks

3. **SIEM Evaluation**
   - Compared commercial vs. open-source solutions
   - Calculated Total Cost of Ownership (TCO)
   - Performed feature comparison analysis

4. **Cost-Benefit Analysis**
   - Evaluated ROI for security investments
   - Compared 5-year TCO: $513K vs. $10.5K
   - Justified recommendation with financial data

5. **Executive Communication**
   - Authored risk assessment memo to CEO
   - Translated technical risks into business impact
   - Provided actionable recommendations

### Enterprise Risk Management Concepts

**Risk Assessment Framework:**
```
1. Identify Assets (MediaWiki user data)
2. Identify Threats (SQL injection, insider threat)
3. Identify Vulnerabilities (SPII in database)
4. Calculate Risk (Likelihood × Impact)
5. Recommend Controls (Wazuh SIEM, encryption, WAF)
```

**Defense-in-Depth for PII Protection:**
```
Layer 1: Application (Input validation, parameterized queries)
Layer 2: Database (Encryption at rest, access control)
Layer 3: Network (WAF, firewall rules)
Layer 4: Monitoring (SIEM, audit logging) ← Wazuh
Layer 5: Process (Incident response, breach notification)
```

---

## 🔐 Security Implications & Real-World Impact

### PII Breach Consequences

**Legal & Regulatory:**
| Regulation | Violation | Penalty |
|------------|-----------|---------|
| **GDPR** | Failure to protect PII | €20M or 4% of annual revenue |
| **CCPA** | Data breach without notification | $2,500 - $7,500 per violation |
| **HIPAA** | PHI disclosure | $100 - $50,000 per violation |
| **PCI-DSS** | Cardholder data breach | $5,000 - $100,000/month non-compliance |

**Financial Impact:**
- Average breach cost: $4.45M (IBM 2023)
- Legal fees: $1M - $5M
- Customer notification: $0.50 - $2.00 per customer
- Credit monitoring services: $10 - $20 per customer/year
- Regulatory fines: Variable (see table above)

**Reputational Damage:**
- Customer trust loss
- Brand damage
- Customer churn (5-10% average)
- Negative press coverage
- Stock price impact (publicly traded companies)

### SIEM Value Proposition

**Without SIEM:**
- Breach detection time: 287 days average
- Manual log review (impossible at scale)
- Missed attack patterns
- Compliance violations (PCI-DSS requires SIEM)

**With SIEM (Wazuh):**
- Breach detection time: Hours to days
- Automated threat detection
- Real-time alerting
- Compliance-ready reporting
- **Cost: $10,500 over 5 years (vs. $4.45M average breach)**

**ROI Calculation:**
```
Investment: $10,500
Prevented breach: $4.45M (if catches 1 breach in 5 years)
ROI: ($4,450,000 - $10,500) / $10,500 = 42,333%

Break-even: Prevent 0.23% of a breach
```

---

## 🚀 Real-World Applications

### Career Roles Demonstrated

**Risk Analyst / Risk Manager ($80K-$130K):**
- Assess organizational security risks
- Quantify risk with likelihood × impact
- Recommend risk mitigation strategies
- Create risk matrices and heat maps

**Security Architect ($130K-$190K):**
- Evaluate security solutions (SIEM, WAF, etc.)
- Design defense-in-depth architectures
- Perform vendor comparisons
- Calculate TCO for security investments

**Compliance Officer ($90K-$140K):**
- Ensure PII/SPII protection compliance
- Conduct regulatory gap analysis
- Document security controls
- Prepare for audits (PCI-DSS, HIPAA)

**Chief Information Security Officer (CISO) ($180K-$350K):**
- Strategic security decision-making
- Budget allocation for security
- Board-level risk communication
- Vendor selection and contract negotiation

---

## 💡 Executive Memo to CEO

**To:** David Murray, CEO, UBNetDef  
**From:** Faraz Ahmed, Security Engineer  
**Date:** November 13th, 2024  
**Subject:** SIEM Solution Assessment and PII Risk Analysis

**Executive Summary:**

UBNetDef SysSec finds that **SolarWinds SIEM is NOT justified** for UBNetDef Wiki. A comprehensive risk assessment reveals that while MediaWiki collects PII and SPII (usernames, passwords, emails), the proposed $513,000 (5-year) SolarWinds investment exceeds projected benefits for our organization size.

**Key Findings:**

**1. PII/SPII Vulnerabilities Identified:**
- User passwords (hashed) stored in database (SPII)
- Email addresses and real names stored in plaintext (PII)
- Risk: SQL injection → database breach → credential compromise
- Priority: HIGH (Risk Score: 15/25)

**2. SIEM Evaluation:**
- SolarWinds: $513,000 (5-year TCO), enterprise features, 24/7 support
- Wazuh: $10,500 (5-year TCO), comprehensive features, community support
- **Cost savings: $502,500 (98% reduction)**

**Recommendation:**

✅ **Deploy Wazuh as cost-effective SIEM alternative**
- Investment: $300 hardware + 8 hours implementation
- Features: Log aggregation, threat detection, vulnerability scanning, FIM
- ROI: Excellent (42,000%+ if prevents single breach)

**Next Steps:**
1. Approve $300 hardware budget
2. Allocate 8 hours for 2 security engineers (implementation)
3. Implement database encryption and WAF (PII mitigation)
4. Deploy Wazuh within 30 days

---

## 📚 References Cited

1. **Wazuh Official Documentation**
   - "Wazuh - Open Source XDR. Open Source SIEM."
   - https://wazuh.com

2. **SolarWinds Product Information**
   - "Security Event Manager - View Event Logs Remotely | SolarWinds"
   - https://www.solarwinds.com/security-event-manager

3. **PII/SPII Definitions**
   - "Differences Between PII, Sensitive PII, and PHI"
   - Municipal Websites Central Help Center

4. **Wazuh Technical Analysis**
   - "Understanding Wazuh: The Free, Open Source Security Platform for XDR & SIEM"
   - Medium (Sigmund Brandstaetter CISSP, CCSP, CISM, OSCP, CEH)

5. **Breach Cost Data**
   - IBM Security Cost of a Data Breach Report 2023
   - Average breach cost: $4.45 million

---

## 📸 Lab Evidence

All analysis documented in original lab report:

**PII Assessment:**
- ✅ MediaWiki registration process (frontend)
- ✅ Admin control panel (limited PII visible)
- ✅ Database backend analysis (MariaDB queries)
- ✅ SPII identification (user table with hashes)

**Risk Analysis:**
- ✅ PII vs. SPII classification
- ✅ Attack scenario documentation
- ✅ Risk quantification (likelihood × impact)
- ✅ Mitigation recommendations

**SIEM Evaluation:**
- ✅ SolarWinds feature analysis
- ✅ Wazuh capabilities assessment
- ✅ Cost comparison (5-year TCO)
- ✅ Feature matrix

**Executive Memo:**
- ✅ Professional memo format
- ✅ Executive summary
- ✅ Technical findings
- ✅ Recommendation with justification

---

## 🏆 Lab Status

**Completion Status:** ✅ Successfully Completed  
**PII Assessment:** ✅ Frontend + backend analyzed  
**Risk Analysis:** ✅ Vulnerabilities quantified  
**SIEM Evaluation:** ✅ SolarWinds vs. Wazuh compared  
**Cost-Benefit Analysis:** ✅ 5-year TCO calculated  
**Recommendation:** ✅ Wazuh selected ($502K savings)  
**Executive Memo:** ✅ Delivered to CEO  

---

## 🔍 Additional Considerations

### Wazuh Implementation Plan

**Phase 1: Preparation (Week 1)**
```
Day 1-2: Hardware procurement ($300 server)
Day 3-4: Wazuh server installation
Day 5: Initial configuration
```

**Phase 2: Agent Deployment (Week 2)**
```
Day 1: UbuntuWebServer agent
Day 2: RockyDBServer agent
Day 3: pfSenseRouter syslog forwarding
Day 4: Win10Client agent (optional)
Day 5: Testing and validation
```

**Phase 3: Alert Configuration (Week 3)**
```
Day 1-2: SQL injection detection rules
Day 3: Database access monitoring
Day 4: File integrity monitoring
Day 5: Dashboard creation
```

**Phase 4: Operationalization (Week 4)**
```
Day 1-2: SOC analyst training
Day 3: Incident response procedures
Day 4: Escalation workflows
Day 5: Documentation and handoff
```

### Database Security Enhancements

**Immediate (0-30 days):**
```sql
-- 1. Enable audit logging
SET GLOBAL general_log = 'ON';

-- 2. Restrict user permissions
REVOKE ALL PRIVILEGES ON *.* FROM 'wiki_nonuser'@'%';
GRANT SELECT, INSERT, UPDATE, DELETE ON wiki_webdb.* TO 'wiki_nonuser'@'%';

-- 3. Create read-only monitoring user
CREATE USER 'wazuh_monitor'@'10.43.32.50' IDENTIFIED BY 'MonitorPass123!';
GRANT SELECT ON wiki_webdb.* TO 'wazuh_monitor'@'10.43.32.50';
```

**Short-Term (30-90 days):**
```sql
-- 4. Enable encryption at rest
ALTER TABLE user ENCRYPTION='Y';

-- 5. Implement column-level encryption
-- Encrypt email addresses
UPDATE user SET user_email = AES_ENCRYPT(user_email, 'EncryptionKey');
```

---