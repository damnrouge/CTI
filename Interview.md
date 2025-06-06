# Levels of Threat Intelligence

Threat Intelligence is categorized into three levels based on its purpose, audience, and technical depth: **Strategic**, **Operational**, and **Tactical**.

---

## 1. Strategic Threat Intelligence

**Purpose**: High-level decision-making based on long-term threat trends.  
**Audience**: Executives, CISOs, policymakers.  
**Focus**: Threat actor intent, geopolitical motives, industry risks.

**Characteristics**:
- Non-technical, narrative style
- Derived from open-source, geopolitical, and industry reporting
- Helps shape security strategies and investment

**Examples**:
- Analysis of APT groups targeting energy sectors in Southeast Asia.
- Reports on the impact of AI in phishing and misinformation campaigns.
- Trends showing shift from ransomware encryption to pure extortion.

---

## 2. Operational Threat Intelligence

**Purpose**: Supports planning and coordination of threat detection and incident response.  
**Audience**: Threat Intelligence teams, IR teams, SOC leads.  
**Focus**: Campaigns, attack infrastructure, TTPs (Tactics, Techniques, and Procedures).

**Characteristics**:
- Semi-technical
- Links threats to known adversaries and recent campaigns
- Enables proactive defense posture

**Examples**:
- Report on Scattered Spider’s SIM-swapping + Okta targeting tactics.
- Infrastructure breakdown of LockBit 3.0 affiliates.
- Campaign data using Google Drive links for malware delivery.

---

## 3. Tactical Threat Intelligence

**Purpose**: Provides immediate, actionable data for SOC/EDR/SIEM operations.  
**Audience**: SOC analysts, detection engineers, threat hunters.  
**Focus**: IOCs (Indicators of Compromise), signatures, hashes, domains, rules.

**Characteristics**:
- Highly technical
- Time-sensitive, fast-aging
- Directly feeds into security tooling

**Examples**:
- IP addresses associated with Cobalt Strike C2 servers.
- File hash of malware loader used in recent QakBot attacks.
- YARA rule detecting Excel macro-based infostealers.

---

## Summary Table

| Level       | Focus Area              | Audience            | Output Format                      | Example                              |
|-------------|-------------------------|----------------------|------------------------------------|--------------------------------------|
| Strategic   | Big picture, trends     | Executives, CISOs    | Reports, presentations             | Nation-state targeting forecasts     |
| Operational | Campaigns, TTPs         | IR Teams, TI Teams   | Threat actor profiles, alerts      | Scattered Spider’s social engineering |
| Tactical    | IOCs, malware signatures| SOC Analysts         | Feeds, rules, correlation queries  | Malicious IPs from C2 infrastructure |

---

> Use all three levels in tandem for a mature and responsive cyber threat intelligence program.
--------------------------------------------------------------------------------------------------------------------------------------------

# 🔍 Differentiating Threat Actors, TTPs, IOCs, and IOAs

A structured comparison of four foundational cyber threat intelligence elements.

---

## 1. 🧠 Threat Actors

**Definition**: Individuals, groups, or entities responsible for malicious cyber activities.

**Key Attributes**:
- **Motivation**: Espionage, financial gain, ideology, revenge
- **Types**:
  - Nation-state (e.g., APT29)
  - Cybercriminals (e.g., FIN7)
  - Hacktivists (e.g., Anonymous)
  - Insider threats

**Example**:  
APT28 (Fancy Bear) is a Russian state-sponsored threat group targeting NATO-related entities using spear-phishing and custom malware.

---

## 2. 🛠️ TTPs – Tactics, Techniques, and Procedures

**Definition**: Describes *how* threat actors operate.

**Structure (MITRE ATT&CK-based)**:
- **Tactic**: Why (goal) – e.g., Initial Access
- **Technique**: How (method) – e.g., Phishing (T1566)
- **Procedure**: Specific implementation – e.g., SMS with fake Okta login link

**Example**:  
- Tactic: Initial Access  
- Technique: Spearphishing via SMS (T1566.001)  
- Procedure: Sending fake Okta login page via SMS to targeted employees

---

## 3. 🧾 IOCs – Indicators of Compromise

**Definition**: Observable forensic data confirming compromise.

**Types**:
- File hashes (MD5, SHA256)
- Malicious IPs and domains
- Registry keys, malware file names

**Purpose**: Reactive detection (e.g., SIEM, EDR, IDS)

**Example**:  
- IP Address: 185.141.63.120  
- File Hash (SHA256): 34d2d90f7f2b3...  
- Domain: secure-login[.]xyz

---

## 4. 🔍 IOAs – Indicators of Attack

**Definition**: Behavioral patterns indicating intent to attack, even without known IOCs.

**Purpose**: Proactive detection based on behavior and sequence of actions.

**Examples**:
- PowerShell execution triggered by a Word document
- Outlook spawning `cmd.exe` followed by system enumeration
- Suspicious access to LSASS memory from unknown process

---

## 🧩 Comparison Table

| Category        | Focus           | Nature     | Purpose                          | Examples                                                  |
|----------------|------------------|------------|----------------------------------|-----------------------------------------------------------|
| **Threat Actor**| WHO              | Identity   | Attribution, profiling           | APT29, Lazarus, FIN7                                       |
| **TTPs**        | HOW              | Behavioral | Detection engineering, emulation | Phishing, LOLBins, lateral movement                        |
| **IOCs**        | WHAT (evidence)  | Static     | Reactive detection                | File hashes, malicious domains, registry keys             |
| **IOAs**        | WHAT (intent)    | Dynamic    | Proactive detection               | Word → PowerShell, LSASS memory access, unusual process trees |

---

## ✅ Summary

- **Threat Actors**: WHO is attacking  
- **TTPs**: HOW they operate  
- **IOCs**: WHAT artifacts prove compromise  
- **IOAs**: WHAT behavior shows attack intent  

All four components work best when combined for layered threat intelligence and defense.

---------------------------------------------------------------------------------------------------------------------------------------------------------

# 🛰️ OSINT Tools for Threat Intelligence Gathering

Open-Source Intelligence (OSINT) tools are critical for gathering external threat data, enriching IOCs, profiling adversaries, and monitoring cyber threat landscapes. Below is a categorized list of high-utility OSINT tools used by CTI analysts.

---

## 🌐 Domain, DNS, and WHOIS Investigation

| Tool             | Use Case                                      |
|------------------|-----------------------------------------------|
| **WhoisXML API / WhoisLookup** | Domain registration and ownership metadata       |
| **SecurityTrails**     | Domain history, DNS data, subdomains             |
| **VirusTotal Passive DNS** | Historical DNS records, resolutions              |
| **ViewDNS.info**       | Multi-function DNS, ASN, reverse tools            |
| **CRT.sh**             | Certificate transparency logs for subdomain discovery |

---

## 🔎 IP and Infrastructure Intelligence

| Tool              | Use Case                                      |
|-------------------|-----------------------------------------------|
| **Shodan**             | Internet-exposed services, banners, and device metadata |
| **Censys**             | Similar to Shodan; enriched with certificate analysis   |
| **Greynoise**          | Internet noise vs targeted attack distinction           |
| **AbuseIPDB**          | Crowdsourced malicious IP reputation tracking           |
| **IPinfo.io / MaxMind**| GeoIP, ASN, and network ownership lookup                |

---

## 🦠 Malware & File Intelligence

| Tool               | Use Case                                      |
|--------------------|-----------------------------------------------|
| **VirusTotal**         | File, URL, domain reputation, sandbox detonation |
| **Hybrid Analysis**    | Deep static/dynamic malware analysis             |
| **Joe Sandbox**        | Advanced malware sandbox with MITRE mapping      |
| **MalShare**           | Community-contributed malware samples             |
| **Any.Run (Community)**| Interactive malware analysis                      |

---

## 👤 Threat Actor Profiling

| Tool              | Use Case                                      |
|-------------------|-----------------------------------------------|
| **Malpedia**          | Malware family + actor attribution            |
| **APTNotes / APTWiki**| Community-collected APT group reports         |
| **MITRE ATT&CK**      | Mapping TTPs to threat groups                 |
| **ThreatFox**         | Real-time malware IOC feeds from abuse.ch    |

---

## 📲 Social Media & Dark Web Monitoring

| Tool               | Use Case                                      |
|--------------------|-----------------------------------------------|
| **IntelX**             | Breach data, dark web content, paste sites      |
| **DeHashed**           | Email, password, and breach search             |
| **Recon-ng**           | Modular recon tool for profiling via social platforms |
| **SpiderFoot HX**      | Automated OSINT + dark web correlation          |

---

## 🛠️ Automation and Aggregation Tools

| Tool              | Use Case                                      |
|-------------------|-----------------------------------------------|
| **TheHarvester**      | Email, domain, and IP OSINT gathering        |
| **Amass**             | Subdomain enumeration and mapping            |
| **OSINT Framework**   | Web-based directory of categorized OSINT tools |
| **OpenCTI**           | Threat intel platform for correlation        |
| **MISP**              | Sharing and managing threat intelligence     |

---

## ⚡ Example Workflow (for IOC enrichment)

1. **Input IOC**: Malicious domain  
2. **Run Tools**:
   - `VirusTotal` – check reputation, relations  
   - `SecurityTrails` – domain history, subdomains  
   - `WhoisXML` – registrar, creation date, email  
   - `Shodan/Censys` – see hosting infrastructure  
3. **Correlate with Threat Actors** using:
   - `MITRE ATT&CK`  
   - `Malpedia`  
   - `ThreatFox`

---

## 🧠 Analyst Tip

- Validate tool results across multiple sources.
- Use APIs + automation for bulk IOC enrichment.
- Leverage MISP or OpenCTI for storing, correlating, and tagging collected intel.

---

> OSINT is only as powerful as the analyst using it—combine tools, context, and critical thinking for actionable intelligence.

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# 🎯 How to Collect and Validate Indicators of Compromise (IOCs)

The accuracy and timeliness of IOC collection and validation are critical for threat detection, hunting, and incident response. Below is a structured breakdown of how CTI analysts collect and validate IOCs.

---

## 📥 1. IOC Collection Sources

### ✅ **Internal Sources**
| Source                     | Description                                      |
|----------------------------|--------------------------------------------------|
| EDR/XDR Alerts             | Malware detections, process telemetry            |
| SIEM Logs                  | Firewall, proxy, DNS, and authentication logs    |
| Incident Response Reports  | Artifacts from previous compromise investigations |
| Honeypots                  | Trap systems to lure and capture threat data     |
| Sandbox Detonations        | Extracted indicators from file/URL analysis      |

### 🌐 **External Sources**
| Source                     | Description                                      |
|----------------------------|--------------------------------------------------|
| Threat Feeds (MISP, Abuse.ch, OTX) | Community or commercial feeds           |
| VirusTotal, Hybrid Analysis        | Public sandbox + reputation services   |
| CERT/CISA Alerts                   | Government advisories with IOCs        |
| Paste Sites & Dark Web             | Leaks, breach data, tools/scripts      |
| APT Reports                        | Adversary profiling with TTPs & IOCs   |

---

## 📊 2. Types of IOCs Collected

| Category         | Examples                                      |
|------------------|-----------------------------------------------|
| **Network**      | IP addresses, domains, URLs, DNS queries      |
| **Host-based**   | File hashes, registry keys, mutexes           |
| **Email**        | Subject lines, headers, sender info           |
| **Behavioral**   | Process trees, command-line arguments         |

---

## 🔍 3. IOC Validation Workflow

### 🔁 A. **De-duplication**
- Remove exact and near-duplicate IOCs.
- Normalize formats (e.g., lowercase domains, hash types).

### 🧪 B. **Contextual Analysis**
| Check                         | Purpose                                      |
|-------------------------------|----------------------------------------------|
| **Timestamp**                 | Is the IOC recent and relevant?             |
| **False Positives**           | Is the IP/domain used by CDN/VPN/service?   |
| **Frequency Analysis**        | IOC seen once vs. widespread activity        |
| **Behavioral Linkage**        | Is it tied to a known malicious behavior?   |

### 🧰 C. **Tool-Based Validation**
- `VirusTotal` → Multi-engine check
- `Hybrid Analysis` / `Joe Sandbox` → Behavioral validation
- `Shodan` / `Censys` → Validate infrastructure behind IP/domain
- `Threat Intelligence Platform (TIP)` → Correlation scoring, tagging

### 🔐 D. **Threat Actor Association**
- Map against known campaigns using:
  - MITRE ATT&CK mappings
  - APT reports (e.g., FireEye, Mandiant, CrowdStrike)
  - Malpedia, ThreatFox

---

## 🧠 Example Scenario: IOC (IP Address 185.234.219.27)

1. **Check VirusTotal**: Low detection? → May be benign or CDN  
2. **Check AbuseIPDB**: Recent malicious reports?  
3. **Correlate via MISP/OTX**: Linked to known malware?  
4. **Check in internal logs**: Has it communicated with internal assets?

If IOC is:
- Seen across multiple sensors and sources
- Behaves maliciously in sandbox
- Matches known TTPs or threat actor infra

✅ **Mark as Validated IOC**  
❌ Else → Flag as Low Confidence / Watchlist / Discard

---

## 🗂️ IOC Tagging & Storage

- Store IOCs in MISP, OpenCTI, or TIP
- Tag with:
  - Source reliability (e.g., CISA, OTX, internal IR)
  - Confidence level (High, Medium, Low)
  - TTL (Time to Live) and expiration
  - Linked threat actor or malware family

---

## ✅ Summary

| Step                   | Action                                       |
|------------------------|----------------------------------------------|
| **Collection**         | Gather from internal + external sources      |
| **Normalization**      | Clean and standardize IOCs                   |
| **Validation**         | Cross-reference, sandbox, context check      |
| **Enrichment**         | Associate with malware, TTPs, actors         |
| **Tagging & Storage**  | Confidence scoring, attribution, TTL         |

---

> High-confidence IOCs fuel detection, hunting, and proactive defense. Avoid blind ingestion—validate before action.

----------------------------------------------------------------------------------------------------------------------------
# 🔐 Closed and Private Threat Intelligence Sources

In addition to open-source intelligence (OSINT), **closed/private intelligence sources** provide higher fidelity, context-rich, and often timely insights into threats. These sources are typically gated by access restrictions, memberships, NDAs, or covert collection methods.

---

## 🏛️ 1. ISACs – Information Sharing and Analysis Centers

**Definition**: Sector-specific groups that facilitate threat intelligence sharing among trusted members.

| ISAC                        | Sector Focus                         |
|-----------------------------|--------------------------------------|
| FS-ISAC                     | Financial Services                   |
| H-ISAC                     | Healthcare and Public Health         |
| Energy ISAC (E-ISAC)        | Energy and Utilities                 |
| Aviation ISAC               | Aerospace and Aviation               |
| Retail & Hospitality ISAC   | Consumer/Retail Services             |
| IT-ISAC                     | Information Technology               |
| MS-ISAC                    | State and Local Government (USA)     |

**Benefits**:
- Contextualized, actionable intel
- Peer collaboration
- Early warnings of sector-specific campaigns

---

## 🕵️ 2. Dark Web Forums and Marketplaces

**Access**: Tor network, encrypted channels, invite-only boards  
**Usage**: Tracking threat actor chatter, leaked credentials, malware sales, TTPs

| Source Category            | Content Examples                                  |
|----------------------------|---------------------------------------------------|
| Hacking Forums             | TTP discussions, malware/tool leaks               |
| Data Breach Markets        | Leaked DBs, PII, credit card dumps                |
| Initial Access Brokers     | Access to RDP/VPN of organizations for sale       |
| Ransomware Leak Sites      | Victim data leak previews (e.g., LockBit, BlackCat)|
| Telegram Channels          | Coordinated campaigns, tool drops, exploit kits   |

**Monitoring Tools**:
- KELA
- Flashpoint
- DarkOwl
- Recorded Future (Dark Web module)
- Cybersixgill

---

## 🤝 3. Private Threat Intelligence Vendors

Vendors offer paid access to proprietary, curated threat intelligence feeds and actor profiling.

| Vendor                  | Features                                                |
|-------------------------|---------------------------------------------------------|
| **Mandiant Advantage**   | Actor tracking, TTP insights, incident-specific intel  |
| **Recorded Future**      | Real-time feeds, dark web, risk scoring, alerting      |
| **CrowdStrike Falcon X** | IOC enrichment, adversary intelligence, API access     |
| **Intel 471**            | Cybercrime actor tracking, underground monitoring      |
| **Group-IB**             | Underground infra tracking, ransomware group activity  |
| **Kaspersky Intel Portal**| Nation-state actor reports, YARA rules, TTPs         |

---

## 🧪 4. Private Research Sharing & Trust Groups

| Group Type               | Description                                           |
|--------------------------|--------------------------------------------------------|
| **Threat Intelligence Sharing Groups (TISGs)** | Invite-only analyst groups sharing TTPs, IOCs, and incident data |
| **Slack/Discord/Signal Groups** | Analyst-run communities with limited access       |
| **RFI Exchanges (via MISP, OpenCTI)** | Structured threat sharing under NDA or MOUs    |

**Examples**:
- Analyst1 Community
- CTI League (Healthcare-focused, vetted)
- Red Sky Alliance
- Operation Transit (Dark web-focused collaboration group)

---

## 🛡️ 5. Government & CERT Channels (Access-restricted)

| Source               | Access Type                       |
|----------------------|------------------------------------|
| CISA AIS (Automated Indicator Sharing) | Registered U.S. orgs only     |
| JPCERT/CC             | Japanese CERT with limited release intel |
| NATO MISP             | Shared among NATO nation CERTs     |
| Europol EC3           | Shared with law enforcement and partners |

---

## ⚙️ Integration with SOC/IR Workflow

| Integration Point     | Description                                       |
|------------------------|--------------------------------------------------|
| TIP Platforms (e.g., MISP, OpenCTI) | Correlate closed-source IOCs with alerts   |
| SOAR Enrichment        | Use APIs from vendors (e.g., Recorded Future)    |
| Dark Web Monitoring Alerts | Track mentions of your brand/org in real time   |
| Threat Actor Mapping   | Use vendor reports to enhance MITRE ATT&CK use   |

---

## ✅ Summary

| Category            | Examples                                           | Purpose                                |
|---------------------|----------------------------------------------------|----------------------------------------|
| **ISACs**            | FS-ISAC, H-ISAC, IT-ISAC                          | Sector-wide sharing, early alerts      |
| **Dark Web Sources** | Ransomware leak sites, forums, Telegram channels | Underground threat tracking            |
| **Vendors**          | Mandiant, CrowdStrike, Intel471, Flashpoint      | Curated TTPs, IOCs, actor behavior     |
| **Trust Groups**     | Analyst1, CTI League, Red Sky Alliance           | Private analyst collaboration          |
| **Gov/CERT Access**  | CISA AIS, JPCERT/CC, Europol                     | Government alerts, sensitive indicators|

---

> Closed sources bridge the intelligence gap that OSINT cannot—leverage them for deeper context, earlier warnings, and targeted defense.




