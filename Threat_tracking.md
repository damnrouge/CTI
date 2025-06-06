# Cyber Threat Intelligence (CTI) Interview Preparation Guide

---

## 1. Fundamentals of CTI

### ❓ What is Cyber Threat Intelligence (CTI), and how does it differ from traditional threat data?
- CTI is analyzed, contextual threat information used to prevent or respond to cyber threats.
- Traditional threat data is raw (e.g., IPs, hashes), while CTI is actionable, enriched, and aligned to organizational needs.

### 🔄 Explain the intelligence lifecycle:
1. **Planning & Direction** – Define intelligence needs.
2. **Collection** – Gather data from various sources.
3. **Processing** – Clean, normalize, and format data.
4. **Analysis** – Extract meaning and assess impact.
5. **Dissemination** – Share with relevant stakeholders.
6. **Feedback** – Refine future cycles based on input.

### 🧠 What are the three levels of threat intelligence?

| Level       | Description                                           | Example                                                  |
|-------------|-------------------------------------------------------|----------------------------------------------------------|
| Strategic   | High-level, long-term threat insights                 | Geopolitical risk reports for executive decisions        |
| Operational | Campaign, actor, or sector-level threat activity      | Ransomware trend targeting financial services            |
| Tactical    | Technical details to support defense teams            | IOC feeds, malware hashes, YARA/Sigma rules              |

### 🧩 How do you differentiate between:
- **Threat Actors** – Individuals or groups (e.g., APT29)
- **TTPs** – Tactics, Techniques, Procedures (e.g., MITRE ATT&CK)
- **IOCs** – Artifacts like IPs, hashes, domains
- **IOAs** – Behavioral patterns suggesting an attack (e.g., suspicious PowerShell use)

---

## 2. Threat Intelligence Collection & Sources

### 🛠 What are some OSINT tools for threat intelligence?
- Shodan, VirusTotal, Censys, URLscan, Maltego, SpiderFoot, PassiveTotal, GitHub, Reddit, Twitter

### 📦 How do you collect and validate IOCs?
- Collected via sensors, logs, feeds.
- Validated using sandboxing, manual analysis, frequency correlation, context scoring.

### 🔐 What are some closed/private sources?
- ISACs (FS-ISAC, MS-ISAC), threat intel vendors (Recorded Future, Intel 471), private threat-sharing groups, paid dark web monitoring.

### 🕵️‍♂️ How would you monitor dark web forums?
- Use threat intel vendors/tools or Tor access + scrapers.
- Track keywords, actor handles, and leak dumps.
- Leverage HUMINT or automated crawlers.

---

## 3. Threat Analysis & Attribution

### 🧪 How would you analyze malware for threat intel?
- Static + dynamic analysis (e.g., Ghidra, Cuckoo Sandbox)
- Extract IOCs, behavior, C2s, techniques
- Compare against known families/campaigns

### 🎯 How do you attribute attacks to actors?
- Analyze infrastructure reuse, malware variants, TTP alignment (MITRE), language/metadata, historical data

### 🧨 Common APT groups and differences:
- **APT29 (Cozy Bear):** Stealthy, phishing + malware, targets gov.
- **APT41:** Chinese nexus, blends cybercrime and espionage, supply-chain attacks

### 📋 How to assess threat report credibility?
- Source reliability, corroboration, methodology transparency, date relevance, motive of source

---

## 4. Threat Intelligence Sharing & Reporting

### 🧾 How to structure intel reports:
- **Executives:** High-level impact, risk summary, trends
- **SOC Analysts:** IOC list, detection logic, TTP mapping, log queries

### 🔄 Standard formats:
- **STIX/TAXII:** Structured sharing protocols
- **MISP:** Community-based platform for sharing and enrichment

### 🛡 How to ensure actionability?
- Include IOC validity, detection mechanisms (YARA, Sigma), recommended mitigations

### ⚠️ Sharing challenges:
- Legal/regulatory constraints, trust issues, data classification, vendor lock-in, info overload

---

## 5. CTI Tools & Technologies

### 🔍 SIEM, TIPs, and threat feeds used:
- **SIEMs:** Splunk, QRadar, Sentinel
- **TIPs:** MISP, ThreatConnect, Anomali
- **Feeds:** AlienVault OTX, Abuse.ch, MalwareBazaar, Intel 471

### 🔄 Integration into SOC:
- IOC ingestion, correlation with log data
- Detection rule enrichment
- Alerts and case enrichment

### 🧬 Use of YARA:
- Create signatures for malware family detection in memory, files
- Deployed across EDR, sandboxes, or scanning tools

### 🤖 Automating CTI:
- SOAR tools (Cortex XSOAR, Phantom)
- API ingestion (TAXII, RSS)
- Scripted enrichment, IOC deduplication, threat scoring

---

## 6. Practical Scenario-Based Questions

### 🦠 New ransomware investigation:
- Collect IOCs, TTPs
- Sandbox behavior
- Map to MITRE
- Notify stakeholders + create detection content

### 🎣 New phishing campaign:
- Extract domains, URLs, sender details
- Check delivery vector (email headers)
- Share with IR/SOC
- Monitor similar artifacts

### 🧨 Zero-day exploit on dark web:
- Track actor selling it
- Gather TTPs or code samples
- Assess targeting
- Alert security teams

### 🛡 Post-breach hunting:
- Use known TTPs/IOCs from IR
- Hunt historical logs
- Pivot to find lateral movement, persistence

---

## 7. CTI & Incident Response (IR)

### 🧩 How CTI supports IR:
- Accelerates triage and containment
- Provides threat context and prioritization
- Informs playbook customization

### 🎯 Using IOCs for detection:
- Feed into SIEM/EDR
- Write rules for correlation
- Alert tuning based on IOC scoring

### 🔍 Retrospective hunting:
- Search historical logs with newly discovered IOCs/TTPs
- Validate past compromise or missed alerts

---

## 8. Soft Skills & Team Collaboration

### 📣 Communicating with non-tech stakeholders:
- Avoid jargon
- Use business impact language
- Provide risk scores, trends, and clear actions

### 📰 Staying updated:
- Threat intel blogs (Kaspersky, Mandiant, Unit42)
- CTI communities (Curated Intel, ThreatIntel Slack)
- Reports (MSTIC, DFIR Report, CISA advisories)

### 💡 Real-world impact:
- Example: Proactively blocked a phishing domain targeting executives, preventing credential theft

---

Would you like these questions tailored to **entry**, **mid**, or **senior** level, or customized for specific **focus areas** like **malware analysis**, **APT tracking**, or **threat hunting**?
