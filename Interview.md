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

