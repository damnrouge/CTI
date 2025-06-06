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
