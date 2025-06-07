# AWS Security Best Practices for Protecting Cloud Infrastructure

Securing AWS infrastructure requires a layered, defense-in-depth approach. Below are key best practices categorized into critical domains:

---

## 1. **Identity and Access Management (IAM)**

- **Use Least Privilege**: Grant users and services the minimum permissions needed.
- **Enable MFA**: Enforce Multi-Factor Authentication for all IAM users, especially root.
- **Avoid Root Account Usage**: Use the root account only for account setup. Create an IAM admin user for daily tasks.
- **Use IAM Roles**: Assign roles to services instead of embedding credentials in code.
- **Implement Permission Boundaries**: Restrict the maximum permissions IAM entities can have.

---

## 2. **Network Security**

- **Use VPC Segmentation**: Separate environments (e.g., prod, dev) using VPCs or subnets.
- **Restrict Inbound/Outbound Traffic**: Use **Security Groups** and **NACLs** to control traffic flow.
- **Use Private Subnets**: Place sensitive workloads in private subnets, expose only necessary services.
- **Enable VPC Flow Logs**: Monitor traffic at the interface level for anomaly detection.

---

## 3. **Data Protection**

- **Encrypt Data at Rest and In Transit**:
  - Use AWS KMS or CMKs for data encryption.
  - Use SSL/TLS for all data in transit.
- **Manage Keys Securely**: Use **AWS KMS** with key rotation enabled.
- **Classify and Tag Sensitive Data**: Use **Macie** for discovering and protecting sensitive data (e.g., PII).

---

## 4. **Monitoring and Logging**

- **Enable CloudTrail**: Audit account activity across AWS services.
- **Use GuardDuty**: Enable for intelligent threat detection using AWS logs and threat intelligence.
- **Enable AWS Config**: Track resource configurations and compliance over time.
- **Centralize Logs**: Aggregate logs to **Amazon S3** or **CloudWatch Logs** with encryption and access controls.
- **Set CloudWatch Alarms**: Alert on abnormal activity (e.g., high API call rates, IAM changes).

---

## 5. **Compute Security (EC2, Lambda, ECS)**

- **Harden EC2 Instances**:
  - Use up-to-date AMIs.
  - Disable unused ports/services.
  - Enable host-based firewalls (e.g., iptables).
- **Use Instance Roles Instead of Hardcoded Credentials**.
- **Use Security Groups to Limit Access** to compute resources.
- **Apply Patch Management** via Systems Manager or automation.
- **Scan Container Images**: Use Amazon ECR image scanning or third-party tools.

---

## 6. **Application Security**

- **Use WAF (Web Application Firewall)**: Protect web applications from common exploits.
- **Enable Shield Advanced**: Protect against DDoS attacks for critical workloads.
- **Validate Input/Output**: Always sanitize user input to avoid injection attacks.
- **Use API Gateway with Throttling and Auth**: Apply rate limiting and authentication (e.g., Cognito, IAM) to APIs.

---

## 7. **Incident Response and Recovery**

- **Create an IR Playbook**: Document response steps, roles, and contacts.
- **Test IR Procedures**: Run simulations using AWS Fault Injection Simulator or Chaos Engineering.
- **Enable Snapshot Backups**: Regular backups using AWS Backup or custom scripts.
- **Use Cross-Region Replication**: For disaster recovery and business continuity.

---

## 8. **Compliance and Governance**

- **Use AWS Organizations and SCPs**: Enforce compliance and control services used by accounts.
- **Tag Resources**: For accountability, cost tracking, and automation.
- **Audit Regularly**: Use **AWS Audit Manager** and **Security Hub** for continuous compliance checks.

---

## 9. **DevSecOps Practices**

- **Integrate Security in CI/CD**:
  - Use code scanning tools like **CodeGuru Security**.
  - Scan IaC templates using **CFN-Nag**, **Checkov**, or **Terraform Validator**.
- **Version Control Infrastructure**: Track changes in IaC (CloudFormation, Terraform) in Git.
- **Automate Security Controls**: With Lambda, EventBridge, or AWS Config Rules.

---

## 10. **Cost and Resource Management**

- **Limit Overprovisioned Resources**: Rightsize instances and services.
- **Set Budgets and Alarms**: Prevent unexpected usage spikes.

---

## Conclusion

Security in AWS is a **shared responsibility**. AWS secures the infrastructure; you must secure what's deployed on it. Regular reviews, automated guardrails, and continuous monitoring are critical for strong security posture.
---


# AWS Shared Responsibility Model

The **AWS Shared Responsibility Model** clearly defines **who is responsible for what** when it comes to security and compliance in the cloud. It separates security duties between **AWS (the provider)** and **you (the customer)**.

---

## 🔐 Two Core Responsibility Domains

| Domain                | Responsibility                     |
|-----------------------|-------------------------------------|
| **Security *of* the Cloud** | **AWS's responsibility**          |
| **Security *in* the Cloud** | **Customer's responsibility**     |

---

## 1. ✅ AWS Responsibility: **Security *of* the Cloud**

AWS is responsible for **protecting the infrastructure** that runs all the services offered in the AWS Cloud.

### Key Areas:
- **Physical security** of data centers.
- **Hardware** and **software infrastructure** (compute, storage, networking).
- **Global network** and facilities.
- **Foundation services**: EC2, S3, Lambda infrastructure security.
- **Hypervisor and virtualization layer** (for IaaS).

### Examples:
- Preventing physical access to servers.
- Securing the hardware and firmware.
- Patching the host OS and hypervisor for EC2.

---

## 2. 🔒 Customer Responsibility: **Security *in* the Cloud**

Customers are responsible for **securing what they deploy and configure** within AWS services.

### Key Areas:
- **Data classification and encryption**.
- **Access management** (IAM, MFA, permissions).
- **Operating system** and **application-level security** (on EC2 or containerized environments).
- **Security configurations** (S3 bucket policies, security groups, VPCs).
- **Monitoring, logging, and incident response**.

### Examples:
- Encrypting S3 buckets.
- Applying OS-level patches on EC2.
- Managing IAM roles and policies.
- Configuring WAF and GuardDuty.
- Detecting and responding to malicious activity.

---

## 📦 Varies by Service Model

| Cloud Model | AWS Responsibility                                 | Customer Responsibility                                     |
|-------------|-----------------------------------------------------|-------------------------------------------------------------|
| **IaaS** (e.g., EC2, VPC) | Infrastructure, hypervisor, physical hardware | OS, apps, network config, data, IAM                         |
| **PaaS** (e.g., RDS, ECS) | Underlying OS, service config, infrastructure | Data, IAM, platform usage settings                         |
| **SaaS** (e.g., Amazon Chime) | All platform-level management           | User access, data input and protection                      |

---

## 📊 Summary Table

| Responsibility Area          | AWS Responsibility | Customer Responsibility |
|-----------------------------|---------------------|--------------------------|
| Physical security            | ✅                  | ❌                       |
| Hypervisor & host OS         | ✅                  | ❌                       |
| Network infrastructure       | ✅                  | ❌                       |
| IAM configuration            | ❌                  | ✅                       |
| Operating system (EC2)       | ❌                  | ✅                       |
| Application code             | ❌                  | ✅                       |
| Data security & encryption   | ❌                  | ✅                       |
| Logging & monitoring         | ❌                  | ✅                       |

---

## CTI (Cyber Threat Intelligence) View

From a CTI perspective, understanding this model helps in:

- **Attributing misconfigurations**: e.g., public S3 bucket is a customer-side misconfiguration.
- **Threat surface mapping**: Define where your team must monitor, harden, and respond.
- **Responsibility delineation in IR**: Understand which party (you vs. AWS) is accountable during incident handling.

---

## 🛡️ Key Takeaway

> **AWS secures the infrastructure. You must secure your workloads, identities, data, and configurations.**

Neglecting customer-side responsibilities leads to common attack vectors like:
- Exposed S3 buckets
- Overprivileged IAM roles
- Misconfigured security groups

---

# AWS Identity and Access Management (IAM): Overview and Security Best Practices

---

## What is AWS IAM?

AWS Identity and Access Management (IAM) is a service that enables you to securely control access to AWS resources.

- **Users:** Individual identities with long-term credentials.  
- **Groups:** Collections of users with shared permissions.  
- **Roles:** Temporary credentials assigned to services or users.  
- **Policies:** JSON documents defining permissions (Allow or Deny).

---

## IAM Security Threats (Relevant MITRE ATT&CK Techniques)

| Technique ID | Description                             |
|--------------|---------------------------------------|
| T1078        | Use of valid accounts (stolen creds)  |
| T1550        | Use of alternate authentication methods (access keys, tokens) |
| T1087        | Account enumeration                    |
| T1606        | Forging web credentials               |

---

## IAM Security Best Practices

### 1. Principle of Least Privilege  
Grant only the minimal required permissions and restrict to necessary resources.

Example policy snippet:

{
"Effect": "Allow",
"Action": "s3:GetObject",
"Resource": "arn:aws:s3:::my-bucket/*"
}


---

### 2. Use IAM Roles Instead of IAM Users for Applications  
Assign roles to AWS services (EC2, Lambda, ECS) to avoid embedding static credentials.

---

### 3. Enforce Multi-Factor Authentication (MFA)  
Require MFA for root account, privileged users, and federated identities.

---

### 4. Monitor and Rotate Credentials  
- Regularly audit and disable unused access keys.  
- Rotate keys periodically.  
- Use AWS CloudTrail, GuardDuty, and Access Analyzer for monitoring.

---

### 5. Use Permission Boundaries and Service Control Policies (SCPs)  
- Permission Boundaries limit max permissions on IAM entities.  
- SCPs enforce organization-wide permission guardrails.

---

### 6. Audit and Alert on IAM Events  
Monitor critical events like `CreateUser`, `AttachPolicy`, `AssumeRole`, and `ConsoleLogin` using CloudTrail and AWS Config.

---

### 7. Avoid Using Root Account for Daily Tasks  
- Use root only for initial setup and emergencies.  
- Secure root credentials with strong password and MFA.

---

### 8. Use IAM Access Analyzer  
Detect overly permissive policies and unintended external access.

---

## Real-World Example

**Incident:** An AWS access key leaked on a public repo allowed an attacker to assume roles with permissions like `iam:PassRole` and `s3:GetObject`.

**Mitigation:**  
- Immediate key revocation and rotation.  
- Use CloudTrail logs for incident analysis.  
- Restrict role permissions and implement strict trust policies.  
- Avoid hardcoding credentials; use Secrets Manager or Parameter Store.

---

## Summary

| Practice                   | Purpose                                |
|----------------------------|---------------------------------------|
| Least Privilege            | Minimize attack surface                |
| IAM Roles                  | Avoid static credentials               |
| MFA                        | Protect against compromised passwords |
| Credential Rotation        | Limit exposure time                    |
| Monitoring & Logging       | Detect and respond to suspicious activity |
| Access Analyzer            | Identify misconfigurations             |
| Avoid Root Usage           | Minimize high-risk access              |

---

**Key Takeaway:**  
IAM is critical for AWS security. Misconfigurations or weak controls expose your environment to unauthorized access and compromise. Enforce strong IAM controls aligned with threat intelligence insights to maintain a secure cloud infrastructure.

---

# AWS GuardDuty: Threat Detection Overview

---

## What is AWS GuardDuty?

AWS GuardDuty is a continuous threat detection service that monitors malicious or unauthorized behavior to help protect your AWS accounts, workloads, and data stored in AWS.

It analyzes data from multiple sources such as:

- **AWS CloudTrail event logs** (API calls)
- **VPC Flow Logs** (network traffic)
- **DNS logs**

GuardDuty uses machine learning, anomaly detection, and integrated threat intelligence feeds to identify potential security threats.

---

## How GuardDuty Helps in Threat Detection

- **Continuous Monitoring:** Automatically and continuously scans AWS account activity and network traffic for suspicious behavior.
- **Threat Intelligence Integration:** Combines AWS threat intelligence and third-party feeds to detect known malicious IPs, domains, and other indicators.
- **Anomaly Detection:** Detects unusual API calls, unauthorized deployments, or reconnaissance activities through ML-based behavioral analysis.
- **Actionable Alerts:** Generates detailed findings with severity levels and recommended remediation steps.
- **Integration:** Works with AWS Security Hub, CloudWatch Events, and Lambda for automated response.

---

## Types of Threats GuardDuty Can Identify

| Threat Category             | Examples of Specific Threats                                  |
|----------------------------|--------------------------------------------------------------|
| **Unauthorized Access**    | Use of compromised credentials, unusual API calls, console login anomalies |
| **Reconnaissance**         | Port scanning, unusual DNS requests, reconnaissance of network resources |
| **Instance Compromise**    | Communication with known malicious IPs, cryptocurrency mining activity, unusual network traffic patterns |
| **Privilege Escalation**   | Attempts to escalate permissions or assume unauthorized roles |
| **Data Exfiltration**      | Suspicious data transfer patterns or access to sensitive data |
| **Account Takeover**       | Changes to security groups, creation of suspicious users or keys |
| **Malware & Botnets**      | Instances communicating with known command-and-control servers |

---

## Summary

| GuardDuty Feature           | Benefit                                       |
|----------------------------|-----------------------------------------------|
| Continuous, automated detection | Real-time threat awareness                    |
| Integration with AWS logs   | Comprehensive visibility into user and network activity |
| ML and anomaly detection   | Identifies novel and evolving threats          |
| Threat intelligence feeds  | Detects known malicious actors and IPs         |
| Actionable alerts          | Enables fast, informed incident response       |

---

**Key Takeaway:**  
AWS GuardDuty strengthens your security posture by proactively identifying suspicious activities and potential threats across your AWS environment, enabling rapid detection and response before damage occurs.

---

# AWS Security Hub: Overview and Integration

---

## What is AWS Security Hub?

AWS Security Hub is a centralized security and compliance service that aggregates, organizes, and prioritizes security alerts (findings) from multiple AWS services and third-party tools.

- Provides a comprehensive view of your security posture across your AWS accounts.
- Continuously monitors your environment against security standards and best practices.
- Supports compliance frameworks such as CIS AWS Foundations Benchmark, PCI DSS, and more.

---

## Core Functions of AWS Security Hub

- **Aggregation:** Collects findings from integrated AWS services and partner products.
- **Normalization:** Standardizes findings into a common format using AWS Security Finding Format (ASFF).
- **Prioritization:** Scores and groups findings by severity and resource impact.
- **Visualization:** Dashboards provide an at-a-glance summary of security posture and compliance status.
- **Automated Response:** Integrates with AWS Lambda and AWS Systems Manager for automated remediation.

---

## Integration with AWS Security Services

| Service                  | Integration Purpose                                      |
|--------------------------|---------------------------------------------------------|
| **Amazon GuardDuty**      | Imports threat detection findings for unified view.    |
| **AWS Config**            | Monitors resource configurations and compliance.       |
| **Amazon Macie**          | Detects sensitive data exposure and alerts Security Hub.|
| **AWS Firewall Manager**  | Shares firewall policy violations and alerts.           |
| **AWS Inspector**         | Sends vulnerability assessment findings.                |
| **AWS CloudTrail**        | Used indirectly for event data supporting findings.    |

---

## Integration with Third-Party Security Tools

- Security Hub supports ingestion of findings from popular third-party security solutions, enabling centralized management across hybrid environments.
- Uses standard formats like ASFF, enabling interoperability.

---

## Benefits of Using AWS Security Hub

- **Centralized Security Posture:** Single pane of glass for all AWS security alerts.
- **Improved Visibility:** Correlates data across services for better context.
- **Simplified Compliance:** Automated checks against industry standards.
- **Streamlined Response:** Enables automation of investigation and remediation workflows.

---

## Summary

| Feature                  | Benefit                                              |
|--------------------------|-----------------------------------------------------|
| Findings Aggregation     | Unified view of all security alerts                  |
| Standardized Format      | Easier integration and correlation                    |
| Compliance Checks       | Continuous monitoring of security best practices      |
| Automation Integration  | Faster and consistent incident response               |

---

**Key Takeaway:**  
AWS Security Hub acts as the security command center for AWS environments by integrating multiple security services and tools into a centralized platform, enhancing detection, compliance, and response capabilities.

---
# Threat Detection & Intelligence in AWS

---

## Monitoring and Detecting Malicious Activity Using AWS-Native Tools

AWS provides a suite of native security and monitoring services designed to detect, analyze, and respond to malicious activities in your cloud environment. Here’s a structured approach using these tools:

---

## 1. AWS CloudTrail

- **Purpose:** Records all API calls and user activity within your AWS account.
- **Use Case:**  
  - Detect unauthorized or suspicious API calls (e.g., `CreateUser`, `DeleteRole`, `ConsoleLogin` failures).  
  - Track changes in permissions and resource configurations.
- **How to Use:**  
  - Enable CloudTrail across all regions.  
  - Integrate with Amazon CloudWatch Logs for real-time monitoring and alerting.

---

## 2. Amazon GuardDuty

- **Purpose:** Continuous threat detection service analyzing CloudTrail logs, VPC Flow Logs, and DNS logs.
- **Use Case:**  
  - Detect compromised instances communicating with known malicious IPs.  
  - Identify suspicious API calls and reconnaissance activities.  
  - Alert on privilege escalation attempts and unusual network traffic.
- **How to Use:**  
  - Enable GuardDuty in all AWS accounts and regions.  
  - Review findings in GuardDuty console or forward to AWS Security Hub.

---

## 3. AWS Security Hub

- **Purpose:** Centralized aggregation and prioritization of security findings from multiple AWS services.
- **Use Case:**  
  - Correlate GuardDuty alerts with findings from Amazon Macie, AWS Inspector, and Config.  
  - Monitor compliance against standards like CIS AWS Foundations.
- **How to Use:**  
  - Enable Security Hub and integrate with GuardDuty, Macie, Inspector.  
  - Use dashboards and automated actions for incident response.

---

## 4. Amazon Macie

- **Purpose:** Data security service that uses machine learning to discover and protect sensitive data stored in S3.
- **Use Case:**  
  - Detect inadvertent exposure of personally identifiable information (PII) or credentials.  
  - Alert on unusual access patterns to sensitive data.
- **How to Use:**  
  - Enable Macie on S3 buckets storing sensitive data.  
  - Review findings regularly for suspicious activity.

---

## 5. AWS Config

- **Purpose:** Continuous monitoring and recording of AWS resource configurations.
- **Use Case:**  
  - Detect drift from secure baseline configurations.  
  - Identify unauthorized resource changes or policy violations.
- **How to Use:**  
  - Enable AWS Config rules to enforce best practices.  
  - Configure alerts for non-compliance.

---

## 6. VPC Flow Logs

- **Purpose:** Capture detailed network traffic information within your VPC.
- **Use Case:**  
  - Monitor for unusual inbound/outbound traffic patterns.  
  - Identify data exfiltration or communication with malicious IPs.
- **How to Use:**  
  - Enable flow logs for critical VPCs or subnets.  
  - Analyze logs with Amazon Athena or send to GuardDuty.

---

## 7. Amazon CloudWatch

- **Purpose:** Centralized monitoring and alerting platform.
- **Use Case:**  
  - Create metrics and alarms for suspicious patterns (e.g., high failed login attempts).  
  - Trigger automated responses using AWS Lambda.
- **How to Use:**  
  - Set custom dashboards and alerts based on CloudTrail and other logs.

---

## 8. AWS Lambda for Automated Response

- **Purpose:** Serverless compute for automated remediation.
- **Use Case:**  
  - Automatically isolate compromised instances.  
  - Revoke suspicious IAM credentials.  
  - Notify security teams.
- **How to Use:**  
  - Trigger Lambda functions from CloudWatch Events or Security Hub findings.

---

## Summary Table

| AWS Tool           | Detection Focus                     | Use Case Example                     |
|--------------------|-----------------------------------|------------------------------------|
| CloudTrail         | API activity & user behavior       | Detect unauthorized API calls      |
| GuardDuty          | Threat detection & anomaly         | Identify compromised instances     |
| Security Hub       | Aggregation & compliance           | Centralized alert management       |
| Macie              | Sensitive data exposure            | Detect PII leaks                   |
| Config             | Configuration compliance           | Monitor resource drift             |
| VPC Flow Logs      | Network traffic                    | Detect unusual inbound/outbound    |
| CloudWatch         | Monitoring & alerting              | Trigger alarms on suspicious activity |
| Lambda             | Automated response                 | Auto-isolate compromised resources |

---

**Key Takeaway:**  
Leverage AWS-native tools in an integrated manner for comprehensive threat detection and intelligence. Continuous monitoring, automated alerting, and rapid response reduce risk and improve security posture in the AWS cloud environment.

---

# Amazon Inspector: Overview and Role in Vulnerability Management

---

## What is Amazon Inspector?

Amazon Inspector is an automated security assessment service that helps improve the security and compliance of applications deployed on AWS.

- It analyzes AWS workloads for vulnerabilities or deviations from best practices.
- Supports assessments for Amazon EC2 instances, container images (Amazon ECR), and Lambda functions.
- Provides detailed findings with prioritized remediation recommendations.

---

## How Amazon Inspector Assists in Vulnerability Management

### 1. Automated Security Assessments  
- Continuously scans your environment for common vulnerabilities, insecure configurations, and compliance issues.
- Uses a curated rules package based on industry standards and security benchmarks (e.g., CVEs, CIS benchmarks).

### 2. Integration with AWS Services  
- Works with AWS Systems Manager for agent deployment and management.  
- Integrates with AWS Security Hub to centralize findings and improve visibility.

### 3. Prioritization and Reporting  
- Scores findings based on severity and exploitability.  
- Provides actionable recommendations to fix issues quickly.

### 4. Supports Multiple Resource Types  
- Scans EC2 instances for OS and network vulnerabilities.  
- Analyzes container images for known vulnerabilities before deployment.  
- Evaluates Lambda functions for security best practices.

### 5. Continuous Monitoring  
- Enables scheduled or on-demand assessments, helping maintain an up-to-date security posture.

---

## Typical Vulnerabilities Detected

- Operating system vulnerabilities (missing patches, outdated software)  
- Network configurations exposing instances  
- Insecure application configurations  
- Known software vulnerabilities in container images  
- Lambda function misconfigurations

---

## Summary

| Feature                      | Benefit                              |
|------------------------------|------------------------------------|
| Automated vulnerability scans| Reduces manual effort               |
| Detailed prioritized findings| Enables focused remediation         |
| Integration with Security Hub| Centralized security management     |
| Multi-resource coverage      | Comprehensive vulnerability detection|

---

**Key Takeaway:**  
Amazon Inspector simplifies vulnerability management by automating security assessments across AWS workloads, enabling proactive detection and remediation of vulnerabilities to strengthen your cloud security posture.

---
# Using AWS CloudTrail and VPC Flow Logs for Threat Hunting

---

## Introduction

Threat hunting in AWS involves proactively searching for signs of compromise, policy violations, or abnormal behaviors across the cloud environment. Two essential native tools for this are:

- **AWS CloudTrail** — Records API activity and user actions.
- **VPC Flow Logs** — Captures network traffic metadata.

Together, they provide deep visibility into operational and network behaviors.

---

## 1. AWS CloudTrail for Threat Hunting

### Description:
CloudTrail logs API calls made through the AWS Management Console, CLI, SDKs, and services.

### What to Hunt:

| Threat Scenario                          | Indicators to Search in CloudTrail                                     |
|------------------------------------------|------------------------------------------------------------------------|
| **Unauthorized Access**                  | `ConsoleLogin` failures, unusual `AssumeRole`, new `AccessKey` usage   |
| **Privilege Escalation**                 | `AttachRolePolicy`, `PutUserPolicy`, `UpdateAssumeRolePolicy`          |
| **Persistence Mechanism**                | Creation of backdoor IAM users, roles, or policies                     |
| **Data Exfiltration Attempts**           | `GetObject`, `GetParameter`, `GetSecretValue` from sensitive resources |
| **Defense Evasion**                      | `StopLogging`, `DeleteTrail`, `DetachPolicy`                          |

### Hunting Tips:
- Correlate API calls with IAM identities and unusual geolocation.
- Set up Athena queries to detect known attack chains.
- Use `eventSource`, `eventName`, `userAgent`, and `sourceIPAddress` fields for context.

---

## 2. VPC Flow Logs for Threat Hunting

### Description:
VPC Flow Logs record metadata about IP traffic going to and from network interfaces in your VPC.

### What to Hunt:

| Threat Scenario                          | Indicators in Flow Logs                                           |
|------------------------------------------|-------------------------------------------------------------------|
| **Command-and-Control Communication**    | Outbound traffic to known malicious IPs/domains                  |
| **Port Scanning / Reconnaissance**       | High volume of connections to multiple ports (low byte count)     |
| **Data Exfiltration**                    | Large outbound data transfers to unfamiliar destinations          |
| **Internal Lateral Movement**            | Unusual east-west traffic between instances                       |
| **Unexpected Protocol Use**              | Connections on uncommon ports/protocols                           |

### Hunting Tips:
- Filter on unusual `srcaddr`, `dstaddr`, and port combinations.
- Monitor for persistent connections over time to external IPs.
- Join with GuardDuty or CTI feeds for IOC correlation.

---

## Combined Use Case: Suspicious EC2 Activity

### Scenario:
An EC2 instance starts making outbound connections to a new IP range.

### Threat Hunt Steps:
1. **CloudTrail:** Check if the EC2 was launched recently or modified.
   - Look for `RunInstances`, `ModifyInstanceAttribute`, or `StartInstances`.
2. **Flow Logs:** Analyze outbound traffic from instance's ENI.
   - Identify if traffic is going to uncommon ports or external IPs.
3. **Correlation:** 
   - Compare destination IPs with threat intelligence (via GuardDuty or MISP).
   - Cross-reference timeframes between API activity and network anomalies.

---

## Summary Table

| Log Type         | Hunting Focus                        | Tooling Support                   |
|------------------|--------------------------------------|----------------------------------|
| **CloudTrail**   | User activity, API calls, IAM abuse  | Athena, CloudWatch, Security Hub |
| **VPC Flow Logs**| Network anomalies, exfiltration, C2  | Athena, GuardDuty, Macie         |

---

**Key Takeaway:**  
CloudTrail and VPC Flow Logs are foundational to AWS threat hunting. CloudTrail offers visibility into user and service activities, while Flow Logs reveal behavioral patterns in network traffic. Used together, they enable detection of subtle indicators of compromise across both control and data planes.

---
# Common AWS-Specific Attack Vectors

---

Understanding AWS-specific attack vectors is essential for building a strong cloud security posture. Below is a categorized breakdown of frequent attack scenarios that leverage misconfigurations, over-privileged identities, and service abuse.

---

## 1. **S3 Bucket Misconfigurations**

### Attack Vectors:
- **Public Buckets:** Buckets with `READ`, `WRITE`, or `LIST` access to `Everyone` or `AuthenticatedUsers`.
- **Unencrypted Data:** Absence of SSE-S3, SSE-KMS, or client-side encryption.
- **Open Bucket Policies:** Weak or overly permissive bucket policies.

### Threat Impact:
- Data leakage, theft of PII/IP, public exposure of logs or credentials.

### Detection:
- Amazon Macie, AWS Config Rules, S3 Access Analyzer.

---

## 2. **IAM Misconfigurations and Privilege Escalation**

### Attack Vectors:
- **Overly Permissive Policies:** Use of wildcards like `Action: "*"` or `Resource: "*"`.
- **Privilege Escalation via Policy Modification:** Attacker uses `iam:AttachUserPolicy` or `iam:PutRolePolicy` to grant elevated access.
- **Use of Temporary Credentials:** Compromised `AssumeRole` or session tokens.

### Privilege Escalation Examples:
- `PassRole` → Attach elevated role to Lambda or EC2.
- Create new admin user → `iam:CreateUser` + `iam:AttachUserPolicy`.
- Escalate via Lambda → Use `lambda:UpdateFunctionCode` to execute code as elevated principal.

### Detection:
- CloudTrail (for policy changes, `AssumeRole`, or `AttachPolicy` calls), IAM Access Analyzer.

---

## 3. **EC2 Instance Compromise**

### Attack Vectors:
- **Metadata Service Exploitation (pre-IMDSv2):** SSRF to steal IAM role credentials.
- **Public IP Exposure:** SSH/RDP open to the internet.
- **User Data Abuse:** Injection of malicious scripts via instance user data.

### Threat Impact:
- Credential theft, lateral movement, malware deployment.

### Detection:
- VPC Flow Logs, GuardDuty (SSH brute force, EC2 exfiltration), Systems Manager inventory.

---

## 4. **Lambda and API Gateway Exploits**

### Attack Vectors:
- **Excessive IAM Permissions:** Lambda functions with wide IAM access can be hijacked.
- **API Gateway Abuse:** Improper throttling or auth misconfiguration leads to DoS or injection.

### Detection:
- CloudTrail, API Gateway access logs, GuardDuty (malicious Lambda behaviors).

---

## 5. **ECS/EKS Misconfigurations**

### Attack Vectors:
- **Access to Instance Metadata from Containers:** IAM credentials leakage from within containers.
- **Over-privileged Task Roles/Service Accounts:** Privilege escalation via ECS task roles or EKS IAM roles.

### Detection:
- GuardDuty (for container compromise), Config rules, logging IAM actions from containers.

---

## 6. **CloudFormation and Infrastructure Abuse**

### Attack Vectors:
- **Stack Abuse:** Inject malicious templates to create backdoors or extract data.
- **Drift from Secure Baseline:** Overwrite resources to introduce persistence.

### Detection:
- CloudTrail, AWS Config (template drift), IAM role monitoring.

---

## 7. **Abuse of CloudTrail and Logging Services**

### Attack Vectors:
- **Disable/Delete Trails:** Evade detection by stopping CloudTrail or deleting logs.
- **Tampering with Logging Destinations:** Redirect logs to attacker-controlled storage.

### Detection:
- CloudTrail (look for `StopLogging`, `DeleteTrail`, `PutBucketPolicy` on log buckets), Security Hub.

---

## 8. **Exploitation via Serverless Misconfigurations**

### Attack Vectors:
- **Hardcoded Secrets:** Exposing credentials in Lambda environment variables or code.
- **Open Event Triggers:** Public API triggers allowing unvalidated event sources.

### Detection:
- Macie (for secrets in code), Config, manual code review, Lambda logs.

---

## Summary Table

| Category                     | Example Attack Vectors                        | Detection Tools                        |
|-----------------------------|-----------------------------------------------|----------------------------------------|
| S3 Misconfiguration          | Public buckets, weak policies                 | Macie, S3 Access Analyzer, Config      |
| IAM Issues                   | Wildcard permissions, privilege escalation    | CloudTrail, IAM Access Analyzer        |
| EC2 Compromise               | Metadata abuse, public SSH                    | GuardDuty, Flow Logs, Systems Manager  |
| Serverless Abuse             | Lambda over-privilege, API abuse              | CloudTrail, Security Hub, Macie        |
| Container Exploits           | Metadata access, IAM misuse                   | GuardDuty, Config, CloudTrail          |
| CloudFormation Abuse         | Malicious stacks, policy drift                | Config, CloudTrail                     |
| Logging Evasion              | Disabling trails, redirecting logs            | CloudTrail, Config                     |

---

**Key Takeaway:**  
AWS-specific attack vectors often stem from misconfigurations and over-permissive access. A layered detection and least-privilege enforcement strategy—supported by native tools like CloudTrail, GuardDuty, and Config—is essential for proactive threat mitigation.

---

# Investigating a Suspected Compromised EC2 Instance

---

## Objective:
To methodically investigate a suspected EC2 compromise, preserve forensic evidence, identify the root cause, and contain further risk.

---

## Step-by-Step Investigation Approach

---

### 🔒 1. Contain the Instance (without termination)
- **Quarantine:**
  - Detach the instance from its current Security Group.
  - Attach it to a restrictive "Quarantine SG" (no inbound/outbound except for analyst IP).
- **Preserve State:**
  - Do **not** stop or terminate the instance immediately to avoid losing volatile memory (RAM).
  - Take a memory dump if EC2 is Linux (using `LiME`) or Windows (using `WinPMEM`).
- **Snapshot:**
  - Create EBS volume snapshots (OS + data) for offline forensic analysis.
  - Preserve the original volumes unaltered.

---

### 📜 2. Collect Evidence
- **CloudTrail Logs:**
  - Look for suspicious activity: `RunInstances`, `StartInstances`, `CreateUser`, `AttachRolePolicy`, `ConsoleLogin`.
- **VPC Flow Logs:**
  - Review outbound connections to suspicious IPs/domains.
  - Check for lateral movement (east-west traffic).
- **GuardDuty Findings:**
  - Review alerts for known IOCs (e.g., crypto mining, C2 activity, SSH brute force).
- **System Logs:**
  - `auth.log`, `secure.log`, `.bash_history`, Windows Event Logs.
  - Focus on login attempts, privilege escalation, unknown scheduled tasks.
- **Running Processes & Network Connections:**
  - List all running processes (`ps`, `tasklist`) and open connections (`netstat`, `ss`).

---

### 🔍 3. Analyze Artifacts

| Artifact                        | What to Look For                                 |
|--------------------------------|--------------------------------------------------|
| **Startup Scripts**            | Unauthorized changes in `/etc/rc.local`, `cron`, Windows `Startup` |
| **IAM Role**                   | Check if instance role was modified or misused   |
| **New User Accounts**          | Unexpected OS-level or IAM users                 |
| **Installed Software**         | Presence of backdoors, miners, web shells        |
| **File System**                | Data exfiltration traces, staging directories    |
| **Web Logs**                   | Suspicious requests, uploads, encoded strings    |
| **Persistence Mechanisms**     | Cron jobs, scheduled tasks, new services         |

---

### 🧠 4. Threat Intelligence Correlation

- Use IPs, domains, hashes from logs to match against:
  - MISP, VirusTotal, AbuseIPDB, ThreatFox
- Correlate TTPs with MITRE ATT&CK (e.g., `Execution > Command and Scripting Interpreter`).

---

### ✅ 5. Remediation & Recovery

- Revoke instance IAM role credentials (rotate access keys if leaked).
- Terminate compromised instance **after** evidence is collected.
- Launch new instance from clean AMI.
- Apply:
  - Least privilege IAM
  - Security group lockdown
  - EDR/Cloud workload protection (e.g., AWS Inspector, Defender)
- Patch system and software vulnerabilities.

---

### 🧾 6. Reporting & Documentation

- Document:
  - Timeline of events
  - Attack vector
  - Compromised data/services
  - Actions taken (containment, eradication, recovery)
- Report to stakeholders and AWS Security (if needed).

---

## Summary Table

| Phase             | Key Actions                                                |
|------------------|------------------------------------------------------------|
| **Contain**       | Isolate instance, snapshot volumes, preserve memory        |
| **Collect**       | CloudTrail, Flow Logs, GuardDuty, system logs              |
| **Analyze**       | Inspect logs, processes, files, IAM roles                  |
| **Correlate**     | Use CTI t

---
# Incident Response Steps: Ransomware Attack on an S3 Bucket (AWS)

---

## 🧨 Scenario Overview

A ransomware actor gains access to an S3 bucket, encrypts stored data, and either deletes originals or replaces files with ransom notes. This scenario demands immediate containment, forensic analysis, and recovery.

---

## 🔐 1. **Containment**

### a. **Revoke Unauthorized Access**
- Review and remove unauthorized IAM users/roles.
- Revoke temporary credentials (`AssumeRole`, session tokens).
- Disable affected IAM entities.
  
### b. **Restrict S3 Bucket Access**
- Immediately update the bucket policy:
  - Remove public access.
  - Deny all except specific analyst/admin roles.
- Enable **S3 Block Public Access** at the account and bucket level.

### c. **Isolate the Affected Account**
- If possible, suspend inter-service or cross-account access via SCP (Service Control Policies).

---

## 🧾 2. **Evidence Collection**

### a. **CloudTrail**
- Audit events like:
  - `PutObject`, `DeleteObject`, `PutBucketPolicy`, `ListObjects`.
- Look for the following:
  - Unusual IP addresses
  - Rare user agents or access patterns
  - Changes to versioning or lifecycle rules

### b. **S3 Access Logs**
- Enable if not already (logs future access).
- Use existing logs to correlate access activity.

### c. **VPC Flow Logs**
- Check for data exfiltration (e.g., large egress to unknown IPs).

### d. **GuardDuty Findings**
- Look for alerts:
  - Unusual S3 API calls
  - Data access from unusual geo-locations
  - Credential misuse or privilege escalation

---

## 💥 3. **Damage Assessment**

| Area                    | What to Assess                                  |
|-------------------------|-------------------------------------------------|
| **Scope of Encryption** | Which objects were encrypted or deleted         |
| **Backups**             | Availability of non-corrupted versions/backups  |
| **Permissions Impacted**| Check if bucket ACLs/policies were modified     |
| **Affected Users**      | Any legitimate users/services impacted          |

---

## 🛠 4. **Remediation & Recovery**

### a. **Data Recovery**
- If versioning is enabled:
  - **Restore Previous**



