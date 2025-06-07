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


