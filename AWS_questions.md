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
