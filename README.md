# ☁️ CloudGuard — AWS Cloud Governance Platform

> Serverless AWS security scanning, cost waste detection, AI-powered explanations, and automated remediation.

![AWS](https://img.shields.io/badge/AWS-Cloud-orange?logo=amazon-aws)
![Python](https://img.shields.io/badge/Python-3.12-blue?logo=python)
![Serverless](https://img.shields.io/badge/Architecture-Serverless-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

---

## What is CloudGuard?

CloudGuard is a cloud governance platform I built from scratch that continuously monitors AWS infrastructure for security vulnerabilities, cost waste, and misconfigurations — then automatically remediates safe issues or flags dangerous ones for human review.

**The one-line version:**
> CloudGuard is an automated security and cost-control system for your AWS environment. It finds problems, explains them in plain English using AI, and fixes the safe ones automatically.

---

## 🔍 What it detects

| Rule ID | Finding | Severity | Category |
|---------|---------|----------|----------|
| SEC-001 | S3 Bucket Public Access Not Blocked | HIGH / CRITICAL | Security |
| SEC-002 | SSH Port 22 Open to Internet (0.0.0.0/0) | CRITICAL | Security |
| SEC-003 | RDP Port 3389 Open to Internet (0.0.0.0/0) | CRITICAL | Security |
| SEC-004 | IAM User Has Console Access Without MFA | HIGH | Security |
| SEC-005 | IAM Access Key Not Rotated in 90+ Days | MEDIUM | Security |
| FIN-001 | Unattached EBS Volume (wasted spend) | LOW / MEDIUM / HIGH | FinOps |
| NET-001 | Unassociated Elastic IP (wasted spend) | LOW | FinOps |
| NET-002 | Default VPC Security Group Has Inbound Rules | MEDIUM | Security |
| NET-003 | EC2 Instance With Direct Public IP | LOW | Security |

---

## 🔧 How remediation works

CloudGuard uses a **policy-based remediation engine** — not blind automation. Every finding is evaluated against a policy before any action is taken.

```
Finding detected
      │
      ▼
Policy evaluation
      │
   ┌──┴──────────────┐
   │                 │
FinOps           Security
LOW / MEDIUM      ANY
   │                 │
   ▼                 ▼
Auto-fix         Human approval
   │              required
   ▼
Full audit trail
recorded in DynamoDB
```

**Auto-remediated (no human needed):**
- Unattached EBS volumes → snapshot created first → volume deleted safely
- Unused Elastic IPs → released immediately, billing stops
- Old CloudGuard snapshots → cleaned up automatically after 1 day

**Always requires human approval:**
- Any security group changes
- Any S3 configuration changes
- Any IAM changes
- Any CRITICAL severity finding

This distinction is intentional. Automatically closing an S3 bucket or modifying a security group in production could break live applications. CloudGuard explains and flags — humans decide and act.

---

## 📊 Dashboard features

- Live findings table sorted by risk score (0–100)
- Findings by severity doughnut chart
- Security vs FinOps distribution chart
- Findings by status bar chart (Open / Awaiting / Remediated / Dismissed)
- Filter by severity, category, and status
- Full-text search across all findings
- AI-generated plain-English explanation per finding (Amazon Bedrock)
- One-click Approve / Dismiss / Snapshot & Tag actions
- Auto-refreshes every 30 seconds

---

## 🏗️ Architecture

```
Amazon EventBridge (daily schedule)
          │
    ┌─────┼──────────────┐
    │     │              │
    ▼     ▼              ▼
EBS    Security      Network
Scanner Scanner      Scanner
    │     │              │
    └─────┼──────────────┘
          │
          ▼
    DynamoDB Table
    (cloudguard-findings)
          │
    ┌─────┼──────────────┐
    │     │              │
    ▼     ▼              ▼
Remediation  AI        Alerting
Engine    Explainer    (SNS Email)
    │     │
    ▼     ▼
  EC2   Bedrock
(auto  (Claude AI)
 fix)
          │
Dashboard API ──► S3 Static Website
Remediation API ──► Browser buttons
```

---

## ☁️ AWS services used

| Service | Purpose |
|---------|---------|
| AWS Lambda (Python 3.12) | All scanner and processing functions |
| Amazon DynamoDB | Findings storage with deterministic IDs |
| Amazon EventBridge | Scheduled daily execution of all scanners |
| Amazon S3 | Static dashboard hosting |
| Amazon SNS | Email alerts for critical and high findings |
| Amazon Bedrock (Claude) | AI-powered plain-English explanations |
| AWS IAM | Least-privilege execution role |

---

## 🚀 Lambda functions

| Function | Purpose | Trigger |
|----------|---------|---------|
| `cloudguard-ebs-scanner` | Detects unattached EBS volumes | EventBridge daily |
| `cloudguard-security-scanner` | Scans S3, security groups, IAM | EventBridge daily |
| `cloudguard-network-scanner` | Scans Elastic IPs, VPC, EC2 | EventBridge daily |
| `cloudguard-remediation-engine` | Auto-remediates open findings | EventBridge daily |
| `cloudguard-remediation-api` | HTTP API for dashboard approve/dismiss | Function URL |
| `cloudguard-ai-explainer` | Generates Bedrock explanations | EventBridge daily |
| `cloudguard-alerting` | Sends SNS email digest | EventBridge daily |
| `cloudguard-dashboard-api` | Serves findings data to dashboard | Function URL |
| `cloudguard-snapshot-cleanup` | Removes old CloudGuard snapshots | EventBridge weekly |

---

## 🔐 Security design decisions

**Deterministic finding IDs**
Every finding ID is generated using `MD5(rule_id + resource_id)`. This means the same misconfiguration always gets the same finding ID regardless of how many times the scanner runs. No duplicates are ever created.

**Least privilege IAM**
The Lambda execution role has only the specific permissions required. EC2 read for scanning, DynamoDB read/write for findings, SNS publish for alerts, Bedrock invoke for AI — nothing else.

**No hardcoded credentials**
All AWS access happens through the IAM execution role. No access keys, no secrets in code.

**Policy-based remediation**
Security findings are never auto-remediated regardless of risk score. The policy engine makes this distinction explicit — not an afterthought.

**Whitelist support**
CloudGuard's own infrastructure (dashboard S3 bucket) is excluded from findings so it doesn't flag itself.

---

## 💰 Running cost

**$0.00 per month** — the entire platform runs within AWS free tier.

- Lambda: well within 1M free requests/month
- DynamoDB: well within 25GB free storage
- EventBridge: free for scheduled rules
- S3: effectively free for a single HTML file
- SNS: free for under 1000 emails/month
- Bedrock: pay-per-use but negligible for daily scans

---

## 📁 Project structure

```
cloudguard/
├── scanners/
│   ├── ebs_scanner.py           # FIN-001: Unattached EBS volumes
│   ├── security_scanner.py      # SEC-001 to SEC-005
│   └── network_scanner.py       # NET-001 to NET-003
├── engine/
│   ├── remediation_engine.py    # Batch auto-remediation processor
│   ├── remediation_api.py       # HTTP API for dashboard actiosbns
│   ├── ai_explainer.py          # Bedrock AI explanation generator
│   └── alerting.py              # SNS email digest sender
├── api/
│   └── dashboard_api.py         # Dashboard data API
├── dashboard/
│   └── index.html               # Static dashboard (S3 hosted)
└── screenshots/
|    ├── screenshot-dashboard.png
|    ├── screenshot-findings.png
|    └── screenshot-statuses.png
|
|---- cleaning/
     |-----cache_clear.py
     |-----snapshot_cleanup.py

```

---

## ⚙️ Setup guide

**Prerequisites:** AWS account, IAM user with admin access, Mumbai region (ap-south-1)

**1. DynamoDB**
Create table `cloudguard-findings`
- Partition key: `finding_id` (String)
- Sort key: `timestamp` (String)

**2. IAM Role**
Create role `cloudguard-lambda-role` with these policies:
- AmazonEC2ReadOnlyAccess
- AmazonEC2FullAccess (for remediation)
- AmazonDynamoDBFullAccess
- AmazonS3ReadOnlyAccess
- IAMReadOnlyAccess
- SecurityAudit
- CloudGuardSNSPublish (custom — SNS publish permission)
- CloudGuardBedrockInvoke (custom — Bedrock invoke permission)

**3. Lambda functions**
Deploy each `.py` file as a separate Lambda function with:
- Runtime: Python 3.12
- Execution role: cloudguard-lambda-role
- Timeout: 5 minutes (remediation engine), 1 minute (all others)

**4. EventBridge schedules**
Create schedules with cron `0 2 * * ? *` pointing to each scanner Lambda.

**5. Dashboard**
- Create S3 bucket, enable static website hosting
- Update `DASHBOARD_API` and `REMEDIATION_API` constants in `index.html`
- Upload `index.html` to the bucket
- Set bucket policy to allow public read

**6. SNS alerts**
- Create topic `cloudguard-alerts`
- Subscribe your email and confirm
- Update `SNS_ARN` constant in `alerting.py`

---

## 👤 Built by

**Ammar Khan**
Final Year CS Student — FAST NUCES, Karachi, Pakistan
Cloud Computing · AWS · Security Engineering

---

*CloudGuard is a portfolio project demonstrating production-grade AWS architecture patterns: serverless computing, event-driven design, least-privilege IAM, policy-based automation, and AI-augmented security tooling.*
