<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d1117,50:1a2f4a,100:0a7cf7&height=200&section=header&text=i-SIEM&fontSize=90&fontColor=ffffff&fontAlignY=38&desc=Self-Hosted%20In-House%20SIEM%20on%20Kubernetes&descAlignY=58&descSize=22&descColor=8ab4f8" alt="i-SIEM Banner"/>

[![Kubernetes](https://img.shields.io/badge/Kubernetes-326CE5?style=for-the-badge&logo=kubernetes&logoColor=white)](https://kubernetes.io/)
[![Wazuh](https://img.shields.io/badge/Wazuh-005571?style=for-the-badge&logo=wazuh&logoColor=white)](https://wazuh.com/)
[![OpenSearch](https://img.shields.io/badge/OpenSearch-005EB8?style=for-the-badge&logo=opensearch&logoColor=white)](https://opensearch.org/)
[![GitLab](https://img.shields.io/badge/GitLab-FC6D26?style=for-the-badge&logo=gitlab&logoColor=white)](https://gitlab.com/)
[![Mattermost](https://img.shields.io/badge/Mattermost-0058CC?style=for-the-badge&logo=mattermost&logoColor=white)](https://mattermost.com/)
[![GCS](https://img.shields.io/badge/Google_Cloud_Storage-4285F4?style=for-the-badge&logo=googlecloud&logoColor=white)](https://cloud.google.com/storage)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

</div>

---

## 🛡️ What is i-SIEM?

**i-SIEM** is a fully self-hosted, on-premise **Security Information and Event Management (SIEM)** platform — built and deployed from scratch on a local Kubernetes environment, referencing the official Wazuh documentation.

This project demonstrates end-to-end ownership of a production-grade security monitoring stack: from certificate generation and cluster bootstrapping, to real-time alerting pipelines, cloud log archival, and custom platform branding — **with zero reliance on managed SaaS services**.

---

## 🎯 What Problem Does This Solve?

Most organizations rely on expensive, third-party SIEM platforms that offer little flexibility and complete vendor lock-in. i-SIEM proves that a fully capable, enterprise-grade security monitoring platform can be:

- 🏠 **Self-hosted** on your own infrastructure
- ☁️ **Cloud-agnostic** — no dependency on AWS, Azure, or SaaS SIEM vendors
- 🔧 **Fully customizable** — branding, alert thresholds, integrations, all owned by you
- 💰 **Cost-effective** — no per-seat licensing or data ingestion costs
- 🔒 **Data privacy by design** — all security logs, events, and audit trails stay within your own network perimeter; no telemetry, no third-party data sharing, full compliance control

---

## ⚙️ Core Capabilities

### 🔍 SIEM Stack Deployment
Deployed a complete Wazuh-based SIEM cluster (i-SIEM) on self-hosted, on-premise Kubernetes — consisting of an Indexer node (OpenSearch), a Dashboard (Wazuh UI), and a Manager cluster (master + worker). The entire stack is secured with TLS certificates generated from a custom internal PKI.

### 🔔 Intelligent Alert Routing
Integrated i-SIEM with two external platforms to ensure security alerts reach the right people instantly:

- **GitLab** — Automatically opens a GitLab Issue when a security event reaches **alert level 15 or higher** (critical/high severity), creating a traceable incident record in the team's existing workflow.
- **Mattermost** — Sends an instant team notification when an alert hits **level 12 or higher** (medium-high severity), enabling real-time SOC awareness without constant dashboard monitoring.

### ☁️ Cloud Log Archival
Built a GCS (Google Cloud Storage) log archival pipeline using a Kubernetes CronJob. The pipeline follows least-privilege security principles with a dedicated ServiceAccount, RBAC Role, and RoleBinding — ensuring logs are automatically and securely exported to cloud storage on a schedule.

### 🎨 Custom Platform Branding
Rebranded the SIEM login interface to the i-SIEM identity — demonstrating full ownership of the platform beyond just infrastructure deployment.

---

## 🧰 Tech Stack

| Domain | Technologies Used |
|---|---|
| Container Orchestration | Kubernetes (self-hosted, on-premise) |
| SIEM Engine | Wazuh (custom-built — i-SIEM) |
| Search & Indexing | OpenSearch |
| Visualization | Wazuh Dashboard |
| Alert Integrations | GitLab API, Mattermost Webhooks |
| Log Storage | Google Cloud Storage (GCS) |
| Scripting & Automation | Python, Bash |
| Config Management | Kustomize |
| Security | TLS/PKI, OpenSearch Security Plugin, Kubernetes RBAC |

---

## 💡 Key Engineering Decisions

- **Self-signed PKI** for all inter-service TLS — no external CA dependency
- **Kustomize overlays** for environment-specific configuration management
- **Kubernetes RBAC** with minimal permissions scoped to the GCS integration only
- **Alert level thresholds** tuned to reduce noise — only actionable events trigger GitLab issues or Mattermost pings
- **Statefulset-based** indexer deployment to ensure persistent storage and stable network identity across pod restarts

---

## 💬 Connect

If you found this project helpful or have any questions, feel free to reach out!

📱 **Phone:** (+91) 7008-62-6663
📧 **Email:** sandeepdashmlops@gmail.com
💻 **GitHub:** [github.com/sandeepdash-mlops](https://github.com/sandeepdash-mlops)

---

<div align="center">

*Built for engineers who believe security infrastructure should be owned — not rented.*

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0a7cf7,50:1a2f4a,100:0d1117&height=100&section=footer"/>

</div>
