# ENDPOINT-IQ: Automated Compliance & Risk Monitoring

## Project Overview
**ENDPOINT-IQ** is a specialized internal auditing and monitoring tool developed to bridge the gap between technical system telemetry and regulatory compliance. In this project, an **endpoint** is defined as any physical or virtual device—such as workstations, laptops, or servers—that serves as a point of entry to a network.

Because endpoints are primary targets for cyber threats, monitoring their health is a critical component of **Governance, Risk, and Compliance (GRC)**. Built with **Python** and **Flask**, this tool automates the evaluation of endpoint security health and maps findings directly to **NIST SP 800-53 Rev. 5** controls.

---

## Key Technical Features

* **NIST Control Mapping:** Automatically correlates system states with specific NIST control families, including **Configuration Management (CM)**, **System and Information Integrity (SI)**, and **Identification and Authentication (IA)**.
* **Dynamic Risk Scoring:** Implements a weighted algorithm that evaluates telemetry—such as BitLocker status, patch age, and real-time protection—to calculate a comprehensive risk posture.
* **Automated Telemetry Parsing:** Efficiently processes local JSON system data generated from PowerShell endpoint scans to provide a centralized health dashboard.
* **Remediation Intelligence:** Provides actionable recommendations based on detected compliance gaps, prioritizing security fixes by risk severity.

---

## Technical Troubleshooting & API Testing

* **Initial Diagnostic:** During the integration of external data streams, a **401 Unauthorized** error was identified, indicating an authentication failure.
* **Testing with Postman:** Utilized **Postman** to isolate the issue from the application code. Manual GET requests verified that API credentials were valid but required a propagation window for global activation.
* **Endpoint Verification:** Audited technical documentation to ensure the project targeted the correct **Free Tier** endpoints rather than restricted paid versions.

---

## Tech Stack

* **Backend:** Python 3.12, Flask.
* **Data Sources:** NIST SP 800-53 CSV Catalog, Local JSON Telemetry.
* **Compliance Framework:** NIST Special Publication 800-53 Revision 5.
* **DevOps & Security:** Git, GitHub, Secret Management (`.env`), and Postman (API Validation).

---

## Setup & Usage

1. **Clone the Repository:** Download the project files to your local machine.
2. **Configure Environment:** Create a `.env` file to manage sensitive local configurations.
3. **Execute Scan:** Run the PowerShell data collection scripts to generate system telemetry.
4. **Launch Dashboard:** Run `python app.py` to view the risk and compliance results in your browser.

---

### Professional Background
Developed for educational research in Cybersecurity and Risk Management by **Akanksha**, Cybersecurity Master's Candidate.

**Contact:** [akanksharaghvesh23@gmail.com](mailto:akanksharaghvesh23@gmail.com)
