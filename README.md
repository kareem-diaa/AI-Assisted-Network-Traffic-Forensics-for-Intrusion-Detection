# AI-Assisted Network Traffic Forensics for Intrusion Detection

![Python](https://img.shields.io/badge/Python-3.x-blue.svg)
![Machine Learning](https://img.shields.io/badge/Machine_Learning-Scikit_Learn-yellow)
![Suricata](https://img.shields.io/badge/Suricata-IDS%2FIPS-red)
![Zeek](https://img.shields.io/badge/Zeek-Network_Security-orange)

## 📌 Problem Statement & Overview
With cybercrime estimated to cost the world $12.2 trillion annually by 2031, traditional signature-based defenses are increasingly insufficient against novel attack vectors. 

This project delivers a comprehensive, hybrid Intrusion Detection System (IDS). By combining the immediate precision of signature-based detection with the adaptive, predictive capabilities of ML-based behavioral analysis, this pipeline provides robust, real-time network forensics and threat identification.

## 👥 Core Team & Ownership
*   **Kareem Diaa** — Project Management, Infrastructure Architecture & Traffic Capture
*   **Ahmed Mohamed** — Zeek Integration & Machine Learning Pipeline
*   **Malak Mahmoud** — Suricata Configuration, ELK Stack Deployment & Reporting

## 🛠 Architecture & Tech Stack

| Component | Technology | Purpose |
| :--- | :--- | :--- |
| **Forensics & Metadata** | Zeek | Deep packet inspection and metadata extraction |
| **Packet Analysis** | Wireshark | Granular PCAP analysis |
| **Signature IDS/IPS** | Suricata | Real-time rule-based threat detection |
| **Behavioral Engine** | Scikit-learn | ML model training for anomaly detection |
| **Visualization** | ELK Stack | Centralized log visualization and forensic dashboarding |
| **Analysis Pipeline** | PcapMonkey | Integrated environment for PCAP processing |

## 📊 Performance & Detection Results

### Machine Learning Efficacy
The models were trained and validated against the **CIC-IDS2017** dataset, processing 512,212 labeled flows focusing on DDoS and Port Scan vectors.

| Algorithm | Accuracy | ROC-AUC |
| :--- | :--- | :--- |
| **Random Forest** | 99.80% | 99.98% |
| **Decision Tree** | 99.79% | 99.98% |
| **Logistic Regression** | 94.52% | 98.80% |

### Live Detection Capabilities
*   **Suricata Alerts:** Successfully triggered on ICMP Pings, TCP Port Scans, and anomalous HTTPS connections.
*   **Zeek Telemetry:** Successfully extracted and indexed highly structured forensic logs (`conn.log`, `dns.log`, `http.log`, `ssl.log`).
*   **Dashboarding:** Kibana successfully mapped attack topologies, visually isolating a traffic spike of 4,755 malicious connections originating from the attacker IP.

## 📂 Repository Structure
```text
├── ml/                 # ML models, training scripts, and performance charts
├── zeek-logs/          # Extracted Zeek forensic logs from PCAP analysis
├── suricata-logs/      # Suricata alert outputs (eve.json)
├── pcap/               # Raw captured network traffic
├── screenshots/        # Wireshark captures and ELK dashboard visualizations
└── docs/               # Final architectural report and presentation slides
```


## How to Run
```bash
# Clone the repo
git clone https://github.com/YourUsername/network-forensics-ids.git

# Run ML model (requires Python 3 + pip)
pip install pandas numpy scikit-learn matplotlib seaborn joblib
cd ml
python3 ids_model.py

# Run full pipeline (requires Docker)
cd ../  
git clone https://github.com/certego/PcapMonkey
cd PcapMonkey
cp ../pcap/attack_scan.pcap pcap/
docker-compose up -d
```
