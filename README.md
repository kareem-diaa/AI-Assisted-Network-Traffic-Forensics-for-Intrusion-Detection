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

### 1 — Train the model (one-time, requires the CIC-IDS2017 CSV dataset)
```bash
pip install pandas numpy scikit-learn matplotlib seaborn joblib
# Place CIC-IDS2017 CSV files (e.g. Friday-WorkingHours.pcap_ISCX.csv) inside ml/
cd ml
python3 ids_model.py
# Produces: ids_model.pkl  scaler.pkl  feature_names.pkl
```

### 2 — Run the model against a PCAP file
```bash
pip install cicflowmeter pandas numpy scikit-learn joblib

# Copy your .pkl files into the ml/ folder, then:
cd ml
python3 predict_pcap.py --pcap ../pcap/attack_scan.pcap

# With explicit paths (useful if .pkl files are elsewhere):
python3 predict_pcap.py \
    --pcap    ../pcap/attack_scan.pcap \
    --model   ids_model.pkl \
    --scaler  scaler.pkl \
    --features feature_names.pkl \
    --output  ../pcap/attack_scan_predictions.csv
```

The script will:
1. Convert the PCAP to network-flow features using **CICFlowMeter**
2. Load the saved model, scaler, and feature list
3. Predict **BENIGN** or **ATTACK** for every flow
4. Print a summary (total flows, attack %, top attacker IPs)
5. Save full per-flow results to a CSV

### 3 — Run full pipeline (requires Docker)
```bash
cd ../  
git clone https://github.com/certego/PcapMonkey
cd PcapMonkey
cp ../pcap/attack_scan.pcap pcap/
docker-compose up -d
```
