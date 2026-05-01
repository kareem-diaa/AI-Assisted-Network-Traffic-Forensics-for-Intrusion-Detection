# AI-Assisted Network Traffic Forensics for Intrusion Detection

## Project Overview
A complete Intrusion Detection System (IDS) combining signature-based detection and AI/ML-based behavioral analysis for real-time network forensics.

## Team
- Member 1 — Infrastructure & Traffic Capture
- Member 2 — Zeek + ML Model
- Member 3 — Suricata + ELK + Report

## Tools Used
| Tool | Purpose |
|---|---|
| Zeek | Network forensics & metadata extraction |
| Wireshark | Packet capture & analysis |
| Suricata | Signature-based IDS/IPS |
| Scikit-learn | ML model training |
| ELK Stack | Log visualization & forensic dashboard |
| PcapMonkey | Integrated PCAP analysis pipeline |

## ML Model Results
| Model | Accuracy | ROC-AUC |
|---|---|---|
| Random Forest | 99.80% | 99.98% |
| Decision Tree | 99.79% | 99.98% |
| Logistic Regression | 94.52% | 98.80% |

Dataset: CIC-IDS2017 (512,212 labeled flows — DDoS + Port Scan)

## Detection Results
- **Suricata** fired alerts on: ICMP Ping, TCP Port Scan, HTTPS connections
- **Zeek** extracted: conn.log, dns.log, http.log, ssl.log
- **Kibana** dashboard showed traffic spike with 4,755 connections from attacker IP

## Project Structure
ml/              → ML model, training script, result charts
zeek-logs/       → Zeek forensic logs from PCAP analysis
suricata-logs/   → Suricata alert output (eve.json)
pcap/            → Captured network traffic
screenshots/     → Wireshark, Kibana dashboard screenshots
docs/            → Final report and presentation slides
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
