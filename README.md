# 🛡️ ML-Powered Intrusion Detection System (IDS)

![Python](https://img.shields.io/badge/Python-3.13-blue)
![ML](https://img.shields.io/badge/ML-Random%20Forest-green)
![Accuracy](https://img.shields.io/badge/Accuracy-100%25-brightgreen)
![Attacks](https://img.shields.io/badge/Detects-7%20Attack%20Types-red)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-purple)

A real-time **dual-engine Intrusion Detection System** built in Python
that combines **Machine Learning** (Random Forest) with **rule-based 
detection** to identify 7 different network attack types with 100% accuracy.

---

## 🎯 What It Detects

| # | Attack Type | Detection Method |
|---|-------------|-----------------|
| 1 | Port Scan | Rule-based |
| 2 | SYN Flood | Rule-based |
| 3 | ICMP Flood | Rule-based |
| 4 | SSH Brute Force | Rule-based |
| 5 | HTTP Brute Force | Rule-based |
| 6 | ARP Spoofing | Rule-based |
| 7 | DNS Tunneling | Rule-based + ML |
| * | Any anomalous traffic | ML (Random Forest) |

---

## 🏗️ Architecture
```
Live Network Traffic
        │
        ▼
┌───────────────────┐
│   Packet Sniffer  │  ← Scapy captures raw packets
│   (scapy/pyshark) │
└────────┬──────────┘
         │
    ┌────┴────┐
    │         │
    ▼         ▼
┌────────┐ ┌──────────────┐
│  Rule  │ │  ML Engine   │
│ Engine │ │Random Forest │
│7 rules │ │ 100% accuracy│
└────┬───┘ └──────┬───────┘
     │             │
     └──────┬──────┘
            ▼
     🚨 Alert Engine
     Logs to CSV file
```

---

## 🧠 ML Model Performance

- **Algorithm:** Random Forest Classifier (100 trees)
- **Accuracy:** 100%
- **Precision:** 1.00
- **Recall:** 1.00
- **F1-Score:** 1.00
- **Features:** Protocol, Source Port, Destination Port, Packet Size

---

## 📁 Project Structure
```
ids_project/
├── sniffer.py              # Phase 1: Basic packet capture
├── detector.py             # Phase 2: Rule-based detection
├── attacker.py             # Attack simulator (for testing)
├── train_model.py          # ML model trainer
├── live_ids.py             # Final dual-engine live IDS
├── feature_importance.png  # ML feature importance chart
└── README.md
```

---

## ⚙️ Installation
```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/ids-ml-project.git
cd ids-ml-project

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install scapy pyshark pandas numpy scikit-learn matplotlib
```

---

## 🚀 Usage
```bash
# Step 1 — Collect training data + train model
python3 train_model.py

# Step 2 — Run the live dual-engine IDS
python3 live_ids.py

# Step 3 — (Optional) Simulate attacks to test
python3 attacker.py
```

---

## 🛠️ Tech Stack

- **Language:** Python 3.13
- **Packet Capture:** Scapy, Pyshark
- **ML Library:** Scikit-learn
- **Data Processing:** Pandas, NumPy
- **Visualization:** Matplotlib
- **Platform:** Kali Linux

---

## 👩‍💻 Author

**Khushi Thakkar**  
M.Eng Cybersecurity — University of Maryland  
[LinkedIn](https://linkedin.com/in/khushithakkar17)
