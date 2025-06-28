# CAN IDS Gateway – Self-Healing Car System

A smart, hybrid Intrusion Detection and Post-Evaluation System for connected vehicles. This system forwards real-time CAN bus traffic and evaluates it using Gemini (Google's LLM) to detect and analyze anomalies that may have bypassed traditional ML-based IDS.

---

## 📌 Problem Statement

Modern vehicles are increasingly vulnerable to cyberattacks (e.g., the Kia USB exploit). Most systems lack the capability to both **detect** and **recover** from intrusions. This project aims to:

- Detect anomalies in CAN/ECU traffic
- Perform intelligent post-analysis
- Provide **self-healing** responses like safe fallbacks or patch recommendations

---

## 🧠 Key Features

- 🟢 **Real-time CAN forwarding** from `vcan0` to `vcan1` using `python-can`
- 📄 **Packet logging** with timestamp, CAN ID, DLC, and payload
- 🤖 **Post-evaluation with Gemini LLM**:
  - Parses past forwarded packets
  - Sends full context + payload to Gemini
  - Expects structured JSON with:
    - `threat_level`: `safe`, `suspicious`, or `dangerous`
    - `reason`: Summary of why it was flagged
    - `pattern`: Detected attack type (e.g., fuzzing, replay, injection)
- 🛡 **Alerts** for `suspicious` and `dangerous` threats with pattern-based insights

---

## 🏗 Project Structure

```

self-healing-car-project/
├── src/
│   ├── ml\_ids/           # IDS logic (this gateway lives here)
│   ├── utils/            # Logger configuration
│   ├── config/           # Configuration loader
│   └── ...
├── models/               # Trained model files (optional)
├── logs/                 # System and forwarded packet logs
├── tests/                # Test cases
└── README.md             # You are here

````

---

## ⚙️ Configuration

Make sure your `config.yaml` has:
```yaml
ml_ids:
  input_interface: vcan0
  output_interface: vcan1
  forward_log_path: logs/forwarded_packets.log
  post_eval_interval: 5

llm:
  gemini_api_key: "your-google-api-key"
````

## 🧑‍💻 Contributors

* **Aravindh** — Methodology, threat research, core IDS design
* **Abhinav** — Secure communication, SSL layer integration
* **Pranav** — Virtual testing, simulator setup

---

## ✅ Future Work

* Auto-generated OTA fixes for flagged threats
* ECU-level rollback and isolation modules
* Integration with vehicle telemetry dashboards

---

## 🛑 Disclaimer

This project uses **vcan** interfaces for development and simulation. Use in production vehicles only after complete validation and manufacturer compliance.

---