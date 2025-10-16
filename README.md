# TRUSTED AI SOC LITE

Prototype local Security Operations Center (SOC) that combines automated Nmap scans, explainable AI analytics, Wazuh SIEM integration and a realtime dashboard.

## 📦 Project Structure

```
trusted_ai_soc_lite/
├── config/
│   └── settings.yaml
├── scanner/
│   ├── nmap_scan.py
│   └── parse_results.py
├── ai_engine/
│   ├── train_model.py
│   ├── detect_anomalies.py
│   └── xai_explain.py
├── response/
│   ├── block_ip.py
│   └── notify.py
├── logs/
│   ├── audit.py
│   ├── audit.json              # generated
│   ├── wazuh_events.ndjson     # generated
│   └── scans/                  # generated
├── dashboard/
│   └── streamlit_app.py
├── integration/
│   └── wazuh/
│       ├── ossec.local.conf
│       ├── decoders/
│       │   └── trusted-ai-soc_decoders.xml
│       └── rules/
│           └── trusted-ai-soc_rules.xml
├── docker/
│   ├── Dockerfile
│   └── docker-compose.yml
├── scripts/                    # reserved for automation helpers
├── .env.example
├── requirements.txt
├── Makefile
└── README.md
```

## 🚀 Quickstart (Debian / Linux)

1. **Install prerequisites**

   ```bash
   sudo apt update && sudo apt install -y python3 python3-venv python3-pip nmap make docker.io docker-compose
   ```

2. **Clone and enter the repository**

   ```bash
   git clone <repo-url> trusted_ai_soc_lite
   cd trusted_ai_soc_lite
   ```

3. **Create the Python environment**

   ```bash
   make install
   ```

   <details>
   <summary>Installing without internet access</summary>

   1. On a machine with internet, download the required wheels:

      ```bash
      pip download -r requirements.txt -d wheels/
      ```

   2. Copy the `wheels/` directory to this project and point `make install` to it:

      ```bash
      WHEEL_DIR=./wheels make install
      ```

   The Makefile will install `pip`, `setuptools`, `wheel`, and all project dependencies from the provided directory without
   contacting PyPI.

   </details>

4. **Run a scan and train the model**

   ```bash
   make scan        # collects Nmap output (simulated if nmap is missing)
   make parse       # converts the latest scan to CSV
   make train       # trains the anomaly detection model
   make detect      # scores the parsed results and writes detections JSON
   make xai         # generates XAI explanations for latest detections
   # or run everything in one shot:
   make pipeline
   ```

5. **Launch the dashboard**

   ```bash
   make streamlit
   ```

   Access the UI at [http://localhost:8501](http://localhost:8501).

## 🐳 Docker Deployment

1. **Copy environment template**

   ```bash
   cp .env.example .env
   ```

2. **Start the stack**

   ```bash
   cd docker
   docker compose up --build
   ```

   - Streamlit dashboard: `http://localhost:8501`
   - Wazuh dashboard (Kibana): `https://localhost:5601`

> **Note:** The official Wazuh images require at least 8 GB of RAM. Adjust Java heap sizes in `docker-compose.yml` for constrained environments.

## 🔄 Automation Workflow

1. `scanner/nmap_scan.py` collects raw vulnerability data (XML or simulated JSON).
2. `scanner/parse_results.py` converts scans into tabular features.
3. `ai_engine/train_model.py` fits an Isolation Forest on accumulated scans.
4. `ai_engine/detect_anomalies.py` produces anomaly scores, severities and audit events.
5. `ai_engine/xai_explain.py` enriches detections with SHAP-based explanations.
6. `response/block_ip.py` and `response/notify.py` execute automated defense and alerting.
7. `dashboard/streamlit_app.py` visualises detections, alerts and audit trail.

All actions are recorded through `logs/audit.py` in both JSON and NDJSON formats to feed Wazuh.

## 📑 Wazuh Integration

- Mount `integration/wazuh` into `/var/ossec/etc/shared/trusted-ai-soc` on the manager.
- Configure `ossec.local.conf` to tail `/var/trusted-ai-soc/logs/wazuh_events.ndjson`.
- Decoders and rules included to tag anomaly and response events from the SOC.

## ⚙️ Configuration

- `config/settings.yaml` holds all tunables: scan targets, AI thresholds, notification backends, audit file paths.
- `.env` exposes runtime variables for containers and dashboard credentials.

## 🧪 Testing the Pipeline

You can simulate data without Nmap by running:

```bash
python3 scanner/nmap_scan.py --config config/settings.yaml
python3 scanner/parse_results.py logs/scans/$(ls -t logs/scans | head -n1) --output logs/parsed.csv
python3 ai_engine/train_model.py logs/parsed.csv
python3 ai_engine/detect_anomalies.py logs/parsed.csv
python3 ai_engine/xai_explain.py logs/parsed.csv logs/explanations/$(ls -t logs/explanations/detections_*.json | head -n1)
```

The fallback simulator will create sample detections which appear in the dashboard.

## 🔐 Security Considerations

- Run all Docker containers on an isolated network segment.
- Replace default credentials and SMTP settings before production use.
- Review generated SHAP explanations to validate XAI transparency.

## 📚 Documentation & Deliverables

- **Scripts** for scanning, AI, response, dashboard and audit logging.
- **Docker assets** for reproducible deployment with Wazuh stack.
- **Audit trail** persisted in JSON & NDJSON for compliance.
- **Dashboard** replicating the provided mock (dark mode, metrics, alert stream).

## 🧭 Next Steps / Extensions

- Integrate OpenVAS feeds for deeper vulnerability coverage.
- Connect to OTX or MISP for threat intelligence enrichment.
- Automate PDF reporting with weekly summaries.
- Add honeypot or deception telemetry to the pipeline.
