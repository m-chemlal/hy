# TRUSTED AI SOC LITE

Prototype local Security Operations Center (SOC) that combines automated Nmap scans, explainable analytics, Wazuh SIEM integration and a console dashboard. The project now runs fully offline using only the Python standard library.

## 📦 Project Structure

```
trusted_ai_soc_lite/
├── config/
│   ├── loader.py
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
│   └── app.py
├── scripts/
│   └── run_pipeline.py
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
├── .env.example
├── requirements.txt
├── Makefile
└── README.md
```

## 🚀 Quickstart (Debian / Linux)

1. **Install prerequisites**

   ```bash
   sudo apt update && sudo apt install -y \
       python3 python3-venv python3-pip \
       nmap make docker.io docker-compose-plugin
   ```

   > **Why the plugin?**
   > Recent Debian releases install `docker-compose` as a Docker CLI plugin. Installing
   > the legacy `docker-compose` package alongside `docker-compose-plugin` causes `dpkg`
   > to abort with a "trying to overwrite ... docker-compose" error. Using the plugin
   > package keeps the default Docker setup intact while still providing the
   > `docker compose` command used in the rest of the docs.

2. **Clone and enter the repository**

   ```bash
   git clone <repo-url> trusted_ai_soc_lite
   cd trusted_ai_soc_lite
   ```

3. **Create the Python environment**

   ```bash
   make install
   ```

   The core pipeline has no third-party Python dependencies, so the command simply creates a virtual environment. If you keep a custom `requirements.txt`, the Makefile will install the listed wheels when a local cache is provided via `WHEEL_DIR=...`.

4. **Run a scan and score it**

   ```bash
   make scan        # collects Nmap output (simulated if nmap is missing)
   make parse       # converts the latest scan to CSV (warns if no scans exist)
   make train       # trains the statistical baseline
   make detect      # scores the parsed results and writes detections JSON
   make xai         # generates human-readable explanations (after detections)
   # or run everything in one shot:
   make pipeline
   ```

   If the parsed CSV is empty the training step now writes a default baseline
   so the rest of the pipeline can still execute. In that fallback mode
   detections are marked informational because the system has no historical
   data yet.

5. **View the latest results**

   ```bash
   make dashboard
   ```

   The dashboard prints a textual summary of detections, explanations and recent audit events to the terminal.

## 🔄 Automation Workflow

1. `scanner/nmap_scan.py` collects raw vulnerability data (XML or simulated JSON when Nmap is unavailable).
2. `scanner/parse_results.py` converts scans into structured dictionaries and optional CSV output.
3. `ai_engine/train_model.py` builds a statistical baseline (port/service frequency model) stored as JSON.
4. `ai_engine/detect_anomalies.py` scores new scans against the baseline, produces severity labels and writes detections JSON while auditing anomalies.
5. `ai_engine/xai_explain.py` reformats detection explanations for analysts and logs them.
6. `response/block_ip.py` and `response/notify.py` execute automated defense and alerting.
7. `dashboard/app.py` renders a console dashboard for quick situational awareness.

All actions are recorded through `logs/audit.py` in both JSON and NDJSON formats to feed Wazuh.

## 📑 Wazuh Integration

- Mount `integration/wazuh` into `/var/ossec/etc/shared/trusted-ai-soc` on the manager.
- Configure `ossec.local.conf` to tail `/var/trusted-ai-soc/logs/wazuh_events.ndjson`.
- Decoders and rules are included to tag anomaly and response events from the SOC.

## ⚙️ Configuration

- `config/settings.yaml` holds all tunables: scan targets, anomaly thresholds, notification backends and audit file paths.
- `.env` exposes runtime variables for containers and dashboard credentials.

## 🧪 Testing the Pipeline

You can simulate data without Nmap by running:

```bash
python3 scanner/nmap_scan.py --config config/settings.yaml
python3 scanner/parse_results.py logs/scans/$(ls -t logs/scans | head -n1) --output logs/parsed.csv
python3 ai_engine/train_model.py logs/parsed.csv --config config/settings.yaml
python3 ai_engine/detect_anomalies.py logs/parsed.csv --config config/settings.yaml
python3 ai_engine/xai_explain.py logs/parsed.csv logs/explanations/$(ls -t logs/explanations/detections_*.json | head -n1) --config config/settings.yaml
```

The fallback simulator will create sample detections which appear in the dashboard.

## 🔐 Security Considerations

- Run all Docker containers on an isolated network segment.
- Replace default credentials and SMTP settings before production use.
- Review generated explanations to validate anomaly decisions.

## 📚 Documentation & Deliverables

- **Scripts** for scanning, analytics, response, dashboard and audit logging.
- **Docker assets** for reproducible deployment with Wazuh stack.
- **Audit trail** persisted in JSON & NDJSON for compliance.
- **Dashboard** providing textual metrics, alerts and audit history.

## 🧭 Next Steps / Extensions

- Integrate OpenVAS feeds for deeper vulnerability coverage.
- Connect to OTX or MISP for threat intelligence enrichment.
- Automate PDF reporting with weekly summaries.
- Add honeypot or deception telemetry to the pipeline.
