PYTHON=python3
CONFIG=config/settings.yaml
DATA_DIR=logs

install:
	$(PYTHON) -m venv .venv
	. .venv/bin/activate && pip install --upgrade pip && pip install -r requirements.txt

scan:
	. .venv/bin/activate && $(PYTHON) scanner/nmap_scan.py --config $(CONFIG)

parse:
	. .venv/bin/activate && latest=$$(ls -t logs/scans | head -n1) && $(PYTHON) scanner/parse_results.py logs/scans/$$latest --output logs/parsed.csv

train:
	. .venv/bin/activate && $(PYTHON) ai_engine/train_model.py logs/parsed.csv

detect:
	. .venv/bin/activate && $(PYTHON) ai_engine/detect_anomalies.py logs/parsed.csv

xai:
	. .venv/bin/activate && latest=$$(ls -t logs/explanations/detections_*.json | head -n1) && $(PYTHON) ai_engine/xai_explain.py $$latest

streamlit:
	. .venv/bin/activate && STREAMLIT_SERVER_PORT=$${STREAMLIT_SERVER_PORT:-8501} streamlit run dashboard/app.py

pipeline:
	. .venv/bin/activate && $(PYTHON) scripts/run_pipeline.py --config $(CONFIG)

.PHONY: install scan parse train detect xai streamlit pipeline

