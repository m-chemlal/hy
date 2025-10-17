PYTHON=python3
VENV=.venv
CONFIG=config/settings.yaml
ACTIVATE=. $(VENV)/bin/activate &&

install:
	$(PYTHON) -m venv $(VENV)
	$(ACTIVATE) \
		if [ -s requirements.txt ] && grep -qEv '^\s*(#|$$)' requirements.txt; then \
			if [ -n "$$WHEEL_DIR" ]; then \
				pip install --no-index --find-links "$$WHEEL_DIR" -r requirements.txt; \
			else \
				pip install -r requirements.txt; \
			fi; \
		else \
			echo "No Python dependencies to install."; \
		fi

scan:
	$(ACTIVATE) $(PYTHON) scanner/nmap_scan.py --config $(CONFIG)

parse:
        latest=$$(ls -t logs/scans 2>/dev/null | head -n1); \
        if [ -z "$$latest" ]; then \
                echo "No scan artifacts found. Run 'make scan' first."; \
                exit 1; \
        fi; \
        $(ACTIVATE) $(PYTHON) scanner/parse_results.py logs/scans/$$latest --output logs/parsed.csv

train:
	$(ACTIVATE) $(PYTHON) ai_engine/train_model.py logs/parsed.csv --config $(CONFIG)

detect:
	$(ACTIVATE) $(PYTHON) ai_engine/detect_anomalies.py logs/parsed.csv --config $(CONFIG)

xai:
        latest=$$(ls -t logs/explanations/detections_*.json 2>/dev/null | head -n1); \
        if [ -z "$$latest" ]; then \
                echo "No detections found. Run 'make detect' first."; \
                exit 1; \
        fi; \
        $(ACTIVATE) $(PYTHON) ai_engine/xai_explain.py logs/parsed.csv logs/explanations/$$latest --config $(CONFIG)

dashboard:
	$(ACTIVATE) $(PYTHON) dashboard/app.py

pipeline:
	$(ACTIVATE) $(PYTHON) scripts/run_pipeline.py --config $(CONFIG)

test:
	$(ACTIVATE) $(PYTHON) -m unittest discover -s tests

.PHONY: install scan parse train detect xai dashboard pipeline test
