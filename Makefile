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
	$(ACTIVATE) latest=$$(ls -t logs/scans | head -n1) && $(PYTHON) scanner/parse_results.py logs/scans/$$latest --output logs/parsed.csv

train:
	$(ACTIVATE) $(PYTHON) ai_engine/train_model.py logs/parsed.csv --config $(CONFIG)

detect:
	$(ACTIVATE) $(PYTHON) ai_engine/detect_anomalies.py logs/parsed.csv --config $(CONFIG)

xai:
	$(ACTIVATE) latest=$$(ls -t logs/explanations/detections_*.json | head -n1) && $(PYTHON) ai_engine/xai_explain.py logs/parsed.csv $$latest --config $(CONFIG)

dashboard:
	$(ACTIVATE) $(PYTHON) dashboard/app.py

pipeline:
	$(ACTIVATE) $(PYTHON) scripts/run_pipeline.py --config $(CONFIG)

test:
	$(ACTIVATE) $(PYTHON) -m unittest discover -s tests

.PHONY: install scan parse train detect xai dashboard pipeline test
