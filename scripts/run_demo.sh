#!/usr/bin/env bash
set -euo pipefail
mkdir -p artifacts
PYTHONPATH=src python -m mail-gateway.cli train data/training.csv --model artifacts/mail-gateway_nb_model.json
PYTHONPATH=src python -m mail-gateway.cli scan-dir data/sample_emails --config configs/policies.json --model artifacts/mail-gateway_nb_model.json
