from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any

from .config import load_config
from .evaluator import compute_metrics
from .ml_classifier import NaiveBayesMailClassifier, load_csv_rows
from .orchestrator import AdaptivePolicyOrchestrator
from .parser import parse_eml
from .syslog_cef import to_cef


def _load_model(path: str | None) -> NaiveBayesMailClassifier:
    if path:
        return NaiveBayesMailClassifier.load(path)
    return NaiveBayesMailClassifier.load("artifacts/mail-gateway_nb_model.json")


def cmd_scan(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    model = _load_model(args.model)
    message = parse_eml(args.eml, attachment_dir="artifacts/attachments")
    result = AdaptivePolicyOrchestrator(config, model).scan(message)
    if args.cef:
        print(to_cef(result))
    else:
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
    return 0


def cmd_scan_dir(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    model = _load_model(args.model)
    orchestrator = AdaptivePolicyOrchestrator(config, model)
    rows: list[dict[str, Any]] = []
    for path in sorted(Path(args.directory).glob("*.eml")):
        message = parse_eml(path, attachment_dir="artifacts/attachments")
        result = orchestrator.scan(message)
        rows.append({"file": str(path), "subject": message.subject, "score": result.total_score, "action": result.action, "reasons": ";".join(result.reasons)})
    print(json.dumps(rows, ensure_ascii=False, indent=2))
    return 0


def cmd_train(args: argparse.Namespace) -> int:
    rows = load_csv_rows(args.csv)
    model = NaiveBayesMailClassifier()
    model.fit(rows)
    model.save(args.model)
    print(f"Model saved to {args.model}; samples={len(rows)}")
    return 0


def cmd_evaluate(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    model = _load_model(args.model)
    orchestrator = AdaptivePolicyOrchestrator(config, model)
    pairs: list[tuple[str, str]] = []
    with Path(args.csv).open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        required = {"eml_path", "label"}
        if not required.issubset(reader.fieldnames or set()):
            raise ValueError("CSV must contain eml_path and label columns")
        for row in reader:
            message = parse_eml(row["eml_path"], attachment_dir="artifacts/attachments")
            result = orchestrator.scan(message)
            predicted = "spam" if result.action in {"quarantine", "reject"} else "ham"
            pairs.append((row["label"], predicted))
    metrics = compute_metrics(pairs)
    print(json.dumps(metrics.__dict__, ensure_ascii=False, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mail-gateway", description="mail-gateway adaptive mail gateway prototype")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan one .eml file")
    scan.add_argument("eml")
    scan.add_argument("--config", default="configs/policies.json")
    scan.add_argument("--model")
    scan.add_argument("--cef", action="store_true")
    scan.set_defaults(func=cmd_scan)

    scan_dir = sub.add_parser("scan-dir", help="Scan all .eml files in a directory")
    scan_dir.add_argument("directory")
    scan_dir.add_argument("--config", default="configs/policies.json")
    scan_dir.add_argument("--model")
    scan_dir.set_defaults(func=cmd_scan_dir)

    train = sub.add_parser("train", help="Train Naive Bayes model from CSV")
    train.add_argument("csv")
    train.add_argument("--model", default="artifacts/mail-gateway_nb_model.json")
    train.set_defaults(func=cmd_train)

    evaluate = sub.add_parser("evaluate", help="Evaluate gateway decisions from CSV")
    evaluate.add_argument("csv")
    evaluate.add_argument("--config", default="configs/policies.json")
    evaluate.add_argument("--model", default="artifacts/mail-gateway_nb_model.json")
    evaluate.set_defaults(func=cmd_evaluate)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
