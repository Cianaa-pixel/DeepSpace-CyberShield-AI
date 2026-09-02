"""
main.py
-------
Command-line entry point: generate/load the dataset, run the full
TTL-Evidence + DSSLV + Dynamic TTL Decay pipeline, print a summary, and
save the enriched results + markdown report to disk.

Run with:  python -m src.main
"""

import os
from .data_loader import load_or_generate
from .attack_detector import run_pipeline
from . import report_generator

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_PATH = os.path.join(BASE_DIR, "dataset", "communication_logs.csv")
RESULTS_PATH = os.path.join(BASE_DIR, "dataset", "detection_results.csv")
REPORT_PATH = os.path.join(BASE_DIR, "dataset", "detection_report.md")


def main():
    print(f"Loading dataset from {DATASET_PATH} ...")
    df = load_or_generate(DATASET_PATH)
    print(f"Loaded {len(df)} bundles. Running detection pipeline...")

    result = run_pipeline(df)
    metrics = report_generator.summarize(result)

    result.to_csv(RESULTS_PATH, index=False)
    with open(REPORT_PATH, "w") as f:
        f.write(report_generator.to_markdown(metrics))

    print(f"Accuracy: {metrics['accuracy']}%  Precision: {metrics['precision']}%  "
          f"Recall: {metrics['recall']}%  F1: {metrics['f1_score']}%")
    print(f"Results saved to {RESULTS_PATH}")
    print(f"Report saved to {REPORT_PATH}")


if __name__ == "__main__":
    main()
