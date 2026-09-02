"""
report_generator.py
--------------------
Turns pipeline output into the performance metrics described in
Section V-A / Fig.6 of the paper: detection accuracy, precision, recall,
F1-score, and a confusion matrix, computed against the synthetic ground
truth labels attached by dataset_generator.
"""

import pandas as pd
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
)

GROUND_TRUTH_MAP = {
    "Normal": "Legitimate",
}


def _ground_truth_verdict(status: str) -> str:
    return GROUND_TRUTH_MAP.get(status, "Malicious (TTL Decayed)")


def summarize(result_df: pd.DataFrame) -> dict:
    df = result_df.copy()
    df["ground_truth"] = df["status"].apply(_ground_truth_verdict)

    # collapse "Suspicious" into "Malicious (TTL Decayed)" bucket for a binary
    # legitimate-vs-flagged comparison against ground truth
    predicted = df["verdict"].apply(
        lambda v: "Legitimate" if v == "Legitimate" else "Malicious (TTL Decayed)"
    )
    actual = df["ground_truth"]

    labels = ["Legitimate", "Malicious (TTL Decayed)"]

    metrics = {
        "total_records": len(df),
        "accuracy": round(accuracy_score(actual, predicted) * 100, 2),
        "precision": round(precision_score(actual, predicted, pos_label="Malicious (TTL Decayed)") * 100, 2),
        "recall": round(recall_score(actual, predicted, pos_label="Malicious (TTL Decayed)") * 100, 2),
        "f1_score": round(f1_score(actual, predicted, pos_label="Malicious (TTL Decayed)") * 100, 2),
        "confusion_matrix": confusion_matrix(actual, predicted, labels=labels).tolist(),
        "confusion_labels": labels,
        "by_attack_type": df.groupby("status")["verdict"].value_counts().unstack(fill_value=0).to_dict(orient="index"),
    }
    return metrics


def to_markdown(metrics: dict) -> str:
    lines = [
        "# DeepSpace CyberShield AI — Detection Report",
        "",
        f"- Total records analyzed: **{metrics['total_records']}**",
        f"- Accuracy: **{metrics['accuracy']}%**",
        f"- Precision: **{metrics['precision']}%**",
        f"- Recall: **{metrics['recall']}%**",
        f"- F1-Score: **{metrics['f1_score']}%**",
        "",
        "## Confusion Matrix",
        "",
        "| | Predicted Legitimate | Predicted Malicious |",
        "|---|---|---|",
    ]
    cm = metrics["confusion_matrix"]
    labels = metrics["confusion_labels"]
    for i, label in enumerate(labels):
        lines.append(f"| Actual {label} | {cm[i][0]} | {cm[i][1]} |")

    lines.append("")
    lines.append("## Verdicts by Attack Type")
    lines.append("")
    for attack_type, verdicts in metrics["by_attack_type"].items():
        parts = ", ".join(f"{k}: {v}" for k, v in verdicts.items())
        lines.append(f"- **{attack_type}** → {parts}")

    return "\n".join(lines)


# ------------------------------------------------------------------
# Fake Signal Priority Ranking
# ------------------------------------------------------------------
# Turns the raw component scores each flagged bundle already carries
# (St, Sl, Sr, Sh, Sc, lineage_score, dynamic_trust, anomaly_confidence)
# into a plain-English explanation of *why* it was flagged, and ranks
# every non-Legitimate bundle by how urgently it needs review.

REASON_THRESHOLDS = {
    "lineage_score": (0.5, "Relay path doesn't match the expected route (lineage score {v:.2f}) "
                            "— route deviates from the known Rover -> Orbiter -> Relay -> Earth chain, "
                            "or includes an unrecognized relay node."),
    "St": (0.4, "Transmission cadence is inconsistent with this source's history (timing consistency "
                "{v:.2f}) — arrives far faster or more irregularly spaced than its normal rhythm."),
    "Sl": (0.4, "Propagation delay doesn't match this source's historical latency profile "
                "(latency consistency {v:.2f})."),
    "Sh": (0.4, "Overall signal profile diverges from this source's historical baseline "
                "(historical similarity {v:.2f})."),
    "dynamic_trust": (0.5, "This source's cumulative trust has eroded to {v:.2f} after a run of "
                           "inconsistent transmissions — no single packet looked wrong, but the "
                           "pattern over time does."),
}


def explain_row(row) -> list:
    reasons = []

    for col, (threshold, template) in REASON_THRESHOLDS.items():
        if col in row and pd.notna(row[col]) and row[col] < threshold:
            reasons.append(template.format(v=row[col]))

    if "anomaly_confidence" in row and pd.notna(row["anomaly_confidence"]) and row["anomaly_confidence"] > 0.6:
        reasons.append(
            f"AI Behavioral Engine scored this bundle's raw telemetry as anomalous "
            f"(confidence {row['anomaly_confidence']:.2f}) relative to learned normal traffic."
        )

    if not reasons:
        reasons.append(
            f"Combined trust + lineage confidence ({row.get('combined_confidence', 0):.2f}) fell "
            f"below the safe threshold, even though no single signal was extreme on its own."
        )

    return reasons


def rank_fake_signals(result_df: pd.DataFrame, top_n: int = 20) -> pd.DataFrame:
    flagged = result_df[result_df["verdict"] != "Legitimate"].copy()
    if flagged.empty:
        return flagged

    flagged["priority_score"] = (1 - flagged["combined_confidence"]).round(3)
    flagged["reasons"] = flagged.apply(lambda r: explain_row(r), axis=1)
    flagged["reason_text"] = flagged["reasons"].apply(lambda rs: " | ".join(rs))

    ranked = flagged.sort_values(
        ["priority_score", "verdict"], ascending=[False, True]
    ).reset_index(drop=True)
    ranked.insert(0, "priority_rank", ranked.index + 1)

    return ranked.head(top_n)
