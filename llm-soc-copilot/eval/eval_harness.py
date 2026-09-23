"""
Evaluation harness: runs the triage pipeline against a labeled alert set
and reports how well its verdicts match ground truth.

Usage:
    export ANTHROPIC_API_KEY=sk-...
    python eval/eval_harness.py eval/sample_labeled_alerts.json

Metrics computed (see compute_metrics, which is the testable core -- it
takes plain dicts, not live model output, so it's covered by
tests/test_eval_harness.py without needing API access):
    - False-positive classification: precision/recall/F1, treating
      "flagged as likely false positive" (false_positive_probability
      >= threshold) as the positive class.
    - Severity exact-match rate, and "within one level" rate (since
      high-vs-critical disagreements are a much smaller miss than
      low-vs-critical).
    - Recommended-action exact-match rate.
    - Per-alert detail table for manual review of misses.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from copilot.schema import Alert
from copilot.vectorstore import TfidfCaseStore, ClosedCase
from copilot.enrichment import enrich_alert, InMemoryAssetLookup
from copilot.triage import TriageEngine

SEVERITY_ORDER = ["low", "medium", "high", "critical"]
DEFAULT_FP_THRESHOLD = 0.5


def _severity_distance(a: str, b: str) -> int:
    return abs(SEVERITY_ORDER.index(a) - SEVERITY_ORDER.index(b))


def compute_metrics(
    predictions: list[dict[str, Any]],
    fp_threshold: float = DEFAULT_FP_THRESHOLD,
) -> dict[str, Any]:
    """
    Pure function over prediction/ground-truth pairs, kept separate from
    the LLM-calling code above so it's unit-testable without API access.

    Each item in `predictions` is expected to have:
        alert_id, predicted_severity, predicted_fp_probability,
        predicted_action, true_severity, true_false_positive, true_action
    """
    n = len(predictions)
    if n == 0:
        raise ValueError("No predictions to score")

    tp = fp = fn = tn = 0  # for false-positive classification
    severity_exact = 0
    severity_within_one = 0
    action_exact = 0
    misses = []

    for p in predictions:
        predicted_is_fp = p["predicted_fp_probability"] >= fp_threshold
        actual_is_fp = p["true_false_positive"]

        if predicted_is_fp and actual_is_fp:
            tp += 1
        elif predicted_is_fp and not actual_is_fp:
            fp += 1
            misses.append((p["alert_id"], "flagged FP but was a true positive"))
        elif not predicted_is_fp and actual_is_fp:
            fn += 1
            misses.append((p["alert_id"], "missed FP -- flagged as true positive"))
        else:
            tn += 1

        if p["predicted_severity"] == p["true_severity"]:
            severity_exact += 1
        dist = _severity_distance(p["predicted_severity"], p["true_severity"])
        if dist <= 1:
            severity_within_one += 1
        if dist > 1:
            misses.append(
                (p["alert_id"], f"severity off by {dist}: predicted {p['predicted_severity']}, "
                                 f"actual {p['true_severity']}")
            )

        if p["predicted_action"] == p["true_action"]:
            action_exact += 1

    precision = tp / (tp + fp) if (tp + fp) else float("nan")
    recall = tp / (tp + fn) if (tp + fn) else float("nan")
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else float("nan")

    return {
        "n": n,
        "false_positive_detection": {
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "f1": round(f1, 3),
            "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        },
        "severity_exact_match_rate": round(severity_exact / n, 3),
        "severity_within_one_level_rate": round(severity_within_one / n, 3),
        "action_exact_match_rate": round(action_exact / n, 3),
        "misses": misses,
    }


def run_eval(labeled_path: str, fp_threshold: float = DEFAULT_FP_THRESHOLD) -> dict[str, Any]:
    with open(labeled_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    vector_store = TfidfCaseStore()
    vector_store.index([ClosedCase(**c) for c in data["closed_cases"]])

    asset_lookup = InMemoryAssetLookup(
        {
            item["entity_value"]: {"criticality": item["asset_criticality"], "owner": "unknown"}
            for item in data["labeled_alerts"]
        }
    )

    engine = TriageEngine()  # requires ANTHROPIC_API_KEY in the environment

    predictions = []
    for item in data["labeled_alerts"]:
        alert = Alert(
            alert_id=item["alert_id"],
            source=item["source"],
            raw_title=item["raw_title"],
            raw_description=item.get("raw_description", ""),
            entity_type=item["entity_type"],
            entity_value=item["entity_value"],
            timestamp=item["timestamp"],
            mitre_techniques=item.get("mitre_techniques", []),
        )
        context = enrich_alert(alert, vector_store, asset_lookup)
        verdict = engine.triage(alert, context)

        predictions.append(
            {
                "alert_id": item["alert_id"],
                "predicted_severity": verdict.severity.value,
                "predicted_fp_probability": verdict.false_positive_probability,
                "predicted_action": verdict.recommended_action.value,
                "true_severity": item["ground_truth"]["severity"],
                "true_false_positive": item["ground_truth"]["false_positive"],
                "true_action": item["ground_truth"]["recommended_action"],
            }
        )

    return compute_metrics(predictions, fp_threshold=fp_threshold)


def _print_report(metrics: dict[str, Any]) -> None:
    print(f"Evaluated {metrics['n']} labeled alerts\n")
    fp = metrics["false_positive_detection"]
    print("False-positive detection:")
    print(f"  precision={fp['precision']}  recall={fp['recall']}  f1={fp['f1']}")
    print(f"  confusion: {fp['confusion']}\n")
    print(f"Severity exact match:      {metrics['severity_exact_match_rate']:.1%}")
    print(f"Severity within one level: {metrics['severity_within_one_level_rate']:.1%}")
    print(f"Action exact match:        {metrics['action_exact_match_rate']:.1%}\n")
    if metrics["misses"]:
        print("Misses (review these manually):")
        for alert_id, reason in metrics["misses"]:
            print(f"  - {alert_id}: {reason}")
    else:
        print("No misses.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python eval/eval_harness.py <labeled_alerts.json>")
        sys.exit(1)
    result = run_eval(sys.argv[1])
    _print_report(result)
