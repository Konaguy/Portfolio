import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from eval.eval_harness import compute_metrics, run_eval
from copilot.schema import TriageVerdict

SAMPLE_PATH = Path(__file__).resolve().parent.parent / "eval" / "sample_labeled_alerts.json"


class TestComputeMetrics:
    def test_perfect_predictions_score_perfectly(self):
        predictions = [
            {
                "alert_id": "e1", "predicted_severity": "high", "predicted_fp_probability": 0.05,
                "predicted_action": "contain_immediately", "true_severity": "high",
                "true_false_positive": False, "true_action": "contain_immediately",
            },
            {
                "alert_id": "e2", "predicted_severity": "low", "predicted_fp_probability": 0.95,
                "predicted_action": "close_false_positive", "true_severity": "low",
                "true_false_positive": True, "true_action": "close_false_positive",
            },
        ]
        metrics = compute_metrics(predictions)
        assert metrics["severity_exact_match_rate"] == 1.0
        assert metrics["action_exact_match_rate"] == 1.0
        assert metrics["false_positive_detection"]["precision"] == 1.0
        assert metrics["false_positive_detection"]["recall"] == 1.0
        assert metrics["misses"] == []

    def test_severity_off_by_two_is_flagged_as_a_miss(self):
        predictions = [
            {
                "alert_id": "e3", "predicted_severity": "medium", "predicted_fp_probability": 0.3,
                "predicted_action": "monitor", "true_severity": "critical",
                "true_false_positive": False, "true_action": "contain_immediately",
            }
        ]
        metrics = compute_metrics(predictions)
        assert metrics["severity_exact_match_rate"] == 0.0
        assert metrics["severity_within_one_level_rate"] == 0.0
        assert len(metrics["misses"]) >= 1

    def test_severity_off_by_one_counts_within_one_level(self):
        predictions = [
            {
                "alert_id": "e4", "predicted_severity": "high", "predicted_fp_probability": 0.2,
                "predicted_action": "escalate_tier2", "true_severity": "critical",
                "true_false_positive": False, "true_action": "escalate_tier2",
            }
        ]
        metrics = compute_metrics(predictions)
        assert metrics["severity_exact_match_rate"] == 0.0
        assert metrics["severity_within_one_level_rate"] == 1.0

    def test_false_negative_fp_detection_is_penalized_and_flagged(self):
        """A predicted-true-positive that was actually a false positive
        (missed FP) should hurt recall and show up in misses."""
        predictions = [
            {
                "alert_id": "e5", "predicted_severity": "high", "predicted_fp_probability": 0.2,
                "predicted_action": "escalate_tier2", "true_severity": "low",
                "true_false_positive": True, "true_action": "close_false_positive",
            }
        ]
        metrics = compute_metrics(predictions)
        assert metrics["false_positive_detection"]["confusion"]["fn"] == 1
        assert any("missed FP" in reason for _, reason in metrics["misses"])

    def test_raises_on_empty_predictions(self):
        with pytest.raises(ValueError):
            compute_metrics([])

    def test_threshold_is_configurable(self):
        predictions = [
            {
                "alert_id": "e6", "predicted_severity": "low", "predicted_fp_probability": 0.6,
                "predicted_action": "monitor", "true_severity": "low",
                "true_false_positive": True, "true_action": "monitor",
            }
        ]
        # At threshold 0.5, 0.6 counts as "flagged FP" -> true positive for FP detection.
        strict = compute_metrics(predictions, fp_threshold=0.5)
        assert strict["false_positive_detection"]["confusion"]["tp"] == 1

        # At threshold 0.8, 0.6 does NOT count as flagged -> false negative.
        loose = compute_metrics(predictions, fp_threshold=0.8)
        assert loose["false_positive_detection"]["confusion"]["fn"] == 1


class TestSampleDataFile:
    def test_sample_file_is_valid_json_with_expected_shape(self):
        with open(SAMPLE_PATH) as f:
            data = json.load(f)
        assert "closed_cases" in data
        assert "labeled_alerts" in data
        assert len(data["closed_cases"]) >= 1
        assert len(data["labeled_alerts"]) >= 1
        for alert in data["labeled_alerts"]:
            assert "ground_truth" in alert
            assert set(alert["ground_truth"].keys()) == {
                "severity", "false_positive", "recommended_action"
            }


class TestRunEvalIntegration:
    def test_run_eval_loads_data_and_calls_engine_per_alert(self):
        """
        Full pipeline test with only the LLM call mocked -- exercises
        real JSON loading, real vector store indexing/retrieval, and real
        enrichment against the shipped sample_labeled_alerts.json.
        """
        with open(SAMPLE_PATH) as f:
            n_alerts = len(json.load(f)["labeled_alerts"])

        fake_verdict = TriageVerdict(
            alert_id="placeholder",
            severity="high",
            false_positive_probability=0.2,
            recommended_action="escalate_tier2",
            rationale="mocked",
            cited_case_ids=[],
        )

        with patch("eval.eval_harness.TriageEngine") as MockEngine:
            instance = MockEngine.return_value

            def fake_triage(alert, context):
                return fake_verdict.model_copy(update={"alert_id": alert.alert_id})

            instance.triage.side_effect = fake_triage

            metrics = run_eval(str(SAMPLE_PATH))

        assert instance.triage.call_count == n_alerts
        assert metrics["n"] == n_alerts
