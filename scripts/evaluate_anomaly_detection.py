"""
ThreatLens GraphOps - Access Anomaly Detection Evaluation & Benchmark Script
Evaluates detection accuracy, precision, recall, false-positive rate, F1-score,
and query latency on the held-out labeled access sequences dataset.
"""

import sys
import time
import os
from pathlib import Path

# Add project root to path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

try:
    import psutil
except ImportError:
    psutil = None

from backend.graphops.anomaly_detection import AccessAnomalyDetector


def run_benchmark():
    print("=" * 72)
    print("THREATLENS GRAPHOPS - PHASE 9 ACCESS ANOMALY DETECTION BENCHMARK")
    print("=" * 72)

    process = psutil.Process(os.getpid()) if psutil else None
    mem_before = process.memory_info().rss / (1024 * 1024) if process else 0.0

    print("\n[1] Initializing Anomaly Baseline & Detection Engine...")
    t0 = time.perf_counter()
    detector = AccessAnomalyDetector()
    init_ms = (time.perf_counter() - t0) * 1000
    print(f"    Baseline Initialization Latency: {init_ms:.3f} ms")

    summary = detector.get_baseline_summary()
    print(f"    Indexed Baseline Entities: {summary.total_baseline_entities}")
    print(f"    Indexed Baseline Relationships: {summary.total_baseline_relationships}")
    print(f"    Network Tiering Rules: {len(summary.network_tiering_rules)}")
    print(f"    Department Profiles: {len(summary.department_profiles)}")

    print("\n[2] Executing Evaluation Across Held-Out Labeled Test Sequences (12 Cases)...")
    t1 = time.perf_counter()
    suite_res = detector.run_test_suite()
    total_eval_ms = (time.perf_counter() - t1) * 1000
    avg_per_seq_ms = total_eval_ms / max(1, suite_res.total_evaluated)

    print("\n[3] Sequence Classification Results Breakdown:")
    print("-" * 72)
    print(f"{'Sequence ID':<16} | {'Ground Truth':<24} | {'Predicted':<24} | {'Score':<5} | {'Match'}")
    print("-" * 72)

    for item in suite_res.results:
        match_str = "[PASS]" if item.is_match else "[FAIL]"
        print(f"{item.sequence_id:<16} | {item.ground_truth_label.value:<24} | {item.predicted_label.value:<24} | {item.anomaly_score:<5} | {match_str}")

    print("-" * 72)

    print("\n[4] Empirical Evaluation Metrics:")
    print(f"    Total Sequences Evaluated: {suite_res.total_evaluated}")
    print(f"    Total Correct Classifications: {suite_res.total_correct} / {suite_res.total_evaluated} ({suite_res.total_correct / suite_res.total_evaluated * 100:.1f}%)")
    print(f"    True Positives (TP):  {suite_res.confusion_matrix['TP']}")
    print(f"    True Negatives (TN):  {suite_res.confusion_matrix['TN']}")
    print(f"    False Positives (FP): {suite_res.confusion_matrix['FP']}")
    print(f"    False Negatives (FN): {suite_res.confusion_matrix['FN']}")
    print(f"    Precision:            {suite_res.precision:.4f} ({suite_res.precision * 100:.1f}%)")
    print(f"    Recall:               {suite_res.recall:.4f} ({suite_res.recall * 100:.1f}%)")
    print(f"    F1-Score:             {suite_res.f1_score:.4f}")
    print(f"    False Positive Rate:  {suite_res.false_positive_rate:.4f} ({suite_res.false_positive_rate * 100:.1f}%)")

    print("\n[5] Performance Latencies & Resource Profile:")
    print(f"    Total Batch Latency (12 sequences): {total_eval_ms:.3f} ms")
    print(f"    Average Evaluation per Sequence:   {avg_per_seq_ms:.3f} ms")

    if process:
        mem_after = process.memory_info().rss / (1024 * 1024)
        print(f"    Memory Consumption RSS:            {mem_after:.2f} MB (Delta: {mem_after - mem_before:+.2f} MB)")

    print("\n" + "=" * 72)
    print("PHASE 9 ANOMALY DETECTION BENCHMARK COMPLETED SUCCESSFULLY!")
    print("=" * 72)


if __name__ == "__main__":
    run_benchmark()
