"""
ThreatLens GraphOps - Synthetic Sample Data Fixtures Loader
Provides programmatic access to curated, realistic, explicitly-labeled sample enterprise security graph data.
"""

import json
from pathlib import Path
from typing import Dict, Any

FIXTURES_DIR = Path(__file__).parent / "fixtures"
SAMPLE_ENTERPRISE_JSON_PATH = FIXTURES_DIR / "sample_enterprise_graph.json"


def load_sample_enterprise_fixture() -> Dict[str, Any]:
    """
    Loads the synthetic enterprise security graph fixture JSON.
    Returns the parsed dictionary.
    """
    if not SAMPLE_ENTERPRISE_JSON_PATH.exists():
        raise FileNotFoundError(f"Fixture not found at {SAMPLE_ENTERPRISE_JSON_PATH}")

    with open(SAMPLE_ENTERPRISE_JSON_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


ANOMALY_SEQUENCES_JSON_PATH = FIXTURES_DIR / "anomaly_test_sequences.json"


def load_anomaly_test_sequences() -> Dict[str, Any]:
    """
    Loads the held-out labeled access anomaly test sequences fixture JSON.
    Returns the parsed dictionary.
    """
    if not ANOMALY_SEQUENCES_JSON_PATH.exists():
        raise FileNotFoundError(f"Fixture not found at {ANOMALY_SEQUENCES_JSON_PATH}")

    with open(ANOMALY_SEQUENCES_JSON_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

