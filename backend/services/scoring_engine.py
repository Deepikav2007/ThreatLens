"""
MailTrace AI - Weighted Scoring Engine
Feature 1: AI Threat Detection
"""

from typing import Dict, Tuple
from backend.core.config import DEFAULT_SIGNAL_WEIGHTS, RISK_THRESHOLDS


def calculate_threat_score(
    signals: Dict[str, bool],
    weights: Dict[str, int] = None,
) -> Tuple[int, str, Dict[str, int]]:
    """
    Calculates the normalized threat score (0-100), risk level, and breakdown of signal scores.
    
    Returns:
        tuple of (threat_score: int, risk_level: str, signal_scores: Dict[str, int])
    """
    weights = weights or DEFAULT_SIGNAL_WEIGHTS
    
    # Calculate score contribution for each active signal
    signal_scores: Dict[str, int] = {}
    raw_score = 0
    
    for signal_name, is_active in signals.items():
        if is_active:
            weight = weights.get(signal_name, 10)
            signal_scores[signal_name] = weight
            raw_score += weight

    # Deduplication and correlated signal capping:
    # If both account_suspension and threat_language are active, cap their combined impact
    if signals.get("account_suspension") and signals.get("threat_language"):
        # Reduce duplicate fear penalty by 5 to avoid artificial inflation
        raw_score -= 5
        
    # Cap final normalized score to [0, 100]
    threat_score = max(0, min(100, raw_score))
    
    # Determine risk level based on configured boundaries
    risk_level = "LOW"
    for level, (min_val, max_val) in RISK_THRESHOLDS.items():
        if min_val <= threat_score <= max_val:
            risk_level = level
            break
            
    return threat_score, risk_level, signal_scores
