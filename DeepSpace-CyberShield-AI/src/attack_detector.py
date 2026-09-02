"""
attack_detector.py
-------------------
Integrated Framework Operation (paper Section IV-D).

Runs the full pipeline over a set of communication bundles, in the order
the paper describes:

    1. AI Behavioural Analysis Engine  -> anomaly_confidence
    2. Temporal Trust Leakage Evidence -> trust_score / dynamic_trust
    3. Deep-Space Signal Lineage Verification -> lineage_score
    4. Dynamic TTL Decay -> ttl_new / verdict
"""

import pandas as pd

from .ai_engine import AIBehavioralEngine
from .ttl_evidence import TTLEvidenceEngine
from . import dsslv
from . import ttl_decay


def run_pipeline(df: pd.DataFrame) -> pd.DataFrame:
    ai = AIBehavioralEngine()
    ai.fit(df)
    anomaly_confidence = ai.score(df)

    ttl_engine = TTLEvidenceEngine()
    df_trust = ttl_engine.evaluate(df, anomaly_confidence)
    df_trust["anomaly_confidence"] = anomaly_confidence.round(3)

    df_trust["lineage_score"] = dsslv.verify(df_trust).round(3)

    result = ttl_decay.apply_decay(df_trust)
    return result.sort_values("bundle_id").reset_index(drop=True)
