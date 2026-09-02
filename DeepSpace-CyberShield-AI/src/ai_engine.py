"""
ai_engine.py
------------
AI Behavioural Analysis Engine (paper Section IV, first stage).

Uses a lightweight unsupervised model (Isolation Forest, standing in for the
paper's "Autoencoder / Isolation Forest" options) to learn normal
communication behaviour from telemetry features and assign each bundle an
initial anomaly confidence score in [0, 1], with no labelled attack data
required.
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

FEATURE_COLUMNS = [
    "propagation_delay_sec",
    "rss_dbm",
    "packet_size_bytes",
    "transmission_rate_bps",
]


class AIBehavioralEngine:
    """Learns a profile of normal behaviour and scores incoming bundles."""

    def __init__(self, contamination=0.15, random_state=42):
        self.scaler = StandardScaler()
        self.model = IsolationForest(
            n_estimators=200,
            contamination=contamination,
            random_state=random_state,
        )
        self._fitted = False

    def fit(self, df: pd.DataFrame):
        X = self.scaler.fit_transform(df[FEATURE_COLUMNS])
        self.model.fit(X)
        self._fitted = True
        return self

    def score(self, df: pd.DataFrame) -> pd.Series:
        """Returns anomaly_confidence in [0,1]; higher = more anomalous."""
        if not self._fitted:
            self.fit(df)

        X = self.scaler.transform(df[FEATURE_COLUMNS])
        # decision_function: higher = more normal. Invert + normalise to [0,1]
        raw = -self.model.decision_function(X)
        raw = (raw - raw.min()) / (raw.max() - raw.min() + 1e-9)
        return pd.Series(raw, index=df.index, name="anomaly_confidence")
