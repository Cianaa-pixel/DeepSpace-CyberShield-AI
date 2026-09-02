"""
ttl_evidence.py
---------------
Temporal Trust Leakage Evidence (TTL-Evidence) — the paper's core
contribution (Section IV-A, Fig.3).

Implements:

    Tscore = w1*St + w2*Sl + w3*Sr + w4*Sh + w5*Sc      (w1+..+w5 = 1)

    where St = transmission timing consistency
          Sl = latency consistency
          Sr = communication rhythm
          Sh = historical behavioural similarity
          Sc = past anomaly confidence (from ai_engine)

and the dynamic trust decay from Fig.3:

    T_new = T_old * exp(-TL(t))

so that a source's trust erodes across a *sequence* of bundles rather than
being judged on any single packet in isolation — this is what lets
TTL-Evidence catch a spoofer that gets every individual packet "right" but
drifts slightly, over and over, from the source's real behaviour.
"""

import numpy as np
import pandas as pd
from collections import defaultdict

DEFAULT_WEIGHTS = {
    "St": 0.25,   # timing consistency
    "Sl": 0.20,   # latency consistency
    "Sr": 0.20,   # communication rhythm
    "Sh": 0.10,   # historical similarity
    "Sc": 0.25,   # past anomaly confidence
}


def _consistency(value, baseline_mean, baseline_std):
    """1.0 = perfectly consistent with history, decays toward 0 with deviation."""
    if baseline_std < 1e-6:
        baseline_std = 1e-6
    z = abs(value - baseline_mean) / baseline_std
    return float(np.exp(-0.5 * z))  # gaussian-shaped consistency score


class TTLEvidenceEngine:
    """
    Stateful, per-source trust tracker. Call `evaluate(df, anomaly_conf)`
    with bundles in chronological order for each source to get both a
    point-in-time Tscore and an eroding dynamic trust value per bundle.
    """

    def __init__(self, weights=None):
        self.weights = weights or DEFAULT_WEIGHTS
        self._history = defaultdict(lambda: {
            "delays": [], "rss": [], "intervals": [], "last_ts": None,
        })
        self._trust = defaultdict(lambda: 1.0)  # dynamic trust per source
        self._seen_fingerprints = defaultdict(set)  # per-source signature cache

    def evaluate(self, df: pd.DataFrame, anomaly_confidence: pd.Series) -> pd.DataFrame:
        df = df.sort_values("timestamp").copy()
        results = []

        for idx, row in df.iterrows():
            src = row["source"]
            hist = self._history[src]
            ts = pd.Timestamp(row["timestamp"])

            # --- interval since last bundle from this source ---
            if hist["last_ts"] is not None:
                interval = (ts - hist["last_ts"]).total_seconds()
            else:
                interval = np.nan
            hist["last_ts"] = ts

            # --- St: timing consistency (spacing between bundles) ---
            if len(hist["intervals"]) >= 3 and not np.isnan(interval):
                St = _consistency(interval, np.mean(hist["intervals"]), np.std(hist["intervals"]))
            else:
                St = 1.0

            # --- Sl: latency (propagation delay) consistency ---
            if len(hist["delays"]) >= 3:
                Sl = _consistency(row["propagation_delay_sec"], np.mean(hist["delays"]), np.std(hist["delays"]))
            else:
                Sl = 1.0

            # --- Sr: communication rhythm (RSS stability as a proxy) ---
            if len(hist["rss"]) >= 3:
                Sr = _consistency(row["rss_dbm"], np.mean(hist["rss"]), np.std(hist["rss"]))
            else:
                Sr = 1.0

            # --- Sh: historical similarity (combined delay+rss profile) ---
            if len(hist["delays"]) >= 3:
                d_sim = _consistency(row["propagation_delay_sec"], np.mean(hist["delays"]), np.std(hist["delays"]) or 1)
                r_sim = _consistency(row["rss_dbm"], np.mean(hist["rss"]), np.std(hist["rss"]) or 1)
                Sh = (d_sim + r_sim) / 2
            else:
                Sh = 1.0

            # --- Sc: past anomaly confidence (inverted: high anomaly -> low trust) ---
            Sc = 1.0 - float(anomaly_confidence.loc[idx])

            w = self.weights
            Tscore = (
                w["St"] * St + w["Sl"] * Sl + w["Sr"] * Sr +
                w["Sh"] * Sh + w["Sc"] * Sc
            )
            Tscore = float(np.clip(Tscore, 0, 1))

            # --- replay detection: a bundle whose signature exactly matches
            # one already transmitted by this source is a re-sent/replayed
            # bundle, not a fresh natural transmission (which always carries
            # its own sensor jitter) -> hard trust penalty.
            fingerprint = (
                round(row["propagation_delay_sec"], 1),
                round(row["rss_dbm"], 1),
                round(row["packet_size_bytes"], -1),
            )
            if fingerprint in self._seen_fingerprints[src] and len(self._seen_fingerprints[src]) > 3:
                Tscore = min(Tscore, 0.10)
            else:
                self._seen_fingerprints[src].add(fingerprint)

            # --- dynamic trust: exponential moving average of Tscore ---
            # Implements the paper's "trust erodes across sustained bad
            # behaviour, not a single packet" idea (Fig.3: T_new = T_old *
            # e^-TL(t)) as a numerically stable EMA: a source that keeps
            # producing low-Tscore bundles sees dynamic_trust decay
            # smoothly toward that low value; a source with consistently
            # high Tscore stays near 1.0.
            alpha = 0.15
            self._trust[src] = self._trust[src] + alpha * (Tscore - self._trust[src])

            results.append({
                "index": idx,
                "St": round(St, 3), "Sl": round(Sl, 3), "Sr": round(Sr, 3),
                "Sh": round(Sh, 3), "Sc": round(Sc, 3),
                "trust_score": round(Tscore, 3),
                "dynamic_trust": round(self._trust[src], 3),
            })

            # update rolling history
            hist["delays"].append(row["propagation_delay_sec"])
            hist["rss"].append(row["rss_dbm"])
            if not np.isnan(interval):
                hist["intervals"].append(interval)
            for key in ("delays", "rss", "intervals"):
                if len(hist[key]) > 50:
                    hist[key] = hist[key][-50:]

        out = pd.DataFrame(results).set_index("index")
        return df.join(out)
