"""
ttl_decay.py
------------
Passive Autonomous Eviction via Dynamic TTL Decay — paper Section IV-C.

Rather than actively deleting suspicious bundles (expensive for
SWaP-constrained spacecraft), the Bundle Protocol TTL of low-trust bundles
is reduced so the network's own garbage collector expires them naturally.

    combined_confidence C = w_trust * trust_score + w_lineage * lineage_score
    TTL_new = TTL_original * C          (legitimate bundles: C ~ 1, TTL unchanged)
                                         (malicious bundles:  C ~ 0, TTL collapses)
"""

import numpy as np
import pandas as pd

W_TRUST = 0.6
W_LINEAGE = 0.4

SUSPICIOUS_THRESHOLD = 0.65
MALICIOUS_THRESHOLD = 0.40


def apply_decay(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()

    # Weighted geometric mean rather than a weighted average: a single very
    # low signal (e.g. a tampered lineage) pulls the combined confidence
    # down sharply instead of being diluted by an otherwise-normal trust
    # score. This matches the paper's "multi-layered defence" intent -
    # any one layer catching a threat should be enough to flag it.
    # Blend the point-in-time Tscore with the cumulative dynamic_trust that
    # erodes across a source's history (Fig.3: T_new = T_old * e^-TL(t)).
    # This is what lets the framework catch a spoof that looks fine on any
    # single bundle but drifts, repeatedly, from the source's real pattern.
    trust_effective = (0.5 * df["trust_score"] + 0.5 * df["dynamic_trust"]).clip(1e-6, 1)
    lineage = df["lineage_score"].clip(1e-6, 1)
    combined_confidence = (trust_effective ** W_TRUST) * (lineage ** W_LINEAGE)
    combined_confidence = combined_confidence.clip(0, 1)

    df["combined_confidence"] = combined_confidence.round(3)
    df["ttl_new"] = (df["ttl_original"] * combined_confidence).round(0).astype(int)

    def verdict(c):
        if c >= SUSPICIOUS_THRESHOLD:
            return "Legitimate"
        elif c >= MALICIOUS_THRESHOLD:
            return "Suspicious"
        return "Malicious (TTL Decayed)"

    df["verdict"] = combined_confidence.apply(verdict)
    return df
