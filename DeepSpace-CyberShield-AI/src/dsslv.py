"""
dsslv.py
--------
Deep-Space Signal Lineage Verification (DSSLV) — paper Section IV-B.

Traces the expected relay journey of a bundle (ground station, orbiter,
relay satellite, receiver) and compares it against the path the bundle
actually took. An improbable route or an impossible relay transition is
flagged, catching forged routing / injected relay nodes even when the
signal itself looks legitimate.

The paper states the lineage score as `Lscore = Ntotal / Nmatch`. Taken
literally that formula grows *larger* the worse the match, which inverts
the intended meaning (a tampered path should score lower, not higher). We
implement the sensible normalized version of the same idea:

    lineage_score = Nmatch / Ntotal        (1.0 = perfect lineage match)

which preserves the paper's concept (counting matching hops against the
expected total) while producing a score that decreases as tampering
increases, consistent with how it's used downstream (low score -> flagged).
"""

from .dataset_generator import VALID_PATH

EXPECTED_PATH = VALID_PATH  # canonical Mars Rover -> Earth chain (Fig.5)


def _hops(relay_path: str):
    return [h.strip() for h in relay_path.split(">") if h.strip()]


def lineage_score(relay_path: str) -> float:
    actual = _hops(relay_path)
    expected = EXPECTED_PATH

    n_total = len(expected)
    n_match = 0
    for i, node in enumerate(expected):
        if i < len(actual) and actual[i] == node:
            n_match += 1

    # penalize extra/unknown hops (e.g. injected relay nodes) and unregistered sources
    unknown_hops = sum(1 for h in actual if h not in expected)
    score = (n_match / n_total) - 0.15 * unknown_hops
    return float(max(0.0, min(1.0, score)))


def verify(df) -> "pd.Series":
    return df["relay_path"].apply(lineage_score).rename("lineage_score")
