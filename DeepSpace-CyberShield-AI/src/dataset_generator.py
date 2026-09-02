"""
dataset_generator.py
---------------------
Generates a synthetic Deep-Space Communication Network (DSCN) dataset that
mirrors the simulation environment described in the paper (Section V):

    "We generate a synthetic dataset that contains both normal communications
    and several simulated cyber-attacks such as signal spoofing, replay,
    relay tampering, Bundle-Flooding and Unauthorised Signal Injection."

Network topology matches Fig.5 of the paper:
    Earth Ground Station <-> Lunar Relay Satellite 1 <-> Lunar Relay Satellite 2
        <-> Mars Orbiter <-> Mars Surface Rovers (1/2/3)

Each row = one communication bundle with the feature set named in the paper:
timestamp, propagation delay, RSS, packet size, transmission rate/frequency,
relay path, and Bundle Protocol TTL.
"""

import random
import numpy as np
import pandas as pd
from datetime import datetime, timedelta

# ------------------------------------------------------------------
# Network topology (Fig.5 of the paper)
# ------------------------------------------------------------------

VALID_PATH = [
    "Mars Surface Rover",
    "Mars Orbiter",
    "Lunar Relay Satellite 2",
    "Lunar Relay Satellite 1",
    "Earth Ground Station",
]

SOURCES = ["Rover-1", "Rover-2", "Rover-3"]

ATTACK_TYPES = [
    "Spoofing",
    "Replay",
    "Relay Tampering",
    "Bundle Flooding",
    "Unauthorized Injection",
]

BASE_DELAY_SEC = 720.0          # ~12 min one-way Mars-Earth baseline delay
BASE_RSS_DBM = -95.0
BASE_PACKET_SIZE = 512
BASE_RATE_BPS = 256
BASE_TTL = 3600                 # seconds, Bundle Protocol TTL


def _jitter(base, pct, rng):
    return base * (1 + rng.uniform(-pct, pct))


def _normal_bundle(bundle_id, source, t, rng):
    return {
        "bundle_id": bundle_id,
        "timestamp": t.isoformat(),
        "source": source,
        "destination": "Earth Ground Station",
        "relay_path": ">".join(VALID_PATH),
        "propagation_delay_sec": round(_jitter(BASE_DELAY_SEC, 0.03, rng), 2),
        "rss_dbm": round(_jitter(BASE_RSS_DBM, 0.05, rng), 2),
        "packet_size_bytes": int(_jitter(BASE_PACKET_SIZE, 0.10, rng)),
        "transmission_rate_bps": int(_jitter(BASE_RATE_BPS, 0.08, rng)),
        "ttl_original": BASE_TTL,
        "status": "Normal",
    }


def _attack_bundle(bundle_id, source, t, attack_type, rng):
    row = _normal_bundle(bundle_id, source, t, rng)
    row["status"] = attack_type

    if attack_type == "Spoofing":
        # Near-perfect mimicry at the packet level, tiny behavioural drift
        row["propagation_delay_sec"] = round(_jitter(BASE_DELAY_SEC, 0.06, rng), 2)
        row["rss_dbm"] = round(_jitter(BASE_RSS_DBM, 0.09, rng), 2)

    elif attack_type == "Replay":
        # A genuinely previously-sent bundle is captured and re-transmitted:
        # its feature values are an exact duplicate of an earlier bundle
        # (real fresh transmissions always carry their own sensor jitter).
        pass  # exact duplication of a prior bundle's values is applied by the caller

    elif attack_type == "Relay Tampering":
        # Impossible / skipped relay hop
        tampered = VALID_PATH.copy()
        idx = rng.randint(1, len(tampered) - 1)
        tampered.insert(idx, "Unknown-Relay-X")
        row["relay_path"] = ">".join(tampered)

    elif attack_type == "Bundle Flooding":
        # Abnormally high transmission rate AND abnormally rapid packet cadence
        # (the tight arrival spacing itself is set by the caller's t-increment)
        row["transmission_rate_bps"] = int(BASE_RATE_BPS * rng.uniform(6, 12))
        row["packet_size_bytes"] = int(_jitter(BASE_PACKET_SIZE, 0.4, rng))

    elif attack_type == "Unauthorized Injection":
        # Traffic from a node outside the known mission node set
        row["source"] = f"Unregistered-Node-{rng.randint(1,99)}"
        row["relay_path"] = "Unregistered-Node>Earth Ground Station"
        row["rss_dbm"] = round(_jitter(BASE_RSS_DBM, 0.25, rng), 2)

    return row


def generate_dataset(n_normal_per_source=260, n_attacks_per_type=30, seed=42):
    rng = random.Random(seed)
    rows = []
    bundle_id = 1
    start = datetime(2026, 8, 1, 0, 0, 0)

    for source in SOURCES:
        t = start
        normal_history = []
        for _ in range(n_normal_per_source):
            t = t + timedelta(seconds=rng.randint(30, 90))
            bundle = _normal_bundle(bundle_id, source, t, rng)
            rows.append(bundle)
            normal_history.append(bundle)
            bundle_id += 1

        for attack_type in ATTACK_TYPES:
            for _ in range(n_attacks_per_type):
                # Bundle Flooding attacks arrive in a rapid burst, far faster
                # than the normal ~30-90s cadence; every other attack type
                # keeps a normal-looking arrival cadence.
                if attack_type == "Bundle Flooding":
                    t = t + timedelta(seconds=rng.randint(1, 4))
                else:
                    t = t + timedelta(seconds=rng.randint(20, 80))
                bundle = _attack_bundle(bundle_id, source, t, attack_type, rng)

                if attack_type == "Replay":
                    # Duplicate an earlier real bundle's exact signature
                    original = rng.choice(normal_history)
                    bundle["propagation_delay_sec"] = original["propagation_delay_sec"]
                    bundle["rss_dbm"] = original["rss_dbm"]
                    bundle["packet_size_bytes"] = original["packet_size_bytes"]

                rows.append(bundle)
                bundle_id += 1

    df = pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)
    return df


def save_dataset(path, **kwargs):
    df = generate_dataset(**kwargs)
    df.to_csv(path, index=False)
    return df


if __name__ == "__main__":
    df = generate_dataset()
    print(df["status"].value_counts())
    print(df.head())
