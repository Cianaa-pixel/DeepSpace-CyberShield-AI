import pandas as pd

def calculate_ttl(data):

    trust_scores = []

    for _, row in data.iterrows():

        trust = 100

        # Unknown relay reduces trust
        if row["relay"] == "Unknown_Relay":
            trust -= 25

        # Delay anomaly
        if row["delay_ms"] < 500 or row["delay_ms"] > 3000:
            trust -= 20

        # Signal anomaly
        if row["signal_strength"] > -30:
            trust -= 20

        # Attack type penalty
        if row["status"] == "Spoofing":
            trust -= 15

        elif row["status"] == "Replay":
            trust -= 20

        elif row["status"] == "Injection":
            trust -= 30

        trust = max(0, trust)

        trust_scores.append(trust)

    data["trust_score"] = trust_scores

    return data