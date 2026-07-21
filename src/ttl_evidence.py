import pandas as pd

def calculate_ttl(data):

    trust_scores = []

    for _, row in data.iterrows():

        # Every communication starts fully trusted
        trust = 100

        # Rule 1: Unknown relay
        if row["relay"] == "Unknown_Relay":
            trust -= 40

        # Rule 2: Very small delay
        if row["delay_ms"] < 500:
            trust -= 20

        # Rule 3: Abnormally strong signal
        if row["signal_strength"] > -30:
            trust -= 25

        # Rule 4: Attack label
        if row["status"] != "Normal":
            trust -= 15

        # Trust cannot go below zero
        trust = max(trust, 0)

        trust_scores.append(trust)

    data["trust_score"] = trust_scores

    return data