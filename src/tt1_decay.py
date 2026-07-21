def apply_dynamic_decay(data):

    current_trust = 100
    attack_streak = 0

    dynamic_scores = []
    trust_level = []
    reason = []

    for _, row in data.iterrows():

        if row["status"] == "Normal":

            attack_streak = 0

            current_trust = min(100, current_trust + 3)

            why = "Normal Communication"

        else:

            attack_streak += 1

            if row["status"] == "Spoofing":
                penalty = 10

            elif row["status"] == "Replay":
                penalty = 15

            elif row["status"] == "Injection":
                penalty = 25

            else:
                penalty = 10

            penalty += attack_streak * 5

            current_trust = max(0, current_trust - penalty)

            why = row["status"] + " Detected"

        dynamic_scores.append(current_trust)

        if current_trust >= 80:
            level = "🟢 Trusted"

        elif current_trust >= 60:
            level = "🟡 Monitor"

        elif current_trust >= 40:
            level = "🟠 Suspicious"

        elif current_trust >= 20:
            level = "🔴 High Risk"

        else:
            level = "⚫ Untrusted"

        trust_level.append(level)
        reason.append(why)

    data["dynamic_trust"] = dynamic_scores
    data["trust_level"] = trust_level
    data["reason"] = reason

    return data