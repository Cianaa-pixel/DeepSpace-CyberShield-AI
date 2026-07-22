# Dynamic Signal Lineage Verification (DSSLV)

def verify_signal_lineage(dataset):

    # Trusted communication routes
    trusted_relays = {
        "Mars_Rover": "Relay_A",
        "Orbiter_1": "Relay_B"
    }

    lineage_status = []
    lineage_score = []

    for _, row in dataset.iterrows():

        source = row["source"]
        relay = row["relay"]

        # Check whether relay matches expected relay
        if trusted_relays.get(source) == relay:
            lineage_status.append("Verified")
            lineage_score.append(100)

        else:
            lineage_status.append("Unauthorized Relay")
            lineage_score.append(40)

    dataset["lineage_status"] = lineage_status
    dataset["lineage_score"] = lineage_score

    return dataset