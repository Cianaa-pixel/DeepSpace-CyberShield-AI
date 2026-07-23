from colorama import Fore, Style, init
import pandas as pd

from data_loader import load_data
from ai_engine import AIEngine

# Initialize Colorama
init(autoreset=True)

# Pandas Display Settings
pd.set_option("display.max_columns", None)
pd.set_option("display.width", None)


# -------------------------------------------------

def print_status(score):

    if score >= 80:
        return Fore.GREEN + "🟢 Trusted"

    elif score >= 60:
        return Fore.YELLOW + "🟡 Monitor"

    elif score >= 40:
        return Fore.LIGHTYELLOW_EX + "🟠 Suspicious"

    elif score >= 20:
        return Fore.RED + "🔴 High Risk"

    else:
        return Fore.MAGENTA + "⚫ Untrusted"


# -------------------------------------------------

def get_recommendation(prediction):

    if prediction == "Anomaly":

        return (
            Fore.RED +
            "🚨 Recommendation : Disconnect Relay\n"
            "📡 Notify Ground Station\n"
            "🛡 Begin Intrusion Scan"
        )

    return (
        Fore.GREEN +
        "✅ Recommendation : Continue Communication\n"
        "📡 Communication Secure"
    )


# -------------------------------------------------

def main():

    print(Fore.CYAN + "=" * 70)
    print(Fore.CYAN + "            DeepSpace CyberShield AI")
    print(Fore.CYAN + "=" * 70)

    # ---------------------------------------------
    # Load Dataset
    # ---------------------------------------------

    dataset = load_data("dataset/communication_logs.csv")

    if dataset is None:
        print(Fore.RED + "Failed to load dataset.")
        return

    # ---------------------------------------------
    # AI Engine
    # ---------------------------------------------

    ai = AIEngine()

    ai.dataset = dataset

    if not ai.load_model():

        ai.train_model()

        ai.save_model()

    dataset = ai.predict()

    ai.evaluate_model()

    # ---------------------------------------------
    # Dashboard
    # ---------------------------------------------

    dataset["trust_level"] = dataset["trust_score"].apply(print_status)

    print(Fore.CYAN)
    print("\n==================== LIVE COMMUNICATION DASHBOARD ====================\n")

    for index, row in dataset.head(20).iterrows():

        print(Fore.CYAN + "=" * 70)

        print(Fore.WHITE + f"🛰 Communication #{index+1}")

        print(Fore.CYAN + "=" * 70)

        print(f"Timestamp          : {row['timestamp']}")
        print(f"Source             : {row['source']}")
        print(f"Destination        : {row['destination']}")
        print(f"Relay              : {row['relay']}")
        print(f"Mission Phase      : {row['mission_phase']}")

        print()

        print(f"Communication      : {row['status']}")
        print(f"AI Prediction      : {row['AI_Prediction']}")

        print()

        print(f"Delay              : {row['delay_ms']} ms")
        print(f"Signal Strength    : {row['signal_strength']} dBm")
        print(f"TTL                : {row['ttl']}")

        print()

        print(f"TTL Evidence       : {row['ttl_evidence']}")
        print(f"DSSLV Score        : {row['dsslv_score']}")
        print(f"Dynamic TTL Trust  : {row['dynamic_ttl_trust']}")

        print()

        print(f"Trust Score        : {row['trust_score']:.2f}")
        print(f"Trust Level        : {row['trust_level']}")

        print()

        print(get_recommendation(row["AI_Prediction"]))

        print(Fore.CYAN + "=" * 70)
        print()

    print(Fore.GREEN + "\n✔ DeepSpace CyberShield AI Execution Completed Successfully!")
    print(Style.RESET_ALL)


# -------------------------------------------------

if __name__ == "__main__":
    main()