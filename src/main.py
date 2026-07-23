from colorama import Fore, Style, init
import pandas as pd

from data_loader import load_data
from ai_engine import AIEngine

# Initialize Colorama
init(autoreset=True)

# Display Settings
pd.set_option("display.max_columns", None)
pd.set_option("display.width", None)


# ---------------------------------------------

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


# ---------------------------------------------

def main():

    print(Fore.CYAN + "=" * 70)
    print(Fore.CYAN + "           DeepSpace CyberShield AI")
    print(Fore.CYAN + "=" * 70)

    # -----------------------------
    # Load Dataset
    # -----------------------------

    dataset = load_data("dataset/communication_logs.csv")

    if dataset is None:
        print(Fore.RED + "\nDataset could not be loaded.")
        return

    # -----------------------------
    # AI Engine
    # -----------------------------

    ai = AIEngine()

    ai.dataset = dataset

    ai.train_model()

    dataset = ai.predict()

    ai.evaluate_model()

    # -----------------------------
    # Trust Level
    # -----------------------------

    dataset["trust_level"] = dataset["trust_score"].apply(print_status)

    # -----------------------------
    # Dashboard
    # -----------------------------

    print(Fore.CYAN)
    print("\n================ COMMUNICATION DASHBOARD ================\n")

    # Display first 20 records
    for index, row in dataset.head(20).iterrows():

        print(Fore.CYAN + "=" * 65)
        print(Fore.WHITE + f"🛰 Communication Record #{index+1}")
        print(Fore.CYAN + "=" * 65)

        print(f"Timestamp        : {row['timestamp']}")
        print(f"Source           : {row['source']}")
        print(f"Destination      : {row['destination']}")
        print(f"Relay            : {row['relay']}")
        print(f"Mission Phase    : {row['mission_phase']}")
        print()

        print(f"Status           : {row['status']}")
        print(f"AI Prediction    : {row['AI_Prediction']}")
        print()

        print(f"TTL              : {row['ttl']}")
        print(f"TTL Evidence     : {row['ttl_evidence']}")
        print(f"DSSLV Score      : {row['dsslv_score']}")
        print(f"Dynamic TTL      : {row['dynamic_ttl_trust']}")
        print()

        print(f"Trust Score      : {row['trust_score']:.2f}")
        print(f"Trust Level      : {row['trust_level']}")

        # Recommendation

        if row["AI_Prediction"] == "Anomaly":

            print(Fore.RED)
            print("Recommendation   : Disconnect Relay")
            print("Action           : Notify Ground Station")

        else:

            print(Fore.GREEN)
            print("Recommendation   : Continue Communication")
            print("Action           : No Threat Detected")

        print(Fore.CYAN + "=" * 65)
        print()

    print(Fore.GREEN + "\n✔ DeepSpace CyberShield AI Execution Completed Successfully!")
    print(Style.RESET_ALL)


# ---------------------------------------------

if __name__ == "__main__":
    main()