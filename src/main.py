from colorama import Fore, Style, init
import pandas as pd

from data_loader import load_data
from ttl_evidence import calculate_ttl
from tt1_decay import apply_dynamic_decay
from dsslv import verify_signal_lineage

# Initialize Colorama
init(autoreset=True)

# Show all columns if needed
pd.set_option("display.max_columns", None)
pd.set_option("display.width", None)


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


def main():

    # Load dataset
    dataset = load_data("dataset/communication_logs.csv")

    if dataset is None:
        print(Fore.RED + "\nFailed to load dataset.")
        return

    # Step 1 - TTL Evidence
    dataset = calculate_ttl(dataset)

    # Step 2 - Dynamic TTL Decay
    dataset = apply_dynamic_decay(dataset)

    # Step 3 - Signal Lineage Verification
    dataset = verify_signal_lineage(dataset)

    # Step 4 - Trust Level
    dataset["trust_level"] = dataset["dynamic_trust"].apply(print_status)

    print(Fore.CYAN + "\n================ DeepSpace CyberShield AI ================\n")

    # Display every communication record
    for index, row in dataset.iterrows():

        print(Fore.CYAN + "=" * 60)
        print(Fore.WHITE + f"🛰️  Communication Record #{index + 1}")
        print(Fore.CYAN + "=" * 60)

        print(f"Source            : {row['source']}")
        print(f"Destination       : {row['destination']}")
        print(f"Relay             : {row['relay']}")
        print(f"Status            : {row['status']}")

        print()

        print(f"Initial Trust     : {row['trust_score']}")
        print(f"Dynamic Trust     : {row['dynamic_trust']}")
        print(f"Lineage Status    : {row['lineage_status']}")
        print(f"Lineage Score     : {row['lineage_score']}")

        print()

        print(f"Trust Level       : {row['trust_level']}")
        print(f"Reason            : {row['reason']}")

        print(Fore.CYAN + "=" * 60)
        print()

    print(Fore.GREEN + "✔ Analysis Completed Successfully!")
    print(Style.RESET_ALL)


if __name__ == "__main__":
    main()