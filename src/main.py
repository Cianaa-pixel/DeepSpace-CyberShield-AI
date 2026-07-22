from colorama import Fore, Style, init

from data_loader import load_data
from ttl_evidence import calculate_ttl
from ttl_decay import apply_dynamic_decay
from dsslv import verify_signal_lineage

# Initialize Colorama
init(autoreset=True)


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

    # Load Dataset
    dataset = load_data("dataset/communication_logs.csv")

    if dataset is None:
        print(Fore.RED + "Failed to load dataset.")
        return

    # Step 1: Calculate Initial Trust Score
    dataset = calculate_ttl(dataset)

    # Step 2: Apply Dynamic TTL Decay
    dataset = apply_dynamic_decay(dataset)

    # Step 3: Verify Signal Lineage (DSSLV)
    dataset = verify_signal_lineage(dataset)

    print(Fore.CYAN + "\n============= DeepSpace CyberShield AI =============\n")

    # Assign Trust Level based on Dynamic Trust
    dataset["trust_level"] = dataset["dynamic_trust"].apply(print_status)

    # Display Results
    print(
        dataset[
            [
                "source",
                "relay",
                "status",
                "trust_score",
                "dynamic_trust",
                "lineage_status",
                "lineage_score",
                "trust_level",
                "reason"
            ]
        ]
    )

    print(Fore.GREEN + "\nAnalysis Completed Successfully!")
    print(Style.RESET_ALL)


if __name__ == "__main__":
    main()