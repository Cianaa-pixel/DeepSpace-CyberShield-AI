from colorama import Fore, Style, init
import pandas as pd

from data_loader import load_data
from ttl_evidence import calculate_ttl
from tt1_decay import apply_dynamic_decay
from dsslv import verify_signal_lineage
from ai_engine import AIEngine
from dashboard import launch_dashboard

# Initialize Colorama
init(autoreset=True)

# Pandas Settings
pd.set_option("display.max_columns", None)
pd.set_option("display.width", None)


def main():

    print(Fore.CYAN + "=" * 70)
    print(Fore.CYAN + "        DeepSpace CyberShield AI")
    print(Fore.CYAN + "=" * 70)

    # -------------------------------------------------
    # Load Dataset
    # -------------------------------------------------

    dataset = load_data("dataset/communication_logs.csv")

    if dataset is None:
        print(Fore.RED + "Failed to load dataset.")
        return

    # -------------------------------------------------
    # TTL Evidence
    # -------------------------------------------------

    dataset = calculate_ttl(dataset)

    # -------------------------------------------------
    # Dynamic TTL Trust
    # -------------------------------------------------

    dataset = apply_dynamic_decay(dataset)

    # -------------------------------------------------
    # DSSLV Verification
    # -------------------------------------------------

    dataset = verify_signal_lineage(dataset)

    # -------------------------------------------------
    # AI Engine
    # -------------------------------------------------

    ai = AIEngine()

    ai.dataset = dataset

    if not ai.load_model():

        ai.train_model()

        ai.save_model()

    dataset = ai.predict()

    ai.evaluate_model()

    # -------------------------------------------------
    # Launch Dashboard
    # -------------------------------------------------

    launch_dashboard(dataset)

    print(Fore.GREEN + "\nDashboard Closed Successfully.")
    print(Style.RESET_ALL)


if __name__ == "__main__":
    main()