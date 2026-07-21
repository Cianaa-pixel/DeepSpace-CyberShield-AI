from data_loader import load_data
from ttl_evidence import calculate_ttl
from tt1_decay import apply_dynamic_decay

def main():

    dataset = load_data("dataset/communication_logs.csv")

    if dataset is not None:

        dataset = calculate_ttl(dataset)

        dataset = apply_dynamic_decay(dataset)

        print("\n============== DeepSpace CyberShield AI ==============\n")

        print(
            dataset[
                [
                    "source",
                    "relay",
                    "status",
                    "trust_score",
                    "dynamic_trust",
                    "trust_level",
                    "reason"
                ]
            ]
        )

if __name__ == "__main__":
    main()