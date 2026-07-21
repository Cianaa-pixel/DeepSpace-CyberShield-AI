from data_loader import load_data
from ttl_evidence import calculate_ttl

def main():

    dataset = load_data("dataset/communication_logs.csv")

    if dataset is not None:

        dataset = calculate_ttl(dataset)

        print("\nTrust Scores\n")

        print(
            dataset[
                [
                    "source",
                    "relay",
                    "status",
                    "trust_score"
                ]
            ]
        )

if __name__ == "__main__":
    main()