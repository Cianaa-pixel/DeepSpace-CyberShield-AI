from data_loader import load_data

def main():
    dataset = load_data("dataset/communication_logs.csv")

    if dataset is not None:
        print("\nDataset loaded successfully!")
    else:
        print("\nFailed to load dataset.")

if __name__ == "__main__":
    main()