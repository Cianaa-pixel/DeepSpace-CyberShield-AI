import pandas as pd

def load_data(file_path):
    try:
        data = pd.read_csv(file_path)

        print("===================================")
        print(" DeepSpace CyberShield AI")
        print(" Dataset Loaded Successfully")
        print("===================================")

        print("\nTotal Records :", len(data))
        print("\nColumns :")
        print(list(data.columns))

        print("\nFirst 5 Records:\n")
        print(data.head())

        return data

    except FileNotFoundError:
        print("Error: Dataset file not found.")
        return None

    except Exception as e:
        print("Error:", e)
        return None