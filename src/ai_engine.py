import pandas as pd
from sklearn.ensemble import IsolationForest


class AIEngine:

    def __init__(self):

        # Isolation Forest Model
        self.model = IsolationForest(
            contamination=0.20,
            random_state=42
        )

        # Features used for AI
        self.features = [
            "delay_ms",
            "signal_strength",
            "ttl",
            "ttl_evidence",
            "dsslv_score",
            "dynamic_ttl_trust",
            "trust_score",
            "packet_size"
        ]

        self.dataset = None

    # ---------------------------------------

    def load_dataset(self):

        self.dataset = pd.read_csv(
            "dataset/communication_logs.csv"
        )

        print("========================================")
        print("Dataset Loaded Successfully")
        print("========================================")
        print("Total Records :", len(self.dataset))
        print("Features Used :", len(self.features))
        print("========================================")

        return self.dataset

    # ---------------------------------------

    def prepare_features(self):

        X = self.dataset[self.features]

        return X