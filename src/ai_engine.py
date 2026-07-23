import os
import joblib
import pandas as pd

from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix
)


class AIEngine:

    def __init__(self):

        self.model = IsolationForest(
            contamination=0.20,
            random_state=42
        )

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

    # ----------------------------------------

    def load_dataset(self):

        self.dataset = pd.read_csv(
            "dataset/communication_logs.csv"
        )

        print("\nDataset Loaded Successfully!")

        return self.dataset

    # ----------------------------------------

    def prepare_features(self):

        return self.dataset[self.features]

    # ----------------------------------------

    def train_model(self):

        X = self.prepare_features()

        self.model.fit(X)

        print("\nIsolation Forest Model Trained Successfully!")

    # ----------------------------------------

    def save_model(self):

        os.makedirs("models", exist_ok=True)

        joblib.dump(
            self.model,
            "models/isolation_forest.pkl"
        )

        print("AI Model Saved Successfully!")

    # ----------------------------------------

    def load_model(self):

        model_path = "models/isolation_forest.pkl"

        if os.path.exists(model_path):

            self.model = joblib.load(model_path)

            print("Existing AI Model Loaded!")

            return True

        return False

    # ----------------------------------------

    def predict(self):

        X = self.prepare_features()

        predictions = self.model.predict(X)

        self.dataset["AI_Prediction"] = predictions

        self.dataset["AI_Prediction"] = self.dataset[
            "AI_Prediction"
        ].replace({
            1: "Normal",
            -1: "Anomaly"
        })

        return self.dataset

    # ----------------------------------------

    def evaluate_model(self):

        actual = self.dataset["status"].apply(
            lambda x: "Normal" if x == "Normal" else "Anomaly"
        )

        predicted = self.dataset["AI_Prediction"]

        accuracy = accuracy_score(actual, predicted)

        precision = precision_score(
            actual,
            predicted,
            pos_label="Anomaly",
            zero_division=0
        )

        recall = recall_score(
            actual,
            predicted,
            pos_label="Anomaly",
            zero_division=0
        )

        f1 = f1_score(
            actual,
            predicted,
            pos_label="Anomaly",
            zero_division=0
        )

        print("\n======================================")
        print("        AI MODEL PERFORMANCE")
        print("======================================")
        print(f"Accuracy  : {accuracy*100:.2f}%")
        print(f"Precision : {precision*100:.2f}%")
        print(f"Recall    : {recall*100:.2f}%")
        print(f"F1 Score  : {f1*100:.2f}%")

        print("\nConfusion Matrix")

        print(confusion_matrix(actual, predicted))

        print("======================================")