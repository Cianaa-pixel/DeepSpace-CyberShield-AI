"""
data_loader.py
--------------
Loads communication_logs.csv, generating a fresh synthetic dataset via
dataset_generator if the file doesn't exist yet.
"""

import os
import pandas as pd
from .dataset_generator import generate_dataset


def load_or_generate(path: str) -> pd.DataFrame:
    if os.path.exists(path):
        try:
            return pd.read_csv(path)
        except Exception:
            pass  # fall through to regeneration

    df = generate_dataset()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    df.to_csv(path, index=False)
    return df
