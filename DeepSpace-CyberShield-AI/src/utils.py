"""
utils.py
--------
Small shared helpers used across the pipeline modules.
"""

import os


def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)


def safe_round(value, digits=3, default=0.0):
    try:
        return round(float(value), digits)
    except (TypeError, ValueError):
        return default
