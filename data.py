"""The data loader: reads a stored CSV and hands the engine plain arrays (SDD 5.1).

Only CSV files already in data/ are read. Nothing is downloaded while the app runs (R4).
"""

from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

DATA_DIR = Path(__file__).parent / "data"
SEED = 42
LABEL = "label"

# Never used as features. kev_listed feeds the label rule, so a model that could see it would
# copy it instead of learning (see data/schema.md). It stays in the CSV for the KEV readout.
HELD_OUT = {"kev_listed"}


def list_datasets():
    return sorted(p.stem for p in DATA_DIR.glob("*.csv"))


def read_csv(name):
    return pd.read_csv(DATA_DIR / f"{name}.csv")


def load_dataset(name):
    """Return X, y, and the feature names. Non-numeric columns (like cve_id) are ignored (R5)."""
    df = read_csv(name)
    numeric = df.select_dtypes(include=["number", "bool"]).columns
    features = [c for c in numeric if c != LABEL and c not in HELD_OUT]
    return df[features].to_numpy(dtype=float), df[LABEL].to_numpy(), features


def split_and_scale(X, y, test_size=0.2):
    """80/20 stratified split, then z-score using the training rows only (same as the notebook)."""
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=SEED, stratify=y)
    mu = X_train.mean(axis=0)
    sd = X_train.std(axis=0)
    sd[sd == 0] = 1.0                                  # a constant column would divide by zero
    return (X_train - mu) / sd, (X_test - mu) / sd, y_train, y_test
