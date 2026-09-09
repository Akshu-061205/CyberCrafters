"""Train a dependency-free Gaussian Naive Bayes traffic classifier."""

import csv
import json
import math
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "dataset" / "network_traffic.csv"
MODEL_DIR = Path(__file__).with_name("models")
MODEL_PATH = MODEL_DIR / "traffic_model.json"
NUMERIC_FEATURES = ["packets", "bytes", "port", "bytes_per_packet"]
CATEGORICAL_FEATURES = ["protocol"]
VARIANCE_FLOOR = 1e-6


def mean_and_variance(values):
    mean = sum(values) / len(values)
    variance = sum((value - mean) ** 2 for value in values) / len(values)
    return mean, max(variance, VARIANCE_FLOOR)


def main():
    if not DATASET.exists():
        raise SystemExit("Dataset missing. Run: python dataset/generate_dataset.py")

    with DATASET.open(newline="", encoding="utf-8") as file:
        rows = list(csv.DictReader(file))
    if not rows:
        raise SystemExit("Dataset is empty.")

    by_label = defaultdict(list)
    for row in rows:
        by_label[row["label"]].append(row)

    model = {
        "model_type": "gaussian_naive_bayes",
        "version": "1.0.0",
        "trained_rows": len(rows),
        "numeric_features": NUMERIC_FEATURES,
        "categorical_features": CATEGORICAL_FEATURES,
        "classes": {},
    }
    for label, label_rows in by_label.items():
        numerical = {
            feature: dict(zip(("mean", "variance"), mean_and_variance([float(row[feature]) for row in label_rows])))
            for feature in NUMERIC_FEATURES
        }
        categorical = {
            feature: dict(Counter(row[feature] for row in label_rows))
            for feature in CATEGORICAL_FEATURES
        }
        model["classes"][label] = {"prior": len(label_rows) / len(rows), "numeric": numerical, "categorical": categorical, "count": len(label_rows)}

    MODEL_DIR.mkdir(exist_ok=True)
    MODEL_PATH.write_text(json.dumps(model, indent=2), encoding="utf-8")
    print(f"Trained {model['model_type']} on {len(rows)} records; wrote {MODEL_PATH}")


if __name__ == "__main__":
    main()
