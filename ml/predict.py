"""Read one JSON traffic record from stdin and print a model prediction as JSON."""

import json
import math
import sys
from pathlib import Path

MODEL_PATH = Path(__file__).with_name("models") / "traffic_model.json"


def log_gaussian(value, mean, variance):
    return -0.5 * math.log(2 * math.pi * variance) - ((value - mean) ** 2) / (2 * variance)


def main():
    if not MODEL_PATH.exists():
        raise SystemExit("Model missing. Run: python ml/train.py")
    traffic = json.load(sys.stdin)
    model = json.loads(MODEL_PATH.read_text(encoding="utf-8"))
    traffic["bytes_per_packet"] = traffic["bytes"] / traffic["packets"] if traffic["packets"] else 0

    log_scores = {}
    for label, details in model["classes"].items():
        score = math.log(details["prior"])
        for feature in model["numeric_features"]:
            score += log_gaussian(float(traffic[feature]), **details["numeric"][feature])
        for feature in model["categorical_features"]:
            counts = details["categorical"][feature]
            score += math.log((counts.get(str(traffic.get(feature, "UNKNOWN")).upper(), 0) + 1) / (details["count"] + len(counts) + 1))
        log_scores[label] = score

    maximum = max(log_scores.values())
    weights = {label: math.exp(score - maximum) for label, score in log_scores.items()}
    total = sum(weights.values())
    probabilities = {label: round(weight / total, 4) for label, weight in weights.items()}
    prediction = max(probabilities, key=probabilities.get)
    risk_scores = {"Normal": 10, "Suspicious": 55, "Malicious": 90}
    print(json.dumps({"prediction": prediction, "risk_score": risk_scores[prediction], "confidence": probabilities[prediction], "probabilities": probabilities, "model_version": model["version"]}))


if __name__ == "__main__":
    main()
