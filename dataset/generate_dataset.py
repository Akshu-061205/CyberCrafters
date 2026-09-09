"""Generate a deterministic labelled IP-traffic dataset for local model training.

This is a development dataset, not a replacement for a curated source such as
CIC-IDS2017. It gives the project a reproducible training pipeline until an
approved real-world dataset is added.
"""

import csv
import random
from pathlib import Path

OUTPUT = Path(__file__).with_name("network_traffic.csv")
ROWS_PER_CLASS = 600
RANDOM_SEED = 20260909
FIELDS = ["packets", "bytes", "port", "protocol", "bytes_per_packet", "label"]


def clipped_normal(rng, mean, stddev, minimum, maximum):
    return round(max(minimum, min(maximum, rng.gauss(mean, stddev))), 2)


def make_row(rng, label):
    if label == "Normal":
        packets = int(clipped_normal(rng, 35, 18, 1, 100))
        bytes_per_packet = clipped_normal(rng, 700, 260, 80, 1500)
        port = rng.choice([53, 80, 443, 8080, 3306])
        protocol = rng.choices(["TCP", "UDP"], weights=[8, 2])[0]
    elif label == "Suspicious":
        packets = int(clipped_normal(rng, 210, 80, 40, 600))
        bytes_per_packet = clipped_normal(rng, 120, 80, 10, 420)
        port = rng.choice([22, 23, 80, 443, 445, 3389])
        protocol = rng.choices(["TCP", "UDP", "ICMP"], weights=[6, 2, 2])[0]
    else:
        packets = int(clipped_normal(rng, 1800, 700, 300, 5000))
        bytes_per_packet = clipped_normal(rng, 35, 22, 1, 130)
        port = rng.choice([22, 23, 445, 3389, 8080])
        protocol = rng.choices(["TCP", "UDP", "ICMP"], weights=[5, 1, 4])[0]

    return {
        "packets": packets,
        "bytes": round(packets * bytes_per_packet, 2),
        "port": port,
        "protocol": protocol,
        "bytes_per_packet": bytes_per_packet,
        "label": label,
    }


def main():
    rng = random.Random(RANDOM_SEED)
    rows = [make_row(rng, label) for label in ("Normal", "Suspicious", "Malicious") for _ in range(ROWS_PER_CLASS)]
    rng.shuffle(rows)
    with OUTPUT.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote {len(rows)} labelled traffic records to {OUTPUT}")


if __name__ == "__main__":
    main()
