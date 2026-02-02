#!/usr/bin/env python3

import csv
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from pathlib import Path

# --------------------------
# Load CSV (value,count)
# --------------------------
def load_hist(csv_path):
    data = []
    with open(csv_path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            data.append((float(row["value"]), int(row["count"])))
    return data

# --------------------------
# Bucket helper
# --------------------------
def bucketize(data, buckets):
    """
    buckets = [(low, high, label), ...]
    high=None means infinity
    """
    result = {label: 0 for _, _, label in buckets}
    for value, count in data:
        for low, high, label in buckets:
            if high is None:
                if value >= low:
                    result[label] += count
            elif low <= value < high:
                result[label] += count
    return result

# --------------------------
# Plot bar chart
# --------------------------
def plot_bars(bucket_counts, title, xlabel, filename):
    from matplotlib.ticker import MaxNLocator
    plt.gca().yaxis.set_major_locator(MaxNLocator(integer=True))

    labels = list(bucket_counts.keys())
    values = list(bucket_counts.values())

    plt.figure(figsize=(9,5))
    plt.bar(labels, values, edgecolor="black")
    plt.ylabel("Number of flows")
    plt.xlabel(xlabel)
    plt.title(title)
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(filename)
    plt.close()

# --------------------------
# Main
# --------------------------
if __name__ == "__main__":
    base = Path("hists")
    out = Path("plots")
    out.mkdir(exist_ok=True)

    # ---------- Duration ----------
    duration = load_hist(base / "duration_secs.csv")
    duration_buckets = [
        (10, 30, "10–30s"),
        (30, 60, "30–60s"),
        (60, 90, "60–90s"),
        (90, 120, "90–120s"),
        (120, None, "120s+"),
    ]
    plot_bars(
        bucketize(duration, duration_buckets),
        "Flow Duration",
        "Duration bucket",
        out / "duration.png"
    )

    # ---------- Volume ----------
    volume = load_hist(base / "volume_bytes.csv")
    volume_buckets = [
        (0, 1_000, "0–1kB"),
        (1_000, 10_000, "1k–10kB"),
        (10_000, 100_000, "10k–100kB"),
        (100_000, 500_000, "100k–500kB"),
        (500_000, 1_000_000, "500k–1MB+"),
    ]
    plot_bars(
        bucketize(volume, volume_buckets),
        "Flow Volume",
        "Bytes transferred",
        out / "volume.png"
    )

    # ---------- Packet Count ----------
    packets = load_hist(base / "packet_count.csv")
    packet_buckets = [
        (0, 50_000, "0–50k"),
        (50_000, 100_000, "50k–100k"),
        (100_000, 250_000, "100k–250k"),
        (250_000, 500_000, "250k–500k"),
        (500_000, 1_000_000, "500k–1M+"),
    ]
    plot_bars(
        bucketize(packets, packet_buckets),
        "Packet Count per Flow",
        "Packets",
        out / "packets.png"
    )

    # ---------- Directionality ----------
    # CSV currently stores ratio = max/min
    # ratio > 1 means asymmetric; direction was lost
    # ASSUMPTION: you also have fwd_bytes & rev_bytes counts
    # If ratio==1 → symmetric, ignore


    # ---------- Throughput ----------
    throughput = load_hist(base / "throughput_bps.csv")

    throughput_buckets = [
        (0, 1_000, "0–1 kbps"),
        (1_000, 10_000, "1–10 kbps"),
        (10_000, 100_000, "10–100 kbps"),
        (100_000, 1_000_000, "100 kbps–1 Mbps"),
        (1_000_000, 10_000_000, "1–10 Mbps"),
        (10_000_000, None, "10+ Mbps"),
    ]

    plot_bars(
        bucketize(throughput, throughput_buckets),
        "Flow Throughput",
        "Throughput (bits/sec)",
        out / "throughput.png"
    )



    print("All plots written to ./plots/")
