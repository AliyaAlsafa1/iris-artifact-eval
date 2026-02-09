#!/usr/bin/env python3

import csv
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.colors as colors
from pathlib import Path
import numpy as np
from matplotlib.ticker import MaxNLocator

PROTO_MAP = {
    6: "TCP",
    17: "UDP",
    1: "ICMP",
}


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
# Load labeled histogram
# --------------------------
def load_label_hist(csv_path, label_key):
    data = {}
    with open(csv_path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            label = row[label_key].upper()
            data[label] = data.get(label, 0) + int(row["count"])
    return data

# --------------------------
# Load 2D histogram CSV
# --------------------------
def load_2d_hist(csv_path):
    rows = []
    with open(csv_path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append((
                int(row["duration_bucket_secs"]),
                int(row["throughput_bucket_bps"]),
                int(row["count"]),
            ))
    return rows

# --------------------------
# Bucket helper
# --------------------------
def bucketize(data, buckets):
    result = {label: 0 for _, _, label in buckets}

    for value, count in data:
        for low, high, label in buckets:
            if high is None and value >= low:
                result[label] += count
                break
            elif high is not None and low <= value < high:
                result[label] += count
                break

    return result

# --------------------------
# Plot bar chart
# --------------------------
def plot_bars(bucket_counts, title, xlabel, filename):
    fig, ax = plt.subplots(figsize=(9,5))

    labels = list(bucket_counts.keys())
    values = list(bucket_counts.values())

    ax.bar(labels, values, edgecolor="black")
    ax.set_ylabel("Number of flows")
    ax.set_xlabel(xlabel)
    ax.set_title(title)

    ax.yaxis.set_major_locator(MaxNLocator(integer=True))

    if values:
        ymax = max(values) * 1.1
        ax.set_ylim(0, ymax)

    for i, v in enumerate(values):
        ax.text(i, v + ymax*0.01, str(v), ha="center", fontsize=8)

    ax.tick_params(axis="x", rotation=30)
    plt.setp(ax.get_xticklabels(), ha="right")

    fig.tight_layout()
    fig.savefig(filename)
    plt.close(fig)

# --------------------------
# Plot 2D heatmap
# --------------------------
def plot_2d_heatmap(rows, title, filename):
    dur_buckets = sorted(set(r[0] for r in rows))
    thr_buckets = sorted(set(r[1] for r in rows))

    dur_index = {v: i for i, v in enumerate(dur_buckets)}
    thr_index = {v: i for i, v in enumerate(thr_buckets)}

    heatmap = np.zeros((len(dur_buckets), len(thr_buckets)))

    for d, t, c in rows:
        heatmap[dur_index[d], thr_index[t]] += c

    plt.figure(figsize=(10, 6))
    im = plt.imshow(
        heatmap,
        origin="lower",
        aspect="auto",
        norm=colors.LogNorm(vmin=1),
    )

    plt.colorbar(im, label="Flow count (log scale)")
    plt.xlabel("Throughput bucket (bps)")
    plt.ylabel("Duration bucket (seconds)")
    plt.title(title)

    plt.xticks(range(len(thr_buckets)), [f"{t:,}" for t in thr_buckets], rotation=45)
    plt.yticks(range(len(dur_buckets)), [f"{d}s" for d in dur_buckets])

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
    plot_bars(
        bucketize(duration, [
            (10, 30, "10–30s"),
            (30, 60, "30–60s"),
            (60, 90, "60–90s"),
            (90, 120, "90–120s"),
            (120, None, "120s+"),
        ]),
        "Flow Duration",
        "Duration bucket",
        out / "duration.png"
    )

    # ---------- Volume ----------
    volume = load_hist(base / "volume_bytes.csv")
    plot_bars(
        bucketize(volume, [
            (0, 1_000, "0–1kB"),
            (1_000, 10_000, "1k–10kB"),
            (10_000, 100_000, "10k–100kB"),
            (100_000, 500_000, "100k–500kB"),
            (500_000, None, "500kB+"),
        ]),
        "Flow Volume",
        "Bytes transferred",
        out / "volume.png"
    )

    # ---------- Packets ----------
    packets = load_hist(base / "packet_count.csv")
    plot_bars(
        bucketize(packets, [
            # Change these measurements for granularity in the beginning and then more spread out for larger flows
            (2, 10, "2–10"),
            (10, 2_000, "10–2k"),
            (2_000, 5_000, "2k–5k"),
            (5_000, 20_000, "5k–20k"),
            (20_000, 50_000, "20k–50k"),
            (50_000, 100_000, "50k-100k"),
            (100_000, None, "100k+"),
            ]),
        "Packet Count per Flow",
        "Packets",
        out / "packets.png"
    )

    # ---------- Throughput ----------
    throughput = load_hist(base / "throughput_bps.csv")
    plot_bars(
        bucketize(throughput, [
            (0, 1_000, "0–1 kbps"),
            (1_000, 10_000, "1–10 kbps"),
            (10_000, 100_000, "10–100 kbps"),
            (100_000, 1_000_000, "100 kbps–1 Mbps"),
            (1_000_000, None, "1+ Mbps"),
        ]),
        "Flow Throughput",
        "Throughput (bps)",
        out / "throughput.png"
    )

    # ---------- Heatmap ----------
    plot_2d_heatmap(
        load_2d_hist(base / "duration_vs_throughput_2d.csv"),
        "Flow Duration vs Throughput",
        out / "duration_vs_throughput_heatmap.png",
    )

    # ---------- Ports (individual common ports) ----------
    ports = load_hist(base / "dst_port.csv")

    common_ports = {
        80: "HTTP (80)",
        443: "HTTPS (443)",
        22: "SSH (22)",
        53: "DNS (53)",
        25: "SMTP (25)",
    }

    port_counts = {label: 0 for label in common_ports.values()}
    port_counts.update({"Public (1024–49151)": 0, "Private (49152+)": 0})

    for port, count in ports:
        port = int(port)
        if port in common_ports:
            port_counts[common_ports[port]] += count
        elif 1024 <= port <= 49151:
            port_counts["Public (1024–49151)"] += count
        elif port >= 49152:
            port_counts["Private (49152+)"] += count

    plot_bars(
        port_counts,
        "Flow Distribution by Port",
        "Port category",
        out / "ports.png"
    )

    # ---------- Protocols ----------
    protocols = {}

    with open(base / "protocol.csv", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            proto_num = int(row["value"])
            count = int(row["count"])

            proto_name = PROTO_MAP.get(proto_num, "Other")
            protocols[proto_name] = protocols.get(proto_name, 0) + count

    plot_bars(
        protocols,
        "Flow Distribution by IP Protocol",
        "Protocol",
        out / "protocols.png"
    )

    # ---------- Direction Dominance ----------
    dir_dom = load_hist(base / "directionality_dominance.csv")

    dir_counts = {
        "Reverse Dominant": 0,
        "Forward Dominant": 0,
    }

    for value, count in dir_dom:
        if int(value) == 0:
            dir_counts["Reverse Dominant"] += count
        elif int(value) == 1:
            dir_counts["Forward Dominant"] += count

    plot_bars(
        dir_counts,
        "Flow Direction Dominance",
        "Dominant Direction",
        out / "direction_dominance.png"
    )

    # ---------- Direction Ratio ----------
    dir_ratio = load_hist(base / "direction_ratio_percent.csv")

    plot_bars(
        bucketize(dir_ratio, [
            (0, 25, "0–25%"),
            (25, 50, "25–50%"),
            (50, 75, "50–75%"),
            (75, 100, "75–100%"),
            (100, None, "100%"),
        ]),
        "Forward Byte Ratio per Flow",
        "Forward traffic percentage",
        out / "direction_ratio.png"
    )

    # ---------- Large Flow Port Class ----------
    large_port = load_hist(base / "large_proto_port_class.csv")

    port_class_map = {
        0: "TCP Well-Known",
        1: "TCP Registered",
        2: "TCP Ephemeral",
        3: "UDP Well-Known",
        4: "UDP Registered",
        5: "UDP Ephemeral",
    }

    port_class_counts = {}

    for value, count in large_port:
        label = port_class_map.get(int(value), "Other")
        port_class_counts[label] = port_class_counts.get(label, 0) + count

    plot_bars(
        port_class_counts,
        "Large Flows by Transport + Port Class",
        "Protocol/Port Class",
        out / "large_proto_port_class.png"
    )




    print("All plots written to ./plots/")
