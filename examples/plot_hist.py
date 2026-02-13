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

L7_MAP = {
    0: "Other",
    1: "HTTP",
    2: "TLS",
    3: "QUIC",
}

# --------------------------
# Load CSV (value,count)
# --------------------------
def load_hist(csv_path):
    data = []
    with open(csv_path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            data.append((int(row["value"]), int(row["count"])))
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

    ymax = max(values) * 1.1 if values else 1
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
            (60, 120, "60–120s"),
            (120, 300, "120–300s"),
            (300, None, "300s+"),
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
            (100_000, 1_000_000, "100kB–1MB"),
            (1_000_000, None, "1MB+"),
        ]),
        "Flow Volume",
        "Bytes transferred",
        out / "volume.png"
    )

    # ---------- Packet Count ----------
    packets = load_hist(base / "packet_count.csv")
    plot_bars(
        bucketize(packets, [
            (2, 10, "2–10"),
            (10, 100, "10–100"),
            (100, 1000, "100–1k"),
            (1000, 10000, "1k–10k"),
            (10000, None, "10k+"),
        ]),
        "Packet Count per Flow",
        "Packets",
        out / "packets.png"
    )

    # ---------- Throughput (Decode proto index properly) ----------
    throughput_encoded = load_hist(base / "throughput_bps.csv")

    tcp_data = []
    udp_data = []

    for value, count in throughput_encoded:
        value = int(value)

        proto_index = value % 2
        throughput = value // 2   # decode original bps

        if proto_index == 0:
            tcp_data.append((throughput, count))
        else:
            udp_data.append((throughput, count))

    throughput_buckets = [
        (0, 100_000, "<100 kbps"),
        (100_000, 1_000_000, "100 kbps–1 Mbps"),
        (1_000_000, 10_000_000, "1–10 Mbps"),
        (10_000_000, 50_000_000, "10–50 Mbps"),
        (50_000_000, 100_000_000, "50–100 Mbps"),
        (100_000_000, None, "100+ Mbps"),
    ]

    plot_bars(
        bucketize(tcp_data, throughput_buckets),
        "TCP Flow Throughput",
        "Throughput (bps)",
        out / "throughput_tcp.png"
    )

    plot_bars(
        bucketize(udp_data, throughput_buckets),
        "UDP Flow Throughput",
        "Throughput (bps)",
        out / "throughput_udp.png"
    )


    # ---------- Direction Dominance ----------
    dir_dom = load_hist(base / "directionality_dominance.csv")

    tcp_counts = {"Reverse": 0, "Forward": 0}
    udp_counts = {"Reverse": 0, "Forward": 0}

    for value, count in dir_dom:
        if value in (0,1):
            tcp_counts["Forward" if value==1 else "Reverse"] += count
        elif value in (2,3):
            udp_counts["Forward" if value==3 else "Reverse"] += count

    plot_bars(tcp_counts,
              "TCP Flow Direction Dominance",
              "Direction",
              out / "direction_tcp.png")

    plot_bars(udp_counts,
              "UDP Flow Direction Dominance",
              "Direction",
              out / "direction_udp.png")

    # ---------- Direction Ratio ----------
    dir_ratio = load_hist(base / "direction_ratio_percent.csv")

    tcp_ratio = []
    udp_ratio = []

    for value, count in dir_ratio:
        value = int(value)

        if value <= 100:
            tcp_ratio.append((value, count))
        else:
            udp_ratio.append((value - 101, count))

    ratio_buckets = [
        (0, 25, "0–25%"),
        (25, 45, "25–45%"),
        (45, 56, "45–55% (Balanced)"),
        (56, 75, "55–75%"),
        (75, 100, "75–100%"),
        (100, None, "100%"),
    ]

    plot_bars(
        bucketize(tcp_ratio, ratio_buckets),
        "TCP Forward Byte Ratio",
        "Forward %",
        out / "ratio_tcp.png"
    )

    plot_bars(
        bucketize(udp_ratio, ratio_buckets),
        "UDP Forward Byte Ratio",
        "Forward %",
        out / "ratio_udp.png"
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

    counts = {}
    for value, count in large_port:
        label = port_class_map.get(value, "Other")
        counts[label] = counts.get(label, 0) + count

    plot_bars(counts,
              "Large Flows by Transport + Port Class",
              "Protocol/Port Class",
              out / "large_proto_port_class.png")

    # ---------- Large Flow L7 ----------
    l7 = load_hist(base / "large_flow_l7_protocol.csv")

    l7_counts = {}
    for value, count in l7:
        label = L7_MAP.get(value, "Other")
        l7_counts[label] = l7_counts.get(label, 0) + count

    plot_bars(l7_counts,
              "Large Flows by L7 Protocol",
              "Application Protocol",
              out / "large_flow_l7.png")

    # ---------- Heatmap ----------
    plot_2d_heatmap(
        load_2d_hist(base / "duration_vs_throughput_2d.csv"),
        "Flow Duration vs Throughput",
        out / "duration_vs_throughput_heatmap.png",
    )

    print("All plots written to ./plots/")
