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
        fieldnames = reader.fieldnames

        key1 = fieldnames[0]
        key2 = fieldnames[1]

        for row in reader:
            rows.append((
                int(row[key1]),
                int(row[key2]),
                int(row["count"]),
            ))
    return rows

# --------------------------
# Load SNI histogram CSV (domain,count)
# --------------------------
def load_sni(csv_path):
    data = {}
    with open(csv_path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            domain = row.get("domain", "").strip()
            count_str = row.get("count", "").strip()

            # Skip invalid rows
            if not domain or not count_str:
                continue

            try:
                data[domain] = int(count_str)
            except ValueError:
                continue

    return data

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
    if not rows:
        print(f"[WARN] No data for heatmap: {filename}")
        return

    dur_buckets = sorted(set(r[0] for r in rows))
    thr_buckets = sorted(set(r[1] for r in rows))

    if len(dur_buckets) == 0 or len(thr_buckets) == 0:
        print(f"[WARN] Empty bucket axes for heatmap: {filename}")
        return

    dur_index = {v: i for i, v in enumerate(dur_buckets)}
    thr_index = {v: i for i, v in enumerate(thr_buckets)}

    heatmap = np.zeros((len(dur_buckets), len(thr_buckets)))

    for d, t, c in rows:
        heatmap[dur_index[d], thr_index[t]] += c

    # If everything is zero, skip log scale
    max_val = heatmap.max()

    plt.figure(figsize=(10, 6))

    if max_val <= 0:
        print(f"[WARN] Heatmap has only zero values: {filename}")
        im = plt.imshow(
            heatmap,
            origin="lower",
            aspect="auto",
        )
    else:
        im = plt.imshow(
            heatmap,
            origin="lower",
            aspect="auto",
            norm=colors.LogNorm(vmin=1, vmax=max_val),
        )

    plt.colorbar(im, label="Flow count (log scale)" if max_val > 0 else "Flow count")

    plt.xlabel("Throughput bucket (bps)")
    plt.ylabel("Duration bucket (seconds)")
    plt.title(title)

    if len(thr_buckets) > 1:
        plt.xticks(range(len(thr_buckets)), [f"{t:,}" for t in thr_buckets], rotation=45)
    else:
        plt.xticks([0], [f"{thr_buckets[0]:,}"])

    if len(dur_buckets) > 1:
        plt.yticks(range(len(dur_buckets)), [f"{d}s" for d in dur_buckets])
    else:
        plt.yticks([0], [f"{dur_buckets[0]}s"])

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

    # ---------- Protocol ----------
    protocol = load_hist(base / "protocol.csv")

    proto_counts = {}
    for value, count in protocol:
        label = PROTO_MAP.get(value, f"Proto {value}")
        proto_counts[label] = proto_counts.get(label, 0) + count

    plot_bars(proto_counts,
            "Transport Protocol Distribution",
            "Protocol",
            out / "protocol.png")

    # ---------- Destination Port Distribution ----------
    dst_ports = load_hist(base / "dst_port.csv")

    plot_bars(
        bucketize(dst_ports, [
            (0, 1024, "Well-Known (<1024)"),
            (1024, 49152, "Registered (1024–49151)"),
            (49152, None, "Ephemeral (49152+)"),
        ]),
        "Destination Port Classes",
        "Port Range",
        out / "dst_port_classes.png"
    )


    # ---------- Pure Direction Protocol ----------
    pure_proto = load_hist(base / "pure_direction_proto.csv")

    pure_map = {
        0: "TCP Forward Only",
        1: "TCP Reverse Only",
        2: "UDP Forward Only",
        3: "UDP Reverse Only",
    }

    counts = {}
    for value, count in pure_proto:
        label = pure_map.get(value, "Other")
        counts[label] = counts.get(label, 0) + count

    plot_bars(counts,
            "Purely Unidirectional Flows by Protocol",
            "Type",
            out / "pure_direction_proto.png")

    # ---------- Pure Direction Duration ----------
    pure_dur = load_hist(base / "pure_direction_duration.csv")

    plot_bars(
        bucketize(pure_dur, [
            (0, 10, "<10s"),
            (10, 60, "10–60s"),
            (60, 300, "1–5 min"),
            (300, None, "5min+"),
        ]),
        "Duration of Purely Unidirectional Flows",
        "Duration",
        out / "pure_direction_duration.png"
    )

    # ---------- Pure Direction Destination Port ----------
    pure_ports = load_hist(base / "pure_direction_dst_port.csv")

    plot_bars(
        bucketize(pure_ports, [
            (0, 1024, "Well-Known"),
            (1024, 49152, "Registered"),
            (49152, None, "Ephemeral"),
        ]),
        "Pure Direction Flows by Port Class",
        "Port Range",
        out / "pure_direction_ports.png"
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

    # ---------- HTTP Heatmap ----------
    plot_2d_heatmap(
        load_2d_hist(base / "duration_vs_throughput_http.csv"),
        "HTTP Duration vs Throughput",
        out / "heatmap_http.png",
    )

    # ---------- TLS Heatmap ----------
    plot_2d_heatmap(
        load_2d_hist(base / "duration_vs_throughput_tls.csv"),
        "TLS Duration vs Throughput",
        out / "heatmap_tls.png",
    )

    # ---------- QUIC Heatmap ----------
    plot_2d_heatmap(
        load_2d_hist(base / "duration_vs_throughput_quic.csv"),
        "QUIC Duration vs Throughput",
        out / "heatmap_quic.png",
    )

    # ---------- TLS SNI Buckets ----------
    sni_data = load_sni(base / "sni_buckets.csv")

    # Take top 15 domains
    top_sni = dict(sorted(sni_data.items(), key=lambda x: x[1], reverse=True)[:15])

    plot_bars(top_sni,
            "Top 15 TLS Root Domains (SNI)",
            "Domain",
            out / "top_sni_domains.png")
    
    # ---------- Long-Lived TLS SNI Buckets ----------
    sni_long = load_sni(base / "sni_long_lived.csv")

    top_sni_long = dict(
        sorted(sni_long.items(), key=lambda x: x[1], reverse=True)[:15]
    )

    plot_bars(
        top_sni_long,
        "Top 15 TLS Root Domains (Long-Lived Flows)",
        "Domain",
        out / "top_sni_long_lived.png"
    )

    # ---------- Burstiness Heatmaps ----------

    plot_2d_heatmap(
        load_2d_hist(base / "burst_thr_lt5.csv"),
        "Burstiness vs Throughput (<5s Flows)",
        out / "burst_heatmap_lt5.png",
    )

    plot_2d_heatmap(
        load_2d_hist(base / "burst_thr_5_10.csv"),
        "Burstiness vs Throughput (5–10s Flows)",
        out / "burst_heatmap_5_10.png",
    )

    plot_2d_heatmap(
        load_2d_hist(base / "burst_thr_10_30.csv"),
        "Burstiness vs Throughput (10–30s Flows)",
        out / "burst_heatmap_10_30.png",
    )

    plot_2d_heatmap(
        load_2d_hist(base / "burst_thr_30_60.csv"),
        "Burstiness vs Throughput (30–60s Flows)",
        out / "burst_heatmap_30_60.png",
    )

    plot_2d_heatmap(
        load_2d_hist(base / "burst_thr_60p.csv"),
        "Burstiness vs Throughput (60s+ Flows)",
        out / "burst_heatmap_60p.png",
    )

    # ---------- Duration vs Port Heatmap ----------
    plot_2d_heatmap(
        load_2d_hist(base / "duration_vs_port.csv"),
        "Flow Duration vs Destination Port",
        out / "duration_vs_port_heatmap.png",
    )

    # ---------- Port Long vs Short Heatmap ----------
    plot_2d_heatmap(
        load_2d_hist(base / "port_long_vs_short.csv"),
        "Port vs Long/Short Flow Classification",
        out / "port_long_vs_short_heatmap.png",
    )

    # ---------- Port-Specific Duration Heatmaps ----------
    plot_2d_heatmap(
        load_2d_hist(base / "duration_vs_throughput_443.csv"),
        "Duration vs Throughput (Port 443)",
        out / "heatmap_443.png",
    )

    plot_2d_heatmap(
        load_2d_hist(base / "duration_vs_throughput_22.csv"),
        "Duration vs Throughput (Port 22)",
        out / "heatmap_22.png",
    )

    plot_2d_heatmap(
        load_2d_hist(base / "duration_vs_throughput_80.csv"),
        "Duration vs Throughput (Port 80)",
        out / "heatmap_80.png",
    )

    plot_2d_heatmap(
        load_2d_hist(base / "duration_vs_throughput_8801_8810.csv"),
        "Duration vs Throughput (Ports 8801–8810)",
        out / "heatmap_8801_8810.png",
    )

    plot_2d_heatmap(
        load_2d_hist(base / "duration_vs_throughput_3478_3481.csv"),
        "Duration vs Throughput (Ports 3478–3481)",
        out / "heatmap_3478_3481.png",
    )

    plot_2d_heatmap(
        load_2d_hist(base / "duration_vs_throughput_19302_19309.csv"),
        "Duration vs Throughput (Ports 19302–19309)",
        out / "heatmap_19302_19309.png",
    )

    plot_2d_heatmap(
        load_2d_hist(base / "duration_vs_throughput_well_known.csv"),
        "Duration vs Throughput (Well-Known Ports)",
        out / "heatmap_well_known.png",
    )

    plot_2d_heatmap(
        load_2d_hist(base / "duration_vs_throughput_registered.csv"),
        "Duration vs Throughput (Registered Ports)",
        out / "heatmap_registered.png",
    )

    plot_2d_heatmap(
        load_2d_hist(base / "duration_vs_throughput_ephemeral.csv"),
        "Duration vs Throughput (Ephemeral Ports)",
        out / "heatmap_ephemeral.png",
    )


    print("All plots written to ./plots/")
