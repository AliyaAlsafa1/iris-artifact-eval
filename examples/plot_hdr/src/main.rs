// examples/plot_hdr/src/main.rs
//
// Histogram (bucketed counts):
//   X-axis: value (duration/bytes/bps)
//     - duration / bytes: log scale with log buckets
//     - throughput: linear scale with linear buckets
//   Y-axis: number of flows in each bucket

use hdrhistogram::{serialization::Deserializer, Histogram};
use plotters::prelude::*;
use std::{env, fs::File};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let in_path = env::args()
        .nth(1)
        .expect("usage: plot_hdr <file.hdr> [out.png]");
    let out_path = env::args().nth(2).unwrap_or_else(|| "hist.png".to_string());

    // Read HDRHistogram binary
    let mut f = File::open(&in_path)?;
    let h: Histogram<u64> = Deserializer::new().deserialize(&mut f)?;

    // Empty histogram case
    if h.len() == 0 {
        let root = BitMapBackend::new(&out_path, (1000, 600)).into_drawing_area();
        root.fill(&WHITE)?;
        let style: TextStyle = ("sans-serif", 30).into_text_style(&root).color(&BLACK);
        root.draw_text(&format!("Empty histogram: {}", in_path), &style, (40, 280))?;
        root.present()?;
        eprintln!("Wrote {}", out_path);
        return Ok(());
    }

    // Decide x-axis label + behavior based on filename
    let in_lower = in_path.to_lowercase();
    let is_throughput =
        in_lower.contains("throughput") || in_lower.contains("bps");

    let x_label = if in_lower.contains("duration") {
        "Duration (ms)"
    } else if in_lower.contains("volume") || in_lower.contains("bytes") {
        "Volume (bytes)"
    } else if is_throughput {
        "Throughput (bps)"
    } else {
        "Value"
    };

    // ---------------- Bucket construction ----------------
    let mut counts: Vec<((f64, f64), f64)> = Vec::new();

    if is_throughput {
        // -------- Linear buckets for throughput --------
        let min_v = h.min().max(0);
        let max_v = h.max().max(min_v + 1);

        let num_bins = 20;
        let width = ((max_v - min_v) as f64 / num_bins as f64).max(1.0);

        for i in 0..num_bins {
            let lo = min_v as f64 + i as f64 * width;
            let hi = if i == num_bins - 1 {
                max_v as f64
            } else {
                lo + width
            };

            let c = h.count_between(lo as u64, hi as u64) as f64;
            counts.push(((lo, hi), c));
        }
    } else {
        // -------- Log buckets (powers of 10) --------
        let max_v = h.max().max(1);
        let mut buckets: Vec<u64> = vec![1];

        while *buckets.last().unwrap() <= max_v {
            let next = buckets.last().unwrap().saturating_mul(10);
            if next == *buckets.last().unwrap() {
                break;
            }
            buckets.push(next);
        }

        if buckets.len() < 2 {
            buckets.push(10);
        }

        for w in buckets.windows(2) {
            let lo = w[0];
            let hi = w[1].saturating_sub(1).max(lo);
            let c = h.count_between(lo, hi) as f64;
            counts.push(((lo as f64, (hi + 1) as f64), c));
        }
    }

    // ---------------- Axis bounds ----------------
    let y_max = counts
        .iter()
        .map(|(_, c)| *c)
        .fold(0.0, f64::max)
        .max(1.0);

    let x_min = counts.first().unwrap().0 .0;
    let x_max = counts.last().unwrap().0 .1.max(x_min + 1.0);

    // ---------------- Plot ----------------
    let root = BitMapBackend::new(&out_path, (1100, 650)).into_drawing_area();
    root.fill(&WHITE)?;

    let mut chart = if is_throughput {
        ChartBuilder::on(&root)
            .margin(20)
            .caption(format!("Histogram: {}", in_path), ("sans-serif", 24))
            .x_label_area_size(60)
            .y_label_area_size(90)
            .build_cartesian_2d(x_min..x_max, 0f64..(y_max * 1.15))?
    } else {
        ChartBuilder::on(&root)
            .margin(20)
            .caption(format!("Histogram: {}", in_path), ("sans-serif", 24))
            .x_label_area_size(60)
            .y_label_area_size(90)
            .build_cartesian_2d((x_min..x_max).log_scale(), 0f64..(y_max * 1.15))?
    };

    chart
        .configure_mesh()
        .x_desc(x_label)
        .y_desc("Number of flows")
        .draw()?;

    // ---------------- Bars ----------------
    chart.draw_series(counts.iter().map(|((lo, hi), c)| {
        Rectangle::new([(*lo, 0.0), (*hi, *c)], BLUE.mix(0.6).filled())
    }))?;

    root.present()?;
    eprintln!("Wrote {}", out_path);
    Ok(())
}
