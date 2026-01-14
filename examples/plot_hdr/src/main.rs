// examples/plot_hdr/src/main.rs
//
// Histogram (bucketed counts):
//   X-axis: value (duration/bytes/bps), log scale with 10^k tick labels
//   Y-axis: number of flows in each bucket

use hdrhistogram::{serialization::Deserializer, Histogram};
use plotters::prelude::*;
use std::{env, fs::File};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let in_path = env::args()
        .nth(1)
        .expect("usage: plot_hdr <file.hdr> [out.png]");
    let out_path = env::args().nth(2).unwrap_or_else(|| "hist.png".to_string());

    // Read HDRHistogram binary (written by Rust serializer)
    let mut f = File::open(&in_path)?;
    let h: Histogram<u64> = Deserializer::new().deserialize(&mut f)?;

    // If empty, still write an image with a message
    if h.len() == 0 {
        let root = BitMapBackend::new(&out_path, (1000, 600)).into_drawing_area();
        root.fill(&WHITE)?;
        let style: TextStyle = ("sans-serif", 30).into_text_style(&root).color(&BLACK);
        root.draw_text(&format!("Empty histogram: {}", in_path), &style, (40, 280))?;
        root.present()?;
        eprintln!("Wrote {}", out_path);
        return Ok(());
    }

    // --- Build log-spaced buckets (powers of 10) up to max ---
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

    // Count flows in each [lo, hi] bucket
    let mut counts: Vec<((f64, f64), f64)> = Vec::new();
    for w in buckets.windows(2) {
        let lo = w[0];
        let hi = w[1].saturating_sub(1).max(lo); // inclusive upper bound
        let c = h.count_between(lo, hi) as f64;
        counts.push(((lo as f64, (hi + 1) as f64), c)); // hi+1 => nicer bar width
    }

    let y_max = counts
        .iter()
        .map(|(_, c)| *c)
        .fold(0.0, f64::max)
        .max(1.0);

    // Plot
    let root = BitMapBackend::new(&out_path, (1100, 650)).into_drawing_area();
    root.fill(&WHITE)?;

    let x_min = counts.first().unwrap().0 .0.max(1.0);
    let x_max = counts.last().unwrap().0 .1.max(x_min + 1.0);

    // Decide x-axis label based on input filename (case-insensitive)
    let in_lower = in_path.to_lowercase();
    let x_label = if in_lower.contains("duration") {
        "Duration (ms, log scale)"
    } else if in_lower.contains("volume") || in_lower.contains("bytes") {
        "Volume (bytes, log scale)"
    } else if in_lower.contains("throughput") || in_lower.contains("bps") {
        "Throughput (bps, log scale)"
    } else {
        "Value (log scale)"
    };

    let mut chart = ChartBuilder::on(&root)
        .margin(20)
        .caption(format!("Histogram: {}", in_path), ("sans-serif", 24))
        .x_label_area_size(60)
        .y_label_area_size(90)
        .build_cartesian_2d((x_min..x_max).log_scale(), 0f64..(y_max * 1.15))?;

    chart
        .configure_mesh()
        .x_desc(x_label)
        .y_desc("Number of flows")
        // Format tick labels like 10^6 instead of 1000000
        .x_label_formatter(&|v| {
            if *v <= 0.0 {
                return "0".to_string();
            }
            let k = v.log10().round() as i32;
            // Only label clean powers of 10; otherwise leave blank to reduce clutter
            let pow10 = 10f64.powi(k);
            if (v / pow10 - 1.0).abs() < 1e-9 {
                format!("10^{}", k)
            } else {
                "".to_string()
            }
        })
        .draw()?;

    // Draw bars
    chart.draw_series(counts.iter().map(|((lo, hi), c)| {
        Rectangle::new([(*lo, 0.0), (*hi, *c)], BLUE.mix(0.6).filled())
    }))?;

    root.present()?;
    eprintln!("Wrote {}", out_path);
    Ok(())
}

