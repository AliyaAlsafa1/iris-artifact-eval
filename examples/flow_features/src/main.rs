use clap::Parser;
use iris_compiler::*;
use iris_core::{config::load_config, L4Pdu, Runtime};
use std::path::PathBuf;
use std::time::Instant;
use hdrhistogram::{Histogram, serialization::{V2Serializer, Serializer}};
use once_cell::sync::Lazy;
use std::{fs::File, sync::Mutex};

// GLOBALS
static H_DURATION: Lazy<Mutex<Histogram<u64>>> =
    Lazy::new(|| Mutex::new(Histogram::new_with_bounds(1, 600_000_000, 3).unwrap())); // up to 10min
static H_BYTES: Lazy<Mutex<Histogram<u64>>> =
    Lazy::new(|| Mutex::new(Histogram::new_with_bounds(1, 10_000_000_000, 3).unwrap())); // up to 10GB
static H_THROUGHPUT: Lazy<Mutex<Histogram<u64>>> =
    Lazy::new(|| Mutex::new(Histogram::new_with_bounds(1, 1_000_000_000_000, 3).unwrap())); // up to 1Tbps

// Command Args
#[derive(Parser, Debug)]
struct Args {
    #[clap(
        short,
        long,
        parse(from_os_str),
        value_name = "FILE",
        default_value = "./configs/offline.toml"
    )]
    config: PathBuf,
    
    // specify output directory for histogram files if desired
    #[clap(short = 'o', long, parse(from_os_str), default_value = "./hists")]
    out_dir: PathBuf,
}

/*
 * An Iris datatype is defined using #[datatype] syntax.
 * One of these structs will be initialized per connection
 * (i.e., you can use this struct to maintain per-connection state).
 * (Note: you could alternatively define this as a callback, especially
 * if you wanted to filter.)
 */
#[derive(Debug, Clone)]
#[datatype("level=L4Terminated")]
pub struct ConnVolume {
    start_ts: Instant,   // start time of connection
    end_ts: Instant,     // end time of connection
    packet_count: u64,   // total packets
    byte_count: u64,     // total bytes (currently payload bytes via length()?)
}

impl ConnVolume {
    /* PDU is a required argument. */
    pub fn new(pdu: &L4Pdu) -> Self {
        let ts = pdu.ts;                 // timestamp
        let bytes = pdu.mbuf.data_len(); // length of mbuf (bytes on the wire)

        ConnVolume {
            start_ts: ts,
            end_ts: ts,
            packet_count: 1,
            byte_count: bytes as u64,
        }
    }

    /* `level=L4InPayload` indicates that this should be invoked on every new packet */
    #[datatype_group("ConnVolume,level=L4InPayload")]
    pub fn new_packet(&mut self, pdu: &L4Pdu) {
        self.packet_count += 1;
        self.byte_count += pdu.mbuf.data_len() as u64;
        self.end_ts = pdu.ts;
    }
}

/*
 * An Iris callback is defined using #[callback] syntax with two inputs: "filter,level"
 * This will be invoked when the connection terminates.
 * Note: buggy when filter is empty; just do `tcp or udp` for now.
 */
#[callback("tcp or udp,level=L4Terminated")]
pub fn record_data(conn: &ConnVolume) {
    let duration = (conn.end_ts - conn.start_ts).as_millis() as u64;
    let duration = duration.max(1);

    let bytes = (conn.byte_count as u64).max(1);

    // bps = bytes * 8 / seconds = bytes*8*1000/ milliseconds
    let bps = bytes.saturating_mul(8).saturating_mul(1_000) / duration;
    let bps = bps.max(1);

    H_DURATION.lock().unwrap().record(duration).unwrap();
    H_BYTES.lock().unwrap().record(bytes).unwrap();
    H_THROUGHPUT.lock().unwrap().record(bps).unwrap();
}

/* Dump histogram to file */
fn dump_hist(path: PathBuf, h: &Histogram<u64>) {
    let mut f = File::create(path).unwrap();
    V2Serializer::new().serialize(h, &mut f).unwrap();
}

/*
 * Note: if you want to use the data types in the datatypes/ crate, you need to:
 * - Build `datatypes` with `skip_expand` feature disabled
 * - Add this macro to `main`: #[input_files("$IRIS_HOME/datatypes/data.txt")]
 */
#[iris_main]
fn main() {
    env_logger::init();
    let args = Args::parse();
    let config = load_config(&args.config);

    let out_dir = args.out_dir.clone();
    std::fs::create_dir_all(&out_dir).unwrap();

    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();

    // Dump histograms on graceful shutdown
    let dur_path = out_dir.join("duration_us.hdr");
    let vol_path = out_dir.join("volume_bytes.hdr");
    let thr_path = out_dir.join("throughput_bps.hdr");

    dump_hist(dur_path.clone(), &H_DURATION.lock().unwrap());
    dump_hist(vol_path.clone(), &H_BYTES.lock().unwrap());
    dump_hist(thr_path.clone(), &H_THROUGHPUT.lock().unwrap());

    println!("Histograms written to:");
    println!("  {}", dur_path.display());
    println!("  {}", vol_path.display());
    println!("  {}", thr_path.display());
}