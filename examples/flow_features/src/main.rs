use clap::Parser;
use iris_compiler::*;
use iris_core::{config::load_config, L4Pdu, Runtime};
use std::path::PathBuf;
use std::time::Instant;
use hdrhistogram::Histogram;
use once_cell::sync::Lazy;
use std::{fs::File, sync::Mutex};
use std::io::BufWriter;
use std::io::Write;

// GLOBALS
static H_DURATION: Lazy<Mutex<Histogram<u64>>> =
    Lazy::new(|| Mutex::new(Histogram::new(3).unwrap()));
static H_BYTES: Lazy<Mutex<Histogram<u64>>> =
    Lazy::new(|| Mutex::new(Histogram::new(3).unwrap()));
static H_THROUGHPUT: Lazy<Mutex<Histogram<u64>>> =
    Lazy::new(|| Mutex::new(Histogram::new(3).unwrap()));
static H_PACKETS: Lazy<Mutex<Histogram<u64>>> =
    Lazy::new(|| Mutex::new(Histogram::new(3).unwrap()));
static H_DIR_DOMINANCE: Lazy<Mutex<Histogram<u64>>> =
    Lazy::new(|| Mutex::new(Histogram::new(1).unwrap()));

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
    byte_count: u64,     // total bytes

    fwd_bytes: u64,
    rev_bytes: u64,
}

impl ConnVolume {
    /* PDU is a required argument. */
    pub fn new(pdu: &L4Pdu) -> Self {
        let ts = pdu.ts;                 // timestamp
        let bytes = pdu.mbuf.data_len() as u64; // length of mbuf (bytes on the wire)

        let (fwd, rev) = if pdu.dir {
            (bytes, 0)
        } else {
            (0, bytes)
        };

        ConnVolume {
            start_ts: ts,
            end_ts: ts,
            packet_count: 1,
            byte_count: bytes as u64, // might need to cast
            fwd_bytes: fwd,
            rev_bytes: rev,
        }
    }

    /* `level=L4InPayload` indicates that this should be invoked on every new packet */
    #[datatype_group("ConnVolume,level=L4InPayload")]
    pub fn new_packet(&mut self, pdu: &L4Pdu) {
        let bytes = pdu.mbuf.data_len() as u64; // might need to cast
        self.packet_count += 1;
        self.byte_count += bytes;
        self.end_ts = pdu.ts;

        if pdu.dir {
        self.fwd_bytes += bytes;
        } else {
            self.rev_bytes += bytes;
        }
    }
}

/*
 * An Iris callback is defined using #[callback] syntax with two inputs: "filter,level"
 * This will be invoked when the connection terminates.
 * Note: buggy when filter is empty; just do `tcp or udp` for now.
 */
#[callback("tcp or udp,level=L4Terminated")]
pub fn record_data(conn: &ConnVolume) {
    // Ignore single-packet flows
    if conn.packet_count <= 1 {
        return;
    }

    let duration_secs = (conn.end_ts - conn.start_ts).as_secs().max(1);
    let bytes = conn.byte_count.max(1);
    let packets = conn.packet_count;

    // Only record duration if >= 10s
    if duration_secs >= 10 {
        H_DURATION.lock().unwrap().record(duration_secs).unwrap();
    }

    H_BYTES.lock().unwrap().record(bytes).unwrap();
    H_PACKETS.lock().unwrap().record(packets).unwrap();

    // Directionality
    let dir = if conn.fwd_bytes >= conn.rev_bytes {
        1  // dominantly forward
    } else {
        0  // dominantly reverse
    };

    H_DIR_DOMINANCE.lock().unwrap().record(dir).unwrap();


    // Throughput only for long-lived flows (≥10s)
    if duration_secs >= 10 {
        let bps = bytes.saturating_mul(8) / duration_secs;
        H_THROUGHPUT.lock().unwrap().record(bps.max(1)).unwrap();
    }
}

/* Dump histogram to file */
fn dump_hist(path: PathBuf, h: &Histogram<u64>) -> std::io::Result<()> {
    let f = File::create(path)?;
    let mut w = BufWriter::new(f);
    writeln!(w, "value,count")?;

    for v in h.iter_recorded() {
        writeln!(w, "{},{}", v.value_iterated_to(), v.count_at_value())?;
    }

    Ok(())
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
    let dur_path = out_dir.join("duration_secs.csv");
    let vol_path = out_dir.join("volume_bytes.csv");
    let thr_path = out_dir.join("throughput_bps.csv");
    let pkt_path = out_dir.join("packet_count.csv");
    let dir_path = out_dir.join("directionality_dominance.csv");

    dump_hist(dur_path.clone(), &H_DURATION.lock().unwrap())
        .expect("Failed to write duration histogram");
    dump_hist(vol_path.clone(), &H_BYTES.lock().unwrap())
        .expect("Failed to write volume histogram");
    dump_hist(thr_path.clone(), &H_THROUGHPUT.lock().unwrap())
        .expect("Failed to write throughput histogram");
    dump_hist(pkt_path.clone(), &H_PACKETS.lock().unwrap())
        .expect("Failed to write packet count histogram");
    dump_hist(dir_path.clone(), &H_DIR_DOMINANCE.lock().unwrap())
        .expect("Failed to write directionality histogram");


    println!("Histograms written to:");
    println!("  {}", dur_path.display());
    println!("  {}", vol_path.display());
    println!("  {}", thr_path.display());
    println!("  {}", pkt_path.display());
    println!("  {}", dir_path.display());
}