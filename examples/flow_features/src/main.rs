use clap::Parser;
use iris_compiler::*;
use iris_core::{config::load_config, L4Pdu, Runtime};
use std::path::PathBuf;
use std::time::Instant;
use hdrhistogram::Histogram;
use once_cell::sync::Lazy;
use std::{fs::File, sync::Mutex};
use std::io::{BufWriter, Write};
use std::collections::HashMap;
use iris_core::protocols::stream::SessionProto;

// GLOBAL CONSTANTS
const LARGE_FLOW_MIN_DURATION_SECS: u64 = 120;
const LARGE_FLOW_MIN_THROUGHPUT_BPS: u64 = 10_000; // 10_000_000 10 Mbps (tune as needed)

// GLOBAL HISTOGRAMS
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
static H_PROTOCOL: Lazy<Mutex<Histogram<u64>>> =
    Lazy::new(|| Mutex::new(Histogram::new(3).unwrap()));
static H_DST_PORT: Lazy<Mutex<Histogram<u64>>> =
    Lazy::new(|| Mutex::new(Histogram::new(3).unwrap()));
static H_LARGE_FLOW_L7: Lazy<Mutex<Histogram<u64>>> =
    Lazy::new(|| Mutex::new(Histogram::new(3).unwrap()));
static H_DIR_RATIO_PERCENT: Lazy<Mutex<Histogram<u64>>> =
    Lazy::new(|| Mutex::new(Histogram::new(3).unwrap()));
static H_LARGE_PROTO_PORT_CLASS: Lazy<Mutex<Histogram<u64>>> =
    Lazy::new(|| Mutex::new(Histogram::new(3).unwrap()));

// HEATMAP COUNTER
static H_DUR_THR_2D: Lazy<Mutex<HashMap<(u64, u64), u64>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

// COMMAND ARGS
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

    #[clap(short = 'o', long, parse(from_os_str), default_value = "./hists")]
    out_dir: PathBuf,
}

// HEATMAP BUCKET HELPERS
fn duration_bucket_secs(d: u64) -> u64 {
    match d {
        10..=29 => 10,
        30..=59 => 30,
        60..=119 => 60,
        120..=299 => 120,
        300..=599 => 300,
        600..=1799 => 600,
        _ => 1800,
    }
}

fn throughput_bucket_bps(bps: u64) -> u64 {
    match bps {
        1_000..=9_999 => 1_000,
        10_000..=99_999 => 10_000,
        100_000..=999_999 => 100_000,
        1_000_000..=9_999_999 => 1_000_000,
        10_000_000..=99_999_999 => 10_000_000,
        _ => 100_000_000,
    }
}

// CONNECTION STATE
#[derive(Debug, Clone)]
#[datatype("level=L4Terminated,parsers=http&tls&quic")]
pub struct ConnVolume {
    start_ts: Instant,
    end_ts: Instant,
    packet_count: u64,
    byte_count: u64,
    fwd_bytes: u64,
    rev_bytes: u64,
    proto: usize,
    src_port: u16,
    dst_port: u16,

    l7_proto: Option<SessionProto>,
}

impl ConnVolume {
    pub fn new(pdu: &L4Pdu) -> Self {
        let ts = pdu.ts;
        let bytes = pdu.mbuf.data_len() as u64;

        let (fwd, rev) = if pdu.dir { (bytes, 0) } else { (0, bytes) };

        ConnVolume {
            start_ts: ts,
            end_ts: ts,
            packet_count: 1,
            byte_count: bytes,
            fwd_bytes: fwd,
            rev_bytes: rev,
            proto: pdu.ctxt.proto,
            src_port: pdu.ctxt.src.port(),
            dst_port: pdu.ctxt.dst.port(),

            l7_proto: None,
        }
    }

    #[datatype_group("ConnVolume,level=L4InPayload")]
    pub fn new_packet(&mut self, pdu: &L4Pdu) {
        let bytes = pdu.mbuf.data_len() as u64;
        self.packet_count += 1;
        self.byte_count += bytes;
        self.end_ts = pdu.ts;

        if pdu.dir {
            self.fwd_bytes += bytes;
        } else {
            self.rev_bytes += bytes;
        }
    }

    #[datatype_group("ConnVolume,level=L7OnDisc")]
    pub fn proto_id(&mut self, proto: &SessionProto) {
        if self.l7_proto.is_none() {
            self.l7_proto = Some(proto.clone());
        }
    }
}

// UPDATING COUNTERS
#[callback("tcp or udp,level=L4Terminated")]
pub fn record_data(conn: &ConnVolume) {
    if conn.packet_count <= 1 {
        return;
    }

    let duration_secs = (conn.end_ts - conn.start_ts).as_secs().max(1);
    let bytes = conn.byte_count.max(1);
    let packets = conn.packet_count;

    H_BYTES.lock().unwrap().record(bytes).unwrap();
    H_PACKETS.lock().unwrap().record(packets).unwrap();

    let dir = if conn.fwd_bytes >= conn.rev_bytes { 1 } else { 0 };
    H_DIR_DOMINANCE.lock().unwrap().record(dir).unwrap();

    // Direction ratio analysis
    let total_bytes = conn.fwd_bytes + conn.rev_bytes;

    if total_bytes > 0 {
        let forward_ratio_percent =
            (conn.fwd_bytes * 100) / total_bytes;

        H_DIR_RATIO_PERCENT
            .lock()
            .unwrap()
            .record(forward_ratio_percent)
            .unwrap();
    }

    H_PROTOCOL.lock().unwrap().record(conn.proto as u64).unwrap();
    H_DST_PORT.lock().unwrap().record(conn.dst_port as u64).unwrap();

    let throughput_bps = bytes.saturating_mul(8) / duration_secs;

    // Initial flow inspection logic
    if duration_secs >= 10 {
        H_DURATION.lock().unwrap().record(duration_secs).unwrap();
        H_THROUGHPUT
            .lock()
            .unwrap()
            .record(throughput_bps.max(1))
            .unwrap();

        let d_bucket = duration_bucket_secs(duration_secs);
        let t_bucket = throughput_bucket_bps(throughput_bps);

        let mut map = H_DUR_THR_2D.lock().unwrap();
        *map.entry((d_bucket, t_bucket)).or_insert(0) += 1;
    }

    // Looking for large flows with high throughput
    if duration_secs >= LARGE_FLOW_MIN_DURATION_SECS
        && throughput_bps >= LARGE_FLOW_MIN_THROUGHPUT_BPS
    {
        // --- Transport + Port Class (for LARGE flows only) ---

        // Check which ports have larger flows, separated by TCP / UDP (characterizing protocol/port of large flows)

        // Check both ports of UDP connection and see which is in assigned port space
        // if udp { if ft.dst < 1024 record, else if ft.src < 1024 record // well known
        //  else if ft.dst < 41952, else if ft.src < 41592 record // assigned
        // else record dst // ephemeral}

        let port_class = match conn.proto {
            6 => { // TCP
                let port = conn.dst_port;
                if port < 1024 {
                    0 // well-known
                } else if port < 49152 {
                    1 // registered
                } else {
                    2 // ephemeral
                }
            }
            17 => { // UDP
                let src = conn.src_port;
                let dst = conn.dst_port;

                // Prefer well-known
                if src < 1024 || dst < 1024 {
                    3 // UDP well-known
                }
                // Then registered
                else if src < 49152 || dst < 49152 {
                    4 // UDP registered
                }
                // Else ephemeral
                else {
                    5 // UDP ephemeral
                }
            }
            _ => return, // ignore non-TCP/UDP
        };

        H_LARGE_PROTO_PORT_CLASS
            .lock()
            .unwrap()
            .record(port_class)
            .ok();

        let bucket = match &conn.l7_proto {
            Some(SessionProto::Http) => 1,
            Some(SessionProto::Tls) => 2,
            Some(SessionProto::Quic) => 3,
            _ => 0, // Unknown or other
        };

        H_LARGE_FLOW_L7.lock().unwrap().record(bucket).unwrap();
    }
}

// WRITE TO CSV
fn dump_hist(path: PathBuf, h: &Histogram<u64>) -> std::io::Result<()> {
    let f = File::create(path)?;
    let mut w = BufWriter::new(f);
    writeln!(w, "value,count")?;

    for v in h.iter_recorded() {
        writeln!(w, "{},{}", v.value_iterated_to(), v.count_at_value())?;
    }
    Ok(())
}

fn dump_2d_hist(
    path: PathBuf,
    map: &HashMap<(u64, u64), u64>,
) -> std::io::Result<()> {
    let f = File::create(path)?;
    let mut w = BufWriter::new(f);

    writeln!(w, "duration_bucket_secs,throughput_bucket_bps,count")?;
    for ((d, t), c) in map {
        writeln!(w, "{},{},{}", d, t, c)?;
    }
    Ok(())
}

// MAIN
#[iris_main]
fn main() {
    env_logger::init();
    let args = Args::parse();
    let config = load_config(&args.config);

    let out_dir = args.out_dir.clone();
    std::fs::create_dir_all(&out_dir).unwrap();

    let mut runtime: Runtime<SubscribedWrapper> =
        Runtime::new(config, filter).unwrap();
    runtime.run();

    dump_hist(out_dir.join("duration_secs.csv"), &H_DURATION.lock().unwrap()).unwrap();
    dump_hist(out_dir.join("volume_bytes.csv"), &H_BYTES.lock().unwrap()).unwrap();
    dump_hist(out_dir.join("throughput_bps.csv"), &H_THROUGHPUT.lock().unwrap()).unwrap();
    dump_hist(out_dir.join("packet_count.csv"), &H_PACKETS.lock().unwrap()).unwrap();
    dump_hist(out_dir.join("directionality_dominance.csv"), &H_DIR_DOMINANCE.lock().unwrap()).unwrap();
    dump_hist(out_dir.join("protocol.csv"), &H_PROTOCOL.lock().unwrap()).unwrap();
    dump_hist(out_dir.join("dst_port.csv"), &H_DST_PORT.lock().unwrap()).unwrap();
    dump_hist(out_dir.join("direction_ratio_percent.csv"), &H_DIR_RATIO_PERCENT.lock().unwrap()).unwrap();
    dump_hist(out_dir.join("large_proto_port_class.csv"), &H_LARGE_PROTO_PORT_CLASS.lock().unwrap()).unwrap();

    dump_hist(
        out_dir.join("large_flow_l7_protocol.csv"),
        &H_LARGE_FLOW_L7.lock().unwrap(),
    ).unwrap();

    dump_2d_hist(
        out_dir.join("duration_vs_throughput_2d.csv"),
        &H_DUR_THR_2D.lock().unwrap(),
    )
    .unwrap();

    println!("Histograms written to {}", out_dir.display());
}
