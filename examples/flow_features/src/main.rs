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
use iris_core::protocols::stream::{SessionProto, Session, SessionData};
use publicsuffix::List;
use publicsuffix::Psl;

static PSL: Lazy<List> = Lazy::new(List::new);

// GLOBAL CONSTANTS
const LARGE_FLOW_MIN_DURATION_SECS: u64 = 20;
const LARGE_FLOW_MIN_THROUGHPUT_BPS: u64 = 1_000_000; // 1 Mbps

// GLOBAL COUNTERS
static TOTAL_BYTES: Lazy<Mutex<u128>> = Lazy::new(|| Mutex::new(0));
static LONG_LIVED_BYTES: Lazy<Mutex<u128>> = Lazy::new(|| Mutex::new(0));

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

static H_PURE_DIR_PROTO: Lazy<Mutex<Histogram<u64>>> =
    Lazy::new(|| Mutex::new(Histogram::new(1).unwrap()));
static H_PURE_DIR_DST_PORT: Lazy<Mutex<Histogram<u64>>> =
    Lazy::new(|| Mutex::new(Histogram::new(3).unwrap()));
static H_PURE_DIR_DURATION: Lazy<Mutex<Histogram<u64>>> =
    Lazy::new(|| Mutex::new(Histogram::new(3).unwrap()));

static H_DUR_THR_HTTP: Lazy<Mutex<HashMap<(u64, u64), u64>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static H_DUR_THR_TLS: Lazy<Mutex<HashMap<(u64, u64), u64>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static H_DUR_THR_QUIC: Lazy<Mutex<HashMap<(u64, u64), u64>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

static H_SNI_BUCKETS: Lazy<Mutex<HashMap<String, u64>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static H_SNI_LONG_LIVED: Lazy<Mutex<HashMap<String, u64>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static H_DUR_PORT: Lazy<Mutex<HashMap<(u64, u16), u64>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static H_PORT_LONG_SHORT: Lazy<Mutex<HashMap<(u16, u8), u64>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

// BURSTINESS HEATMAPS:
static H_BURSTY_THR_LT5: Lazy<Mutex<HashMap<(u64,u64),u64>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

static H_BURSTY_THR_5_10: Lazy<Mutex<HashMap<(u64,u64),u64>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

static H_BURSTY_THR_10_30: Lazy<Mutex<HashMap<(u64,u64),u64>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

static H_BURSTY_THR_30_60: Lazy<Mutex<HashMap<(u64,u64),u64>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

static H_BURSTY_THR_60P: Lazy<Mutex<HashMap<(u64,u64),u64>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

// DURATION HEATMAPS:
static H_DUR_THR_2D: Lazy<Mutex<HashMap<(u64, u64), u64>>> =
    Lazy::new(|| Mutex::new(HashMap::new())); // general duration vs. throughput heatmap (all flows)

static H_DUR_THR_443: Lazy<Mutex<HashMap<(u64,u64),u64>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

static H_DUR_THR_22: Lazy<Mutex<HashMap<(u64,u64),u64>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

static H_DUR_THR_80: Lazy<Mutex<HashMap<(u64,u64),u64>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

static H_DUR_THR_8801_8810: Lazy<Mutex<HashMap<(u64,u64),u64>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

static H_DUR_THR_3478_3481: Lazy<Mutex<HashMap<(u64,u64),u64>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

static H_DUR_THR_19302_19309: Lazy<Mutex<HashMap<(u64,u64),u64>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

static H_DUR_THR_WELL_KNOWN: Lazy<Mutex<HashMap<(u64,u64),u64>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

static H_DUR_THR_REGISTERED: Lazy<Mutex<HashMap<(u64,u64),u64>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

static H_DUR_THR_EPHEMERAL: Lazy<Mutex<HashMap<(u64,u64),u64>>> =
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

// SNI NORMALIZATION HELPER
fn normalize_sni(host: &str) -> Option<String> {
    // Lowercase and trim trailing dot
    let host = host.to_lowercase();
    let host = host.trim_end_matches('.');

    // Convert to bytes for the publicsuffix API
    let host_bytes = host.as_bytes();

    // PSL.domain returns an Option<Domain<'_>>
    if let Some(domain) = PSL.domain(host_bytes) {
        // Convert `domain` (which displays as the registrable domain) to String
        return Some(
            String::from_utf8(domain.as_bytes().to_vec()).unwrap_or_default()
        );
    }

    None
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
    tls_sni: Option<String>,

    last_packet_ts: Option<Instant>,
    iat_sum_ns: u128,
    iat_sq_sum_ns: u128,
    iat_count: u64,
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
            tls_sni: None,

            last_packet_ts: Some(ts),
            iat_sum_ns: 0,
            iat_sq_sum_ns: 0,
            iat_count: 0,
        }
    }

    #[datatype_group("ConnVolume,level=L4InPayload")]
    pub fn new_packet(&mut self, pdu: &L4Pdu) {
        let bytes = pdu.mbuf.data_len() as u64;
        self.packet_count += 1;
        self.byte_count += bytes;

        // --- IAT computation (FIRST 2 SECONDS ONLY) ---
        if let Some(last_ts) = self.last_packet_ts {
            let delta = (pdu.ts - last_ts).as_nanos();

            let elapsed = (pdu.ts - self.start_ts).as_secs();

            if elapsed < 2 {
                self.iat_sum_ns += delta;
                self.iat_sq_sum_ns += delta * delta;
                self.iat_count += 1;
            }
        }

        self.last_packet_ts = Some(pdu.ts);
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

    #[datatype_group("ConnVolume,level=L7EndHdrs")]
    pub fn tls(&mut self, session: &Session) {
        if let SessionData::Tls(tls) = &session.data {
            let sni = tls.sni();
            if !sni.is_empty() {
                self.tls_sni = Some(sni.to_string());
            }
        }
    }
}

// UPDATING COUNTERS
#[callback("tcp or udp,level=L4Terminated")]
pub fn record_data(conn: &ConnVolume) {
    // Filter out single-packet flows
    if conn.packet_count <= 1 {
        return;
    }

    let duration_secs = (conn.end_ts - conn.start_ts).as_secs().max(1);
    let bytes = conn.byte_count.max(1);
    let packets = conn.packet_count;

    // Record basic volume and duration metrics
    H_BYTES.lock().unwrap().record(bytes).unwrap();
    H_PACKETS.lock().unwrap().record(packets).unwrap();

    // Compute burstiness (coefficient of variation)
    let burstiness = if conn.iat_count > 1 {
        let mean = conn.iat_sum_ns as f64 / conn.iat_count as f64;
        let variance =
            (conn.iat_sq_sum_ns as f64 / conn.iat_count as f64)
            - (mean * mean);

        if variance > 0.0 && mean > 0.0 {
            variance.sqrt() / mean
        } else {
            0.0
        }
    } else {
        0.0
    };

    // Compute throughput (bps)
    let throughput = (bytes * 8) / duration_secs;

    // Bucket throughput (example: round to nearest 100 kbps)
    let thr_bucket = (throughput / 100_000) * 100_000;

    // Bucket burstiness
    let burst_bucket = (burstiness * 100.0) as u64;

    // Select duration bucket
    let target_map = if duration_secs < 5 {
        &H_BURSTY_THR_LT5
    } else if duration_secs < 10 {
        &H_BURSTY_THR_5_10
    } else if duration_secs < 30 {
        &H_BURSTY_THR_10_30
    } else if duration_secs < 60 {
        &H_BURSTY_THR_30_60
    } else {
        &H_BURSTY_THR_60P
    };

    let mut guard = target_map.lock().unwrap();
    *guard.entry((burst_bucket, thr_bucket)).or_insert(0) += 1;

    // Grab SNI and bucket it by root domain
    if let Some(ref sni) = conn.tls_sni {
        if let Some(bucket) = normalize_sni(sni) {

            // ---- All flows ----
            {
                let mut map = H_SNI_BUCKETS.lock().unwrap();
                *map.entry(bucket.clone()).or_insert(0) += 1;
            }

            // ---- Long-lived flows only ----
            if duration_secs >= LARGE_FLOW_MIN_DURATION_SECS {
                let mut map = H_SNI_LONG_LIVED.lock().unwrap();
                *map.entry(bucket).or_insert(0) += 1;
            }
        }
    }

    // Direction dominance (encoded TCP/UDP in same histogram)
    // TCP: 0 = rev-heavy, 1 = fwd-heavy 
    // UDP: 2 = rev-heavy, 3 = fwd-heavy

    let dir = if conn.fwd_bytes >= conn.rev_bytes { 1 } else { 0 };

    let encoded_dir = match conn.proto {
        6 => dir,         // TCP
        17 => dir + 2,    // UDP
        _ => return,
    };

    H_DIR_DOMINANCE
        .lock()
        .unwrap()
        .record(encoded_dir)
        .unwrap();


    // Direction ratio analysis
    let total_bytes = conn.fwd_bytes + conn.rev_bytes;
    // if ratio is 100%, grab port number, duration

    if total_bytes > 0 {
    let forward_ratio_percent =
        (conn.fwd_bytes * 100) / total_bytes;

        let ratio = forward_ratio_percent.min(100);

        // ---- 100% unidirectional tracking ----
        if ratio == 100 || ratio == 0 {
            let dir_flag = if ratio == 100 { 0 } else { 1 }; 
            // 0 = forward-only
            // 1 = reverse-only

            let proto_flag = match conn.proto {
                6 => 0,   // TCP
                17 => 2,  // UDP
                _ => return,
            };

            let encoded = proto_flag + dir_flag;

            H_PURE_DIR_PROTO
                .lock()
                .unwrap()
                .record(encoded)
                .unwrap();

            H_PURE_DIR_DST_PORT
                .lock()
                .unwrap()
                .record(conn.dst_port as u64)
                .unwrap();

            H_PURE_DIR_DURATION
                .lock()
                .unwrap()
                .record(duration_secs)
                .unwrap();
        }

        // TCP: 0–100
        // UDP: 101–201
        let encoded_ratio = match conn.proto {
            6 => ratio,
            17 => ratio + 101,
            _ => return,
        };

        H_DIR_RATIO_PERCENT
            .lock()
            .unwrap()
            .record(encoded_ratio)
            .unwrap();
    }

    // Basic protocol and dst port recording
    H_PROTOCOL.lock().unwrap().record(conn.proto as u64).unwrap();
    H_DST_PORT.lock().unwrap().record(conn.dst_port as u64).unwrap();

    let throughput_bps = bytes.saturating_mul(8) / duration_secs;

    // Initial flow inspection logic
    if duration_secs >= 10 {
        H_DURATION.lock().unwrap().record(duration_secs).unwrap();

        let proto_index = match conn.proto {
            6 => 0,
            17 => 1,
            _ => return,
        };

        let encoded_throughput =
            throughput_bps.saturating_mul(2) + proto_index;

        H_THROUGHPUT
            .lock()
            .unwrap()
            .record(encoded_throughput.max(1))
            .unwrap();

        let d_bucket = duration_bucket_secs(duration_secs);
        let t_bucket = throughput_bucket_bps(throughput_bps);

        // ---- Port CLASS Duration vs Throughput Heatmaps ----

        let (well, registered, ephemeral) = if conn.proto == 6 {
            // TCP
            if conn.dst_port < 1024 {
                (true, false, false)
            } else if conn.dst_port < 49152 {
                (false, true, false)
            } else {
                (false, false, true)
            }
        } else if conn.proto == 17 {
            // UDP (consider either src or dst)
            if conn.src_port < 1024 || conn.dst_port < 1024 {
                (true, false, false)
            } else if conn.src_port < 49152 || conn.dst_port < 49152 {
                (false, true, false)
            } else {
                (false, false, true)
            }
        } else {
            (false, false, false)
        };

        if well {
            let mut map = H_DUR_THR_WELL_KNOWN.lock().unwrap();
            *map.entry((d_bucket, t_bucket)).or_insert(0) += 1;
        }

        if registered {
            let mut map = H_DUR_THR_REGISTERED.lock().unwrap();
            *map.entry((d_bucket, t_bucket)).or_insert(0) += 1;
        }

        if ephemeral {
            let mut map = H_DUR_THR_EPHEMERAL.lock().unwrap();
            *map.entry((d_bucket, t_bucket)).or_insert(0) += 1;
        }
    
        // ---- Port-Specific Duration vs Throughput Heatmaps ----

        match conn.dst_port {
            443 => {
                let mut map = H_DUR_THR_443.lock().unwrap();
                *map.entry((d_bucket, t_bucket)).or_insert(0) += 1;
            }
            22 => {
                let mut map = H_DUR_THR_22.lock().unwrap();
                *map.entry((d_bucket, t_bucket)).or_insert(0) += 1;
            }
            80 => {
                let mut map = H_DUR_THR_80.lock().unwrap();
                *map.entry((d_bucket, t_bucket)).or_insert(0) += 1;
            }
            8801..=8810 => {
                let mut map = H_DUR_THR_8801_8810.lock().unwrap();
                *map.entry((d_bucket, t_bucket)).or_insert(0) += 1;
            }
            3478..=3481 => {
                let mut map = H_DUR_THR_3478_3481.lock().unwrap();
                *map.entry((d_bucket, t_bucket)).or_insert(0) += 1;
            }
            19302..=19309 => {
                let mut map = H_DUR_THR_19302_19309.lock().unwrap();
                *map.entry((d_bucket, t_bucket)).or_insert(0) += 1;
            }
            _ => {}
        }

        // ---- Global heatmaps ----
        {
            let mut map = H_DUR_THR_2D.lock().unwrap();
            *map.entry((d_bucket, t_bucket)).or_insert(0) += 1;
        }

        {
            let mut map = H_DUR_PORT.lock().unwrap();
            *map.entry((d_bucket, conn.dst_port)).or_insert(0) += 1;
        }

        // ---- L7-specific heatmaps ----
        if let Some(proto) = &conn.l7_proto {
            match proto {
                SessionProto::Http => {
                    let mut map = H_DUR_THR_HTTP.lock().unwrap();
                    *map.entry((d_bucket, t_bucket)).or_insert(0) += 1;
                }
                SessionProto::Tls => {
                    let mut map = H_DUR_THR_TLS.lock().unwrap();
                    *map.entry((d_bucket, t_bucket)).or_insert(0) += 1;
                }
                SessionProto::Quic => {
                    let mut map = H_DUR_THR_QUIC.lock().unwrap();
                    *map.entry((d_bucket, t_bucket)).or_insert(0) += 1;
                }
                _ => {}
            }
        }
    }
    
    // Classify flows as long vs short based on duration threshold and track port distribution
    let class = if duration_secs >= LARGE_FLOW_MIN_DURATION_SECS { 1 } else { 0 };

    {
        let mut map = H_PORT_LONG_SHORT.lock().unwrap();
        *map.entry((conn.dst_port, class)).or_insert(0) += 1;
    }


    // Looking for large flows with high throughput
    if duration_secs >= LARGE_FLOW_MIN_DURATION_SECS
      && throughput_bps >= LARGE_FLOW_MIN_THROUGHPUT_BPS
    {
        // --- Transport + Port Class (for LARGE flows only) ---
        // For well known ports track actual port number << NOT IMPLEMENTED
        let port_class_opt = match conn.proto {
            6 => { // TCP
                let port = conn.dst_port;
                Some(if port < 1024 {
                    0 // TCP well-known
                } else if port < 49152 {
                    1 // TCP registered
                } else {
                    2 // TCP ephemeral
                })
            }
            17 => { // UDP
                let src = conn.src_port;
                let dst = conn.dst_port;

                Some(if src < 1024 || dst < 1024 {
                    3 // UDP well-known
                } else if src < 49152 || dst < 49152 {
                    4 // UDP registered
                } else {
                    5 // UDP ephemeral
                })
            }
            _ => None, // don't record port class, but don't exit
        };

        if let Some(port_class) = port_class_opt {
            H_LARGE_PROTO_PORT_CLASS
                .lock()
                .unwrap()
                .record(port_class)
                .unwrap();
        }

        if let Some(proto) = &conn.l7_proto {
            let bucket = match proto {
                SessionProto::Http => 1,
                SessionProto::Tls => 2,
                SessionProto::Quic => 3,
                _ => 0,
            };

        H_LARGE_FLOW_L7
            .lock()
            .unwrap()
            .record(bucket)
            .unwrap();
        }
    }

    // Update total and long-lived byte counters for percentage calculation
    {
        let mut total = TOTAL_BYTES.lock().unwrap();
        *total += bytes as u128;
    }

    if duration_secs >= LARGE_FLOW_MIN_DURATION_SECS {
        let mut long = LONG_LIVED_BYTES.lock().unwrap();
        *long += bytes as u128;
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

// WRITE 2D HISTOGRAM TO CSV
fn dump_2d_hist<K1: std::fmt::Display, K2: std::fmt::Display>(
    path: PathBuf,
    header1: &str,
    header2: &str,
    map: &HashMap<(K1, K2), u64>,
) -> std::io::Result<()> {
    let f = File::create(path)?;
    let mut w = BufWriter::new(f);

    writeln!(w, "{},{},count", header1, header2)?;
    for ((k1, k2), c) in map {
        writeln!(w, "{},{},{}", k1, k2, c)?;
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

    // Dumping histograms to CSV
    dump_hist(out_dir.join("duration_secs.csv"), &H_DURATION.lock().unwrap()).unwrap();
    dump_hist(out_dir.join("volume_bytes.csv"), &H_BYTES.lock().unwrap()).unwrap();
    dump_hist(out_dir.join("throughput_bps.csv"), &H_THROUGHPUT.lock().unwrap()).unwrap();
    dump_hist(out_dir.join("packet_count.csv"), &H_PACKETS.lock().unwrap()).unwrap();
    dump_hist(out_dir.join("directionality_dominance.csv"), &H_DIR_DOMINANCE.lock().unwrap()).unwrap();
    dump_hist(out_dir.join("protocol.csv"), &H_PROTOCOL.lock().unwrap()).unwrap();
    dump_hist(out_dir.join("dst_port.csv"), &H_DST_PORT.lock().unwrap()).unwrap();
    dump_hist(out_dir.join("direction_ratio_percent.csv"), &H_DIR_RATIO_PERCENT.lock().unwrap()).unwrap();
    dump_hist(out_dir.join("large_proto_port_class.csv"), &H_LARGE_PROTO_PORT_CLASS.lock().unwrap()).unwrap();
    dump_hist(out_dir.join("pure_direction_proto.csv"), &H_PURE_DIR_PROTO.lock().unwrap()).unwrap();
    dump_hist(out_dir.join("pure_direction_dst_port.csv"), &H_PURE_DIR_DST_PORT.lock().unwrap()).unwrap();
    dump_hist(out_dir.join("pure_direction_duration.csv"), &H_PURE_DIR_DURATION.lock().unwrap()).unwrap();
    dump_hist(out_dir.join("large_flow_l7_protocol.csv"), &H_LARGE_FLOW_L7.lock().unwrap()).unwrap();
    
    // Dumping burstiness histograms to CSV
    dump_2d_hist(
        out_dir.join("burst_thr_lt5.csv"),
        "burstiness_scaled",
        "throughput_bucket_bps",
        &H_BURSTY_THR_LT5.lock().unwrap(),
    ).unwrap();

    dump_2d_hist(
        out_dir.join("burst_thr_5_10.csv"),
        "burstiness_scaled",
        "throughput_bucket_bps",
        &H_BURSTY_THR_5_10.lock().unwrap(),
    ).unwrap();

    dump_2d_hist(
        out_dir.join("burst_thr_10_30.csv"),
        "burstiness_scaled",
        "throughput_bucket_bps",
        &H_BURSTY_THR_10_30.lock().unwrap(),
    ).unwrap();

    dump_2d_hist(
        out_dir.join("burst_thr_30_60.csv"),
        "burstiness_scaled",
        "throughput_bucket_bps",
        &H_BURSTY_THR_30_60.lock().unwrap(),
    ).unwrap();

    dump_2d_hist(
        out_dir.join("burst_thr_60p.csv"),
        "burstiness_scaled",
        "throughput_bucket_bps",
        &H_BURSTY_THR_60P.lock().unwrap(),
    ).unwrap();

    // Dumping 2D duration histograms to CSV
    dump_2d_hist(
        out_dir.join("duration_vs_throughput_2d.csv"),
        "duration_bucket_secs",
        "throughput_bucket_bps",
        &H_DUR_THR_2D.lock().unwrap(),
    ).unwrap();

    dump_2d_hist(
        out_dir.join("duration_vs_throughput_http.csv"),
        "duration_bucket_secs",
        "throughput_bucket_bps",
        &H_DUR_THR_HTTP.lock().unwrap(),
    ).unwrap();

    dump_2d_hist(
        out_dir.join("duration_vs_throughput_tls.csv"),
        "duration_bucket_secs",
        "throughput_bucket_bps",
        &H_DUR_THR_TLS.lock().unwrap(),
    ).unwrap();

    dump_2d_hist(
        out_dir.join("duration_vs_throughput_quic.csv"),
        "duration_bucket_secs",
        "throughput_bucket_bps",
        &H_DUR_THR_QUIC.lock().unwrap(),
    ).unwrap();

    dump_2d_hist(
        out_dir.join("duration_vs_port.csv"),
        "duration_bucket_secs",
        "dst_port",
        &H_DUR_PORT.lock().unwrap(),
    ).unwrap();

    dump_2d_hist(
        out_dir.join("port_long_vs_short.csv"),
        "dst_port",
        "class",
        &H_PORT_LONG_SHORT.lock().unwrap(),
    ).unwrap();

    dump_2d_hist(
        out_dir.join("duration_vs_throughput_443.csv"),
        "duration_bucket_secs",
        "throughput_bucket_bps",
        &H_DUR_THR_443.lock().unwrap(),
    ).unwrap();

    dump_2d_hist(
        out_dir.join("duration_vs_throughput_22.csv"),
        "duration_bucket_secs",
        "throughput_bucket_bps",
        &H_DUR_THR_22.lock().unwrap(),
    ).unwrap();

    dump_2d_hist(
        out_dir.join("duration_vs_throughput_80.csv"),
        "duration_bucket_secs",
        "throughput_bucket_bps",
        &H_DUR_THR_80.lock().unwrap(),
    ).unwrap();

    dump_2d_hist(
        out_dir.join("duration_vs_throughput_8801_8810.csv"),
        "duration_bucket_secs",
        "throughput_bucket_bps",
        &H_DUR_THR_8801_8810.lock().unwrap(),
    ).unwrap();

    dump_2d_hist(
        out_dir.join("duration_vs_throughput_3478_3481.csv"),
        "duration_bucket_secs",
        "throughput_bucket_bps",
        &H_DUR_THR_3478_3481.lock().unwrap(),
    ).unwrap();

    dump_2d_hist(
        out_dir.join("duration_vs_throughput_19302_19309.csv"),
        "duration_bucket_secs",
        "throughput_bucket_bps",
        &H_DUR_THR_19302_19309.lock().unwrap(),
    ).unwrap();

    dump_2d_hist(
        out_dir.join("duration_vs_throughput_well_known.csv"),
        "duration_bucket_secs",
        "throughput_bucket_bps",
        &H_DUR_THR_WELL_KNOWN.lock().unwrap(),
    ).unwrap();

    dump_2d_hist(
        out_dir.join("duration_vs_throughput_registered.csv"),
        "duration_bucket_secs",
        "throughput_bucket_bps",
        &H_DUR_THR_REGISTERED.lock().unwrap(),
    ).unwrap();

    dump_2d_hist(
        out_dir.join("duration_vs_throughput_ephemeral.csv"),
        "duration_bucket_secs",
        "throughput_bucket_bps",
        &H_DUR_THR_EPHEMERAL.lock().unwrap(),
    ).unwrap();

    // Dumping SNI bucket counts to CSV
    fn dump_sni_buckets(path: PathBuf) -> std::io::Result<()> {
        let map = H_SNI_BUCKETS.lock().unwrap();
        let mut w = std::io::BufWriter::new(std::fs::File::create(path)?);

        writeln!(w, "domain,count")?;

        for (domain, count) in map.iter() {
            writeln!(w, "{},{}", domain, count)?;
        }

        Ok(())
    }

    dump_sni_buckets(out_dir.join("sni_buckets.csv")).unwrap();

    fn dump_sni_long_lived(path: PathBuf) -> std::io::Result<()> {
        let map = H_SNI_LONG_LIVED.lock().unwrap();
        let mut w = std::io::BufWriter::new(std::fs::File::create(path)?);

        writeln!(w, "domain,count")?;

        for (domain, count) in map.iter() {
            writeln!(w, "{},{}", domain, count)?;
        }

        Ok(())
    }

    dump_sni_long_lived(out_dir.join("sni_long_lived.csv")).unwrap();

    // Finished
    println!("Histograms written to {}", out_dir.display());

    // Print percentage of bytes in long-lived flows
    let total = *TOTAL_BYTES.lock().unwrap();
    let long = *LONG_LIVED_BYTES.lock().unwrap();

    if total > 0 {
        let percent = (long as f64 / total as f64) * 100.0;
        println!("Long-lived flows account for {:.2}% of total bytes", percent);
    }
}
