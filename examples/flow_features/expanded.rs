Parsed datatype: ConnDuration
Caching input in memory
Parsed datatype function: update
Caching input in memory
Parsed datatype: PktCount
Caching input in memory
Parsed datatype function: update
Caching input in memory
Parsed datatype: ByteCount
Caching input in memory
Parsed datatype function: update
Caching input in memory
Parsed datatype: InterArrivals
Caching input in memory
Parsed datatype function: update
Caching input in memory
Parsed datatype: ConnHistory
Caching input in memory
Parsed datatype function: update
Caching input in memory
Parsed datatype: ConnRecord
Caching input in memory
Parsed datatype function: update
Caching input in memory
Parsed datatype: DnsTransaction
Caching input in memory
Parsed datatype function: from_session
Caching input in memory
Parsed datatype: HttpTransaction
Caching input in memory
Parsed datatype function: from_session
Caching input in memory
Parsed datatype: BidirPktStream
Caching input in memory
Parsed datatype function: update
Caching input in memory
Parsed datatype: OrigPktStream
Caching input in memory
Parsed datatype function: update
Caching input in memory
Parsed datatype: RespPktStream
Caching input in memory
Parsed datatype function: update
Caching input in memory
Parsed datatype: ZcFrame
Caching input in memory
Parsed datatype function: new
Caching input in memory
Parsed datatype: Payload
Caching input in memory
Parsed datatype function: new
Caching input in memory
Parsed datatype: QuicStream
Caching input in memory
Parsed datatype function: from_session
Caching input in memory
Parsed datatype: SshHandshake
Caching input in memory
Parsed datatype function: from_session
Caching input in memory
Parsed datatype: FiveTuple
Caching input in memory
Parsed datatype: AnonFiveTuple
Caching input in memory
Parsed datatype: ClearedFiveTuple
Caching input in memory
Parsed datatype: StartTime
Caching input in memory
Parsed datatype: EtherTCI
Caching input in memory
Parsed datatype: EthAddr
Caching input in memory
Parsed datatype: TlsHandshake
Caching input in memory
Parsed datatype function: from_session
Caching input in memory
Warning - clearing existing contents of file /home/aliya/iris-artifact-eval/datatypes/data.txt
GOT OUTPUT FILE NAME: /home/aliya/iris-artifact-eval/datatypes/data.txt
Parsed datatype: ConnVolume
Caching input in memory
Parsed datatype function: new_packet
Caching input in memory
Parsed datatype function: proto_id
Caching input in memory
Parsed callback: "record_data"
Caching input in memory
Done with macros - beginning code generation

Parsers: http, tls, quic

Tree Per-Packet:
`- ethernet (0)
   |- ipv4 (1)
   |  |- tcp (2)
   |  `- udp (3)
   `- ipv6 (4)
      |- tcp (5)
      `- udp (6)

Tree L4FirstPacket
,`- 0: ethernet
   |- 1: ipv4
   |  |- 2: tcp -- Actions: L4: Actions[Update, PassThrough, Track] (Until:  L7OnDisc: Actions[PassThrough], L4Terminated: Actions[Update, PassThrough, Track]) L7: Actions[Parse] (Until:  L7OnDisc: Actions[Parse], L4Terminated: Actions[Parse])
   |  `- 3: udp -- Actions: L4: Actions[Update, PassThrough, Track] (Until:  L7OnDisc: Actions[PassThrough], L4Terminated: Actions[Update, PassThrough, Track]) L7: Actions[Parse] (Until:  L7OnDisc: Actions[Parse], L4Terminated: Actions[Parse]) x
   `- 4: ipv6 x
      |- 5: tcp -- Actions: L4: Actions[Update, PassThrough, Track] (Until:  L7OnDisc: Actions[PassThrough], L4Terminated: Actions[Update, PassThrough, Track]) L7: Actions[Parse] (Until:  L7OnDisc: Actions[Parse], L4Terminated: Actions[Parse])
      `- 6: udp -- Actions: L4: Actions[Update, PassThrough, Track] (Until:  L7OnDisc: Actions[PassThrough], L4Terminated: Actions[Update, PassThrough, Track]) L7: Actions[Parse] (Until:  L7OnDisc: Actions[Parse], L4Terminated: Actions[Parse]) x

Tree L4InPayload(false)
,`- 0: ethernet
   |- 1: tcp -- Actions: L4: Actions[Update, Track] (Until:  L4Terminated: Actions[Update, Track]) L7: None
   |  `- 2: L7=Discovery -- Actions: L4: Actions[PassThrough] (Until:  L7OnDisc: Actions[PassThrough], L4Terminated: Actions[PassThrough]) L7: Actions[Parse] (Until:  L7OnDisc: Actions[Parse], L4Terminated: Actions[Parse])
   `- 3: udp -- Actions: L4: Actions[Update, Track] (Until:  L4Terminated: Actions[Update, Track]) L7: None x
      `- 4: L7=Discovery -- Actions: L4: Actions[PassThrough] (Until:  L7OnDisc: Actions[PassThrough], L4Terminated: Actions[PassThrough]) L7: Actions[Parse] (Until:  L7OnDisc: Actions[Parse], L4Terminated: Actions[Parse])

Tree L7OnDisc
,`- 0: ethernet
   |- 1: tcp -- Actions: L4: Actions[Update, Track] (Until:  L4Terminated: Actions[Update, Track]) L7: None
   `- 2: udp -- Actions: L4: Actions[Update, Track] (Until:  L4Terminated: Actions[Update, Track]) L7: None x

Tree L4Terminated
,`- 0: ethernet Invoke: ( record_data, )

#![feature(prelude_import)]
#[prelude_import]
use std::prelude::rust_2024::*;
#[macro_use]
extern crate std;
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
const LARGE_FLOW_MIN_DURATION_SECS: u64 = 120;
const LARGE_FLOW_MIN_THROUGHPUT_BPS: u64 = 10_000_000;
static H_DURATION: Lazy<Mutex<Histogram<u64>>> = Lazy::new(|| Mutex::new(
    Histogram::new(3).unwrap(),
));
static H_BYTES: Lazy<Mutex<Histogram<u64>>> = Lazy::new(|| Mutex::new(
    Histogram::new(3).unwrap(),
));
static H_THROUGHPUT: Lazy<Mutex<Histogram<u64>>> = Lazy::new(|| Mutex::new(
    Histogram::new(3).unwrap(),
));
static H_PACKETS: Lazy<Mutex<Histogram<u64>>> = Lazy::new(|| Mutex::new(
    Histogram::new(3).unwrap(),
));
static H_DIR_DOMINANCE: Lazy<Mutex<Histogram<u64>>> = Lazy::new(|| Mutex::new(
    Histogram::new(1).unwrap(),
));
static H_PROTOCOL: Lazy<Mutex<Histogram<u64>>> = Lazy::new(|| Mutex::new(
    Histogram::new(3).unwrap(),
));
static H_DST_PORT: Lazy<Mutex<Histogram<u64>>> = Lazy::new(|| Mutex::new(
    Histogram::new(3).unwrap(),
));
static H_LARGE_FLOW_L7: Lazy<Mutex<Histogram<u64>>> = Lazy::new(|| Mutex::new(
    Histogram::new(3).unwrap(),
));
static H_DIR_RATIO_PERCENT: Lazy<Mutex<Histogram<u64>>> = Lazy::new(|| Mutex::new(
    Histogram::new(3).unwrap(),
));
static H_LARGE_PROTO_PORT_CLASS: Lazy<Mutex<Histogram<u64>>> = Lazy::new(|| Mutex::new(
    Histogram::new(3).unwrap(),
));
static H_DUR_THR_2D: Lazy<Mutex<HashMap<(u64, u64), u64>>> = Lazy::new(|| Mutex::new(
    HashMap::new(),
));
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
impl clap::Parser for Args {}
#[allow(dead_code, unreachable_code, unused_variables, unused_braces)]
#[allow(
    clippy::style,
    clippy::complexity,
    clippy::pedantic,
    clippy::restriction,
    clippy::perf,
    clippy::deprecated,
    clippy::nursery,
    clippy::cargo,
    clippy::suspicious_else_formatting,
    clippy::almost_swapped,
)]
#[allow(deprecated)]
impl clap::CommandFactory for Args {
    fn into_app<'b>() -> clap::Command<'b> {
        let __clap_app = clap::Command::new("flow_features");
        <Self as clap::Args>::augment_args(__clap_app)
    }
    fn into_app_for_update<'b>() -> clap::Command<'b> {
        let __clap_app = clap::Command::new("flow_features");
        <Self as clap::Args>::augment_args_for_update(__clap_app)
    }
}
#[allow(dead_code, unreachable_code, unused_variables, unused_braces)]
#[allow(
    clippy::style,
    clippy::complexity,
    clippy::pedantic,
    clippy::restriction,
    clippy::perf,
    clippy::deprecated,
    clippy::nursery,
    clippy::cargo,
    clippy::suspicious_else_formatting,
    clippy::almost_swapped,
)]
impl clap::FromArgMatches for Args {
    fn from_arg_matches(
        __clap_arg_matches: &clap::ArgMatches,
    ) -> ::std::result::Result<Self, clap::Error> {
        Self::from_arg_matches_mut(&mut __clap_arg_matches.clone())
    }
    fn from_arg_matches_mut(
        __clap_arg_matches: &mut clap::ArgMatches,
    ) -> ::std::result::Result<Self, clap::Error> {
        #![allow(deprecated)]
        let v = Args {
            config: __clap_arg_matches
                .get_one::<::std::ffi::OsString>("config")
                .map(|s| ::std::ops::Deref::deref(s))
                .ok_or_else(|| clap::Error::raw(
                    clap::ErrorKind::MissingRequiredArgument,
                    ::alloc::__export::must_use({
                        ::alloc::fmt::format(
                            format_args!(
                                "The following required argument was not provided: {0}",
                                "config",
                            ),
                        )
                    }),
                ))
                .and_then(|s| ::std::result::Result::Ok::<
                    _,
                    clap::Error,
                >(::std::convert::From::from(s)))?,
            out_dir: __clap_arg_matches
                .get_one::<::std::ffi::OsString>("out-dir")
                .map(|s| ::std::ops::Deref::deref(s))
                .ok_or_else(|| clap::Error::raw(
                    clap::ErrorKind::MissingRequiredArgument,
                    ::alloc::__export::must_use({
                        ::alloc::fmt::format(
                            format_args!(
                                "The following required argument was not provided: {0}",
                                "out-dir",
                            ),
                        )
                    }),
                ))
                .and_then(|s| ::std::result::Result::Ok::<
                    _,
                    clap::Error,
                >(::std::convert::From::from(s)))?,
        };
        ::std::result::Result::Ok(v)
    }
    fn update_from_arg_matches(
        &mut self,
        __clap_arg_matches: &clap::ArgMatches,
    ) -> ::std::result::Result<(), clap::Error> {
        self.update_from_arg_matches_mut(&mut __clap_arg_matches.clone())
    }
    fn update_from_arg_matches_mut(
        &mut self,
        __clap_arg_matches: &mut clap::ArgMatches,
    ) -> ::std::result::Result<(), clap::Error> {
        #![allow(deprecated)]
        if __clap_arg_matches.contains_id("config") {
            #[allow(non_snake_case)]
            let config = &mut self.config;
            *config = __clap_arg_matches
                .get_one::<::std::ffi::OsString>("config")
                .map(|s| ::std::ops::Deref::deref(s))
                .ok_or_else(|| clap::Error::raw(
                    clap::ErrorKind::MissingRequiredArgument,
                    ::alloc::__export::must_use({
                        ::alloc::fmt::format(
                            format_args!(
                                "The following required argument was not provided: {0}",
                                "config",
                            ),
                        )
                    }),
                ))
                .and_then(|s| ::std::result::Result::Ok::<
                    _,
                    clap::Error,
                >(::std::convert::From::from(s)))?;
        }
        if __clap_arg_matches.contains_id("out-dir") {
            #[allow(non_snake_case)]
            let out_dir = &mut self.out_dir;
            *out_dir = __clap_arg_matches
                .get_one::<::std::ffi::OsString>("out-dir")
                .map(|s| ::std::ops::Deref::deref(s))
                .ok_or_else(|| clap::Error::raw(
                    clap::ErrorKind::MissingRequiredArgument,
                    ::alloc::__export::must_use({
                        ::alloc::fmt::format(
                            format_args!(
                                "The following required argument was not provided: {0}",
                                "out-dir",
                            ),
                        )
                    }),
                ))
                .and_then(|s| ::std::result::Result::Ok::<
                    _,
                    clap::Error,
                >(::std::convert::From::from(s)))?;
        }
        ::std::result::Result::Ok(())
    }
}
#[allow(dead_code, unreachable_code, unused_variables, unused_braces)]
#[allow(
    clippy::style,
    clippy::complexity,
    clippy::pedantic,
    clippy::restriction,
    clippy::perf,
    clippy::deprecated,
    clippy::nursery,
    clippy::cargo,
    clippy::suspicious_else_formatting,
    clippy::almost_swapped,
)]
impl clap::Args for Args {
    fn augment_args<'b>(__clap_app: clap::Command<'b>) -> clap::Command<'b> {
        {
            let __clap_app = __clap_app;
            let __clap_app = __clap_app
                .arg({
                    #[allow(deprecated)]
                    let arg = clap::Arg::new("config")
                        .takes_value(true)
                        .value_name("CONFIG")
                        .required(false && clap::ArgAction::StoreValue.takes_values())
                        .value_parser(clap::builder::ValueParser::os_string())
                        .action(clap::ArgAction::StoreValue);
                    let arg = arg
                        .short('c')
                        .long("config")
                        .value_name("FILE")
                        .default_value("./configs/offline.toml");
                    arg
                });
            let __clap_app = __clap_app
                .arg({
                    #[allow(deprecated)]
                    let arg = clap::Arg::new("out-dir")
                        .takes_value(true)
                        .value_name("OUT_DIR")
                        .required(false && clap::ArgAction::StoreValue.takes_values())
                        .value_parser(clap::builder::ValueParser::os_string())
                        .action(clap::ArgAction::StoreValue);
                    let arg = arg.short('o').long("out-dir").default_value("./hists");
                    arg
                });
            __clap_app
        }
    }
    fn augment_args_for_update<'b>(__clap_app: clap::Command<'b>) -> clap::Command<'b> {
        {
            let __clap_app = __clap_app;
            let __clap_app = __clap_app
                .arg({
                    #[allow(deprecated)]
                    let arg = clap::Arg::new("config")
                        .takes_value(true)
                        .value_name("CONFIG")
                        .required(false && clap::ArgAction::StoreValue.takes_values())
                        .value_parser(clap::builder::ValueParser::os_string())
                        .action(clap::ArgAction::StoreValue);
                    let arg = arg
                        .short('c')
                        .long("config")
                        .value_name("FILE")
                        .default_value("./configs/offline.toml");
                    arg
                });
            let __clap_app = __clap_app
                .arg({
                    #[allow(deprecated)]
                    let arg = clap::Arg::new("out-dir")
                        .takes_value(true)
                        .value_name("OUT_DIR")
                        .required(false && clap::ArgAction::StoreValue.takes_values())
                        .value_parser(clap::builder::ValueParser::os_string())
                        .action(clap::ArgAction::StoreValue);
                    let arg = arg.short('o').long("out-dir").default_value("./hists");
                    arg
                });
            __clap_app
        }
    }
}
#[automatically_derived]
impl ::core::fmt::Debug for Args {
    #[inline]
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        ::core::fmt::Formatter::debug_struct_field2_finish(
            f,
            "Args",
            "config",
            &self.config,
            "out_dir",
            &&self.out_dir,
        )
    }
}
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
#[automatically_derived]
impl ::core::fmt::Debug for ConnVolume {
    #[inline]
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        let names: &'static _ = &[
            "start_ts",
            "end_ts",
            "packet_count",
            "byte_count",
            "fwd_bytes",
            "rev_bytes",
            "proto",
            "src_port",
            "dst_port",
            "l7_proto",
        ];
        let values: &[&dyn ::core::fmt::Debug] = &[
            &self.start_ts,
            &self.end_ts,
            &self.packet_count,
            &self.byte_count,
            &self.fwd_bytes,
            &self.rev_bytes,
            &self.proto,
            &self.src_port,
            &self.dst_port,
            &&self.l7_proto,
        ];
        ::core::fmt::Formatter::debug_struct_fields_finish(
            f,
            "ConnVolume",
            names,
            values,
        )
    }
}
#[automatically_derived]
impl ::core::clone::Clone for ConnVolume {
    #[inline]
    fn clone(&self) -> ConnVolume {
        ConnVolume {
            start_ts: ::core::clone::Clone::clone(&self.start_ts),
            end_ts: ::core::clone::Clone::clone(&self.end_ts),
            packet_count: ::core::clone::Clone::clone(&self.packet_count),
            byte_count: ::core::clone::Clone::clone(&self.byte_count),
            fwd_bytes: ::core::clone::Clone::clone(&self.fwd_bytes),
            rev_bytes: ::core::clone::Clone::clone(&self.rev_bytes),
            proto: ::core::clone::Clone::clone(&self.proto),
            src_port: ::core::clone::Clone::clone(&self.src_port),
            dst_port: ::core::clone::Clone::clone(&self.dst_port),
            l7_proto: ::core::clone::Clone::clone(&self.l7_proto),
        }
    }
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
    pub fn proto_id(&mut self, proto: &SessionProto) {
        if self.l7_proto.is_none() {
            self.l7_proto = Some(proto.clone());
        }
    }
}
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
    let encoded_dir = match conn.proto {
        6 => dir,
        17 => dir + 2,
        _ => return,
    };
    H_DIR_DOMINANCE.lock().unwrap().record(encoded_dir).unwrap();
    let total_bytes = conn.fwd_bytes + conn.rev_bytes;
    if total_bytes > 0 {
        let forward_ratio_percent = (conn.fwd_bytes * 100) / total_bytes;
        let ratio = forward_ratio_percent.min(100);
        let encoded_ratio = match conn.proto {
            6 => ratio,
            17 => ratio + 101,
            _ => return,
        };
        H_DIR_RATIO_PERCENT.lock().unwrap().record(encoded_ratio).unwrap();
    }
    H_PROTOCOL.lock().unwrap().record(conn.proto as u64).unwrap();
    H_DST_PORT.lock().unwrap().record(conn.dst_port as u64).unwrap();
    let throughput_bps = bytes.saturating_mul(8) / duration_secs;
    if duration_secs >= 10 {
        H_DURATION.lock().unwrap().record(duration_secs).unwrap();
        let proto_index = match conn.proto {
            6 => 0,
            17 => 1,
            _ => return,
        };
        let encoded_throughput = throughput_bps.saturating_mul(2) + proto_index;
        H_THROUGHPUT.lock().unwrap().record(encoded_throughput.max(1)).unwrap();
        let d_bucket = duration_bucket_secs(duration_secs);
        let t_bucket = throughput_bucket_bps(throughput_bps);
        let mut map = H_DUR_THR_2D.lock().unwrap();
        *map.entry((d_bucket, t_bucket)).or_insert(0) += 1;
    }
    let port_class_opt = match conn.proto {
        6 => {
            let port = conn.dst_port;
            Some(if port < 1024 { 0 } else if port < 49152 { 1 } else { 2 })
        }
        17 => {
            let src = conn.src_port;
            let dst = conn.dst_port;
            Some(
                if src < 1024 || dst < 1024 {
                    3
                } else if src < 49152 || dst < 49152 {
                    4
                } else {
                    5
                },
            )
        }
        _ => None,
    };
    if let Some(port_class) = port_class_opt {
        H_LARGE_PROTO_PORT_CLASS.lock().unwrap().record(port_class).unwrap();
    }
    if let Some(proto) = &conn.l7_proto {
        let bucket = match proto {
            SessionProto::Http => 1,
            SessionProto::Tls => 2,
            SessionProto::Quic => 3,
            _ => 0,
        };
        H_LARGE_FLOW_L7.lock().unwrap().record(bucket).unwrap();
    }
}
fn dump_hist(path: PathBuf, h: &Histogram<u64>) -> std::io::Result<()> {
    let f = File::create(path)?;
    let mut w = BufWriter::new(f);
    w.write_fmt(format_args!("value,count\n"))?;
    for v in h.iter_recorded() {
        w.write_fmt(
            format_args!("{0},{1}\n", v.value_iterated_to(), v.count_at_value()),
        )?;
    }
    Ok(())
}
fn dump_2d_hist(path: PathBuf, map: &HashMap<(u64, u64), u64>) -> std::io::Result<()> {
    let f = File::create(path)?;
    let mut w = BufWriter::new(f);
    w.write_fmt(format_args!("duration_bucket_secs,throughput_bucket_bps,count\n"))?;
    for ((d, t), c) in map {
        w.write_fmt(format_args!("{0},{1},{2}\n", d, t, c))?;
    }
    Ok(())
}
use iris_core::subscription::{Trackable, Subscribable};
use iris_core::conntrack::{TrackedActions, ConnInfo};
use iris_core::protocols::stream::ParserRegistry;
use iris_core::StateTransition;
use iris_core::subscription::*;
use iris_datatypes::*;
pub struct SubscribedWrapper;
impl Subscribable for SubscribedWrapper {
    type Tracked = TrackedWrapper;
}
pub struct TrackedWrapper {
    packets: Vec<iris_core::Mbuf>,
    core_id: iris_core::CoreId,
    connvolume: ConnVolume,
}
impl Trackable for TrackedWrapper {
    type Subscribed = SubscribedWrapper;
    fn new(first_pkt: &iris_core::L4Pdu, core_id: iris_core::CoreId) -> Self {
        Self {
            packets: Vec::new(),
            core_id,
            connvolume: ConnVolume::new(first_pkt),
        }
    }
    fn packets(&self) -> &Vec<iris_core::Mbuf> {
        &self.packets
    }
    fn core_id(&self) -> &iris_core::CoreId {
        &self.core_id
    }
    fn parsers() -> ParserRegistry {
        ParserRegistry::from_strings(Vec::from(["http", "tls", "quic"]))
    }
    fn clear(&mut self) {
        self.packets.clear();
    }
}
pub fn filter() -> iris_core::filter::FilterFactory<TrackedWrapper> {
    fn packet_filter(mbuf: &iris_core::Mbuf, core_id: &iris_core::CoreId) -> bool {
        if let Ok(ethernet) = &iris_core::protocols::packet::Packet::parse_to::<
            iris_core::protocols::packet::ethernet::Ethernet,
        >(mbuf) {
            if let Ok(ipv4) = &iris_core::protocols::packet::Packet::parse_to::<
                iris_core::protocols::packet::ipv4::Ipv4,
            >(ethernet) {
                if let Ok(tcp) = &iris_core::protocols::packet::Packet::parse_to::<
                    iris_core::protocols::packet::tcp::Tcp,
                >(ipv4) {
                    return true;
                } else if let Ok(udp) = &iris_core::protocols::packet::Packet::parse_to::<
                    iris_core::protocols::packet::udp::Udp,
                >(ipv4) {
                    return true;
                }
            } else if let Ok(ipv6) = &iris_core::protocols::packet::Packet::parse_to::<
                iris_core::protocols::packet::ipv6::Ipv6,
            >(ethernet) {
                if let Ok(tcp) = &iris_core::protocols::packet::Packet::parse_to::<
                    iris_core::protocols::packet::tcp::Tcp,
                >(ipv6) {
                    return true;
                } else if let Ok(udp) = &iris_core::protocols::packet::Packet::parse_to::<
                    iris_core::protocols::packet::udp::Udp,
                >(ipv6) {
                    return true;
                }
            }
            return false;
        }
        false
    }
    fn state_tx(conn: &mut ConnInfo<TrackedWrapper>, tx: &iris_core::StateTransition) {
        match tx {
            StateTransition::L4FirstPacket => tx_l4firstpacket(conn, &tx),
            StateTransition::L4InPayload(_) => tx_l4inpayload(conn, &tx),
            StateTransition::L7OnDisc => tx_l7ondisc(conn, &tx),
            StateTransition::L4Terminated => tx_l4terminated(conn, &tx),
            _ => {}
        }
    }
    fn tx_l4firstpacket(conn: &mut ConnInfo<TrackedWrapper>, tx: &StateTransition) {
        let mut ret = false;
        let tx = iris_core::StateTxData::from_tx(tx, &conn.layers[0]);
        let mut transport_actions = iris_core::conntrack::TrackedActions::new();
        let mut layer0_actions = iris_core::conntrack::TrackedActions::new();
        if let Ok(ipv4) = &iris_core::protocols::stream::ConnData::parse_to::<
            iris_core::protocols::stream::conn::Ipv4CData,
        >(&conn.cdata) {
            if let Ok(tcp) = &iris_core::protocols::stream::ConnData::parse_to::<
                iris_core::protocols::stream::conn::TcpCData,
            >(&conn.cdata) {
                transport_actions
                    .extend(
                        &TrackedActions {
                            active: iris_core::conntrack::Actions::from(13),
                            refresh_at: [
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(4),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(13),
                            ],
                        },
                    );
                layer0_actions
                    .extend(
                        &TrackedActions {
                            active: iris_core::conntrack::Actions::from(2),
                            refresh_at: [
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(2),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(2),
                            ],
                        },
                    );
            } else if let Ok(udp) = &iris_core::protocols::stream::ConnData::parse_to::<
                iris_core::protocols::stream::conn::UdpCData,
            >(&conn.cdata) {
                transport_actions
                    .extend(
                        &TrackedActions {
                            active: iris_core::conntrack::Actions::from(13),
                            refresh_at: [
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(4),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(13),
                            ],
                        },
                    );
                layer0_actions
                    .extend(
                        &TrackedActions {
                            active: iris_core::conntrack::Actions::from(2),
                            refresh_at: [
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(2),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(2),
                            ],
                        },
                    );
            }
        } else if let Ok(ipv6) = &iris_core::protocols::stream::ConnData::parse_to::<
            iris_core::protocols::stream::conn::Ipv6CData,
        >(&conn.cdata) {
            if let Ok(tcp) = &iris_core::protocols::stream::ConnData::parse_to::<
                iris_core::protocols::stream::conn::TcpCData,
            >(&conn.cdata) {
                transport_actions
                    .extend(
                        &TrackedActions {
                            active: iris_core::conntrack::Actions::from(13),
                            refresh_at: [
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(4),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(13),
                            ],
                        },
                    );
                layer0_actions
                    .extend(
                        &TrackedActions {
                            active: iris_core::conntrack::Actions::from(2),
                            refresh_at: [
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(2),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(2),
                            ],
                        },
                    );
            } else if let Ok(udp) = &iris_core::protocols::stream::ConnData::parse_to::<
                iris_core::protocols::stream::conn::UdpCData,
            >(&conn.cdata) {
                transport_actions
                    .extend(
                        &TrackedActions {
                            active: iris_core::conntrack::Actions::from(13),
                            refresh_at: [
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(4),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(13),
                            ],
                        },
                    );
                layer0_actions
                    .extend(
                        &TrackedActions {
                            active: iris_core::conntrack::Actions::from(2),
                            refresh_at: [
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(2),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(2),
                            ],
                        },
                    );
            }
        }
        conn.linfo.actions.extend(&transport_actions);
        conn.layers[0].extend_actions(&layer0_actions);
    }
    fn tx_l4inpayload(conn: &mut ConnInfo<TrackedWrapper>, tx: &StateTransition) {
        let mut ret = false;
        let tx = iris_core::StateTxData::from_tx(tx, &conn.layers[0]);
        let mut transport_actions = iris_core::conntrack::TrackedActions::new();
        let mut layer0_actions = iris_core::conntrack::TrackedActions::new();
        if let Ok(tcp) = &iris_core::protocols::stream::ConnData::parse_to::<
            iris_core::protocols::stream::conn::TcpCData,
        >(&conn.cdata) {
            if conn.layers[0].layer_info().state
                == iris_core::conntrack::LayerState::Discovery
            {
                transport_actions
                    .extend(
                        &TrackedActions {
                            active: iris_core::conntrack::Actions::from(4),
                            refresh_at: [
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(4),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(4),
                            ],
                        },
                    );
                layer0_actions
                    .extend(
                        &TrackedActions {
                            active: iris_core::conntrack::Actions::from(2),
                            refresh_at: [
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(2),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(2),
                            ],
                        },
                    );
            }
            transport_actions
                .extend(
                    &TrackedActions {
                        active: iris_core::conntrack::Actions::from(9),
                        refresh_at: [
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(9),
                        ],
                    },
                );
        } else if let Ok(udp) = &iris_core::protocols::stream::ConnData::parse_to::<
            iris_core::protocols::stream::conn::UdpCData,
        >(&conn.cdata) {
            if conn.layers[0].layer_info().state
                == iris_core::conntrack::LayerState::Discovery
            {
                transport_actions
                    .extend(
                        &TrackedActions {
                            active: iris_core::conntrack::Actions::from(4),
                            refresh_at: [
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(4),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(4),
                            ],
                        },
                    );
                layer0_actions
                    .extend(
                        &TrackedActions {
                            active: iris_core::conntrack::Actions::from(2),
                            refresh_at: [
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(2),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(2),
                            ],
                        },
                    );
            }
            transport_actions
                .extend(
                    &TrackedActions {
                        active: iris_core::conntrack::Actions::from(9),
                        refresh_at: [
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(9),
                        ],
                    },
                );
        }
        conn.linfo.actions.extend(&transport_actions);
        conn.layers[0].extend_actions(&layer0_actions);
    }
    fn tx_l7ondisc(conn: &mut ConnInfo<TrackedWrapper>, tx: &StateTransition) {
        let mut ret = false;
        let tx = iris_core::StateTxData::from_tx(tx, &conn.layers[0]);
        let mut transport_actions = iris_core::conntrack::TrackedActions::new();
        let mut layer0_actions = iris_core::conntrack::TrackedActions::new();
        conn.tracked.connvolume.proto_id(&conn.layers[0].last_protocol());
        if let Ok(tcp) = &iris_core::protocols::stream::ConnData::parse_to::<
            iris_core::protocols::stream::conn::TcpCData,
        >(&conn.cdata) {
            transport_actions
                .extend(
                    &TrackedActions {
                        active: iris_core::conntrack::Actions::from(9),
                        refresh_at: [
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(9),
                        ],
                    },
                );
        } else if let Ok(udp) = &iris_core::protocols::stream::ConnData::parse_to::<
            iris_core::protocols::stream::conn::UdpCData,
        >(&conn.cdata) {
            transport_actions
                .extend(
                    &TrackedActions {
                        active: iris_core::conntrack::Actions::from(9),
                        refresh_at: [
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(9),
                        ],
                    },
                );
        }
        conn.linfo.actions.extend(&transport_actions);
        conn.layers[0].extend_actions(&layer0_actions);
    }
    fn tx_l4terminated(conn: &mut ConnInfo<TrackedWrapper>, tx: &StateTransition) {
        let mut ret = false;
        let tx = iris_core::StateTxData::from_tx(tx, &conn.layers[0]);
        let mut transport_actions = iris_core::conntrack::TrackedActions::new();
        let mut layer0_actions = iris_core::conntrack::TrackedActions::new();
        record_data(&conn.tracked.connvolume);
        conn.linfo.actions.extend(&transport_actions);
        conn.layers[0].extend_actions(&layer0_actions);
    }
    fn update(
        conn: &mut ConnInfo<TrackedWrapper>,
        pdu: &iris_core::L4Pdu,
        state: iris_core::StateTransition,
    ) -> bool {
        let mut ret = false;
        match state {
            StateTransition::L4InPayload(_) => {
                conn.tracked.connvolume.new_packet(pdu);
            }
            _ => {}
        }
        ret
    }
    iris_core::filter::FilterFactory::new(
        "((ipv4) and (tcp)) or ((ipv4) and (udp)) or ((ipv6) and (tcp)) or ((ipv6) and (udp))",
        packet_filter,
        state_tx,
        update,
    )
}
fn main() {
    env_logger::init();
    let args = Args::parse();
    let config = load_config(&args.config);
    let out_dir = args.out_dir.clone();
    std::fs::create_dir_all(&out_dir).unwrap();
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
    dump_hist(out_dir.join("duration_secs.csv"), &H_DURATION.lock().unwrap()).unwrap();
    dump_hist(out_dir.join("volume_bytes.csv"), &H_BYTES.lock().unwrap()).unwrap();
    dump_hist(out_dir.join("throughput_bps.csv"), &H_THROUGHPUT.lock().unwrap())
        .unwrap();
    dump_hist(out_dir.join("packet_count.csv"), &H_PACKETS.lock().unwrap()).unwrap();
    dump_hist(
            out_dir.join("directionality_dominance.csv"),
            &H_DIR_DOMINANCE.lock().unwrap(),
        )
        .unwrap();
    dump_hist(out_dir.join("protocol.csv"), &H_PROTOCOL.lock().unwrap()).unwrap();
    dump_hist(out_dir.join("dst_port.csv"), &H_DST_PORT.lock().unwrap()).unwrap();
    dump_hist(
            out_dir.join("direction_ratio_percent.csv"),
            &H_DIR_RATIO_PERCENT.lock().unwrap(),
        )
        .unwrap();
    dump_hist(
            out_dir.join("large_proto_port_class.csv"),
            &H_LARGE_PROTO_PORT_CLASS.lock().unwrap(),
        )
        .unwrap();
    dump_hist(
            out_dir.join("large_flow_l7_protocol.csv"),
            &H_LARGE_FLOW_L7.lock().unwrap(),
        )
        .unwrap();
    dump_2d_hist(
            out_dir.join("duration_vs_throughput_2d.csv"),
            &H_DUR_THR_2D.lock().unwrap(),
        )
        .unwrap();
    {
        ::std::io::_print(
            format_args!("Histograms written to {0}\n", out_dir.display()),
        );
    };
}
