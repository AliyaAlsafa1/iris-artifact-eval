use clap::Parser;
use iris_core::FiveTuple;
use iris_core::{Runtime, config::load_config};
use iris_datatypes::{ByteCount, ConnDuration, PktCount};
use iris_compiler::*;
use std::path::PathBuf;
use std::sync::atomic::AtomicUsize;

#[callback("tls,level=L7OnDisc")]
fn new_conn(_: &FiveTuple) {
    CONNS_TOT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

#[callback("tls,level=L4Terminated")]
fn conn_done(dur: &ConnDuration, _bytes: &ByteCount, _pkts: &PktCount) {
    let dur = dur.duration().as_secs();
    if dur > 5 * 60 {
        CONNS_GT_5M.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    if dur > 2 * 60 {
        CONNS_GT_2M.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    if dur > 1 * 60 {
        CONNS_GT_1M.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

const CONNS_TOT: AtomicUsize = AtomicUsize::new(0);
const CONNS_GT_5M: AtomicUsize = AtomicUsize::new(0);
const CONNS_GT_2M: AtomicUsize = AtomicUsize::new(0);
const CONNS_GT_1M: AtomicUsize = AtomicUsize::new(0);

#[input_files("$IRIS_HOME/datatypes/data.txt")]
#[iris_main]
fn main() {
    env_logger::init();
    let args = Args::parse();
    let config = load_config(&args.config);
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
    println!(
        "{} total connections",
        CONNS_TOT.load(std::sync::atomic::Ordering::Relaxed)
    );
    println!(
        "{} connections > 1 minute",
        CONNS_GT_1M.load(std::sync::atomic::Ordering::Relaxed)
    );
    println!(
        "{} connections > 2 minutes",
        CONNS_GT_2M.load(std::sync::atomic::Ordering::Relaxed)
    );
    println!(
        "{} connections > 5 minutes",
        CONNS_GT_5M.load(std::sync::atomic::Ordering::Relaxed)
    );
}

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
}
