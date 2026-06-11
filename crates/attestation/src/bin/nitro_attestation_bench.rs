#![allow(clippy::print_stdout)]

#[cfg(feature = "nitro")]
use std::{
    env,
    time::{Duration, Instant},
};

#[cfg(feature = "nitro")]
use tokio::{sync::Barrier, task::JoinSet};

#[cfg(feature = "nitro")]
use attestation::nitro;

#[cfg(feature = "nitro")]
#[derive(Debug)]
struct Sample {
    task_id: usize,
    elapsed: Duration,
    attestation_len: usize,
}

#[cfg(feature = "nitro")]
#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let (count, rounds) = parse_args();

    println!("Nitro attestation benchmark");
    println!("count={count} rounds={rounds}");

    for round in 0..rounds {
        println!();
        println!("Round {}", round + 1);

        let (serial_wall_clock, serial) = serial_run(count).await;
        print_summary("serial", serial_wall_clock, &serial);

        let (concurrent_wall_clock, concurrent) = concurrent_run(count).await;
        print_summary("concurrent", concurrent_wall_clock, &concurrent);
    }
}

#[cfg(not(feature = "nitro"))]
fn main() {
    eprintln!("This benchmark requires the `nitro` feature.");
    std::process::exit(1);
}

#[cfg(feature = "nitro")]
async fn serial_run(count: usize) -> (Duration, Vec<Sample>) {
    let phase_start = Instant::now();
    let mut samples = Vec::with_capacity(count);

    for task_id in 0..count {
        let nonce = nonce_for(task_id, 0);
        let start = Instant::now();
        let attestation = nitro::create_nitro_attestation(nonce)
            .unwrap_or_else(|err| panic!("serial attestation {task_id} failed: {err}"));
        samples.push(Sample {
            task_id,
            elapsed: start.elapsed(),
            attestation_len: attestation.len(),
        });
    }

    (phase_start.elapsed(), samples)
}

#[cfg(feature = "nitro")]
async fn concurrent_run(count: usize) -> (Duration, Vec<Sample>) {
    let phase_start = Instant::now();
    let barrier = std::sync::Arc::new(Barrier::new(count + 1));
    let mut join_set = JoinSet::new();

    for task_id in 0..count {
        let barrier = std::sync::Arc::clone(&barrier);
        join_set.spawn(async move {
            let nonce = nonce_for(task_id, 1);
            barrier.wait().await;
            let start = Instant::now();
            let attestation = nitro::create_nitro_attestation(nonce)
                .unwrap_or_else(|err| panic!("concurrent attestation {task_id} failed: {err}"));
            Sample { task_id, elapsed: start.elapsed(), attestation_len: attestation.len() }
        });
    }

    barrier.wait().await;

    let mut samples = Vec::with_capacity(count);
    while let Some(result) = join_set.join_next().await {
        samples.push(result.expect("join failed"));
    }
    samples.sort_by_key(|sample| sample.task_id);
    (phase_start.elapsed(), samples)
}

#[cfg(feature = "nitro")]
fn print_summary(label: &str, wall_clock: Duration, samples: &[Sample]) {
    let sum_elapsed: Duration = samples.iter().map(|sample| sample.elapsed).sum();
    let avg_elapsed =
        if samples.is_empty() { Duration::ZERO } else { sum_elapsed / samples.len() as u32 };

    println!(
        "{label}: wall_clock={:?} avg_per_task={:?} min={:?} max={:?}",
        wall_clock,
        avg_elapsed,
        samples.iter().map(|sample| sample.elapsed).min().unwrap_or_default(),
        samples.iter().map(|sample| sample.elapsed).max().unwrap_or_default(),
    );

    for sample in samples {
        println!(
            "  task={} elapsed={:?} attestation_len={}",
            sample.task_id, sample.elapsed, sample.attestation_len
        );
    }
}

#[cfg(feature = "nitro")]
fn nonce_for(task_id: usize, round: usize) -> [u8; 64] {
    let mut nonce = [0u8; 64];
    nonce[..8].copy_from_slice(&(task_id as u64).to_le_bytes());
    nonce[8..16].copy_from_slice(&(round as u64).to_le_bytes());
    nonce
}

#[cfg(feature = "nitro")]
fn parse_args() -> (usize, usize) {
    let args: Vec<String> = env::args().skip(1).collect();

    let count = args.first().map_or(8, |raw| {
        raw.parse::<usize>().unwrap_or_else(|err| {
            panic!("invalid count value '{raw}': {err}");
        })
    });
    let rounds = args.get(1).map_or(1, |raw| {
        raw.parse::<usize>().unwrap_or_else(|err| {
            panic!("invalid rounds value '{raw}': {err}");
        })
    });

    assert!(count >= 1, "count must be at least 1");
    assert!(rounds >= 1, "rounds must be at least 1");

    (count, rounds)
}
