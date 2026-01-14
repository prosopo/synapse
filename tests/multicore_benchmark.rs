// Benchmark tests for multi-core performance
use std::time::{Duration, Instant};

#[tokio::test(flavor = "current_thread")]
async fn benchmark_single_threaded() {
    // Baseline: single-threaded runtime
    let start = Instant::now();
    let mut handles = vec![];

    for i in 0..100 {
        let handle = tokio::spawn(async move {
            // Simulate work
            tokio::time::sleep(Duration::from_millis(10)).await;
            i
        });
        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.await;
    }

    let elapsed = start.elapsed();
    println!("Single-threaded runtime: 100 tasks completed in {:?}", elapsed);
    println!("Average per task: {:?}", elapsed / 100);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn benchmark_two_threads() {
    let start = Instant::now();
    let mut handles = vec![];

    for i in 0..100 {
        let handle = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            i
        });
        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.await;
    }

    let elapsed = start.elapsed();
    println!("Two-threaded runtime: 100 tasks completed in {:?}", elapsed);
    println!("Average per task: {:?}", elapsed / 100);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn benchmark_four_threads() {
    let start = Instant::now();
    let mut handles = vec![];

    for i in 0..100 {
        let handle = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            i
        });
        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.await;
    }

    let elapsed = start.elapsed();
    println!("Four-threaded runtime: 100 tasks completed in {:?}", elapsed);
    println!("Average per task: {:?}", elapsed / 100);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn benchmark_eight_threads() {
    let start = Instant::now();
    let mut handles = vec![];

    for i in 0..100 {
        let handle = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            i
        });
        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.await;
    }

    let elapsed = start.elapsed();
    println!("Eight-threaded runtime: 100 tasks completed in {:?}", elapsed);
    println!("Average per task: {:?}", elapsed / 100);
}

#[test]
fn benchmark_cpu_intensive_single_thread() {
    let start = Instant::now();

    for _ in 0..8 {
        let mut sum: u64 = 0;
        for i in 0..1_000_000 {
            sum = sum.wrapping_add(i);
        }
    }

    let elapsed = start.elapsed();
    println!("Single-threaded CPU work: 8 tasks completed in {:?}", elapsed);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn benchmark_cpu_intensive_multi_thread() {
    let start = Instant::now();
    let mut handles = vec![];

    for _ in 0..8 {
        let handle = tokio::task::spawn_blocking(|| {
            let mut sum: u64 = 0;
            for i in 0..1_000_000 {
                sum = sum.wrapping_add(i);
            }
            sum
        });
        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.await;
    }

    let elapsed = start.elapsed();
    println!("Multi-threaded CPU work: 8 tasks completed in {:?}", elapsed);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn benchmark_realistic_proxy_workload() {
    // Simulate a realistic proxy workload with mixed IO and CPU tasks
    let start = Instant::now();
    let mut handles = vec![];

    // Simulate 50 concurrent requests
    for i in 0..50 {
        let handle = tokio::spawn(async move {
            // Simulate receiving request
            tokio::time::sleep(Duration::from_millis(2)).await;

            // Simulate parsing (CPU work)
            let result = tokio::task::spawn_blocking(move || {
                let mut sum: u64 = 0;
                for j in 0..10_000 {
                    sum = sum.wrapping_add(i * j);
                }
                sum
            }).await.unwrap();

            // Simulate upstream request
            tokio::time::sleep(Duration::from_millis(5)).await;

            // Simulate response processing
            tokio::time::sleep(Duration::from_millis(1)).await;

            result
        });
        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.await;
    }

    let elapsed = start.elapsed();
    let rps = 50.0 / elapsed.as_secs_f64();
    println!("Realistic proxy workload: 50 requests completed in {:?}", elapsed);
    println!("Throughput: {:.2} requests/second", rps);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn benchmark_high_throughput() {
    // Test maximum throughput with many concurrent tasks
    let start = Instant::now();
    let mut handles = vec![];
    let num_requests = 1000;

    for i in 0..num_requests {
        let handle = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(1)).await;
            i
        });
        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.await;
    }

    let elapsed = start.elapsed();
    let rps = num_requests as f64 / elapsed.as_secs_f64();
    println!("High throughput test: {} requests completed in {:?}", num_requests, elapsed);
    println!("Throughput: {:.2} requests/second", rps);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn benchmark_memory_allocation_concurrent() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let start = Instant::now();
    let total_allocated = Arc::new(AtomicUsize::new(0));
    let mut handles = vec![];

    // Simulate concurrent memory allocations (like buffering requests/responses)
    for _ in 0..100 {
        let counter = total_allocated.clone();
        let handle = tokio::spawn(async move {
            // Allocate buffers
            let mut buffers = Vec::with_capacity(10);
            for _ in 0..10 {
                let buffer = vec![0u8; 1024]; // 1KB buffer
                buffers.push(buffer);
            }

            counter.fetch_add(buffers.len() * 1024, Ordering::SeqCst);

            // Simulate processing
            tokio::time::sleep(Duration::from_millis(5)).await;
        });
        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.await;
    }

    let elapsed = start.elapsed();
    let total_kb = total_allocated.load(Ordering::SeqCst) / 1024;
    println!("Memory allocation benchmark: {}KB allocated across 100 concurrent tasks in {:?}",
             total_kb, elapsed);
}
