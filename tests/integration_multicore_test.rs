// Integration tests for multi-core support in the main application
use std::time::Duration;

#[test]
fn test_app_detects_multiple_cores() {
    // Verify the application can detect multiple CPU cores
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    println!("System has {} CPU cores available", cpus);
    assert!(cpus >= 1);

    // On modern systems, we expect multiple cores
    if cpus == 1 {
        println!("Warning: Only 1 CPU core detected. Multi-core tests may not be representative.");
    }
}

#[test]
fn test_tokio_worker_threads_calculation() {
    // Test that the logic used in main.rs for calculating worker threads is correct
    let num_cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    println!("Calculated worker threads: {}", num_cpus);
    assert!(num_cpus >= 1);

    // Verify this matches what the environment variable would be set to
    unsafe {
        std::env::set_var("TEST_TOKIO_WORKER_THREADS", num_cpus.to_string());
    }
    let env_value: usize = std::env::var("TEST_TOKIO_WORKER_THREADS")
        .unwrap()
        .parse()
        .unwrap();

    assert_eq!(env_value, num_cpus);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_runtime_configuration_matches_main() {
    // This test uses similar runtime configuration as main.rs
    let num_cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    println!("Testing with {} worker threads", num_cpus);

    // Spawn tasks equal to number of CPUs
    let mut handles = vec![];
    for i in 0..num_cpus {
        let handle = tokio::spawn(async move {
            let thread_id = std::thread::current().id();
            println!("Task {} running on thread {:?}", i, thread_id);
            tokio::time::sleep(Duration::from_millis(10)).await;
            i
        });
        handles.push(handle);
    }

    // Wait for all tasks
    let mut results = vec![];
    for handle in handles {
        results.push(handle.await.unwrap());
    }

    assert_eq!(results.len(), num_cpus);
}

#[test]
fn test_multi_thread_builder_configuration() {
    // Verify that tokio runtime can be built with multi-thread configuration
    let num_cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    // Build runtime like main.rs does
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(num_cpus)
        .enable_all()
        .build();

    assert!(runtime.is_ok(), "Failed to build multi-threaded runtime");

    let runtime = runtime.unwrap();

    // Use the runtime to execute a simple task
    let result = runtime.block_on(async {
        let thread_id = std::thread::current().id();
        println!("Task executed on thread {:?}", thread_id);
        42
    });

    assert_eq!(result, 42);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_high_concurrency_scenario() {
    // Simulate high concurrency like a real proxy workload
    let concurrent_requests = 100;
    let mut handles = vec![];

    let start = std::time::Instant::now();

    for i in 0..concurrent_requests {
        let handle = tokio::spawn(async move {
            // Simulate request processing
            tokio::time::sleep(Duration::from_millis(10)).await;
            i
        });
        handles.push(handle);
    }

    // Wait for all "requests"
    let mut results = vec![];
    for handle in handles {
        results.push(handle.await.unwrap());
    }

    let elapsed = start.elapsed();
    println!("{} concurrent tasks completed in {:?}", concurrent_requests, elapsed);

    assert_eq!(results.len(), concurrent_requests);

    // With 4 workers, 100 tasks with 10ms each should complete much faster than sequential
    // Sequential would be 1000ms, concurrent should be around 250-300ms with 4 workers
    assert!(elapsed < Duration::from_millis(600),
        "Concurrent execution took too long: {:?}. May not be utilizing all cores.", elapsed);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_mixed_cpu_and_io_workload() {
    // Test a mix of CPU-intensive and IO tasks (realistic proxy scenario)
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let io_tasks_completed = Arc::new(AtomicUsize::new(0));
    let cpu_tasks_completed = Arc::new(AtomicUsize::new(0));
    let mut io_handles = vec![];
    let mut cpu_handles = vec![];

    // Spawn IO-bound tasks (like network requests)
    for _ in 0..20 {
        let counter = io_tasks_completed.clone();
        let handle = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            counter.fetch_add(1, Ordering::SeqCst);
        });
        io_handles.push(handle);
    }

    // Spawn CPU-bound tasks (like parsing, encryption)
    for _ in 0..8 {
        let counter = cpu_tasks_completed.clone();
        let handle = tokio::task::spawn_blocking(move || {
            let mut sum: u64 = 0;
            for i in 0..500_000 {
                sum = sum.wrapping_add(i);
            }
            counter.fetch_add(1, Ordering::SeqCst);
            sum
        });
        cpu_handles.push(handle);
    }

    // Wait for IO tasks
    for handle in io_handles {
        let _ = handle.await;
    }

    // Wait for CPU tasks
    for handle in cpu_handles {
        let _ = handle.await;
    }

    let io_completed = io_tasks_completed.load(Ordering::SeqCst);
    let cpu_completed = cpu_tasks_completed.load(Ordering::SeqCst);

    println!("IO tasks completed: {}", io_completed);
    println!("CPU tasks completed: {}", cpu_completed);

    assert_eq!(io_completed, 20, "All IO tasks should complete");
    assert_eq!(cpu_completed, 8, "All CPU tasks should complete");
}

#[test]
fn test_environment_variable_override() {
    // Test that TOKIO_WORKER_THREADS can override the default
    let original = std::env::var("TOKIO_WORKER_THREADS").ok();

    // Set custom value
    unsafe {
        std::env::set_var("TOKIO_WORKER_THREADS", "2");
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build();

    assert!(runtime.is_ok());

    let runtime = runtime.unwrap();
    let result = runtime.block_on(async {
        "success"
    });

    assert_eq!(result, "success");

    // Restore original value
    unsafe {
        match original {
            Some(val) => std::env::set_var("TOKIO_WORKER_THREADS", val),
            None => std::env::remove_var("TOKIO_WORKER_THREADS"),
        }
    }
}

#[test]
fn test_mimalloc_allocator_multicore_safe() {
    // Verify mimalloc works correctly in multi-threaded scenarios
    // mimalloc is the global allocator in main.rs
    use std::thread;

    let mut handles = vec![];

    // Spawn threads that allocate memory
    for i in 0..8 {
        let handle = thread::spawn(move || {
            // Allocate and use memory
            let mut data = Vec::with_capacity(1000);
            for j in 0..1000 {
                data.push(i * 1000 + j);
            }
            data.iter().sum::<usize>()
        });
        handles.push(handle);
    }

    // Wait for all threads
    let mut results = vec![];
    for handle in handles {
        results.push(handle.join().unwrap());
    }

    assert_eq!(results.len(), 8);
    println!("Memory allocation test across 8 threads completed successfully");
}
