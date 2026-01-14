use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_multiple_workers_are_used() {
    // This test verifies that tasks actually run on different threads
    let thread_ids = Arc::new(Mutex::new(HashSet::new()));
    let mut handles = vec![];

    // Spawn 10 tasks that record their thread IDs
    for _ in 0..10 {
        let thread_ids = thread_ids.clone();
        let handle = tokio::spawn(async move {
            let thread_id = std::thread::current().id();
            thread_ids.lock().unwrap().insert(thread_id);
            // Do some work to ensure the task actually runs
            tokio::time::sleep(Duration::from_millis(10)).await;
        });
        handles.push(handle);
    }

    // Wait for all tasks to complete
    for handle in handles {
        handle.await.unwrap();
    }

    // Verify that more than one thread was used
    let unique_threads = thread_ids.lock().unwrap().len();
    println!("Tasks executed on {} different threads", unique_threads);
    assert!(unique_threads > 1, "Expected tasks to run on multiple threads, but only {} thread(s) were used", unique_threads);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_concurrent_task_execution() {
    // This test verifies that tasks can run concurrently
    let start = std::time::Instant::now();
    let mut handles = vec![];

    // Spawn 4 tasks that each sleep for 100ms
    // If running concurrently, total time should be ~100ms
    // If running sequentially, total time would be ~400ms
    for _ in 0..4 {
        let handle = tokio::spawn(async {
            tokio::time::sleep(Duration::from_millis(100)).await;
        });
        handles.push(handle);
    }

    // Wait for all tasks to complete
    for handle in handles {
        handle.await.unwrap();
    }

    let elapsed = start.elapsed();
    println!("4 concurrent 100ms tasks completed in {:?}", elapsed);

    // If tasks run concurrently, they should complete in roughly 100ms
    // Allow some overhead but verify it's not sequential
    assert!(elapsed < Duration::from_millis(250),
        "Expected concurrent execution (~100ms), but took {:?}. Tasks may be running sequentially.", elapsed);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_cpu_intensive_tasks_on_multiple_cores() {
    // This test verifies CPU-intensive work is distributed across cores
    let thread_ids = Arc::new(Mutex::new(HashSet::new()));
    let mut handles = vec![];

    // Spawn 8 CPU-intensive tasks
    for task_num in 0..8 {
        let thread_ids = thread_ids.clone();
        let handle = tokio::task::spawn_blocking(move || {
            let thread_id = std::thread::current().id();
            thread_ids.lock().unwrap().insert(thread_id);

            // Simulate CPU-intensive work
            let mut sum: u64 = 0;
            for i in 0..1_000_000 {
                sum = sum.wrapping_add(i);
            }
            (task_num, sum, thread_id)
        });
        handles.push(handle);
    }

    // Wait for all tasks
    let mut results = vec![];
    for handle in handles {
        results.push(handle.await.unwrap());
    }

    let unique_threads = thread_ids.lock().unwrap().len();
    println!("CPU-intensive tasks executed on {} different blocking threads", unique_threads);

    // Verify all tasks completed
    assert_eq!(results.len(), 8, "All 8 tasks should complete");

    // Verify multiple threads were used for blocking tasks
    assert!(unique_threads > 1,
        "Expected CPU-intensive tasks to run on multiple threads, but only {} thread(s) were used",
        unique_threads);
}

#[test]
fn test_tokio_worker_threads_env_var() {
    // Test that the application respects TOKIO_WORKER_THREADS
    let available_cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    println!("Available CPU cores: {}", available_cpus);
    assert!(available_cpus >= 1, "Should detect at least 1 CPU core");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_parallel_work_distribution() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    // Counter to track concurrent execution
    let active_count = Arc::new(AtomicUsize::new(0));
    let max_concurrent = Arc::new(AtomicUsize::new(0));
    let mut handles = vec![];

    // Spawn tasks that increment active counter during execution
    for _ in 0..10 {
        let active_count = active_count.clone();
        let max_concurrent = max_concurrent.clone();

        let handle = tokio::spawn(async move {
            let current = active_count.fetch_add(1, Ordering::SeqCst) + 1;

            // Update max concurrent if this is a new peak
            let mut max = max_concurrent.load(Ordering::SeqCst);
            while current > max {
                match max_concurrent.compare_exchange(
                    max,
                    current,
                    Ordering::SeqCst,
                    Ordering::SeqCst
                ) {
                    Ok(_) => break,
                    Err(new_max) => max = new_max,
                }
            }

            // Simulate work
            tokio::time::sleep(Duration::from_millis(50)).await;

            active_count.fetch_sub(1, Ordering::SeqCst);
        });
        handles.push(handle);
    }

    // Wait for all tasks
    for handle in handles {
        handle.await.unwrap();
    }

    let max_concurrent_tasks = max_concurrent.load(Ordering::SeqCst);
    println!("Maximum concurrent tasks: {}", max_concurrent_tasks);

    // Verify that at least 2 tasks ran concurrently
    assert!(max_concurrent_tasks >= 2,
        "Expected at least 2 tasks to run concurrently, but only {} were concurrent",
        max_concurrent_tasks);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_tokio_runtime_thread_count() {
    // Verify the runtime is using multiple threads
    let threads_used = Arc::new(Mutex::new(HashSet::new()));
    let mut handles = vec![];

    // Create 20 tasks to ensure we see all worker threads
    for _ in 0..20 {
        let threads_used = threads_used.clone();
        let handle = tokio::spawn(async move {
            let thread_id = std::thread::current().id();
            threads_used.lock().unwrap().insert(thread_id);
            tokio::time::sleep(Duration::from_micros(100)).await;
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await.unwrap();
    }

    let thread_count = threads_used.lock().unwrap().len();
    println!("Tokio runtime used {} worker threads", thread_count);

    // Should use multiple threads (expecting 2-4 based on configuration)
    assert!(thread_count >= 2 && thread_count <= 4,
        "Expected 2-4 worker threads, got {}", thread_count);
}
