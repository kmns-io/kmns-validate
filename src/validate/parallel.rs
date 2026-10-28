//! Parallel / sequential dispatch for network I/O validators.

use crate::validate::http::ResourceTestResult;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Dispatch a resource validation task (parallel if feature is enabled and requested).
pub fn dispatch_io<R, F>(
    pairs: Vec<(String, R)>,
    parallel: bool,
    max_threads: usize,
    validator: F,
) -> Vec<ResourceTestResult>
where
    R: Send + Sync,
    F: Fn(&str, &R) -> ResourceTestResult + Send + Sync,
{
    #[cfg(feature = "parallel")]
    if parallel {
        return run_parallel(pairs, max_threads, validator);
    }

    // fallback when feature disabled or not requested
    let _ = parallel;
    let _ = max_threads;
    run_sequential(pairs, validator)
}

/// Fallback sequential execution.
fn run_sequential<R, F>(pairs: Vec<(String, R)>, validator: F) -> Vec<ResourceTestResult>
where
    F: Fn(&str, &R) -> ResourceTestResult,
{
    pairs
        .into_iter()
        .map(|(name, resource)| validator(&name, &resource))
        .collect()
}

/// Parallel execution using rayon.
#[cfg(feature = "parallel")]
fn run_parallel<R, F>(
    pairs: Vec<(String, R)>,
    max_threads: usize,
    validator: F,
) -> Vec<ResourceTestResult>
where
    R: Send + Sync,
    F: Fn(&str, &R) -> ResourceTestResult + Send + Sync,
{
    let mut builder = rayon::ThreadPoolBuilder::new();
    if max_threads > 0 {
        builder = builder.num_threads(max_threads);
    }

    let pool = builder.build().expect("failed to build rayon pool");

    pool.install(|| {
        pairs
            .par_iter()
            .map(|(name, resource)| validator(name, resource))
            .collect()
    })
}
