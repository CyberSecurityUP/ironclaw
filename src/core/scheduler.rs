//! Task scheduler for IronClaw.
//!
//! Provides a lightweight cron-like scheduler that executes registered jobs on
//! a recurring basis. Supports simple schedule expressions ("every 5 minutes",
//! "@hourly", "@daily") and full audit logging of all executions.

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, Notify};
use tokio::task::JoinHandle;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Represents a scheduled recurring job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronJob {
    /// Unique identifier for this job.
    pub id: String,
    /// Human-readable schedule expression (e.g. "every 5 minutes", "@hourly").
    pub schedule: String,
    /// The command or action to execute.
    pub command: String,
    /// Whether this job is enabled.
    pub enabled: bool,
    /// Timestamp of the last successful run (if any).
    pub last_run: Option<DateTime<Utc>>,
    /// Computed next run time (if any).
    pub next_run: Option<DateTime<Utc>>,
}

/// Result of a single job execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobExecution {
    pub job_id: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub success: bool,
    pub output: String,
}

/// Internal representation with parsed interval.
struct ScheduledJob {
    meta: CronJob,
    interval: Duration,
    /// The async callback that performs the work.
    handler: Arc<dyn Fn() -> tokio::task::JoinHandle<Result<String>> + Send + Sync>,
}

// ---------------------------------------------------------------------------
// Schedule parser
// ---------------------------------------------------------------------------

/// Parse a simple schedule expression into a `chrono::Duration`.
///
/// Supported formats:
///   - `"every N minutes"` / `"every N minute"`
///   - `"every N hours"` / `"every N hour"`
///   - `"every N days"` / `"every N day"`
///   - `"@hourly"` (equivalent to `"every 1 hour"`)
///   - `"@daily"` (equivalent to `"every 1 day"`)
///   - `"@every_5m"` (shorthand: `@every_<N>m` / `@every_<N>h`)
pub fn parse_schedule(expr: &str) -> Result<Duration> {
    let expr = expr.trim().to_lowercase();

    // Named shortcuts
    match expr.as_str() {
        "@hourly" => return Ok(Duration::hours(1)),
        "@daily" => return Ok(Duration::days(1)),
        "@weekly" => return Ok(Duration::weeks(1)),
        _ => {}
    }

    // "@every_Nm" or "@every_Nh"
    if expr.starts_with("@every_") {
        let rest = &expr[7..]; // after "@every_"
        if let Some(num_str) = rest.strip_suffix('m') {
            let n: i64 = num_str.parse().with_context(|| format!("Invalid schedule: {}", expr))?;
            return Ok(Duration::minutes(n));
        }
        if let Some(num_str) = rest.strip_suffix('h') {
            let n: i64 = num_str.parse().with_context(|| format!("Invalid schedule: {}", expr))?;
            return Ok(Duration::hours(n));
        }
        if let Some(num_str) = rest.strip_suffix('d') {
            let n: i64 = num_str.parse().with_context(|| format!("Invalid schedule: {}", expr))?;
            return Ok(Duration::days(n));
        }
        anyhow::bail!("Unrecognised @every_ suffix in: {}", expr);
    }

    // "every N minutes/hours/days"
    if expr.starts_with("every ") {
        let parts: Vec<&str> = expr.split_whitespace().collect();
        if parts.len() >= 3 {
            let n: i64 = parts[1]
                .parse()
                .with_context(|| format!("Invalid number in schedule: {}", expr))?;
            let unit = parts[2];
            if unit.starts_with("minute") {
                return Ok(Duration::minutes(n));
            } else if unit.starts_with("hour") {
                return Ok(Duration::hours(n));
            } else if unit.starts_with("day") {
                return Ok(Duration::days(n));
            } else if unit.starts_with("second") {
                return Ok(Duration::seconds(n));
            }
        }
        anyhow::bail!("Cannot parse schedule expression: {}", expr);
    }

    anyhow::bail!(
        "Unsupported schedule expression: '{}'. Use 'every N minutes/hours/days', '@hourly', or '@daily'.",
        expr
    );
}

// ---------------------------------------------------------------------------
// Scheduler
// ---------------------------------------------------------------------------

/// A lightweight task scheduler that runs jobs at configured intervals.
///
/// Jobs are registered with `add_job()` and the scheduler loop is started
/// with `start()`. All executions are logged via `tracing` for audit purposes.
pub struct Scheduler {
    jobs: Arc<Mutex<HashMap<String, ScheduledJob>>>,
    execution_log: Arc<Mutex<Vec<JobExecution>>>,
    stop_signal: Arc<Notify>,
    handle: Mutex<Option<JoinHandle<()>>>,
    job_timeout_secs: u64,
}

impl Scheduler {
    /// Create a new scheduler.
    pub fn new(job_timeout_secs: u64) -> Self {
        Self {
            jobs: Arc::new(Mutex::new(HashMap::new())),
            execution_log: Arc::new(Mutex::new(Vec::new())),
            stop_signal: Arc::new(Notify::new()),
            handle: Mutex::new(None),
            job_timeout_secs,
        }
    }

    /// Register a new job. The `handler` closure is spawned on the tokio
    /// runtime each time the job fires.
    pub async fn add_job<F>(&self, job: CronJob, handler: F) -> Result<()>
    where
        F: Fn() -> tokio::task::JoinHandle<Result<String>> + Send + Sync + 'static,
    {
        let interval = parse_schedule(&job.schedule)?;
        if interval.num_seconds() <= 0 {
            anyhow::bail!("Schedule interval must be positive");
        }

        let id = job.id.clone();
        let mut meta = job;
        meta.next_run = Some(Utc::now() + interval);

        let scheduled = ScheduledJob {
            meta,
            interval,
            handler: Arc::new(handler),
        };

        let mut jobs = self.jobs.lock().await;
        if jobs.contains_key(&id) {
            anyhow::bail!("Job '{}' is already registered", id);
        }
        tracing::info!(job_id = %id, schedule = %scheduled.meta.schedule, "Job registered");
        jobs.insert(id, scheduled);
        Ok(())
    }

    /// Remove a job by ID. Returns `true` if the job existed and was removed.
    pub async fn remove_job(&self, id: &str) -> bool {
        let mut jobs = self.jobs.lock().await;
        let removed = jobs.remove(id).is_some();
        if removed {
            tracing::info!(job_id = id, "Job removed");
        }
        removed
    }

    /// List all registered jobs (returns cloned metadata).
    pub async fn list_jobs(&self) -> Vec<CronJob> {
        let jobs = self.jobs.lock().await;
        jobs.values().map(|j| j.meta.clone()).collect()
    }

    /// Start the scheduler loop. The loop checks every second for jobs that
    /// are due and executes them.
    pub async fn start(&self) {
        let jobs = Arc::clone(&self.jobs);
        let log = Arc::clone(&self.execution_log);
        let stop = Arc::clone(&self.stop_signal);
        let timeout_secs = self.job_timeout_secs;

        let handle = tokio::spawn(async move {
            tracing::info!("Scheduler started");
            loop {
                tokio::select! {
                    _ = stop.notified() => {
                        tracing::info!("Scheduler stopping");
                        break;
                    }
                    _ = tokio::time::sleep(tokio::time::Duration::from_secs(1)) => {
                        Self::tick(&jobs, &log, timeout_secs).await;
                    }
                }
            }
        });

        let mut h = self.handle.lock().await;
        *h = Some(handle);
    }

    /// Stop the scheduler loop gracefully.
    pub async fn stop(&self) {
        self.stop_signal.notify_one();
        let mut h = self.handle.lock().await;
        if let Some(handle) = h.take() {
            let _ = handle.await;
        }
        tracing::info!("Scheduler stopped");
    }

    /// Internal: check all jobs and run those that are due.
    async fn tick(
        jobs: &Mutex<HashMap<String, ScheduledJob>>,
        log: &Mutex<Vec<JobExecution>>,
        timeout_secs: u64,
    ) {
        let now = Utc::now();
        let mut to_run: Vec<(String, Arc<dyn Fn() -> JoinHandle<Result<String>> + Send + Sync>, Duration)> = Vec::new();

        {
            let mut jobs_guard = jobs.lock().await;
            for (id, job) in jobs_guard.iter_mut() {
                if !job.meta.enabled {
                    continue;
                }
                if let Some(next) = job.meta.next_run {
                    if now >= next {
                        to_run.push((id.clone(), Arc::clone(&job.handler), job.interval));
                        job.meta.last_run = Some(now);
                        job.meta.next_run = Some(now + job.interval);
                    }
                }
            }
        }

        for (job_id, handler, _interval) in to_run {
            let log = Arc::clone(log);
            let timeout = tokio::time::Duration::from_secs(timeout_secs);

            tokio::spawn(async move {
                let started_at = Utc::now();
                tracing::info!(job_id = %job_id, "Executing scheduled job");

                let result = tokio::time::timeout(timeout, handler()).await;

                let (success, output) = match result {
                    Ok(join_result) => match join_result.await {
                        Ok(Ok(out)) => (true, out),
                        Ok(Err(e)) => (false, format!("Error: {}", e)),
                        Err(e) => (false, format!("Join error: {}", e)),
                    },
                    Err(_) => (false, "Job timed out".to_string()),
                };

                let finished_at = Utc::now();
                let execution = JobExecution {
                    job_id: job_id.clone(),
                    started_at,
                    finished_at,
                    success,
                    output: output.clone(),
                };

                tracing::info!(
                    job_id = %job_id,
                    success,
                    duration_ms = (finished_at - started_at).num_milliseconds(),
                    "Scheduled job completed"
                );

                let mut log_guard = log.lock().await;
                log_guard.push(execution);
            });
        }
    }

    /// Retrieve the execution log (for auditing).
    pub async fn execution_log(&self) -> Vec<JobExecution> {
        let log = self.execution_log.lock().await;
        log.clone()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_every_minutes() {
        let d = parse_schedule("every 5 minutes").unwrap();
        assert_eq!(d.num_minutes(), 5);
    }

    #[test]
    fn test_parse_every_hours() {
        let d = parse_schedule("every 2 hours").unwrap();
        assert_eq!(d.num_hours(), 2);
    }

    #[test]
    fn test_parse_every_days() {
        let d = parse_schedule("every 1 day").unwrap();
        assert_eq!(d.num_days(), 1);
    }

    #[test]
    fn test_parse_at_hourly() {
        let d = parse_schedule("@hourly").unwrap();
        assert_eq!(d.num_hours(), 1);
    }

    #[test]
    fn test_parse_at_daily() {
        let d = parse_schedule("@daily").unwrap();
        assert_eq!(d.num_days(), 1);
    }

    #[test]
    fn test_parse_at_every_shorthand() {
        let d = parse_schedule("@every_10m").unwrap();
        assert_eq!(d.num_minutes(), 10);

        let d = parse_schedule("@every_3h").unwrap();
        assert_eq!(d.num_hours(), 3);
    }

    #[test]
    fn test_parse_invalid() {
        assert!(parse_schedule("not a schedule").is_err());
        assert!(parse_schedule("every abc minutes").is_err());
        assert!(parse_schedule("").is_err());
    }

    #[tokio::test]
    async fn test_add_and_list_jobs() {
        let scheduler = Scheduler::new(30);

        let job = CronJob {
            id: "test-job".to_string(),
            schedule: "every 5 minutes".to_string(),
            command: "echo hello".to_string(),
            enabled: true,
            last_run: None,
            next_run: None,
        };

        scheduler
            .add_job(job, || {
                tokio::spawn(async { Ok("done".to_string()) })
            })
            .await
            .unwrap();

        let jobs = scheduler.list_jobs().await;
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].id, "test-job");
        assert!(jobs[0].next_run.is_some());
    }

    #[tokio::test]
    async fn test_remove_job() {
        let scheduler = Scheduler::new(30);

        let job = CronJob {
            id: "rm-job".to_string(),
            schedule: "@hourly".to_string(),
            command: "cleanup".to_string(),
            enabled: true,
            last_run: None,
            next_run: None,
        };

        scheduler
            .add_job(job, || {
                tokio::spawn(async { Ok("ok".to_string()) })
            })
            .await
            .unwrap();

        assert!(scheduler.remove_job("rm-job").await);
        assert!(!scheduler.remove_job("rm-job").await); // already removed
        assert!(scheduler.list_jobs().await.is_empty());
    }

    #[tokio::test]
    async fn test_duplicate_job_rejected() {
        let scheduler = Scheduler::new(30);

        let job = CronJob {
            id: "dup".to_string(),
            schedule: "every 1 minutes".to_string(),
            command: "x".to_string(),
            enabled: true,
            last_run: None,
            next_run: None,
        };

        scheduler
            .add_job(job.clone(), || {
                tokio::spawn(async { Ok("a".to_string()) })
            })
            .await
            .unwrap();

        let result = scheduler
            .add_job(job, || {
                tokio::spawn(async { Ok("b".to_string()) })
            })
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_start_stop() {
        let scheduler = Scheduler::new(5);
        scheduler.start().await;
        // Give it a moment to run
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        scheduler.stop().await;
        // Should not panic or hang
    }
}
