//! Cost Tracking and Budget Management for IronClaw.
//!
//! Records per-request token usage and estimated cost, enforces daily and
//! monthly spending limits, and stores history in SQLite for auditing.
//!
//! Features:
//! - `record_usage()` — persist token counts and cost per provider/model call
//! - `get_daily_total()` / `get_monthly_total()` — aggregated spend
//! - `check_budget()` — returns Ok or error if daily/monthly budget exceeded
//! - `get_report()` — breakdown by provider and model
//! - Alert thresholds — warn when approaching budget limits
//! - Currency formatting helpers

use anyhow::Result;
use chrono::{Datelike, NaiveDate, Utc};
use parking_lot::Mutex;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A single usage record for one LLM request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderUsage {
    pub provider: String,
    pub model: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    /// Estimated cost in USD (floating point).
    pub cost_usd: f64,
    /// ISO-8601 timestamp.
    pub timestamp: String,
}

/// Budget configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetConfig {
    /// Maximum daily spend in USD.
    pub daily_limit_usd: f64,
    /// Maximum monthly spend in USD.
    pub monthly_limit_usd: f64,
    /// Alert threshold as a fraction (0.0 - 1.0) of the limit. Default 0.8.
    pub alert_threshold: f64,
}

impl Default for BudgetConfig {
    fn default() -> Self {
        Self {
            daily_limit_usd: 5.0,
            monthly_limit_usd: 100.0,
            alert_threshold: 0.8,
        }
    }
}

/// Summary report entry grouped by provider + model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostReportEntry {
    pub provider: String,
    pub model: String,
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
    pub total_cost_usd: f64,
    pub request_count: u64,
}

/// Full cost report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostReport {
    pub entries: Vec<CostReportEntry>,
    pub daily_total_usd: f64,
    pub monthly_total_usd: f64,
    pub budget: BudgetConfig,
}

// ---------------------------------------------------------------------------
// CostTracker
// ---------------------------------------------------------------------------

/// Thread-safe cost tracker backed by SQLite.
pub struct CostTracker {
    db: Mutex<Connection>,
    budget: BudgetConfig,
}

impl CostTracker {
    /// Create a new CostTracker. Pass `":memory:"` for an in-memory database
    /// or a file path for persistent storage.
    pub fn new(db_path: &str, budget: BudgetConfig) -> Result<Self> {
        let conn = Connection::open(db_path)?;
        Self::init_schema(&conn)?;
        info!(
            db = %db_path,
            daily_limit = %format_usd(budget.daily_limit_usd),
            monthly_limit = %format_usd(budget.monthly_limit_usd),
            "Cost tracker initialized"
        );
        Ok(Self {
            db: Mutex::new(conn),
            budget,
        })
    }

    /// Initialize the SQLite schema if it does not already exist.
    fn init_schema(conn: &Connection) -> Result<()> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS cost_usage (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                provider    TEXT NOT NULL,
                model       TEXT NOT NULL,
                input_tok   INTEGER NOT NULL,
                output_tok  INTEGER NOT NULL,
                cost_usd    REAL NOT NULL,
                ts          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            );
            CREATE INDEX IF NOT EXISTS idx_cost_ts ON cost_usage(ts);",
        )?;
        Ok(())
    }

    // ----- Recording -------------------------------------------------------

    /// Record a single usage event.
    pub fn record_usage(&self, usage: &ProviderUsage) -> Result<()> {
        let db = self.db.lock();
        db.execute(
            "INSERT INTO cost_usage (provider, model, input_tok, output_tok, cost_usd, ts)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                usage.provider,
                usage.model,
                usage.input_tokens,
                usage.output_tokens,
                usage.cost_usd,
                usage.timestamp,
            ],
        )?;
        Ok(())
    }

    // ----- Aggregation -----------------------------------------------------

    /// Total cost for today (UTC).
    pub fn get_daily_total(&self) -> Result<f64> {
        let today = Utc::now().format("%Y-%m-%d").to_string();
        let db = self.db.lock();
        let total: f64 = db.query_row(
            "SELECT COALESCE(SUM(cost_usd), 0.0) FROM cost_usage WHERE ts >= ?1",
            params![format!("{}T00:00:00Z", today)],
            |row| row.get(0),
        )?;
        Ok(total)
    }

    /// Total cost for the current calendar month (UTC).
    pub fn get_monthly_total(&self) -> Result<f64> {
        let now = Utc::now();
        let first_of_month = NaiveDate::from_ymd_opt(now.year(), now.month(), 1)
            .unwrap_or_else(|| NaiveDate::from_ymd_opt(now.year(), now.month(), 1).unwrap());
        let start = format!("{}T00:00:00Z", first_of_month);
        let db = self.db.lock();
        let total: f64 = db.query_row(
            "SELECT COALESCE(SUM(cost_usd), 0.0) FROM cost_usage WHERE ts >= ?1",
            params![start],
            |row| row.get(0),
        )?;
        Ok(total)
    }

    // ----- Budget enforcement ----------------------------------------------

    /// Check whether the current spend is within budget.
    /// Returns `Ok(())` if within limits, or an error describing which limit
    /// was exceeded.
    pub fn check_budget(&self) -> Result<()> {
        let daily = self.get_daily_total()?;
        let monthly = self.get_monthly_total()?;

        // Hard limits
        if daily >= self.budget.daily_limit_usd {
            anyhow::bail!(
                "Daily budget exceeded: {} spent of {} limit",
                format_usd(daily),
                format_usd(self.budget.daily_limit_usd)
            );
        }
        if monthly >= self.budget.monthly_limit_usd {
            anyhow::bail!(
                "Monthly budget exceeded: {} spent of {} limit",
                format_usd(monthly),
                format_usd(self.budget.monthly_limit_usd)
            );
        }

        // Soft alert thresholds
        let daily_pct = daily / self.budget.daily_limit_usd;
        let monthly_pct = monthly / self.budget.monthly_limit_usd;

        if daily_pct >= self.budget.alert_threshold {
            warn!(
                "Daily spend at {:.0}% ({} / {})",
                daily_pct * 100.0,
                format_usd(daily),
                format_usd(self.budget.daily_limit_usd)
            );
        }
        if monthly_pct >= self.budget.alert_threshold {
            warn!(
                "Monthly spend at {:.0}% ({} / {})",
                monthly_pct * 100.0,
                format_usd(monthly),
                format_usd(self.budget.monthly_limit_usd)
            );
        }

        Ok(())
    }

    // ----- Reporting -------------------------------------------------------

    /// Generate a cost report broken down by provider and model.
    pub fn get_report(&self) -> Result<CostReport> {
        let db = self.db.lock();
        let mut stmt = db.prepare(
            "SELECT provider, model,
                    SUM(input_tok), SUM(output_tok),
                    SUM(cost_usd), COUNT(*)
             FROM cost_usage
             GROUP BY provider, model
             ORDER BY SUM(cost_usd) DESC",
        )?;

        let entries: Vec<CostReportEntry> = stmt
            .query_map([], |row| {
                Ok(CostReportEntry {
                    provider: row.get(0)?,
                    model: row.get(1)?,
                    total_input_tokens: row.get::<_, i64>(2)? as u64,
                    total_output_tokens: row.get::<_, i64>(3)? as u64,
                    total_cost_usd: row.get(4)?,
                    request_count: row.get::<_, i64>(5)? as u64,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();

        drop(stmt);
        drop(db);

        Ok(CostReport {
            entries,
            daily_total_usd: self.get_daily_total()?,
            monthly_total_usd: self.get_monthly_total()?,
            budget: self.budget.clone(),
        })
    }
}

// ---------------------------------------------------------------------------
// Currency helpers
// ---------------------------------------------------------------------------

/// Format a USD amount for display (e.g. "$1.23").
pub fn format_usd(amount: f64) -> String {
    format!("${:.4}", amount)
}

/// Convert cents to USD.
pub fn cents_to_usd(cents: u64) -> f64 {
    cents as f64 / 100.0
}

/// Convert USD to cents.
pub fn usd_to_cents(usd: f64) -> u64 {
    (usd * 100.0).round() as u64
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_tracker() -> CostTracker {
        CostTracker::new(":memory:", BudgetConfig::default()).unwrap()
    }

    fn make_usage(provider: &str, model: &str, cost: f64) -> ProviderUsage {
        ProviderUsage {
            provider: provider.into(),
            model: model.into(),
            input_tokens: 100,
            output_tokens: 200,
            cost_usd: cost,
            timestamp: Utc::now().to_rfc3339(),
        }
    }

    #[test]
    fn test_record_and_daily_total() {
        let tracker = test_tracker();
        tracker.record_usage(&make_usage("anthropic", "claude-sonnet", 0.01)).unwrap();
        tracker.record_usage(&make_usage("anthropic", "claude-sonnet", 0.02)).unwrap();

        let daily = tracker.get_daily_total().unwrap();
        assert!((daily - 0.03).abs() < 1e-6);
    }

    #[test]
    fn test_monthly_total() {
        let tracker = test_tracker();
        tracker.record_usage(&make_usage("openai", "gpt-4o", 0.05)).unwrap();

        let monthly = tracker.get_monthly_total().unwrap();
        assert!((monthly - 0.05).abs() < 1e-6);
    }

    #[test]
    fn test_check_budget_within_limits() {
        let tracker = test_tracker();
        tracker.record_usage(&make_usage("anthropic", "claude", 0.01)).unwrap();
        assert!(tracker.check_budget().is_ok());
    }

    #[test]
    fn test_check_budget_daily_exceeded() {
        let budget = BudgetConfig {
            daily_limit_usd: 0.02,
            monthly_limit_usd: 100.0,
            alert_threshold: 0.8,
        };
        let tracker = CostTracker::new(":memory:", budget).unwrap();
        tracker.record_usage(&make_usage("a", "b", 0.03)).unwrap();

        let result = tracker.check_budget();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Daily budget exceeded"));
    }

    #[test]
    fn test_check_budget_monthly_exceeded() {
        let budget = BudgetConfig {
            daily_limit_usd: 100.0,
            monthly_limit_usd: 0.01,
            alert_threshold: 0.8,
        };
        let tracker = CostTracker::new(":memory:", budget).unwrap();
        tracker.record_usage(&make_usage("a", "b", 0.02)).unwrap();

        let result = tracker.check_budget();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Monthly budget exceeded"));
    }

    #[test]
    fn test_get_report() {
        let tracker = test_tracker();
        tracker.record_usage(&make_usage("anthropic", "claude", 0.01)).unwrap();
        tracker.record_usage(&make_usage("anthropic", "claude", 0.02)).unwrap();
        tracker.record_usage(&make_usage("openai", "gpt-4o", 0.05)).unwrap();

        let report = tracker.get_report().unwrap();
        assert_eq!(report.entries.len(), 2);
        // openai/gpt-4o should be first (highest cost)
        assert_eq!(report.entries[0].provider, "openai");
        assert_eq!(report.entries[0].request_count, 1);
        assert_eq!(report.entries[1].provider, "anthropic");
        assert_eq!(report.entries[1].request_count, 2);
    }

    #[test]
    fn test_format_usd() {
        assert_eq!(format_usd(1.5), "$1.5000");
        assert_eq!(format_usd(0.0001), "$0.0001");
        assert_eq!(format_usd(0.0), "$0.0000");
    }

    #[test]
    fn test_cents_conversion() {
        assert!((cents_to_usd(500) - 5.0).abs() < 1e-9);
        assert_eq!(usd_to_cents(5.0), 500);
        assert_eq!(usd_to_cents(0.01), 1);
    }

    #[test]
    fn test_empty_report() {
        let tracker = test_tracker();
        let report = tracker.get_report().unwrap();
        assert!(report.entries.is_empty());
        assert!((report.daily_total_usd).abs() < 1e-9);
    }
}
