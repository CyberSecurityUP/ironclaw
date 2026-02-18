//! Conversation history management for IronClaw.
//!
//! Provides SQLite-backed persistent storage for conversations and their
//! messages, with support for compression, retention policies, and export
//! in JSON / JSONL formats.

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A stored conversation (header).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conversation {
    pub id: String,
    pub title: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub message_count: usize,
    #[serde(default)]
    pub metadata: serde_json::Value,
}

/// A single message within a conversation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredMessage {
    pub id: i64,
    pub conversation_id: String,
    pub role: String,
    pub content: String,
    #[serde(default)]
    pub tool_calls: serde_json::Value,
    pub timestamp: DateTime<Utc>,
}

/// Export format for conversation data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Json,
    JsonLines,
}

/// Retention policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicy {
    /// Maximum age for conversations in days. Older ones are auto-deleted.
    #[serde(default = "default_retention_days")]
    pub max_age_days: u64,
    /// Whether retention enforcement is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_retention_days() -> u64 { 90 }
fn default_true() -> bool { true }

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            max_age_days: default_retention_days(),
            enabled: true,
        }
    }
}

// ---------------------------------------------------------------------------
// HistoryStore
// ---------------------------------------------------------------------------

/// SQLite-backed conversation history store.
///
/// Schema:
///   conversations (id TEXT PK, title TEXT, created_at TEXT, updated_at TEXT, metadata TEXT)
///   messages (id INTEGER PK, conversation_id TEXT FK, role TEXT, content TEXT,
///             tool_calls TEXT, timestamp TEXT)
pub struct HistoryStore {
    conn: parking_lot::Mutex<rusqlite::Connection>,
    retention: RetentionPolicy,
}

impl HistoryStore {
    /// Open or create the history database at the given path.
    pub fn new(path: &str, retention: RetentionPolicy) -> Result<Self> {
        let db_path = shellexpand_path(path);
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Cannot create directory for history DB: {}", parent.display()))?;
        }

        let conn = rusqlite::Connection::open(&db_path)
            .with_context(|| format!("Failed to open history DB at {}", db_path.display()))?;

        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA foreign_keys = ON;
             PRAGMA busy_timeout = 5000;",
        )?;

        let store = Self {
            conn: parking_lot::Mutex::new(conn),
            retention,
        };
        store.init_tables()?;

        tracing::info!(path = %db_path.display(), "HistoryStore initialized");
        Ok(store)
    }

    /// Open an in-memory database (useful for tests).
    pub fn in_memory(retention: RetentionPolicy) -> Result<Self> {
        let conn = rusqlite::Connection::open_in_memory()?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        let store = Self {
            conn: parking_lot::Mutex::new(conn),
            retention,
        };
        store.init_tables()?;
        Ok(store)
    }

    fn init_tables(&self) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS conversations (
                id          TEXT PRIMARY KEY,
                title       TEXT NOT NULL,
                created_at  TEXT NOT NULL,
                updated_at  TEXT NOT NULL,
                metadata    TEXT NOT NULL DEFAULT '{}'
            );

            CREATE TABLE IF NOT EXISTS messages (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                conversation_id TEXT NOT NULL,
                role            TEXT NOT NULL,
                content         TEXT NOT NULL,
                tool_calls      TEXT NOT NULL DEFAULT '[]',
                timestamp       TEXT NOT NULL,
                FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_messages_conv
                ON messages(conversation_id);
            CREATE INDEX IF NOT EXISTS idx_conversations_updated
                ON conversations(updated_at);",
        )?;
        Ok(())
    }

    // -- Core operations -----------------------------------------------------

    /// Save a complete conversation (header + messages).
    ///
    /// If a conversation with the same ID already exists, its messages are
    /// replaced and the header is updated.
    pub fn save_conversation(
        &self,
        id: &str,
        title: &str,
        messages: &[StoredMessage],
        metadata: Option<&serde_json::Value>,
    ) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        let meta_str = serde_json::to_string(metadata.unwrap_or(&serde_json::json!({})))?;

        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;

        // Upsert conversation header
        tx.execute(
            "INSERT INTO conversations (id, title, created_at, updated_at, metadata)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(id) DO UPDATE SET
                 title = excluded.title,
                 updated_at = excluded.updated_at,
                 metadata = excluded.metadata",
            rusqlite::params![id, title, &now, &now, meta_str],
        )?;

        // Replace messages
        tx.execute(
            "DELETE FROM messages WHERE conversation_id = ?1",
            rusqlite::params![id],
        )?;

        let mut insert_stmt = tx.prepare(
            "INSERT INTO messages (conversation_id, role, content, tool_calls, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )?;

        for msg in messages {
            let tc = serde_json::to_string(&msg.tool_calls)?;
            insert_stmt.execute(rusqlite::params![
                id,
                msg.role,
                msg.content,
                tc,
                msg.timestamp.to_rfc3339(),
            ])?;
        }

        drop(insert_stmt);
        tx.commit()?;

        tracing::debug!(conversation_id = id, messages = messages.len(), "Conversation saved");
        Ok(())
    }

    /// Load a conversation and all its messages.
    pub fn load_conversation(&self, id: &str) -> Result<Option<(Conversation, Vec<StoredMessage>)>> {
        let conn = self.conn.lock();

        // Load header
        let mut header_stmt = conn.prepare(
            "SELECT id, title, created_at, updated_at, metadata FROM conversations WHERE id = ?1",
        )?;

        let conversation = header_stmt
            .query_row(rusqlite::params![id], |row| {
                let id: String = row.get(0)?;
                let title: String = row.get(1)?;
                let created_at: String = row.get(2)?;
                let updated_at: String = row.get(3)?;
                let metadata: String = row.get(4)?;
                Ok((id, title, created_at, updated_at, metadata))
            })
            .ok();

        let (conv_id, title, created_at, updated_at, metadata_str) = match conversation {
            Some(c) => c,
            None => return Ok(None),
        };

        // Load messages
        let mut msg_stmt = conn.prepare(
            "SELECT id, conversation_id, role, content, tool_calls, timestamp
             FROM messages WHERE conversation_id = ?1 ORDER BY id ASC",
        )?;

        let messages: Vec<StoredMessage> = msg_stmt
            .query_map(rusqlite::params![id], |row| {
                let msg_id: i64 = row.get(0)?;
                let cid: String = row.get(1)?;
                let role: String = row.get(2)?;
                let content: String = row.get(3)?;
                let tc_str: String = row.get(4)?;
                let ts_str: String = row.get(5)?;
                Ok((msg_id, cid, role, content, tc_str, ts_str))
            })?
            .filter_map(|r| r.ok())
            .map(|(msg_id, cid, role, content, tc_str, ts_str)| {
                let tool_calls: serde_json::Value =
                    serde_json::from_str(&tc_str).unwrap_or(serde_json::json!([]));
                let timestamp = DateTime::parse_from_rfc3339(&ts_str)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now());
                StoredMessage {
                    id: msg_id,
                    conversation_id: cid,
                    role,
                    content,
                    tool_calls,
                    timestamp,
                }
            })
            .collect();

        let created = parse_dt(&created_at);
        let updated = parse_dt(&updated_at);
        let metadata: serde_json::Value =
            serde_json::from_str(&metadata_str).unwrap_or(serde_json::json!({}));

        Ok(Some((
            Conversation {
                id: conv_id,
                title,
                created_at: created,
                updated_at: updated,
                message_count: messages.len(),
                metadata,
            },
            messages,
        )))
    }

    /// List all conversations, ordered by most recently updated.
    pub fn list_conversations(&self, limit: usize, offset: usize) -> Result<Vec<Conversation>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT c.id, c.title, c.created_at, c.updated_at, c.metadata,
                    (SELECT COUNT(*) FROM messages m WHERE m.conversation_id = c.id) as msg_count
             FROM conversations c
             ORDER BY c.updated_at DESC
             LIMIT ?1 OFFSET ?2",
        )?;

        let rows = stmt.query_map(rusqlite::params![limit, offset], |row| {
            let id: String = row.get(0)?;
            let title: String = row.get(1)?;
            let created_at: String = row.get(2)?;
            let updated_at: String = row.get(3)?;
            let metadata_str: String = row.get(4)?;
            let msg_count: usize = row.get(5)?;
            Ok((id, title, created_at, updated_at, metadata_str, msg_count))
        })?;

        let mut conversations = Vec::new();
        for row in rows {
            let (id, title, created_at, updated_at, metadata_str, msg_count) = row?;
            let metadata: serde_json::Value =
                serde_json::from_str(&metadata_str).unwrap_or(serde_json::json!({}));
            conversations.push(Conversation {
                id,
                title,
                created_at: parse_dt(&created_at),
                updated_at: parse_dt(&updated_at),
                message_count: msg_count,
                metadata,
            });
        }

        Ok(conversations)
    }

    /// Delete a conversation and all its messages (cascade).
    pub fn delete_conversation(&self, id: &str) -> Result<bool> {
        let conn = self.conn.lock();
        let affected = conn.execute(
            "DELETE FROM conversations WHERE id = ?1",
            rusqlite::params![id],
        )?;
        if affected > 0 {
            tracing::info!(conversation_id = id, "Conversation deleted");
        }
        Ok(affected > 0)
    }

    /// Search conversations by title or message content.
    pub fn search_history(&self, query: &str, limit: usize) -> Result<Vec<Conversation>> {
        let conn = self.conn.lock();
        let pattern = format!("%{}%", query);

        let mut stmt = conn.prepare(
            "SELECT DISTINCT c.id, c.title, c.created_at, c.updated_at, c.metadata,
                    (SELECT COUNT(*) FROM messages m2 WHERE m2.conversation_id = c.id)
             FROM conversations c
             LEFT JOIN messages m ON m.conversation_id = c.id
             WHERE c.title LIKE ?1 OR m.content LIKE ?1
             ORDER BY c.updated_at DESC
             LIMIT ?2",
        )?;

        let rows = stmt.query_map(rusqlite::params![pattern, limit], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, usize>(5)?,
            ))
        })?;

        let mut results = Vec::new();
        for row in rows {
            let (id, title, created_at, updated_at, meta_str, msg_count) = row?;
            results.push(Conversation {
                id,
                title,
                created_at: parse_dt(&created_at),
                updated_at: parse_dt(&updated_at),
                message_count: msg_count,
                metadata: serde_json::from_str(&meta_str).unwrap_or(serde_json::json!({})),
            });
        }

        Ok(results)
    }

    /// Export a conversation to the specified format.
    pub fn export(&self, id: &str, format: ExportFormat) -> Result<String> {
        let (conv, messages) = self
            .load_conversation(id)?
            .ok_or_else(|| anyhow::anyhow!("Conversation not found: {}", id))?;

        match format {
            ExportFormat::Json => {
                let export = serde_json::json!({
                    "conversation": conv,
                    "messages": messages,
                });
                Ok(serde_json::to_string_pretty(&export)?)
            }
            ExportFormat::JsonLines => {
                let mut buf = Vec::new();
                // First line: conversation header
                writeln!(buf, "{}", serde_json::to_string(&conv)?)?;
                // Subsequent lines: one message per line
                for msg in &messages {
                    writeln!(buf, "{}", serde_json::to_string(msg)?)?;
                }
                Ok(String::from_utf8(buf)?)
            }
        }
    }

    // -- Compression --------------------------------------------------------

    /// Compress a conversation's message content using flate2 (deflate).
    /// Returns the compressed bytes that could be stored elsewhere.
    pub fn compress_conversation(&self, id: &str) -> Result<Vec<u8>> {
        let (conv, messages) = self
            .load_conversation(id)?
            .ok_or_else(|| anyhow::anyhow!("Conversation not found: {}", id))?;

        let payload = serde_json::to_vec(&serde_json::json!({
            "conversation": conv,
            "messages": messages,
        }))?;

        let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&payload)?;
        let compressed = encoder.finish()?;

        tracing::debug!(
            conversation_id = id,
            original = payload.len(),
            compressed = compressed.len(),
            "Conversation compressed"
        );

        Ok(compressed)
    }

    /// Decompress conversation data produced by `compress_conversation`.
    pub fn decompress_conversation(data: &[u8]) -> Result<(Conversation, Vec<StoredMessage>)> {
        use std::io::Read;
        let mut decoder = flate2::read::DeflateDecoder::new(data);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed)?;

        let value: serde_json::Value = serde_json::from_slice(&decompressed)?;
        let conv: Conversation = serde_json::from_value(value["conversation"].clone())?;
        let messages: Vec<StoredMessage> = serde_json::from_value(value["messages"].clone())?;
        Ok((conv, messages))
    }

    // -- Retention policy ---------------------------------------------------

    /// Enforce the retention policy by deleting conversations older than the
    /// configured maximum age. Returns the number of deleted conversations.
    pub fn enforce_retention(&self) -> Result<usize> {
        if !self.retention.enabled {
            return Ok(0);
        }

        let cutoff = Utc::now() - Duration::days(self.retention.max_age_days as i64);
        let cutoff_str = cutoff.to_rfc3339();

        let conn = self.conn.lock();
        let affected = conn.execute(
            "DELETE FROM conversations WHERE updated_at < ?1",
            rusqlite::params![cutoff_str],
        )?;

        if affected > 0 {
            tracing::info!(
                deleted = affected,
                max_age_days = self.retention.max_age_days,
                "Retention policy enforced"
            );
        }

        Ok(affected)
    }
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

fn parse_dt(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
}

fn shellexpand_path(raw: &str) -> PathBuf {
    if raw.starts_with("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(&raw[2..]);
        }
    }
    PathBuf::from(raw)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_store() -> HistoryStore {
        HistoryStore::in_memory(RetentionPolicy::default()).unwrap()
    }

    fn make_messages(n: usize) -> Vec<StoredMessage> {
        (0..n)
            .map(|i| StoredMessage {
                id: 0,
                conversation_id: String::new(),
                role: if i % 2 == 0 { "user" } else { "assistant" }.to_string(),
                content: format!("Message {}", i),
                tool_calls: serde_json::json!([]),
                timestamp: Utc::now(),
            })
            .collect()
    }

    #[test]
    fn test_save_and_load_conversation() {
        let store = make_store();
        let msgs = make_messages(4);
        store
            .save_conversation("conv1", "Test Chat", &msgs, None)
            .unwrap();

        let (conv, loaded_msgs) = store.load_conversation("conv1").unwrap().unwrap();
        assert_eq!(conv.id, "conv1");
        assert_eq!(conv.title, "Test Chat");
        assert_eq!(loaded_msgs.len(), 4);
        assert_eq!(loaded_msgs[0].content, "Message 0");
    }

    #[test]
    fn test_list_conversations() {
        let store = make_store();
        store
            .save_conversation("a", "Alpha", &make_messages(2), None)
            .unwrap();
        store
            .save_conversation("b", "Beta", &make_messages(3), None)
            .unwrap();

        let list = store.list_conversations(10, 0).unwrap();
        assert_eq!(list.len(), 2);
        // Most recently updated first
        assert_eq!(list[0].id, "b");
    }

    #[test]
    fn test_delete_conversation() {
        let store = make_store();
        store
            .save_conversation("del1", "To Delete", &make_messages(1), None)
            .unwrap();

        assert!(store.delete_conversation("del1").unwrap());
        assert!(store.load_conversation("del1").unwrap().is_none());
        assert!(!store.delete_conversation("del1").unwrap()); // already gone
    }

    #[test]
    fn test_search_history() {
        let store = make_store();
        let msgs = vec![StoredMessage {
            id: 0,
            conversation_id: String::new(),
            role: "user".to_string(),
            content: "How do I configure Kubernetes?".to_string(),
            tool_calls: serde_json::json!([]),
            timestamp: Utc::now(),
        }];
        store
            .save_conversation("k8s", "K8s Help", &msgs, None)
            .unwrap();
        store
            .save_conversation("other", "Unrelated", &make_messages(1), None)
            .unwrap();

        let results = store.search_history("Kubernetes", 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "k8s");
    }

    #[test]
    fn test_export_json() {
        let store = make_store();
        store
            .save_conversation("exp1", "Export Test", &make_messages(2), None)
            .unwrap();

        let json = store.export("exp1", ExportFormat::Json).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["conversation"]["id"], "exp1");
        assert_eq!(parsed["messages"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn test_export_jsonl() {
        let store = make_store();
        store
            .save_conversation("exp2", "JSONL Test", &make_messages(3), None)
            .unwrap();

        let jsonl = store.export("exp2", ExportFormat::JsonLines).unwrap();
        let lines: Vec<&str> = jsonl.trim().lines().collect();
        // 1 header + 3 messages = 4 lines
        assert_eq!(lines.len(), 4);
    }

    #[test]
    fn test_compress_decompress() {
        let store = make_store();
        let msgs = make_messages(10);
        store
            .save_conversation("cmp1", "Compression Test", &msgs, None)
            .unwrap();

        let compressed = store.compress_conversation("cmp1").unwrap();
        assert!(!compressed.is_empty());

        let (conv, decompressed_msgs) =
            HistoryStore::decompress_conversation(&compressed).unwrap();
        assert_eq!(conv.id, "cmp1");
        assert_eq!(decompressed_msgs.len(), 10);
    }

    #[test]
    fn test_upsert_replaces_messages() {
        let store = make_store();
        store
            .save_conversation("up1", "First", &make_messages(2), None)
            .unwrap();
        store
            .save_conversation("up1", "Updated Title", &make_messages(5), None)
            .unwrap();

        let (conv, msgs) = store.load_conversation("up1").unwrap().unwrap();
        assert_eq!(conv.title, "Updated Title");
        assert_eq!(msgs.len(), 5);
    }

    #[test]
    fn test_load_nonexistent() {
        let store = make_store();
        assert!(store.load_conversation("no-such-id").unwrap().is_none());
    }
}
