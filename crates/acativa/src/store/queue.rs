//! SQLite-backed command queue contracts for the event-driven workflow host.
//!
//! Queue rows are append-only facts.  A claim changes only delivery state and
//! can be recovered after a host disappears; replay always reads the durable
//! cursor log instead of relying on an in-memory channel.

use anyhow::{Result, anyhow, ensure};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt::Display;

use crate::routing::{ChannelKind, QueueBounds, QueueCapacityExceeded, QueuedItem};

use super::store::{StoreDialect, StrategyStore};

const DEFAULT_LEASE_MS: i64 = 5 * 60 * 1000;

/// Storage error for the durable queue.  Capacity remains a typed runtime
/// outcome; SQLite and malformed persisted rows are returned as storage facts.
#[derive(Debug, thiserror::Error)]
pub enum QueueStoreError {
    #[error("{0}")]
    Capacity(#[from] QueueCapacityExceeded),
    #[error("workflow queue storage failed: {0}")]
    Storage(String),
}

impl QueueStoreError {
    fn storage(error: impl Display) -> Self {
        Self::Storage(error.to_string())
    }
}

impl From<anyhow::Error> for QueueStoreError {
    fn from(error: anyhow::Error) -> Self {
        Self::storage(error)
    }
}

/// A durable claim.  The caller must acknowledge or release it after the
/// external effect reaches its own safe boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DurableQueueLease {
    pub item: QueuedItem,
    pub claimant: String,
    pub lease_until_unix_ms: i64,
}

/// Queue counts used for bounded admission and diagnostics.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DurableQueueStats {
    pub pending_control: usize,
    pub pending_data: usize,
    pub active_control_bytes: usize,
    pub active_data_bytes: usize,
    pub next_cursor: u64,
}

/// The durable replay shape is deliberately the same as the runtime queue
/// item.  No second message vocabulary is introduced at the storage boundary.
pub type QueueReplay = Vec<QueuedItem>;

#[derive(Clone, Debug)]
pub struct DurableQueue {
    store: StrategyStore,
}

impl DurableQueue {
    pub(crate) fn from_store(store: StrategyStore) -> Self {
        Self { store }
    }

    pub fn open(portable_root: &std::path::Path, dialect: &StoreDialect) -> Result<Self> {
        Ok(Self::from_store(StrategyStore::open(
            portable_root,
            dialect,
        )?))
    }

    pub fn enqueue(
        &self,
        channel: ChannelKind,
        item_id: &str,
        content: Value,
        timestamp_unix_ms: i64,
        bounds: QueueBounds,
    ) -> std::result::Result<QueuedItem, QueueStoreError> {
        self.store.with_connection_typed(
            |connection| -> std::result::Result<QueuedItem, QueueStoreError> {
                let transaction = connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(QueueStoreError::storage)?;
                let item = enqueue_in_transaction(
                    &transaction,
                    channel,
                    item_id,
                    &content,
                    timestamp_unix_ms,
                    bounds,
                )?;
                transaction.commit().map_err(QueueStoreError::storage)?;
                Ok(item)
            },
        )
    }

    /// Claim one item using a persisted control streak so fair service survives
    /// a process restart.  Expired claims return to the pending pool first.
    pub fn claim_next(
        &self,
        claimant: &str,
        now_unix_ms: i64,
        lease_until_unix_ms: i64,
        control_quantum: usize,
    ) -> std::result::Result<Option<DurableQueueLease>, QueueStoreError> {
        ensure_valid_id(claimant).map_err(QueueStoreError::storage)?;
        if lease_until_unix_ms <= now_unix_ms {
            return Err(QueueStoreError::storage("workflow_queue_lease_invalid"));
        }
        self.store.with_connection_typed(
            |connection| -> std::result::Result<Option<DurableQueueLease>, QueueStoreError> {
                let transaction = connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(QueueStoreError::storage)?;
                transaction
                    .execute(
                        "UPDATE workflow_queue SET status='pending', claimant=NULL, lease_until=NULL
                         WHERE status='claimed' AND lease_until IS NOT NULL AND lease_until<=?1",
                        params![now_unix_ms],
                    )
                    .map_err(QueueStoreError::storage)?;
                let (control_pending, data_pending): (i64, i64) = transaction
                    .query_row(
                        "SELECT
                           COALESCE(SUM(channel='control'), 0),
                           COALESCE(SUM(channel='data'), 0)
                         FROM workflow_queue WHERE status='pending'",
                        [],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .map_err(QueueStoreError::storage)?;
                if control_pending == 0 && data_pending == 0 {
                    transaction.commit().map_err(QueueStoreError::storage)?;
                    return Ok(None);
                }
                let streak: i64 = transaction
                    .query_row(
                        "SELECT value FROM workflow_queue_meta WHERE key='control_streak'",
                        [],
                        |row| row.get(0),
                    )
                    .map_err(QueueStoreError::storage)?;
                let quantum = control_quantum.max(1) as i64;
                let channel = if control_pending > 0 && (data_pending == 0 || streak < quantum) {
                    ChannelKind::Control
                } else {
                    ChannelKind::Data
                };
                let row = transaction
                    .query_row(
                        "SELECT channel, payload_json, cursor, item_id, payload_bytes, enqueued_at
                         FROM workflow_queue
                         WHERE status='pending' AND channel=?1
                         ORDER BY cursor ASC LIMIT 1",
                        params![channel_wire(channel)],
                        queue_item_row,
                    )
                    .optional()
                    .map_err(QueueStoreError::storage)?;
                let Some(row) = row else {
                    transaction.commit().map_err(QueueStoreError::storage)?;
                    return Ok(None);
                };
                let item = row_to_item(row).map_err(QueueStoreError::storage)?;
                let changed = transaction
                    .execute(
                        "UPDATE workflow_queue SET status='claimed', claimant=?2, lease_until=?3
                         WHERE cursor=?1 AND status='pending'",
                        params![item.cursor as i64, claimant, lease_until_unix_ms],
                    )
                    .map_err(QueueStoreError::storage)?;
                if changed != 1 {
                    return Err(QueueStoreError::storage("workflow_queue_claim_lost"));
                }
                let next_streak = if channel == ChannelKind::Control {
                    streak.saturating_add(1)
                } else {
                    0
                };
                transaction
                    .execute(
                        "UPDATE workflow_queue_meta SET value=?2 WHERE key='control_streak'",
                        params!["control_streak", next_streak],
                    )
                    .map_err(QueueStoreError::storage)?;
                transaction.commit().map_err(QueueStoreError::storage)?;
                Ok(Some(DurableQueueLease {
                    item,
                    claimant: claimant.to_owned(),
                    lease_until_unix_ms,
                }))
            },
        )
    }

    pub fn acknowledge(
        &self,
        cursor: u64,
        claimant: &str,
    ) -> std::result::Result<(), QueueStoreError> {
        self.store
            .with_connection_typed(|connection| -> std::result::Result<(), QueueStoreError> {
                let changed = connection
                    .execute(
                        "DELETE FROM workflow_queue
                         WHERE cursor=?1 AND status='claimed' AND claimant=?2",
                        params![cursor as i64, claimant],
                    )
                    .map_err(QueueStoreError::storage)?;
                if changed != 1 {
                    return Err(QueueStoreError::storage("workflow_queue_claim_lost"));
                }
                Ok(())
            })
    }

    pub fn release(&self, cursor: u64, claimant: &str) -> std::result::Result<(), QueueStoreError> {
        self.store
            .with_connection_typed(|connection| -> std::result::Result<(), QueueStoreError> {
                let changed = connection
                    .execute(
                        "UPDATE workflow_queue SET status='pending', claimant=NULL, lease_until=NULL
                         WHERE cursor=?1 AND status='claimed' AND claimant=?2",
                        params![cursor as i64, claimant],
                    )
                    .map_err(QueueStoreError::storage)?;
                if changed != 1 {
                    return Err(QueueStoreError::storage("workflow_queue_claim_lost"));
                }
                Ok(())
            })
    }

    /// Consume one item atomically for short local consumers.  Long effects
    /// should use `claim_next` and `acknowledge` instead.
    pub fn dequeue(
        &self,
        now_unix_ms: i64,
        control_quantum: usize,
    ) -> std::result::Result<Option<QueuedItem>, QueueStoreError> {
        let claimant = format!("dequeue-{now_unix_ms}");
        let Some(lease) = self.claim_next(
            &claimant,
            now_unix_ms,
            now_unix_ms.saturating_add(DEFAULT_LEASE_MS),
            control_quantum,
        )?
        else {
            return Ok(None);
        };
        self.acknowledge(lease.item.cursor, &claimant)?;
        Ok(Some(lease.item))
    }

    pub fn replay_from_cursor(&self, from_cursor: u64) -> Result<QueueReplay> {
        self.store.with_connection(|connection| {
            let mut statement = connection.prepare(
                "SELECT channel, payload_json, cursor, item_id, payload_bytes, enqueued_at
                 FROM workflow_queue WHERE cursor>=?1 ORDER BY cursor ASC",
            )?;
            let rows = statement.query_map(params![from_cursor as i64], queue_item_row)?;
            rows.map(|row| row.map_err(Into::into).and_then(row_to_item))
                .collect()
        })
    }

    pub fn stats(&self) -> Result<DurableQueueStats> {
        self.store.with_connection(|connection| {
            let (control_entries, data_entries, control_bytes, data_bytes): (i64, i64, i64, i64) =
                connection.query_row(
                    "SELECT
                       COALESCE(SUM(channel='control'), 0),
                       COALESCE(SUM(channel='data'), 0),
                       COALESCE(SUM(CASE WHEN channel='control' THEN payload_bytes ELSE 0 END), 0),
                       COALESCE(SUM(CASE WHEN channel='data' THEN payload_bytes ELSE 0 END), 0)
                     FROM workflow_queue WHERE status IN ('pending', 'claimed')",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )?;
            // AUTOINCREMENT's high-water mark, not MAX(cursor): acknowledged
            // rows are deleted, so the surviving rows no longer bound the
            // next cursor.
            let next_cursor: i64 = connection.query_row(
                "SELECT COALESCE(
                   (SELECT seq FROM sqlite_sequence WHERE name='workflow_queue'), 0) + 1",
                [],
                |row| row.get(0),
            )?;
            Ok(DurableQueueStats {
                pending_control: control_entries.max(0) as usize,
                pending_data: data_entries.max(0) as usize,
                active_control_bytes: control_bytes.max(0) as usize,
                active_data_bytes: data_bytes.max(0) as usize,
                next_cursor: next_cursor.max(0) as u64,
            })
        })
    }

    pub fn current_cursor(&self) -> Result<u64> {
        Ok(self.stats()?.next_cursor)
    }
}

pub(crate) fn enqueue_in_transaction(
    transaction: &Transaction<'_>,
    channel: ChannelKind,
    item_id: &str,
    content: &Value,
    timestamp_unix_ms: i64,
    bounds: QueueBounds,
) -> std::result::Result<QueuedItem, QueueStoreError> {
    ensure_valid_id(item_id).map_err(QueueStoreError::storage)?;
    let content_json = serde_json::to_string(content).map_err(QueueStoreError::storage)?;
    let payload_bytes = content_json.len();
    if let Some(existing) = transaction
        .query_row(
            "SELECT channel, payload_json, cursor, item_id, payload_bytes, enqueued_at
             FROM workflow_queue WHERE item_id=?1",
            params![item_id],
            queue_item_row,
        )
        .optional()
        .map_err(QueueStoreError::storage)?
    {
        let (existing_channel, existing_json, _, _, _, _) = existing.clone();
        if existing_channel == channel_wire(channel) && existing_json == content_json {
            return row_to_item(existing).map_err(QueueStoreError::storage);
        }
        return Err(QueueStoreError::storage(
            "workflow_queue_idempotency_conflict",
        ));
    }

    let (entries, bytes): (i64, i64) = transaction
        .query_row(
            "SELECT COUNT(*), COALESCE(SUM(payload_bytes), 0)
             FROM workflow_queue WHERE status IN ('pending', 'claimed') AND channel=?1",
            params![channel_wire(channel)],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(QueueStoreError::storage)?;
    if entries as usize + 1 > bounds.max_entries
        || bytes as usize + payload_bytes > bounds.max_bytes
    {
        return Err(QueueStoreError::Capacity(QueueCapacityExceeded {
            channel,
            current_entries: entries.max(0) as usize,
            current_bytes: bytes.max(0) as usize,
            limit_entries: bounds.max_entries,
            limit_bytes: bounds.max_bytes,
        }));
    }

    transaction
        .execute(
            "INSERT INTO workflow_queue(
               channel, item_id, payload_json, payload_bytes, enqueued_at,
               status, claimant, lease_until
             ) VALUES (?1, ?2, ?3, ?4, ?5, 'pending', NULL, NULL)",
            params![
                channel_wire(channel),
                item_id,
                content_json,
                payload_bytes as i64,
                timestamp_unix_ms,
            ],
        )
        .map_err(QueueStoreError::storage)?;
    let item = transaction
        .query_row(
            "SELECT channel, payload_json, cursor, item_id, payload_bytes, enqueued_at
             FROM workflow_queue WHERE item_id=?1",
            params![item_id],
            queue_item_row,
        )
        .map_err(QueueStoreError::storage)?;
    row_to_item(item).map_err(QueueStoreError::storage)
}

pub(crate) fn initialize_schema(connection: &rusqlite::Connection) -> Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS workflow_store_meta(
           key TEXT PRIMARY KEY, value INTEGER NOT NULL
         );
         INSERT INTO workflow_store_meta(key, value) VALUES ('version', 1)
           ON CONFLICT(key) DO NOTHING;
         CREATE TABLE IF NOT EXISTS workflow_queue(
           cursor INTEGER PRIMARY KEY AUTOINCREMENT,
           channel TEXT NOT NULL CHECK(channel IN ('control', 'data')),
           item_id TEXT NOT NULL UNIQUE,
           payload_json TEXT NOT NULL,
           payload_bytes INTEGER NOT NULL,
           enqueued_at INTEGER NOT NULL,
           status TEXT NOT NULL CHECK(status IN ('pending', 'claimed', 'completed')),
           claimant TEXT,
           lease_until INTEGER
         );
         CREATE INDEX IF NOT EXISTS workflow_queue_pending_idx
           ON workflow_queue(status, channel, cursor);
         CREATE INDEX IF NOT EXISTS workflow_queue_lease_idx
           ON workflow_queue(status, lease_until);
         CREATE TABLE IF NOT EXISTS workflow_queue_meta(
           key TEXT PRIMARY KEY, value INTEGER NOT NULL
         );
         INSERT INTO workflow_queue_meta(key, value) VALUES ('control_streak', 0)
           ON CONFLICT(key) DO NOTHING;",
    )?;
    Ok(())
}

fn channel_wire(channel: ChannelKind) -> &'static str {
    match channel {
        ChannelKind::Control => "control",
        ChannelKind::Data => "data",
    }
}

fn parse_channel(value: &str) -> Result<ChannelKind> {
    match value {
        "control" => Ok(ChannelKind::Control),
        "data" => Ok(ChannelKind::Data),
        _ => Err(anyhow!("workflow_queue_channel_invalid")),
    }
}

fn ensure_valid_id(value: &str) -> Result<()> {
    ensure!(
        !value.trim().is_empty()
            && value == value.trim()
            && value.len() <= 160
            && !value.chars().any(char::is_control),
        "workflow_queue_id_invalid"
    );
    Ok(())
}

type QueueRow = (String, String, i64, String, i64, i64);

fn queue_item_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<QueueRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
    ))
}

fn row_to_item(row: QueueRow) -> Result<QueuedItem> {
    Ok(QueuedItem {
        channel: parse_channel(&row.0)?,
        content: serde_json::from_str(&row.1)?,
        cursor: row.2.max(0) as u64,
        item_id: row.3,
        payload_bytes: row.4.max(0) as usize,
        enqueued_at_unix_ms: row.5,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;
    use uuid::Uuid;

    #[test]
    fn durable_queue_reopens_with_fair_claims_and_recoverable_leases() {
        let root = std::env::temp_dir().join(format!("acativa-workflow-queue-{}", Uuid::new_v4()));
        let bounds = QueueBounds {
            max_entries: 1,
            max_bytes: 1024,
        };
        let control_cursor = {
            let store = StrategyStore::open(&root, &StoreDialect::generic()).unwrap();
            let queue = store.durable_queue();
            let control = queue
                .enqueue(
                    ChannelKind::Control,
                    "control-1",
                    json!({"operation": "stop"}),
                    1,
                    bounds,
                )
                .unwrap();
            let duplicate = queue
                .enqueue(
                    ChannelKind::Control,
                    "control-1",
                    json!({"operation": "stop"}),
                    2,
                    bounds,
                )
                .unwrap();
            assert_eq!(duplicate, control);
            assert!(matches!(
                queue.enqueue(
                    ChannelKind::Control,
                    "control-2",
                    json!({"operation": "pause"}),
                    3,
                    bounds,
                ),
                Err(QueueStoreError::Capacity(_))
            ));

            let data = queue
                .enqueue(
                    ChannelKind::Data,
                    "data-1",
                    json!({"input": "payload"}),
                    4,
                    bounds,
                )
                .unwrap();
            let control_lease = queue.claim_next("worker-a", 10, 20, 1).unwrap().unwrap();
            assert_eq!(control_lease.item, control);
            let data_lease = queue.claim_next("worker-a", 11, 21, 1).unwrap().unwrap();
            assert_eq!(data_lease.item, data);
            queue
                .acknowledge(data_lease.item.cursor, "worker-a")
                .unwrap();
            control_lease.item.cursor
        };

        let store = StrategyStore::open(&root, &StoreDialect::generic()).unwrap();
        let queue = store.durable_queue();
        let recovered = queue.claim_next("worker-b", 30, 40, 1).unwrap().unwrap();
        assert_eq!(recovered.item.cursor, control_cursor);
        queue
            .acknowledge(recovered.item.cursor, "worker-b")
            .unwrap();

        // Acknowledged items are deleted, not archived: replay surfaces only
        // what still needs delivery, and the durable history stays bounded.
        let replay = queue.replay_from_cursor(0).unwrap();
        assert!(replay.is_empty());
        let stats = queue.stats().unwrap();
        assert_eq!(stats.pending_control, 0);
        assert_eq!(stats.pending_data, 0);
        assert_eq!(stats.next_cursor, 3);
        drop(queue);
        drop(store);
        let _ = fs::remove_dir_all(root);
    }
}
