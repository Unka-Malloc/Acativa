//! Durable implementation of the controlled-store port.

use anyhow::{Result, ensure};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

use crate::control::{
    AdmissionConflict, AdmissionFences, AdmissionReceipt, ControlOperation, ControlScope,
    ControlledStore, FenceFacts, OperationGrant, evaluate_fences,
};
use crate::routing::{ChannelKind, QueueBounds};

use super::store::{StoreDialect, StrategyStore};
use super::{queue, queue::QueueStoreError};

#[derive(Clone, Debug)]
pub struct DurableControlledStore {
    store: StrategyStore,
}

impl DurableControlledStore {
    pub fn from_store(store: StrategyStore) -> Self {
        Self { store }
    }

    pub fn open(portable_root: &std::path::Path, dialect: &StoreDialect) -> Result<Self> {
        Ok(Self::from_store(StrategyStore::open(
            portable_root,
            dialect,
        )?))
    }

    pub fn store(&self) -> &StrategyStore {
        &self.store
    }

    pub fn set_graph_revision(&self, graph_id: &str, revision: u64) -> Result<()> {
        validate_id(graph_id)?;
        self.store.with_connection(|connection| -> Result<()> {
            connection.execute(
                "INSERT INTO workflow_graph_state(graph_id, graph_revision, barrier_active)
                 VALUES (?1, ?2, 0)
                 ON CONFLICT(graph_id) DO UPDATE SET graph_revision=excluded.graph_revision",
                params![graph_id, revision as i64],
            )?;
            Ok(())
        })
    }

    pub fn set_node_control_revision(
        &self,
        graph_id: &str,
        node_id: &str,
        revision: u64,
    ) -> Result<()> {
        validate_id(graph_id)?;
        validate_id(node_id)?;
        self.store.with_connection(|connection| -> Result<()> {
            connection.execute(
                "INSERT INTO workflow_node_state(
                   graph_id, node_id, control_revision, generation, lifecycle_state,
                   pause_negotiating
                 ) VALUES (?1, ?2, ?3, 1, 'ready', 0)
                 ON CONFLICT(graph_id, node_id)
                 DO UPDATE SET control_revision=excluded.control_revision",
                params![graph_id, node_id, revision as i64],
            )?;
            Ok(())
        })
    }

    pub fn mark_invocation_settled(
        &self,
        graph_id: &str,
        node_id: &str,
        invocation_id: &str,
    ) -> Result<()> {
        validate_id(graph_id)?;
        validate_id(node_id)?;
        validate_id(invocation_id)?;
        self.store.with_connection(|connection| -> Result<()> {
            connection.execute(
                "INSERT INTO workflow_invocations(graph_id, node_id, invocation_id, settled)
                 VALUES (?1, ?2, ?3, 1)
                 ON CONFLICT(graph_id, node_id, invocation_id) DO UPDATE SET settled=1",
                params![graph_id, node_id, invocation_id],
            )?;
            Ok(())
        })
    }

    pub fn mark_stop_requested(&self, graph_id: &str, target: &str) -> Result<()> {
        validate_id(graph_id)?;
        validate_id(target)?;
        self.store.with_connection(|connection| -> Result<()> {
            connection.execute(
                "INSERT OR IGNORE INTO workflow_stop_requests(graph_id, target)
                 VALUES (?1, ?2)",
                params![graph_id, target],
            )?;
            Ok(())
        })
    }

    pub fn mark_pause_negotiating(&self, graph_id: &str, target: &str) -> Result<()> {
        validate_id(graph_id)?;
        validate_id(target)?;
        self.store.with_connection(|connection| -> Result<()> {
            connection.execute(
                "INSERT INTO workflow_pause_requests(graph_id, target, active)
                 VALUES (?1, ?2, 1)
                 ON CONFLICT(graph_id, target) DO UPDATE SET active=1",
                params![graph_id, target],
            )?;
            Ok(())
        })
    }

    pub fn clear_pause_negotiating(&self, graph_id: &str, target: &str) -> Result<bool> {
        validate_id(graph_id)?;
        validate_id(target)?;
        self.store.with_connection(|connection| {
            Ok(connection.execute(
                "UPDATE workflow_pause_requests SET active=0
                 WHERE graph_id=?1 AND target=?2 AND active=1",
                params![graph_id, target],
            )? == 1)
        })
    }

    pub fn set_target_generation(
        &self,
        graph_id: &str,
        target: &str,
        generation: u64,
    ) -> Result<()> {
        validate_id(graph_id)?;
        validate_id(target)?;
        self.store.with_connection(|connection| -> Result<()> {
            connection.execute(
                "INSERT INTO workflow_node_state(
                   graph_id, node_id, control_revision, generation, lifecycle_state,
                   pause_negotiating
                 ) VALUES (?1, ?2, 0, ?3, 'ready', 0)
                 ON CONFLICT(graph_id, node_id)
                 DO UPDATE SET generation=excluded.generation",
                params![graph_id, target, generation as i64],
            )?;
            Ok(())
        })
    }

    pub fn set_graph_barrier(&self, graph_id: &str, active: bool) -> Result<()> {
        validate_id(graph_id)?;
        self.store.with_connection(|connection| -> Result<()> {
            connection.execute(
                "INSERT INTO workflow_graph_state(graph_id, graph_revision, barrier_active)
                 VALUES (?1, 1, ?2)
                 ON CONFLICT(graph_id) DO UPDATE SET barrier_active=excluded.barrier_active",
                params![graph_id, i64::from(active)],
            )?;
            Ok(())
        })
    }

    pub fn revoke_grant(&self, principal_id: &str, grant: &OperationGrant) -> Result<()> {
        validate_id(principal_id)?;
        self.store.with_connection(|connection| {
            connection.execute(
                "INSERT OR IGNORE INTO workflow_revoked_grants(principal_id, grant_json)
                 VALUES (?1, ?2)",
                params![principal_id, serde_json::to_string(grant)?],
            )?;
            Ok(())
        })
    }
}

/// An authorization or fence read that could not be evaluated is a storage
/// failure, never a "false": an admission decided on a failed read would be a
/// fail-open gate, so every lookup propagates as [`AdmissionConflict::Storage`].
fn storage_conflict(error: anyhow::Error) -> AdmissionConflict {
    AdmissionConflict::Storage {
        reason: error.to_string(),
    }
}

impl ControlledStore for DurableControlledStore {
    fn get_graph_revision(&self, graph_id: &str) -> Result<Option<u64>, AdmissionConflict> {
        self.store
            .with_connection(|connection| -> Result<Option<u64>> {
                Ok(connection
                    .query_row(
                        "SELECT graph_revision FROM workflow_graph_state WHERE graph_id=?1",
                        params![graph_id],
                        |row| row.get::<_, i64>(0),
                    )
                    .optional()?
                    .map(|value| value.max(0) as u64))
            })
            .map_err(storage_conflict)
    }

    fn get_node_control_revision(
        &self,
        graph_id: &str,
        node_id: &str,
    ) -> Result<Option<u64>, AdmissionConflict> {
        self.store
            .with_connection(|connection| -> Result<Option<u64>> {
                Ok(connection
                    .query_row(
                        "SELECT control_revision FROM workflow_node_state
                         WHERE graph_id=?1 AND node_id=?2",
                        params![graph_id, node_id],
                        |row| row.get::<_, i64>(0),
                    )
                    .optional()?
                    .map(|value| value.max(0) as u64))
            })
            .map_err(storage_conflict)
    }

    fn is_invocation_settled(
        &self,
        graph_id: &str,
        node_id: &str,
        invocation_id: &str,
    ) -> Result<bool, AdmissionConflict> {
        self.store
            .with_connection(|connection| -> Result<bool> {
                let count: i64 = connection.query_row(
                    "SELECT COUNT(*) FROM workflow_invocations
                     WHERE graph_id=?1 AND node_id=?2 AND invocation_id=?3 AND settled=1",
                    params![graph_id, node_id, invocation_id],
                    |row| row.get(0),
                )?;
                Ok(count != 0)
            })
            .map_err(storage_conflict)
    }

    fn is_stop_requested(&self, graph_id: &str, target: &str) -> Result<bool, AdmissionConflict> {
        self.store
            .with_connection(|connection| -> Result<bool> {
                let count: i64 = connection.query_row(
                    "SELECT COUNT(*) FROM workflow_stop_requests
                     WHERE graph_id=?1 AND target IN (?2, 'graph')",
                    params![graph_id, target],
                    |row| row.get(0),
                )?;
                Ok(count != 0)
            })
            .map_err(storage_conflict)
    }

    fn is_pause_negotiating(
        &self,
        graph_id: &str,
        target: &str,
    ) -> Result<bool, AdmissionConflict> {
        self.store
            .with_connection(|connection| -> Result<bool> {
                let count: i64 = connection.query_row(
                    "SELECT COUNT(*) FROM workflow_pause_requests
                     WHERE graph_id=?1 AND target=?2 AND active=1",
                    params![graph_id, target],
                    |row| row.get(0),
                )?;
                Ok(count != 0)
            })
            .map_err(storage_conflict)
    }

    fn is_graph_barrier_active(&self, graph_id: &str) -> Result<bool, AdmissionConflict> {
        self.store
            .with_connection(|connection| -> Result<bool> {
                Ok(connection
                    .query_row(
                        "SELECT barrier_active FROM workflow_graph_state WHERE graph_id=?1",
                        params![graph_id],
                        |row| row.get::<_, i64>(0),
                    )
                    .optional()?
                    .is_some_and(|value| value == 1))
            })
            .map_err(storage_conflict)
    }

    fn get_target_generation(
        &self,
        graph_id: &str,
        target: &str,
    ) -> Result<Option<u64>, AdmissionConflict> {
        self.store
            .with_connection(|connection| -> Result<Option<u64>> {
                Ok(connection
                    .query_row(
                        "SELECT generation FROM workflow_node_state
                         WHERE graph_id=?1 AND node_id=?2",
                        params![graph_id, target],
                        |row| row.get::<_, i64>(0),
                    )
                    .optional()?
                    .map(|value| value.max(0) as u64))
            })
            .map_err(storage_conflict)
    }

    fn is_grant_revoked(
        &self,
        principal_id: &str,
        grant: &OperationGrant,
    ) -> Result<bool, AdmissionConflict> {
        self.store
            .with_connection(|connection| -> Result<bool> {
                let grant_json = serde_json::to_string(grant)?;
                let count: i64 = connection.query_row(
                    "SELECT COUNT(*) FROM workflow_revoked_grants
                     WHERE principal_id=?1 AND grant_json=?2",
                    params![principal_id, grant_json],
                    |row| row.get(0),
                )?;
                Ok(count != 0)
            })
            .map_err(storage_conflict)
    }

    fn find_idempotency_record(
        &self,
        request_id: &str,
    ) -> Result<Option<(AdmissionReceipt, String)>, AdmissionConflict> {
        self.store
            .with_connection(|connection| -> Result<Option<(AdmissionReceipt, String)>> {
                let value: Option<(String, String)> = connection
                    .query_row(
                        "SELECT receipt_json, payload_digest FROM workflow_control_admissions
                         WHERE request_id=?1",
                        params![request_id],
                        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                    )
                    .optional()?;
                value
                    .map(|(receipt, digest)| Ok((serde_json::from_str(&receipt)?, digest)))
                    .transpose()
            })
            .map_err(storage_conflict)
    }

    fn record_admission(
        &mut self,
        receipt: &mut AdmissionReceipt,
        payload_digest: String,
        expected_control_revision: Option<u64>,
        fences: &AdmissionFences,
    ) -> Result<(), AdmissionConflict> {
        self.store.with_connection_typed(
            |connection| -> std::result::Result<(), AdmissionConflict> {
                let transaction = connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(AdmissionConflict::from)?;
                // Idempotency is re-read under the write lock: two identical
                // requests admitted back-to-back converge on the recorded
                // receipt instead of tripping the unique constraint.
                let existing: Option<(String, String)> = transaction
                    .query_row(
                        "SELECT receipt_json, payload_digest FROM workflow_control_admissions
                         WHERE request_id=?1",
                        params![receipt.request_id],
                        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                    )
                    .optional()?;
                if let Some((receipt_json, existing_digest)) = existing {
                    if existing_digest == payload_digest {
                        *receipt = serde_json::from_str(&receipt_json)?;
                        receipt.is_replay = true;
                        transaction.commit()?;
                        return Ok(());
                    }
                    let existing_receipt: AdmissionReceipt = serde_json::from_str(&receipt_json)?;
                    return Err(AdmissionConflict::IdempotencyMismatch {
                        request_id: receipt.request_id.clone(),
                        existing_author: existing_receipt.author_principal_id,
                        reason: "request_id reused with different command payload".to_string(),
                    });
                }
                // Every admission fence is re-evaluated under the write lock
                // that commits this admission: a revocation, stop, pause,
                // barrier or generation change committed between the proxy's
                // prechecks and now still rejects the operation.
                let mut covering_grants_all_revoked = !fences.covering_grants.is_empty();
                for grant in &fences.covering_grants {
                    let count: i64 = transaction.query_row(
                        "SELECT COUNT(*) FROM workflow_revoked_grants
                         WHERE principal_id=?1 AND grant_json=?2",
                        params![fences.principal_id, serde_json::to_string(grant)?],
                        |row| row.get(0),
                    )?;
                    if count == 0 {
                        covering_grants_all_revoked = false;
                        break;
                    }
                }
                let barrier_active: i64 = transaction
                    .query_row(
                        "SELECT barrier_active FROM workflow_graph_state WHERE graph_id=?1",
                        params![receipt.graph_id],
                        |row| row.get(0),
                    )
                    .optional()?
                    .unwrap_or(0);
                let stop_hit = |target: &str| -> Result<bool, rusqlite::Error> {
                    let count: i64 = transaction.query_row(
                        "SELECT COUNT(*) FROM workflow_stop_requests
                         WHERE graph_id=?1 AND target IN (?2, 'graph')",
                        params![receipt.graph_id, target],
                        |row| row.get(0),
                    )?;
                    Ok(count != 0)
                };
                let stopped_scope = if stop_hit(&fences.target_scope)? {
                    Some(fences.target_scope.clone())
                } else {
                    match &fences.invocation_scope {
                        Some(key) if stop_hit(key)? => Some(key.clone()),
                        _ => None,
                    }
                };
                let invocation_settled = match (&receipt.operation, &receipt.target_node_id) {
                    (ControlOperation::Steer { invocation_id, .. }, Some(node)) => {
                        let count: i64 = transaction.query_row(
                            "SELECT COUNT(*) FROM workflow_invocations
                             WHERE graph_id=?1 AND node_id=?2 AND invocation_id=?3 AND settled=1",
                            params![receipt.graph_id, node, invocation_id],
                            |row| row.get(0),
                        )?;
                        count != 0
                    }
                    _ => false,
                };
                let pause_negotiating: i64 = transaction.query_row(
                    "SELECT COUNT(*) FROM workflow_pause_requests
                     WHERE graph_id=?1 AND target=?2 AND active=1",
                    params![receipt.graph_id, fences.target_scope],
                    |row| row.get(0),
                )?;
                let graph_revision: i64 = transaction
                    .query_row(
                        "SELECT graph_revision FROM workflow_graph_state WHERE graph_id=?1",
                        params![receipt.graph_id],
                        |row| row.get(0),
                    )
                    .optional()?
                    .unwrap_or(1);
                let target_generation: i64 = transaction
                    .query_row(
                        "SELECT generation FROM workflow_node_state
                         WHERE graph_id=?1 AND node_id=?2",
                        params![receipt.graph_id, fences.target_scope],
                        |row| row.get(0),
                    )
                    .optional()?
                    .unwrap_or(1);
                evaluate_fences(
                    receipt,
                    fences,
                    FenceFacts {
                        covering_grants_all_revoked,
                        barrier_active: barrier_active == 1,
                        stopped_scope,
                        invocation_settled,
                        pause_negotiating: pause_negotiating != 0,
                        graph_revision: graph_revision.max(0) as u64,
                        target_generation: target_generation.max(0) as u64,
                    },
                )?;
                receipt.graph_revision = graph_revision.max(0) as u64;
                // The exclusive-control fence is a compare-and-swap, not a
                // pre-txn read: the persisted revision is re-read under the write
                // lock, so two proxies that both observed the same revision cannot
                // both admit.
                if let Some(node) = receipt.target_node_id.as_deref() {
                    let persisted: i64 = transaction
                        .query_row(
                            "SELECT control_revision FROM workflow_node_state
                         WHERE graph_id=?1 AND node_id=?2",
                            params![receipt.graph_id, node],
                            |row| row.get(0),
                        )
                        .optional()?
                        .unwrap_or(0);
                    let persisted = persisted.max(0) as u64;
                    if let Some(expected) = expected_control_revision
                        && expected != persisted
                    {
                        return Err(AdmissionConflict::ControlRevisionConflict {
                            target_node_id: node.to_string(),
                            expected,
                            current: persisted,
                            reason: "competing exclusive control revision conflict".to_string(),
                        });
                    }
                    receipt.control_revision = persisted + 1;
                }
                let next_sequence: i64 = transaction.query_row(
                    "SELECT COALESCE(MAX(admitted_sequence), 0) + 1
                 FROM workflow_control_admissions",
                    [],
                    |row| row.get(0),
                )?;
                receipt.admitted_sequence = next_sequence.max(0) as u64;
                transaction.execute(
                    "INSERT INTO workflow_control_admissions(
                   request_id, admitted_sequence, receipt_json, payload_digest
                 ) VALUES (?1, ?2, ?3, ?4)",
                    params![
                        receipt.request_id,
                        receipt.admitted_sequence as i64,
                        serde_json::to_string(receipt)?,
                        payload_digest,
                    ],
                )?;
                transaction.execute(
                    "INSERT INTO workflow_graph_state(graph_id, graph_revision, barrier_active)
                 VALUES (?1, ?2, 0)
                 ON CONFLICT(graph_id) DO NOTHING",
                    params![receipt.graph_id, receipt.graph_revision as i64],
                )?;
                if let Some(node) = receipt.target_node_id.as_deref() {
                    transaction.execute(
                        "INSERT INTO workflow_node_state(
                       graph_id, node_id, control_revision, generation, lifecycle_state,
                       pause_negotiating
                     ) VALUES (?1, ?2, ?3, 1, 'ready', 0)
                     ON CONFLICT(graph_id, node_id)
                     DO UPDATE SET control_revision=excluded.control_revision",
                        params![receipt.graph_id, node, receipt.control_revision as i64],
                    )?;
                }
                match &receipt.operation {
                    ControlOperation::Pause { scope } => {
                        transaction.execute(
                            "INSERT INTO workflow_pause_requests(graph_id, target, active)
                         VALUES (?1, ?2, 1)
                         ON CONFLICT(graph_id, target) DO UPDATE SET active=1",
                            params![receipt.graph_id, pause_target(scope)],
                        )?;
                    }
                    ControlOperation::Stop { scope, .. } => {
                        let target = control_target(scope);
                        transaction.execute(
                            "INSERT OR IGNORE INTO workflow_stop_requests(graph_id, target)
                         VALUES (?1, ?2)",
                            params![receipt.graph_id, target],
                        )?;
                        if matches!(scope, ControlScope::Graph) {
                            transaction.execute(
                            "UPDATE workflow_graph_state SET barrier_active=1 WHERE graph_id=?1",
                            params![receipt.graph_id],
                        )?;
                        }
                    }
                    _ => {}
                }
                let payload = serde_json::to_value(&*receipt)?;
                queue::enqueue_in_transaction(
                    &transaction,
                    ChannelKind::Control,
                    &receipt.request_id,
                    &payload,
                    receipt.admitted_at_unix_ms,
                    QueueBounds::default(),
                )
                .map_err(|error| match error {
                    QueueStoreError::Capacity(capacity) => {
                        AdmissionConflict::QueueCapacity(capacity)
                    }
                    other => AdmissionConflict::Storage {
                        reason: other.to_string(),
                    },
                })?;
                transaction.commit()?;
                Ok(())
            },
        )
    }
}

pub(crate) fn initialize_schema(connection: &rusqlite::Connection) -> Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS workflow_graph_state(
           graph_id TEXT PRIMARY KEY,
           graph_revision INTEGER NOT NULL,
           barrier_active INTEGER NOT NULL
         );
         CREATE TABLE IF NOT EXISTS workflow_node_state(
           graph_id TEXT NOT NULL,
           node_id TEXT NOT NULL,
           control_revision INTEGER NOT NULL,
           generation INTEGER NOT NULL,
           lifecycle_state TEXT NOT NULL,
           pause_negotiating INTEGER NOT NULL,
           PRIMARY KEY(graph_id, node_id)
         );
         CREATE TABLE IF NOT EXISTS workflow_invocations(
           graph_id TEXT NOT NULL,
           node_id TEXT NOT NULL,
           invocation_id TEXT NOT NULL,
           settled INTEGER NOT NULL,
           PRIMARY KEY(graph_id, node_id, invocation_id)
         );
         CREATE TABLE IF NOT EXISTS workflow_stop_requests(
           graph_id TEXT NOT NULL,
           target TEXT NOT NULL,
           PRIMARY KEY(graph_id, target)
         );
         CREATE TABLE IF NOT EXISTS workflow_pause_requests(
           graph_id TEXT NOT NULL,
           target TEXT NOT NULL,
           active INTEGER NOT NULL,
           PRIMARY KEY(graph_id, target)
         );
         CREATE TABLE IF NOT EXISTS workflow_revoked_grants(
           principal_id TEXT NOT NULL,
           grant_json TEXT NOT NULL,
           PRIMARY KEY(principal_id, grant_json)
         );
         CREATE TABLE IF NOT EXISTS workflow_control_admissions(
           request_id TEXT PRIMARY KEY,
           admitted_sequence INTEGER NOT NULL UNIQUE,
           receipt_json TEXT NOT NULL,
           payload_digest TEXT NOT NULL
         );",
    )?;
    Ok(())
}

fn control_target(scope: &ControlScope) -> String {
    match scope {
        ControlScope::Graph => "graph".to_owned(),
        ControlScope::Node(node) => node.clone(),
        ControlScope::Invocation {
            node_id,
            invocation_id,
        } => format!("{node_id}/{invocation_id}"),
    }
}

fn pause_target(scope: &ControlScope) -> String {
    match scope {
        ControlScope::Graph => "graph".to_owned(),
        ControlScope::Node(node) => node.clone(),
        ControlScope::Invocation { node_id, .. } => node_id.clone(),
    }
}

fn validate_id(value: &str) -> Result<()> {
    ensure!(
        !value.trim().is_empty()
            && value == value.trim()
            && value.len() <= 160
            && !value.chars().any(char::is_control),
        "workflow_control_id_invalid"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlledStore;
    use std::fs;
    use uuid::Uuid;

    #[test]
    fn controlled_state_and_admission_receipts_survive_restart() {
        let root =
            std::env::temp_dir().join(format!("acativa-workflow-control-{}", Uuid::new_v4()));
        let grant = OperationGrant::GraphAll;
        {
            let store = StrategyStore::open(&root, &StoreDialect::generic()).unwrap();
            let mut control = store.durable_control();
            control.set_graph_revision("graph-1", 4).unwrap();
            control
                .set_node_control_revision("graph-1", "node-1", 9)
                .unwrap();
            control
                .set_target_generation("graph-1", "node-1", 3)
                .unwrap();
            control
                .mark_invocation_settled("graph-1", "node-1", "inv-1")
                .unwrap();
            control.mark_stop_requested("graph-1", "node-1").unwrap();
            control.mark_pause_negotiating("graph-1", "node-1").unwrap();
            control.revoke_grant("principal-1", &grant).unwrap();

            let mut receipt = AdmissionReceipt {
                admitted_sequence: 0,
                request_id: "request-1".into(),
                graph_id: "graph-1".into(),
                target_node_id: Some("node-1".into()),
                author_principal_id: "principal-1".into(),
                admitted_at_unix_ms: 10,
                operation: ControlOperation::Pause {
                    scope: ControlScope::Invocation {
                        node_id: "node-1".into(),
                        invocation_id: "inv-1".into(),
                    },
                },
                graph_revision: 4,
                control_revision: 9,
                is_replay: false,
            };
            control
                .record_admission(
                    &mut receipt,
                    "digest".into(),
                    Some(9),
                    &AdmissionFences::default(),
                )
                .unwrap();
            assert_eq!(receipt.admitted_sequence, 1);
        }

        let store = StrategyStore::open(&root, &StoreDialect::generic()).unwrap();
        let control = store.durable_control();
        let queued = store.durable_queue().replay_from_cursor(0).unwrap();
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].channel, ChannelKind::Control);
        assert_eq!(queued[0].item_id, "request-1");
        assert_eq!(control.get_graph_revision("graph-1").unwrap(), Some(4));
        assert_eq!(
            control
                .get_node_control_revision("graph-1", "node-1")
                .unwrap(),
            Some(10)
        );
        assert_eq!(
            control.get_target_generation("graph-1", "node-1").unwrap(),
            Some(3)
        );
        assert!(
            control
                .is_invocation_settled("graph-1", "node-1", "inv-1")
                .unwrap()
        );
        assert!(control.is_stop_requested("graph-1", "node-1").unwrap());
        assert!(control.is_pause_negotiating("graph-1", "node-1").unwrap());
        assert!(control.is_grant_revoked("principal-1", &grant).unwrap());
        assert_eq!(
            control
                .find_idempotency_record("request-1")
                .unwrap()
                .unwrap()
                .0
                .admitted_sequence,
            1
        );
        assert!(
            control
                .clear_pause_negotiating("graph-1", "node-1")
                .unwrap()
        );
        assert!(!control.is_pause_negotiating("graph-1", "node-1").unwrap());
        drop(control);
        drop(store);
        let _ = fs::remove_dir_all(root);
    }

    /// The exclusive-control fence compares inside the committing
    /// transaction: a second admission carrying a revision that was current
    /// when read but stale by commit is refused.
    #[test]
    fn a_stale_expected_control_revision_conflicts_at_commit() {
        let root =
            std::env::temp_dir().join(format!("acativa-workflow-control-{}", Uuid::new_v4()));
        {
            let store = StrategyStore::open(&root, &StoreDialect::generic()).unwrap();
            let mut control = store.durable_control();
            control
                .set_node_control_revision("graph-1", "node-1", 9)
                .unwrap();
            let make_receipt = |request_id: &str| AdmissionReceipt {
                admitted_sequence: 0,
                request_id: request_id.into(),
                graph_id: "graph-1".into(),
                target_node_id: Some("node-1".into()),
                author_principal_id: "principal-1".into(),
                admitted_at_unix_ms: 10,
                operation: ControlOperation::Steer {
                    invocation_id: "inv-1".into(),
                    instruction: String::new(),
                    follow_up: false,
                },
                graph_revision: 1,
                control_revision: 0,
                is_replay: false,
            };
            // Both proxies read revision 9; the first commits 10.
            let mut first = make_receipt("request-a");
            control
                .record_admission(
                    &mut first,
                    "digest-a".into(),
                    Some(9),
                    &AdmissionFences::default(),
                )
                .unwrap();
            assert_eq!(first.control_revision, 10);
            // The second still pins 9 and conflicts at commit.
            let mut second = make_receipt("request-b");
            let conflict = control
                .record_admission(
                    &mut second,
                    "digest-b".into(),
                    Some(9),
                    &AdmissionFences::default(),
                )
                .expect_err("a stale expected revision cannot admit");
            assert!(matches!(
                conflict,
                AdmissionConflict::ControlRevisionConflict { current: 10, .. }
            ));
        }
        let _ = fs::remove_dir_all(root);
    }
}
