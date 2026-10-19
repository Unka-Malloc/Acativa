//! Post-commit transition decoration and durable reconciliation intent.

use anyhow::{Result, anyhow};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::workflow::machine::{ReducerEvent, RunSnapshot};

use super::store::StrategyStore;

/// A transition intent stored in the same transaction as the run event and
/// snapshot.  It remains pending until the post-commit observer completes.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransitionIntent {
    pub run_id: String,
    pub sequence: u64,
    pub event: ReducerEvent,
    pub before: RunSnapshot,
    pub after: RunSnapshot,
    pub created_at_unix_ms: i64,
}

/// The observer-facing view of one committed transition.
pub type CommittedTransition = TransitionIntent;

/// Receives committed transitions.  Implementations run after the SQLite
/// transaction has committed and must not be called by storage code while a
/// write transaction is open.
pub trait TransitionObserver: Send + Sync {
    fn after_commit(&self, transition: &CommittedTransition) -> Result<()>;
}

impl<F> TransitionObserver for F
where
    F: Fn(&CommittedTransition) -> Result<()> + Send + Sync,
{
    fn after_commit(&self, transition: &CommittedTransition) -> Result<()> {
        self(transition)
    }
}

/// Decorates the store's transition boundary.  State and delivery intent are
/// committed first; subscription reconciliation and host wake happen only
/// after that commit and can be replayed from the intent table after a crash.
#[derive(Clone)]
pub struct TransitionDecorator {
    store: StrategyStore,
    observer: Option<Arc<dyn TransitionObserver>>,
}

impl std::fmt::Debug for TransitionDecorator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TransitionDecorator")
            .field("store", &self.store)
            .field("observer_attached", &self.observer.is_some())
            .finish()
    }
}

impl TransitionDecorator {
    pub fn new(store: StrategyStore) -> Self {
        Self {
            store,
            observer: None,
        }
    }

    pub fn with_observer(mut self, observer: Arc<dyn TransitionObserver>) -> Self {
        self.observer = Some(observer);
        self
    }

    pub fn store(&self) -> &StrategyStore {
        &self.store
    }

    /// Apply one reducer event and invoke the observer after the write commit.
    /// Observer failure leaves the durable intent pending and does not roll
    /// back the already committed workflow state.
    pub fn apply_event(&self, run_id: &str, event: ReducerEvent) -> Result<RunSnapshot> {
        let committed = self.store.apply_event_with_commit(run_id, event)?;
        let Some(committed) = committed else {
            return self.store.run(run_id);
        };
        self.dispatch(committed.clone());
        Ok(committed.after)
    }

    /// Replay pending post-commit intents.  The same durable identity is used
    /// for every retry, so observers can make their own delivery idempotent.
    pub fn reconcile_pending(&self) -> Result<usize> {
        let intents = self.store.pending_transition_intents()?;
        let mut completed = 0usize;
        for intent in intents {
            if self.dispatch(intent) {
                completed += 1;
            }
        }
        Ok(completed)
    }

    fn dispatch(&self, intent: TransitionIntent) -> bool {
        let Some(observer) = &self.observer else {
            return false;
        };
        if observer.after_commit(&intent).is_err() {
            return false;
        }
        self.store
            .acknowledge_transition_intent(&intent.run_id, intent.sequence)
            .is_ok()
    }
}

impl StrategyStore {
    pub(crate) fn pending_transition_intents(&self) -> Result<Vec<TransitionIntent>> {
        self.with_connection(|connection| {
            let mut statement = connection.prepare(
                "SELECT run_id, sequence, event_json, before_json, after_json, created_at
                 FROM workflow_transition_intents
                 WHERE status='pending' ORDER BY created_at ASC, run_id ASC, sequence ASC",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            })?;
            rows.map(|row| {
                let (run_id, sequence, event, before, after, created_at) = row?;
                Ok(TransitionIntent {
                    run_id,
                    sequence: sequence.max(0) as u64,
                    event: serde_json::from_str(&event)?,
                    before: serde_json::from_str(&before)?,
                    after: serde_json::from_str(&after)?,
                    created_at_unix_ms: created_at,
                })
            })
            .collect()
        })
    }

    pub(crate) fn acknowledge_transition_intent(&self, run_id: &str, sequence: u64) -> Result<()> {
        let changed = self.with_connection(|connection| -> anyhow::Result<usize> {
            Ok(connection.execute(
                "UPDATE workflow_transition_intents
                 SET status='dispatched', dispatched_at=?3
                 WHERE run_id=?1 AND sequence=?2 AND status='pending'",
                params![run_id, sequence as i64, unix_ms()],
            )?)
        })?;
        if changed == 1 {
            Ok(())
        } else {
            Err(anyhow!("workflow_transition_intent_missing"))
        }
    }
}

pub(crate) fn initialize_schema(connection: &rusqlite::Connection) -> Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS workflow_transition_intents(
           run_id TEXT NOT NULL,
           sequence INTEGER NOT NULL,
           event_json TEXT NOT NULL,
           before_json TEXT NOT NULL,
           after_json TEXT NOT NULL,
           status TEXT NOT NULL CHECK(status IN ('pending', 'dispatched')),
           created_at INTEGER NOT NULL,
           dispatched_at INTEGER,
           PRIMARY KEY(run_id, sequence)
         );
         CREATE INDEX IF NOT EXISTS workflow_transition_intents_pending_idx
           ON workflow_transition_intents(status, created_at);",
    )?;
    Ok(())
}

pub(crate) fn insert_intent(
    transaction: &rusqlite::Transaction<'_>,
    run_id: &str,
    sequence: u64,
    event: &ReducerEvent,
    before: &RunSnapshot,
    after: &RunSnapshot,
    created_at: i64,
) -> Result<()> {
    transaction.execute(
        "INSERT INTO workflow_transition_intents(
           run_id, sequence, event_json, before_json, after_json,
           status, created_at, dispatched_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, 'pending', ?6, NULL)",
        params![
            run_id,
            sequence as i64,
            serde_json::to_string(event)?,
            serde_json::to_string(before)?,
            serde_json::to_string(after)?,
            created_at,
        ],
    )?;
    Ok(())
}

fn unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BindingValue;
    use crate::{
        ActorSlot, GraphState, GraphStateKind, RetryPolicy, Transition, TransitionEvent,
        TransitionMode, WorkflowDefinition, WorkflowLimits, WorkflowMetadata,
    };
    use serde_json::json;
    use std::sync::{Arc, Mutex};

    fn ephemeral_workflow() -> WorkflowDefinition {
        WorkflowDefinition {
            schema: crate::GENERIC_WORKFLOW_SCHEMA.into(),
            metadata: WorkflowMetadata {
                id: "acativa-temporary-commit-test".into(),
                name: "Commit test".into(),
                version: "1".into(),
                description: String::new(),
            },
            limits: WorkflowLimits::default(),
            actor_slots: vec![ActorSlot::required_actor("worker", "Worker")],
            runtimes: vec![],
            worksets: vec![],
            initial: "work".into(),
            states: vec![
                GraphState {
                    id: "work".into(),
                    kind: GraphStateKind::Actor,
                    label: "Work".into(),
                    instruction: String::new(),
                    binding: Some("worker".into()),
                    runtime: None,
                    entry: None,
                    workset: None,
                    retry: RetryPolicy::default(),
                },
                GraphState {
                    id: "done".into(),
                    kind: GraphStateKind::Succeed,
                    label: "Done".into(),
                    instruction: String::new(),
                    binding: None,
                    runtime: None,
                    entry: None,
                    workset: None,
                    retry: RetryPolicy::default(),
                },
                GraphState {
                    id: "fail".into(),
                    kind: GraphStateKind::Fail,
                    label: "Fail".into(),
                    instruction: String::new(),
                    binding: None,
                    runtime: None,
                    entry: None,
                    workset: None,
                    retry: RetryPolicy::default(),
                },
            ],
            transitions: vec![
                Transition {
                    id: "done".into(),
                    from: "work".into(),
                    to: "done".into(),
                    event: TransitionEvent::Success,
                    mode: TransitionMode::Flow,
                    guard: None,
                },
                Transition {
                    id: "failed".into(),
                    from: "work".into(),
                    to: "fail".into(),
                    event: TransitionEvent::Failure,
                    mode: TransitionMode::Flow,
                    guard: None,
                },
            ],
        }
    }

    #[test]
    fn observer_runs_after_commit_and_pending_intents_reconcile() {
        let store = StrategyStore::open_in_memory().unwrap();
        let (run, _) = store
            .admit_ephemeral_run(
                "commit-test-revision",
                "commit-test-semantics",
                &ephemeral_workflow(),
                &[BindingValue {
                    slot_id: "worker".into(),
                    ordinal: 0,
                    value_id: "agent:test".into(),
                    model: String::new(),
                    reasoning_effort: String::new(),
                    revision: 1,
                }],
                json!({"input": "synthetic"}),
                "commit-test-idempotency",
                "context:test",
                json!({"member": "member:test", "source": "test"}),
            )
            .unwrap();
        let observed_sequences = Arc::new(Mutex::new(Vec::new()));
        let attempts = Arc::new(Mutex::new(0usize));
        let observer_store = store.clone();
        let observer = Arc::new({
            let observed_sequences = observed_sequences.clone();
            let attempts = attempts.clone();
            move |transition: &CommittedTransition| -> Result<()> {
                let persisted = observer_store.run(&transition.run_id)?;
                assert_eq!(persisted.sequence, transition.after.sequence);
                let mut attempt = attempts.lock().unwrap();
                if *attempt == 0 {
                    *attempt += 1;
                    return Err(anyhow!("synthetic post-commit interruption"));
                }
                observed_sequences.lock().unwrap().push(transition.sequence);
                Ok(())
            }
        });
        let decorator = TransitionDecorator::new(store.clone()).with_observer(observer);

        assert_eq!(decorator.reconcile_pending().unwrap(), 0);
        assert_eq!(decorator.reconcile_pending().unwrap(), 1);
        let command = run.commands.values().next().unwrap();
        let after = decorator
            .apply_event(
                &run.run_id,
                ReducerEvent::CommandClaimed {
                    command_id: command.id.clone(),
                    attempt_token: command.attempt_token.clone(),
                },
            )
            .unwrap();
        assert_eq!(after.sequence, run.sequence + 1);
        assert_eq!(*observed_sequences.lock().unwrap(), vec![1, 2]);
        assert_eq!(decorator.reconcile_pending().unwrap(), 0);
    }
}
