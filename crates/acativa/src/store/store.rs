use anyhow::{Result, anyhow, ensure};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

use super::{
    BindingCandidate, BindingValue, StrategyAuthorization, StrategyDefinition,
    StrategyDefinitionSummary, StrategyDiagnostic, StrategyProjection,
};
use crate::util::file_security;
use crate::util::sqlite_contract;
use crate::{
    CommandStatus, FailureClass, ReducerEvent, RunCommand, RunSnapshot, StrategyRunStatus,
    WorkflowDefinition, compile_workflow, reduce,
};

const DATABASE_FILE: &str = "strategies.sqlite3";

/// The persisted meta version of this build's strategy schema. It is `1`:
/// the engine owns no legacy layout, so any other value is a foreign or
/// future database and is refused rather than repaired.
const META_VERSION: &str = "1";

/// The host-bound identity of one strategy database.
///
/// Everything persisted that names the host arrives here: the state directory
/// under the portable root, the schema stamped onto projection documents, the
/// workflow schema admitted definitions compile under, and the
/// ephemeral-definition id prefix the host reserves. The engine owns the table
/// names and the strategy vocabulary; the host owns these values.
#[derive(Clone, Debug)]
pub struct StoreDialect {
    /// Directory under the host's portable root that owns `strategies.sqlite3`.
    pub state_root: String,
    /// The schema stamped onto every [`StrategyProjection`] this store
    /// projects.
    pub projection_schema: crate::SchemaId,
    /// The workflow schema identity every admitted definition compiles under.
    pub workflow_schema: crate::SchemaId,
    /// The id prefix the host reserves for ephemeral definitions it creates
    /// inside one run rather than imports. `None` admits no ephemeral
    /// definition at all.
    pub ephemeral_definition_prefix: Option<String>,
}

impl StoreDialect {
    /// The dialect this crate's own fixtures and tests use. It is the
    /// engine's generic identity, not a product's: a host binds its own
    /// values at the same parameters.
    pub fn generic() -> Self {
        Self {
            state_root: "client-state/acativa".to_owned(),
            projection_schema: crate::SchemaId::new(crate::GENERIC_PROJECTION_SCHEMA),
            workflow_schema: crate::SchemaId::new(crate::GENERIC_WORKFLOW_SCHEMA),
            ephemeral_definition_prefix: Some("acativa-temporary".to_owned()),
        }
    }

    /// The directory under `portable_root` this dialect's database owns.
    pub fn state_dir(&self, portable_root: &Path) -> PathBuf {
        portable_root.join(&self.state_root)
    }
}

/// Removes an in-memory store's private scratch directory once the last
/// handle drops. Each clone shares the guard, so the directory outlives every
/// connection and is reclaimed when the store itself is gone.
#[derive(Debug)]
struct ScratchDir {
    path: PathBuf,
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[derive(Clone, Debug)]
pub struct StrategyStore {
    db_path: PathBuf,
    dialect: StoreDialect,
    /// Held only for its `Drop`: the private scratch directory of an
    /// in-memory store is removed when the last handle goes away.
    #[allow(dead_code)]
    scratch_dir: Option<std::sync::Arc<ScratchDir>>,
}

impl StrategyStore {
    /// Open this dialect's database under `portable_root`, creating it when it
    /// does not exist. An existing file must carry this build's schema exactly:
    /// the engine owns no legacy layout, so a foreign version is refused rather
    /// than repaired.
    pub fn open(portable_root: &Path, dialect: &StoreDialect) -> Result<Self> {
        let root = dialect.state_dir(portable_root);
        let db_path = root.join(DATABASE_FILE);
        preflight_existing_store(&db_path)?;
        if let Some(parent) = root.parent() {
            file_security::ensure_private_dir(parent)?;
        }
        file_security::ensure_private_dir(&root)?;
        let existed = db_path.exists();
        let store = Self {
            db_path,
            dialect: dialect.clone(),
            scratch_dir: None,
        };
        store.with_connection(|connection| {
            if existed {
                validate_current_schema(connection)
            } else {
                initialize_schema(connection)
            }
        })?;
        file_security::harden_private_path(&store.db_path)?;
        Ok(store)
    }

    /// An in-memory store under this crate's generic dialect, for tests and
    /// hosts that do not need durability.
    pub fn open_in_memory() -> Result<Self> {
        Self::open_in_memory_as(&StoreDialect::generic())
    }

    /// An in-memory store under an explicit dialect.
    ///
    /// The database lives in a private scratch directory that only this user
    /// can read and that is removed when the last store handle drops; a file
    /// name in the shared temp root would be readable by other processes and
    /// would linger after use.
    pub fn open_in_memory_as(dialect: &StoreDialect) -> Result<Self> {
        let root = std::env::temp_dir().join(format!("acativa-memory-{}", Uuid::new_v4()));
        file_security::ensure_private_dir(&root)?;
        let store = Self {
            db_path: root.join(DATABASE_FILE),
            dialect: dialect.clone(),
            scratch_dir: Some(std::sync::Arc::new(ScratchDir { path: root })),
        };
        store.with_connection(initialize_schema)?;
        file_security::harden_private_path(&store.db_path)?;
        Ok(store)
    }

    /// The dialect this store was opened under.
    pub fn dialect(&self) -> &StoreDialect {
        &self.dialect
    }

    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    pub fn durable_queue(&self) -> super::DurableQueue {
        super::DurableQueue::from_store(self.clone())
    }

    pub fn durable_subscriptions(&self) -> super::DurableSubscriptionStore {
        super::DurableSubscriptionStore::from_store(self.clone())
    }

    pub fn durable_control(&self) -> super::DurableControlledStore {
        super::DurableControlledStore::from_store(self.clone())
    }

    pub fn with_connection<T>(
        &self,
        operation: impl FnOnce(&mut Connection) -> Result<T>,
    ) -> Result<T> {
        self.with_connection_typed(operation)
    }

    pub(crate) fn with_connection_typed<T, E>(
        &self,
        operation: impl FnOnce(&mut Connection) -> std::result::Result<T, E>,
    ) -> std::result::Result<T, E>
    where
        E: From<anyhow::Error>,
    {
        let mut connection = Connection::open(&self.db_path)
            .map_err(|_| E::from(anyhow!("strategy_database_open_failed")))?;
        configure_connection(&connection).map_err(E::from)?;
        operation(&mut connection)
    }

    pub fn register_definition(
        &self,
        revision_digest: &str,
        semantics_digest: &str,
        workflow: &WorkflowDefinition,
        asset_count: usize,
        imported_at_unix_ms: i64,
    ) -> Result<StrategyDefinition> {
        let compiled = compile_workflow(workflow.clone(), &self.dialect.workflow_schema)?;
        let workflow_json = serde_json::to_string(compiled.definition())?;
        self.with_connection(|connection| {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            transaction.execute(
                "INSERT INTO strategy_definitions(
                   definition_id, revision_digest, semantics_digest, name, version,
                   workflow_json, asset_count, imported_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(revision_digest) DO NOTHING",
                params![
                    compiled.definition().metadata.id,
                    revision_digest,
                    semantics_digest,
                    compiled.definition().metadata.name,
                    compiled.definition().metadata.version,
                    workflow_json,
                    asset_count as i64,
                    imported_at_unix_ms,
                ],
            )?;
            let existing: Option<(String, String)> = transaction
                .query_row(
                    "SELECT definition_id, semantics_digest FROM strategy_definitions
                     WHERE revision_digest=?1",
                    params![revision_digest],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            ensure!(
                existing
                    == Some((
                        compiled.definition().metadata.id.clone(),
                        semantics_digest.to_owned()
                    )),
                "strategy_revision_conflict"
            );
            transaction.commit()?;
            self.definition_by_revision(revision_digest)
        })
    }

    /// Imported definitions, newest first. Definitions under the dialect's
    /// ephemeral prefix are the host's run-scoped internals, not a catalog
    /// entry, so they are never listed.
    pub fn list_definitions(&self) -> Result<Vec<StrategyDefinitionSummary>> {
        let ephemeral_like = self
            .dialect
            .ephemeral_definition_prefix
            .as_deref()
            .map(|prefix| format!("{prefix}%"));
        self.with_connection(|connection| {
            let mut statement = connection.prepare(
                "SELECT definition_id, revision_digest, semantics_digest, name, version, imported_at,
                        EXISTS(
                          SELECT 1 FROM strategy_authorizations
                          WHERE revision_digest=strategy_definitions.revision_digest AND active=1
                        )
                 FROM strategy_definitions
                 WHERE (?1 IS NULL OR definition_id NOT LIKE ?1)
                 ORDER BY imported_at DESC, revision_digest ASC",
            )?;
            let rows = statement.query_map(params![ephemeral_like], summary_from_row)?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .map_err(Into::into)
        })
    }

    pub fn definition_by_revision(&self, revision_digest: &str) -> Result<StrategyDefinition> {
        self.with_connection(|connection| definition_by_revision(connection, revision_digest))
    }

    pub fn latest_definition(&self, definition_id: &str) -> Result<StrategyDefinition> {
        self.with_connection(|connection| {
            let revision: Option<String> = connection
                .query_row(
                    "SELECT revision_digest FROM strategy_definitions
                     WHERE definition_id=?1 ORDER BY imported_at DESC, revision_digest ASC LIMIT 1",
                    params![definition_id],
                    |row| row.get(0),
                )
                .optional()?;
            definition_by_revision(
                connection,
                revision
                    .as_deref()
                    .ok_or_else(|| anyhow!("strategy_definition_not_found"))?,
            )
        })
    }

    pub fn update_binding(
        &self,
        revision_digest: &str,
        slot_id: &str,
        value_id: &str,
        model: &str,
        reasoning_effort: &str,
        expected_revision: Option<u64>,
    ) -> Result<BindingValue> {
        self.replace_slot_bindings(
            revision_digest,
            slot_id,
            &[BindingCandidate {
                value_id: value_id.to_owned(),
                model: model.to_owned(),
                reasoning_effort: reasoning_effort.to_owned(),
            }],
            expected_revision,
        )?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("strategy_binding_incomplete"))
    }

    pub fn replace_slot_bindings(
        &self,
        revision_digest: &str,
        slot_id: &str,
        candidates: &[BindingCandidate],
        expected_revision: Option<u64>,
    ) -> Result<Vec<BindingValue>> {
        validate_opaque_id(slot_id, "strategy_binding_slot_invalid")?;
        ensure!(candidates.len() <= 16, "strategy_binding_limit");
        for candidate in candidates {
            validate_opaque_id(&candidate.value_id, "strategy_binding_value_invalid")?;
            validate_optional_text(&candidate.model, "strategy_binding_model_invalid")?;
            validate_optional_text(
                &candidate.reasoning_effort,
                "strategy_binding_reasoning_effort_invalid",
            )?;
        }
        let definition = self.definition_by_revision(revision_digest)?;
        ensure!(
            definition
                .workflow
                .actor_slots
                .iter()
                .any(|slot| slot.id == slot_id),
            "strategy_binding_slot_unknown"
        );
        self.with_connection(|connection| {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let current: Option<u64> = transaction
                .query_row(
                    "SELECT MAX(revision) FROM strategy_bindings
                     WHERE revision_digest=?1 AND slot_id=?2",
                    params![revision_digest, slot_id],
                    |row| row.get::<_, Option<i64>>(0),
                )
                .optional()?
                .flatten()
                .map(|value| value as u64);
            if let Some(expected) = expected_revision {
                ensure!(current.unwrap_or(0) == expected, "strategy_revision_conflict");
            }
            let revision = current.unwrap_or(0) + 1;
            transaction.execute(
                "DELETE FROM strategy_bindings WHERE revision_digest=?1 AND slot_id=?2",
                params![revision_digest, slot_id],
            )?;
            let mut values = Vec::with_capacity(candidates.len());
            for (ordinal, candidate) in candidates.iter().enumerate() {
                let ordinal = u8::try_from(ordinal).map_err(|_| anyhow!("strategy_binding_limit"))?;
                transaction.execute(
                    "INSERT INTO strategy_bindings(
                       revision_digest, slot_id, ordinal, value_id, model, reasoning_effort, revision
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        revision_digest,
                        slot_id,
                        ordinal as i64,
                        candidate.value_id,
                        candidate.model,
                        candidate.reasoning_effort,
                        revision as i64
                    ],
                )?;
                values.push(BindingValue {
                    slot_id: slot_id.to_owned(),
                    ordinal,
                    value_id: candidate.value_id.clone(),
                    model: candidate.model.clone(),
                    reasoning_effort: candidate.reasoning_effort.clone(),
                    revision,
                });
            }
            transaction.execute(
                "UPDATE strategy_authorizations SET active=0 WHERE revision_digest=?1 AND active=1",
                params![revision_digest],
            )?;
            transaction.commit()?;
            Ok(values)
        })
    }

    pub fn remove_binding(
        &self,
        revision_digest: &str,
        slot_id: &str,
        expected_revision: Option<u64>,
    ) -> Result<()> {
        validate_opaque_id(slot_id, "strategy_binding_slot_invalid")?;
        self.with_connection(|connection| {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let current: Option<u64> = transaction
                .query_row(
                    "SELECT MAX(revision) FROM strategy_bindings
                     WHERE revision_digest=?1 AND slot_id=?2",
                    params![revision_digest, slot_id],
                    |row| row.get::<_, Option<i64>>(0),
                )
                .optional()?
                .flatten()
                .map(|value| value as u64);
            if let Some(expected) = expected_revision {
                ensure!(
                    current.unwrap_or(0) == expected,
                    "strategy_revision_conflict"
                );
            }
            transaction.execute(
                "DELETE FROM strategy_bindings WHERE revision_digest=?1 AND slot_id=?2",
                params![revision_digest, slot_id],
            )?;
            transaction.execute(
                "UPDATE strategy_authorizations SET active=0
                 WHERE revision_digest=?1 AND active=1",
                params![revision_digest],
            )?;
            transaction.commit()?;
            Ok(())
        })
    }

    pub fn authorization_preview(&self, revision_digest: &str) -> Result<StrategyAuthorization> {
        let definition = self.definition_by_revision(revision_digest)?;
        ensure!(
            bindings_complete(&definition),
            "strategy_binding_incomplete"
        );
        let binding_digest = binding_digest(&definition.bindings)?;
        let next_revision = definition
            .authorization
            .as_ref()
            .map_or(1, |authorization| authorization.revision + 1);
        let authorization_digest = authorization_digest(
            revision_digest,
            &definition.summary.semantics_digest,
            &binding_digest,
            next_revision,
        );
        Ok(StrategyAuthorization {
            definition_digest: revision_digest.to_owned(),
            semantics_digest: definition.summary.semantics_digest,
            binding_digest,
            authorization_digest,
            revision: next_revision,
            active: false,
        })
    }

    pub fn grant_authorization(
        &self,
        revision_digest: &str,
        expected_authorization_digest: &str,
    ) -> Result<StrategyAuthorization> {
        self.with_connection(|connection| {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let definition = definition_by_revision(&transaction, revision_digest)?;
            ensure!(
                bindings_complete(&definition),
                "strategy_binding_incomplete"
            );
            let binding_digest = binding_digest(&definition.bindings)?;
            let next_revision = definition
                .authorization
                .as_ref()
                .map_or(1, |authorization| authorization.revision + 1);
            let authorization_digest = authorization_digest(
                revision_digest,
                &definition.summary.semantics_digest,
                &binding_digest,
                next_revision,
            );
            ensure!(
                authorization_digest == expected_authorization_digest,
                "strategy_authorization_stale"
            );
            transaction.execute(
                "UPDATE strategy_authorizations SET active=0 WHERE revision_digest=?1 AND active=1",
                params![revision_digest],
            )?;
            transaction.execute(
                "INSERT INTO strategy_authorizations(
                   revision_digest, revision, semantics_digest, binding_digest,
                   authorization_digest, active, created_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6)",
                params![
                    revision_digest,
                    next_revision as i64,
                    definition.summary.semantics_digest,
                    binding_digest,
                    authorization_digest,
                    now_ms(),
                ],
            )?;
            transaction.commit()?;
            Ok(StrategyAuthorization {
                definition_digest: revision_digest.to_owned(),
                semantics_digest: definition.summary.semantics_digest,
                binding_digest,
                authorization_digest,
                revision: next_revision,
                active: true,
            })
        })
    }

    pub fn revoke_authorization(&self, revision_digest: &str) -> Result<()> {
        self.with_connection(|connection| {
            connection.execute(
                "UPDATE strategy_authorizations SET active=0 WHERE revision_digest=?1 AND active=1",
                params![revision_digest],
            )?;
            Ok(())
        })
    }

    /// Admit one run of an authorized definition.
    ///
    /// `context_id` is the durable, indexed host grouping key the run answers
    /// to (a channel, a tenant, a document); the engine stores it without
    /// interpreting it.
    pub fn start_run(
        &self,
        revision_digest: &str,
        input: Value,
        idempotency_key: &str,
        context_id: Option<&str>,
        cwd: Option<String>,
    ) -> Result<RunSnapshot> {
        self.start_run_with_binding(
            revision_digest,
            input,
            idempotency_key,
            context_id,
            None,
            cwd,
        )
    }

    /// The binding-admitting variant. `run_binding` is the opaque host binding
    /// the snapshot persists (a routing receipt, a member identity); the
    /// engine never reads it.
    pub fn start_run_with_binding(
        &self,
        revision_digest: &str,
        input: Value,
        idempotency_key: &str,
        context_id: Option<&str>,
        run_binding: Option<Value>,
        cwd: Option<String>,
    ) -> Result<RunSnapshot> {
        validate_opaque_id(idempotency_key, "strategy_idempotency_key_invalid")?;
        if let Some(context_id) = context_id {
            validate_opaque_id(context_id, "strategy_context_id_invalid")?;
        }
        let input_bytes = serde_json::to_vec(&input)?;
        let mut digest_source = Vec::from(revision_digest.as_bytes());
        digest_source.push(0);
        digest_source.extend_from_slice(&input_bytes);
        digest_source.push(0);
        digest_source.extend_from_slice(context_id.unwrap_or("").as_bytes());
        digest_source.push(0);
        digest_source.extend_from_slice(cwd.as_deref().unwrap_or("").as_bytes());
        digest_source.push(0);
        digest_source.extend_from_slice(&serde_json::to_vec(&run_binding)?);
        let request_digest = sha256_hex(&digest_source);
        self.with_connection(|connection| {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let existing: Option<(String, String)> = transaction
                .query_row(
                    "SELECT run_id, request_digest FROM strategy_runs WHERE idempotency_key=?1",
                    params![idempotency_key],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            if let Some((run_id, existing_digest)) = existing {
                ensure!(
                    existing_digest == request_digest,
                    "strategy_idempotency_conflict"
                );
                let snapshot = load_run(&transaction, &run_id)?;
                transaction.commit()?;
                return Ok(snapshot);
            }

            // Authorization, exact bindings, reduction, and insertion share
            // one write transaction. A concurrent revoke or binding update
            // therefore happens wholly before or wholly after this admission.
            let definition = definition_by_revision(&transaction, revision_digest)?;
            ensure!(
                bindings_complete(&definition),
                "strategy_binding_incomplete"
            );
            let authorization = current_authorization(&definition)?;
            ensure!(
                authorization.binding_digest == binding_digest(&definition.bindings)?,
                "strategy_authorization_stale"
            );
            let slot_candidate_counts = slot_candidate_counts(&definition.bindings);
            let semantics_digest = definition.summary.semantics_digest.clone();
            let compiled = compile_workflow(definition.workflow, &self.dialect.workflow_schema)?;
            let run_id = format!("run-{}", Uuid::new_v4());
            let empty = RunSnapshot::empty(&run_id, revision_digest, &semantics_digest);
            let event = ReducerEvent::Start { input };
            let output = reduce(&compiled, &empty, event.clone())?;
            let mut snapshot = output.snapshot;
            snapshot.context_id = context_id.map(str::to_owned);
            snapshot.run_binding = run_binding;
            snapshot.cwd = cwd;
            snapshot.slot_candidate_counts = slot_candidate_counts;
            let now = now_ms();
            transaction.execute(
                "INSERT INTO strategy_runs(
                   run_id, revision_digest, semantics_digest, idempotency_key,
                   request_digest, snapshot_json, context_id, terminal,
                   created_at, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)",
                params![
                    run_id,
                    revision_digest,
                    semantics_digest,
                    idempotency_key,
                    request_digest,
                    serde_json::to_string(&snapshot)?,
                    snapshot.context_id,
                    i64::from(run_is_terminal(snapshot.status)),
                    now,
                ],
            )?;
            persist_event_and_commands(
                &transaction,
                &empty,
                &snapshot,
                &event,
                &output.emitted_commands,
                now,
            )?;
            transaction.commit()?;
            Ok(snapshot)
        })
    }

    /// Atomically freezes one ephemeral definition, its exact bindings, its
    /// authorization and one run snapshot — the admission a host performs when
    /// it authors a definition inside a run rather than importing it. The
    /// definition's id must carry the dialect's ephemeral prefix; the
    /// definition digest already commits to the run binding, so existing rows
    /// must be byte-for-byte equivalent and can never be rebound.
    #[allow(clippy::too_many_arguments)]
    pub fn admit_ephemeral_run(
        &self,
        revision_digest: &str,
        semantics_digest: &str,
        workflow: &WorkflowDefinition,
        bindings: &[BindingValue],
        input: Value,
        idempotency_key: &str,
        context_id: &str,
        run_binding: Value,
    ) -> Result<(RunSnapshot, bool)> {
        validate_opaque_id(idempotency_key, "strategy_idempotency_key_invalid")?;
        validate_opaque_id(context_id, "strategy_context_id_invalid")?;
        let ephemeral_prefix = self
            .dialect
            .ephemeral_definition_prefix
            .as_deref()
            .ok_or_else(|| anyhow!("graph_identity_rejected"))?;
        ensure!(
            workflow.metadata.id.starts_with(ephemeral_prefix),
            "graph_identity_rejected"
        );
        let compiled = compile_workflow(workflow.clone(), &self.dialect.workflow_schema)?;
        let workflow_json = serde_json::to_string(compiled.definition())?;
        let mut expected_bindings = bindings.to_vec();
        expected_bindings.sort_by(|left, right| {
            left.slot_id
                .cmp(&right.slot_id)
                .then_with(|| left.ordinal.cmp(&right.ordinal))
        });
        for binding in &expected_bindings {
            validate_opaque_id(&binding.slot_id, "strategy_binding_slot_invalid")?;
            validate_opaque_id(&binding.value_id, "strategy_binding_value_invalid")?;
            ensure!(binding.ordinal < 16, "strategy_binding_limit");
            validate_optional_text(&binding.model, "strategy_binding_model_invalid")?;
            validate_optional_text(
                &binding.reasoning_effort,
                "strategy_binding_reasoning_effort_invalid",
            )?;
        }
        let mut request_source = Vec::from(revision_digest.as_bytes());
        request_source.push(0);
        request_source.extend_from_slice(&serde_json::to_vec(&input)?);
        request_source.push(0);
        request_source.extend_from_slice(context_id.as_bytes());
        request_source.push(0);
        request_source.extend_from_slice(&serde_json::to_vec(&run_binding)?);
        let request_digest = sha256_hex(&request_source);
        self.with_connection(|connection| {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let existing: Option<(String, String)> = transaction
                .query_row(
                    "SELECT run_id, request_digest FROM strategy_runs WHERE idempotency_key=?1",
                    params![idempotency_key],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            if let Some((run_id, existing_digest)) = existing {
                ensure!(
                    existing_digest == request_digest,
                    "strategy_idempotency_conflict"
                );
                let snapshot = load_run(&transaction, &run_id)?;
                transaction.commit()?;
                return Ok((snapshot, false));
            }

            transaction.execute(
                "INSERT INTO strategy_definitions(
                   definition_id, revision_digest, semantics_digest, name, version,
                   workflow_json, asset_count, imported_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7)
                 ON CONFLICT(revision_digest) DO NOTHING",
                params![
                    compiled.definition().metadata.id,
                    revision_digest,
                    semantics_digest,
                    compiled.definition().metadata.name,
                    compiled.definition().metadata.version,
                    workflow_json,
                    now_ms(),
                ],
            )?;
            let stored_identity: (String, String, String) = transaction.query_row(
                "SELECT definition_id, semantics_digest, workflow_json
                 FROM strategy_definitions WHERE revision_digest=?1",
                params![revision_digest],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?;
            ensure!(
                stored_identity
                    == (
                        compiled.definition().metadata.id.clone(),
                        semantics_digest.to_owned(),
                        serde_json::to_string(compiled.definition())?,
                    ),
                "strategy_revision_conflict"
            );
            for binding in &expected_bindings {
                transaction.execute(
                    "INSERT OR IGNORE INTO strategy_bindings(
                       revision_digest, slot_id, ordinal, value_id, model,
                       reasoning_effort, revision
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1)",
                    params![
                        revision_digest,
                        binding.slot_id,
                        binding.ordinal as i64,
                        binding.value_id,
                        binding.model,
                        binding.reasoning_effort,
                    ],
                )?;
            }
            let definition = definition_by_revision(&transaction, revision_digest)?;
            let mut stored_bindings = definition.bindings.clone();
            stored_bindings.sort_by(|left, right| {
                left.slot_id
                    .cmp(&right.slot_id)
                    .then_with(|| left.ordinal.cmp(&right.ordinal))
            });
            ensure!(
                stored_bindings.len() == expected_bindings.len()
                    && stored_bindings
                        .iter()
                        .zip(&expected_bindings)
                        .all(|(stored, expected)| {
                            stored.slot_id == expected.slot_id
                                && stored.ordinal == expected.ordinal
                                && stored.value_id == expected.value_id
                                && stored.model == expected.model
                                && stored.reasoning_effort == expected.reasoning_effort
                        })
                    && bindings_complete(&definition),
                "strategy_revision_conflict"
            );
            let frozen_binding_digest = binding_digest(&stored_bindings)?;
            let frozen_authorization_digest =
                authorization_digest(revision_digest, semantics_digest, &frozen_binding_digest, 1);
            transaction.execute(
                "INSERT OR IGNORE INTO strategy_authorizations(
                   revision_digest, revision, semantics_digest, binding_digest,
                   authorization_digest, active, created_at
                 ) VALUES (?1, 1, ?2, ?3, ?4, 1, ?5)",
                params![
                    revision_digest,
                    semantics_digest,
                    frozen_binding_digest,
                    frozen_authorization_digest,
                    now_ms(),
                ],
            )?;
            let authorization = load_authorization(&transaction, revision_digest)?
                .ok_or_else(|| anyhow!("strategy_authorization_stale"))?;
            ensure!(
                authorization.active
                    && authorization.revision == 1
                    && authorization.semantics_digest == semantics_digest
                    && authorization.binding_digest == frozen_binding_digest
                    && authorization.authorization_digest == frozen_authorization_digest,
                "strategy_authorization_stale"
            );

            let slot_candidate_counts = slot_candidate_counts(&stored_bindings);
            let run_id = format!("run-{}", Uuid::new_v4());
            let empty = RunSnapshot::empty(&run_id, revision_digest, semantics_digest);
            let event = ReducerEvent::Start { input };
            let output = reduce(&compiled, &empty, event.clone())?;
            let mut snapshot = output.snapshot;
            snapshot.context_id = Some(context_id.to_owned());
            snapshot.run_binding = Some(run_binding);
            snapshot.slot_candidate_counts = slot_candidate_counts;
            let now = now_ms();
            transaction.execute(
                "INSERT INTO strategy_runs(
                   run_id, revision_digest, semantics_digest, idempotency_key,
                   request_digest, snapshot_json, context_id, terminal,
                   created_at, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)",
                params![
                    run_id,
                    revision_digest,
                    semantics_digest,
                    idempotency_key,
                    request_digest,
                    serde_json::to_string(&snapshot)?,
                    context_id,
                    i64::from(run_is_terminal(snapshot.status)),
                    now,
                ],
            )?;
            persist_event_and_commands(
                &transaction,
                &empty,
                &snapshot,
                &event,
                &output.emitted_commands,
                now,
            )?;
            transaction.commit()?;
            Ok((snapshot, true))
        })
    }

    pub fn run_id_by_idempotency_key(&self, idempotency_key: &str) -> Result<Option<String>> {
        validate_opaque_id(idempotency_key, "strategy_idempotency_key_invalid")?;
        self.with_connection(|connection| {
            connection
                .query_row(
                    "SELECT run_id FROM strategy_runs WHERE idempotency_key=?1",
                    params![idempotency_key],
                    |row| row.get(0),
                )
                .optional()
                .map_err(Into::into)
        })
    }

    pub fn run(&self, run_id: &str) -> Result<RunSnapshot> {
        self.with_connection(|connection| load_run(connection, run_id))
    }

    pub fn apply_event(&self, run_id: &str, event: ReducerEvent) -> Result<RunSnapshot> {
        let committed = self.apply_event_with_commit(run_id, event)?;
        match committed {
            Some((_, after)) => Ok(after),
            None => self.run(run_id),
        }
    }

    /// Apply a command lifecycle event on behalf of the claim's recorded
    /// owner. Ownership is compared against the persisted lease inside the
    /// same transaction that commits the transition: a settlement carrying a
    /// valid attempt token still fails when the live lease names another
    /// claimant. Events for commands that hold no live lease (pending work
    /// that was never claimed, or an expired claim) settle through the plain
    /// [`Self::apply_event`] path exactly like before.
    pub fn apply_owned_event(
        &self,
        run_id: &str,
        claimant: &str,
        event: ReducerEvent,
    ) -> Result<RunSnapshot> {
        let committed = self.apply_event_inner(run_id, event, Some(claimant))?;
        match committed {
            Some((_, after)) => Ok(after),
            None => self.run(run_id),
        }
    }

    pub(crate) fn apply_event_with_commit(
        &self,
        run_id: &str,
        event: ReducerEvent,
    ) -> Result<Option<(super::CommittedTransition, RunSnapshot)>> {
        self.apply_event_inner(run_id, event, None)
    }

    pub(crate) fn apply_event_inner(
        &self,
        run_id: &str,
        event: ReducerEvent,
        claimant: Option<&str>,
    ) -> Result<Option<(super::CommittedTransition, RunSnapshot)>> {
        if let Some(claimant) = claimant {
            validate_opaque_id(claimant, "strategy_claimant_invalid")?;
        }
        self.with_connection(|connection| {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            authenticate_command_event(&transaction, run_id, &event, claimant)?;
            let previous = load_run(&transaction, run_id)?;
            let workflow = workflow_for_revision(&transaction, &previous.definition_digest)?;
            let compiled = compile_workflow(workflow, &self.dialect.workflow_schema)?;
            let output = reduce(&compiled, &previous, event.clone())?;
            if output.applied {
                let now = now_ms();
                persist_event_and_commands(
                    &transaction,
                    &previous,
                    &output.snapshot,
                    &event,
                    &output.emitted_commands,
                    now,
                )?;
                transaction.execute(
                    "UPDATE strategy_runs SET snapshot_json=?2, context_id=?3,
                     terminal=?4, updated_at=?5 WHERE run_id=?1",
                    params![
                        run_id,
                        serde_json::to_string(&output.snapshot)?,
                        output.snapshot.context_id,
                        i64::from(run_is_terminal(output.snapshot.status)),
                        now
                    ],
                )?;
            }
            transaction.commit()?;
            if output.applied {
                let after = output.snapshot;
                let intent = super::CommittedTransition {
                    run_id: run_id.to_owned(),
                    sequence: after.sequence,
                    event,
                    before: transition_delta(&previous, &after),
                    after: transition_delta(&after, &previous),
                    created_at_unix_ms: now_ms(),
                };
                Ok(Some((intent, after)))
            } else {
                Ok(None)
            }
        })
    }

    pub fn claim_next_command(
        &self,
        run_id: &str,
        claimant: &str,
        lease_until_unix_ms: i64,
    ) -> Result<Option<RunCommand>> {
        validate_opaque_id(claimant, "strategy_claimant_invalid")?;
        let now = now_ms();
        ensure!(lease_until_unix_ms > now, "strategy_lease_invalid");
        self.with_connection(|connection| {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let active: i64 = transaction.query_row(
                "SELECT COUNT(*) FROM strategy_commands
                 WHERE status IN ('claimed', 'running') AND lease_until>?1",
                params![now],
                |row| row.get(0),
            )?;
            if active >= crate::MAX_ACTIVE_EFFECTS as i64 {
                transaction.commit()?;
                return Ok(None);
            }
            let previous = load_run(&transaction, run_id)?;
            if !matches!(
                previous.status,
                StrategyRunStatus::Running
                    | StrategyRunStatus::Waiting
                    | StrategyRunStatus::Retryable
            ) {
                transaction.commit()?;
                return Ok(None);
            }
            let workflow = workflow_for_revision(&transaction, &previous.definition_digest)?;
            let compiled = compile_workflow(workflow, &self.dialect.workflow_schema)?;
            let run_active: i64 = transaction.query_row(
                "SELECT COUNT(*) FROM strategy_commands
                 WHERE run_id=?1 AND status IN ('claimed', 'running') AND lease_until>?2",
                params![run_id, now],
                |row| row.get(0),
            )?;
            if run_active >= compiled.definition().limits.max_parallelism as i64 {
                transaction.commit()?;
                return Ok(None);
            }
            let value: Option<String> = transaction
                .query_row(
                    "SELECT command_json FROM strategy_commands
                     WHERE run_id=?1 AND status='pending' AND kind!='authorization'
                     ORDER BY command_id ASC LIMIT 1",
                    params![run_id],
                    |row| row.get(0),
                )
                .optional()?;
            let Some(value) = value else {
                transaction.commit()?;
                return Ok(None);
            };
            let command: RunCommand = serde_json::from_str(&value)?;
            let event = ReducerEvent::CommandClaimed {
                command_id: command.id.clone(),
                attempt_token: command.attempt_token.clone(),
            };
            let output = reduce(&compiled, &previous, event.clone())?;
            ensure!(output.applied, "strategy_command_not_claimable");
            persist_event_and_commands(
                &transaction,
                &previous,
                &output.snapshot,
                &event,
                &output.emitted_commands,
                now,
            )?;
            transaction.execute(
                "UPDATE strategy_runs SET snapshot_json=?2, context_id=?3,
                 terminal=?4, updated_at=?5 WHERE run_id=?1",
                params![
                    run_id,
                    serde_json::to_string(&output.snapshot)?,
                    output.snapshot.context_id,
                    i64::from(run_is_terminal(output.snapshot.status)),
                    now
                ],
            )?;
            transaction.execute(
                "UPDATE strategy_commands SET status='claimed', lease_owner=?2,
                 lease_until=?3, command_json=?4, updated_at=?5 WHERE command_id=?1",
                params![
                    command.id,
                    claimant,
                    lease_until_unix_ms,
                    serde_json::to_string(&output.snapshot.commands[&command.id])?,
                    now,
                ],
            )?;
            let claimed = output.snapshot.commands.get(&command.id).cloned();
            transaction.commit()?;
            Ok(claimed)
        })
    }

    pub fn renew_command_lease(
        &self,
        command_id: &str,
        claimant: &str,
        lease_until_unix_ms: i64,
    ) -> Result<()> {
        validate_opaque_id(claimant, "strategy_claimant_invalid")?;
        ensure!(lease_until_unix_ms > now_ms(), "strategy_lease_invalid");
        self.with_connection(|connection| {
            let changed = connection.execute(
                "UPDATE strategy_commands SET lease_until=?3, updated_at=?4
                 WHERE command_id=?1 AND lease_owner=?2
                   AND status IN ('claimed', 'running')",
                params![command_id, claimant, lease_until_unix_ms, now_ms()],
            )?;
            ensure!(changed == 1, "strategy_lease_lost");
            Ok(())
        })
    }

    /// Revalidate the exact command and authorization immediately before an
    /// effect permit is issued. The write lock serializes this admission with
    /// binding updates and authorization revocation; a later revoke does not
    /// retroactively invalidate the already-issued one-shot permit.
    pub fn authorize_effect(
        &self,
        run_id: &str,
        command_id: &str,
        attempt_token: &str,
        expected_authorization_digest: &str,
        claimant: &str,
        lease_until_unix_ms: i64,
    ) -> Result<()> {
        validate_opaque_id(claimant, "strategy_claimant_invalid")?;
        let now = now_ms();
        ensure!(lease_until_unix_ms > now, "strategy_lease_invalid");
        self.with_connection(|connection| {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let lease: Option<(String, String, Option<String>, Option<i64>)> = transaction
                .query_row(
                    "SELECT status, attempt_token, lease_owner, lease_until
                     FROM strategy_commands WHERE command_id=?1 AND run_id=?2",
                    params![command_id, run_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()?;
            ensure!(
                lease.is_some_and(|(status, token, owner, lease_until)| {
                    status == "running"
                        && token == attempt_token
                        && owner.as_deref() == Some(claimant)
                        && lease_until.is_some_and(|value| value > now)
                }),
                "strategy_lease_lost"
            );
            let snapshot = load_run(&transaction, run_id)?;
            let command = snapshot
                .commands
                .get(command_id)
                .filter(|command| {
                    command.status == CommandStatus::Running
                        && command.attempt_token == attempt_token
                })
                .ok_or_else(|| anyhow!("strategy_callback_stale"))?;
            ensure!(command.id == command_id, "strategy_callback_stale");
            let definition = definition_by_revision(&transaction, &snapshot.definition_digest)?;
            ensure!(
                definition.summary.semantics_digest == snapshot.semantics_digest,
                "strategy_authorization_stale"
            );
            ensure!(
                bindings_complete(&definition),
                "strategy_binding_incomplete"
            );
            let authorization = current_authorization(&definition)?;
            ensure!(
                authorization.binding_digest == binding_digest(&definition.bindings)?
                    && authorization.authorization_digest == expected_authorization_digest,
                "strategy_authorization_stale"
            );
            let renewed = transaction.execute(
                "UPDATE strategy_commands SET lease_until=?4, updated_at=?5
                 WHERE command_id=?1 AND run_id=?2 AND lease_owner=?3
                   AND status='running' AND lease_until>?5",
                params![command_id, run_id, claimant, lease_until_unix_ms, now],
            )?;
            ensure!(renewed == 1, "strategy_lease_lost");
            transaction.commit()?;
            Ok(())
        })
    }

    /// Atomically fence and recover the next expired effect claim of one run.
    ///
    /// Lease renewal and this recovery both require the same SQLite write
    /// lock. The winner observes and commits one state transition; the loser
    /// cannot act on a stale pre-lock observation. Claimed-before-start work
    /// is retried in the same transaction, while expired running work is
    /// retained as in-doubt and is never blindly retried.
    ///
    /// A previous host process disappearing is **not** an input here. There is
    /// no abandoned-host path: an unexpired claim stays held by its recorded
    /// owner, so process exit is neither lease revocation nor authority to
    /// repeat an external effect. Only the persisted lease clock resolves a
    /// claim, and only in one of two ways: a claim whose effect never started is
    /// retried against the same attempt identity, while a claim whose effect was
    /// already in flight stays in doubt and is never blindly repeated.
    pub fn recover_next_expired_command(&self, run_id: &str) -> Result<bool> {
        self.with_connection(|connection| {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            // Selection and transition run under the same write lock: a lease
            // renewal that commits first makes the claim unexpired and it is
            // never selected, so a renewed claim cannot be retried or marked
            // in-doubt behind its owner's back.
            let value: Option<(String, String)> = transaction
                .query_row(
                    "SELECT command_json, status FROM strategy_commands
                     WHERE run_id=?1 AND status IN ('claimed', 'running')
                       AND lease_until IS NOT NULL AND lease_until<=?2
                     ORDER BY command_id ASC LIMIT 1",
                    params![run_id, now_ms()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            let Some((command_json, persisted_status)) = value else {
                transaction.commit()?;
                return Ok(false);
            };
            let command: RunCommand = serde_json::from_str(&command_json)?;
            let expected_status = enum_wire(command.status)?;
            ensure!(
                expected_status == persisted_status
                    && matches!(
                        command.status,
                        CommandStatus::Claimed | CommandStatus::Running
                    ),
                "strategy_recovery_state_conflict"
            );
            let previous = load_run(&transaction, run_id)?;
            ensure!(
                previous.commands.get(&command.id).is_some_and(|current| {
                    current.status == command.status
                        && current.attempt_token == command.attempt_token
                }),
                "strategy_recovery_state_conflict"
            );
            let workflow = workflow_for_revision(&transaction, &previous.definition_digest)?;
            let compiled = compile_workflow(workflow, &self.dialect.workflow_schema)?;
            let (class, code) = match command.status {
                CommandStatus::Claimed => (FailureClass::Transient, "lease_expired_before_start"),
                _ => (FailureClass::InDoubt, "effect_outcome_unknown"),
            };
            let failure_event = ReducerEvent::CommandFailed {
                command_id: command.id.clone(),
                attempt_token: command.attempt_token.clone(),
                class,
                code: code.to_owned(),
            };
            let failure = reduce(&compiled, &previous, failure_event.clone())?;
            let now = now_ms();
            persist_event_and_commands(
                &transaction,
                &previous,
                &failure.snapshot,
                &failure_event,
                &failure.emitted_commands,
                now,
            )?;
            let final_snapshot = if failure
                .snapshot
                .commands
                .get(&command.id)
                .is_some_and(|current| current.status == CommandStatus::Retryable)
            {
                let retry_event = ReducerEvent::RetryRequested {
                    command_id: command.id.clone(),
                };
                let retry = reduce(&compiled, &failure.snapshot, retry_event.clone())?;
                persist_event_and_commands(
                    &transaction,
                    &failure.snapshot,
                    &retry.snapshot,
                    &retry_event,
                    &retry.emitted_commands,
                    now,
                )?;
                retry.snapshot
            } else {
                failure.snapshot
            };
            transaction.execute(
                "UPDATE strategy_runs SET snapshot_json=?2, context_id=?3,
                 terminal=?4, updated_at=?5 WHERE run_id=?1",
                params![
                    run_id,
                    serde_json::to_string(&final_snapshot)?,
                    final_snapshot.context_id,
                    i64::from(run_is_terminal(final_snapshot.status)),
                    now
                ],
            )?;
            transaction.execute(
                "UPDATE strategy_commands SET lease_owner=NULL, lease_until=NULL
                 WHERE command_id=?1",
                params![&command.id],
            )?;
            transaction.commit()?;
            Ok(true)
        })
    }

    pub fn projection_for_definition(&self, revision_digest: &str) -> Result<StrategyProjection> {
        let definition = self.definition_by_revision(revision_digest)?;
        let complete = bindings_complete(&definition);
        let mut allowed = BTreeSet::from([
            "strategy.definition.inspect".into(),
            "strategy.binding.update".into(),
            "strategy.binding.replace".into(),
            "strategy.authorization.preview".into(),
        ]);
        let status = if complete {
            if definition
                .authorization
                .as_ref()
                .is_some_and(|value| value.active)
            {
                allowed.extend([
                    "strategy.authorization.revoke".into(),
                    "strategy.run.start".into(),
                ]);
                StrategyRunStatus::Pending
            } else {
                allowed.insert("strategy.authorization.grant".into());
                StrategyRunStatus::AuthorizationRequired
            }
        } else {
            StrategyRunStatus::Pending
        };
        Ok(StrategyProjection {
            schema: self.dialect.projection_schema.to_string(),
            definition: definition.summary,
            run_id: None,
            status,
            current_states: BTreeSet::new(),
            neighbor_states: BTreeSet::new(),
            allowed_operations: allowed,
            bindings: definition.bindings,
            diagnostic: if complete {
                None
            } else {
                Some(StrategyDiagnostic {
                    code: "binding_incomplete".into(),
                    component: "strategy_binding".into(),
                    retryable: true,
                    recovery: "Bind every required actor and runtime slot.".into(),
                    arguments: BTreeMap::new(),
                })
            },
            history_count: 0,
            fallbacks: Vec::new(),
            pending_callbacks: Vec::new(),
            needs_human_input: false,
            entry_session_id: None,
        })
    }

    pub fn projection_for_run(&self, run_id: &str) -> Result<StrategyProjection> {
        let snapshot = self.run(run_id)?;
        let definition = self.definition_by_revision(&snapshot.definition_digest)?;
        let compiled =
            compile_workflow(definition.workflow.clone(), &self.dialect.workflow_schema)?;
        let neighbors = snapshot
            .active_states
            .iter()
            .flat_map(|state| {
                compiled
                    .outgoing(state)
                    .map(|transition| transition.to.clone())
            })
            .collect();
        let mut allowed = BTreeSet::from(["strategy.run.inspect".into()]);
        match snapshot.status {
            StrategyRunStatus::AuthorizationRequired
            | StrategyRunStatus::RuntimeMissing
            | StrategyRunStatus::Waiting => {
                allowed.insert("strategy.run.resume".into());
                allowed.insert("strategy.run.cancel".into());
            }
            StrategyRunStatus::Running => {
                allowed.insert("strategy.run.resume".into());
                allowed.insert("strategy.run.cancel".into());
            }
            StrategyRunStatus::Retryable => {
                allowed.insert("strategy.run.retry".into());
                allowed.insert("strategy.run.cancel".into());
            }
            StrategyRunStatus::CancelRequested => {
                allowed.insert("strategy.run.inspect".into());
            }
            _ => {}
        }
        let history_count = self.with_connection(|connection| -> Result<u64> {
            connection
                .query_row(
                    "SELECT COUNT(*) FROM strategy_run_events WHERE run_id=?1",
                    params![run_id],
                    |row| row.get::<_, i64>(0).map(|value| value as u64),
                )
                .map_err(Into::into)
        })?;
        let pending_callbacks = snapshot.pending_callbacks.clone();
        Ok(StrategyProjection {
            schema: self.dialect.projection_schema.to_string(),
            definition: definition.summary,
            run_id: Some(run_id.to_owned()),
            status: snapshot.status,
            current_states: snapshot.active_states,
            neighbor_states: neighbors,
            allowed_operations: allowed,
            bindings: definition.bindings,
            diagnostic: snapshot.diagnostic_code.map(|code| StrategyDiagnostic {
                component: "strategy_runtime".into(),
                retryable: matches!(
                    snapshot.status,
                    StrategyRunStatus::Retryable
                        | StrategyRunStatus::RuntimeMissing
                        | StrategyRunStatus::AuthorizationRequired
                ),
                recovery: recovery_for_status(snapshot.status).into(),
                code,
                arguments: BTreeMap::new(),
            }),
            history_count,
            fallbacks: snapshot.fallbacks,
            pending_callbacks: pending_callbacks.clone(),
            needs_human_input: !pending_callbacks.is_empty()
                || matches!(
                    snapshot.status,
                    StrategyRunStatus::AuthorizationRequired
                        | StrategyRunStatus::RuntimeMissing
                        | StrategyRunStatus::Waiting
                        | StrategyRunStatus::Retryable
                ),
            entry_session_id: definition
                .workflow
                .actor_slots
                .iter()
                .find(|slot| slot.kind == crate::BindingKind::Actor && slot.entry)
                .and_then(|slot| {
                    let prefix = format!("{}\0", slot.id);
                    snapshot
                        .actor_sessions
                        .iter()
                        .filter(|(key, _)| key.starts_with(&prefix))
                        .filter_map(|(key, session)| {
                            snapshot
                                .merge_sources
                                .get(&format!("session\0{key}"))
                                .map(|source| (source, key, session))
                        })
                        .max_by(|left, right| left.0.cmp(right.0).then(left.1.cmp(right.1)))
                        .map(|(_, _, session)| session.clone())
                }),
        })
    }

    /// The live (non-terminal) run bound to one host context under one
    /// revision, when there is one.
    pub fn active_run_for_context(
        &self,
        revision_digest: &str,
        context_id: &str,
    ) -> Result<Option<RunSnapshot>> {
        validate_opaque_id(context_id, "strategy_context_id_invalid")?;
        self.with_connection(|connection| {
            connection
                .query_row(
                    "SELECT snapshot_json FROM strategy_runs
                     WHERE revision_digest=?1 AND context_id=?2 AND terminal=0
                     ORDER BY updated_at DESC LIMIT 1",
                    params![revision_digest, context_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .map(|snapshot_json| serde_json::from_str(&snapshot_json).map_err(Into::into))
                .transpose()
        })
    }

    /// Bind one run to its host context when it was admitted without one. A
    /// run that already names a context keeps it: binding is fill-once, never
    /// a re-association.
    pub fn bind_context_if_absent(&self, run_id: &str, context_id: &str) -> Result<()> {
        validate_opaque_id(context_id, "strategy_context_id_invalid")?;
        self.with_connection(|connection| {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let mut snapshot = load_run(&transaction, run_id)?;
            if snapshot
                .context_id
                .as_deref()
                .is_some_and(|value| !value.is_empty())
            {
                transaction.commit()?;
                return Ok(());
            }
            snapshot.context_id = Some(context_id.to_owned());
            transaction.execute(
                "UPDATE strategy_runs SET snapshot_json=?2, context_id=?3, updated_at=?4
                 WHERE run_id=?1",
                params![
                    run_id,
                    serde_json::to_string(&snapshot)?,
                    snapshot.context_id,
                    now_ms()
                ],
            )?;
            transaction.commit()?;
            Ok(())
        })
    }
}

fn initialize_schema(connection: &mut Connection) -> Result<()> {
    initialize_schema_through(connection)?;
    super::queue::initialize_schema(connection)?;
    super::subscriptions::initialize_schema(connection)?;
    super::commit::initialize_schema(connection)?;
    super::controlled::initialize_schema(connection)?;
    Ok(())
}

fn initialize_schema_through(connection: &mut Connection) -> Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS strategy_meta(
           key TEXT PRIMARY KEY, value TEXT NOT NULL
         );
         INSERT INTO strategy_meta(key, value) VALUES ('version', '1')
           ON CONFLICT(key) DO NOTHING;
         CREATE TABLE IF NOT EXISTS strategy_definitions(
           definition_id TEXT NOT NULL,
           revision_digest TEXT PRIMARY KEY,
           semantics_digest TEXT NOT NULL,
           name TEXT NOT NULL,
           version TEXT NOT NULL,
           workflow_json TEXT NOT NULL,
           asset_count INTEGER NOT NULL,
           imported_at INTEGER NOT NULL
         );
         CREATE INDEX IF NOT EXISTS strategy_definitions_id_idx
           ON strategy_definitions(definition_id, imported_at DESC);
         CREATE TABLE IF NOT EXISTS strategy_bindings(
           revision_digest TEXT NOT NULL REFERENCES strategy_definitions(revision_digest) ON DELETE CASCADE,
           slot_id TEXT NOT NULL,
           ordinal INTEGER NOT NULL DEFAULT 0,
           value_id TEXT NOT NULL,
           model TEXT NOT NULL DEFAULT '',
           reasoning_effort TEXT NOT NULL DEFAULT '',
           revision INTEGER NOT NULL,
           PRIMARY KEY(revision_digest, slot_id, ordinal)
         );
         CREATE TABLE IF NOT EXISTS strategy_authorizations(
           revision_digest TEXT NOT NULL REFERENCES strategy_definitions(revision_digest) ON DELETE CASCADE,
           revision INTEGER NOT NULL,
           semantics_digest TEXT NOT NULL,
           binding_digest TEXT NOT NULL,
           authorization_digest TEXT NOT NULL,
           active INTEGER NOT NULL,
           created_at INTEGER NOT NULL,
           PRIMARY KEY(revision_digest, revision)
         );
         CREATE UNIQUE INDEX IF NOT EXISTS strategy_authorization_active_idx
           ON strategy_authorizations(revision_digest) WHERE active=1;
         CREATE TABLE IF NOT EXISTS strategy_runs(
           run_id TEXT PRIMARY KEY,
           revision_digest TEXT NOT NULL REFERENCES strategy_definitions(revision_digest),
           semantics_digest TEXT NOT NULL,
           idempotency_key TEXT NOT NULL UNIQUE,
           request_digest TEXT NOT NULL,
           snapshot_json TEXT NOT NULL,
           context_id TEXT,
           terminal INTEGER NOT NULL,
           created_at INTEGER NOT NULL,
           updated_at INTEGER NOT NULL
         );
         CREATE INDEX IF NOT EXISTS strategy_runs_revision_idx
           ON strategy_runs(revision_digest, updated_at DESC);
         CREATE TABLE IF NOT EXISTS strategy_run_events(
           run_id TEXT NOT NULL REFERENCES strategy_runs(run_id) ON DELETE CASCADE,
           sequence INTEGER NOT NULL,
           event_type TEXT NOT NULL,
           event_json TEXT NOT NULL,
           created_at INTEGER NOT NULL,
           PRIMARY KEY(run_id, sequence)
         );
         CREATE TABLE IF NOT EXISTS strategy_commands(
           command_id TEXT PRIMARY KEY,
           run_id TEXT NOT NULL REFERENCES strategy_runs(run_id) ON DELETE CASCADE,
           state_id TEXT NOT NULL,
           kind TEXT NOT NULL,
           status TEXT NOT NULL,
           attempt INTEGER NOT NULL,
           attempt_token TEXT NOT NULL,
           command_json TEXT NOT NULL,
           lease_owner TEXT,
           lease_until INTEGER,
           updated_at INTEGER NOT NULL
         );
         CREATE INDEX IF NOT EXISTS strategy_commands_ready_idx
           ON strategy_commands(status, command_id);
         CREATE INDEX IF NOT EXISTS strategy_commands_lease_idx
           ON strategy_commands(lease_until) WHERE status IN ('claimed', 'running');",
    )?;
    connection.execute_batch(
        "CREATE INDEX IF NOT EXISTS strategy_runs_active_context_idx
           ON strategy_runs(revision_digest, context_id, terminal, updated_at DESC);",
    )?;
    Ok(())
}

fn validate_current_schema(connection: &mut Connection) -> Result<()> {
    configure_connection(connection)?;
    let version: String = connection.query_row(
        "SELECT value FROM strategy_meta WHERE key='version'",
        [],
        |row| row.get(0),
    )?;
    ensure!(
        version == META_VERSION,
        "strategy_schema_migration_required"
    );
    super::queue::initialize_schema(connection)?;
    super::subscriptions::initialize_schema(connection)?;
    super::commit::initialize_schema(connection)?;
    super::controlled::initialize_schema(connection)?;
    Ok(())
}

pub(crate) fn preflight_existing_store(path: &Path) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "unsupported_state_shape"
    );
    let connection = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let version: String = connection.query_row(
        "SELECT value FROM strategy_meta WHERE key='version'",
        [],
        |row| row.get(0),
    )?;
    ensure!(version == META_VERSION, "unsupported_state_shape");
    validate_published_core_layout(&connection, &version)
}

/// Read-only validation of this build's published core layout.
///
/// The caller names the `strategy_meta.version` it classified the file as.
/// The tables, columns, keys, foreign keys, uniqueness constraints and named
/// indexes are then checked exactly, so a database that merely carries a
/// version row — or one whose primary key or unique authorization index is
/// missing — is refused without writing a byte.
pub fn validate_published_core_layout(
    connection: &Connection,
    expected_meta_version: &str,
) -> Result<()> {
    let version: Option<String> = connection
        .query_row(
            "SELECT value FROM strategy_meta WHERE key='version'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    ensure!(
        version.as_deref() == Some(expected_meta_version),
        "unsupported_state_shape"
    );
    // Validate all write semantics, including tables created on demand by
    // their owners. An absent auxiliary table is created by startup; a
    // malformed existing table is never repaired by CREATE IF NOT EXISTS.
    let mut reference = Connection::open_in_memory()?;
    initialize_schema_through(&mut reference)?;
    let required = sqlite_contract::tables(&reference)?;
    super::queue::initialize_schema(&reference)?;
    super::subscriptions::initialize_schema(&reference)?;
    super::commit::initialize_schema(&reference)?;
    super::controlled::initialize_schema(&reference)?;
    let existing = sqlite_contract::tables(connection)?;
    for table in sqlite_contract::tables(&reference)? {
        if !existing.contains(&table) && !required.contains(&table) {
            continue;
        }
        sqlite_contract::validate_table(connection, &reference, &table, None)?;
    }
    Ok(())
}

fn run_is_terminal(status: StrategyRunStatus) -> bool {
    matches!(
        status,
        StrategyRunStatus::Completed
            | StrategyRunStatus::Failed
            | StrategyRunStatus::Cancelled
            | StrategyRunStatus::Blocked
            | StrategyRunStatus::CancelInDoubt
    )
}

fn configure_connection(connection: &Connection) -> Result<()> {
    connection.execute_batch(
        "PRAGMA foreign_keys=ON;
         PRAGMA journal_mode=WAL;
         PRAGMA synchronous=FULL;
         PRAGMA busy_timeout=5000;",
    )?;
    Ok(())
}

type DefinitionRow = (String, String, String, String, String, String, i64, i64);

fn definition_by_revision(connection: &Connection, revision: &str) -> Result<StrategyDefinition> {
    let base: Option<DefinitionRow> = connection
        .query_row(
            "SELECT definition_id, revision_digest, semantics_digest, name, version,
             workflow_json, asset_count, imported_at FROM strategy_definitions
             WHERE revision_digest=?1",
            params![revision],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            },
        )
        .optional()?;
    let Some((
        definition_id,
        revision_digest,
        semantics_digest,
        name,
        version,
        workflow_json,
        asset_count,
        imported_at,
    )) = base
    else {
        return Err(anyhow!("strategy_definition_not_found"));
    };
    let workflow: WorkflowDefinition = serde_json::from_str(&workflow_json)?;
    let bindings = load_bindings(connection, &revision_digest)?;
    let authorization = load_authorization(connection, &revision_digest)?;
    Ok(StrategyDefinition {
        summary: StrategyDefinitionSummary {
            definition_id,
            revision_digest,
            semantics_digest,
            name,
            version,
            imported_at_unix_ms: imported_at,
            authorized: authorization.as_ref().is_some_and(|value| value.active),
        },
        workflow,
        asset_count: asset_count as usize,
        bindings,
        authorization,
    })
}

fn summary_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StrategyDefinitionSummary> {
    Ok(StrategyDefinitionSummary {
        definition_id: row.get(0)?,
        revision_digest: row.get(1)?,
        semantics_digest: row.get(2)?,
        name: row.get(3)?,
        version: row.get(4)?,
        imported_at_unix_ms: row.get(5)?,
        authorized: row
            .get::<_, i64>(6)
            .map(|value| value != 0)
            .unwrap_or(false),
    })
}

fn load_bindings(connection: &Connection, revision: &str) -> Result<Vec<BindingValue>> {
    let mut statement = connection.prepare(
        "SELECT slot_id, ordinal, value_id, model, reasoning_effort, revision
         FROM strategy_bindings
         WHERE revision_digest=?1 ORDER BY slot_id ASC, ordinal ASC",
    )?;
    let rows = statement.query_map(params![revision], |row| {
        Ok(BindingValue {
            slot_id: row.get(0)?,
            ordinal: row.get::<_, i64>(1)? as u8,
            value_id: row.get(2)?,
            model: row.get(3)?,
            reasoning_effort: row.get(4)?,
            revision: row.get::<_, i64>(5)? as u64,
        })
    })?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}

fn load_authorization(
    connection: &Connection,
    revision: &str,
) -> Result<Option<StrategyAuthorization>> {
    connection
        .query_row(
            "SELECT revision, semantics_digest, binding_digest, authorization_digest, active
             FROM strategy_authorizations WHERE revision_digest=?1
             ORDER BY revision DESC LIMIT 1",
            params![revision],
            |row| {
                Ok(StrategyAuthorization {
                    definition_digest: revision.to_owned(),
                    revision: row.get::<_, i64>(0)? as u64,
                    semantics_digest: row.get(1)?,
                    binding_digest: row.get(2)?,
                    authorization_digest: row.get(3)?,
                    active: row.get::<_, i64>(4)? != 0,
                })
            },
        )
        .optional()
        .map_err(Into::into)
}

fn current_authorization(definition: &StrategyDefinition) -> Result<&StrategyAuthorization> {
    definition
        .authorization
        .as_ref()
        .filter(|authorization| {
            authorization.active
                && authorization.definition_digest == definition.summary.revision_digest
                && authorization.semantics_digest == definition.summary.semantics_digest
        })
        .ok_or_else(|| anyhow!("strategy_authorization_required"))
}

fn bindings_complete(definition: &StrategyDefinition) -> bool {
    let bound = definition
        .bindings
        .iter()
        .filter(|binding| binding.ordinal == 0)
        .map(|binding| binding.slot_id.as_str())
        .collect::<BTreeSet<_>>();
    definition
        .workflow
        .actor_slots
        .iter()
        .filter(|slot| slot.required)
        .all(|slot| bound.contains(slot.id.as_str()))
}

fn binding_digest(bindings: &[BindingValue]) -> Result<String> {
    let mut sorted = bindings.to_vec();
    sorted.sort_by(|left, right| {
        left.slot_id
            .cmp(&right.slot_id)
            .then(left.ordinal.cmp(&right.ordinal))
    });
    Ok(sha256_hex(&serde_json::to_vec(&sorted)?))
}

fn slot_candidate_counts(bindings: &[BindingValue]) -> BTreeMap<String, u8> {
    let mut counts = BTreeMap::new();
    for binding in bindings {
        let entry = counts.entry(binding.slot_id.clone()).or_insert(0);
        *entry = (*entry).max(binding.ordinal.saturating_add(1));
    }
    counts
}

fn authorization_digest(
    revision: &str,
    semantics: &str,
    bindings: &str,
    authorization_revision: u64,
) -> String {
    sha256_hex(
        format!(
            "acativa.strategy-authorization.v1\0{revision}\0{semantics}\0{bindings}\0{authorization_revision}"
        )
        .as_bytes(),
    )
}

fn workflow_for_revision(connection: &Connection, revision: &str) -> Result<WorkflowDefinition> {
    let value: String = connection
        .query_row(
            "SELECT workflow_json FROM strategy_definitions WHERE revision_digest=?1",
            params![revision],
            |row| row.get(0),
        )
        .optional()?
        .ok_or_else(|| anyhow!("strategy_definition_not_found"))?;
    serde_json::from_str(&value).map_err(Into::into)
}

fn load_run(connection: &Connection, run_id: &str) -> Result<RunSnapshot> {
    let value: Option<String> = connection
        .query_row(
            "SELECT snapshot_json FROM strategy_runs WHERE run_id=?1",
            params![run_id],
            |row| row.get(0),
        )
        .optional()?;
    serde_json::from_str(
        value
            .as_deref()
            .ok_or_else(|| anyhow!("strategy_run_not_found"))?,
    )
    .map_err(Into::into)
}

fn persist_event_and_commands(
    transaction: &Transaction<'_>,
    before: &RunSnapshot,
    snapshot: &RunSnapshot,
    event: &ReducerEvent,
    emitted: &[RunCommand],
    now: i64,
) -> Result<()> {
    let event_json = serde_json::to_string(event)?;
    let event_type = event_json.split('"').nth(3).unwrap_or("event").to_owned();
    transaction.execute(
        "INSERT INTO strategy_run_events(run_id, sequence, event_type, event_json, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            snapshot.run_id,
            snapshot.sequence as i64,
            event_type,
            event_json,
            now
        ],
    )?;
    super::commit::insert_intent(
        transaction,
        &snapshot.run_id,
        snapshot.sequence,
        event,
        before,
        snapshot,
        now,
    )?;
    for command in emitted {
        transaction.execute(
            "INSERT INTO strategy_commands(
               command_id, run_id, state_id, kind, status, attempt,
               attempt_token, command_json, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                command.id,
                snapshot.run_id,
                command.state_id,
                enum_wire(command.kind)?,
                enum_wire(command.status)?,
                command.attempt as i64,
                command.attempt_token,
                serde_json::to_string(command)?,
                now,
            ],
        )?;
    }
    // Only the commands this event touched are rewritten; updating every
    // accumulated row per event would turn a long run's persistence quadratic.
    let emitted_ids = emitted
        .iter()
        .map(|command| command.id.as_str())
        .collect::<BTreeSet<_>>();
    for command in snapshot.commands.values().filter(|command| {
        !emitted_ids.contains(command.id.as_str())
            && before.commands.get(&command.id) != Some(command)
    }) {
        transaction.execute(
            "UPDATE strategy_commands SET status=?2, command_json=?3, updated_at=?4
             WHERE command_id=?1",
            params![
                command.id,
                enum_wire(command.status)?,
                serde_json::to_string(command)?,
                now,
            ],
        )?;
    }
    Ok(())
}

/// Authenticate a command lifecycle event against the persisted lease inside
/// the committing transaction.
///
/// The attempt token alone is not authority: a caller that learned one (logs,
/// an older lease, a replayed message) could otherwise settle a command it
/// does not own. While a claim's lease is live the persisted `lease_owner`
/// must equal the presented claimant; an expired or absent lease admits the
/// event on the token the reducer still checks. `CommandClaimed` is refused
/// outright here because a claim is only durable through the lease-writing
/// [`StrategyStore::claim_next_command`] path.
fn authenticate_command_event(
    transaction: &Transaction<'_>,
    run_id: &str,
    event: &ReducerEvent,
    claimant: Option<&str>,
) -> Result<()> {
    let (command_id, attempt_token) = match event {
        ReducerEvent::CommandClaimed { .. } => {
            return Err(anyhow!("strategy_claim_requires_lease"));
        }
        ReducerEvent::CommandStarted {
            command_id,
            attempt_token,
        }
        | ReducerEvent::CommandSucceeded {
            command_id,
            attempt_token,
            ..
        }
        | ReducerEvent::CommandFailed {
            command_id,
            attempt_token,
            ..
        }
        | ReducerEvent::CancellationAcknowledged {
            command_id,
            attempt_token,
        }
        | ReducerEvent::CancellationUnknown {
            command_id,
            attempt_token,
        } => (command_id, Some(attempt_token.as_str())),
        ReducerEvent::RetryRequested { command_id } => (command_id, None),
        _ => return Ok(()),
    };
    let lease: Option<(String, Option<String>, Option<i64>)> = transaction
        .query_row(
            "SELECT attempt_token, lease_owner, lease_until FROM strategy_commands
             WHERE command_id=?1 AND run_id=?2",
            params![command_id, run_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((persisted_token, owner, lease_until)) = lease else {
        // A command row the event names but the store never recorded is the
        // reducer's problem: it reports the stale callback itself.
        return Ok(());
    };
    if let Some(token) = attempt_token {
        ensure!(persisted_token == token, "strategy_callback_stale");
    }
    if let (Some(owner), Some(until)) = (owner, lease_until)
        && until > now_ms()
    {
        ensure!(claimant == Some(owner.as_str()), "strategy_lease_lost");
    }
    Ok(())
}

/// The observer-facing half of a committed transition: the full run-level
/// state of `snapshot`, but only the commands whose record differs in
/// `other`. Persisting and dispatching this delta keeps each transition's
/// cost proportional to the work it changed, not to the whole accumulated
/// ledger.
pub(crate) fn transition_delta(snapshot: &RunSnapshot, other: &RunSnapshot) -> RunSnapshot {
    let mut delta = snapshot.clone();
    delta.commands = snapshot
        .commands
        .iter()
        .filter(|(id, command)| other.commands.get(*id) != Some(command))
        .map(|(id, command)| (id.clone(), command.clone()))
        .collect();
    delta
}

fn enum_wire(value: impl serde::Serialize) -> Result<String> {
    serde_json::to_value(value)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("strategy_enum_invalid"))
}

fn validate_opaque_id(value: &str, code: &'static str) -> Result<()> {
    ensure!(
        value == value.trim()
            && !value.is_empty()
            && value.len() <= 160
            && !value.chars().any(char::is_control),
        code
    );
    Ok(())
}

fn validate_optional_text(value: &str, code: &'static str) -> Result<()> {
    ensure!(
        value == value.trim() && value.len() <= 160 && !value.chars().any(char::is_control),
        code
    );
    Ok(())
}

fn recovery_for_status(status: StrategyRunStatus) -> &'static str {
    match status {
        StrategyRunStatus::AuthorizationRequired => "Review and authorize the current semantics.",
        StrategyRunStatus::RuntimeMissing => "Bind an available verified local runtime.",
        StrategyRunStatus::Retryable => "Retry the failed command.",
        StrategyRunStatus::CancelInDoubt => "Inspect the external effect before continuing.",
        _ => "Inspect the run history.",
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ActorSlot, GraphState, GraphStateKind, RetryPolicy, Transition, TransitionEvent,
        TransitionMode, WorkflowLimits, WorkflowMetadata,
    };
    use serde_json::json;

    fn workflow() -> WorkflowDefinition {
        WorkflowDefinition {
            schema: crate::GENERIC_WORKFLOW_SCHEMA.into(),
            metadata: WorkflowMetadata {
                id: "test".into(),
                name: "Test".into(),
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
                    retry: RetryPolicy {
                        max_attempts: 2,
                        transient_only: true,
                    },
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
    fn open_rejects_a_foreign_meta_version() {
        let root =
            std::env::temp_dir().join(format!("acativa-strategy-foreign-{}", Uuid::new_v4()));
        let database = root.join("client-state/acativa/strategies.sqlite3");
        fs::create_dir_all(database.parent().unwrap()).unwrap();
        let connection = Connection::open(&database).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE strategy_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
                 INSERT INTO strategy_meta(key, value) VALUES ('version', '0');",
            )
            .unwrap();
        drop(connection);
        // A version this build did not write is a foreign database, not a
        // migration input: the engine owns no legacy layout to convert.
        assert!(StrategyStore::open(&root, &StoreDialect::generic()).is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn event_snapshot_and_outbox_commit_together() {
        let store = StrategyStore::open_in_memory().unwrap();
        store
            .register_definition(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                &workflow(),
                1,
                1,
            )
            .unwrap();
        let binding = store
            .update_binding(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "worker",
                "agent:test",
                "gpt-5",
                "high",
                None,
            )
            .unwrap();
        assert_eq!(binding.model, "gpt-5");
        assert_eq!(binding.reasoning_effort, "high");
        let persisted = store
            .definition_by_revision(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap();
        assert_eq!(persisted.bindings[0].ordinal, 0);
        assert_eq!(persisted.bindings[0].model, "gpt-5");
        assert_eq!(persisted.bindings[0].reasoning_effort, "high");
        let chain = store
            .replace_slot_bindings(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "worker",
                &[
                    BindingCandidate {
                        value_id: "agent:primary".into(),
                        model: "model-a".into(),
                        reasoning_effort: "high".into(),
                    },
                    BindingCandidate {
                        value_id: "agent:fallback".into(),
                        model: "model-b".into(),
                        reasoning_effort: String::new(),
                    },
                ],
                Some(binding.revision),
            )
            .unwrap();
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].ordinal, 0);
        assert_eq!(chain[1].ordinal, 1);
        assert_eq!(chain[1].value_id, "agent:fallback");
        let preview = store
            .authorization_preview(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap();
        store
            .grant_authorization(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                &preview.authorization_digest,
            )
            .unwrap();
        let run = store
            .start_run(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                json!({}),
                "idempotency-test",
                Some("context:test"),
                None,
            )
            .unwrap();
        assert_eq!(run.commands.len(), 1);
        assert_eq!(
            store
                .active_run_for_context(
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "context:test",
                )
                .unwrap()
                .map(|snapshot| snapshot.run_id),
            Some(run.run_id.clone())
        );
        let indexed: (String, i64) = store
            .with_connection(|connection| {
                connection
                    .query_row(
                        "SELECT context_id, terminal FROM strategy_runs WHERE run_id=?1",
                        params![run.run_id],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .map_err(Into::into)
            })
            .unwrap();
        assert_eq!(indexed, ("context:test".to_owned(), 0));
        let replay = store
            .start_run(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                json!({}),
                "idempotency-test",
                Some("context:test"),
                None,
            )
            .unwrap();
        assert_eq!(run, replay);
    }

    #[test]
    fn effect_authorization_revalidates_digest_owner_and_live_lease() {
        let store = StrategyStore::open_in_memory().unwrap();
        let revision = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
        store
            .register_definition(revision, revision, &workflow(), 1, 1)
            .unwrap();
        store
            .update_binding(revision, "worker", "agent:test", "", "", None)
            .unwrap();
        let preview = store.authorization_preview(revision).unwrap();
        let authorization = store
            .grant_authorization(revision, &preview.authorization_digest)
            .unwrap();
        let run = store
            .start_run(revision, json!({}), "authorization-fence", None, None)
            .unwrap();
        let command = store
            .claim_next_command(&run.run_id, "claimant", now_ms() + 60_000)
            .unwrap()
            .unwrap();
        store
            .apply_owned_event(
                &run.run_id,
                "claimant",
                ReducerEvent::CommandStarted {
                    command_id: command.id.clone(),
                    attempt_token: command.attempt_token.clone(),
                },
            )
            .unwrap();
        store
            .authorize_effect(
                &run.run_id,
                &command.id,
                &command.attempt_token,
                &authorization.authorization_digest,
                "claimant",
                now_ms() + 60_000,
            )
            .unwrap();
        assert!(
            store
                .authorize_effect(
                    &run.run_id,
                    &command.id,
                    &command.attempt_token,
                    &authorization.authorization_digest,
                    "other-claimant",
                    now_ms() + 60_000,
                )
                .is_err()
        );
        store.revoke_authorization(revision).unwrap();
        assert!(
            store
                .authorize_effect(
                    &run.run_id,
                    &command.id,
                    &command.attempt_token,
                    &authorization.authorization_digest,
                    "claimant",
                    now_ms() + 60_000,
                )
                .is_err()
        );
        let next = store.authorization_preview(revision).unwrap();
        let next = store
            .grant_authorization(revision, &next.authorization_digest)
            .unwrap();
        assert!(
            store
                .authorize_effect(
                    &run.run_id,
                    &command.id,
                    &command.attempt_token,
                    &authorization.authorization_digest,
                    "claimant",
                    now_ms() + 60_000,
                )
                .is_err()
        );
        store
            .authorize_effect(
                &run.run_id,
                &command.id,
                &command.attempt_token,
                &next.authorization_digest,
                "claimant",
                now_ms() + 60_000,
            )
            .unwrap();
        let connection = Connection::open(store.db_path()).unwrap();
        connection
            .execute(
                "UPDATE strategy_commands SET lease_until=0 WHERE command_id=?1",
                params![&command.id],
            )
            .unwrap();
        assert!(
            store
                .authorize_effect(
                    &run.run_id,
                    &command.id,
                    &command.attempt_token,
                    &next.authorization_digest,
                    "claimant",
                    now_ms() + 60_000,
                )
                .is_err(),
            "an expired running lease must never issue an effect permit"
        );
    }

    #[test]
    fn expired_claim_recovery_is_atomic_and_retries_before_start() {
        let store = StrategyStore::open_in_memory().unwrap();
        let revision = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        store
            .register_definition(
                revision,
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                &workflow(),
                1,
                1,
            )
            .unwrap();
        store
            .update_binding(revision, "worker", "agent:test", "", "", None)
            .unwrap();
        let preview = store.authorization_preview(revision).unwrap();
        store
            .grant_authorization(revision, &preview.authorization_digest)
            .unwrap();
        let run = store
            .start_run(revision, json!({}), "recovery-test", None, None)
            .unwrap();
        let claimed = store
            .claim_next_command(&run.run_id, "claimant", now_ms() + 60_000)
            .unwrap()
            .unwrap();
        let connection = Connection::open(store.db_path()).unwrap();
        connection
            .execute(
                "UPDATE strategy_commands SET lease_until=0 WHERE command_id=?1",
                params![claimed.id],
            )
            .unwrap();

        assert!(store.recover_next_expired_command(&run.run_id).unwrap());
        assert!(!store.recover_next_expired_command(&run.run_id).unwrap());
        assert!(
            store
                .renew_command_lease(&claimed.id, "claimant", now_ms() + 60_000)
                .is_err()
        );
        let recovered = store.run(&run.run_id).unwrap();
        assert_eq!(
            recovered.commands[&claimed.id].status,
            CommandStatus::Cancelled
        );
        assert!(
            recovered.commands.values().any(|command| {
                command.attempt == 2 && command.status == CommandStatus::Pending
            })
        );
    }

    #[test]
    fn expired_running_effect_is_fenced_in_doubt_without_retry() {
        let store = StrategyStore::open_in_memory().unwrap();
        let revision = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        store
            .register_definition(
                revision,
                "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                &workflow(),
                1,
                1,
            )
            .unwrap();
        store
            .update_binding(revision, "worker", "agent:test", "", "", None)
            .unwrap();
        let preview = store.authorization_preview(revision).unwrap();
        store
            .grant_authorization(revision, &preview.authorization_digest)
            .unwrap();
        let run = store
            .start_run(revision, json!({}), "running-recovery-test", None, None)
            .unwrap();
        let claimed = store
            .claim_next_command(&run.run_id, "claimant", now_ms() + 60_000)
            .unwrap()
            .unwrap();
        store
            .apply_owned_event(
                &run.run_id,
                "claimant",
                ReducerEvent::CommandStarted {
                    command_id: claimed.id.clone(),
                    attempt_token: claimed.attempt_token.clone(),
                },
            )
            .unwrap();
        let connection = Connection::open(store.db_path()).unwrap();
        connection
            .execute(
                "UPDATE strategy_commands SET lease_until=0 WHERE command_id=?1",
                params![claimed.id],
            )
            .unwrap();

        assert!(store.recover_next_expired_command(&run.run_id).unwrap());
        let recovered = store.run(&run.run_id).unwrap();
        assert_eq!(recovered.status, StrategyRunStatus::CancelInDoubt);
        assert_eq!(
            recovered.commands[&claimed.id].status,
            CommandStatus::InDoubt
        );
        assert!(
            !recovered
                .commands
                .values()
                .any(|command| command.attempt == 2)
        );
    }

    #[test]
    fn an_unexpired_claim_stays_held_when_this_host_becomes_the_driver() {
        let store = StrategyStore::open_in_memory().unwrap();
        let revision = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
        store
            .register_definition(
                revision,
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                &workflow(),
                1,
                1,
            )
            .unwrap();
        store
            .update_binding(revision, "worker", "agent:test", "", "", None)
            .unwrap();
        let preview = store.authorization_preview(revision).unwrap();
        store
            .grant_authorization(revision, &preview.authorization_digest)
            .unwrap();
        let run = store
            .start_run(revision, json!({}), "abandoned-host-recovery", None, None)
            .unwrap();
        let claimed = store
            .claim_next_command(&run.run_id, "claimant", now_ms() + 60_000)
            .unwrap()
            .unwrap();
        store
            .apply_owned_event(
                &run.run_id,
                "claimant",
                ReducerEvent::CommandStarted {
                    command_id: claimed.id.clone(),
                    attempt_token: claimed.attempt_token.clone(),
                },
            )
            .unwrap();

        // A previous host process disappearing is not lease revocation, so the
        // still-valid claim is neither released nor retried.
        assert!(!store.recover_next_expired_command(&run.run_id).unwrap());
        let held = store.run(&run.run_id).unwrap();
        assert_eq!(held.commands[&claimed.id].status, CommandStatus::Running);
        assert!(held.commands[&claimed.id].failure_code.is_none());
        assert!(
            !held.commands.values().any(|command| command.attempt == 2),
            "an unexpired in-flight effect is never repeated"
        );
        assert_eq!(held.status, StrategyRunStatus::Running);
    }

    #[test]
    fn a_released_unexpired_claim_never_becomes_retryable() {
        let store = StrategyStore::open_in_memory().unwrap();
        let revision = "5656565656565656565656565656565656565656565656565656565656565656";
        store
            .register_definition(
                revision,
                "7878787878787878787878787878787878787878787878787878787878787878",
                &workflow(),
                1,
                1,
            )
            .unwrap();
        store
            .update_binding(revision, "worker", "agent:test", "", "", None)
            .unwrap();
        let preview = store.authorization_preview(revision).unwrap();
        store
            .grant_authorization(revision, &preview.authorization_digest)
            .unwrap();
        let run = store
            .start_run(revision, json!({}), "held-claim", None, None)
            .unwrap();
        let claimed = store
            .claim_next_command(&run.run_id, "claimant", now_ms() + 60_000)
            .unwrap()
            .unwrap();
        store
            .apply_owned_event(
                &run.run_id,
                "claimant",
                ReducerEvent::CommandStarted {
                    command_id: claimed.id.clone(),
                    attempt_token: claimed.attempt_token.clone(),
                },
            )
            .unwrap();

        // The owner settles its own attempt; nothing else may report on it.
        assert!(
            store
                .apply_owned_event(
                    &run.run_id,
                    "claimant",
                    ReducerEvent::CommandSucceeded {
                        command_id: claimed.id.clone(),
                        attempt_token: "attempt:someone-else".into(),
                        output: json!({ "ok": true }),
                    },
                )
                .is_err(),
            "a stale owner result cannot settle an attempt it does not own"
        );
        let unchanged = store.run(&run.run_id).unwrap();
        assert_eq!(
            unchanged.commands[&claimed.id].status,
            CommandStatus::Running
        );
        assert!(unchanged.commands[&claimed.id].output_digest.is_none());
    }

    #[test]
    fn bind_context_if_absent_fills_an_unbound_run() {
        let store = StrategyStore::open_in_memory().unwrap();
        let revision = "1111111111111111111111111111111111111111111111111111111111111111";
        store
            .register_definition(
                revision,
                "2222222222222222222222222222222222222222222222222222222222222222",
                &workflow(),
                1,
                1,
            )
            .unwrap();
        store
            .update_binding(revision, "worker", "agent:test", "", "", None)
            .unwrap();
        let preview = store.authorization_preview(revision).unwrap();
        store
            .grant_authorization(revision, &preview.authorization_digest)
            .unwrap();
        let run = store
            .start_run(revision, json!({}), "bind-context", None, None)
            .unwrap();
        assert!(run.context_id.is_none());
        store
            .bind_context_if_absent(&run.run_id, "context:group")
            .unwrap();
        store
            .bind_context_if_absent(&run.run_id, "context:other")
            .unwrap();
        let bound = store.run(&run.run_id).unwrap();
        assert_eq!(bound.context_id.as_deref(), Some("context:group"));
    }

    /// Recovery selects and transitions the expired claim inside one
    /// immediate transaction, so a lease renewal that committed first is
    /// observed under the same write lock and the claim is never retried or
    /// marked in-doubt behind its owner's back.
    #[test]
    fn a_renewed_claim_is_never_recovered() {
        let store = StrategyStore::open_in_memory().unwrap();
        let revision = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        store
            .register_definition(revision, revision, &workflow(), 1, 1)
            .unwrap();
        store
            .update_binding(revision, "worker", "agent:test", "", "", None)
            .unwrap();
        let preview = store.authorization_preview(revision).unwrap();
        store
            .grant_authorization(revision, &preview.authorization_digest)
            .unwrap();
        let run = store
            .start_run(revision, json!({}), "renewal-fence", None, None)
            .unwrap();
        let claimed = store
            .claim_next_command(&run.run_id, "claimant", now_ms() + 60_000)
            .unwrap()
            .unwrap();
        store
            .apply_owned_event(
                &run.run_id,
                "claimant",
                ReducerEvent::CommandStarted {
                    command_id: claimed.id.clone(),
                    attempt_token: claimed.attempt_token.clone(),
                },
            )
            .unwrap();
        store
            .renew_command_lease(&claimed.id, "claimant", now_ms() + 120_000)
            .unwrap();
        assert!(!store.recover_next_expired_command(&run.run_id).unwrap());
        let held = store.run(&run.run_id).unwrap();
        assert_eq!(held.commands[&claimed.id].status, CommandStatus::Running);
    }

    /// A command whose effect outcome is unknowable cannot be cancelled into
    /// a clean `Cancelled` report: the run stays `CancelInDoubt` until every
    /// position is resolved.
    #[test]
    fn an_in_doubt_position_holds_cancellation_open() {
        let store = StrategyStore::open_in_memory().unwrap();
        let revision = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        store
            .register_definition(revision, revision, &workflow(), 1, 1)
            .unwrap();
        store
            .update_binding(revision, "worker", "agent:test", "", "", None)
            .unwrap();
        let preview = store.authorization_preview(revision).unwrap();
        store
            .grant_authorization(revision, &preview.authorization_digest)
            .unwrap();
        let run = store
            .start_run(revision, json!({}), "cancel-in-doubt-single", None, None)
            .unwrap();
        let claimed = store
            .claim_next_command(&run.run_id, "claimant", now_ms() + 60_000)
            .unwrap()
            .unwrap();
        store
            .apply_owned_event(
                &run.run_id,
                "claimant",
                ReducerEvent::CommandStarted {
                    command_id: claimed.id.clone(),
                    attempt_token: claimed.attempt_token.clone(),
                },
            )
            .unwrap();
        store
            .apply_event(&run.run_id, ReducerEvent::CancelRequested)
            .unwrap();
        store
            .apply_owned_event(
                &run.run_id,
                "claimant",
                ReducerEvent::CancellationUnknown {
                    command_id: claimed.id.clone(),
                    attempt_token: claimed.attempt_token.clone(),
                },
            )
            .unwrap();
        // A second cancel request re-evaluates; the in-doubt position keeps
        // the run open instead of being reported cancelled.
        store
            .apply_event(&run.run_id, ReducerEvent::CancelRequested)
            .unwrap();
        let snapshot = store.run(&run.run_id).unwrap();
        assert_eq!(snapshot.status, StrategyRunStatus::CancelInDoubt);
        assert_eq!(
            snapshot.commands[&claimed.id].status,
            CommandStatus::InDoubt
        );
    }

    /// The in-memory store's scratch file lives in a directory only this user
    /// can read and disappears with the last handle.
    #[test]
    fn in_memory_store_scratch_dir_is_private_and_removed() {
        let store = StrategyStore::open_in_memory().unwrap();
        let dir = store.db_path().parent().unwrap().to_owned();
        assert!(store.db_path().exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        drop(store);
        assert!(!dir.exists(), "scratch directory removed with the store");
    }
}
