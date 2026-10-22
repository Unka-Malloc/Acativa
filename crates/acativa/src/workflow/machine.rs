use anyhow::{Result, anyhow, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::{
    CompiledWorkflow, ContributionOrder, FailureClass, FallbackReceipt, GraphStateKind,
    INPUT_ADAPTER_VERSION, InputBinding, InputPlan, MAX_WORKSET_ITEMS, MergePolicy,
    PendingCallback, PredecessorInput, ResultRef, SHARED_CONTEXT_RESOURCE,
    SHARED_WORKSETS_RESOURCE, SessionPolicy, SharedResourceRef, SharedWriter, StrategyRunStatus,
    TransitionEvent, TransitionMode,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CommandKind {
    Authorization,
    Actor,
    Script,
    WorksetItem,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CommandStatus {
    Pending,
    Claimed,
    Running,
    Succeeded,
    Failed,
    Retryable,
    CancelRequested,
    Cancelled,
    InDoubt,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunCommand {
    pub id: String,
    pub state_id: String,
    #[serde(default = "default_state_visit")]
    pub state_visit: u64,
    pub kind: CommandKind,
    pub status: CommandStatus,
    pub attempt: u8,
    pub attempt_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item_id: Option<String>,
    #[serde(default)]
    pub session_policy: SessionPolicy,
    #[serde(default)]
    pub binding_ordinal: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resume_session_id: Option<String>,
    pub input_digest: String,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub input: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_class: Option<FailureClass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
}

/// One value one writer published into a shared resource.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SharedEntry {
    /// How many writes to *this key* have been accepted. A per-key revision is
    /// the only one that can be stored beside a value without making arrival
    /// order observable: a resource-wide write index stored per key would
    /// differ between two runs that accepted the same contributions in a
    /// different order, even though every value and every merge was identical.
    pub revision: u64,
    pub value: Value,
    /// The effects the stored value is made of. A scalar value has exactly the
    /// writer that put it there; an accumulated collection has every member
    /// that contributed to it, because no single one of them owns the merged
    /// value and naming the last arrival would make the provenance depend on
    /// completion order. A key with no writer was declared by the run itself.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub writers: BTreeSet<SharedWriter>,
}

/// One shared resource's versioned contents.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SharedResourceState {
    /// Monotone across every accepted write to this resource, and the token a
    /// compare-and-swap checks. It counts accepted contributions, so two runs
    /// that accepted the same ones agree on it.
    pub revision: u64,
    pub keys: BTreeMap<String, SharedEntry>,
}

/// A predecessor's arrival at a join, bound to the exact visit that arrived.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JoinArrival {
    pub node_visit: u64,
    pub result: ResultRef,
    /// The ordinal this arrival was recorded at, so a node that declares its
    /// business order sensitive can name the order it actually observed.
    pub arrival_ordinal: u64,
}

/// An arrival the join refused to count, and why. Never dropped in silence: a
/// stale arrival is a durable fact about the run, not an implementation detail.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StaleJoinArrival {
    pub predecessor: String,
    pub node_visit: u64,
    pub superseded_by: u64,
}

/// One join's arrivals, kept per visit rather than per node.
///
/// The set of names that have arrived is not enough to decide a join: a visit-1
/// arrival and a visit-2 arrival of the same predecessor are different
/// contributions, and a join that consumes both as one round is a join whose
/// input never existed as a single instant of the run.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JoinLedger {
    /// The latest arrival per declared predecessor.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub arrivals: BTreeMap<String, JoinArrival>,
    /// The visit epoch the join last fired at. A repeated arrival can never
    /// fire the same epoch twice.
    pub consumed_epoch: u64,
    /// Arrivals refused because a newer visit of the same predecessor had
    /// already contributed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stale: Vec<StaleJoinArrival>,
    /// How many arrivals this join has seen, across epochs.
    pub arrival_count: u64,
}

impl JoinLedger {
    fn ordinal(&self) -> u64 {
        self.arrival_count.saturating_add(1)
    }
}

/// One node visit, as a fact.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VisitFact {
    pub node_id: String,
    pub node_visit: u64,
}

/// One shared write this step accepted.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SharedWriteReceipt {
    pub resource_id: String,
    pub key: String,
    pub revision: u64,
    pub writer: String,
    /// True when the write re-delivered the value already stored, so nothing
    /// changed. Duplicates are idempotent; a differing value is refused before
    /// this receipt exists.
    pub duplicate: bool,
}

/// One join that fired, and the epoch it fired at.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JoinSatisfaction {
    pub node_id: String,
    pub epoch: u64,
    pub arrivals: Vec<PredecessorInput>,
}

/// One join-ledger change this step made.
///
/// An arrival is causal state even when the join does not fire: it is the
/// contribution a later arrival completes. A store that persisted only entered
/// visits would lose it, and the join would never close after a restore, so
/// every accepted or refused arrival is reported. A refused arrival carries no
/// ordinal because the ledger recorded none for it.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JoinArrivalReceipt {
    pub node_id: String,
    pub predecessor: String,
    pub node_visit: u64,
    /// The ordinal the ledger recorded this arrival at, or 0 when refused.
    pub arrival_ordinal: u64,
    /// True when this arrival is the predecessor's contribution for its visit;
    /// false when a newer visit had already contributed and this one is kept as
    /// a superseded fact.
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub superseded_by: Option<u64>,
}

/// What one reducer step changed.
///
/// The delta is what a store persists incrementally, so it is built from the
/// facts the machine actually produced rather than recomputed from the two
/// snapshots: a consumer that applied only the delta must hold exactly the
/// snapshot the step returned, and the differential test checks that claim
/// against an independent diff instead of trusting it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReducerDelta {
    pub run_id: String,
    pub sequence: u64,
    pub applied: bool,
    pub status_before: StrategyRunStatus,
    pub status_after: StrategyRunStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entered: Vec<VisitFact>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bindings: Vec<InputBinding>,
    /// Results this step made final, in completion order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub results: Vec<ResultRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub joins_satisfied: Vec<JoinSatisfaction>,
    /// Join arrivals this step recorded or refused. An arrival is causal state
    /// even before the join fires, so a consumer that applies only the delta
    /// must receive it here rather than re-deriving it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub join_arrivals: Vec<JoinArrivalReceipt>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shared_writes: Vec<SharedWriteReceipt>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub settled_commands: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub emitted_commands: Vec<String>,
}

impl Default for ReducerDelta {
    fn default() -> Self {
        Self {
            run_id: String::new(),
            sequence: 0,
            applied: false,
            // A step that changed nothing starts and ends at the same status;
            // the machine fills both in from the snapshot it was handed.
            status_before: StrategyRunStatus::Pending,
            status_after: StrategyRunStatus::Pending,
            entered: Vec::new(),
            bindings: Vec::new(),
            results: Vec::new(),
            joins_satisfied: Vec::new(),
            join_arrivals: Vec::new(),
            shared_writes: Vec::new(),
            settled_commands: Vec::new(),
            emitted_commands: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunSnapshot {
    pub run_id: String,
    pub definition_digest: String,
    pub semantics_digest: String,
    pub status: StrategyRunStatus,
    pub sequence: u64,
    pub input: Value,
    pub active_states: BTreeSet<String>,
    pub completed_states: BTreeSet<String>,
    pub state_visits: BTreeMap<String, u64>,
    /// Per-visit arrivals, so an old visit of a predecessor can never satisfy a
    /// new join round.
    pub join_arrivals: BTreeMap<String, JoinLedger>,
    /// The run's declared causal input plan.
    #[serde(default)]
    pub input_plan: InputPlan,
    /// Versioned shared state. Reading it without naming a revision is not
    /// expressible: the only readers are bindings, and a binding records one.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub shared: BTreeMap<String, SharedResourceState>,
    /// The exact binding every entered node visit received.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub bindings: BTreeMap<String, InputBinding>,
    #[serde(default)]
    pub actor_sessions: BTreeMap<String, String>,
    #[serde(default)]
    pub slot_ordinals: BTreeMap<String, u8>,
    #[serde(default)]
    pub slot_candidate_counts: BTreeMap<String, u8>,
    #[serde(default)]
    pub attempt_lineage: BTreeMap<String, u8>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub merge_sources: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fallbacks: Vec<FallbackReceipt>,
    /// The host context this run answers to.
    ///
    /// The engine never interprets it: it is the durable, indexed grouping key
    /// a host binds one run to (a channel, a tenant, a document) so it can
    /// ask the store for the live run of one context. The store writes it; the
    /// machine only persists it with the snapshot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    /// Opaque host binding for this run.
    ///
    /// The engine never reads it: a host binds the run to its own context (a
    /// routing receipt, an actor identity) by writing one JSON value
    /// here, and reads it back through its own projection. Persisting it with
    /// the snapshot is the only thing the machine does with it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_binding: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// Callback-mode edges whose targets wait for the run decider's
    /// settlement, in the deterministic order the waits were entered. The
    /// decision event always settles the first entry.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pending_callbacks: Vec<PendingCallback>,
    pub commands: BTreeMap<String, RunCommand>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostic_code: Option<String>,
}

impl RunSnapshot {
    pub fn empty(
        run_id: impl Into<String>,
        definition_digest: impl Into<String>,
        semantics_digest: impl Into<String>,
    ) -> Self {
        Self {
            run_id: run_id.into(),
            definition_digest: definition_digest.into(),
            semantics_digest: semantics_digest.into(),
            status: StrategyRunStatus::Pending,
            sequence: 0,
            input: Value::Object(Default::default()),
            active_states: BTreeSet::new(),
            completed_states: BTreeSet::new(),
            state_visits: BTreeMap::new(),
            join_arrivals: BTreeMap::new(),
            input_plan: InputPlan::default(),
            shared: BTreeMap::new(),
            bindings: BTreeMap::new(),
            actor_sessions: BTreeMap::new(),
            slot_ordinals: BTreeMap::new(),
            slot_candidate_counts: BTreeMap::new(),
            attempt_lineage: BTreeMap::new(),
            merge_sources: BTreeMap::new(),
            fallbacks: Vec::new(),
            context_id: None,
            run_binding: None,
            cwd: None,
            pending_callbacks: Vec::new(),
            commands: BTreeMap::new(),
            diagnostic_code: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ReducerEvent {
    /// The run's declared causal input plan, before anything runs. A run that
    /// never declares one keeps the safe default; a plan that declares an
    /// adapter version this build does not project is refused, so a stored
    /// version can never be silently read as a different one.
    InputPlanDeclared {
        plan: InputPlan,
    },
    Start {
        input: Value,
    },
    AuthorizationGranted {
        semantics_digest: String,
    },
    AuthorizationDenied,
    AuthorizationRevoked,
    CommandClaimed {
        command_id: String,
        attempt_token: String,
    },
    CommandStarted {
        command_id: String,
        attempt_token: String,
    },
    CommandSucceeded {
        command_id: String,
        attempt_token: String,
        output: Value,
    },
    CommandFailed {
        command_id: String,
        attempt_token: String,
        class: FailureClass,
        code: String,
    },
    /// The run decider's settlement for the oldest pending callback wait. The
    /// wait is durable: the declared edge is only taken, the completed state
    /// re-entered, or the run terminated after this run input arrives.
    CallbackDecision {
        state_id: String,
        state_visit: u64,
        decision: crate::CallbackDecision,
    },
    RetryRequested {
        command_id: String,
    },
    CancelRequested,
    CancellationAcknowledged {
        command_id: String,
        attempt_token: String,
    },
    CancellationUnknown {
        command_id: String,
        attempt_token: String,
    },
    FallbackIssued {
        failed_command_id: String,
        next_ordinal: u8,
        locator: Value,
        from_value_id: String,
        to_value_id: String,
        reason: String,
        attempts: u8,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub struct ReducerOutput {
    pub snapshot: RunSnapshot,
    pub emitted_commands: Vec<RunCommand>,
    pub applied: bool,
    /// What this step changed, for a consumer that persists incrementally.
    pub delta: ReducerDelta,
}

/// One deterministic actor-command input for a state: the run input wrapped
/// with the state instruction when one exists. Registration and drive share
/// this builder so a pre-registered entry turn sends exactly the prompt the
/// emitted command would carry.
pub fn effect_input_for(
    workflow: &CompiledWorkflow,
    state_id: &str,
    input: Value,
) -> Result<Value> {
    let state = workflow
        .state(state_id)
        .ok_or_else(|| anyhow!("strategy_state_unknown"))?;
    if state.instruction.trim().is_empty() {
        return Ok(input);
    }
    let context = serde_json::to_string(&input)?;
    Ok(json!({
        "prompt": format!(
            "{}\n\nState: {}\nInput JSON:\n{}",
            state.instruction, state.id, context
        ),
        "context": input,
    }))
}

pub fn reduce(
    workflow: &CompiledWorkflow,
    previous: &RunSnapshot,
    event: ReducerEvent,
) -> Result<ReducerOutput> {
    let mut machine = Machine {
        workflow,
        snapshot: previous.clone(),
        emitted: Vec::new(),
        automatic: VecDeque::new(),
        applied: true,
        delta: ReducerDelta {
            run_id: previous.run_id.clone(),
            sequence: previous.sequence,
            status_before: previous.status,
            status_after: previous.status,
            ..ReducerDelta::default()
        },
    };
    // A run bound to an input projection this build does not implement is not
    // advanced under a different one: its bindings would name an adapter that
    // never produced them.
    ensure!(
        previous.input_plan.input_adapter_version == INPUT_ADAPTER_VERSION,
        "strategy_input_adapter_mismatch"
    );
    machine.snapshot.sequence = machine
        .snapshot
        .sequence
        .checked_add(1)
        .ok_or_else(|| anyhow!("strategy_event_sequence_overflow"))?;
    machine.delta.sequence = machine.snapshot.sequence;
    match event {
        ReducerEvent::InputPlanDeclared { plan } => {
            ensure!(
                previous.status == StrategyRunStatus::Pending && previous.sequence == 0,
                "strategy_input_plan_too_late"
            );
            ensure!(
                plan.input_adapter_version == INPUT_ADAPTER_VERSION,
                "strategy_input_adapter_mismatch"
            );
            machine.snapshot.input_plan = plan;
            // Declaring the plan is not a run step: it happens before the run
            // exists, so it does not consume the sequence that `Start` guards.
            machine.snapshot.sequence = previous.sequence;
            machine.delta.sequence = previous.sequence;
        }
        ReducerEvent::Start { input } => {
            ensure!(
                previous.status == StrategyRunStatus::Pending && previous.sequence == 0,
                "strategy_run_already_started"
            );
            ensure!(
                serde_json::to_vec(&input)?.len() <= 1024 * 1024,
                "strategy_run_input_too_large"
            );
            machine.snapshot.input = input;
            machine.snapshot.status = StrategyRunStatus::Running;
            machine.enter(&workflow.definition.initial, None)?;
        }
        ReducerEvent::AuthorizationGranted { semantics_digest } => {
            ensure!(
                semantics_digest == previous.semantics_digest,
                "strategy_authorization_stale"
            );
            let command_id = machine
                .snapshot
                .commands
                .values()
                .find(|command| {
                    command.kind == CommandKind::Authorization
                        && command.status == CommandStatus::Pending
                })
                .map(|command| command.id.clone())
                .ok_or_else(|| anyhow!("strategy_authorization_not_pending"))?;
            machine.settle_success(&command_id, None, json!({"authorized": true}))?;
        }
        ReducerEvent::AuthorizationDenied => {
            let command_id = pending_authorization(&machine.snapshot)?;
            machine.settle_failure(
                &command_id,
                None,
                FailureClass::Authority,
                "authorization_denied",
            )?;
        }
        ReducerEvent::AuthorizationRevoked => {
            if matches!(
                machine.snapshot.status,
                StrategyRunStatus::Completed
                    | StrategyRunStatus::Cancelled
                    | StrategyRunStatus::Failed
                    | StrategyRunStatus::Blocked
                    | StrategyRunStatus::CancelInDoubt
            ) {
                machine.applied = false;
            } else {
                machine.snapshot.status = StrategyRunStatus::AuthorizationRequired;
                machine.snapshot.diagnostic_code = Some("authorization_revoked".into());
            }
        }
        ReducerEvent::CommandClaimed {
            command_id,
            attempt_token,
        } => machine.transition_command(
            &command_id,
            &attempt_token,
            CommandStatus::Pending,
            CommandStatus::Claimed,
        )?,
        ReducerEvent::CommandStarted {
            command_id,
            attempt_token,
        } => {
            let current = machine
                .snapshot
                .commands
                .get(&command_id)
                .ok_or_else(|| anyhow!("strategy_callback_stale"))?
                .status;
            ensure!(
                matches!(current, CommandStatus::Pending | CommandStatus::Claimed),
                "strategy_callback_conflict"
            );
            machine.transition_command(
                &command_id,
                &attempt_token,
                current,
                CommandStatus::Running,
            )?;
        }
        ReducerEvent::CommandSucceeded {
            command_id,
            attempt_token,
            output,
        } => machine.settle_success(&command_id, Some(&attempt_token), output)?,
        ReducerEvent::CommandFailed {
            command_id,
            attempt_token,
            class,
            code,
        } => machine.settle_failure(&command_id, Some(&attempt_token), class, &code)?,
        ReducerEvent::CallbackDecision {
            state_id,
            state_visit,
            decision,
        } => machine.apply_callback_decision(&state_id, state_visit, decision)?,
        ReducerEvent::RetryRequested { command_id } => machine.retry(&command_id)?,
        ReducerEvent::CancelRequested => machine.cancel()?,
        ReducerEvent::CancellationAcknowledged {
            command_id,
            attempt_token,
        } => machine.cancel_acknowledged(&command_id, &attempt_token)?,
        ReducerEvent::CancellationUnknown {
            command_id,
            attempt_token,
        } => machine.cancel_unknown(&command_id, &attempt_token)?,
        ReducerEvent::FallbackIssued {
            failed_command_id,
            next_ordinal,
            locator,
            from_value_id,
            to_value_id,
            reason,
            attempts,
        } => machine.issue_fallback(
            &failed_command_id,
            next_ordinal,
            locator,
            from_value_id,
            to_value_id,
            reason,
            attempts,
        )?,
    }
    machine.drain_automatic()?;
    if !machine.applied {
        machine.snapshot.sequence = previous.sequence;
    }
    machine.delta.applied = machine.applied;
    machine.delta.status_after = machine.snapshot.status;
    machine.delta.emitted_commands = machine
        .emitted
        .iter()
        .map(|command| command.id.clone())
        .collect();
    if !machine.applied {
        // A replayed event changes nothing, so its delta claims nothing.
        machine.delta.entered.clear();
        machine.delta.bindings.clear();
        machine.delta.results.clear();
        machine.delta.joins_satisfied.clear();
        machine.delta.shared_writes.clear();
        machine.delta.settled_commands.clear();
        machine.delta.emitted_commands.clear();
    }
    Ok(ReducerOutput {
        snapshot: machine.snapshot,
        emitted_commands: machine.emitted,
        applied: machine.applied,
        delta: machine.delta,
    })
}

struct Machine<'a> {
    workflow: &'a CompiledWorkflow,
    snapshot: RunSnapshot,
    emitted: Vec<RunCommand>,
    automatic: VecDeque<(String, TransitionEvent, Value)>,
    applied: bool,
    delta: ReducerDelta,
}

impl Machine<'_> {
    fn enter(&mut self, state_id: &str, predecessor: Option<&str>) -> Result<()> {
        let state = self
            .workflow
            .state(state_id)
            .ok_or_else(|| anyhow!("strategy_state_unknown"))?
            .clone();
        let mut arrivals = Vec::new();
        if state.kind == GraphStateKind::Join {
            if let Some(epoch) = self.record_join_arrival(&state.id, predecessor)? {
                arrivals = self.join_arrivals_at(&state.id, epoch);
                self.delta.joins_satisfied.push(JoinSatisfaction {
                    node_id: state.id.clone(),
                    epoch,
                    arrivals: arrivals.clone(),
                });
            } else {
                // No epoch has every declared predecessor yet. Waiting is the
                // honest outcome: firing here would mean consuming a
                // contribution from a visit of another round.
                self.snapshot.status = StrategyRunStatus::Waiting;
                self.snapshot.diagnostic_code = Some("strategy_join_waiting".into());
                return Ok(());
            }
        }
        self.snapshot.completed_states.remove(&state.id);
        self.snapshot.active_states.insert(state.id.clone());
        let visit = self
            .snapshot
            .state_visits
            .entry(state.id.clone())
            .or_default();
        *visit = visit.saturating_add(1);
        let visit = *visit;
        let binding = self.record_binding(&state.id, visit, predecessor, arrivals)?;
        self.delta.entered.push(VisitFact {
            node_id: state.id.clone(),
            node_visit: visit,
        });
        self.delta.bindings.push(binding);
        self.snapshot.status = StrategyRunStatus::Running;
        self.snapshot.diagnostic_code = None;
        match state.kind {
            GraphStateKind::Pass | GraphStateKind::Choice | GraphStateKind::Join => {
                let input = self.projected_input(&state.id, visit)?;
                self.automatic
                    .push_back((state.id, TransitionEvent::Complete, input));
            }
            GraphStateKind::Fork => self.complete_fork(&state.id)?,
            GraphStateKind::Authorization => {
                self.emit_command(&state.id, CommandKind::Authorization, None, Value::Null)?;
                self.snapshot.status = StrategyRunStatus::AuthorizationRequired;
            }
            GraphStateKind::Actor => {
                let input = self.projected_input(&state.id, visit)?;
                let input = self.effect_input(&state.id, input)?;
                self.emit_command(&state.id, CommandKind::Actor, None, input)?;
            }
            GraphStateKind::Script => {
                let input = self.projected_input(&state.id, visit)?;
                self.emit_command(&state.id, CommandKind::Script, None, input)?;
            }
            GraphStateKind::Workset => {
                if self.schedule_workset(&state.id)? {
                    let input = self.projected_input(&state.id, visit)?;
                    self.automatic
                        .push_back((state.id, TransitionEvent::Success, input));
                }
            }
            GraphStateKind::Succeed => {
                self.snapshot.active_states.remove(&state.id);
                self.snapshot.completed_states.insert(state.id);
                self.snapshot.status = StrategyRunStatus::Completed;
            }
            GraphStateKind::Fail => {
                self.snapshot.active_states.remove(&state.id);
                self.snapshot.status = StrategyRunStatus::Failed;
            }
            GraphStateKind::Blocked => {
                self.snapshot.active_states.remove(&state.id);
                self.snapshot.status = StrategyRunStatus::Blocked;
            }
        }
        Ok(())
    }

    /// Record one arrival at a join and return the epoch it completes, if any.
    ///
    /// A join is decided per visit epoch, not per name: the round that fires is
    /// the one where every declared predecessor contributed a result from the
    /// same visit value. An arrival from an older visit of a predecessor that
    /// has already contributed a newer one is refused and kept as a durable
    /// fact, so a stale contribution can neither satisfy a new round nor vanish
    /// without a trace.
    fn record_join_arrival(
        &mut self,
        join_id: &str,
        predecessor: Option<&str>,
    ) -> Result<Option<u64>> {
        if let Some(predecessor) = predecessor {
            ensure!(
                self.workflow.predecessors(join_id).contains(predecessor),
                "strategy_join_predecessor_undeclared"
            );
            let visit = self
                .snapshot
                .state_visits
                .get(predecessor)
                .copied()
                .unwrap_or(0);
            ensure!(visit > 0, "strategy_join_predecessor_unvisited");
            let result = self.result_ref_for(predecessor, visit)?;
            let ordinal = self
                .snapshot
                .join_arrivals
                .get(join_id)
                .map_or(1, JoinLedger::ordinal);
            let receipt = {
                let ledger = self
                    .snapshot
                    .join_arrivals
                    .entry(join_id.to_owned())
                    .or_default();
                match ledger.arrivals.get(predecessor) {
                    Some(existing) if existing.node_visit == visit => {
                        // The same visit contributed twice. Equal content is the
                        // same contribution; differing content is a conflict.
                        ensure!(
                            existing.result.digest == result.digest,
                            "strategy_input_conflict"
                        );
                        None
                    }
                    Some(existing) if existing.node_visit > visit => {
                        ledger.stale.push(StaleJoinArrival {
                            predecessor: predecessor.to_owned(),
                            node_visit: visit,
                            superseded_by: existing.node_visit,
                        });
                        Some(JoinArrivalReceipt {
                            node_id: join_id.to_owned(),
                            predecessor: predecessor.to_owned(),
                            node_visit: visit,
                            arrival_ordinal: 0,
                            accepted: false,
                            superseded_by: Some(existing.node_visit),
                        })
                    }
                    superseded => {
                        let superseded_by = superseded.map(|arrival| arrival.node_visit);
                        if let Some(superseded) = superseded {
                            ledger.stale.push(StaleJoinArrival {
                                predecessor: predecessor.to_owned(),
                                node_visit: superseded.node_visit,
                                superseded_by: visit,
                            });
                        }
                        ledger.arrival_count = ledger.arrival_count.saturating_add(1);
                        ledger.arrivals.insert(
                            predecessor.to_owned(),
                            JoinArrival {
                                node_visit: visit,
                                result,
                                arrival_ordinal: ordinal,
                            },
                        );
                        Some(JoinArrivalReceipt {
                            node_id: join_id.to_owned(),
                            predecessor: predecessor.to_owned(),
                            node_visit: visit,
                            arrival_ordinal: ordinal,
                            accepted: true,
                            superseded_by,
                        })
                    }
                }
            };
            if let Some(receipt) = receipt {
                self.delta.join_arrivals.push(receipt);
            }
        }
        let Some(epoch) = self.join_epoch(join_id) else {
            return Ok(None);
        };
        // The epoch is consumed here, before the join is entered: a second
        // arrival carrying the same contributions is a duplicate, and a
        // duplicate re-delivers a result rather than opening a new round.
        if let Some(ledger) = self.snapshot.join_arrivals.get_mut(join_id) {
            ledger.consumed_epoch = epoch;
        }
        Ok(Some(epoch))
    }

    /// The visit epoch a join can fire at: the newest arrival visit such that
    /// every declared predecessor arrived at exactly that visit, and no round
    /// has consumed it yet.
    fn join_epoch(&self, join_id: &str) -> Option<u64> {
        let declared = self.workflow.predecessors(join_id);
        if declared.is_empty() {
            return None;
        }
        let ledger = self.snapshot.join_arrivals.get(join_id)?;
        let epoch = ledger
            .arrivals
            .values()
            .map(|arrival| arrival.node_visit)
            .max()?;
        if epoch <= ledger.consumed_epoch {
            return None;
        }
        declared
            .iter()
            .all(|predecessor| {
                ledger
                    .arrivals
                    .get(predecessor)
                    .is_some_and(|arrival| arrival.node_visit == epoch)
            })
            .then_some(epoch)
    }

    /// The contributions of one epoch, in the definition's declared order.
    fn join_arrivals_at(&self, join_id: &str, epoch: u64) -> Vec<PredecessorInput> {
        let Some(ledger) = self.snapshot.join_arrivals.get(join_id) else {
            return Vec::new();
        };
        self.workflow
            .predecessors(join_id)
            .iter()
            .filter_map(|predecessor| {
                ledger
                    .arrivals
                    .get(predecessor)
                    .filter(|arrival| arrival.node_visit == epoch)
                    .map(|arrival| PredecessorInput {
                        node_id: predecessor.clone(),
                        node_visit: arrival.node_visit,
                        result: arrival.result.clone(),
                    })
            })
            .collect()
    }

    /// The identity of one node visit's result.
    ///
    /// A visit that produced effects is identified by them, sorted, so a
    /// re-delivered result has the same identity and a differing one does not.
    /// A visit that produced no result is identified by the visit and by why:
    /// an automatic state reached this visit, or an effect state reached it and
    /// settled nothing that succeeded. Those are different facts, and a
    /// successor that binds one may not mistake it for the other.
    fn result_ref_for(&self, node_id: &str, visit: u64) -> Result<ResultRef> {
        let mut commands = self
            .snapshot
            .commands
            .values()
            .filter(|command| {
                command.state_id == node_id
                    && command.state_visit == visit
                    && command.status == CommandStatus::Succeeded
            })
            .collect::<Vec<_>>();
        let settled_without_result = self.snapshot.commands.values().any(|command| {
            command.state_id == node_id
                && command.state_visit == visit
                && matches!(
                    command.status,
                    CommandStatus::Failed
                        | CommandStatus::Retryable
                        | CommandStatus::InDoubt
                        | CommandStatus::Cancelled
                )
        });
        commands.sort_by(|left, right| {
            left.item_id
                .cmp(&right.item_id)
                .then(left.id.cmp(&right.id))
        });
        let mut material = format!("{}\0{}\0{}\0", self.snapshot.run_id, node_id, visit);
        if commands.is_empty() {
            material.push_str(if settled_without_result {
                "effect-without-result"
            } else {
                "state"
            });
        } else {
            for command in &commands {
                material.push_str(command.item_id.as_deref().unwrap_or(""));
                material.push('\0');
                material.push_str(command.output_digest.as_deref().unwrap_or(""));
                material.push('\0');
            }
        }
        Ok(ResultRef {
            run_id: self.snapshot.run_id.clone(),
            node_id: node_id.to_owned(),
            node_visit: visit,
            digest: sha256_hex(material.as_bytes()),
            producers: commands
                .into_iter()
                .map(|command| command.id.clone())
                .collect(),
        })
    }

    /// Bind one node visit to exactly the inputs it may read, and keep the
    /// binding. This is the whole of a node's causal input: declared
    /// predecessor results, shared revisions observed at this instant, and the
    /// adapter that projected them.
    fn record_binding(
        &mut self,
        state_id: &str,
        visit: u64,
        predecessor: Option<&str>,
        arrivals: Vec<PredecessorInput>,
    ) -> Result<InputBinding> {
        let predecessors = if arrivals.is_empty() {
            match predecessor {
                Some(predecessor) => {
                    let predecessor_visit = self
                        .snapshot
                        .state_visits
                        .get(predecessor)
                        .copied()
                        .unwrap_or(0);
                    ensure!(
                        predecessor_visit > 0,
                        "strategy_input_predecessor_unvisited"
                    );
                    vec![PredecessorInput {
                        node_id: predecessor.to_owned(),
                        node_visit: predecessor_visit,
                        result: self.result_ref_for(predecessor, predecessor_visit)?,
                    }]
                }
                None => Vec::new(),
            }
        } else {
            arrivals
        };
        let plan = self.snapshot.input_plan.clone();
        let shared = if plan.reads_shared_state(state_id) {
            plan.resources
                .iter()
                .map(|declaration| {
                    let state = self.snapshot.shared.get(&declaration.id);
                    SharedResourceRef {
                        resource_id: declaration.id.clone(),
                        revision: state.map_or(0, |state| state.revision),
                        keys: state
                            .map(|state| {
                                state
                                    .keys
                                    .iter()
                                    .map(|(key, entry)| (key.clone(), entry.revision))
                                    .collect()
                            })
                            .unwrap_or_default(),
                    }
                })
                .collect()
        } else {
            Vec::new()
        };
        let arrival_order = match plan.contribution_order(state_id) {
            ContributionOrder::Declaration => Vec::new(),
            ContributionOrder::Arrival => {
                let ledger = self.snapshot.join_arrivals.get(state_id);
                let mut ordered = predecessors
                    .iter()
                    .map(|contribution| {
                        let ordinal = ledger
                            .and_then(|ledger| ledger.arrivals.get(&contribution.node_id))
                            .filter(|arrival| arrival.node_visit == contribution.node_visit)
                            .map_or(0, |arrival| arrival.arrival_ordinal);
                        (ordinal, contribution.node_id.clone())
                    })
                    .collect::<Vec<_>>();
                ordered.sort();
                ordered.into_iter().map(|(_, node_id)| node_id).collect()
            }
        };
        let binding = InputBinding {
            run_id: self.snapshot.run_id.clone(),
            node_id: state_id.to_owned(),
            node_visit: visit,
            predecessors,
            shared,
            input_adapter_version: INPUT_ADAPTER_VERSION,
            arrival_order,
        };
        self.snapshot
            .bindings
            .insert(InputBinding::key(state_id, visit), binding.clone());
        Ok(binding)
    }

    /// The input one bound node visit receives: the run's own input, the
    /// declared predecessor result references, and the shared resources at the
    /// revisions the binding recorded. Nothing else can reach it.
    fn projected_input(&self, state_id: &str, visit: u64) -> Result<Value> {
        self.projection(state_id, visit, &BTreeSet::new())
    }

    /// The projection a completing node hands its outgoing transition.
    ///
    /// A writer sees its own writes: the keys this node just wrote are visible,
    /// whatever their new revision. Every other key stays at the revision the
    /// node's binding recorded, so a concurrent branch cannot change which edge
    /// this node takes.
    fn completion_input(
        &self,
        state_id: &str,
        visit: u64,
        own_writes: &BTreeSet<(String, String)>,
    ) -> Result<Value> {
        self.projection(state_id, visit, own_writes)
    }

    /// The input one bound node visit receives: the run's own input, the
    /// declared predecessor result references, and every shared key the binding
    /// observed at the revision it observed it. Nothing else can reach it.
    fn projection(
        &self,
        state_id: &str,
        visit: u64,
        own_writes: &BTreeSet<(String, String)>,
    ) -> Result<Value> {
        let binding = self.binding(state_id, visit)?;
        let mut input = match self.snapshot.input.clone() {
            Value::Object(object) => object,
            other => {
                let mut object = serde_json::Map::new();
                object.insert("input".to_owned(), other);
                object
            }
        };
        if !binding.predecessors.is_empty() {
            let mut predecessors = serde_json::Map::new();
            for contribution in &binding.predecessors {
                predecessors.insert(
                    contribution.node_id.clone(),
                    serde_json::to_value(&contribution.result)?,
                );
            }
            input.insert("predecessors".to_owned(), Value::Object(predecessors));
        }
        for reference in &binding.shared {
            let Some(state) = self.snapshot.shared.get(&reference.resource_id) else {
                continue;
            };
            let mut keys = input
                .get(&reference.resource_id)
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            for (key, entry) in &state.keys {
                let observed = reference.keys.get(key).copied().unwrap_or(0);
                if entry.revision <= observed
                    || own_writes.contains(&(reference.resource_id.clone(), key.clone()))
                {
                    keys.insert(key.clone(), entry.value.clone());
                }
            }
            input.insert(reference.resource_id.clone(), Value::Object(keys));
        }
        Ok(Value::Object(input))
    }

    fn binding(&self, state_id: &str, visit: u64) -> Result<InputBinding> {
        self.snapshot
            .bindings
            .get(&InputBinding::key(state_id, visit))
            .cloned()
            .ok_or_else(|| anyhow!("strategy_input_binding_missing"))
    }

    /// Apply one settled effect's shared writes under the run's declared merge
    /// policy, and return the (resource, key) pairs that changed.
    ///
    /// Every write is validated before any is applied, so a refused write
    /// leaves the shared state exactly as it was. A write to a resource the
    /// writer did not read at a recorded revision is refused: that is the
    /// undeclared global write this contract removes, not a merge policy.
    fn apply_shared_writes(
        &mut self,
        command_id: &str,
        state_id: &str,
        visit: u64,
        output: &Value,
    ) -> Result<BTreeSet<(String, String)>> {
        let Some(output) = output.as_object() else {
            return Ok(BTreeSet::new());
        };
        let mut candidates = Vec::<(String, serde_json::Map<String, Value>)>::new();
        for (namespace, resource_id) in [
            ("context", SHARED_CONTEXT_RESOURCE),
            ("worksets", SHARED_WORKSETS_RESOURCE),
        ] {
            if let Some(values) = output.get(namespace).and_then(Value::as_object) {
                candidates.push((resource_id.to_owned(), values.clone()));
            }
        }
        if let Some(named) = output.get("shared").and_then(Value::as_object) {
            for (resource_id, values) in named {
                candidates.push((
                    resource_id.clone(),
                    values.as_object().cloned().unwrap_or_default(),
                ));
            }
        }
        if candidates.is_empty() {
            return Ok(BTreeSet::new());
        }
        let binding = self.binding(state_id, visit)?;
        let plan = self.snapshot.input_plan.clone();
        let writer = SharedWriter {
            run_id: self.snapshot.run_id.clone(),
            node_id: state_id.to_owned(),
            node_visit: visit,
            command_id: command_id.to_owned(),
        };
        let mut accepted = Vec::<(MergePolicy, String, Vec<(String, Value)>)>::new();
        for (resource_id, values) in &candidates {
            let declaration = plan
                .resource(resource_id)
                .ok_or_else(|| anyhow!("strategy_shared_resource_undeclared"))?;
            let observed = binding
                .shared_revision(resource_id)
                .ok_or_else(|| anyhow!("strategy_shared_write_unread"))?;
            let state = self.snapshot.shared.get(resource_id);
            let current = state.map_or(0, |state| state.revision);
            match declaration.merge {
                MergePolicy::Exclusive => {
                    ensure!(
                        declaration.writer.as_deref() == Some(state_id),
                        "strategy_shared_write_conflict"
                    );
                }
                MergePolicy::Cas => {
                    ensure!(observed == current, "strategy_shared_write_conflict");
                }
                // Accumulation is per key and commutative, so it needs no
                // whole-resource revision check: two members filling different
                // keys, or the same key with different contributions, both
                // reach one canonical value either way.
                MergePolicy::KeyUnion | MergePolicy::Accumulate => {}
            }
            let mut keys = Vec::new();
            for (key, value) in values {
                let stored = state.and_then(|state| state.keys.get(key));
                let merged = match declaration.merge {
                    MergePolicy::Accumulate => {
                        match accumulate(stored.map(|entry| &entry.value), value) {
                            Some(merged) => merged,
                            None => return Err(anyhow!("strategy_shared_write_conflict")),
                        }
                    }
                    _ => value.clone(),
                };
                match stored {
                    // Re-delivering a value already stored is the same write,
                    // not a second one; so is accumulating a contribution the
                    // collection already holds.
                    Some(entry) if entry.value == merged => continue,
                    Some(_) => {
                        ensure!(
                            declaration.merge != MergePolicy::KeyUnion,
                            "strategy_shared_write_conflict"
                        );
                        keys.push((key.clone(), merged));
                    }
                    None => keys.push((key.clone(), merged)),
                }
            }
            accepted.push((declaration.merge, resource_id.clone(), keys));
        }
        let mut touched = BTreeSet::new();
        for (merge, resource_id, keys) in accepted {
            let state = self.snapshot.shared.entry(resource_id.clone()).or_default();
            if keys.is_empty() {
                // Nothing to change: the effect re-delivered what was already
                // stored, so the receipt says so and the revision stands.
                self.delta.shared_writes.push(SharedWriteReceipt {
                    resource_id,
                    key: String::new(),
                    revision: state.revision,
                    writer: command_id.to_owned(),
                    duplicate: true,
                });
                continue;
            }
            state.revision = state.revision.saturating_add(1);
            for (key, value) in keys {
                // The key's own revision counts the writes accepted for it, so
                // two runs that accepted the same contributions agree on it
                // whatever order they arrived in.
                let revision = state
                    .keys
                    .get(&key)
                    .map_or(1, |entry| entry.revision.saturating_add(1));
                let writers = match merge {
                    // The merged value belongs to every member that contributed
                    // to it, and to nobody else.
                    MergePolicy::Accumulate => state
                        .keys
                        .get(&key)
                        .map(|entry| entry.writers.clone())
                        .unwrap_or_default(),
                    // A scalar value belongs to the writer that put it there.
                    _ => BTreeSet::new(),
                }
                .into_iter()
                .chain(std::iter::once(writer.clone()))
                .collect();
                state.keys.insert(
                    key.clone(),
                    SharedEntry {
                        revision,
                        value,
                        writers,
                    },
                );
                // The legacy provenance map keeps one string per key. For a
                // shared key that string is the whole contributor set in a
                // canonical order, never the last arrival: a stored fact that
                // names only the last writer of a merged value would differ
                // between two runs that accepted the same contributions in a
                // different order. Session keys still map to the single command
                // that established the session, which is what their readers
                // compare.
                let contributors = state
                    .keys
                    .get(&key)
                    .map(|entry| {
                        entry
                            .writers
                            .iter()
                            .map(|writer| writer.command_id.as_str())
                            .collect::<Vec<_>>()
                            .join(",")
                    })
                    .unwrap_or_default();
                self.snapshot
                    .merge_sources
                    .insert(format!("{resource_id}\0{key}"), contributors);
                touched.insert((resource_id.clone(), key.clone()));
                self.delta.shared_writes.push(SharedWriteReceipt {
                    resource_id: resource_id.clone(),
                    key,
                    revision,
                    writer: command_id.to_owned(),
                    duplicate: false,
                });
            }
        }
        Ok(touched)
    }

    fn drain_automatic(&mut self) -> Result<()> {
        let mut remaining = self
            .workflow
            .definition
            .states
            .len()
            .saturating_mul(4)
            .max(16);
        while let Some((state_id, event, payload)) = self.automatic.pop_front() {
            ensure!(remaining > 0, "strategy_automatic_transition_limit");
            remaining -= 1;
            self.complete_state(&state_id, event, &payload)?;
        }
        Ok(())
    }

    fn complete_fork(&mut self, state_id: &str) -> Result<()> {
        self.snapshot.active_states.remove(state_id);
        self.snapshot.completed_states.insert(state_id.to_owned());
        let targets = self
            .workflow
            .transitions(state_id, TransitionEvent::Complete)
            .map(|transition| transition.to.clone())
            .collect::<Vec<_>>();
        ensure!(targets.len() >= 2, "strategy_fork_invalid");
        for target in targets {
            self.enter(&target, Some(state_id))?;
        }
        Ok(())
    }

    fn complete_state(
        &mut self,
        state_id: &str,
        event: TransitionEvent,
        payload: &Value,
    ) -> Result<()> {
        self.snapshot.active_states.remove(state_id);
        self.snapshot.completed_states.insert(state_id.to_owned());
        // The node visit's result is final now, and it is what a successor
        // binds to. Recording it here is what makes a successor boundary
        // reference resolvable without replaying the effect.
        if let Some(visit) = self.snapshot.state_visits.get(state_id).copied() {
            self.delta
                .results
                .push(self.result_ref_for(state_id, visit)?);
        }
        let transition = self
            .workflow
            .select_transition(state_id, event, payload)?
            .ok_or_else(|| anyhow!("strategy_transition_missing"))?;
        if transition.mode == TransitionMode::Callback {
            let event = transition.event;
            let transition_id = transition.id.clone();
            let target = transition.to.clone();
            self.park_callback(state_id, event, &transition_id, &target);
            return Ok(());
        }
        let target = transition.to.clone();
        self.enter(&target, Some(state_id))
    }

    /// A callback-mode edge does not take the run to its target on its own:
    /// the settled state is recorded and the run durably waits for the decider
    /// agent's decision as a run input.
    fn park_callback(
        &mut self,
        state_id: &str,
        event: TransitionEvent,
        transition_id: &str,
        target: &str,
    ) {
        let state_visit = self
            .snapshot
            .state_visits
            .get(state_id)
            .copied()
            .unwrap_or(0);
        self.snapshot.pending_callbacks.push(PendingCallback {
            state_id: state_id.to_owned(),
            state_visit,
            transition_id: transition_id.to_owned(),
            event,
            target: target.to_owned(),
        });
        self.snapshot.status = StrategyRunStatus::Waiting;
    }

    fn apply_callback_decision(
        &mut self,
        state_id: &str,
        state_visit: u64,
        decision: crate::CallbackDecision,
    ) -> Result<()> {
        // The decision binds the exact wait it settles: a replayed or stale
        // decision can never consume a later callback of the same edge.
        let matches_pending = self
            .snapshot
            .pending_callbacks
            .first()
            .is_some_and(|pending| {
                pending.state_id == state_id && pending.state_visit == state_visit
            });
        ensure!(matches_pending, "strategy_callback_stale");
        let pending = self.snapshot.pending_callbacks.remove(0);
        match decision {
            crate::CallbackDecision::Enter(target) if target == pending.target => {
                self.snapshot.status = StrategyRunStatus::Running;
                let target = pending.target.clone();
                self.enter(&target, Some(&pending.state_id))?;
            }
            crate::CallbackDecision::Enter(target) if target == pending.state_id => {
                self.snapshot.status = StrategyRunStatus::Running;
                self.enter(&target, None)?;
            }
            // A name the parked wait cannot enter is a conflict, not a silent
            // no-op: the decider's vocabulary is open, its answer is checked.
            crate::CallbackDecision::Enter(_) => {
                return Err(anyhow!("strategy_callback_conflict"));
            }
            crate::CallbackDecision::Terminate => {
                self.cancel()?;
            }
        }
        Ok(())
    }

    fn schedule_workset(&mut self, state_id: &str) -> Result<bool> {
        let state = self.workflow.state(state_id).unwrap();
        let workset_id = state.workset.as_deref().unwrap();
        // Items come from the projection this node's binding named, not from a
        // live run-wide bag: a later write by an unrelated branch cannot change
        // which items this visit scheduled.
        let visit = self
            .snapshot
            .state_visits
            .get(state_id)
            .copied()
            .unwrap_or(0);
        let items = self
            .projected_input(state_id, visit)?
            .get(SHARED_WORKSETS_RESOURCE)
            .and_then(|value| value.get(workset_id))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        ensure!(
            items.len() <= self.workflow.definition.limits.max_workset_items as usize
                && items.len() <= MAX_WORKSET_ITEMS,
            "strategy_workset_limit"
        );
        if items.is_empty() {
            return Ok(true);
        }
        let template = self
            .workflow
            .definition
            .worksets
            .iter()
            .find(|template| template.id == workset_id)
            .unwrap();
        let mut seen = BTreeSet::new();
        let mut normalized = Vec::with_capacity(items.len());
        for item in items {
            let item_id = item
                .get(&template.item_binding)
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty() && value.len() <= 96)
                .ok_or_else(|| anyhow!("strategy_workset_item_id_invalid"))?;
            ensure!(
                seen.insert(item_id.to_owned()),
                "strategy_workset_item_duplicate"
            );
            let predecessors = if template.predecessor_field.is_empty() {
                BTreeSet::new()
            } else {
                match item.get(&template.predecessor_field) {
                    None | Some(Value::Null) => BTreeSet::new(),
                    Some(Value::Array(values)) => values
                        .iter()
                        .map(|value| {
                            value
                                .as_str()
                                .filter(|value| !value.is_empty() && value.len() <= 96)
                                .map(str::to_owned)
                                .ok_or_else(|| anyhow!("strategy_workset_predecessor_invalid"))
                        })
                        .collect::<Result<BTreeSet<_>>>()?,
                    Some(_) => return Err(anyhow!("strategy_workset_predecessor_invalid")),
                }
            };
            ensure!(
                !predecessors.contains(item_id),
                "strategy_workset_predecessor_invalid"
            );
            normalized.push((item_id.to_owned(), predecessors, item));
        }
        ensure!(
            normalized
                .iter()
                .flat_map(|(_, predecessors, _)| predecessors)
                .all(|predecessor| seen.contains(predecessor)),
            "strategy_workset_predecessor_unknown"
        );
        let mut topological = BTreeSet::new();
        loop {
            let ready = normalized
                .iter()
                .filter(|(id, predecessors, _)| {
                    !topological.contains(id) && predecessors.is_subset(&topological)
                })
                .map(|(id, _, _)| id.clone())
                .collect::<Vec<_>>();
            if ready.is_empty() {
                break;
            }
            topological.extend(ready);
        }
        ensure!(
            topological.len() == normalized.len(),
            "strategy_workset_cycle"
        );

        let succeeded = self
            .snapshot
            .commands
            .values()
            .filter(|command| {
                command.state_id == state_id
                    && command.state_visit == self.snapshot.state_visits[state_id]
                    && command.status == CommandStatus::Succeeded
            })
            .filter_map(|command| command.item_id.clone())
            .collect::<BTreeSet<_>>();
        if succeeded.len() == normalized.len() {
            return Ok(true);
        }
        let issued = self
            .snapshot
            .commands
            .values()
            .filter(|command| {
                command.state_id == state_id
                    && command.state_visit == self.snapshot.state_visits[state_id]
            })
            .filter_map(|command| command.item_id.clone())
            .collect::<BTreeSet<_>>();
        let ready = normalized
            .into_iter()
            .filter(|(id, predecessors, _)| {
                !issued.contains(id) && predecessors.is_subset(&succeeded)
            })
            .collect::<Vec<_>>();
        for (item_id, _, item) in ready {
            let input = self.effect_input(state_id, item)?;
            self.emit_command(state_id, CommandKind::WorksetItem, Some(item_id), input)?;
        }
        Ok(false)
    }

    fn effect_input(&self, state_id: &str, input: Value) -> Result<Value> {
        effect_input_for(self.workflow, state_id, input)
    }

    fn emit_command(
        &mut self,
        state_id: &str,
        kind: CommandKind,
        item_id: Option<String>,
        input: Value,
    ) -> Result<()> {
        let state = self.workflow.state(state_id).unwrap();
        let visit = self.snapshot.state_visits[state_id];
        let ordinal = state
            .binding
            .as_deref()
            .map(|slot| self.current_ordinal(state_id, visit, slot, item_id.as_deref()))
            .unwrap_or(0);
        let input_bytes = serde_json::to_vec(&input)?;
        let input_digest = sha256_hex(&input_bytes);
        let identity = format!(
            "{}\0{}\0{}\0{}\0{}\0{}",
            self.snapshot.run_id,
            state_id,
            visit,
            item_id.as_deref().unwrap_or(""),
            ordinal,
            1
        );
        let id = format!("command:{}", sha256_hex(identity.as_bytes()));
        let attempt_token = format!(
            "attempt:{}",
            sha256_hex(format!("{}\0{}", id, 1).as_bytes())
        );
        self.bump_attempt_lineage(
            state_id,
            visit,
            state.binding.as_deref(),
            item_id.as_deref(),
        )?;
        let command = RunCommand {
            id: id.clone(),
            state_id: state_id.to_owned(),
            state_visit: visit,
            kind,
            status: CommandStatus::Pending,
            attempt: 1,
            attempt_token,
            binding_id: state.binding.clone(),
            runtime_id: state.runtime.clone(),
            entry: state.entry.clone(),
            item_id,
            session_policy: state
                .binding
                .as_deref()
                .and_then(|binding| {
                    self.workflow
                        .definition
                        .actor_slots
                        .iter()
                        .find(|slot| slot.id == binding)
                })
                .map_or(SessionPolicy::New, |slot| slot.session_policy),
            binding_ordinal: ordinal,
            resume_session_id: state.binding.as_ref().and_then(|binding| {
                self.snapshot
                    .actor_sessions
                    .get(&binding_session_key(binding, ordinal))
                    .cloned()
            }),
            input_digest,
            input,
            output_digest: None,
            failure_class: None,
            failure_code: None,
        };
        ensure!(
            self.snapshot.commands.insert(id, command.clone()).is_none(),
            "strategy_command_identity_conflict"
        );
        self.emitted.push(command);
        Ok(())
    }

    fn current_ordinal(
        &self,
        state_id: &str,
        visit: u64,
        slot_id: &str,
        item_id: Option<&str>,
    ) -> u8 {
        self.snapshot
            .slot_ordinals
            .get(&ordinal_key(state_id, visit, slot_id, item_id))
            .copied()
            .unwrap_or(0)
    }

    fn bump_attempt_lineage(
        &mut self,
        state_id: &str,
        visit: u64,
        slot_id: Option<&str>,
        item_id: Option<&str>,
    ) -> Result<()> {
        let key = lineage_key(state_id, visit, slot_id, item_id);
        let used = self
            .snapshot
            .attempt_lineage
            .get(&key)
            .copied()
            .unwrap_or(0);
        ensure!(
            u32::from(used.saturating_add(1))
                <= self.workflow.definition.limits.max_attempts as u32,
            "strategy_attempt_budget_exhausted"
        );
        self.snapshot.attempt_lineage.insert(key, used + 1);
        Ok(())
    }

    fn visit_commands<'s>(
        &'s self,
        state_id: &str,
        visit: u64,
    ) -> impl Iterator<Item = &'s RunCommand> + 's {
        let state_id = state_id.to_owned();
        self.snapshot
            .commands
            .values()
            .filter(move |command| command.state_id == state_id && command.state_visit == visit)
    }

    fn workset_failure_pending(&self, state_id: &str) -> bool {
        let visit = self
            .snapshot
            .state_visits
            .get(state_id)
            .copied()
            .unwrap_or(0);
        self.visit_commands(state_id, visit).any(|command| {
            command.status == CommandStatus::Failed
                && fallback_reason_base(self.workflow, &self.snapshot, command).is_none()
        })
    }

    fn visit_unsettled(&self, state_id: &str, visit: u64) -> bool {
        self.visit_commands(state_id, visit).any(|command| {
            matches!(
                command.status,
                CommandStatus::Pending
                    | CommandStatus::Claimed
                    | CommandStatus::Running
                    | CommandStatus::Retryable
                    | CommandStatus::CancelRequested
                    | CommandStatus::InDoubt
            ) || (command.status == CommandStatus::Failed
                && fallback_reason_base(self.workflow, &self.snapshot, command).is_some())
        })
    }

    fn refresh_workset_status(&mut self, state_id: &str) {
        let visit = self
            .snapshot
            .state_visits
            .get(state_id)
            .copied()
            .unwrap_or(0);
        let commands = self.visit_commands(state_id, visit).collect::<Vec<_>>();
        let status = if commands
            .iter()
            .any(|command| command.status == CommandStatus::InDoubt)
        {
            StrategyRunStatus::CancelInDoubt
        } else if commands.iter().any(|command| {
            command.status == CommandStatus::Retryable
                && command.failure_class == Some(FailureClass::Authority)
        }) {
            StrategyRunStatus::AuthorizationRequired
        } else if commands.iter().any(|command| {
            command.status == CommandStatus::Retryable
                && matches!(
                    command.failure_class,
                    Some(FailureClass::Runtime | FailureClass::Sandbox)
                )
        }) {
            StrategyRunStatus::RuntimeMissing
        } else if commands
            .iter()
            .any(|command| command.status == CommandStatus::Retryable)
        {
            StrategyRunStatus::Retryable
        } else {
            StrategyRunStatus::Running
        };
        let diagnostic_code = commands
            .iter()
            .filter(|command| {
                matches!(
                    command.status,
                    CommandStatus::Failed | CommandStatus::Retryable | CommandStatus::InDoubt
                )
            })
            .min_by_key(|command| command.id.as_str())
            .and_then(|command| command.failure_code.clone());
        self.snapshot.status = status;
        self.snapshot.diagnostic_code = diagnostic_code;
    }

    fn workset_failure_ready(&mut self, state_id: &str) -> Result<bool> {
        let visit = self
            .snapshot
            .state_visits
            .get(state_id)
            .copied()
            .unwrap_or(0);
        let cancel = self
            .visit_commands(state_id, visit)
            .filter(|command| {
                matches!(
                    command.status,
                    CommandStatus::Pending | CommandStatus::Claimed | CommandStatus::Retryable
                ) || (command.status == CommandStatus::Failed
                    && fallback_reason_base(self.workflow, &self.snapshot, command).is_some())
            })
            .map(|command| command.id.clone())
            .collect::<BTreeSet<_>>();
        for command_id in &cancel {
            self.set_command_status(command_id, CommandStatus::Cancelled);
        }
        if self.visit_unsettled(state_id, visit) {
            self.refresh_workset_status(state_id);
            return Ok(false);
        }
        let primary = self
            .visit_commands(state_id, visit)
            .filter(|command| command.status == CommandStatus::Failed)
            .min_by_key(|command| {
                (
                    command
                        .item_id
                        .clone()
                        .unwrap_or_else(|| command.id.clone()),
                    command.id.clone(),
                )
            });
        let Some(primary) = primary else {
            return Ok(false);
        };
        let item = primary
            .item_id
            .clone()
            .unwrap_or_else(|| primary.id.clone());
        let code = primary
            .failure_code
            .clone()
            .unwrap_or_else(|| "effect_failed".to_owned());
        let payload = json!({"code": code, "itemId": item});
        let transition = self
            .workflow
            .select_transition(state_id, TransitionEvent::Failure, &payload)?
            .ok_or_else(|| anyhow!("strategy_transition_missing"))?;
        let transition_id = transition.id.clone();
        let target = transition.to.clone();
        let callback = transition.mode == TransitionMode::Callback;
        self.snapshot.active_states.remove(state_id);
        if callback {
            self.park_callback(state_id, TransitionEvent::Failure, &transition_id, &target);
            return Ok(true);
        }
        self.enter(&target, Some(state_id))?;
        Ok(true)
    }

    #[allow(clippy::too_many_arguments)]
    fn issue_fallback(
        &mut self,
        failed_command_id: &str,
        next_ordinal: u8,
        locator: Value,
        from_value_id: String,
        to_value_id: String,
        reason: String,
        attempts: u8,
    ) -> Result<()> {
        let old = self
            .snapshot
            .commands
            .get(failed_command_id)
            .cloned()
            .ok_or_else(|| anyhow!("strategy_callback_stale"))?;
        ensure!(
            old.status == CommandStatus::Failed,
            "strategy_callback_conflict"
        );
        ensure!(
            lineage_within_budget(
                &self.snapshot,
                &old.state_id,
                old.state_visit,
                old.binding_id.as_deref(),
                old.item_id.as_deref(),
                self.workflow.definition.limits.max_attempts,
            ),
            "strategy_attempt_budget_exhausted"
        );
        let expected_reason = fallback_reason(self.workflow, &self.snapshot, &old)
            .ok_or_else(|| anyhow!("strategy_fallback_not_admissible"))?;
        ensure!(
            reason == expected_reason,
            "strategy_fallback_reason_invalid"
        );
        let slot_id = old
            .binding_id
            .clone()
            .ok_or_else(|| anyhow!("binding_incomplete"))?;
        ensure!(
            next_ordinal == old.binding_ordinal.saturating_add(1),
            "strategy_fallback_ordinal_invalid"
        );
        ensure!(
            attempts == old.attempt,
            "strategy_fallback_attempts_invalid"
        );
        let count = self
            .snapshot
            .slot_candidate_counts
            .get(&slot_id)
            .copied()
            .unwrap_or(1);
        ensure!(next_ordinal < count, "strategy_fallback_exhausted");
        self.bump_attempt_lineage(
            &old.state_id,
            old.state_visit,
            old.binding_id.as_deref(),
            old.item_id.as_deref(),
        )?;
        self.snapshot.slot_ordinals.insert(
            ordinal_key(
                &old.state_id,
                old.state_visit,
                &slot_id,
                old.item_id.as_deref(),
            ),
            next_ordinal,
        );
        let mut input = old.input.clone();
        if let Value::Object(ref mut object) = input {
            object.insert("predecessorLocator".into(), locator);
        } else {
            input = json!({
                "context": old.input,
                "predecessorLocator": locator,
            });
        }
        let state_id = old.state_id.clone();
        let kind = old.kind;
        let item_id = old.item_id.clone();
        self.snapshot.fallbacks.push(FallbackReceipt {
            fallback_from: from_value_id,
            fallback_to: to_value_id,
            reason,
            attempts,
        });
        self.snapshot.fallbacks.sort_by(|left, right| {
            left.fallback_from
                .cmp(&right.fallback_from)
                .then(left.fallback_to.cmp(&right.fallback_to))
                .then(left.reason.cmp(&right.reason))
                .then(left.attempts.cmp(&right.attempts))
        });
        self.set_command_status(failed_command_id, CommandStatus::Cancelled);
        self.emit_fallback_command(&state_id, kind, item_id, next_ordinal, input)?;
        if kind == CommandKind::WorksetItem {
            self.refresh_workset_status(&state_id);
        } else {
            self.snapshot.status = StrategyRunStatus::Running;
            self.snapshot.diagnostic_code = None;
        }
        Ok(())
    }

    fn emit_fallback_command(
        &mut self,
        state_id: &str,
        kind: CommandKind,
        item_id: Option<String>,
        ordinal: u8,
        input: Value,
    ) -> Result<()> {
        let state = self.workflow.state(state_id).unwrap();
        let visit = self.snapshot.state_visits[state_id];
        let input_bytes = serde_json::to_vec(&input)?;
        let input_digest = sha256_hex(&input_bytes);
        let identity = format!(
            "{}\0{}\0{}\0{}\0{}\0{}",
            self.snapshot.run_id,
            state_id,
            visit,
            item_id.as_deref().unwrap_or(""),
            ordinal,
            1
        );
        let id = format!("command:{}", sha256_hex(identity.as_bytes()));
        let attempt_token = format!(
            "attempt:{}",
            sha256_hex(format!("{}\0{}", id, 1).as_bytes())
        );
        let command = RunCommand {
            id: id.clone(),
            state_id: state_id.to_owned(),
            state_visit: visit,
            kind,
            status: CommandStatus::Pending,
            attempt: 1,
            attempt_token,
            binding_id: state.binding.clone(),
            runtime_id: state.runtime.clone(),
            entry: state.entry.clone(),
            item_id,
            session_policy: state
                .binding
                .as_deref()
                .and_then(|binding| {
                    self.workflow
                        .definition
                        .actor_slots
                        .iter()
                        .find(|slot| slot.id == binding)
                })
                .map_or(SessionPolicy::New, |slot| slot.session_policy),
            binding_ordinal: ordinal,
            resume_session_id: None,
            input_digest,
            input,
            output_digest: None,
            failure_class: None,
            failure_code: None,
        };
        ensure!(
            self.snapshot.commands.insert(id, command.clone()).is_none(),
            "strategy_command_identity_conflict"
        );
        self.emitted.push(command);
        Ok(())
    }

    /// Move one command to a new status, once, recording the move.
    ///
    /// Every status change in the machine goes through here, so the delta's
    /// settled set is a record of what happened rather than a diff of two
    /// snapshots. A consumer that applies only the delta therefore has no way
    /// to learn about a transition the machine forgot to mention.
    fn set_command_status(&mut self, command_id: &str, next: CommandStatus) {
        let Some(command) = self.snapshot.commands.get_mut(command_id) else {
            return;
        };
        if command.status == next {
            return;
        }
        command.status = next;
        if !self
            .delta
            .settled_commands
            .iter()
            .any(|settled| settled == command_id)
        {
            self.delta.settled_commands.push(command_id.to_owned());
        }
    }

    fn transition_command(
        &mut self,
        command_id: &str,
        attempt_token: &str,
        expected: CommandStatus,
        next: CommandStatus,
    ) -> Result<()> {
        let command = self
            .snapshot
            .commands
            .get_mut(command_id)
            .ok_or_else(|| anyhow!("strategy_callback_stale"))?;
        ensure!(
            command.attempt_token == attempt_token,
            "strategy_callback_stale"
        );
        ensure!(command.status == expected, "strategy_callback_conflict");
        self.set_command_status(command_id, next);
        Ok(())
    }

    fn settle_success(
        &mut self,
        command_id: &str,
        attempt_token: Option<&str>,
        output: Value,
    ) -> Result<()> {
        let output_digest = sha256_hex(&serde_json::to_vec(&output)?);
        let (state_id, state_visit, binding_id, binding_ordinal, session_policy, duplicate) = {
            let command = self
                .snapshot
                .commands
                .get_mut(command_id)
                .ok_or_else(|| anyhow!("strategy_callback_stale"))?;
            if let Some(attempt_token) = attempt_token {
                ensure!(
                    command.attempt_token == attempt_token,
                    "strategy_callback_stale"
                );
            }
            if command.status == CommandStatus::Succeeded {
                ensure!(
                    command.output_digest.as_deref() == Some(&output_digest),
                    "strategy_callback_conflict"
                );
                (
                    command.state_id.clone(),
                    command.state_visit,
                    command.binding_id.clone(),
                    command.binding_ordinal,
                    command.session_policy,
                    true,
                )
            } else {
                ensure!(
                    matches!(
                        command.status,
                        CommandStatus::Pending | CommandStatus::Claimed | CommandStatus::Running
                    ),
                    "strategy_callback_conflict"
                );
                command.output_digest = Some(output_digest);
                (
                    command.state_id.clone(),
                    command.state_visit,
                    command.binding_id.clone(),
                    command.binding_ordinal,
                    command.session_policy,
                    false,
                )
            }
        };
        if duplicate {
            self.applied = false;
            return Ok(());
        }
        self.set_command_status(command_id, CommandStatus::Succeeded);
        let own_writes = self.apply_shared_writes(command_id, &state_id, state_visit, &output)?;
        if session_policy != SessionPolicy::New
            && let (Some(binding_id), Some(session_id)) = (
                binding_id,
                output
                    .get("nativeSessionId")
                    .or_else(|| output.get("sessionId"))
                    .and_then(Value::as_str),
            )
            && !session_id.is_empty()
            && session_id.len() <= 160
            && !session_id.chars().any(char::is_control)
        {
            let binding_key = binding_session_key(&binding_id, binding_ordinal);
            let source_key = format!("session\0{binding_key}");
            if self
                .snapshot
                .merge_sources
                .get(&source_key)
                .is_none_or(|source| command_id > source.as_str())
            {
                self.snapshot
                    .actor_sessions
                    .insert(binding_key, session_id.to_owned());
                self.snapshot
                    .merge_sources
                    .insert(source_key, command_id.to_owned());
            }
        }
        let is_workset = self.workflow.state(&state_id).unwrap().kind == GraphStateKind::Workset;
        if is_workset && self.workset_failure_pending(&state_id) {
            self.workset_failure_ready(&state_id)?;
            return Ok(());
        }
        let satisfied = if is_workset {
            self.schedule_workset(&state_id)?
        } else {
            true
        };
        if satisfied {
            let payload = if is_workset {
                self.completion_input(&state_id, state_visit, &own_writes)?
            } else {
                output
            };
            self.complete_state(&state_id, TransitionEvent::Success, &payload)?;
        } else if is_workset {
            self.refresh_workset_status(&state_id);
        }
        Ok(())
    }

    fn settle_failure(
        &mut self,
        command_id: &str,
        attempt_token: Option<&str>,
        class: FailureClass,
        code: &str,
    ) -> Result<()> {
        validate_failure_code(code)?;
        let current = self
            .snapshot
            .commands
            .get(command_id)
            .cloned()
            .ok_or_else(|| anyhow!("strategy_callback_stale"))?;
        if let Some(attempt_token) = attempt_token {
            ensure!(
                current.attempt_token == attempt_token,
                "strategy_callback_stale"
            );
        }
        if matches!(
            current.status,
            CommandStatus::Failed | CommandStatus::Retryable | CommandStatus::Cancelled
        ) && current.failure_class == Some(class)
            && current.failure_code.as_deref() == Some(code)
        {
            self.applied = false;
            return Ok(());
        }
        ensure!(
            matches!(
                current.status,
                CommandStatus::Pending | CommandStatus::Claimed | CommandStatus::Running
            ),
            "strategy_callback_conflict"
        );
        let retryable = retry_policy_allows(self.workflow, &current, class, code)
            && lineage_within_budget(
                &self.snapshot,
                &current.state_id,
                current.state_visit,
                current.binding_id.as_deref(),
                current.item_id.as_deref(),
                self.workflow.definition.limits.max_attempts,
            );
        let terminal = if retryable {
            CommandStatus::Retryable
        } else if class == FailureClass::InDoubt {
            CommandStatus::InDoubt
        } else {
            CommandStatus::Failed
        };
        let command = self
            .snapshot
            .commands
            .get_mut(command_id)
            .ok_or_else(|| anyhow!("strategy_callback_stale"))?;
        command.failure_class = Some(class);
        command.failure_code = Some(code.to_owned());
        self.set_command_status(command_id, terminal);
        let state_id = current.state_id;
        let command_kind = current.kind;
        self.snapshot.diagnostic_code = Some(code.to_owned());
        if command_kind == CommandKind::Authorization {
            if let Some(transition) = self.workflow.select_transition(
                &state_id,
                TransitionEvent::Failure,
                &json!({"code": code}),
            )? {
                let transition_id = transition.id.clone();
                let target = transition.to.clone();
                let callback = transition.mode == TransitionMode::Callback;
                self.snapshot.active_states.remove(&state_id);
                if callback {
                    self.park_callback(
                        &state_id,
                        TransitionEvent::Failure,
                        &transition_id,
                        &target,
                    );
                    return Ok(());
                }
                self.enter(&target, Some(&state_id))?;
            } else {
                self.snapshot.status = StrategyRunStatus::Blocked;
            }
            return Ok(());
        }
        if retryable {
            if command_kind == CommandKind::WorksetItem {
                self.refresh_workset_status(&state_id);
            } else {
                self.snapshot.status = match class {
                    FailureClass::Authority => StrategyRunStatus::AuthorizationRequired,
                    FailureClass::Runtime | FailureClass::Sandbox => {
                        StrategyRunStatus::RuntimeMissing
                    }
                    _ => StrategyRunStatus::Retryable,
                };
            }
            return Ok(());
        }
        let has_other_final_workset_failure = command_kind == CommandKind::WorksetItem
            && self
                .visit_commands(&state_id, current.state_visit)
                .filter(|candidate| candidate.id != command_id)
                .any(|candidate| {
                    candidate.status == CommandStatus::Failed
                        && fallback_reason_base(self.workflow, &self.snapshot, candidate).is_none()
                });
        if !has_other_final_workset_failure
            && self
                .snapshot
                .commands
                .get(command_id)
                .is_some_and(|command| {
                    fallback_reason_base(self.workflow, &self.snapshot, command).is_some()
                })
        {
            if command_kind == CommandKind::WorksetItem {
                self.refresh_workset_status(&state_id);
            } else {
                self.snapshot.status = StrategyRunStatus::Running;
            }
            return Ok(());
        }
        if class == FailureClass::InDoubt {
            if command_kind == CommandKind::WorksetItem {
                self.refresh_workset_status(&state_id);
            } else {
                self.snapshot.status = StrategyRunStatus::CancelInDoubt;
            }
        } else if command_kind == CommandKind::WorksetItem {
            self.workset_failure_ready(&state_id)?;
        } else if let Some(transition) = self.workflow.select_transition(
            &state_id,
            TransitionEvent::Failure,
            &json!({"code": code}),
        )? {
            let transition_id = transition.id.clone();
            let target = transition.to.clone();
            let callback = transition.mode == TransitionMode::Callback;
            self.snapshot.active_states.remove(&state_id);
            if callback {
                self.park_callback(&state_id, TransitionEvent::Failure, &transition_id, &target);
                return Ok(());
            }
            self.enter(&target, Some(&state_id))?;
        } else {
            self.snapshot.status = StrategyRunStatus::Failed;
        }
        Ok(())
    }

    fn retry(&mut self, command_id: &str) -> Result<()> {
        let old = self
            .snapshot
            .commands
            .get(command_id)
            .cloned()
            .ok_or_else(|| anyhow!("strategy_callback_stale"))?;
        ensure!(
            old.status == CommandStatus::Retryable,
            "strategy_run_not_retryable"
        );
        ensure!(
            lineage_within_budget(
                &self.snapshot,
                &old.state_id,
                old.state_visit,
                old.binding_id.as_deref(),
                old.item_id.as_deref(),
                self.workflow.definition.limits.max_attempts,
            ),
            "strategy_attempt_budget_exhausted"
        );
        let failure_class = old
            .failure_class
            .ok_or_else(|| anyhow!("strategy_run_not_retryable"))?;
        let failure_code = old
            .failure_code
            .as_deref()
            .ok_or_else(|| anyhow!("strategy_run_not_retryable"))?;
        ensure!(
            retry_policy_allows(self.workflow, &old, failure_class, failure_code),
            "strategy_run_not_retryable"
        );
        let next_attempt = old.attempt + 1;
        let new_id = format!(
            "command:{}",
            sha256_hex(format!("{}\0{}", old.id, next_attempt).as_bytes())
        );
        let mut command = old.clone();
        command.id = new_id.clone();
        command.status = CommandStatus::Pending;
        command.attempt = next_attempt;
        command.attempt_token = format!(
            "attempt:{}",
            sha256_hex(format!("{}\0{}", new_id, next_attempt).as_bytes())
        );
        command.output_digest = None;
        command.failure_class = None;
        command.failure_code = None;
        ensure!(
            !self.snapshot.commands.contains_key(&new_id),
            "strategy_command_identity_conflict"
        );
        self.bump_attempt_lineage(
            &old.state_id,
            old.state_visit,
            old.binding_id.as_deref(),
            old.item_id.as_deref(),
        )?;
        self.set_command_status(command_id, CommandStatus::Cancelled);
        self.snapshot.commands.insert(new_id, command.clone());
        if old.kind == CommandKind::WorksetItem {
            self.refresh_workset_status(&old.state_id);
        } else {
            self.snapshot.status = StrategyRunStatus::Running;
            self.snapshot.diagnostic_code = None;
        }
        self.emitted.push(command);
        Ok(())
    }

    fn cancel(&mut self) -> Result<()> {
        if matches!(
            self.snapshot.status,
            StrategyRunStatus::Completed | StrategyRunStatus::Cancelled | StrategyRunStatus::Failed
        ) {
            self.applied = false;
            return Ok(());
        }
        self.snapshot.pending_callbacks.clear();
        let mut in_flight = false;
        let mut in_doubt = false;
        let cancellable = self
            .snapshot
            .commands
            .iter()
            .map(|(id, command)| (id.clone(), command.status))
            .collect::<Vec<_>>();
        for (command_id, status) in cancellable {
            match status {
                CommandStatus::Pending | CommandStatus::Claimed | CommandStatus::Retryable => {
                    self.set_command_status(&command_id, CommandStatus::Cancelled);
                }
                CommandStatus::Running | CommandStatus::CancelRequested => {
                    self.set_command_status(&command_id, CommandStatus::CancelRequested);
                    in_flight = true;
                }
                // A command whose effect outcome is unknown is not
                // cancellable: reporting the run cancelled while an external
                // effect may still have happened would lie about the world.
                CommandStatus::InDoubt => in_doubt = true,
                _ => {}
            }
        }
        self.snapshot.status = if in_doubt {
            self.snapshot.diagnostic_code = Some("cancellation_outcome_unknown".into());
            StrategyRunStatus::CancelInDoubt
        } else if in_flight {
            StrategyRunStatus::CancelRequested
        } else {
            StrategyRunStatus::Cancelled
        };
        Ok(())
    }

    fn cancel_acknowledged(&mut self, command_id: &str, attempt_token: &str) -> Result<()> {
        self.transition_command(
            command_id,
            attempt_token,
            CommandStatus::CancelRequested,
            CommandStatus::Cancelled,
        )?;
        if self.snapshot.commands.values().all(|command| {
            !matches!(
                command.status,
                CommandStatus::Running | CommandStatus::CancelRequested
            )
        }) {
            // Cancellation is final only when no position stays in doubt.
            self.snapshot.status = if self
                .snapshot
                .commands
                .values()
                .any(|command| command.status == CommandStatus::InDoubt)
            {
                self.snapshot.diagnostic_code = Some("cancellation_outcome_unknown".into());
                StrategyRunStatus::CancelInDoubt
            } else {
                StrategyRunStatus::Cancelled
            };
        }
        Ok(())
    }

    fn cancel_unknown(&mut self, command_id: &str, attempt_token: &str) -> Result<()> {
        self.transition_command(
            command_id,
            attempt_token,
            CommandStatus::CancelRequested,
            CommandStatus::InDoubt,
        )?;
        self.snapshot.status = StrategyRunStatus::CancelInDoubt;
        self.snapshot.diagnostic_code = Some("cancellation_outcome_unknown".into());
        Ok(())
    }
}

/// Merge one collection key with an incoming contribution.
///
/// The union is canonical: elements are deduplicated and ordered by their own
/// canonical encoding, so the result depends on the two sets and on nothing
/// else. That is what makes an accumulating bag safe to fill from concurrent
/// members — the completion order is not observable in the merged value, a
/// re-delivered contribution is not counted twice, and a scalar write into a
/// collection key is refused instead of being coerced into one.
fn accumulate(stored: Option<&Value>, incoming: &Value) -> Option<Value> {
    let incoming = incoming.as_array()?;
    let mut elements = BTreeMap::<String, Value>::new();
    if let Some(stored) = stored {
        for element in stored.as_array()? {
            elements.insert(canonical(element), element.clone());
        }
    }
    for element in incoming {
        elements.insert(canonical(element), element.clone());
    }
    Some(Value::Array(elements.into_values().collect::<Vec<_>>()))
}

/// The canonical encoding of one JSON value: its identity in a merged
/// collection. Object keys are ordered by the encoding itself rather than by
/// insertion, so two equal values always produce one element.
fn canonical(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_default()
}

fn pending_authorization(snapshot: &RunSnapshot) -> Result<String> {
    snapshot
        .commands
        .values()
        .find(|command| {
            command.kind == CommandKind::Authorization && command.status == CommandStatus::Pending
        })
        .map(|command| command.id.clone())
        .ok_or_else(|| anyhow!("strategy_authorization_not_pending"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn ordinal_key(state_id: &str, visit: u64, slot_id: &str, item_id: Option<&str>) -> String {
    lineage_key(state_id, visit, Some(slot_id), item_id)
}

pub fn binding_session_key(slot_id: &str, ordinal: u8) -> String {
    format!("{slot_id}\0{ordinal}")
}

fn lineage_key(state_id: &str, visit: u64, slot_id: Option<&str>, item_id: Option<&str>) -> String {
    match (slot_id, item_id) {
        (Some(slot), Some(item)) => format!("{state_id}\0{visit}\0{slot}\0{item}"),
        (Some(slot), None) => format!("{state_id}\0{visit}\0{slot}"),
        (None, Some(item)) => format!("{state_id}\0{visit}\0{item}"),
        (None, None) => format!("{state_id}\0{visit}"),
    }
}

pub fn lineage_within_budget(
    snapshot: &RunSnapshot,
    state_id: &str,
    visit: u64,
    slot_id: Option<&str>,
    item_id: Option<&str>,
    max_attempts: u8,
) -> bool {
    let used = snapshot
        .attempt_lineage
        .get(&lineage_key(state_id, visit, slot_id, item_id))
        .copied()
        .unwrap_or(0);
    u32::from(used.saturating_add(1)) <= max_attempts as u32
}

fn retry_policy_allows(
    workflow: &CompiledWorkflow,
    command: &RunCommand,
    class: FailureClass,
    code: &str,
) -> bool {
    if command.kind == CommandKind::Authorization || class == FailureClass::InDoubt {
        return false;
    }
    let Some(state) = workflow.state(&command.state_id) else {
        return false;
    };
    if class == FailureClass::Permanent && code == "quota_exhausted" {
        return false;
    }
    let class_allowed = match class {
        FailureClass::Transient
        | FailureClass::Authority
        | FailureClass::Runtime
        | FailureClass::Sandbox => true,
        FailureClass::Permanent => !state.retry.transient_only,
        FailureClass::InDoubt => false,
    };
    if !class_allowed {
        return false;
    }
    let limit = if matches!(command.kind, CommandKind::Actor | CommandKind::WorksetItem)
        && class == FailureClass::Transient
    {
        state
            .binding
            .as_deref()
            .and_then(|binding| {
                workflow
                    .definition
                    .actor_slots
                    .iter()
                    .find(|slot| slot.id == binding)
            })
            .map_or(state.retry.max_attempts, |slot| {
                state
                    .retry
                    .max_attempts
                    .min(slot.fallback.after_transient_attempts)
            })
    } else {
        state.retry.max_attempts
    };
    command.attempt < limit
}

fn validate_failure_code(code: &str) -> Result<()> {
    ensure!(
        !code.is_empty()
            && code.len() <= 96
            && code.chars().all(|character| {
                character.is_ascii_lowercase()
                    || character.is_ascii_digit()
                    || matches!(character, '-' | '_')
            }),
        "strategy_failure_code_invalid"
    );
    Ok(())
}

pub fn fallback_reason(
    workflow: &CompiledWorkflow,
    snapshot: &RunSnapshot,
    command: &RunCommand,
) -> Option<&'static str> {
    let reason = fallback_reason_base(workflow, snapshot, command)?;
    if command.kind == CommandKind::WorksetItem
        && snapshot.commands.values().any(|other| {
            other.id != command.id
                && other.state_id == command.state_id
                && other.state_visit == command.state_visit
                && (matches!(
                    other.status,
                    CommandStatus::Pending
                        | CommandStatus::Claimed
                        | CommandStatus::Running
                        | CommandStatus::Retryable
                        | CommandStatus::CancelRequested
                        | CommandStatus::InDoubt
                ) || (other.status == CommandStatus::Failed
                    && fallback_reason_base(workflow, snapshot, other).is_none()))
        })
    {
        return None;
    }
    Some(reason)
}

fn fallback_reason_base(
    workflow: &CompiledWorkflow,
    snapshot: &RunSnapshot,
    command: &RunCommand,
) -> Option<&'static str> {
    if command.status != CommandStatus::Failed
        || !matches!(command.kind, CommandKind::Actor | CommandKind::WorksetItem)
        || !snapshot.active_states.contains(&command.state_id)
    {
        return None;
    }
    let slot_id = command.binding_id.as_deref()?;
    let slot = workflow
        .definition
        .actor_slots
        .iter()
        .find(|slot| slot.id == slot_id)?;
    let reason = match (command.failure_class?, command.failure_code.as_deref()) {
        (FailureClass::Transient, _) => "transient-exhausted",
        (FailureClass::Permanent, Some("quota_exhausted")) if slot.fallback.on_quota => "quota",
        _ => return None,
    };
    let count = snapshot
        .slot_candidate_counts
        .get(slot_id)
        .copied()
        .unwrap_or(0);
    if command.binding_ordinal.saturating_add(1) >= count
        || !lineage_within_budget(
            snapshot,
            &command.state_id,
            command.state_visit,
            command.binding_id.as_deref(),
            command.item_id.as_deref(),
            workflow.definition.limits.max_attempts,
        )
    {
        return None;
    }
    Some(reason)
}

const fn default_state_visit() -> u64 {
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ActorSlot, GraphState, RetryPolicy, SessionPolicy, Transition, WorkflowDefinition,
        WorkflowLimits, WorkflowMetadata, WorksetTemplate,
    };

    /// The schema this crate's fixtures compile under: the generic identity,
    /// bound the same way a host binds its own.
    fn compile_workflow(
        definition: WorkflowDefinition,
    ) -> Result<CompiledWorkflow, crate::WorkflowValidationFailure> {
        crate::compile_workflow(
            definition,
            &crate::SchemaId::new(crate::GENERIC_WORKFLOW_SCHEMA),
        )
    }

    fn state(id: &str, kind: GraphStateKind) -> GraphState {
        GraphState {
            id: id.into(),
            kind,
            label: id.into(),
            instruction: String::new(),
            binding: None,
            runtime: None,
            entry: None,
            workset: None,
            retry: RetryPolicy::default(),
        }
    }

    fn actor_loop() -> CompiledWorkflow {
        compile_workflow(WorkflowDefinition {
            schema: crate::GENERIC_WORKFLOW_SCHEMA.into(),
            metadata: WorkflowMetadata {
                id: "loop".into(),
                name: "Loop".into(),
                version: "1".into(),
                description: String::new(),
            },
            limits: WorkflowLimits::default(),
            actor_slots: vec![{
                let mut slot = ActorSlot::required_actor("worker", "Worker");
                slot.session_policy = SessionPolicy::Sticky;
                slot
            }],
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
                state("fail", GraphStateKind::Fail),
            ],
            transitions: vec![
                Transition {
                    id: "loop-again".into(),
                    from: "work".into(),
                    to: "work".into(),
                    event: TransitionEvent::Success,
                    mode: TransitionMode::Flow,
                    guard: Some(super::super::GuardExpression {
                        path: "again".into(),
                        equals: Some(true.into()),
                        exists: false,
                    }),
                },
                Transition {
                    id: "finish".into(),
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
        })
        .unwrap()
    }

    #[test]
    fn back_edge_is_driven_only_by_matching_callback() {
        let workflow = actor_loop();
        let empty = RunSnapshot::empty("run-1", "revision", "semantics");
        let started = reduce(&workflow, &empty, ReducerEvent::Start { input: json!({}) }).unwrap();
        assert_eq!(started.emitted_commands.len(), 1);
        let command = &started.emitted_commands[0];
        let looped = reduce(
            &workflow,
            &started.snapshot,
            ReducerEvent::CommandSucceeded {
                command_id: command.id.clone(),
                attempt_token: command.attempt_token.clone(),
                output: json!({"again": true, "nativeSessionId": "session-1"}),
            },
        )
        .unwrap();
        assert_eq!(looped.snapshot.status, StrategyRunStatus::Running);
        assert_eq!(looped.emitted_commands.len(), 1);
        assert_ne!(looped.emitted_commands[0].id, command.id);
        assert_eq!(
            looped.emitted_commands[0].resume_session_id.as_deref(),
            Some("session-1")
        );
    }

    #[test]
    fn replay_is_byte_equivalent_and_duplicate_callback_is_idempotent() {
        let workflow = actor_loop();
        let empty = RunSnapshot::empty("run-1", "revision", "semantics");
        let event = ReducerEvent::Start { input: json!({}) };
        let first = reduce(&workflow, &empty, event.clone()).unwrap();
        let replay = reduce(&workflow, &empty, event).unwrap();
        assert_eq!(
            serde_json::to_vec(&first.snapshot).unwrap(),
            serde_json::to_vec(&replay.snapshot).unwrap()
        );
        let command = first.emitted_commands[0].clone();
        let success = ReducerEvent::CommandSucceeded {
            command_id: command.id,
            attempt_token: command.attempt_token,
            output: json!({"again": false}),
        };
        let completed = reduce(&workflow, &first.snapshot, success.clone()).unwrap();
        let duplicate = reduce(&workflow, &completed.snapshot, success).unwrap();
        assert!(!duplicate.applied);
        assert_eq!(duplicate.snapshot, completed.snapshot);
    }

    #[test]
    fn workset_emits_only_the_ready_dag_frontier() {
        let workflow = compile_workflow(WorkflowDefinition {
            schema: crate::GENERIC_WORKFLOW_SCHEMA.into(),
            metadata: WorkflowMetadata {
                id: "workset".into(),
                name: "Workset".into(),
                version: "1".into(),
                description: String::new(),
            },
            limits: WorkflowLimits::default(),
            actor_slots: vec![ActorSlot::required_actor("worker", "Worker")],
            runtimes: vec![],
            worksets: vec![WorksetTemplate {
                id: "tasks".into(),
                item_binding: "id".into(),
                predecessor_field: "prerequisites".into(),
            }],
            initial: "tasks".into(),
            states: vec![
                GraphState {
                    id: "tasks".into(),
                    kind: GraphStateKind::Workset,
                    label: "Tasks".into(),
                    instruction: "Execute the ready task.".into(),
                    binding: Some("worker".into()),
                    runtime: None,
                    entry: None,
                    workset: Some("tasks".into()),
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
                state("fail", GraphStateKind::Fail),
            ],
            transitions: vec![
                Transition {
                    id: "done".into(),
                    from: "tasks".into(),
                    to: "done".into(),
                    event: TransitionEvent::Success,
                    mode: TransitionMode::Flow,
                    guard: None,
                },
                Transition {
                    id: "failed".into(),
                    from: "tasks".into(),
                    to: "fail".into(),
                    event: TransitionEvent::Failure,
                    mode: TransitionMode::Flow,
                    guard: None,
                },
            ],
        })
        .unwrap();
        let empty = RunSnapshot::empty("run-1", "revision", "semantics");
        let started = reduce(
            &workflow,
            &empty,
            ReducerEvent::Start {
                input: json!({
                    "worksets": {
                        "tasks": [
                            {"id": "a", "prerequisites": []},
                            {"id": "b", "prerequisites": ["a"]}
                        ]
                    }
                }),
            },
        )
        .unwrap();
        assert_eq!(started.emitted_commands.len(), 1);
        assert_eq!(started.emitted_commands[0].item_id.as_deref(), Some("a"));
        let first = started.emitted_commands[0].clone();
        let second_frontier = reduce(
            &workflow,
            &started.snapshot,
            ReducerEvent::CommandSucceeded {
                command_id: first.id,
                attempt_token: first.attempt_token,
                output: json!({"ok": true}),
            },
        )
        .unwrap();
        assert_eq!(second_frontier.emitted_commands.len(), 1);
        assert_eq!(
            second_frontier.emitted_commands[0].item_id.as_deref(),
            Some("b")
        );
        let second = second_frontier.emitted_commands[0].clone();
        let completed = reduce(
            &workflow,
            &second_frontier.snapshot,
            ReducerEvent::CommandSucceeded {
                command_id: second.id,
                attempt_token: second.attempt_token,
                output: json!({"ok": true}),
            },
        )
        .unwrap();
        assert_eq!(completed.snapshot.status, StrategyRunStatus::Completed);
    }

    #[test]
    fn authorization_denial_uses_the_graph_failure_edge() {
        let workflow = compile_workflow(WorkflowDefinition {
            schema: crate::GENERIC_WORKFLOW_SCHEMA.into(),
            metadata: WorkflowMetadata {
                id: "authorization".into(),
                name: "Authorization".into(),
                version: "1".into(),
                description: String::new(),
            },
            limits: WorkflowLimits::default(),
            actor_slots: vec![],
            runtimes: vec![],
            worksets: vec![],
            initial: "authorize".into(),
            states: vec![
                state("authorize", GraphStateKind::Authorization),
                state("done", GraphStateKind::Succeed),
                state("blocked", GraphStateKind::Blocked),
            ],
            transitions: vec![
                Transition {
                    id: "granted".into(),
                    from: "authorize".into(),
                    to: "done".into(),
                    event: TransitionEvent::Success,
                    mode: TransitionMode::Flow,
                    guard: None,
                },
                Transition {
                    id: "denied".into(),
                    from: "authorize".into(),
                    to: "blocked".into(),
                    event: TransitionEvent::Failure,
                    mode: TransitionMode::Flow,
                    guard: None,
                },
            ],
        })
        .unwrap();
        let started = reduce(
            &workflow,
            &RunSnapshot::empty("run", "revision", "semantics"),
            ReducerEvent::Start { input: json!({}) },
        )
        .unwrap();
        let denied = reduce(
            &workflow,
            &started.snapshot,
            ReducerEvent::AuthorizationDenied,
        )
        .unwrap();
        assert_eq!(denied.snapshot.status, StrategyRunStatus::Blocked);
        assert!(denied.snapshot.active_states.is_empty());
    }

    #[test]
    fn workset_back_edge_reissues_items_for_the_new_state_visit() {
        let workflow = compile_workflow(WorkflowDefinition {
            schema: crate::GENERIC_WORKFLOW_SCHEMA.into(),
            metadata: WorkflowMetadata {
                id: "workset-loop".into(),
                name: "Workset loop".into(),
                version: "1".into(),
                description: String::new(),
            },
            limits: WorkflowLimits::default(),
            actor_slots: vec![ActorSlot::required_actor("worker", "Worker")],
            runtimes: vec![],
            worksets: vec![WorksetTemplate {
                id: "tasks".into(),
                item_binding: "id".into(),
                predecessor_field: String::new(),
            }],
            initial: "tasks".into(),
            states: vec![
                GraphState {
                    id: "tasks".into(),
                    kind: GraphStateKind::Workset,
                    label: "Tasks".into(),
                    instruction: "Execute.".into(),
                    binding: Some("worker".into()),
                    runtime: None,
                    entry: None,
                    workset: Some("tasks".into()),
                    retry: RetryPolicy::default(),
                },
                GraphState {
                    id: "repeat".into(),
                    kind: GraphStateKind::Actor,
                    label: "Repeat".into(),
                    instruction: "Continue the next visit.".into(),
                    binding: Some("worker".into()),
                    runtime: None,
                    entry: None,
                    workset: None,
                    retry: RetryPolicy::default(),
                },
                state("done", GraphStateKind::Succeed),
                state("fail", GraphStateKind::Fail),
            ],
            transitions: vec![
                Transition {
                    id: "again".into(),
                    from: "tasks".into(),
                    to: "repeat".into(),
                    event: TransitionEvent::Success,
                    mode: TransitionMode::Flow,
                    guard: Some(super::super::GuardExpression {
                        path: "context.again".into(),
                        equals: Some(true.into()),
                        exists: false,
                    }),
                },
                Transition {
                    id: "done".into(),
                    from: "tasks".into(),
                    to: "done".into(),
                    event: TransitionEvent::Success,
                    mode: TransitionMode::Flow,
                    guard: None,
                },
                Transition {
                    id: "failed".into(),
                    from: "tasks".into(),
                    to: "fail".into(),
                    event: TransitionEvent::Failure,
                    mode: TransitionMode::Flow,
                    guard: None,
                },
                Transition {
                    id: "repeat-success".into(),
                    from: "repeat".into(),
                    to: "tasks".into(),
                    event: TransitionEvent::Success,
                    mode: TransitionMode::Flow,
                    guard: None,
                },
                Transition {
                    id: "repeat-failure".into(),
                    from: "repeat".into(),
                    to: "fail".into(),
                    event: TransitionEvent::Failure,
                    mode: TransitionMode::Flow,
                    guard: None,
                },
            ],
        })
        .unwrap();
        let started = reduce(
            &workflow,
            &RunSnapshot::empty("run", "revision", "semantics"),
            ReducerEvent::Start {
                input: json!({"worksets": {"tasks": [{"id": "same"}]}}),
            },
        )
        .unwrap();
        let first = &started.emitted_commands[0];
        let looped = reduce(
            &workflow,
            &started.snapshot,
            ReducerEvent::CommandSucceeded {
                command_id: first.id.clone(),
                attempt_token: first.attempt_token.clone(),
                output: json!({"context": {"again": true}}),
            },
        )
        .unwrap();
        let repeat = &looped.emitted_commands[0];
        let revisited = reduce(
            &workflow,
            &looped.snapshot,
            ReducerEvent::CommandSucceeded {
                command_id: repeat.id.clone(),
                attempt_token: repeat.attempt_token.clone(),
                output: json!({}),
            },
        )
        .unwrap();
        assert_eq!(revisited.emitted_commands.len(), 1);
        assert_eq!(
            revisited.emitted_commands[0].item_id.as_deref(),
            Some("same")
        );
        assert_eq!(revisited.emitted_commands[0].state_visit, 2);
    }

    #[test]
    fn actor_json_worksets_are_merged_into_run_input_before_guards() {
        let workflow = compile_workflow(WorkflowDefinition {
            schema: crate::GENERIC_WORKFLOW_SCHEMA.into(),
            metadata: WorkflowMetadata {
                id: "merge".into(),
                name: "Merge".into(),
                version: "1".into(),
                description: String::new(),
            },
            limits: WorkflowLimits::default(),
            actor_slots: vec![ActorSlot::required_actor("entry", "Entry")],
            runtimes: vec![],
            worksets: vec![WorksetTemplate {
                id: "tasks".into(),
                item_binding: "id".into(),
                predecessor_field: String::new(),
            }],
            initial: "plan".into(),
            states: vec![
                GraphState {
                    id: "plan".into(),
                    kind: GraphStateKind::Actor,
                    label: "Plan".into(),
                    instruction: "Plan".into(),
                    binding: Some("entry".into()),
                    runtime: None,
                    entry: None,
                    workset: None,
                    retry: RetryPolicy::default(),
                },
                GraphState {
                    id: "tasks".into(),
                    kind: GraphStateKind::Workset,
                    label: "Tasks".into(),
                    instruction: "Do".into(),
                    binding: Some("entry".into()),
                    runtime: None,
                    entry: None,
                    workset: Some("tasks".into()),
                    retry: RetryPolicy::default(),
                },
                state("done", GraphStateKind::Succeed),
                state("fail", GraphStateKind::Fail),
            ],
            transitions: vec![
                Transition {
                    id: "planned".into(),
                    from: "plan".into(),
                    to: "tasks".into(),
                    event: TransitionEvent::Success,
                    mode: TransitionMode::Flow,
                    guard: None,
                },
                Transition {
                    id: "plan-failed".into(),
                    from: "plan".into(),
                    to: "fail".into(),
                    event: TransitionEvent::Failure,
                    mode: TransitionMode::Flow,
                    guard: None,
                },
                Transition {
                    id: "finished".into(),
                    from: "tasks".into(),
                    to: "done".into(),
                    event: TransitionEvent::Success,
                    mode: TransitionMode::Flow,
                    guard: None,
                },
                Transition {
                    id: "tasks-failed".into(),
                    from: "tasks".into(),
                    to: "fail".into(),
                    event: TransitionEvent::Failure,
                    mode: TransitionMode::Flow,
                    guard: None,
                },
            ],
        })
        .unwrap();
        let started = reduce(
            &workflow,
            &RunSnapshot::empty("run", "revision", "semantics"),
            ReducerEvent::Start { input: json!({}) },
        )
        .unwrap();
        let command = &started.emitted_commands[0];
        let planned = reduce(
            &workflow,
            &started.snapshot,
            ReducerEvent::CommandSucceeded {
                command_id: command.id.clone(),
                attempt_token: command.attempt_token.clone(),
                output: json!({
                    "worksets": {"tasks": [{"id": "from-actor"}]},
                    "context": {"note": "keep"}
                }),
            },
        )
        .unwrap();
        // The writes landed in versioned shared resources, each naming its
        // writer, rather than in one silently merged run-wide bag.
        let worksets = &planned.snapshot.shared["worksets"];
        assert_eq!(worksets.revision, 1);
        assert_eq!(worksets.keys["tasks"].value[0]["id"], "from-actor");
        assert_eq!(
            worksets.keys["tasks"]
                .writers
                .iter()
                .map(|writer| writer.node_id.as_str())
                .collect::<Vec<_>>(),
            vec!["plan"]
        );
        assert_eq!(
            planned.snapshot.shared["context"].keys["note"].value,
            "keep"
        );
        assert_eq!(
            planned.snapshot.merge_sources["worksets\0tasks"],
            command.id
        );
        assert_eq!(planned.emitted_commands.len(), 1);
        assert_eq!(
            planned.emitted_commands[0].item_id.as_deref(),
            Some("from-actor")
        );
        // The scheduled workset read that resource at the revision it bound,
        // and the item it scheduled is the one the writer published.
        let binding = &planned.snapshot.bindings[&InputBinding::key("tasks", 1)];
        assert_eq!(binding.shared_revision("worksets"), Some(1));
        assert_eq!(binding.predecessors.len(), 1);
        assert_eq!(binding.predecessors[0].node_id, "plan");
        assert_eq!(binding.predecessors[0].node_visit, 1);
    }

    #[test]
    fn quota_fallback_opens_a_new_command_with_locator_and_no_resume() {
        let workflow = actor_loop();
        let mut empty = RunSnapshot::empty("run-1", "revision", "semantics");
        empty.slot_candidate_counts.insert("worker".into(), 2);
        let started = reduce(&workflow, &empty, ReducerEvent::Start { input: json!({}) }).unwrap();
        let command = started.emitted_commands[0].clone();
        let failed = reduce(
            &workflow,
            &started.snapshot,
            ReducerEvent::CommandFailed {
                command_id: command.id.clone(),
                attempt_token: command.attempt_token.clone(),
                class: FailureClass::Permanent,
                code: "quota_exhausted".into(),
            },
        )
        .unwrap();
        assert_eq!(failed.snapshot.status, StrategyRunStatus::Running);
        assert!(failed.snapshot.active_states.contains("work"));
        assert!(!failed.snapshot.state_visits.contains_key("fail"));
        let next = reduce(
            &workflow,
            &failed.snapshot,
            ReducerEvent::FallbackIssued {
                failed_command_id: command.id.clone(),
                next_ordinal: 1,
                locator: json!({
                    "sourcePath": "/synthetic/store",
                    "nativeSessionId": "native-1",
                    "sourceKind": "fixture"
                }),
                from_value_id: "agent:primary".into(),
                to_value_id: "agent:fallback".into(),
                reason: "quota".into(),
                attempts: 1,
            },
        )
        .unwrap();
        assert_eq!(next.emitted_commands.len(), 1);
        assert_eq!(next.emitted_commands[0].binding_ordinal, 1);
        assert_eq!(
            next.snapshot.commands[&command.id].status,
            CommandStatus::Cancelled
        );
        assert_eq!(next.emitted_commands[0].resume_session_id, None);
        assert_eq!(
            next.emitted_commands[0].input["predecessorLocator"]["sourcePath"],
            "/synthetic/store"
        );
        assert_eq!(next.snapshot.fallbacks[0].fallback_from, "agent:primary");
        assert_eq!(next.snapshot.fallbacks[0].fallback_to, "agent:fallback");
        assert!(
            !serde_json::to_string(&next.snapshot.fallbacks)
                .unwrap()
                .contains("sourcePath")
        );
    }

    #[test]
    fn transient_failure_is_retryable_until_slot_attempts_then_can_fallback() {
        let workflow = actor_loop();
        let mut empty = RunSnapshot::empty("run-1", "revision", "semantics");
        empty.slot_candidate_counts.insert("worker".into(), 2);
        let started = reduce(&workflow, &empty, ReducerEvent::Start { input: json!({}) }).unwrap();
        let command = started.emitted_commands[0].clone();
        let first = reduce(
            &workflow,
            &started.snapshot,
            ReducerEvent::CommandFailed {
                command_id: command.id.clone(),
                attempt_token: command.attempt_token.clone(),
                class: FailureClass::Transient,
                code: "effect_temporarily_unavailable".into(),
            },
        )
        .unwrap();
        assert_eq!(first.snapshot.status, StrategyRunStatus::Retryable);
        let retried = reduce(
            &workflow,
            &first.snapshot,
            ReducerEvent::RetryRequested {
                command_id: command.id,
            },
        )
        .unwrap();
        let retry_command = retried.emitted_commands[0].clone();
        assert_eq!(retry_command.attempt, 2);
        let exhausted = reduce(
            &workflow,
            &retried.snapshot,
            ReducerEvent::CommandFailed {
                command_id: retry_command.id.clone(),
                attempt_token: retry_command.attempt_token.clone(),
                class: FailureClass::Transient,
                code: "effect_temporarily_unavailable".into(),
            },
        )
        .unwrap();
        assert_eq!(
            exhausted.snapshot.commands[&retry_command.id].status,
            CommandStatus::Failed
        );
        assert_eq!(exhausted.snapshot.status, StrategyRunStatus::Running);
        assert!(!exhausted.snapshot.state_visits.contains_key("fail"));
        let next = reduce(
            &workflow,
            &exhausted.snapshot,
            ReducerEvent::FallbackIssued {
                failed_command_id: retry_command.id,
                next_ordinal: 1,
                locator: json!({"locatorUnavailable": true}),
                from_value_id: "agent:primary".into(),
                to_value_id: "agent:fallback".into(),
                reason: "transient-exhausted".into(),
                attempts: 2,
            },
        )
        .unwrap();
        assert_eq!(next.emitted_commands[0].binding_ordinal, 1);
        assert_eq!(next.snapshot.status, StrategyRunStatus::Running);
    }

    #[test]
    fn fallback_list_exhaustion_keeps_the_failed_run() {
        let workflow = actor_loop();
        let mut empty = RunSnapshot::empty("run-1", "revision", "semantics");
        empty.slot_candidate_counts.insert("worker".into(), 1);
        let started = reduce(&workflow, &empty, ReducerEvent::Start { input: json!({}) }).unwrap();
        let command = started.emitted_commands[0].clone();
        let failed = reduce(
            &workflow,
            &started.snapshot,
            ReducerEvent::CommandFailed {
                command_id: command.id.clone(),
                attempt_token: command.attempt_token.clone(),
                class: FailureClass::Permanent,
                code: "quota_exhausted".into(),
            },
        )
        .unwrap();
        assert_eq!(failed.snapshot.status, StrategyRunStatus::Failed);
        assert!(
            reduce(
                &workflow,
                &failed.snapshot,
                ReducerEvent::FallbackIssued {
                    failed_command_id: command.id,
                    next_ordinal: 1,
                    locator: json!({"locatorUnavailable": true}),
                    from_value_id: "agent:primary".into(),
                    to_value_id: "agent:fallback".into(),
                    reason: "quota".into(),
                    attempts: 1,
                },
            )
            .is_err()
        );
    }

    fn callback_workflow(failure_mode: TransitionMode) -> CompiledWorkflow {
        compile_workflow(WorkflowDefinition {
            schema: crate::GENERIC_WORKFLOW_SCHEMA.into(),
            metadata: WorkflowMetadata {
                id: "callback".into(),
                name: "Callback".into(),
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
                state("done", GraphStateKind::Succeed),
                state("fail", GraphStateKind::Fail),
            ],
            transitions: vec![
                Transition {
                    id: "review".into(),
                    from: "work".into(),
                    to: "done".into(),
                    event: TransitionEvent::Success,
                    mode: TransitionMode::Callback,
                    guard: None,
                },
                Transition {
                    id: "failed".into(),
                    from: "work".into(),
                    to: "fail".into(),
                    event: TransitionEvent::Failure,
                    mode: failure_mode,
                    guard: None,
                },
            ],
        })
        .unwrap()
    }

    fn park_work(workflow: &CompiledWorkflow) -> (ReducerOutput, RunCommand) {
        let started = reduce(
            workflow,
            &RunSnapshot::empty("run-callback", "revision", "semantics"),
            ReducerEvent::Start { input: json!({}) },
        )
        .unwrap();
        let command = started.emitted_commands[0].clone();
        let parked = reduce(
            workflow,
            &started.snapshot,
            ReducerEvent::CommandSucceeded {
                command_id: command.id.clone(),
                attempt_token: command.attempt_token.clone(),
                output: json!({"context": {"note": "ready"}}),
            },
        )
        .unwrap();
        (parked, command)
    }

    fn decide(
        workflow: &CompiledWorkflow,
        snapshot: &RunSnapshot,
        decision: crate::CallbackDecision,
    ) -> Result<ReducerOutput> {
        reduce(
            workflow,
            snapshot,
            ReducerEvent::CallbackDecision {
                state_id: "work".into(),
                state_visit: 1,
                decision,
            },
        )
    }

    #[test]
    fn callback_edge_parks_the_run_until_the_decider_decides() {
        let workflow = callback_workflow(TransitionMode::Flow);
        let (parked, command) = park_work(&workflow);
        assert_eq!(parked.snapshot.status, StrategyRunStatus::Waiting);
        assert!(
            parked.emitted_commands.is_empty(),
            "a callback edge emits no next command before the decision"
        );
        assert!(parked.snapshot.completed_states.contains("work"));
        assert!(parked.snapshot.active_states.is_empty());
        assert_eq!(parked.snapshot.pending_callbacks.len(), 1);
        let pending = &parked.snapshot.pending_callbacks[0];
        assert_eq!(pending.state_id, "work");
        assert_eq!(pending.state_visit, 1);
        assert_eq!(pending.transition_id, "review");
        assert_eq!(pending.event, TransitionEvent::Success);
        assert_eq!(pending.target, "done");
        // The completed effect's write is durable and attributable: the
        // context resource moved to revision 1, the key names the node visit
        // that wrote it, and the run input itself was never mutated.
        assert_eq!(parked.snapshot.shared["context"].revision, 1);
        assert_eq!(
            parked.snapshot.shared["context"].keys["note"].value,
            "ready"
        );
        assert_eq!(
            parked.snapshot.shared["context"].keys["note"]
                .writers
                .iter()
                .map(|writer| (writer.node_id.as_str(), writer.node_visit))
                .collect::<Vec<_>>(),
            vec![("work", 1)]
        );
        assert!(parked.snapshot.input.get("context").is_none());
        // A duplicate settlement stays idempotent and never double-parks.
        let duplicate = reduce(
            &workflow,
            &parked.snapshot,
            ReducerEvent::CommandSucceeded {
                command_id: command.id.clone(),
                attempt_token: command.attempt_token.clone(),
                output: json!({"context": {"note": "ready"}}),
            },
        )
        .unwrap();
        assert!(!duplicate.applied);
        assert_eq!(duplicate.snapshot.pending_callbacks.len(), 1);
    }

    #[test]
    fn callback_decision_advance_enters_the_declared_target() {
        let workflow = callback_workflow(TransitionMode::Flow);
        let (parked, _) = park_work(&workflow);
        let advanced = decide(
            &workflow,
            &parked.snapshot,
            crate::CallbackDecision::Enter("done".to_owned()),
        )
        .unwrap();
        assert_eq!(advanced.snapshot.status, StrategyRunStatus::Completed);
        assert!(advanced.snapshot.pending_callbacks.is_empty());
        assert!(advanced.snapshot.completed_states.contains("done"));
        // The same decision replayed against the settled run is stale.
        let replay = decide(
            &workflow,
            &advanced.snapshot,
            crate::CallbackDecision::Enter("done".to_owned()),
        );
        assert!(
            replay
                .unwrap_err()
                .to_string()
                .contains("strategy_callback_stale")
        );
    }

    #[test]
    fn callback_decision_return_reenters_the_completed_state() {
        let workflow = callback_workflow(TransitionMode::Flow);
        let (parked, _) = park_work(&workflow);
        let returned = decide(
            &workflow,
            &parked.snapshot,
            crate::CallbackDecision::Enter("work".to_owned()),
        )
        .unwrap();
        assert_eq!(returned.snapshot.status, StrategyRunStatus::Running);
        assert!(returned.snapshot.pending_callbacks.is_empty());
        assert_eq!(returned.snapshot.state_visits["work"], 2);
        assert_eq!(returned.emitted_commands.len(), 1);
        assert_eq!(returned.emitted_commands[0].state_id, "work");
        assert_eq!(returned.emitted_commands[0].state_visit, 2);
        // The re-entered visit parks again on the same callback edge.
        let command = returned.emitted_commands[0].clone();
        let reparked = reduce(
            &workflow,
            &returned.snapshot,
            ReducerEvent::CommandSucceeded {
                command_id: command.id.clone(),
                attempt_token: command.attempt_token.clone(),
                output: json!({}),
            },
        )
        .unwrap();
        assert_eq!(reparked.snapshot.status, StrategyRunStatus::Waiting);
        assert_eq!(reparked.snapshot.pending_callbacks.len(), 1);
        assert_eq!(reparked.snapshot.pending_callbacks[0].state_visit, 2);
        // The visit-1 decision is stale against the visit-2 wait.
        assert!(
            decide(
                &workflow,
                &reparked.snapshot,
                crate::CallbackDecision::Enter("done".to_owned())
            )
            .unwrap_err()
            .to_string()
            .contains("strategy_callback_stale")
        );
    }

    #[test]
    fn callback_decision_terminate_cancels_the_run() {
        let workflow = callback_workflow(TransitionMode::Flow);
        let (parked, _) = park_work(&workflow);
        let terminated = decide(
            &workflow,
            &parked.snapshot,
            crate::CallbackDecision::Terminate,
        )
        .unwrap();
        assert_eq!(terminated.snapshot.status, StrategyRunStatus::Cancelled);
        assert!(terminated.snapshot.pending_callbacks.is_empty());
        assert!(terminated.emitted_commands.is_empty());
        assert!(
            decide(
                &workflow,
                &terminated.snapshot,
                crate::CallbackDecision::Enter("done".to_owned())
            )
            .unwrap_err()
            .to_string()
            .contains("strategy_callback_stale")
        );
    }

    #[test]
    fn callback_decision_binds_the_exact_pending_wait() {
        let workflow = callback_workflow(TransitionMode::Flow);
        let (parked, _) = park_work(&workflow);
        for (state_id, state_visit) in [("work", 2u64), ("done", 1u64)] {
            let stale = reduce(
                &workflow,
                &parked.snapshot,
                ReducerEvent::CallbackDecision {
                    state_id: state_id.into(),
                    state_visit,
                    decision: crate::CallbackDecision::Enter("done".to_owned()),
                },
            );
            assert!(
                stale
                    .unwrap_err()
                    .to_string()
                    .contains("strategy_callback_stale"),
                "decision for {state_id} visit {state_visit} must be stale"
            );
        }
    }

    #[test]
    fn callback_failure_edge_parks_the_failed_state_for_decision() {
        let workflow = callback_workflow(TransitionMode::Callback);
        let started = reduce(
            &workflow,
            &RunSnapshot::empty("run-callback", "revision", "semantics"),
            ReducerEvent::Start { input: json!({}) },
        )
        .unwrap();
        let command = started.emitted_commands[0].clone();
        let parked = reduce(
            &workflow,
            &started.snapshot,
            ReducerEvent::CommandFailed {
                command_id: command.id.clone(),
                attempt_token: command.attempt_token.clone(),
                class: FailureClass::Permanent,
                code: "effect_failed".into(),
            },
        )
        .unwrap();
        assert_eq!(parked.snapshot.status, StrategyRunStatus::Waiting);
        assert!(parked.emitted_commands.is_empty());
        assert_eq!(parked.snapshot.pending_callbacks.len(), 1);
        assert_eq!(
            parked.snapshot.pending_callbacks[0].event,
            TransitionEvent::Failure
        );
        assert_eq!(parked.snapshot.pending_callbacks[0].target, "fail");
        let advanced = decide(
            &workflow,
            &parked.snapshot,
            crate::CallbackDecision::Enter("fail".to_owned()),
        )
        .unwrap();
        assert_eq!(advanced.snapshot.status, StrategyRunStatus::Failed);
        assert!(advanced.snapshot.state_visits.contains_key("fail"));
    }

    #[test]
    fn callback_wait_survives_snapshot_persistence_and_legacy_snapshots_default_empty() {
        let workflow = callback_workflow(TransitionMode::Flow);
        let (parked, _) = park_work(&workflow);
        let bytes = serde_json::to_vec(&parked.snapshot).unwrap();
        let restored: RunSnapshot = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(restored, parked.snapshot);
        // Snapshots persisted before callback mode existed carry no field.
        let legacy = serde_json::to_vec(&parked.snapshot).unwrap();
        let mut value: Value = serde_json::from_slice(&legacy).unwrap();
        value.as_object_mut().unwrap().remove("pendingCallbacks");
        let restored: RunSnapshot = serde_json::from_value(value).unwrap();
        assert!(restored.pending_callbacks.is_empty());
    }

    #[test]
    fn authorization_denial_on_a_callback_failure_edge_parks_for_decision() {
        let workflow = compile_workflow(WorkflowDefinition {
            schema: crate::GENERIC_WORKFLOW_SCHEMA.into(),
            metadata: WorkflowMetadata {
                id: "callback-authorization".into(),
                name: "Callback authorization".into(),
                version: "1".into(),
                description: String::new(),
            },
            limits: WorkflowLimits::default(),
            actor_slots: vec![],
            runtimes: vec![],
            worksets: vec![],
            initial: "authorize".into(),
            states: vec![
                state("authorize", GraphStateKind::Authorization),
                state("done", GraphStateKind::Succeed),
                state("blocked", GraphStateKind::Blocked),
            ],
            transitions: vec![
                Transition {
                    id: "granted".into(),
                    from: "authorize".into(),
                    to: "done".into(),
                    event: TransitionEvent::Success,
                    mode: TransitionMode::Flow,
                    guard: None,
                },
                Transition {
                    id: "denied".into(),
                    from: "authorize".into(),
                    to: "blocked".into(),
                    event: TransitionEvent::Failure,
                    mode: TransitionMode::Callback,
                    guard: None,
                },
            ],
        })
        .unwrap();
        let started = reduce(
            &workflow,
            &RunSnapshot::empty("run", "revision", "semantics"),
            ReducerEvent::Start { input: json!({}) },
        )
        .unwrap();
        let parked = reduce(
            &workflow,
            &started.snapshot,
            ReducerEvent::AuthorizationDenied,
        )
        .unwrap();
        assert_eq!(parked.snapshot.status, StrategyRunStatus::Waiting);
        assert_eq!(parked.snapshot.pending_callbacks.len(), 1);
        assert_eq!(parked.snapshot.pending_callbacks[0].target, "blocked");
        let decided = reduce(
            &workflow,
            &parked.snapshot,
            ReducerEvent::CallbackDecision {
                state_id: "authorize".into(),
                state_visit: 1,
                decision: crate::CallbackDecision::Enter("blocked".to_owned()),
            },
        )
        .unwrap();
        assert_eq!(decided.snapshot.status, StrategyRunStatus::Blocked);
    }
}
