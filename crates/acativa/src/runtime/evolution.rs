//! Evolution seams connecting the workflow runtime to observation, cost,
//! context, and strategy facts.
//!
//! The runtime asks four typed questions and never answers them itself:
//!
//! * **observation** — what did the run's nodes do ([`EvolutionObservationPort`]);
//! * **cost** — what has this run spent ([`EvolutionCostPort`]);
//! * **context** — which durable run facts bound the current wait
//!   ([`EvolutionContextPort`]);
//! * **strategy** — which configured option should be suggested next
//!   ([`EvolutionStrategyPort`]).
//!
//! A suggestion is advice only: every [`StrategySuggestion`] marks
//! `has_execution_permission: false`, so an explicit choice and an adopted
//! default decide first and a suggestion never grants an effect. Permission,
//! version, and resource facts are rechecked strictly before any effect
//! executes through [`recheck_before_effect`], the single evaluation path.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::{Mutex, RwLock};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::adapter::SingleWriterSessionRegistry;
use crate::ports::host_ports;
use crate::store::{StrategyAuthorization, StrategyDefinition};
use crate::{RunCommand, RunSnapshot};

// ----------------------------------------------------------------------------
// Typed observation seam
// ----------------------------------------------------------------------------

#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ObservationScopeSeam {
    pub responsibility_id: String,
    pub task_type: String,
    pub configuration_id: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObservationFactKindSeam {
    Run,
    Wait,
    Result,
    Repeat,
    Correction,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ObservationFactRecordSeam {
    pub fact_id: String,
    pub scope: ObservationScopeSeam,
    pub kind: ObservationFactKindSeam,
    pub state_id: String,
    pub visit: u64,
    pub recorded_at_unix_ms: i64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeObservationSummary {
    pub node_id: String,
    pub generation: u64,
    pub lifecycle_state: String,
    pub work_role: String,
    pub active_invocation_id: Option<String>,
    pub durable_cursor: u64,
}

pub trait EvolutionObservationPort: Send + Sync {
    fn collect_node_observations(&self, run_id: &str) -> Vec<NodeObservationSummary>;
}

#[derive(Default)]
pub struct DefaultEvolutionObservationPort {
    observations: Mutex<BTreeMap<String, Vec<NodeObservationSummary>>>,
}

impl DefaultEvolutionObservationPort {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_observation(&self, run_id: &str, obs: NodeObservationSummary) {
        let mut guard = self.observations.lock().unwrap_or_else(|p| p.into_inner());
        guard.entry(run_id.to_owned()).or_default().push(obs);
    }
}

impl EvolutionObservationPort for DefaultEvolutionObservationPort {
    fn collect_node_observations(&self, run_id: &str) -> Vec<NodeObservationSummary> {
        let guard = self.observations.lock().unwrap_or_else(|p| p.into_inner());
        guard.get(run_id).cloned().unwrap_or_default()
    }
}

// ----------------------------------------------------------------------------
// Typed cost seam
// ----------------------------------------------------------------------------

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BudgetPoolReservationSeam {
    pub invocation_id: String,
    pub budget_id: String,
    pub reserved_tokens: u64,
    pub settled_tokens: Option<u64>,
    pub overage_tokens: Option<u64>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvolutionCostFacts {
    pub prompt_tokens: u64,
    pub cached_input_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
    pub exact_count: u64,
    pub estimated_count: u64,
    /// Whether a configured budget pool and its reservations contributed to
    /// these facts. `false` means the numbers come from the ledger's recorded
    /// usage alone and no pool is enforcing anything on this run.
    pub budget_pool_seam_active: bool,
}

pub trait EvolutionCostPort: Send + Sync {
    /// Facts about what this run has spent.
    ///
    /// `None` means no reading was available (the ledger could not be read).
    /// Unknown spend is never reported as zero.
    fn query_cost_facts(&self, portable_root: &Path, run_id: &str) -> Option<EvolutionCostFacts>;
}

#[derive(Default)]
pub struct LedgerEvolutionCostPort;

impl LedgerEvolutionCostPort {
    pub fn new() -> Self {
        Self
    }
}

impl EvolutionCostPort for LedgerEvolutionCostPort {
    fn query_cost_facts(&self, portable_root: &Path, run_id: &str) -> Option<EvolutionCostFacts> {
        let report_result = host_ports().usage.workflow_report(&json!({
            "stateRoot": portable_root,
            "runId": run_id,
        }));
        match report_result {
            Ok(report) => {
                let summary = report.get("summary");
                Some(EvolutionCostFacts {
                    prompt_tokens: summary
                        .and_then(|s| s.get("promptTokens"))
                        .and_then(Value::as_u64)
                        .unwrap_or(0),
                    cached_input_tokens: summary
                        .and_then(|s| s.get("cachedInputTokens"))
                        .and_then(Value::as_u64)
                        .unwrap_or(0),
                    completion_tokens: summary
                        .and_then(|s| s.get("completionTokens"))
                        .and_then(Value::as_u64)
                        .unwrap_or(0),
                    total_tokens: summary
                        .and_then(|s| s.get("totalTokens"))
                        .and_then(Value::as_u64)
                        .unwrap_or(0),
                    exact_count: summary
                        .and_then(|s| s.get("exactCount"))
                        .and_then(Value::as_u64)
                        .unwrap_or(0),
                    estimated_count: summary
                        .and_then(|s| s.get("estimatedCount"))
                        .and_then(Value::as_u64)
                        .unwrap_or(0),
                    budget_pool_seam_active: false,
                })
            }
            Err(_) => None,
        }
    }
}

// ----------------------------------------------------------------------------
// Typed context seam
// ----------------------------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceRefSeam {
    pub source_id: String,
    pub revision: String,
    pub validity: String,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextManifestSummarySeam {
    pub source_refs: Vec<SourceRefSeam>,
    pub agreement_revisions: Vec<String>,
    pub token_estimate: Option<u64>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvolutionContextFacts {
    /// The durable host context this run answers to, when it is bound to one.
    pub context_id: Option<String>,
    /// The opaque host binding persisted with the run; the engine reports it
    /// back verbatim and never interprets it.
    pub run_binding: Option<Value>,
    pub state_id: String,
    pub state_visit: u64,
    pub transition_id: String,
    pub causation_id: Option<String>,
    pub answer_channel: String,
    pub context_composition_seam_active: bool,
}

pub trait EvolutionContextPort: Send + Sync {
    fn assemble_context_facts(
        &self,
        snapshot: &RunSnapshot,
        state_id: &str,
        state_visit: u64,
        transition_id: &str,
        answer_channel: &str,
    ) -> EvolutionContextFacts;
}

#[derive(Default)]
pub struct DefaultEvolutionContextPort;

impl DefaultEvolutionContextPort {
    pub fn new() -> Self {
        Self
    }
}

impl EvolutionContextPort for DefaultEvolutionContextPort {
    fn assemble_context_facts(
        &self,
        snapshot: &RunSnapshot,
        state_id: &str,
        state_visit: u64,
        transition_id: &str,
        answer_channel: &str,
    ) -> EvolutionContextFacts {
        EvolutionContextFacts {
            context_id: snapshot.context_id.clone(),
            run_binding: snapshot.run_binding.clone(),
            state_id: state_id.to_owned(),
            state_visit,
            transition_id: transition_id.to_owned(),
            causation_id: Some(snapshot.run_id.clone()),
            answer_channel: answer_channel.to_owned(),
            context_composition_seam_active: true,
        }
    }
}

// ----------------------------------------------------------------------------
// Typed strategy seam & revocable defaults
// ----------------------------------------------------------------------------

#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlanningScopeSeam {
    pub task_kind: String,
    pub configuration: String,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StrategySourceSeam {
    pub source_id: String,
    pub revision: String,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentModelOptionSeam {
    pub agent_id: String,
    pub model_id: String,
    pub thinking: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdoptedPlanningDefaultSeam {
    pub scope: PlanningScopeSeam,
    pub source: StrategySourceSeam,
    pub selected_option: AgentModelOptionSeam,
    pub revocable: bool,
    pub supersedes_revision: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StrategyVersionSeam {
    pub version_id: String,
    pub revision: String,
    pub source: StrategySourceSeam,
    pub scope: PlanningScopeSeam,
    pub revocable: bool,
    pub revoked: bool,
}

/// A strategy suggestion presented to the run's decider.
///
/// **INVARIANT**: strategy versions feed selection without granting execution
/// permission. `has_execution_permission` is ALWAYS `false`: a decider may
/// adopt a recommendation, but effect execution requires the independent
/// pre-effect recheck.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StrategySuggestion {
    pub candidate: AgentModelOptionSeam,
    pub ranking_basis: String,
    pub source: Option<StrategySourceSeam>,
    pub scope: Option<PlanningScopeSeam>,
    pub is_default: bool,
    /// Must remain false: strategy selection grants no execution permission.
    pub has_execution_permission: bool,
    pub rationale: String,
}

pub trait EvolutionStrategyPort: Send + Sync {
    fn suggest_strategy(
        &self,
        scope: &PlanningScopeSeam,
        candidates: &[AgentModelOptionSeam],
        explicit_choice: Option<&AgentModelOptionSeam>,
    ) -> Option<StrategySuggestion>;
}

/// The default strategy seam: an explicit choice wins, an adopted and
/// unrevoked default follows, and with neither the seam answers `None` — the
/// configured list is the preference order, not the answer, so the first
/// entry is never silently promoted. A host that wants policy routing over
/// the candidates supplies its own [`EvolutionStrategyPort`].
pub struct DefaultEvolutionStrategyPort {
    defaults: RwLock<BTreeMap<PlanningScopeSeam, AdoptedPlanningDefaultSeam>>,
    revocations: RwLock<BTreeSet<String>>,
}

impl DefaultEvolutionStrategyPort {
    pub fn new() -> Self {
        Self {
            defaults: RwLock::new(BTreeMap::new()),
            revocations: RwLock::new(BTreeSet::new()),
        }
    }

    /// Adopt a revocable default strategy.
    pub fn adopt_default(&self, default: AdoptedPlanningDefaultSeam) {
        let mut guard = self.defaults.write().unwrap_or_else(|p| p.into_inner());
        guard.insert(default.scope.clone(), default);
    }

    /// Revoke an adopted strategy default.
    pub fn revoke_strategy(&self, source_id: &str) {
        let mut guard = self.revocations.write().unwrap_or_else(|p| p.into_inner());
        guard.insert(source_id.to_owned());
    }
}

impl Default for DefaultEvolutionStrategyPort {
    fn default() -> Self {
        Self::new()
    }
}

impl EvolutionStrategyPort for DefaultEvolutionStrategyPort {
    fn suggest_strategy(
        &self,
        scope: &PlanningScopeSeam,
        candidates: &[AgentModelOptionSeam],
        explicit_choice: Option<&AgentModelOptionSeam>,
    ) -> Option<StrategySuggestion> {
        // An explicit configuration strictly takes precedence.
        if let Some(choice) = explicit_choice
            && candidates.contains(choice)
        {
            return Some(StrategySuggestion {
                candidate: choice.clone(),
                ranking_basis: "explicit-configured".to_owned(),
                source: None,
                scope: Some(scope.clone()),
                is_default: false,
                has_execution_permission: false, // Invariant: no execution permission granted
                rationale: "Explicit selection preserved without implicit upgrade".to_owned(),
            });
        }

        let defaults_guard = self.defaults.read().unwrap_or_else(|p| p.into_inner());
        let revocations_guard = self.revocations.read().unwrap_or_else(|p| p.into_inner());

        if let Some(adopted) = defaults_guard.get(scope) {
            // Check revocation
            if !revocations_guard.contains(&adopted.source.source_id) {
                // Must select only from caller's candidate set
                if candidates.contains(&adopted.selected_option) {
                    return Some(StrategySuggestion {
                        candidate: adopted.selected_option.clone(),
                        ranking_basis: "adopted-default-comparable-outcome".to_owned(),
                        source: Some(adopted.source.clone()),
                        scope: Some(scope.clone()),
                        is_default: true,
                        has_execution_permission: false, // Invariant: no execution permission granted
                        rationale: format!(
                            "Adopted default from source '{}' rev '{}'",
                            adopted.source.source_id, adopted.source.revision
                        ),
                    });
                }
            }
        }

        // No routing owner is composed into this crate: with neither an
        // explicit choice nor an adopted default the seam answers nothing
        // rather than guessing the first configured entry.
        None
    }
}

// ============================================================================
// Pre-Effect Recheck: Permission, Version, Resource
// ============================================================================

/// Context evaluated immediately prior to executing any effect.
pub struct EffectRecheckContext<'a> {
    pub run_id: &'a str,
    pub command_id: &'a str,
    pub definition_revision: &'a str,
    pub expected_revision: &'a str,
    pub expected_generation: u64,
    pub current_generation: u64,
    pub authorization: Option<&'a StrategyAuthorization>,
    pub claimant: &'a str,
    /// Session this effect will write through, when the executor holds a
    /// single-writer registration. `None` means the executor has no session lock
    /// to recheck, not that the lock check passed.
    pub session_id: Option<&'a str>,
    pub single_writer_registry: Option<&'a SingleWriterSessionRegistry>,
    /// Tokens this effect is about to spend against a configured pool, and what
    /// is left of it. `None` means no pool fact is available to compare.
    pub required_tokens: Option<u64>,
    pub token_budget_remaining: Option<u64>,
}

impl<'a> EffectRecheckContext<'a> {
    /// Build the pre-effect recheck context for one command the executor claimed.
    ///
    /// The generation check compares two independently sourced facts: the visit
    /// the command was minted for (`RunCommand::state_visit`) against the visit
    /// the run is at now (`RunSnapshot::state_visits`). A command whose state was
    /// re-entered, or that was claimed for a state the run has since advanced
    /// past, must not reach the executor with stale semantics.
    ///
    /// The revision check asserts the run is still bound to the definition it
    /// was loaded from. That binding is structural here (the definition is read
    /// by `snapshot.definition_digest`), so the check is an invariant assertion
    /// rather than a second read of mutable state.
    ///
    /// Session-lock and token-budget facts stay `None` until the executor holds
    /// them; callers holding those facts set the fields directly.
    pub fn for_run_command(
        run_id: &'a str,
        snapshot: &'a RunSnapshot,
        definition: &'a StrategyDefinition,
        command: &'a RunCommand,
        claimant: &'a str,
    ) -> Self {
        Self {
            run_id,
            command_id: &command.id,
            definition_revision: &snapshot.definition_digest,
            expected_revision: &definition.summary.revision_digest,
            expected_generation: command.state_visit,
            current_generation: snapshot
                .state_visits
                .get(&command.state_id)
                .copied()
                .unwrap_or(0),
            authorization: definition.authorization.as_ref(),
            claimant,
            session_id: None,
            single_writer_registry: None,
            required_tokens: None,
            token_budget_remaining: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EffectRecheckReceipt {
    pub run_id: String,
    pub command_id: String,
    pub rechecked_at_unix_ms: i64,
    pub revision_digest: String,
    pub generation: u64,
    pub permission_verified: bool,
    pub version_verified: bool,
    pub resource_verified: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EffectRecheckFailure {
    PermissionDenied { code: String, reason: String },
    VersionMismatch { expected: String, actual: String },
    StaleGeneration { expected: u64, current: u64 },
    ResourceUnavailable { code: String, reason: String },
}

impl EffectRecheckFailure {
    pub fn code(&self) -> &'static str {
        match self {
            Self::PermissionDenied { .. } => "authorization_required",
            Self::VersionMismatch { .. } => "strategy_recheck_version_mismatch",
            Self::StaleGeneration { .. } => "strategy_recheck_stale_generation",
            Self::ResourceUnavailable { code, .. } => {
                if code == "session_writer_conflict" {
                    "strategy_recheck_session_writer_conflict"
                } else if code == "token_budget_exhausted" {
                    "strategy_recheck_token_budget_exhausted"
                } else {
                    "strategy_recheck_resource_unavailable"
                }
            }
        }
    }
}

impl std::fmt::Display for EffectRecheckFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PermissionDenied { reason, .. } => write!(f, "Permission denied: {reason}"),
            Self::VersionMismatch { expected, actual } => {
                write!(f, "Version mismatch: expected {expected}, actual {actual}")
            }
            Self::StaleGeneration { expected, current } => {
                write!(
                    f,
                    "Stale generation: expected {expected}, current {current}"
                )
            }
            Self::ResourceUnavailable { code, reason } => {
                write!(f, "Resource unavailable ({code}): {reason}")
            }
        }
    }
}

impl std::error::Error for EffectRecheckFailure {}

/// Recheck permission, version, and resources before executing any effect.
///
/// Returns [`Ok(EffectRecheckReceipt)`] if all checks pass, or [`Err(EffectRecheckFailure)`]
/// stopping execution before any real effect occurs.
pub fn recheck_before_effect(
    ctx: &EffectRecheckContext<'_>,
) -> std::result::Result<EffectRecheckReceipt, EffectRecheckFailure> {
    // 1. Permission Recheck: authorization must be present and active
    let Some(auth) = ctx.authorization else {
        return Err(EffectRecheckFailure::PermissionDenied {
            code: "authorization_missing".into(),
            reason: "No authorization configured on definition".into(),
        });
    };
    if !auth.active {
        return Err(EffectRecheckFailure::PermissionDenied {
            code: "authorization_inactive".into(),
            reason: "Strategy authorization is marked inactive or has been revoked".into(),
        });
    }

    // 2. Version Recheck: expected definition revision and node generation must match
    if ctx.definition_revision != ctx.expected_revision {
        return Err(EffectRecheckFailure::VersionMismatch {
            expected: ctx.expected_revision.to_owned(),
            actual: ctx.definition_revision.to_owned(),
        });
    }
    if ctx.expected_generation != ctx.current_generation {
        return Err(EffectRecheckFailure::StaleGeneration {
            expected: ctx.expected_generation,
            current: ctx.current_generation,
        });
    }

    // 3. Resource Recheck: check single-writer lock and token budget limits
    if let (Some(registry), Some(session)) = (ctx.single_writer_registry, ctx.session_id)
        && let Some(active_writer) = registry.current_writer(session)
        && active_writer != ctx.claimant
    {
        return Err(EffectRecheckFailure::ResourceUnavailable {
            code: "session_writer_conflict".into(),
            reason: format!(
                "Session '{}' is currently locked by claimant '{}'",
                session, active_writer
            ),
        });
    }

    if let (Some(req), Some(remaining)) = (ctx.required_tokens, ctx.token_budget_remaining)
        && req > remaining
    {
        return Err(EffectRecheckFailure::ResourceUnavailable {
            code: "token_budget_exhausted".into(),
            reason: format!("Required tokens ({req}) exceed remaining budget ({remaining})"),
        });
    }

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);

    Ok(EffectRecheckReceipt {
        run_id: ctx.run_id.to_owned(),
        command_id: ctx.command_id.to_owned(),
        rechecked_at_unix_ms: now_ms,
        revision_digest: ctx.definition_revision.to_owned(),
        generation: ctx.current_generation,
        permission_verified: true,
        version_verified: true,
        resource_verified: true,
    })
}
