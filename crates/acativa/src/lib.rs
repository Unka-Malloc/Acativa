//! Acativa — the generic multi-agent collaboration engine.
//!
//! Acativa compiles a collaboration strategy once into an immutable plan,
//! persists run state and dispatch intent in a durable store, and executes
//! effects through host-owned adapters and ports. It is host-agnostic: it
//! carries no product schema, package format or host-vocabulary dependency.
//! A host binds its own schema identity, persisted vocabulary and
//! effect implementations at every admission boundary.
//!
//! ```text
//!   host            ──►  acativa::runtime  ──►  acativa::store  ──►  acativa::workflow
//!   (composes ports)     (executes effects)     (persists state)     (pure machine)
//! ```

pub mod runtime;
pub mod store;
pub mod util;
pub mod workflow;

// ---------------------------------------------------------------------------
// Crate parameters
// ---------------------------------------------------------------------------

/// A schema identity the host binds to the engine.
///
/// The engine validates nothing against a schema it does not know; every
/// compile and every store projection names the schema the caller compiles and
/// projects under. Newtyped so a schema id cannot be confused with a digest, a
/// table name or arbitrary text.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SchemaId(String);

impl SchemaId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for SchemaId {
    fn from(id: &str) -> Self {
        Self::new(id)
    }
}

impl From<String> for SchemaId {
    fn from(id: String) -> Self {
        Self::new(id)
    }
}

impl AsRef<str> for SchemaId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl std::fmt::Display for SchemaId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// The workflow schema Acativa's own fixtures and conformance suite compile
/// under. It is the engine's generic test dialect: a product host binds its
/// own schema identity at the same parameter.
pub const GENERIC_WORKFLOW_SCHEMA: &str = "acativa.workflow.v1";

/// The projection schema Acativa's own fixtures project under.
pub const GENERIC_PROJECTION_SCHEMA: &str = "acativa.strategy-state.v1";

// ---------------------------------------------------------------------------
// Flat re-exports of the generic public machinery
// ---------------------------------------------------------------------------

// Module paths stay resolvable as `crate::<module>` for all public machinery.
pub use runtime::{adapter, driver, evolution, node, ports, service};
pub use store::{control, routing, usage_ledger};
pub use workflow::{analysis, compile, diagnostic, dispatch, machine, syntax};

pub use workflow::analysis::{
    AnalyzedWorkflow, WorkflowValidation, WorkflowValidationFailure, analyze,
    compile_workflow_source, compile_workflow_value, validate_workflow_value,
};
pub use workflow::compile::{
    ACATIVA_PLAN_IDENTITY, CompiledWorkflow, CompilerSemantics, DefinitionRevision,
    EngineSemantics, HandoffReason, InterpreterProfile, LoweringCapabilities, LoweringRefusal,
    PlanIdentity, PlanInputError, PlanKey, PlanMismatch, RecordedPlanKey, RetainedPlan,
    RunAdmission,
};
pub use workflow::diagnostic::{
    PreflightDiagnostic, WorkflowDiagnosticActualKind, WorkflowDiagnosticCode,
    WorkflowDiagnosticExpected, WorkflowDiagnosticRecovery, WorkflowDiagnosticStage,
};
pub use workflow::dispatch::{
    ClaimLease, ClaimVerdict, CompletionVerdict, DispatchDecision, DispatchGate, DispatchIntent,
    DispatchRecipient, DispatchRefusal, EffectCompletion, EffectProgress, RecoveryVerdict,
    SuccessorAdmission, SuccessorEdge, SuccessorGate, SuccessorRefusal, claim_effect,
    recover_claim, settle_effect,
};
pub use workflow::ir::*;
pub use workflow::machine::{
    CommandKind, CommandStatus, ReducerDelta, ReducerEvent, ReducerOutput, RunCommand, RunSnapshot,
    effect_input_for, fallback_reason, reduce,
};
pub use workflow::strategy::{
    BindingCandidate, BindingValue, StrategyAuthorization, StrategyDefinition,
    StrategyDefinitionSummary, StrategyDiagnostic, StrategyProjection,
};
pub use workflow::syntax::{ParsedWorkflow, parse};

pub const MAX_ACTIVE_EFFECTS: usize = 8;
pub const MAX_GRAPH_STATES: usize = 512;
pub const MAX_GRAPH_TRANSITIONS: usize = 2_048;
pub const MAX_BINDING_SLOTS: usize = 64;
pub const MAX_RUNTIME_REQUIREMENTS: usize = 16;
pub const MAX_WORKSET_ITEMS: usize = 256;
pub const MAX_RETRY_ATTEMPTS: u8 = 8;

/// Compile a canonical in-memory definition through the same analysis path as
/// source and value entry points, under the schema identity the host binds.
pub fn compile_workflow(
    definition: WorkflowDefinition,
    supported_schema: &SchemaId,
) -> Result<CompiledWorkflow, WorkflowValidationFailure> {
    workflow::analysis::compile_workflow_definition(definition, supported_schema)
}
