//! Event-driven collaboration execution: adapters, node execution, the
//! continuous driver, host ports, evolution seams and drive bookkeeping.
//!
//! Nothing here reaches back into the host. Everything the runtime needs from
//! above arrives through [`ports`]: the host installs its answers once at its
//! crate root, and a process that installs none runs fail-closed.
//!
//! Runtime leaves are intentionally separate from the durable store: adapters
//! may perform external work, while store transactions only persist state,
//! commands, and post-commit intent.

pub mod adapter;
pub mod driver;
pub mod evolution;
pub mod node;
pub mod ports;
pub mod service;

pub use adapter::{
    AdapterError, AdapterExecutionStatus, CancelOutcome, CooperativeDrainAdapter,
    NodeCapabilityAdapter, NodeInvocation, PauseOutcome, ResumeOutcome,
    SingleWriterSessionRegistry, SteerOutcome, SyntheticCapabilityAdapter,
};
pub use driver::{
    ContinuousNodeDriver, DispatchedEffectReport, DriverError, DriverStepOutcome, GraphPauseReport,
    GraphStopReport, PerNodePauseOutcome, PerNodeStopOutcome, ResultReentry,
};
pub use evolution::{
    AdoptedPlanningDefaultSeam, AgentModelOptionSeam, BudgetPoolReservationSeam,
    ContextManifestSummarySeam, DefaultEvolutionContextPort, DefaultEvolutionObservationPort,
    DefaultEvolutionStrategyPort, EffectRecheckContext, EffectRecheckFailure, EffectRecheckReceipt,
    EvolutionContextFacts, EvolutionContextPort, EvolutionCostFacts, EvolutionCostPort,
    EvolutionObservationPort, EvolutionStrategyPort, LedgerEvolutionCostPort,
    NodeObservationSummary, ObservationFactKindSeam, ObservationFactRecordSeam,
    ObservationScopeSeam, PlanningScopeSeam, SourceRefSeam, StrategySourceSeam, StrategySuggestion,
    StrategyVersionSeam, recheck_before_effect,
};
pub use node::{
    CancellationFacts, InvocationRecord, NodeExecutionError, NodeExecutionOutcome,
    NodeExecutionReceipt, NodeFacade, NodeObservation, PauseResult, ResumeResult, SteerResult,
    StopResult,
};
pub use ports::{
    ActorTurnError, EffectPort, HostPorts, ModelFactsPort, ResolvedRuntime, StrategyEffectPermit,
    UsageLedgerPort, host_ports, install_host_ports,
};
pub use service::{
    ActorTurnPort, DriveReservation, EntryTurnRegistration, LiveTurnOwner, LiveTurnRegistration,
    RunWakePort, TurnCancelDisposition, cancellation_pending, live_turn_owner, mark_run_cancelled,
    unmark_run_cancelled,
};
