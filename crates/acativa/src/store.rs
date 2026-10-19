//! Durable collaboration-run state, command, queue, subscription, and commit
//! contracts.
//!
//! The store is the independent durable owner of the strategy database. It
//! sits below the runtime and the host:
//!
//! ```text
//!   host      ──►  acativa::runtime  ──►  acativa::store  ──►  acativa::workflow
//!   (composes)     (executes)            (persists)            (pure machine)
//! ```
//!
//! Routing, subscription, and admission control are the store's own durable
//! contracts. Runtime code owns adapters and execution; this module owns the
//! short SQLite transactions that make accepted state and delivery intent
//! recoverable across a process restart. Every product-bound fact — schema
//! identity, database layout, ephemeral definition prefixes — arrives through
//! [`store::StoreDialect`], not through a constant of this crate.

mod admission;
mod commit;
#[cfg(test)]
mod conformance;
pub mod control;
mod controlled;
#[cfg(test)]
mod dispatch_composition;
mod queue;
pub mod routing;
#[allow(clippy::module_inception)]
mod store;
mod subscriptions;

pub use admission::{
    MAX_UNFINISHED_WORKFLOW_WORK, UnfinishedWorkflowWork, WorkflowWorkBlocker, WorkflowWorkKind,
    read_unfinished_local_work,
};
pub use commit::{CommittedTransition, TransitionDecorator, TransitionIntent, TransitionObserver};
pub use control::{ControlOperation, ControlScope, ControlledStore};
pub use controlled::DurableControlledStore;
pub use queue::{DurableQueue, DurableQueueLease, DurableQueueStats, QueueReplay, QueueStoreError};
pub use store::validate_published_core_layout;
pub use store::{StoreDialect, StrategyStore};
pub use subscriptions::DurableSubscriptionStore;

/// Definition, binding, projection, and error vocabulary the store and the
/// runtime both name. It is defined by the pure machine module so neither of
/// them has to own the other's identity.
pub use crate::workflow::strategy::{
    BindingCandidate, BindingValue, StrategyAuthorization, StrategyDefinition,
    StrategyDefinitionSummary, StrategyDiagnostic, StrategyProjection,
};
