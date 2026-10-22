//! Continuous node driver with graceful lifecycle and source-identity result re-entry.
//!
//! Coordinates queue items, proxy receipts, node facades, feature indexes, and subscriptions.
//! Ensures independent node concurrency (A->C executes while independent B runs).
//! Collects per-node outcomes for graph pause/stop.
//! Re-enters execution results with source identity and pre-effect validity checks.

use crate::adapter::AdapterExecutionStatus;
use crate::control::ControlOperation;
use crate::node::{
    CancellationFacts, NodeExecutionError, NodeExecutionOutcome, NodeExecutionReceipt, NodeFacade,
    PauseResult, SteerResult, StopResult,
};
use crate::routing::{
    ActivationRule, FairDispatchQueue, FrozenTargets, NodeFeatureIndex, NodeLifecycleState,
    RecipientEffectStatus, SubscriptionPredicate, SubscriptionRegistry, SubscriptionScope,
};
#[cfg(test)]
use crate::routing::{ChannelKind, QueueCapacityExceeded};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};

/// Admitted message payload carried inside `QueuedItem.content`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdmittedMessagePayload {
    pub source_principal_id: String,
    pub graph_id: String,
    pub operation: ControlOperation,
    pub targets: FrozenTargets,
}

/// Result re-entry with source identity.
///
/// When an execution completes or fails, results re-enter through source identity
/// (principal, graph_id, node_id, invocation_id, generation, durable_cursor).
/// Stale generations are rejected and cannot satisfy new dependencies.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResultReentry {
    pub source_principal_id: String,
    pub graph_id: String,
    pub node_id: String,
    pub invocation_id: String,
    pub generation: u64,
    pub cursor: u64,
    pub attempt_token: String,
    pub outcome: NodeExecutionOutcome,
}

/// Report for an individual recipient's effect dispatch.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DispatchedEffectReport {
    pub delivery_id: String,
    pub recipient_node_id: String,
    pub status: RecipientEffectStatus,
    pub operation: String,
    pub invocation_id: Option<String>,
}

/// Per-node outcome when pausing a graph.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PerNodePauseOutcome {
    pub node_id: String,
    pub state_before: NodeLifecycleState,
    pub state_after: NodeLifecycleState,
    pub result: Result<PauseResult, String>,
}

/// Graph-wide pause report collecting individual node outcomes truthfully.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphPauseReport {
    pub graph_id: String,
    pub node_outcomes: Vec<PerNodePauseOutcome>,
    pub scope_barrier_established: bool,
}

/// Per-node outcome when stopping a graph.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PerNodeStopOutcome {
    pub node_id: String,
    pub state_before: NodeLifecycleState,
    pub state_after: NodeLifecycleState,
    pub cancellation_facts: Option<CancellationFacts>,
    pub result: Result<StopResult, String>,
}

/// Graph-wide stop report collecting individual node outcomes truthfully.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphStopReport {
    pub graph_id: String,
    pub node_outcomes: Vec<PerNodeStopOutcome>,
    pub scope_barrier_established: bool,
}

/// Outcome of one step of the continuous driver.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DriverStepOutcome {
    pub items_dispatched: usize,
    pub effects_attempted: usize,
    pub effects_succeeded: usize,
    pub stale_recipients_skipped: usize,
    pub completions_settled: usize,
    pub reports: Vec<DispatchedEffectReport>,
}

/// Errors originating in continuous driver operations.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DriverError {
    GraphMismatch {
        expected: String,
        received: String,
    },
    NodeNotFound(String),
    StaleGenerationResult {
        node_id: String,
        expected: u64,
        received: u64,
    },
    ResultSourceMismatch {
        node_id: String,
        expected: String,
        received: String,
    },
    InvocationMismatch {
        node_id: String,
        expected: String,
        received: String,
    },
    AttemptTokenMismatch {
        node_id: String,
        expected: String,
        received: String,
    },
    StaleResultCursor {
        node_id: String,
        current: u64,
        received: u64,
    },
    ScopeAdmissionBarrierActive,
    NodeExecution(NodeExecutionError),
}

impl Display for DriverError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GraphMismatch { expected, received } => {
                write!(
                    f,
                    "Graph mismatch: expected {expected}, received {received}"
                )
            }
            Self::NodeNotFound(id) => write!(f, "Node {id} not found in driver"),
            Self::StaleGenerationResult {
                node_id,
                expected,
                received,
            } => write!(
                f,
                "Stale generation result for node {node_id}: expected gen {expected}, got gen {received}"
            ),
            Self::ResultSourceMismatch {
                node_id,
                expected,
                received,
            } => write!(
                f,
                "Unverified result source for node {node_id}: expected {expected}, got {received}"
            ),
            Self::InvocationMismatch {
                node_id,
                expected,
                received,
            } => write!(
                f,
                "Invocation mismatch for node {node_id}: expected {expected}, got {received}"
            ),
            Self::AttemptTokenMismatch {
                node_id,
                expected,
                received,
            } => write!(
                f,
                "Attempt token mismatch for node {node_id}: expected {expected}, got {received}"
            ),
            Self::StaleResultCursor {
                node_id,
                current,
                received,
            } => write!(
                f,
                "Stale result cursor for node {node_id}: current {current}, got {received}"
            ),
            Self::ScopeAdmissionBarrierActive => {
                write!(f, "Scope admission barrier active; new work rejected")
            }
            Self::NodeExecution(err) => write!(f, "Node execution error: {err}"),
        }
    }
}

impl std::error::Error for DriverError {}

impl From<NodeExecutionError> for DriverError {
    fn from(err: NodeExecutionError) -> Self {
        Self::NodeExecution(err)
    }
}

/// Continuous driver orchestrating node facades, feature indexing, queues, and result re-entry.
pub struct ContinuousNodeDriver {
    pub graph_id: String,
    pub nodes: BTreeMap<String, NodeFacade>,
    pub index: NodeFeatureIndex,
    /// The dispatch queue is private: admitted work enters only through
    /// `InterventionProxy` — handing the queue to callers would hand them a
    /// path around the admission boundary.
    queue: FairDispatchQueue,
    pub subscriptions: SubscriptionRegistry,
    pub active_invocations: BTreeMap<String, String>, // invocation_id -> node_id
    pub scope_barrier_active: bool,
    pub durable_cursor: u64,
}

impl ContinuousNodeDriver {
    pub fn new(
        graph_id: impl Into<String>,
        queue: FairDispatchQueue,
        subscriptions: SubscriptionRegistry,
    ) -> Self {
        Self {
            graph_id: graph_id.into(),
            nodes: BTreeMap::new(),
            index: NodeFeatureIndex::new(),
            queue,
            subscriptions,
            active_invocations: BTreeMap::new(),
            scope_barrier_active: false,
            durable_cursor: 0,
        }
    }

    /// Register a new node facade into the driver and feature index.
    pub fn register_node(&mut self, facade: NodeFacade) {
        let meta = facade.metadata();
        let node_id = facade.node_id.clone();
        self.nodes.insert(node_id, facade);
        self.index.register_or_update(meta);
    }

    /// Access a node facade by ID.
    pub fn get_node(&self, node_id: &str) -> Option<&NodeFacade> {
        self.nodes.get(node_id)
    }

    /// Mutably access a node facade by ID.
    pub fn get_node_mut(&mut self, node_id: &str) -> Option<&mut NodeFacade> {
        self.nodes.get_mut(node_id)
    }

    /// Test-only helper to enqueue an admitted message payload.
    ///
    /// Admission flows through `InterventionProxy`, the only boundary that
    /// verifies the principal; this helper is test plumbing, not a host API.
    #[cfg(test)]
    fn enqueue_admitted(
        &mut self,
        channel: ChannelKind,
        item_id: impl Into<String>,
        payload: AdmittedMessagePayload,
        timestamp_unix_ms: i64,
    ) -> Result<u64, QueueCapacityExceeded> {
        let content = serde_json::to_value(&payload).unwrap_or_default();
        self.queue
            .enqueue(channel, item_id, content, timestamp_unix_ms)
    }

    /// Remove driver entries whose facade has already settled the invocation.
    /// A direct stop/cancel may settle a node before the next driver poll; the
    /// index must not turn that settled observation into a second re-entry.
    fn prune_settled_invocations(&mut self) {
        let stale_ids: Vec<String> = self
            .active_invocations
            .iter()
            .filter_map(|(invocation_id, node_id)| {
                let active_id = self
                    .nodes
                    .get(node_id)
                    .and_then(|facade| facade.active_invocation.as_ref())
                    .map(|invocation| invocation.invocation_id.as_str());
                (active_id != Some(invocation_id.as_str())).then(|| invocation_id.clone())
            })
            .collect();

        for invocation_id in stale_ids {
            self.active_invocations.remove(&invocation_id);
        }
    }

    /// Refresh the live metadata used by pre-effect validation for the
    /// recipients in one admitted publication. This keeps the feature index
    /// authoritative even when a caller has just observed or controlled a
    /// facade through the narrow mutable access port.
    fn refresh_recipient_index(&mut self, targets: &FrozenTargets) {
        let metadata: Vec<(String, Option<_>)> = targets
            .recipients
            .iter()
            .map(|recipient| {
                (
                    recipient.node_id.clone(),
                    self.nodes.get(&recipient.node_id).map(NodeFacade::metadata),
                )
            })
            .collect();

        for (node_id, metadata) in metadata {
            if let Some(metadata) = metadata {
                self.index.register_or_update(metadata);
            } else {
                self.index.remove(&node_id);
            }
        }
    }

    /// Turn one terminal adapter observation into a source-authenticated
    /// result re-entry. The active invocation and attempt token are copied
    /// from the live facade, never from an untrusted observation.
    fn result_reentry_from_status(
        &self,
        invocation_id: &str,
        node_id: &str,
        cursor: u64,
        status: AdapterExecutionStatus,
    ) -> Option<ResultReentry> {
        let facade = self.nodes.get(node_id)?;
        let active = facade.active_invocation.as_ref()?;
        if active.invocation_id != invocation_id {
            return None;
        }

        let outcome = match status {
            AdapterExecutionStatus::Completed { output } => {
                NodeExecutionOutcome::Success { output }
            }
            AdapterExecutionStatus::Failed { error, retryable } => {
                NodeExecutionOutcome::Failure { error, retryable }
            }
            AdapterExecutionStatus::Cancelled { acknowledged } => {
                NodeExecutionOutcome::Cancelled { acknowledged }
            }
            AdapterExecutionStatus::Running | AdapterExecutionStatus::Suspended => return None,
        };

        Some(ResultReentry {
            source_principal_id: facade.adapter.adapter_identity().to_string(),
            graph_id: self.graph_id.clone(),
            node_id: node_id.to_string(),
            invocation_id: invocation_id.to_string(),
            generation: facade.generation,
            cursor,
            attempt_token: active.attempt_token.clone(),
            outcome,
        })
    }

    /// Perform a single drive step:
    /// 1. Pull next queue item.
    /// 2. Validate live recipient states and generations.
    /// 3. Dispatch to node facades.
    /// 4. Poll and re-enter settled invocations.
    pub fn drive_step(&mut self) -> Result<DriverStepOutcome, DriverError> {
        let mut outcome = DriverStepOutcome::default();
        self.prune_settled_invocations();

        // 1. Process one queued item if available
        if let Some(item) = self.queue.dequeue() {
            outcome.items_dispatched += 1;
            self.durable_cursor = self.durable_cursor.max(item.cursor);

            if let Ok(payload) = serde_json::from_value::<AdmittedMessagePayload>(item.content) {
                if payload.graph_id != self.graph_id {
                    return Err(DriverError::GraphMismatch {
                        expected: self.graph_id.clone(),
                        received: payload.graph_id,
                    });
                }
                if self.scope_barrier_active
                    && matches!(&payload.operation, ControlOperation::SubmitTask { .. })
                {
                    return Err(DriverError::ScopeAdmissionBarrierActive);
                }

                self.refresh_recipient_index(&payload.targets);
                let validations = payload.targets.validate_before_effect(&self.index);
                let op_str = format!("{:?}", payload.operation);

                for (recipient, status) in validations {
                    outcome.effects_attempted += 1;
                    match status {
                        RecipientEffectStatus::Valid => {
                            let mut inv_id = None;

                            if let Some(facade) = self.nodes.get_mut(&recipient.node_id) {
                                match &payload.operation {
                                    ControlOperation::SubmitTask { input } => {
                                        if let Ok(inv) = facade.submit(input.clone(), item.cursor) {
                                            inv_id = Some(inv.invocation_id.clone());
                                            self.active_invocations.insert(
                                                inv.invocation_id.clone(),
                                                recipient.node_id.clone(),
                                            );
                                            outcome.effects_succeeded += 1;
                                        }
                                    }
                                    ControlOperation::Steer {
                                        invocation_id,
                                        instruction,
                                        follow_up,
                                    } => {
                                        match facade.steer(
                                            invocation_id.as_str(),
                                            instruction.as_str(),
                                            *follow_up,
                                        ) {
                                            Ok(
                                                SteerResult::AppliedInFlight
                                                | SteerResult::FollowUpQueued { .. },
                                            ) => {
                                                outcome.effects_succeeded += 1;
                                            }
                                            Ok(SteerResult::Unsupported) | Err(_) => {}
                                        }
                                    }
                                    ControlOperation::Pause { .. } => match facade.pause() {
                                        Ok(PauseResult::Unsupported) | Err(_) => {}
                                        Ok(_) => outcome.effects_succeeded += 1,
                                    },
                                    ControlOperation::Resume { .. } if facade.resume().is_ok() => {
                                        outcome.effects_succeeded += 1;
                                    }
                                    ControlOperation::Stop { reason, .. }
                                        if facade.stop(reason.as_str()).is_ok() =>
                                    {
                                        outcome.effects_succeeded += 1;
                                    }
                                    _ => {
                                        // Other control operations handled at graph level
                                    }
                                }

                                // Update feature index with updated metadata
                                let meta = facade.metadata();
                                self.index.register_or_update(meta);
                            }

                            outcome.reports.push(DispatchedEffectReport {
                                delivery_id: recipient.delivery_id,
                                recipient_node_id: recipient.node_id,
                                status: RecipientEffectStatus::Valid,
                                operation: op_str.clone(),
                                invocation_id: inv_id,
                            });
                        }
                        RecipientEffectStatus::StateChanged { expected, current } => {
                            outcome.stale_recipients_skipped += 1;
                            outcome.reports.push(DispatchedEffectReport {
                                delivery_id: recipient.delivery_id,
                                recipient_node_id: recipient.node_id,
                                status: RecipientEffectStatus::StateChanged { expected, current },
                                operation: op_str.clone(),
                                invocation_id: None,
                            });
                        }
                        RecipientEffectStatus::GenerationStale { expected, current } => {
                            outcome.stale_recipients_skipped += 1;
                            outcome.reports.push(DispatchedEffectReport {
                                delivery_id: recipient.delivery_id,
                                recipient_node_id: recipient.node_id,
                                status: RecipientEffectStatus::GenerationStale {
                                    expected,
                                    current,
                                },
                                operation: op_str.clone(),
                                invocation_id: None,
                            });
                        }
                        RecipientEffectStatus::NodeMissing => {
                            outcome.stale_recipients_skipped += 1;
                            outcome.reports.push(DispatchedEffectReport {
                                delivery_id: recipient.delivery_id,
                                recipient_node_id: recipient.node_id,
                                status: RecipientEffectStatus::NodeMissing,
                                operation: op_str.clone(),
                                invocation_id: None,
                            });
                        }
                    }
                }
            }
        }

        // 2. Poll active invocations for backend completions
        let mut settled_reentries = Vec::new();
        let mut next_result_cursor = self.durable_cursor;
        for (inv_id, node_id) in &self.active_invocations {
            if let Some(facade) = self.nodes.get(node_id) {
                next_result_cursor = next_result_cursor.max(facade.durable_cursor);
                let active_matches = facade
                    .active_invocation
                    .as_ref()
                    .is_some_and(|invocation| invocation.invocation_id.as_str() == inv_id.as_str());
                if active_matches
                    && let Ok(status) = facade.adapter.poll_status(inv_id)
                    && matches!(
                        &status,
                        AdapterExecutionStatus::Completed { .. }
                            | AdapterExecutionStatus::Failed { .. }
                            | AdapterExecutionStatus::Cancelled { .. }
                    )
                {
                    next_result_cursor = next_result_cursor.saturating_add(1);
                    if let Some(reentry) =
                        self.result_reentry_from_status(inv_id, node_id, next_result_cursor, status)
                    {
                        settled_reentries.push(reentry);
                    }
                }
            }
        }

        for reentry in settled_reentries {
            self.reenter_result(reentry)?;
            outcome.completions_settled += 1;
        }

        Ok(outcome)
    }

    /// Re-enter an execution result carrying full source identity.
    /// Stale generations are rejected and cannot satisfy new dependencies.
    pub fn reenter_result(
        &mut self,
        reentry: ResultReentry,
    ) -> Result<NodeExecutionReceipt, DriverError> {
        if reentry.graph_id != self.graph_id {
            return Err(DriverError::GraphMismatch {
                expected: self.graph_id.clone(),
                received: reentry.graph_id,
            });
        }

        let facade = self
            .nodes
            .get(&reentry.node_id)
            .ok_or_else(|| DriverError::NodeNotFound(reentry.node_id.clone()))?;

        // The adapter identity is the authenticated result port for this
        // facade. A serialized source label alone cannot authorize re-entry.
        let expected_source = facade.adapter.adapter_identity().to_string();
        if expected_source != reentry.source_principal_id {
            return Err(DriverError::ResultSourceMismatch {
                node_id: reentry.node_id.clone(),
                expected: expected_source,
                received: reentry.source_principal_id,
            });
        }

        // Verify generation matches live node generation.
        if facade.generation != reentry.generation {
            return Err(DriverError::StaleGenerationResult {
                node_id: reentry.node_id.clone(),
                expected: facade.generation,
                received: reentry.generation,
            });
        }

        let active = facade.active_invocation.as_ref().ok_or_else(|| {
            DriverError::NodeExecution(
                if facade
                    .invocation_history
                    .iter()
                    .any(|record| record.invocation_id == reentry.invocation_id)
                {
                    NodeExecutionError::InvocationSettled(reentry.invocation_id.clone())
                } else {
                    NodeExecutionError::InvocationNotFound(reentry.invocation_id.clone())
                },
            )
        })?;

        if active.invocation_id != reentry.invocation_id {
            return Err(DriverError::InvocationMismatch {
                node_id: reentry.node_id.clone(),
                expected: active.invocation_id.clone(),
                received: reentry.invocation_id,
            });
        }
        if active.attempt_token != reentry.attempt_token {
            return Err(DriverError::AttemptTokenMismatch {
                node_id: reentry.node_id.clone(),
                expected: active.attempt_token.clone(),
                received: reentry.attempt_token,
            });
        }
        if reentry.cursor < facade.durable_cursor {
            return Err(DriverError::StaleResultCursor {
                node_id: reentry.node_id.clone(),
                current: facade.durable_cursor,
                received: reentry.cursor,
            });
        }

        let facade = self
            .nodes
            .get_mut(&reentry.node_id)
            .ok_or_else(|| DriverError::NodeNotFound(reentry.node_id.clone()))?;

        // Settle invocation completion on facade
        let receipt =
            facade.settle_invocation_completion(reentry.outcome.clone(), reentry.cursor)?;
        self.active_invocations.remove(&reentry.invocation_id);
        self.durable_cursor = self.durable_cursor.max(reentry.cursor);

        // Update index with new lifecycle state
        let meta = facade.metadata();
        self.index.register_or_update(meta);

        // Match subscriptions against this transition / event
        let scope = SubscriptionScope::Node {
            graph_id: self.graph_id.clone(),
            node_id: reentry.node_id.clone(),
        };
        let matched = self.subscriptions.match_event(
            &scope,
            &SubscriptionPredicate::OnLifecycleState(receipt.resulting_state),
            Some(receipt.resulting_state),
        );

        for sub in matched {
            match sub.activation_rule {
                ActivationRule::AutoResume => {
                    // Authorized auto-resume rule resumes paused node
                    if !self.scope_barrier_active
                        && let Some(facade) = self.nodes.get_mut(&reentry.node_id)
                        && facade.lifecycle_state == NodeLifecycleState::Paused
                    {
                        let _ = facade.resume();
                        let updated_meta = facade.metadata();
                        self.index.register_or_update(updated_meta);
                    }
                }
                ActivationRule::NotifyOnly => {}
                ActivationRule::TriggerTransition { .. } => {}
            }
        }

        Ok(receipt)
    }

    /// Graceful graph pause: establishes scope admission barrier and requests pause on all active nodes.
    /// Collects per-node outcomes without fabricating success for unavailable backends.
    pub fn pause_graph(&mut self) -> Result<GraphPauseReport, DriverError> {
        self.scope_barrier_active = true;
        let mut outcomes = Vec::new();

        for (node_id, facade) in &mut self.nodes {
            if facade.lifecycle_state.is_active() {
                let before = facade.lifecycle_state;
                let res = facade.pause().map_err(|e| e.to_string());
                let after = facade.lifecycle_state;
                outcomes.push(PerNodePauseOutcome {
                    node_id: node_id.clone(),
                    state_before: before,
                    state_after: after,
                    result: res,
                });
            }
        }

        // Update all metadata in index
        for facade in self.nodes.values() {
            self.index.register_or_update(facade.metadata());
        }

        Ok(GraphPauseReport {
            graph_id: self.graph_id.clone(),
            node_outcomes: outcomes,
            scope_barrier_established: true,
        })
    }

    /// Graceful graph stop: establishes scope admission barrier and cooperatively cancels all active nodes.
    /// Collects per-node outcomes and preserves requested, acknowledged, and effect-unknown facts.
    pub fn stop_graph(&mut self, reason: &str) -> Result<GraphStopReport, DriverError> {
        self.scope_barrier_active = true;
        let mut outcomes = Vec::new();

        for (node_id, facade) in &mut self.nodes {
            if facade.lifecycle_state.is_active() {
                let before = facade.lifecycle_state;
                let res = facade.stop(reason).map_err(|e| e.to_string());
                let after = facade.lifecycle_state;
                outcomes.push(PerNodeStopOutcome {
                    node_id: node_id.clone(),
                    state_before: before,
                    state_after: after,
                    cancellation_facts: facade.cancellation_facts.clone(),
                    result: res,
                });
            }
        }

        // Update all metadata in index
        for facade in self.nodes.values() {
            self.index.register_or_update(facade.metadata());
        }

        Ok(GraphStopReport {
            graph_id: self.graph_id.clone(),
            node_outcomes: outcomes,
            scope_barrier_established: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::{CooperativeDrainAdapter, SyntheticCapabilityAdapter};
    use crate::routing::{
        DeliveryMode, FrozenTargetRecipient, QueueBounds, Subscription, TargetSelector,
    };
    use serde_json::json;
    use std::sync::Arc;

    fn test_queue() -> FairDispatchQueue {
        FairDispatchQueue::new(
            QueueBounds {
                max_entries: 100,
                max_bytes: 1024 * 1024,
            },
            QueueBounds {
                max_entries: 100,
                max_bytes: 1024 * 1024,
            },
            QueueBounds {
                max_entries: 100,
                max_bytes: 1024 * 1024,
            },
            4,
        )
    }

    #[test]
    fn test_driver_step_dispatches_queued_item_and_updates_index() {
        let queue = test_queue();
        let subs = SubscriptionRegistry::new();
        let mut driver = ContinuousNodeDriver::new("graph-1", queue, subs);

        let adapter = Arc::new(SyntheticCapabilityAdapter::new("adapt-1"));
        let facade = NodeFacade::new("node-1", "graph-1", 1, "worker", adapter, None, None);
        driver.register_node(facade);

        // Verify index has node-1 as Ready
        let matches = driver
            .index
            .query(&TargetSelector::ExactNode("node-1".into()));
        assert_eq!(matches.len(), 1);

        // Enqueue task
        let targets = FrozenTargets {
            frozen_at_cursor: 1,
            mode: DeliveryMode::DispatchOne,
            recipients: vec![FrozenTargetRecipient {
                delivery_id: "del-1".into(),
                node_id: "node-1".into(),
                generation: 1,
                admitted_state: NodeLifecycleState::Ready,
            }],
        };

        driver
            .enqueue_admitted(
                ChannelKind::Data,
                "msg-1",
                AdmittedMessagePayload {
                    source_principal_id: "admin".into(),
                    graph_id: "graph-1".into(),
                    operation: ControlOperation::SubmitTask {
                        input: json!({"run": true}),
                    },
                    targets,
                },
                1000,
            )
            .unwrap();

        // Drive one step
        let outcome = driver.drive_step().unwrap();
        assert_eq!(outcome.items_dispatched, 1);
        assert_eq!(outcome.effects_succeeded, 1);

        // Node is now Running and feature index reflects Running
        let node = driver.get_node("node-1").unwrap();
        assert_eq!(node.lifecycle_state, NodeLifecycleState::Running);
        let running_nodes = driver
            .index
            .query(&TargetSelector::Lifecycle(NodeLifecycleState::Running));
        assert!(running_nodes.contains("node-1"));
    }

    #[test]
    fn test_driver_pre_effect_validation_skips_stale_or_missing_recipients() {
        let queue = test_queue();
        let subs = SubscriptionRegistry::new();
        let mut driver = ContinuousNodeDriver::new("graph-1", queue, subs);

        let adapter = Arc::new(SyntheticCapabilityAdapter::new("adapt-1"));
        // Registered at generation 2
        let facade = NodeFacade::new("node-recycled", "graph-1", 2, "worker", adapter, None, None);
        driver.register_node(facade);

        // Target was frozen with stale generation 1
        let targets = FrozenTargets {
            frozen_at_cursor: 1,
            mode: DeliveryMode::DispatchOne,
            recipients: vec![FrozenTargetRecipient {
                delivery_id: "del-stale".into(),
                node_id: "node-recycled".into(),
                generation: 1, // Stale!
                admitted_state: NodeLifecycleState::Ready,
            }],
        };

        driver
            .enqueue_admitted(
                ChannelKind::Data,
                "msg-stale",
                AdmittedMessagePayload {
                    source_principal_id: "admin".into(),
                    graph_id: "graph-1".into(),
                    operation: ControlOperation::SubmitTask {
                        input: json!({"work": 1}),
                    },
                    targets,
                },
                1000,
            )
            .unwrap();

        // Drive step
        let outcome = driver.drive_step().unwrap();
        assert_eq!(outcome.items_dispatched, 1);
        assert_eq!(outcome.stale_recipients_skipped, 1);
        assert_eq!(outcome.effects_succeeded, 0);

        // Node remains Ready; did NOT start work!
        let node = driver.get_node("node-recycled").unwrap();
        assert_eq!(node.lifecycle_state, NodeLifecycleState::Ready);
    }

    #[test]
    fn test_driver_rejects_wrong_graph_and_scope_barrier_submissions() {
        let queue = test_queue();
        let subs = SubscriptionRegistry::new();
        let mut driver = ContinuousNodeDriver::new("graph-guard", queue, subs);
        driver.register_node(NodeFacade::new(
            "node-guard",
            "graph-guard",
            1,
            "worker",
            Arc::new(SyntheticCapabilityAdapter::new("guard-adapter")),
            None,
            None,
        ));

        let targets = FrozenTargets {
            frozen_at_cursor: 1,
            mode: DeliveryMode::DispatchOne,
            recipients: vec![FrozenTargetRecipient {
                delivery_id: "del-guard".into(),
                node_id: "node-guard".into(),
                generation: 1,
                admitted_state: NodeLifecycleState::Ready,
            }],
        };

        driver
            .enqueue_admitted(
                ChannelKind::Data,
                "msg-barrier",
                AdmittedMessagePayload {
                    source_principal_id: "admin".into(),
                    graph_id: "graph-guard".into(),
                    operation: ControlOperation::SubmitTask {
                        input: json!({"blocked": true}),
                    },
                    targets: targets.clone(),
                },
                1000,
            )
            .unwrap();
        driver.scope_barrier_active = true;
        assert!(matches!(
            driver.drive_step(),
            Err(DriverError::ScopeAdmissionBarrierActive)
        ));
        assert_eq!(
            driver.get_node("node-guard").unwrap().lifecycle_state,
            NodeLifecycleState::Ready
        );

        driver.scope_barrier_active = false;
        driver
            .enqueue_admitted(
                ChannelKind::Data,
                "msg-wrong-graph",
                AdmittedMessagePayload {
                    source_principal_id: "admin".into(),
                    graph_id: "other-graph".into(),
                    operation: ControlOperation::SubmitTask {
                        input: json!({"blocked": true}),
                    },
                    targets,
                },
                1001,
            )
            .unwrap();
        assert!(matches!(
            driver.drive_step(),
            Err(DriverError::GraphMismatch { .. })
        ));
        assert_eq!(
            driver.get_node("node-guard").unwrap().lifecycle_state,
            NodeLifecycleState::Ready
        );
    }

    #[test]
    fn test_driver_result_reentry_with_source_identity() {
        let queue = test_queue();
        let subs = SubscriptionRegistry::new();
        let mut driver = ContinuousNodeDriver::new("graph-1", queue, subs);

        let adapter = Arc::new(SyntheticCapabilityAdapter::new("adapt-1"));
        let facade = NodeFacade::new("node-reentry", "graph-1", 1, "worker", adapter, None, None);
        driver.register_node(facade);

        // Start task on node
        let inv = driver
            .get_node_mut("node-reentry")
            .unwrap()
            .submit(json!({"compute": 123}), 1)
            .unwrap();

        // Re-enter successful result with matching source identity
        let receipt = driver
            .reenter_result(ResultReentry {
                source_principal_id: "adapt-1".into(),
                graph_id: "graph-1".into(),
                node_id: "node-reentry".into(),
                invocation_id: inv.invocation_id.clone(),
                generation: 1,
                cursor: 2,
                attempt_token: inv.attempt_token.clone(),
                outcome: NodeExecutionOutcome::Success {
                    output: json!({"result": 456}),
                },
            })
            .unwrap();

        assert_eq!(receipt.resulting_state, NodeLifecycleState::Ready);
        assert_eq!(driver.durable_cursor, 2);

        // Re-entering result with stale generation is rejected
        let stale_res = driver.reenter_result(ResultReentry {
            source_principal_id: "adapt-1".into(),
            graph_id: "graph-1".into(),
            node_id: "node-reentry".into(),
            invocation_id: "inv-old".into(),
            generation: 99, // Stale!
            cursor: 3,
            attempt_token: "att-old".into(),
            outcome: NodeExecutionOutcome::Success { output: json!({}) },
        });

        assert!(matches!(
            stale_res,
            Err(DriverError::StaleGenerationResult {
                expected: 1,
                received: 99,
                ..
            })
        ));
    }

    #[test]
    fn test_driver_result_reentry_rejects_unverified_invocation_identity() {
        let queue = test_queue();
        let subs = SubscriptionRegistry::new();
        let mut driver = ContinuousNodeDriver::new("graph-identity", queue, subs);
        let adapter = Arc::new(SyntheticCapabilityAdapter::new("verified-adapter"));
        driver.register_node(NodeFacade::new(
            "node-identity",
            "graph-identity",
            1,
            "worker",
            adapter,
            None,
            None,
        ));
        let invocation = driver
            .get_node_mut("node-identity")
            .unwrap()
            .submit(json!({"work": true}), 1)
            .unwrap();

        let make_reentry =
            |source: &str, invocation_id: &str, attempt_token: &str, cursor: u64| ResultReentry {
                source_principal_id: source.to_string(),
                graph_id: "graph-identity".to_string(),
                node_id: "node-identity".to_string(),
                invocation_id: invocation_id.to_string(),
                generation: 1,
                cursor,
                attempt_token: attempt_token.to_string(),
                outcome: NodeExecutionOutcome::Success {
                    output: json!({"ok": true}),
                },
            };

        assert!(matches!(
            driver.reenter_result(make_reentry(
                "forged-adapter",
                &invocation.invocation_id,
                &invocation.attempt_token,
                2,
            )),
            Err(DriverError::ResultSourceMismatch { .. })
        ));
        assert!(matches!(
            driver.reenter_result(make_reentry(
                "verified-adapter",
                "inv-other",
                &invocation.attempt_token,
                2,
            )),
            Err(DriverError::InvocationMismatch { .. })
        ));
        assert!(matches!(
            driver.reenter_result(make_reentry(
                "verified-adapter",
                &invocation.invocation_id,
                "attempt-other",
                2,
            )),
            Err(DriverError::AttemptTokenMismatch { .. })
        ));
        assert!(matches!(
            driver.reenter_result(make_reentry(
                "verified-adapter",
                &invocation.invocation_id,
                &invocation.attempt_token,
                0,
            )),
            Err(DriverError::StaleResultCursor { .. })
        ));

        let receipt = driver
            .reenter_result(make_reentry(
                "verified-adapter",
                &invocation.invocation_id,
                &invocation.attempt_token,
                2,
            ))
            .unwrap();
        assert_eq!(receipt.resulting_state, NodeLifecycleState::Ready);
    }

    #[test]
    fn test_driver_independent_node_concurrency() {
        // In a graph with A->C and independent B:
        // C can start when A finishes while B is still running!
        let queue = test_queue();
        let subs = SubscriptionRegistry::new();
        let mut driver = ContinuousNodeDriver::new("graph-concur", queue, subs);

        let adapt_a = Arc::new(SyntheticCapabilityAdapter::new("adapt-a"));
        let adapt_b = Arc::new(SyntheticCapabilityAdapter::new("adapt-b"));
        let adapt_c = Arc::new(SyntheticCapabilityAdapter::new("adapt-c"));

        driver.register_node(NodeFacade::new(
            "node-A",
            "graph-concur",
            1,
            "task-a",
            adapt_a,
            None,
            None,
        ));
        driver.register_node(NodeFacade::new(
            "node-B",
            "graph-concur",
            1,
            "task-b",
            adapt_b,
            None,
            None,
        ));
        driver.register_node(NodeFacade::new(
            "node-C",
            "graph-concur",
            1,
            "task-c",
            adapt_c,
            None,
            None,
        ));

        // Submit to A and B
        let inv_a = driver
            .get_node_mut("node-A")
            .unwrap()
            .submit(json!({"step": "A"}), 1)
            .unwrap();
        let _inv_b = driver
            .get_node_mut("node-B")
            .unwrap()
            .submit(json!({"step": "B"}), 2)
            .unwrap();

        // Both A and B are Running
        assert_eq!(
            driver.get_node("node-A").unwrap().lifecycle_state,
            NodeLifecycleState::Running
        );
        assert_eq!(
            driver.get_node("node-B").unwrap().lifecycle_state,
            NodeLifecycleState::Running
        );
        assert_eq!(
            driver.get_node("node-C").unwrap().lifecycle_state,
            NodeLifecycleState::Ready
        );

        // Settle A
        driver
            .reenter_result(ResultReentry {
                source_principal_id: "adapt-a".into(),
                graph_id: "graph-concur".into(),
                node_id: "node-A".into(),
                invocation_id: inv_a.invocation_id,
                generation: 1,
                cursor: 3,
                attempt_token: inv_a.attempt_token,
                outcome: NodeExecutionOutcome::Success {
                    output: json!({"a": "done"}),
                },
            })
            .unwrap();

        // A is Ready (idle), B is STILL Running, C starts!
        assert_eq!(
            driver.get_node("node-A").unwrap().lifecycle_state,
            NodeLifecycleState::Ready
        );
        assert_eq!(
            driver.get_node("node-B").unwrap().lifecycle_state,
            NodeLifecycleState::Running
        );

        let _inv_c = driver
            .get_node_mut("node-C")
            .unwrap()
            .submit(json!({"step": "C", "input_from_a": "done"}), 4)
            .unwrap();

        // Now C is Running concurrently while B is still Running!
        assert_eq!(
            driver.get_node("node-C").unwrap().lifecycle_state,
            NodeLifecycleState::Running
        );
        assert_eq!(
            driver.get_node("node-B").unwrap().lifecycle_state,
            NodeLifecycleState::Running
        );
    }

    #[test]
    fn test_driver_assigns_distinct_cursors_to_independent_completions() {
        let queue = test_queue();
        let subs = SubscriptionRegistry::new();
        let mut driver = ContinuousNodeDriver::new("graph-cursors", queue, subs);
        let adapter_a = Arc::new(SyntheticCapabilityAdapter::new("cursor-a"));
        let adapter_b = Arc::new(SyntheticCapabilityAdapter::new("cursor-b"));
        driver.register_node(NodeFacade::new(
            "node-a",
            "graph-cursors",
            1,
            "worker",
            adapter_a.clone(),
            None,
            None,
        ));
        driver.register_node(NodeFacade::new(
            "node-b",
            "graph-cursors",
            1,
            "worker",
            adapter_b.clone(),
            None,
            None,
        ));
        let invocation_a = driver
            .get_node_mut("node-a")
            .unwrap()
            .submit(json!({"node": "a"}), 1)
            .unwrap();
        let invocation_b = driver
            .get_node_mut("node-b")
            .unwrap()
            .submit(json!({"node": "b"}), 1)
            .unwrap();
        driver
            .active_invocations
            .insert(invocation_a.invocation_id.clone(), "node-a".to_string());
        driver
            .active_invocations
            .insert(invocation_b.invocation_id.clone(), "node-b".to_string());
        adapter_a.set_status(
            &invocation_a.invocation_id,
            AdapterExecutionStatus::Completed {
                output: json!({"done": "a"}),
            },
        );
        adapter_b.set_status(
            &invocation_b.invocation_id,
            AdapterExecutionStatus::Completed {
                output: json!({"done": "b"}),
            },
        );

        let outcome = driver.drive_step().unwrap();
        assert_eq!(outcome.completions_settled, 2);
        assert_eq!(driver.durable_cursor, 3);
        assert!(driver.active_invocations.is_empty());
    }

    #[test]
    fn test_driver_graceful_graph_pause_and_stop_collects_per_node_outcomes() {
        let queue = test_queue();
        let subs = SubscriptionRegistry::new();
        let mut driver = ContinuousNodeDriver::new("graph-lifecycle", queue, subs);

        let adapt_1 = Arc::new(CooperativeDrainAdapter::new("coop-1"));
        let adapt_2 = Arc::new(CooperativeDrainAdapter::new("coop-2"));

        driver.register_node(NodeFacade::new(
            "node-1",
            "graph-lifecycle",
            1,
            "worker",
            adapt_1,
            None,
            None,
        ));
        driver.register_node(NodeFacade::new(
            "node-2",
            "graph-lifecycle",
            1,
            "worker",
            adapt_2,
            None,
            None,
        ));
        // Start node-1 running, leave node-2 ready
        let invocation = driver
            .get_node_mut("node-1")
            .unwrap()
            .submit(json!({}), 1)
            .unwrap();
        driver
            .active_invocations
            .insert(invocation.invocation_id, "node-1".to_string());

        // Pause graph
        let pause_report = driver.pause_graph().unwrap();
        assert!(pause_report.scope_barrier_established);
        assert_eq!(pause_report.node_outcomes.len(), 2);

        // Node 1 was running -> entered PauseRequested (draining to safe boundary)
        let o1 = pause_report
            .node_outcomes
            .iter()
            .find(|o| o.node_id == "node-1")
            .unwrap();
        assert_eq!(o1.state_before, NodeLifecycleState::Running);
        assert_eq!(o1.state_after, NodeLifecycleState::PauseRequested);

        // Node 2 was ready -> directly entered Paused
        let o2 = pause_report
            .node_outcomes
            .iter()
            .find(|o| o.node_id == "node-2")
            .unwrap();
        assert_eq!(o2.state_before, NodeLifecycleState::Ready);
        assert_eq!(o2.state_after, NodeLifecycleState::Paused);

        // Stop graph
        let stop_report = driver.stop_graph("shutdown").unwrap();
        assert!(stop_report.scope_barrier_established);
        assert_eq!(stop_report.node_outcomes.len(), 2);

        for outcome in stop_report.node_outcomes {
            assert_eq!(outcome.state_after, NodeLifecycleState::Stopped);
            let facts = outcome.cancellation_facts.unwrap();
            assert!(facts.requested);
            assert!(facts.acknowledged);
            assert_eq!(facts.reason, "shutdown");
        }

        // The acknowledged stop settled node-1 before the next poll; the
        // driver must prune that map entry rather than re-entering twice.
        assert!(driver.drive_step().is_ok());
        assert!(driver.active_invocations.is_empty());
    }

    #[test]
    fn test_driver_subscription_auto_resume_on_matching_event() {
        let queue = test_queue();
        let mut subs = SubscriptionRegistry::new();

        // Register auto-resume subscription on node-paused when it enters Paused
        subs.subscribe(Subscription {
            subscription_id: "sub-auto-resume".into(),
            subscriber_id: "subscriber-1".into(),
            scope: SubscriptionScope::Node {
                graph_id: "graph-sub".into(),
                node_id: "node-paused".into(),
            },
            predicate: SubscriptionPredicate::OnLifecycleState(NodeLifecycleState::Paused),
            activation_rule: ActivationRule::AutoResume,
            durable_cursor: 0,
            is_control: false,
            active: true,
        });

        let mut driver = ContinuousNodeDriver::new("graph-sub", queue, subs);

        let adapter = Arc::new(CooperativeDrainAdapter::new("coop"));
        let facade = NodeFacade::new("node-paused", "graph-sub", 1, "worker", adapter, None, None);
        driver.register_node(facade);

        // Submit task to node
        let inv = driver
            .get_node_mut("node-paused")
            .unwrap()
            .submit(json!({"task": 1}), 1)
            .unwrap();

        // Request pause on running node: enters PauseRequested
        let pause_res = driver.get_node_mut("node-paused").unwrap().pause().unwrap();
        assert!(matches!(pause_res, PauseResult::DrainingToSafeBoundary));
        assert_eq!(
            driver.get_node("node-paused").unwrap().lifecycle_state,
            NodeLifecycleState::PauseRequested
        );

        // An invocation completion arrives: settles invocation, reaches safe boundary -> Paused,
        // and triggers the registered auto-resume subscription!
        let receipt = driver
            .reenter_result(ResultReentry {
                source_principal_id: "coop".into(),
                graph_id: "graph-sub".into(),
                node_id: "node-paused".into(),
                invocation_id: inv.invocation_id,
                generation: 1,
                cursor: 5,
                attempt_token: inv.attempt_token,
                outcome: NodeExecutionOutcome::Success {
                    output: json!({"wake": true}),
                },
            })
            .unwrap();

        assert_eq!(receipt.resulting_state, NodeLifecycleState::Paused);

        // The auto-resume rule triggered on Paused, resuming the node to Ready!
        let node = driver.get_node("node-paused").unwrap();
        assert_eq!(node.lifecycle_state, NodeLifecycleState::Ready);
    }
}
