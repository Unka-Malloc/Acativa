//! Node facade for uniform operations and truthful capabilities.
//!
//! Maps node identity to its session / runtime binding.
//! Provides uniform operations (Submit, Steer, Pause, Resume, Stop, Observe).
//! Truthfully enforces adapter capabilities without faking pause or steer via process kill.
//! Preserves requested, acknowledged, and effect-unknown cancellation facts separately.

use crate::adapter::{
    AdapterError, CancelOutcome, NodeCapabilityAdapter, NodeInvocation, PauseOutcome,
    ResumeOutcome, SingleWriterSessionRegistry, SteerOutcome,
};
use crate::control::VerifiedPrincipal;
use crate::routing::{NodeCapability, NodeLifecycleState, NodeMetadata};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fmt::{Display, Formatter};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Separate cancellation facts preserved truthfully.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CancellationFacts {
    pub requested: bool,
    pub acknowledged: bool,
    pub effect_unknown: bool,
    pub reason: String,
    pub requested_at_ms: u64,
}

/// Truthful observation of a node without starting or extending work.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeObservation {
    pub node_id: String,
    pub graph_id: String,
    pub generation: u64,
    pub lifecycle_state: NodeLifecycleState,
    pub work_role: String,
    pub adapter_identity: String,
    pub capabilities: BTreeSet<NodeCapability>,
    pub active_invocation_id: Option<String>,
    pub durable_cursor: u64,
    pub cancellation_facts: Option<CancellationFacts>,
    pub follow_up_instructions: Vec<String>,
}

/// Result of a steer operation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SteerResult {
    /// Delivered live to in-flight invocation.
    AppliedInFlight,
    /// Backend does not support live steering; queued for evaluation at next safe boundary.
    FollowUpQueued { instruction: String },
    /// Steer is unsupported.
    Unsupported,
}

/// Result of a pause operation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PauseResult {
    /// In-flight invocation was actively suspended.
    Suspended,
    /// In-flight work is draining to the next safe boundary.
    DrainingToSafeBoundary,
    /// Node was already paused.
    AlreadyPaused,
    /// Pause is unsupported.
    Unsupported,
}

/// Result of a resume operation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ResumeResult {
    Resumed,
    AlreadyRunning,
}

/// Result of a stop operation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum StopResult {
    /// Node stopped immediately (e.g. idle or cooperative cancel acknowledged).
    Stopped,
    /// Cooperative cancellation requested and tracked.
    CancellationRequested(CancellationFacts),
    /// Already stopped.
    AlreadyStopped,
}

/// Final outcome of an invocation execution.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NodeExecutionOutcome {
    Success { output: Value },
    Failure { error: String, retryable: bool },
    Cancelled { acknowledged: bool },
    Suspended { safe_boundary: String },
}

/// Historical record of an execution attempt on a node.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InvocationRecord {
    pub invocation_id: String,
    pub attempt_token: String,
    pub generation: u64,
    pub input: Value,
    pub outcome: Option<NodeExecutionOutcome>,
    pub started_at_ms: u64,
    pub settled_at_ms: Option<u64>,
}

/// Durable receipt issued upon settling an invocation completion.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeExecutionReceipt {
    pub receipt_id: String,
    pub node_id: String,
    pub graph_id: String,
    pub invocation_id: String,
    pub generation: u64,
    pub resulting_state: NodeLifecycleState,
    pub cursor: u64,
    pub outcome: NodeExecutionOutcome,
    pub settled_at_ms: u64,
}

/// Errors originating during node facade operations.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NodeExecutionError {
    InvalidStateTransition {
        current: NodeLifecycleState,
        attempted: String,
    },
    CapabilityUnsupported(NodeCapability),
    StopRequestedMonotonic,
    InvocationNotFound(String),
    InvocationSettled(String),
    AdapterError(AdapterError),
}

impl Display for NodeExecutionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidStateTransition { current, attempted } => {
                write!(
                    f,
                    "Invalid state transition from {current:?} for {attempted}"
                )
            }
            Self::CapabilityUnsupported(cap) => write!(f, "Node capability unsupported: {cap:?}"),
            Self::StopRequestedMonotonic => {
                write!(f, "Stop has been requested; node cannot accept new work")
            }
            Self::InvocationNotFound(id) => write!(f, "Invocation {id} not found"),
            Self::InvocationSettled(id) => write!(f, "Invocation {id} has already settled"),
            Self::AdapterError(err) => write!(f, "Adapter error: {err}"),
        }
    }
}

impl std::error::Error for NodeExecutionError {}

impl From<AdapterError> for NodeExecutionError {
    fn from(err: AdapterError) -> Self {
        Self::AdapterError(err)
    }
}

/// Facade presenting one uniform control surface for a node instance.
pub struct NodeFacade {
    pub node_id: String,
    pub graph_id: String,
    pub generation: u64,
    pub work_role: String,
    pub lifecycle_state: NodeLifecycleState,
    pub capabilities: BTreeSet<NodeCapability>,
    pub adapter: Arc<dyn NodeCapabilityAdapter>,
    pub session_id: Option<String>,
    pub session_registry: Option<SingleWriterSessionRegistry>,
    pub active_invocation: Option<NodeInvocation>,
    pub invocation_history: Vec<InvocationRecord>,
    pub durable_cursor: u64,
    pub stop_requested: bool,
    pub cancellation_facts: Option<CancellationFacts>,
    pub follow_up_instructions: Vec<String>,
}

impl NodeFacade {
    pub fn new(
        node_id: impl Into<String>,
        graph_id: impl Into<String>,
        generation: u64,
        work_role: impl Into<String>,
        adapter: Arc<dyn NodeCapabilityAdapter>,
        session_id: Option<String>,
        session_registry: Option<SingleWriterSessionRegistry>,
    ) -> Self {
        let declared = adapter.declared_capabilities();
        Self {
            node_id: node_id.into(),
            graph_id: graph_id.into(),
            generation,
            work_role: work_role.into(),
            lifecycle_state: NodeLifecycleState::Ready,
            capabilities: declared,
            adapter,
            session_id,
            session_registry,
            active_invocation: None,
            invocation_history: Vec::new(),
            durable_cursor: 0,
            stop_requested: false,
            cancellation_facts: None,
            follow_up_instructions: Vec::new(),
        }
    }

    /// Snapshot node metadata for registration and feature indexing.
    pub fn metadata(&self) -> NodeMetadata {
        NodeMetadata {
            node_id: self.node_id.clone(),
            generation: self.generation,
            graph_id: self.graph_id.clone(),
            lifecycle_state: self.lifecycle_state,
            adapter_identity: self.adapter.adapter_identity().to_string(),
            work_role: self.work_role.clone(),
            capabilities: self.capabilities.clone(),
            active_invocation_id: self
                .active_invocation
                .as_ref()
                .map(|i| i.invocation_id.clone()),
        }
    }

    /// Submit a task to this node.
    pub fn submit(
        &mut self,
        input: Value,
        _principal: &VerifiedPrincipal,
        current_cursor: u64,
    ) -> Result<NodeInvocation, NodeExecutionError> {
        if self.stop_requested || self.lifecycle_state.is_stop_requested() {
            return Err(NodeExecutionError::StopRequestedMonotonic);
        }
        if !self.lifecycle_state.can_accept_new_work() {
            return Err(NodeExecutionError::InvalidStateTransition {
                current: self.lifecycle_state,
                attempted: "submit".to_string(),
            });
        }
        if !self.capabilities.contains(&NodeCapability::Submit) {
            return Err(NodeExecutionError::CapabilityUnsupported(
                NodeCapability::Submit,
            ));
        }

        // Enforce single-writer session ownership if session is bound
        if let (Some(session_id), Some(registry)) = (&self.session_id, &self.session_registry) {
            registry.acquire_writer(session_id, &self.node_id)?;
        }

        let invocation_id = format!("inv-{}", Uuid::new_v4());
        let attempt_token = format!("att-{}", Uuid::new_v4());
        let invocation = NodeInvocation {
            invocation_id: invocation_id.clone(),
            node_id: self.node_id.clone(),
            graph_id: self.graph_id.clone(),
            generation: self.generation,
            input: input.clone(),
            started_at_ms: now_ms(),
            attempt_token: attempt_token.clone(),
        };

        // Start invocation in adapter. A failed start must not strand the
        // single-writer reservation acquired above.
        if let Err(error) = self.adapter.start_invocation(&invocation) {
            if let (Some(session_id), Some(registry)) = (&self.session_id, &self.session_registry) {
                registry.release_writer(session_id, &self.node_id);
            }
            return Err(error.into());
        }

        self.active_invocation = Some(invocation.clone());
        self.lifecycle_state = NodeLifecycleState::Running;
        self.durable_cursor = current_cursor;

        self.invocation_history.push(InvocationRecord {
            invocation_id,
            attempt_token,
            generation: self.generation,
            input,
            outcome: None,
            started_at_ms: now_ms(),
            settled_at_ms: None,
        });

        Ok(invocation)
    }

    /// Steer the active invocation with new instructions.
    /// Truthfully reports whether live in-flight steering was applied,
    /// follow-up was queued for safe boundary, or steering is unsupported.
    /// Never kills or restarts the process!
    pub fn steer(
        &mut self,
        invocation_id: &str,
        instruction: &str,
        follow_up: bool,
    ) -> Result<SteerResult, NodeExecutionError> {
        if self.stop_requested || self.lifecycle_state.is_stop_requested() {
            return Err(NodeExecutionError::StopRequestedMonotonic);
        }
        if !self.capabilities.contains(&NodeCapability::Steer) {
            return Err(NodeExecutionError::CapabilityUnsupported(
                NodeCapability::Steer,
            ));
        }

        let active = match &self.active_invocation {
            Some(inv) => inv,
            None => {
                // Check history to distinguish settled from never existed
                if self
                    .invocation_history
                    .iter()
                    .any(|r| r.invocation_id == invocation_id)
                {
                    return Err(NodeExecutionError::InvocationSettled(
                        invocation_id.to_string(),
                    ));
                } else {
                    return Err(NodeExecutionError::InvocationNotFound(
                        invocation_id.to_string(),
                    ));
                }
            }
        };

        if active.invocation_id != invocation_id {
            return Err(NodeExecutionError::InvocationNotFound(
                invocation_id.to_string(),
            ));
        }

        if follow_up {
            self.follow_up_instructions.push(instruction.to_string());
            return Ok(SteerResult::FollowUpQueued {
                instruction: instruction.to_string(),
            });
        }

        let outcome = self.adapter.steer_invocation(invocation_id, instruction)?;
        match outcome {
            SteerOutcome::AppliedInFlight { instruction: _ } => Ok(SteerResult::AppliedInFlight),
            SteerOutcome::SafeBoundaryFollowUp {
                follow_up_instruction,
            } => {
                self.follow_up_instructions
                    .push(follow_up_instruction.clone());
                Ok(SteerResult::FollowUpQueued {
                    instruction: follow_up_instruction,
                })
            }
            SteerOutcome::Unsupported => Ok(SteerResult::Unsupported),
        }
    }

    /// Request pause / drain for this node.
    /// In-flight work may suspend if supported, or drain to safe boundary.
    /// Never fakes pause by killing processes.
    pub fn pause(&mut self) -> Result<PauseResult, NodeExecutionError> {
        if self.stop_requested || self.lifecycle_state.is_stop_requested() {
            return Err(NodeExecutionError::StopRequestedMonotonic);
        }
        if !self.capabilities.contains(&NodeCapability::Pause) {
            return Err(NodeExecutionError::CapabilityUnsupported(
                NodeCapability::Pause,
            ));
        }

        if self.lifecycle_state == NodeLifecycleState::Paused {
            return Ok(PauseResult::AlreadyPaused);
        }

        // If idle, safe boundary is already reached: transition directly to Paused
        if self.lifecycle_state.can_accept_new_work() && self.active_invocation.is_none() {
            self.lifecycle_state = NodeLifecycleState::Paused;
            return Ok(PauseResult::Suspended);
        }

        // If running, enter PauseRequested
        self.lifecycle_state = NodeLifecycleState::PauseRequested;

        if let Some(active) = &self.active_invocation {
            let outcome = self.adapter.pause_invocation(&active.invocation_id)?;
            match outcome {
                PauseOutcome::SuspendedInFlight => {
                    self.lifecycle_state = NodeLifecycleState::Paused;
                    Ok(PauseResult::Suspended)
                }
                PauseOutcome::DrainToSafeBoundary => Ok(PauseResult::DrainingToSafeBoundary),
                PauseOutcome::Unsupported => {
                    self.lifecycle_state = NodeLifecycleState::Running;
                    Ok(PauseResult::Unsupported)
                }
            }
        } else {
            self.lifecycle_state = NodeLifecycleState::Paused;
            Ok(PauseResult::Suspended)
        }
    }

    /// Mark that a safe boundary has been observed for this node.
    /// Converts `PauseRequested` to `Paused`.
    pub fn observe_safe_boundary(&mut self) {
        if self.lifecycle_state == NodeLifecycleState::PauseRequested {
            self.lifecycle_state = NodeLifecycleState::Paused;
        }
    }

    /// Resume a paused or waiting node.
    pub fn resume(&mut self) -> Result<ResumeResult, NodeExecutionError> {
        if self.stop_requested || self.lifecycle_state.is_stop_requested() {
            return Err(NodeExecutionError::StopRequestedMonotonic);
        }
        if !self.capabilities.contains(&NodeCapability::Resume) {
            return Err(NodeExecutionError::CapabilityUnsupported(
                NodeCapability::Resume,
            ));
        }

        if self.lifecycle_state == NodeLifecycleState::Running {
            return Ok(ResumeResult::AlreadyRunning);
        }

        if self.lifecycle_state == NodeLifecycleState::PauseRequested {
            // Cancel pause negotiation and remain running
            self.lifecycle_state = NodeLifecycleState::Running;
            return Ok(ResumeResult::Resumed);
        }

        if self.lifecycle_state != NodeLifecycleState::Paused
            && self.lifecycle_state != NodeLifecycleState::Waiting
        {
            return Err(NodeExecutionError::InvalidStateTransition {
                current: self.lifecycle_state,
                attempted: "resume".to_string(),
            });
        }

        if let Some(active) = &self.active_invocation {
            let outcome = self.adapter.resume_invocation(&active.invocation_id)?;
            match outcome {
                ResumeOutcome::Resumed | ResumeOutcome::NotPaused => {
                    self.lifecycle_state = NodeLifecycleState::Running;
                    Ok(ResumeResult::Resumed)
                }
                ResumeOutcome::Unsupported => Err(NodeExecutionError::CapabilityUnsupported(
                    NodeCapability::Resume,
                )),
            }
        } else {
            self.lifecycle_state = NodeLifecycleState::Ready;
            Ok(ResumeResult::Resumed)
        }
    }

    /// Cooperatively stop this node.
    /// Preserves requested, acknowledged, and effect-unknown facts separately.
    pub fn stop(&mut self, reason: &str) -> Result<StopResult, NodeExecutionError> {
        if !self.capabilities.contains(&NodeCapability::Stop) {
            return Err(NodeExecutionError::CapabilityUnsupported(
                NodeCapability::Stop,
            ));
        }

        if self.lifecycle_state == NodeLifecycleState::Stopped {
            return Ok(StopResult::AlreadyStopped);
        }

        self.stop_requested = true;
        self.lifecycle_state = NodeLifecycleState::StopRequested;

        if let Some(active) = &self.active_invocation {
            let cancel_outcome = self.adapter.cancel_invocation(&active.invocation_id)?;
            let facts = match cancel_outcome {
                CancelOutcome::Acknowledged => CancellationFacts {
                    requested: true,
                    acknowledged: true,
                    effect_unknown: false,
                    reason: reason.to_string(),
                    requested_at_ms: now_ms(),
                },
                CancelOutcome::Draining => CancellationFacts {
                    requested: true,
                    acknowledged: false,
                    effect_unknown: false,
                    reason: reason.to_string(),
                    requested_at_ms: now_ms(),
                },
                CancelOutcome::EffectUnknown { reason: err } => CancellationFacts {
                    requested: true,
                    acknowledged: false,
                    effect_unknown: true,
                    reason: err,
                    requested_at_ms: now_ms(),
                },
            };

            self.cancellation_facts = Some(facts.clone());

            if facts.acknowledged {
                // Cooperative cancel immediately acknowledged; settle invocation
                let cursor = self.durable_cursor;
                self.settle_invocation_completion(
                    NodeExecutionOutcome::Cancelled { acknowledged: true },
                    cursor,
                )?;
                Ok(StopResult::Stopped)
            } else {
                Ok(StopResult::CancellationRequested(facts))
            }
        } else {
            // Idle node stops immediately
            if let (Some(session_id), Some(registry)) = (&self.session_id, &self.session_registry) {
                registry.release_writer(session_id, &self.node_id);
            }
            let facts = CancellationFacts {
                requested: true,
                acknowledged: true,
                effect_unknown: false,
                reason: reason.to_string(),
                requested_at_ms: now_ms(),
            };
            self.cancellation_facts = Some(facts);
            self.lifecycle_state = NodeLifecycleState::Stopped;
            Ok(StopResult::Stopped)
        }
    }

    /// Observe current node state without starting or extending work.
    pub fn observe(&self) -> NodeObservation {
        NodeObservation {
            node_id: self.node_id.clone(),
            graph_id: self.graph_id.clone(),
            generation: self.generation,
            lifecycle_state: self.lifecycle_state,
            work_role: self.work_role.clone(),
            adapter_identity: self.adapter.adapter_identity().to_string(),
            capabilities: self.capabilities.clone(),
            active_invocation_id: self
                .active_invocation
                .as_ref()
                .map(|i| i.invocation_id.clone()),
            durable_cursor: self.durable_cursor,
            cancellation_facts: self.cancellation_facts.clone(),
            follow_up_instructions: self.follow_up_instructions.clone(),
        }
    }

    /// Settle an active invocation completion, issuing a durable execution receipt.
    pub fn settle_invocation_completion(
        &mut self,
        outcome: NodeExecutionOutcome,
        cursor: u64,
    ) -> Result<NodeExecutionReceipt, NodeExecutionError> {
        let active = self
            .active_invocation
            .take()
            .ok_or_else(|| NodeExecutionError::InvocationNotFound("no active invocation".into()))?;

        // Release session writer
        if let (Some(session_id), Some(registry)) = (&self.session_id, &self.session_registry) {
            registry.release_writer(session_id, &self.node_id);
        }

        let now = now_ms();

        // Update historical record
        if let Some(record) = self
            .invocation_history
            .iter_mut()
            .find(|r| r.invocation_id == active.invocation_id)
        {
            record.outcome = Some(outcome.clone());
            record.settled_at_ms = Some(now);
        }

        // Determine resulting lifecycle state
        if self.stop_requested {
            let work_stopped = match &outcome {
                NodeExecutionOutcome::Cancelled { acknowledged } => *acknowledged,
                NodeExecutionOutcome::Suspended { .. } => false,
                NodeExecutionOutcome::Success { .. } | NodeExecutionOutcome::Failure { .. } => true,
            };
            self.lifecycle_state = if work_stopped {
                NodeLifecycleState::Stopped
            } else {
                NodeLifecycleState::StopRequested
            };
        } else if self.lifecycle_state == NodeLifecycleState::PauseRequested {
            // Reached safe boundary upon invocation completion
            self.lifecycle_state = NodeLifecycleState::Paused;
        } else {
            match &outcome {
                NodeExecutionOutcome::Success { .. } => {
                    self.lifecycle_state = NodeLifecycleState::Ready;
                }
                NodeExecutionOutcome::Failure {
                    retryable: false, ..
                } => {
                    self.lifecycle_state = NodeLifecycleState::Failed;
                }
                NodeExecutionOutcome::Failure {
                    retryable: true, ..
                } => {
                    self.lifecycle_state = NodeLifecycleState::Waiting;
                }
                NodeExecutionOutcome::Cancelled { .. } => {
                    self.lifecycle_state = NodeLifecycleState::Stopped;
                }
                NodeExecutionOutcome::Suspended { .. } => {
                    self.lifecycle_state = NodeLifecycleState::Paused;
                }
            }
        }

        self.durable_cursor = cursor;

        Ok(NodeExecutionReceipt {
            receipt_id: format!("rec-{}", Uuid::new_v4()),
            node_id: self.node_id.clone(),
            graph_id: self.graph_id.clone(),
            invocation_id: active.invocation_id,
            generation: self.generation,
            resulting_state: self.lifecycle_state,
            cursor,
            outcome,
            settled_at_ms: now,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::{
        AdapterExecutionStatus, CooperativeDrainAdapter, SyntheticCapabilityAdapter,
    };
    use serde_json::json;
    use std::collections::BTreeSet;

    struct StartFailingAdapter;

    impl NodeCapabilityAdapter for StartFailingAdapter {
        fn adapter_identity(&self) -> &str {
            "start-fails"
        }

        fn declared_capabilities(&self) -> BTreeSet<NodeCapability> {
            [NodeCapability::Submit, NodeCapability::Stop]
                .into_iter()
                .collect()
        }

        fn supports_inflight_steer(&self) -> bool {
            false
        }

        fn supports_inflight_pause(&self) -> bool {
            false
        }

        fn supports_cooperative_cancel(&self) -> bool {
            false
        }

        fn start_invocation(&self, _invocation: &NodeInvocation) -> Result<(), AdapterError> {
            Err(AdapterError::BackendError("start failed".to_string()))
        }

        fn steer_invocation(
            &self,
            invocation_id: &str,
            _instruction: &str,
        ) -> Result<SteerOutcome, AdapterError> {
            Err(AdapterError::InvocationNotFound(invocation_id.to_string()))
        }

        fn pause_invocation(&self, invocation_id: &str) -> Result<PauseOutcome, AdapterError> {
            Err(AdapterError::InvocationNotFound(invocation_id.to_string()))
        }

        fn resume_invocation(&self, invocation_id: &str) -> Result<ResumeOutcome, AdapterError> {
            Err(AdapterError::InvocationNotFound(invocation_id.to_string()))
        }

        fn cancel_invocation(&self, invocation_id: &str) -> Result<CancelOutcome, AdapterError> {
            Err(AdapterError::InvocationNotFound(invocation_id.to_string()))
        }

        fn poll_status(&self, invocation_id: &str) -> Result<AdapterExecutionStatus, AdapterError> {
            Err(AdapterError::InvocationNotFound(invocation_id.to_string()))
        }
    }

    #[test]
    fn test_node_facade_failed_start_releases_session_writer() {
        let registry = SingleWriterSessionRegistry::new();
        let mut facade = NodeFacade::new(
            "node-start-fails",
            "graph-1",
            1,
            "worker",
            Arc::new(StartFailingAdapter),
            Some("session-1".to_string()),
            Some(registry.clone()),
        );

        let principal = VerifiedPrincipal::local_admin("admin-1");
        assert!(facade.submit(json!({"work": true}), &principal, 1).is_err());
        assert_eq!(registry.current_writer("session-1"), None);
        assert_eq!(facade.lifecycle_state, NodeLifecycleState::Ready);
        assert!(facade.active_invocation.is_none());
    }

    #[test]
    fn test_node_facade_submit_lifecycle_transition() {
        let adapter = Arc::new(
            SyntheticCapabilityAdapter::new("test-adapter")
                .with_capabilities([NodeCapability::Submit, NodeCapability::Observe]),
        );
        let mut facade = NodeFacade::new("node-1", "graph-1", 1, "worker", adapter, None, None);

        assert_eq!(facade.lifecycle_state, NodeLifecycleState::Ready);
        let principal = VerifiedPrincipal::local_admin("admin-1");

        // Submit task
        let inv = facade.submit(json!({"param": 42}), &principal, 10).unwrap();
        assert_eq!(facade.lifecycle_state, NodeLifecycleState::Running);
        assert_eq!(facade.durable_cursor, 10);
        assert_eq!(
            facade.active_invocation.as_ref().map(|i| &i.invocation_id),
            Some(&inv.invocation_id)
        );

        // Submitting while running fails with InvalidStateTransition
        let err = facade
            .submit(json!({"param": 43}), &principal, 11)
            .unwrap_err();
        assert!(matches!(
            err,
            NodeExecutionError::InvalidStateTransition {
                current: NodeLifecycleState::Running,
                ..
            }
        ));
    }

    #[test]
    fn test_node_facade_stop_requested_blocks_new_work() {
        let adapter = Arc::new(CooperativeDrainAdapter::new("coop"));
        let mut facade = NodeFacade::new("node-stop", "graph-1", 1, "worker", adapter, None, None);

        // Stop the idle node
        let stop_res = facade.stop("user request").unwrap();
        assert!(matches!(stop_res, StopResult::Stopped));
        assert_eq!(facade.lifecycle_state, NodeLifecycleState::Stopped);
        assert!(facade.stop_requested);

        // Submit to stopped node fails monotonically
        let principal = VerifiedPrincipal::local_admin("admin-1");
        let err = facade
            .submit(json!({"param": 1}), &principal, 1)
            .unwrap_err();
        assert_eq!(err, NodeExecutionError::StopRequestedMonotonic);
    }

    #[test]
    fn test_node_facade_steer_in_flight_vs_follow_up_and_settled() {
        let adapter =
            Arc::new(SyntheticCapabilityAdapter::new("steerable").with_inflight_steer(true));
        let mut facade = NodeFacade::new("node-steer", "graph-1", 1, "worker", adapter, None, None);

        let principal = VerifiedPrincipal::local_admin("admin-1");
        let inv = facade.submit(json!({}), &principal, 1).unwrap();

        // In-flight steer applies live
        let res = facade
            .steer(&inv.invocation_id, "add logging", false)
            .unwrap();
        assert!(matches!(res, SteerResult::AppliedInFlight));

        // Follow-up steer queues for safe boundary
        let res_fu = facade
            .steer(&inv.invocation_id, "follow up instruction", true)
            .unwrap();
        assert!(matches!(
            res_fu,
            SteerResult::FollowUpQueued { ref instruction } if instruction == "follow up instruction"
        ));
        assert_eq!(
            facade.follow_up_instructions,
            vec!["follow up instruction".to_string()]
        );

        // Steer on unknown invocation returns InvocationNotFound
        let err = facade.steer("unknown-inv", "do that", false).unwrap_err();
        assert!(matches!(err, NodeExecutionError::InvocationNotFound(_)));

        // Settle invocation
        facade
            .settle_invocation_completion(
                NodeExecutionOutcome::Success {
                    output: json!({"ok": true}),
                },
                2,
            )
            .unwrap();

        // Steer on now-settled invocation returns InvocationSettled
        let err_settled = facade
            .steer(&inv.invocation_id, "too late", false)
            .unwrap_err();
        assert!(matches!(
            err_settled,
            NodeExecutionError::InvocationSettled(_)
        ));
    }

    #[test]
    fn test_node_facade_pause_drain_and_observe_safe_boundary() {
        let adapter = Arc::new(CooperativeDrainAdapter::new("drain-adapter"));
        let mut facade = NodeFacade::new("node-pause", "graph-1", 1, "worker", adapter, None, None);

        let principal = VerifiedPrincipal::local_admin("admin-1");
        facade.submit(json!({}), &principal, 1).unwrap();

        // Request pause on running node with cooperative drain adapter
        let pause_res = facade.pause().unwrap();
        assert!(matches!(pause_res, PauseResult::DrainingToSafeBoundary));
        assert_eq!(facade.lifecycle_state, NodeLifecycleState::PauseRequested);

        // Observing safe boundary moves to Paused
        facade.observe_safe_boundary();
        assert_eq!(facade.lifecycle_state, NodeLifecycleState::Paused);

        // Resume returns to Running
        let resume_res = facade.resume().unwrap();
        assert!(matches!(resume_res, ResumeResult::Resumed));
        assert_eq!(facade.lifecycle_state, NodeLifecycleState::Running);
    }

    #[test]
    fn test_node_facade_stop_preserves_distinct_cancellation_facts() {
        // Case 1: Acknowledged cooperative cancel
        let ack_adapter = Arc::new(
            SyntheticCapabilityAdapter::new("ack-adapter")
                .with_inflight_steer(true)
                .with_inflight_pause(true)
                .with_forced_cancel_outcome(CancelOutcome::Acknowledged),
        );
        let mut facade_ack =
            NodeFacade::new("node-ack", "graph-1", 1, "worker", ack_adapter, None, None);
        let principal = VerifiedPrincipal::local_admin("admin-1");
        facade_ack.submit(json!({}), &principal, 1).unwrap();

        let stop_ack = facade_ack.stop("graceful shutdown").unwrap();
        assert!(matches!(stop_ack, StopResult::Stopped));
        assert_eq!(facade_ack.lifecycle_state, NodeLifecycleState::Stopped);
        let facts = facade_ack.cancellation_facts.clone().unwrap();
        assert!(facts.requested);
        assert!(facts.acknowledged);
        assert!(!facts.effect_unknown);
        assert_eq!(facts.reason, "graceful shutdown");
        assert!(matches!(
            facade_ack.steer("settled", "late", false),
            Err(NodeExecutionError::StopRequestedMonotonic)
        ));
        assert!(matches!(
            facade_ack.pause(),
            Err(NodeExecutionError::StopRequestedMonotonic)
        ));
        assert!(matches!(
            facade_ack.resume(),
            Err(NodeExecutionError::StopRequestedMonotonic)
        ));

        // Case 2: Effect unknown cancellation
        let unk_adapter = Arc::new(
            SyntheticCapabilityAdapter::new("unk-adapter").with_forced_cancel_outcome(
                CancelOutcome::EffectUnknown {
                    reason: "timeout awaiting cancellation ack".to_string(),
                },
            ),
        );
        let mut facade_unk =
            NodeFacade::new("node-unk", "graph-1", 1, "worker", unk_adapter, None, None);
        facade_unk.submit(json!({}), &principal, 1).unwrap();

        let stop_unk = facade_unk.stop("cancel requested").unwrap();
        assert!(matches!(
            stop_unk,
            StopResult::CancellationRequested(ref f) if f.effect_unknown && !f.acknowledged
        ));
        // Node remains in StopRequested because cancellation was not confirmed
        assert_eq!(
            facade_unk.lifecycle_state,
            NodeLifecycleState::StopRequested
        );
        let unk_facts = facade_unk.cancellation_facts.clone().unwrap();
        assert!(unk_facts.requested);
        assert!(!unk_facts.acknowledged);
        assert!(unk_facts.effect_unknown);
        assert_eq!(unk_facts.reason, "timeout awaiting cancellation ack");

        let receipt = facade_unk
            .settle_invocation_completion(
                NodeExecutionOutcome::Cancelled {
                    acknowledged: false,
                },
                2,
            )
            .unwrap();
        assert_eq!(receipt.resulting_state, NodeLifecycleState::StopRequested);
    }

    #[test]
    fn test_node_facade_observe_truthful_and_does_not_mutate() {
        let adapter = Arc::new(
            SyntheticCapabilityAdapter::new("obs-adapter")
                .with_capabilities([NodeCapability::Submit, NodeCapability::Observe]),
        );
        let facade = NodeFacade::new("node-obs", "graph-1", 2, "analyst", adapter, None, None);

        let obs = facade.observe();
        assert_eq!(obs.node_id, "node-obs");
        assert_eq!(obs.generation, 2);
        assert_eq!(obs.work_role, "analyst");
        assert_eq!(obs.lifecycle_state, NodeLifecycleState::Ready);
        assert_eq!(obs.durable_cursor, 0);
        assert!(obs.active_invocation_id.is_none());
        assert!(obs.cancellation_facts.is_none());

        // State remains Ready
        assert_eq!(facade.lifecycle_state, NodeLifecycleState::Ready);
    }
}
