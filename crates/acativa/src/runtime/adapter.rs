//! Native capability adapter leaves used by node execution.
//!
//! Adapters declare truthful capabilities (Submit, Steer, Pause, Resume, Stop, Observe).
//! Gating prevents fabricating pause or steer by killing/restarting processes.
//! Enforces single-writer session binding: one native session has one writer across facades.

use crate::routing::NodeCapability;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Display, Formatter};
use std::sync::{Arc, Mutex};

/// Invocations dispatched to a node adapter.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeInvocation {
    pub invocation_id: String,
    pub node_id: String,
    pub graph_id: String,
    pub generation: u64,
    pub input: Value,
    pub started_at_ms: u64,
    pub attempt_token: String,
}

/// Truthful outcome of a steer intervention.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SteerOutcome {
    /// In-flight invocation was steered live by the native backend.
    AppliedInFlight { instruction: String },
    /// Native backend does not support in-flight steer; recorded as follow-up for next safe boundary.
    SafeBoundaryFollowUp { follow_up_instruction: String },
    /// Steer is completely unsupported by this adapter.
    Unsupported,
}

/// Truthful outcome of a pause command.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PauseOutcome {
    /// Native backend actively suspended the running execution in-flight.
    SuspendedInFlight,
    /// Native backend does not support in-flight suspension; will drain to next safe boundary.
    DrainToSafeBoundary,
    /// Pause is completely unsupported by this adapter.
    Unsupported,
}

/// Truthful outcome of a resume command.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ResumeOutcome {
    /// Invocation or node was resumed.
    Resumed,
    /// Invocation is not in a paused or suspended state.
    NotPaused,
    /// Resume is unsupported by this adapter.
    Unsupported,
}

/// Separate cancellation facts preserved truthfully.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CancelOutcome {
    /// Adapter acknowledged cooperative cancellation.
    Acknowledged,
    /// Adapter is draining in-flight work before stopping.
    Draining,
    /// Cancellation status could not be verified (e.g. transport timeout); must remain explicit and recoverable.
    EffectUnknown { reason: String },
}

/// Live execution status of an adapter invocation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AdapterExecutionStatus {
    Running,
    Suspended,
    Completed { output: Value },
    Failed { error: String, retryable: bool },
    Cancelled { acknowledged: bool },
}

/// Adapter error kinds.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AdapterError {
    InvocationNotFound(String),
    CapabilityUnsupported(NodeCapability),
    SingleWriterConflict {
        session_id: String,
        active_node_id: String,
    },
    BackendError(String),
}

impl Display for AdapterError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvocationNotFound(id) => write!(f, "Invocation not found: {id}"),
            Self::CapabilityUnsupported(cap) => write!(f, "Capability unsupported: {cap:?}"),
            Self::SingleWriterConflict {
                session_id,
                active_node_id,
            } => write!(
                f,
                "Single writer conflict for session '{session_id}': already bound to node '{active_node_id}'"
            ),
            Self::BackendError(msg) => write!(f, "Adapter backend error: {msg}"),
        }
    }
}

impl std::error::Error for AdapterError {}

/// Abstract native capability adapter for node execution.
pub trait NodeCapabilityAdapter: Send + Sync {
    /// Unique identity of this adapter.
    fn adapter_identity(&self) -> &str;

    /// Truthful set of declared capabilities.
    fn declared_capabilities(&self) -> BTreeSet<NodeCapability>;

    /// Whether native in-flight steering is supported (without killing process).
    fn supports_inflight_steer(&self) -> bool;

    /// Whether native in-flight suspension is supported (without killing process).
    fn supports_inflight_pause(&self) -> bool;

    /// Whether cooperative cancellation is acknowledged.
    fn supports_cooperative_cancel(&self) -> bool;

    /// Start a new invocation.
    fn start_invocation(&self, invocation: &NodeInvocation) -> Result<(), AdapterError>;

    /// Deliver steer intervention to an active invocation.
    fn steer_invocation(
        &self,
        invocation_id: &str,
        instruction: &str,
    ) -> Result<SteerOutcome, AdapterError>;

    /// Request pause of an active invocation.
    fn pause_invocation(&self, invocation_id: &str) -> Result<PauseOutcome, AdapterError>;

    /// Request resume of a paused invocation.
    fn resume_invocation(&self, invocation_id: &str) -> Result<ResumeOutcome, AdapterError>;

    /// Cooperatively cancel an invocation.
    fn cancel_invocation(&self, invocation_id: &str) -> Result<CancelOutcome, AdapterError>;

    /// Poll execution status.
    fn poll_status(&self, invocation_id: &str) -> Result<AdapterExecutionStatus, AdapterError>;
}

/// Registry enforcing that one native session has at most one writer across all facades.
#[derive(Clone, Debug, Default)]
pub struct SingleWriterSessionRegistry {
    writers: Arc<Mutex<BTreeMap<String, String>>>,
}

impl SingleWriterSessionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Try to acquire exclusive writer ownership for a session.
    pub fn acquire_writer(&self, session_id: &str, node_id: &str) -> Result<(), AdapterError> {
        let mut map = self
            .writers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(existing) = map.get(session_id)
            && existing != node_id
        {
            return Err(AdapterError::SingleWriterConflict {
                session_id: session_id.to_string(),
                active_node_id: existing.clone(),
            });
        }
        map.insert(session_id.to_string(), node_id.to_string());
        Ok(())
    }

    /// Release writer ownership for a session.
    pub fn release_writer(&self, session_id: &str, node_id: &str) {
        let mut map = self
            .writers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(existing) = map.get(session_id)
            && existing == node_id
        {
            map.remove(session_id);
        }
    }

    /// Get current active writer for a session.
    pub fn current_writer(&self, session_id: &str) -> Option<String> {
        let map = self
            .writers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        map.get(session_id).cloned()
    }
}

/// Synthetic adapter for testing and deterministic verification of capability combinations.
pub struct SyntheticCapabilityAdapter {
    identity: String,
    capabilities: BTreeSet<NodeCapability>,
    can_inflight_steer: bool,
    can_inflight_pause: bool,
    can_cooperative_cancel: bool,
    forced_steer_outcome: Option<SteerOutcome>,
    forced_pause_outcome: Option<PauseOutcome>,
    forced_cancel_outcome: Option<CancelOutcome>,
    invocations: Arc<Mutex<BTreeMap<String, (NodeInvocation, AdapterExecutionStatus)>>>,
}

impl SyntheticCapabilityAdapter {
    pub fn new(identity: impl Into<String>) -> Self {
        let mut caps = BTreeSet::new();
        caps.insert(NodeCapability::Submit);
        caps.insert(NodeCapability::Observe);
        caps.insert(NodeCapability::Stop);

        Self {
            identity: identity.into(),
            capabilities: caps,
            can_inflight_steer: false,
            can_inflight_pause: false,
            can_cooperative_cancel: true,
            forced_steer_outcome: None,
            forced_pause_outcome: None,
            forced_cancel_outcome: None,
            invocations: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    pub fn with_capabilities(mut self, caps: impl IntoIterator<Item = NodeCapability>) -> Self {
        self.capabilities = caps.into_iter().collect();
        self
    }

    pub fn with_inflight_steer(mut self, enabled: bool) -> Self {
        self.can_inflight_steer = enabled;
        if enabled {
            self.capabilities.insert(NodeCapability::Steer);
        }
        self
    }

    pub fn with_inflight_pause(mut self, enabled: bool) -> Self {
        self.can_inflight_pause = enabled;
        if enabled {
            self.capabilities.insert(NodeCapability::Pause);
            self.capabilities.insert(NodeCapability::Resume);
        }
        self
    }

    pub fn with_forced_cancel_outcome(mut self, outcome: CancelOutcome) -> Self {
        self.forced_cancel_outcome = Some(outcome);
        self
    }

    pub fn set_status(&self, invocation_id: &str, status: AdapterExecutionStatus) {
        let mut map = self
            .invocations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some((_, entry)) = map.get_mut(invocation_id) {
            *entry = status;
        }
    }
}

impl NodeCapabilityAdapter for SyntheticCapabilityAdapter {
    fn adapter_identity(&self) -> &str {
        &self.identity
    }

    fn declared_capabilities(&self) -> BTreeSet<NodeCapability> {
        self.capabilities.clone()
    }

    fn supports_inflight_steer(&self) -> bool {
        self.can_inflight_steer
    }

    fn supports_inflight_pause(&self) -> bool {
        self.can_inflight_pause
    }

    fn supports_cooperative_cancel(&self) -> bool {
        self.can_cooperative_cancel
    }

    fn start_invocation(&self, invocation: &NodeInvocation) -> Result<(), AdapterError> {
        let mut map = self
            .invocations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        map.insert(
            invocation.invocation_id.clone(),
            (invocation.clone(), AdapterExecutionStatus::Running),
        );
        Ok(())
    }

    fn steer_invocation(
        &self,
        invocation_id: &str,
        instruction: &str,
    ) -> Result<SteerOutcome, AdapterError> {
        let map = self
            .invocations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !map.contains_key(invocation_id) {
            return Err(AdapterError::InvocationNotFound(invocation_id.to_string()));
        }
        if let Some(forced) = &self.forced_steer_outcome {
            return Ok(forced.clone());
        }
        if self.can_inflight_steer {
            Ok(SteerOutcome::AppliedInFlight {
                instruction: instruction.to_string(),
            })
        } else if self.capabilities.contains(&NodeCapability::Steer) {
            Ok(SteerOutcome::SafeBoundaryFollowUp {
                follow_up_instruction: instruction.to_string(),
            })
        } else {
            Ok(SteerOutcome::Unsupported)
        }
    }

    fn pause_invocation(&self, invocation_id: &str) -> Result<PauseOutcome, AdapterError> {
        let mut map = self
            .invocations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (_, status) = map
            .get_mut(invocation_id)
            .ok_or_else(|| AdapterError::InvocationNotFound(invocation_id.to_string()))?;
        if let Some(forced) = &self.forced_pause_outcome {
            return Ok(forced.clone());
        }
        if self.can_inflight_pause {
            *status = AdapterExecutionStatus::Suspended;
            Ok(PauseOutcome::SuspendedInFlight)
        } else if self.capabilities.contains(&NodeCapability::Pause) {
            Ok(PauseOutcome::DrainToSafeBoundary)
        } else {
            Ok(PauseOutcome::Unsupported)
        }
    }

    fn resume_invocation(&self, invocation_id: &str) -> Result<ResumeOutcome, AdapterError> {
        let mut map = self
            .invocations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (_, status) = map
            .get_mut(invocation_id)
            .ok_or_else(|| AdapterError::InvocationNotFound(invocation_id.to_string()))?;
        if !self.capabilities.contains(&NodeCapability::Resume) {
            return Ok(ResumeOutcome::Unsupported);
        }
        if *status == AdapterExecutionStatus::Suspended {
            *status = AdapterExecutionStatus::Running;
            Ok(ResumeOutcome::Resumed)
        } else {
            Ok(ResumeOutcome::NotPaused)
        }
    }

    fn cancel_invocation(&self, invocation_id: &str) -> Result<CancelOutcome, AdapterError> {
        let mut map = self
            .invocations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (_, status) = map
            .get_mut(invocation_id)
            .ok_or_else(|| AdapterError::InvocationNotFound(invocation_id.to_string()))?;
        if let Some(forced) = &self.forced_cancel_outcome {
            return Ok(forced.clone());
        }
        if self.can_cooperative_cancel {
            *status = AdapterExecutionStatus::Cancelled { acknowledged: true };
            Ok(CancelOutcome::Acknowledged)
        } else {
            Ok(CancelOutcome::Draining)
        }
    }

    fn poll_status(&self, invocation_id: &str) -> Result<AdapterExecutionStatus, AdapterError> {
        let map = self
            .invocations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        map.get(invocation_id)
            .map(|(_, status)| status.clone())
            .ok_or_else(|| AdapterError::InvocationNotFound(invocation_id.to_string()))
    }
}

/// Cooperative drain adapter: supports Submit, safe-boundary Steer, Pause
/// (via drain to safe boundary), Stop, and Observe. It truthfully exposes
/// that in-flight pause and steer are not supported without killing processes.
pub struct CooperativeDrainAdapter {
    identity: String,
    capabilities: BTreeSet<NodeCapability>,
    invocations: Arc<Mutex<BTreeMap<String, (NodeInvocation, AdapterExecutionStatus)>>>,
}

impl CooperativeDrainAdapter {
    pub fn new(identity: impl Into<String>) -> Self {
        let mut caps = BTreeSet::new();
        caps.insert(NodeCapability::Submit);
        caps.insert(NodeCapability::Steer);
        caps.insert(NodeCapability::Pause);
        caps.insert(NodeCapability::Resume);
        caps.insert(NodeCapability::Stop);
        caps.insert(NodeCapability::Observe);

        Self {
            identity: identity.into(),
            capabilities: caps,
            invocations: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    pub fn set_completion(&self, invocation_id: &str, output: Value) {
        let mut map = self
            .invocations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some((_, status)) = map.get_mut(invocation_id) {
            *status = AdapterExecutionStatus::Completed { output };
        }
    }
}

impl NodeCapabilityAdapter for CooperativeDrainAdapter {
    fn adapter_identity(&self) -> &str {
        &self.identity
    }

    fn declared_capabilities(&self) -> BTreeSet<NodeCapability> {
        self.capabilities.clone()
    }

    fn supports_inflight_steer(&self) -> bool {
        false
    }

    fn supports_inflight_pause(&self) -> bool {
        false
    }

    fn supports_cooperative_cancel(&self) -> bool {
        true
    }

    fn start_invocation(&self, invocation: &NodeInvocation) -> Result<(), AdapterError> {
        let mut map = self
            .invocations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        map.insert(
            invocation.invocation_id.clone(),
            (invocation.clone(), AdapterExecutionStatus::Running),
        );
        Ok(())
    }

    fn steer_invocation(
        &self,
        invocation_id: &str,
        instruction: &str,
    ) -> Result<SteerOutcome, AdapterError> {
        let map = self
            .invocations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !map.contains_key(invocation_id) {
            return Err(AdapterError::InvocationNotFound(invocation_id.to_string()));
        }
        if !self.capabilities.contains(&NodeCapability::Steer) {
            return Ok(SteerOutcome::Unsupported);
        }
        Ok(SteerOutcome::SafeBoundaryFollowUp {
            follow_up_instruction: instruction.to_string(),
        })
    }

    fn pause_invocation(&self, invocation_id: &str) -> Result<PauseOutcome, AdapterError> {
        let map = self
            .invocations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !map.contains_key(invocation_id) {
            return Err(AdapterError::InvocationNotFound(invocation_id.to_string()));
        }
        Ok(PauseOutcome::DrainToSafeBoundary)
    }

    fn resume_invocation(&self, invocation_id: &str) -> Result<ResumeOutcome, AdapterError> {
        let map = self
            .invocations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !map.contains_key(invocation_id) {
            return Err(AdapterError::InvocationNotFound(invocation_id.to_string()));
        }
        Ok(ResumeOutcome::Resumed)
    }

    fn cancel_invocation(&self, invocation_id: &str) -> Result<CancelOutcome, AdapterError> {
        let mut map = self
            .invocations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (_, status) = map
            .get_mut(invocation_id)
            .ok_or_else(|| AdapterError::InvocationNotFound(invocation_id.to_string()))?;
        *status = AdapterExecutionStatus::Cancelled { acknowledged: true };
        Ok(CancelOutcome::Acknowledged)
    }

    fn poll_status(&self, invocation_id: &str) -> Result<AdapterExecutionStatus, AdapterError> {
        let map = self
            .invocations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        map.get(invocation_id)
            .map(|(_, status)| status.clone())
            .ok_or_else(|| AdapterError::InvocationNotFound(invocation_id.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_synthetic_adapter_truthful_steer_gating() {
        let inv = NodeInvocation {
            invocation_id: "inv-1".to_string(),
            node_id: "node-1".to_string(),
            graph_id: "graph-1".to_string(),
            generation: 1,
            input: json!({"prompt": "hello"}),
            started_at_ms: 1000,
            attempt_token: "att-1".to_string(),
        };

        // 1. Adapter with native in-flight steer support
        let inflight_adapter =
            SyntheticCapabilityAdapter::new("inflight").with_inflight_steer(true);
        inflight_adapter.start_invocation(&inv).unwrap();
        let steer_res = inflight_adapter
            .steer_invocation("inv-1", "do more")
            .unwrap();
        assert_eq!(
            steer_res,
            SteerOutcome::AppliedInFlight {
                instruction: "do more".to_string()
            }
        );

        // 2. Adapter without in-flight steer but declaring Steer capability
        let follow_up_adapter = SyntheticCapabilityAdapter::new("followup")
            .with_capabilities([NodeCapability::Submit, NodeCapability::Steer]);
        follow_up_adapter.start_invocation(&inv).unwrap();
        let steer_res2 = follow_up_adapter
            .steer_invocation("inv-1", "do more")
            .unwrap();
        assert_eq!(
            steer_res2,
            SteerOutcome::SafeBoundaryFollowUp {
                follow_up_instruction: "do more".to_string()
            }
        );

        // 3. Adapter without Steer capability
        let no_steer_adapter =
            SyntheticCapabilityAdapter::new("nosteer").with_capabilities([NodeCapability::Submit]);
        no_steer_adapter.start_invocation(&inv).unwrap();
        let steer_res3 = no_steer_adapter
            .steer_invocation("inv-1", "do more")
            .unwrap();
        assert_eq!(steer_res3, SteerOutcome::Unsupported);
    }

    #[test]
    fn test_synthetic_adapter_truthful_pause_gating() {
        let inv = NodeInvocation {
            invocation_id: "inv-2".to_string(),
            node_id: "node-2".to_string(),
            graph_id: "graph-1".to_string(),
            generation: 1,
            input: json!({"task": "work"}),
            started_at_ms: 1000,
            attempt_token: "att-2".to_string(),
        };

        // 1. In-flight pause supported
        let pause_adapter = SyntheticCapabilityAdapter::new("pause-supp").with_inflight_pause(true);
        pause_adapter.start_invocation(&inv).unwrap();
        let p_res = pause_adapter.pause_invocation("inv-2").unwrap();
        assert_eq!(p_res, PauseOutcome::SuspendedInFlight);
        assert_eq!(
            pause_adapter.poll_status("inv-2").unwrap(),
            AdapterExecutionStatus::Suspended
        );

        // Resume
        let r_res = pause_adapter.resume_invocation("inv-2").unwrap();
        assert_eq!(r_res, ResumeOutcome::Resumed);
        assert_eq!(
            pause_adapter.poll_status("inv-2").unwrap(),
            AdapterExecutionStatus::Running
        );

        // 2. Cooperative drain on pause
        let drain_adapter = SyntheticCapabilityAdapter::new("drain-supp")
            .with_capabilities([NodeCapability::Submit, NodeCapability::Pause]);
        drain_adapter.start_invocation(&inv).unwrap();
        let p_res2 = drain_adapter.pause_invocation("inv-2").unwrap();
        assert_eq!(p_res2, PauseOutcome::DrainToSafeBoundary);

        // 3. Pause unsupported
        let no_pause_adapter =
            SyntheticCapabilityAdapter::new("no-pause").with_capabilities([NodeCapability::Submit]);
        no_pause_adapter.start_invocation(&inv).unwrap();
        let p_res3 = no_pause_adapter.pause_invocation("inv-2").unwrap();
        assert_eq!(p_res3, PauseOutcome::Unsupported);
    }

    #[test]
    fn test_single_writer_session_registry_enforces_exclusive_binding() {
        let registry = SingleWriterSessionRegistry::new();
        let session = "native-session-42";

        // Node A acquires writer
        assert!(registry.acquire_writer(session, "node-A").is_ok());
        assert_eq!(registry.current_writer(session), Some("node-A".to_string()));

        // Node A re-acquiring is fine (idempotent for same node)
        assert!(registry.acquire_writer(session, "node-A").is_ok());

        // Node B attempting to acquire same session fails with conflict
        let err = registry.acquire_writer(session, "node-B").unwrap_err();
        assert!(matches!(
            err,
            AdapterError::SingleWriterConflict {
                session_id,
                active_node_id,
            } if session_id == session && active_node_id == "node-A"
        ));

        // Release by Node A
        registry.release_writer(session, "node-A");
        assert_eq!(registry.current_writer(session), None);

        // Node B can now acquire
        assert!(registry.acquire_writer(session, "node-B").is_ok());
        assert_eq!(registry.current_writer(session), Some("node-B".to_string()));
    }

    #[test]
    fn test_cooperative_drain_adapter_truthful_reporting() {
        let adapter = CooperativeDrainAdapter::new("coop-drain");
        assert!(
            adapter
                .declared_capabilities()
                .contains(&NodeCapability::Steer)
        );
        assert!(!adapter.supports_inflight_steer());
        assert!(!adapter.supports_inflight_pause());
        assert!(adapter.supports_cooperative_cancel());

        let inv = NodeInvocation {
            invocation_id: "inv-coop".to_string(),
            node_id: "node-coop".to_string(),
            graph_id: "graph-coop".to_string(),
            generation: 1,
            input: json!({"run": true}),
            started_at_ms: 100,
            attempt_token: "att-coop".to_string(),
        };

        adapter.start_invocation(&inv).unwrap();

        // Steer returns safe-boundary follow-up without killing process
        let steer = adapter
            .steer_invocation("inv-coop", "update instruction")
            .unwrap();
        assert_eq!(
            steer,
            SteerOutcome::SafeBoundaryFollowUp {
                follow_up_instruction: "update instruction".to_string()
            }
        );

        // Pause drains to safe boundary
        let pause = adapter.pause_invocation("inv-coop").unwrap();
        assert_eq!(pause, PauseOutcome::DrainToSafeBoundary);

        // Cancellation acknowledged
        let cancel = adapter.cancel_invocation("inv-coop").unwrap();
        assert_eq!(cancel, CancelOutcome::Acknowledged);
    }
}
