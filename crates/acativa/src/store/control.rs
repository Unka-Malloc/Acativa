//! Controlled admission: verified principal, controlled store, and explicit
//! conflict resolution.
//!
//! Every local or peer actor operation that mutates a controlled resource or
//! its nodes enters admission. Admission validates the verified principal,
//! resource scope, operation, target selector, and expected revisions, then
//! durably records the command. It never calls an actor directly or bypasses
//! the queue.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Display, Formatter};

use crate::routing::QueueCapacityExceeded;

/// Operation-scoped authorization grant.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum OperationGrant {
    /// Full administrative control over all graphs.
    GraphAll,
    /// Control over a specific graph instance.
    GraphControl { graph_id: String },
    /// Control over a specific node within a graph.
    NodeControl { graph_id: String, node_id: String },
    /// Read/inspect access to a specific graph.
    ReadScope { graph_id: String },
}

impl OperationGrant {
    /// Whether this held grant covers the required grant.
    pub fn covers(&self, required: &OperationGrant) -> bool {
        if self == required {
            return true;
        }
        match self {
            Self::GraphAll => true,
            Self::GraphControl { graph_id } => match required {
                OperationGrant::NodeControl {
                    graph_id: required_graph,
                    ..
                }
                | OperationGrant::ReadScope {
                    graph_id: required_graph,
                } => graph_id == required_graph,
                _ => false,
            },
            _ => false,
        }
    }
}

/// Verified principal constructing an internal, non-serializable proof of authority.
///
/// Notice: `VerifiedPrincipal` deliberately does NOT implement `Deserialize`.
/// A remote payload cannot forge or select an administrative identity or member
/// to bypass endpoint verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerifiedPrincipal {
    /// In-process local administrator authority.
    LocalAdmin { session_id: String },
    /// Authenticated local user session.
    LocalUser {
        user_id: String,
        session_id: String,
        grants: BTreeSet<OperationGrant>,
    },
    /// Authenticated remote peer session.
    PeerSession {
        peer_id: String,
        authenticated_member_id: String,
        grants: BTreeSet<OperationGrant>,
    },
}

impl VerifiedPrincipal {
    /// Construct a verified local administrator principal.
    pub fn local_admin(session_id: impl Into<String>) -> Self {
        Self::LocalAdmin {
            session_id: session_id.into(),
        }
    }

    /// Construct an authenticated local user principal with initial grants.
    pub fn local_user(
        user_id: impl Into<String>,
        session_id: impl Into<String>,
        grants: impl IntoIterator<Item = OperationGrant>,
    ) -> Self {
        Self::LocalUser {
            user_id: user_id.into(),
            session_id: session_id.into(),
            grants: grants.into_iter().collect(),
        }
    }

    /// Construct an authenticated remote peer principal with initial grants.
    pub fn peer_session(
        peer_id: impl Into<String>,
        member_id: impl Into<String>,
        grants: impl IntoIterator<Item = OperationGrant>,
    ) -> Self {
        Self::PeerSession {
            peer_id: peer_id.into(),
            authenticated_member_id: member_id.into(),
            grants: grants.into_iter().collect(),
        }
    }

    /// Primary identity string for attribution and audit.
    pub fn principal_id(&self) -> String {
        match self {
            Self::LocalAdmin { session_id } => format!("local_admin:{}", session_id),
            Self::LocalUser { user_id, .. } => format!("user:{}", user_id),
            Self::PeerSession {
                peer_id,
                authenticated_member_id,
                ..
            } => {
                format!("peer:{}:{}", peer_id, authenticated_member_id)
            }
        }
    }

    /// Check if this principal is a local administrator.
    pub fn is_local_admin(&self) -> bool {
        matches!(self, Self::LocalAdmin { .. })
    }

    /// Held grants that cover the required grant.
    ///
    /// A local administrator's authority is implicit rather than grant-based,
    /// so this returns an empty set for it even though [`Self::has_grant`]
    /// reports true.
    pub fn covering_grants<'a>(&'a self, required: &OperationGrant) -> Vec<&'a OperationGrant> {
        match self {
            Self::LocalAdmin { .. } => Vec::new(),
            Self::LocalUser { grants, .. } | Self::PeerSession { grants, .. } => grants
                .iter()
                .filter(|grant| grant.covers(required))
                .collect(),
        }
    }

    /// Check if this principal holds the requested grant.
    pub fn has_grant(&self, required: &OperationGrant) -> bool {
        self.is_local_admin() || !self.covering_grants(required).is_empty()
    }
}

/// Scope of a control command.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ControlScope {
    Graph,
    Node(String),
    Invocation {
        node_id: String,
        invocation_id: String,
    },
}

/// Semantic control operations entering the admission queue.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ControlOperation {
    /// Submit a task input to an admitted node.
    SubmitTask { input: Value },
    /// Steer an in-flight invocation with new instructions.
    Steer {
        invocation_id: String,
        instruction: String,
        #[serde(default)]
        follow_up: bool,
    },
    /// Request cooperative pause / drain for the given scope.
    Pause { scope: ControlScope },
    /// Resume an admitted waiting or suspended scope.
    Resume { scope: ControlScope },
    /// Cooperatively request termination for the scope.
    Stop { scope: ControlScope, reason: String },
    /// Submit a decision for a pending callback edge.
    CallbackDecision {
        callback_id: String,
        decision: String,
        payload: Value,
    },
    /// Propose a structural change or new revision.
    StructuralProposal {
        definition_digest: String,
        proposed_revision: u64,
        content: Value,
    },
}

impl ControlOperation {
    /// Determine required grant for this operation.
    pub fn required_grant(&self, graph_id: &str, target_node: Option<&str>) -> OperationGrant {
        match self {
            Self::SubmitTask { .. } => {
                if let Some(node) = target_node {
                    OperationGrant::NodeControl {
                        graph_id: graph_id.to_string(),
                        node_id: node.to_string(),
                    }
                } else {
                    OperationGrant::GraphControl {
                        graph_id: graph_id.to_string(),
                    }
                }
            }
            Self::Steer { .. } => {
                if let Some(node) = target_node {
                    OperationGrant::NodeControl {
                        graph_id: graph_id.to_string(),
                        node_id: node.to_string(),
                    }
                } else {
                    OperationGrant::GraphControl {
                        graph_id: graph_id.to_string(),
                    }
                }
            }
            Self::Pause { scope } | Self::Resume { scope } | Self::Stop { scope, .. } => {
                match scope {
                    ControlScope::Graph => OperationGrant::GraphControl {
                        graph_id: graph_id.to_string(),
                    },
                    ControlScope::Node(node) | ControlScope::Invocation { node_id: node, .. } => {
                        OperationGrant::NodeControl {
                            graph_id: graph_id.to_string(),
                            node_id: node.clone(),
                        }
                    }
                }
            }
            Self::CallbackDecision { .. } => OperationGrant::GraphControl {
                graph_id: graph_id.to_string(),
            },
            Self::StructuralProposal { .. } => OperationGrant::GraphControl {
                graph_id: graph_id.to_string(),
            },
        }
    }
}

/// Admission request submitted to the Intervention Proxy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdmissionRequest {
    /// Unique client request ID / idempotency key.
    pub request_id: String,
    /// Target graph identity.
    pub graph_id: String,
    /// Optional target node identity.
    pub target_node_id: Option<String>,
    /// Expected graph definition revision.
    pub expected_graph_revision: Option<u64>,
    /// Expected control revision on target node / invocation.
    pub expected_control_revision: Option<u64>,
    /// Expected target lifecycle generation.
    pub expected_target_generation: Option<u64>,
    /// Semantic operation to admit.
    pub operation: ControlOperation,
    /// Submission timestamp.
    pub timestamp_unix_ms: i64,
}

impl AdmissionRequest {
    /// Compute a canonical cryptographic hash of the logical operation payload.
    pub fn payload_digest(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.graph_id.as_bytes());
        if let Some(node) = &self.target_node_id {
            hasher.update(node.as_bytes());
        }
        let serialized_op =
            serde_json::to_vec(&self.operation).unwrap_or_else(|_| b"invalid_op".to_vec());
        hasher.update(&serialized_op);
        format!("{:x}", hasher.finalize())
    }
}

/// Durable receipt issued upon successful admission into the queue.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdmissionReceipt {
    /// Monotonically increasing queue admission sequence.
    pub admitted_sequence: u64,
    /// Caller request ID.
    pub request_id: String,
    /// Target graph ID.
    pub graph_id: String,
    /// Optional target node ID.
    pub target_node_id: Option<String>,
    /// Author attribution identity.
    pub author_principal_id: String,
    /// Timestamp when admitted to the queue.
    pub admitted_at_unix_ms: i64,
    /// Admitted operation.
    pub operation: ControlOperation,
    /// Committed graph revision at admission time.
    pub graph_revision: u64,
    /// Committed control revision for the affected target scope.
    pub control_revision: u64,
    /// Whether this receipt is an idempotent replay of an earlier admission.
    pub is_replay: bool,
}

/// Explicit typed conflict when admission is rejected.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "conflictType")]
pub enum AdmissionConflict {
    /// Reusing an existing request_id for different command content.
    IdempotencyMismatch {
        request_id: String,
        existing_author: String,
        reason: String,
    },
    /// Edit or proposal based on a stale graph revision.
    RevisionConflict {
        expected: u64,
        current: u64,
        reason: String,
    },
    /// Contradictory exclusive controls on the same node/invocation.
    ControlRevisionConflict {
        target_node_id: String,
        expected: u64,
        current: u64,
        reason: String,
    },
    /// Stop-requested is monotonic; later steer or resume cannot resurrect it.
    StopMonotonicViolation { target: String, reason: String },
    /// Steer arrived after completion committed; invocation already settled.
    InvocationSettled {
        target_node_id: String,
        invocation_id: String,
        reason: String,
    },
    /// Resume arrived while pause is being negotiated.
    PendingTransition {
        target: String,
        current_state: String,
        pending_action: String,
    },
    /// Principal lacks required grant or grant was revoked.
    PermissionDenied {
        principal_id: String,
        graph_id: String,
        reason: String,
    },
    /// Target lifecycle generation is stale.
    StaleTargetGeneration {
        target: String,
        expected_generation: u64,
        current_generation: u64,
    },
    /// Graph scope admission barrier prevents new tasks from starting.
    ScopeAdmissionBarrier { graph_id: String, reason: String },
    /// The durable admission transaction could not be committed.
    Storage { reason: String },
    /// The durable control queue has reached its configured bounds.
    QueueCapacity(QueueCapacityExceeded),
}

impl Display for AdmissionConflict {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IdempotencyMismatch {
                request_id, reason, ..
            } => {
                write!(
                    formatter,
                    "idempotency mismatch for {}: {}",
                    request_id, reason
                )
            }
            Self::RevisionConflict {
                expected,
                current,
                reason,
            } => {
                write!(
                    formatter,
                    "revision conflict (expected {}, current {}): {}",
                    expected, current, reason
                )
            }
            Self::ControlRevisionConflict {
                target_node_id,
                expected,
                current,
                reason,
            } => {
                write!(
                    formatter,
                    "control revision conflict on {} (expected {}, current {}): {}",
                    target_node_id, expected, current, reason
                )
            }
            Self::StopMonotonicViolation { target, reason } => {
                write!(
                    formatter,
                    "stop monotonic violation on {}: {}",
                    target, reason
                )
            }
            Self::InvocationSettled {
                target_node_id,
                invocation_id,
                reason,
            } => {
                write!(
                    formatter,
                    "invocation {} on {} already settled: {}",
                    invocation_id, target_node_id, reason
                )
            }
            Self::PendingTransition {
                target,
                current_state,
                pending_action,
            } => {
                write!(
                    formatter,
                    "pending transition on {} (state: {}, pending: {})",
                    target, current_state, pending_action
                )
            }
            Self::PermissionDenied {
                principal_id,
                graph_id,
                reason,
            } => {
                write!(
                    formatter,
                    "permission denied for {} on {}: {}",
                    principal_id, graph_id, reason
                )
            }
            Self::StaleTargetGeneration {
                target,
                expected_generation,
                current_generation,
            } => {
                write!(
                    formatter,
                    "stale generation on {} (expected {}, current {})",
                    target, expected_generation, current_generation
                )
            }
            Self::ScopeAdmissionBarrier { graph_id, reason } => {
                write!(
                    formatter,
                    "scope admission barrier active on {}: {}",
                    graph_id, reason
                )
            }
            Self::Storage { reason } => write!(formatter, "durable admission failed: {reason}"),
            Self::QueueCapacity(capacity) => write!(formatter, "{capacity}"),
        }
    }
}

impl std::error::Error for AdmissionConflict {}

/// Every storage-layer failure maps to `Storage`: an admission decided on a
/// failed read would be a fail-open gate.
impl From<anyhow::Error> for AdmissionConflict {
    fn from(error: anyhow::Error) -> Self {
        Self::Storage {
            reason: error.to_string(),
        }
    }
}

impl From<rusqlite::Error> for AdmissionConflict {
    fn from(error: rusqlite::Error) -> Self {
        Self::Storage {
            reason: error.to_string(),
        }
    }
}

impl From<serde_json::Error> for AdmissionConflict {
    fn from(error: serde_json::Error) -> Self {
        Self::Storage {
            reason: error.to_string(),
        }
    }
}

/// Port/contract for the controlled store managing graph state, revisions, and admission log.
///
/// Every read fails closed: a lookup error is `Err(Storage)`, never a quiet
/// "not revoked" or "not stopped" answer.
pub trait ControlledStore: Send + Sync {
    /// Return the current graph definition revision if the graph exists.
    fn get_graph_revision(&self, graph_id: &str) -> Result<Option<u64>, AdmissionConflict>;

    /// Return the current control revision for the specified node.
    fn get_node_control_revision(
        &self,
        graph_id: &str,
        node_id: &str,
    ) -> Result<Option<u64>, AdmissionConflict>;

    /// Check if the invocation has already completed/settled.
    fn is_invocation_settled(
        &self,
        graph_id: &str,
        node_id: &str,
        invocation_id: &str,
    ) -> Result<bool, AdmissionConflict>;

    /// Check if stop has already been requested for this target (node or graph).
    fn is_stop_requested(&self, graph_id: &str, target: &str) -> Result<bool, AdmissionConflict>;

    /// Check if pause is currently being negotiated for this target.
    fn is_pause_negotiating(&self, graph_id: &str, target: &str)
    -> Result<bool, AdmissionConflict>;

    /// Check if a graph-scope admission barrier is currently active.
    fn is_graph_barrier_active(&self, graph_id: &str) -> Result<bool, AdmissionConflict>;

    /// Return the target's current lifecycle generation.
    fn get_target_generation(
        &self,
        graph_id: &str,
        target: &str,
    ) -> Result<Option<u64>, AdmissionConflict>;

    /// Check if a grant has been dynamically revoked for this principal.
    fn is_grant_revoked(
        &self,
        principal_id: &str,
        grant: &OperationGrant,
    ) -> Result<bool, AdmissionConflict>;

    /// Look up an idempotency record by request_id.
    fn find_idempotency_record(
        &self,
        request_id: &str,
    ) -> Result<Option<(AdmissionReceipt, String)>, AdmissionConflict>;

    /// Durably commit an admitted command to the queue.
    ///
    /// The store assigns the monotonically increasing admission sequence on
    /// the receipt, persists the admitted control revision of the target
    /// node, and records the stop/pause negotiation facts implied by the
    /// operation. `expected_control_revision` and every fence in `fences`
    /// are re-verified inside the committing transaction, so a revocation,
    /// stop, pause, barrier, or generation change committed between the
    /// proxy's prechecks and this commit cannot admit a stale operation;
    /// the committed revision the store assigned lands on
    /// `receipt.control_revision`.
    fn record_admission(
        &mut self,
        receipt: &mut AdmissionReceipt,
        payload_digest: String,
        expected_control_revision: Option<u64>,
        fences: &AdmissionFences,
    ) -> Result<(), AdmissionConflict>;
}

/// The admission predicates `record_admission` re-evaluates under the same
/// lock that writes the admission. What the proxy checked before opening
/// the transaction is a preview; these fences are the authoritative read.
#[derive(Clone, Debug, Default)]
pub struct AdmissionFences {
    /// Principal the operation was authorized as.
    pub principal_id: String,
    /// Every grant the principal holds that covers the required grant. An
    /// empty set marks implicit local-admin authority, which grants cannot
    /// revoke; a non-empty set admits only while at least one entry stays
    /// unrevoked.
    pub covering_grants: Vec<OperationGrant>,
    /// Stop/pause fence key for the operation's scope.
    pub target_scope: String,
    /// Invocation-level stop key (`node/invocation`) when the operation
    /// addresses a single invocation.
    pub invocation_scope: Option<String>,
    /// Caller's expected graph definition revision, when supplied.
    pub expected_graph_revision: Option<u64>,
    /// Caller's expected target lifecycle generation, when supplied.
    pub expected_target_generation: Option<u64>,
}

/// The fence state one recheck observes, gathered under the store's write
/// lock. `evaluate_fences` turns facts into the same conflict the
/// pre-commit checks would have raised.
#[derive(Clone, Debug)]
pub(crate) struct FenceFacts {
    pub covering_grants_all_revoked: bool,
    pub barrier_active: bool,
    pub stopped_scope: Option<String>,
    pub invocation_settled: bool,
    pub pause_negotiating: bool,
    pub graph_revision: u64,
    pub target_generation: u64,
}

/// Authoritative fence evaluation: identical conflicts to the proxy's
/// prechecks, raised inside the committing transaction.
pub(crate) fn evaluate_fences(
    receipt: &AdmissionReceipt,
    fences: &AdmissionFences,
    facts: FenceFacts,
) -> Result<(), AdmissionConflict> {
    if !fences.covering_grants.is_empty() && facts.covering_grants_all_revoked {
        return Err(AdmissionConflict::PermissionDenied {
            principal_id: fences.principal_id.clone(),
            graph_id: receipt.graph_id.clone(),
            reason: "operation grant has been revoked".to_string(),
        });
    }
    if facts.barrier_active
        && let ControlOperation::SubmitTask { .. } = receipt.operation
    {
        return Err(AdmissionConflict::ScopeAdmissionBarrier {
            graph_id: receipt.graph_id.clone(),
            reason: "graph scope admission barrier active; new tasks blocked".to_string(),
        });
    }
    if let Some(target) = facts.stopped_scope {
        match &receipt.operation {
            ControlOperation::Steer { .. } | ControlOperation::Resume { .. } => {
                return Err(AdmissionConflict::StopMonotonicViolation {
                    target,
                    reason:
                        "stop-requested is monotonic; later steer or resume cannot resurrect it"
                            .to_string(),
                });
            }
            // Stop-requested prevents new work in the scope; a new task
            // needs its own identity and an admitting scope.
            ControlOperation::SubmitTask { .. } => {
                return Err(AdmissionConflict::StopMonotonicViolation {
                    target,
                    reason: "stop-requested scope does not admit new work".to_string(),
                });
            }
            _ => {}
        }
    }
    if let ControlOperation::Steer { invocation_id, .. } = &receipt.operation
        && let Some(node) = receipt.target_node_id.as_deref()
        && facts.invocation_settled
    {
        return Err(AdmissionConflict::InvocationSettled {
            target_node_id: node.to_string(),
            invocation_id: invocation_id.clone(),
            reason: "invocation already completed before steer arrived".to_string(),
        });
    }
    if let ControlOperation::Resume { .. } = receipt.operation
        && facts.pause_negotiating
    {
        return Err(AdmissionConflict::PendingTransition {
            target: fences.target_scope.clone(),
            current_state: "pause_negotiating".to_string(),
            pending_action: "drain_in_progress".to_string(),
        });
    }
    if let Some(expected_rev) = fences.expected_graph_revision
        && expected_rev != facts.graph_revision
    {
        return Err(AdmissionConflict::RevisionConflict {
            expected: expected_rev,
            current: facts.graph_revision,
            reason: "stale graph revision; proposal must rebase".to_string(),
        });
    }
    if let Some(expected_gen) = fences.expected_target_generation
        && expected_gen != facts.target_generation
    {
        return Err(AdmissionConflict::StaleTargetGeneration {
            target: fences.target_scope.clone(),
            expected_generation: expected_gen,
            current_generation: facts.target_generation,
        });
    }
    Ok(())
}

/// In-memory controlled store implementing `ControlledStore` for tests and isolated execution.
#[derive(Clone, Debug, Default)]
pub struct InMemoryControlledStore {
    pub graph_revisions: BTreeMap<String, u64>,
    pub node_control_revisions: BTreeMap<(String, String), u64>,
    pub settled_invocations: BTreeSet<(String, String, String)>,
    pub stop_requested_targets: BTreeSet<(String, String)>,
    pub pause_negotiating_targets: BTreeSet<(String, String)>,
    pub graph_barriers: BTreeSet<String>,
    pub target_generations: BTreeMap<(String, String), u64>,
    pub revoked_grants: BTreeSet<(String, OperationGrant)>,
    pub idempotency_log: BTreeMap<String, (AdmissionReceipt, String)>,
    pub admitted_queue: Vec<AdmissionReceipt>,
    pub next_sequence: u64,
}

impl InMemoryControlledStore {
    pub fn new() -> Self {
        Self {
            next_sequence: 1,
            ..Default::default()
        }
    }

    pub fn set_graph_revision(&mut self, graph_id: impl Into<String>, revision: u64) {
        self.graph_revisions.insert(graph_id.into(), revision);
    }

    pub fn set_node_control_revision(
        &mut self,
        graph_id: impl Into<String>,
        node_id: impl Into<String>,
        revision: u64,
    ) {
        self.node_control_revisions
            .insert((graph_id.into(), node_id.into()), revision);
    }

    pub fn mark_invocation_settled(
        &mut self,
        graph_id: impl Into<String>,
        node_id: impl Into<String>,
        invocation_id: impl Into<String>,
    ) {
        self.settled_invocations
            .insert((graph_id.into(), node_id.into(), invocation_id.into()));
    }

    pub fn mark_stop_requested(&mut self, graph_id: impl Into<String>, target: impl Into<String>) {
        self.stop_requested_targets
            .insert((graph_id.into(), target.into()));
    }

    pub fn mark_pause_negotiating(
        &mut self,
        graph_id: impl Into<String>,
        target: impl Into<String>,
    ) {
        self.pause_negotiating_targets
            .insert((graph_id.into(), target.into()));
    }

    pub fn clear_pause_negotiating(&mut self, graph_id: &str, target: &str) {
        self.pause_negotiating_targets
            .remove(&(graph_id.to_string(), target.to_string()));
    }

    pub fn set_graph_barrier(&mut self, graph_id: impl Into<String>, active: bool) {
        if active {
            self.graph_barriers.insert(graph_id.into());
        } else {
            self.graph_barriers.remove(&graph_id.into());
        }
    }

    pub fn set_target_generation(
        &mut self,
        graph_id: impl Into<String>,
        target: impl Into<String>,
        generation: u64,
    ) {
        self.target_generations
            .insert((graph_id.into(), target.into()), generation);
    }

    pub fn revoke_grant(&mut self, principal_id: impl Into<String>, grant: OperationGrant) {
        self.revoked_grants.insert((principal_id.into(), grant));
    }
}

impl ControlledStore for InMemoryControlledStore {
    fn get_graph_revision(&self, graph_id: &str) -> Result<Option<u64>, AdmissionConflict> {
        Ok(self.graph_revisions.get(graph_id).copied())
    }

    fn get_node_control_revision(
        &self,
        graph_id: &str,
        node_id: &str,
    ) -> Result<Option<u64>, AdmissionConflict> {
        Ok(self
            .node_control_revisions
            .get(&(graph_id.to_string(), node_id.to_string()))
            .copied())
    }

    fn is_invocation_settled(
        &self,
        graph_id: &str,
        node_id: &str,
        invocation_id: &str,
    ) -> Result<bool, AdmissionConflict> {
        Ok(self.settled_invocations.contains(&(
            graph_id.to_string(),
            node_id.to_string(),
            invocation_id.to_string(),
        )))
    }

    fn is_stop_requested(&self, graph_id: &str, target: &str) -> Result<bool, AdmissionConflict> {
        Ok(self
            .stop_requested_targets
            .contains(&(graph_id.to_string(), target.to_string()))
            || self
                .stop_requested_targets
                .contains(&(graph_id.to_string(), "graph".to_string())))
    }

    fn is_pause_negotiating(
        &self,
        graph_id: &str,
        target: &str,
    ) -> Result<bool, AdmissionConflict> {
        Ok(self
            .pause_negotiating_targets
            .contains(&(graph_id.to_string(), target.to_string())))
    }

    fn is_graph_barrier_active(&self, graph_id: &str) -> Result<bool, AdmissionConflict> {
        Ok(self.graph_barriers.contains(graph_id))
    }

    fn get_target_generation(
        &self,
        graph_id: &str,
        target: &str,
    ) -> Result<Option<u64>, AdmissionConflict> {
        Ok(self
            .target_generations
            .get(&(graph_id.to_string(), target.to_string()))
            .copied())
    }

    fn is_grant_revoked(
        &self,
        principal_id: &str,
        grant: &OperationGrant,
    ) -> Result<bool, AdmissionConflict> {
        Ok(self
            .revoked_grants
            .contains(&(principal_id.to_string(), grant.clone())))
    }

    fn find_idempotency_record(
        &self,
        request_id: &str,
    ) -> Result<Option<(AdmissionReceipt, String)>, AdmissionConflict> {
        Ok(self.idempotency_log.get(request_id).cloned())
    }

    fn record_admission(
        &mut self,
        receipt: &mut AdmissionReceipt,
        payload_digest: String,
        expected_control_revision: Option<u64>,
        fences: &AdmissionFences,
    ) -> Result<(), AdmissionConflict> {
        // Re-evaluate the fences the proxy previewed: this commit is the
        // authoritative read, so a fence raised since the prechecks still
        // rejects the operation.
        let stopped_scope = if self
            .stop_requested_targets
            .contains(&(receipt.graph_id.clone(), fences.target_scope.clone()))
            || self
                .stop_requested_targets
                .contains(&(receipt.graph_id.clone(), "graph".to_string()))
        {
            Some(fences.target_scope.clone())
        } else {
            fences.invocation_scope.clone().filter(|key| {
                self.stop_requested_targets
                    .contains(&(receipt.graph_id.clone(), key.clone()))
            })
        };
        evaluate_fences(
            receipt,
            fences,
            FenceFacts {
                covering_grants_all_revoked: !fences.covering_grants.is_empty()
                    && fences.covering_grants.iter().all(|grant| {
                        self.revoked_grants
                            .contains(&(fences.principal_id.clone(), grant.clone()))
                    }),
                barrier_active: self.graph_barriers.contains(&receipt.graph_id),
                stopped_scope,
                invocation_settled: matches!(&receipt.operation, ControlOperation::Steer { .. })
                    && receipt.target_node_id.as_ref().is_some_and(|node| {
                        match &receipt.operation {
                            ControlOperation::Steer { invocation_id, .. } => {
                                self.settled_invocations.contains(&(
                                    receipt.graph_id.clone(),
                                    node.clone(),
                                    invocation_id.clone(),
                                ))
                            }
                            _ => false,
                        }
                    }),
                pause_negotiating: self
                    .pause_negotiating_targets
                    .contains(&(receipt.graph_id.clone(), fences.target_scope.clone())),
                graph_revision: self
                    .graph_revisions
                    .get(&receipt.graph_id)
                    .copied()
                    .unwrap_or(1),
                target_generation: self
                    .target_generations
                    .get(&(receipt.graph_id.clone(), fences.target_scope.clone()))
                    .copied()
                    .unwrap_or(1),
            },
        )?;
        receipt.graph_revision = self
            .graph_revisions
            .get(&receipt.graph_id)
            .copied()
            .unwrap_or(1);

        // Idempotency is re-checked here so two identical requests committed
        // back-to-back converge on the recorded receipt instead of violating
        // the unique constraint.
        if let Some((existing_receipt, existing_digest)) =
            self.idempotency_log.get(&receipt.request_id).cloned()
        {
            if existing_digest == payload_digest {
                *receipt = existing_receipt;
                receipt.is_replay = true;
                return Ok(());
            }
            return Err(AdmissionConflict::IdempotencyMismatch {
                request_id: receipt.request_id.clone(),
                existing_author: existing_receipt.author_principal_id,
                reason: "request_id reused with different command payload".to_string(),
            });
        }

        receipt.admitted_sequence = self.next_sequence;
        self.next_sequence += 1;

        // Persist the admitted control revision so a competing exclusive
        // control based on the previous revision conflicts; the expected
        // revision is compared at commit, matching the durable store's
        // compare-and-swap.
        if let Some(node) = &receipt.target_node_id {
            let persisted = self
                .node_control_revisions
                .get(&(receipt.graph_id.clone(), node.clone()))
                .copied()
                .unwrap_or(0);
            if let Some(expected) = expected_control_revision
                && expected != persisted
            {
                return Err(AdmissionConflict::ControlRevisionConflict {
                    target_node_id: node.clone(),
                    expected,
                    current: persisted,
                    reason: "competing exclusive control revision conflict".to_string(),
                });
            }
            receipt.control_revision = persisted + 1;
            self.node_control_revisions.insert(
                (receipt.graph_id.clone(), node.clone()),
                receipt.control_revision,
            );
        }

        match &receipt.operation {
            // Record stop-requested at the admitted scope. Invocation-scoped
            // stops use a node/invocation key so sibling invocations of the
            // same node are not fenced.
            ControlOperation::Stop { scope, .. } => {
                let target_str = match scope {
                    ControlScope::Graph => "graph".to_string(),
                    ControlScope::Node(n) => n.clone(),
                    ControlScope::Invocation {
                        node_id,
                        invocation_id,
                    } => format!("{}/{}", node_id, invocation_id),
                };
                self.stop_requested_targets
                    .insert((receipt.graph_id.clone(), target_str));
            }
            // An admitted pause is under negotiation until the safe boundary
            // is observed and the negotiation marker is cleared.
            ControlOperation::Pause { scope } => {
                let target_str = match scope {
                    ControlScope::Graph => "graph".to_string(),
                    ControlScope::Node(n) => n.clone(),
                    ControlScope::Invocation { node_id, .. } => node_id.clone(),
                };
                self.pause_negotiating_targets
                    .insert((receipt.graph_id.clone(), target_str));
            }
            _ => {}
        }

        self.idempotency_log.insert(
            receipt.request_id.clone(),
            (receipt.clone(), payload_digest),
        );
        self.admitted_queue.push(receipt.clone());
        Ok(())
    }
}

/// Intervention Proxy: durably admits operations, enforcing authorization,
/// idempotency, monotonic stops, revision ordering, and queue admission barriers.
pub struct InterventionProxy<S: ControlledStore> {
    store: S,
}

impl<S: ControlledStore> InterventionProxy<S> {
    pub fn new(store: S) -> Self {
        Self { store }
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    /// Authorization effective at use: the principal holds at least one grant
    /// covering the requirement that has not been revoked. A local
    /// administrator's authority is implicit and not grant-revocable here. A
    /// revocation lookup that fails is an error, not a pass: grants are
    /// effective only when the check actually ran.
    fn has_effective_grant(
        &self,
        principal: &VerifiedPrincipal,
        required: &OperationGrant,
    ) -> Result<bool, AdmissionConflict> {
        if principal.is_local_admin() {
            return Ok(true);
        }
        let principal_id = principal.principal_id();
        for grant in principal.covering_grants(required) {
            if !self.store.is_grant_revoked(&principal_id, grant)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Admit an operation through the Proxy into the queue.
    pub fn admit(
        &mut self,
        principal: &VerifiedPrincipal,
        request: AdmissionRequest,
    ) -> Result<AdmissionReceipt, AdmissionConflict> {
        let principal_id = principal.principal_id();
        let target_node = request.target_node_id.as_deref();

        // 1. Authorization & Revocation check
        let required_grant = request
            .operation
            .required_grant(&request.graph_id, target_node);
        if !principal.has_grant(&required_grant) {
            return Err(AdmissionConflict::PermissionDenied {
                principal_id,
                graph_id: request.graph_id,
                reason: "principal does not hold required grant".to_string(),
            });
        }
        if !self.has_effective_grant(principal, &required_grant)? {
            return Err(AdmissionConflict::PermissionDenied {
                principal_id,
                graph_id: request.graph_id,
                reason: "operation grant has been revoked".to_string(),
            });
        }

        // 2. Idempotency verification: Same logical request redelivered
        let payload_digest = request.payload_digest();
        if let Some((existing_receipt, existing_digest)) =
            self.store.find_idempotency_record(&request.request_id)?
        {
            if existing_digest == payload_digest {
                let mut replay = existing_receipt;
                replay.is_replay = true;
                return Ok(replay);
            } else {
                return Err(AdmissionConflict::IdempotencyMismatch {
                    request_id: request.request_id,
                    existing_author: existing_receipt.author_principal_id,
                    reason: "request_id reused with different command payload".to_string(),
                });
            }
        }

        // The stop, pause, barrier, revision and generation fences below are
        // previews only: `record_admission` re-evaluates all of them under
        // the same lock that commits the admission, so a fence committed
        // between here and there still rejects the operation.
        let target_scope_str = match &request.operation {
            ControlOperation::Pause { scope }
            | ControlOperation::Resume { scope }
            | ControlOperation::Stop { scope, .. } => match scope {
                ControlScope::Graph => "graph".to_string(),
                ControlScope::Node(n) => n.clone(),
                ControlScope::Invocation { node_id, .. } => node_id.clone(),
            },
            ControlOperation::Steer { .. } => target_node.unwrap_or("unknown").to_string(),
            _ => target_node.unwrap_or("graph").to_string(),
        };
        // Invocation-scoped stops are recorded under a node/invocation key so
        // stopping one invocation does not fence sibling invocations of the node.
        let invocation_scope_str = match &request.operation {
            ControlOperation::Steer { invocation_id, .. } => {
                target_node.map(|node| format!("{}/{}", node, invocation_id))
            }
            ControlOperation::Resume {
                scope:
                    ControlScope::Invocation {
                        node_id,
                        invocation_id,
                    },
            } => Some(format!("{}/{}", node_id, invocation_id)),
            _ => None,
        };

        // 3. Durable receipt creation & commit. The store fills in
        // `graph_revision` and, for node-scoped operations, the committed
        // `control_revision`; a graph-scoped operation keeps revision 1.
        let graph_scoped = target_node.is_none();
        let fences = AdmissionFences {
            principal_id,
            covering_grants: if principal.is_local_admin() {
                Vec::new()
            } else {
                principal
                    .covering_grants(&required_grant)
                    .into_iter()
                    .cloned()
                    .collect()
            },
            target_scope: target_scope_str,
            invocation_scope: invocation_scope_str,
            expected_graph_revision: request.expected_graph_revision,
            expected_target_generation: request.expected_target_generation,
        };
        let mut receipt = AdmissionReceipt {
            // Assigned from the store's durable sequence counter at commit.
            admitted_sequence: 0,
            request_id: request.request_id,
            graph_id: request.graph_id,
            target_node_id: request.target_node_id,
            author_principal_id: fences.principal_id.clone(),
            admitted_at_unix_ms: request.timestamp_unix_ms,
            operation: request.operation,
            graph_revision: 0,
            control_revision: u64::from(graph_scoped),
            is_replay: false,
        };

        self.store.record_admission(
            &mut receipt,
            payload_digest,
            request.expected_control_revision,
            &fences,
        )?;
        Ok(receipt)
    }

    /// Filter inspected graph read model by the principal's read authority.
    pub fn filter_graph_view<'a>(
        &self,
        principal: &VerifiedPrincipal,
        graph_id: &str,
        raw_graph_data: &'a Value,
    ) -> Result<&'a Value, AdmissionConflict> {
        let read_grant = OperationGrant::ReadScope {
            graph_id: graph_id.to_string(),
        };
        if !principal.has_grant(&read_grant) {
            return Err(AdmissionConflict::PermissionDenied {
                principal_id: principal.principal_id(),
                graph_id: graph_id.to_string(),
                reason: "principal does not have read grant for this graph".to_string(),
            });
        }
        if !self.has_effective_grant(principal, &read_grant)? {
            return Err(AdmissionConflict::PermissionDenied {
                principal_id: principal.principal_id(),
                graph_id: graph_id.to_string(),
                reason: "read grant has been revoked".to_string(),
            });
        }
        Ok(raw_graph_data)
    }

    /// Filter a sequence of admitted receipts, returning only those readable by the principal.
    pub fn filter_admitted_receipts(
        &self,
        principal: &VerifiedPrincipal,
        receipts: &[AdmissionReceipt],
    ) -> Result<Vec<AdmissionReceipt>, AdmissionConflict> {
        let mut visible = Vec::new();
        for receipt in receipts {
            let read_grant = OperationGrant::ReadScope {
                graph_id: receipt.graph_id.clone(),
            };
            if self.has_effective_grant(principal, &read_grant)? {
                visible.push(receipt.clone());
            }
        }
        Ok(visible)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn setup_proxy() -> (InterventionProxy<InMemoryControlledStore>, String) {
        let mut store = InMemoryControlledStore::new();
        let graph_id = "graph-alpha".to_string();
        store.set_graph_revision(&graph_id, 1);
        store.set_node_control_revision(&graph_id, "node-1", 0);
        store.set_target_generation(&graph_id, "node-1", 1);
        (InterventionProxy::new(store), graph_id)
    }

    #[test]
    fn test_verified_principal_grant_hierarchy_and_administrative_authority() {
        let admin = VerifiedPrincipal::local_admin("session-xyz");
        assert!(admin.is_local_admin());
        assert!(admin.has_grant(&OperationGrant::GraphAll));
        assert!(admin.has_grant(&OperationGrant::GraphControl {
            graph_id: "any".to_string()
        }));

        let user = VerifiedPrincipal::local_user(
            "alice",
            "sess-1",
            vec![OperationGrant::GraphControl {
                graph_id: "graph-1".to_string(),
            }],
        );
        assert!(!user.is_local_admin());
        assert!(user.has_grant(&OperationGrant::GraphControl {
            graph_id: "graph-1".to_string()
        }));
        // GraphControl covers NodeControl and ReadScope for the same graph
        assert!(user.has_grant(&OperationGrant::NodeControl {
            graph_id: "graph-1".to_string(),
            node_id: "worker-a".to_string(),
        }));
        assert!(user.has_grant(&OperationGrant::ReadScope {
            graph_id: "graph-1".to_string()
        }));
        // But not other graphs
        assert!(!user.has_grant(&OperationGrant::GraphControl {
            graph_id: "graph-2".to_string()
        }));
    }

    #[test]
    fn test_proxy_admission_success_and_receipt_issuance() {
        let (mut proxy, graph_id) = setup_proxy();
        let principal = VerifiedPrincipal::local_admin("admin-sess");

        let request = AdmissionRequest {
            request_id: "req-001".to_string(),
            graph_id: graph_id.clone(),
            target_node_id: Some("node-1".to_string()),
            expected_graph_revision: Some(1),
            expected_control_revision: Some(0),
            expected_target_generation: Some(1),
            operation: ControlOperation::SubmitTask {
                input: json!({"prompt": "solve problem"}),
            },
            timestamp_unix_ms: 1000,
        };

        let receipt = proxy.admit(&principal, request).expect("should admit");
        assert_eq!(receipt.request_id, "req-001");
        assert_eq!(receipt.graph_id, graph_id);
        assert_eq!(receipt.target_node_id.as_deref(), Some("node-1"));
        assert_eq!(receipt.graph_revision, 1);
        assert_eq!(receipt.control_revision, 1);
        assert!(!receipt.is_replay);
    }

    #[test]
    fn test_idempotent_redelivery_returns_recorded_receipt() {
        let (mut proxy, graph_id) = setup_proxy();
        let principal = VerifiedPrincipal::local_admin("admin-sess");

        let request1 = AdmissionRequest {
            request_id: "req-idem".to_string(),
            graph_id: graph_id.clone(),
            target_node_id: Some("node-1".to_string()),
            expected_graph_revision: Some(1),
            expected_control_revision: Some(0),
            expected_target_generation: Some(1),
            operation: ControlOperation::SubmitTask {
                input: json!({"prompt": "build feature"}),
            },
            timestamp_unix_ms: 1000,
        };

        let receipt1 = proxy
            .admit(&principal, request1.clone())
            .expect("admit first");
        assert!(!receipt1.is_replay);

        // Redeliver identical command with same request_id
        let receipt2 = proxy
            .admit(&principal, request1)
            .expect("replay should succeed");
        assert!(receipt2.is_replay);
        assert_eq!(receipt2.request_id, receipt1.request_id);
        assert_eq!(receipt2.control_revision, receipt1.control_revision);
    }

    #[test]
    fn test_idempotent_redelivery_with_different_payload_conflicts() {
        let (mut proxy, graph_id) = setup_proxy();
        let principal = VerifiedPrincipal::local_admin("admin-sess");

        let request1 = AdmissionRequest {
            request_id: "req-conflict".to_string(),
            graph_id: graph_id.clone(),
            target_node_id: Some("node-1".to_string()),
            expected_graph_revision: Some(1),
            expected_control_revision: Some(0),
            expected_target_generation: Some(1),
            operation: ControlOperation::SubmitTask {
                input: json!({"prompt": "task A"}),
            },
            timestamp_unix_ms: 1000,
        };

        proxy.admit(&principal, request1).expect("first passes");

        // Reusing req-conflict for different operation
        let request2 = AdmissionRequest {
            request_id: "req-conflict".to_string(),
            graph_id: graph_id.clone(),
            target_node_id: Some("node-1".to_string()),
            expected_graph_revision: Some(1),
            expected_control_revision: Some(0),
            expected_target_generation: Some(1),
            operation: ControlOperation::SubmitTask {
                input: json!({"prompt": "task B totally different"}),
            },
            timestamp_unix_ms: 2000,
        };

        let result = proxy.admit(&principal, request2);
        match result {
            Err(AdmissionConflict::IdempotencyMismatch { request_id, .. }) => {
                assert_eq!(request_id, "req-conflict");
            }
            other => panic!("expected IdempotencyMismatch, got {:?}", other),
        }
    }

    #[test]
    fn test_unauthorized_principal_is_rejected() {
        let (mut proxy, graph_id) = setup_proxy();
        let peer = VerifiedPrincipal::peer_session(
            "peer-99",
            "member-remote",
            vec![OperationGrant::ReadScope {
                graph_id: graph_id.clone(),
            }],
        );

        let request = AdmissionRequest {
            request_id: "req-unauth".to_string(),
            graph_id: graph_id.clone(),
            target_node_id: Some("node-1".to_string()),
            expected_graph_revision: None,
            expected_control_revision: None,
            expected_target_generation: None,
            operation: ControlOperation::SubmitTask {
                input: json!({"data": 123}),
            },
            timestamp_unix_ms: 1000,
        };

        let result = proxy.admit(&peer, request);
        match result {
            Err(AdmissionConflict::PermissionDenied { principal_id, .. }) => {
                assert!(principal_id.contains("peer-99"));
            }
            other => panic!("expected PermissionDenied, got {:?}", other),
        }
    }

    #[test]
    fn test_dynamically_revoked_grant_is_rejected() {
        let (mut proxy, graph_id) = setup_proxy();
        let user = VerifiedPrincipal::local_user(
            "bob",
            "sess-bob",
            vec![OperationGrant::NodeControl {
                graph_id: graph_id.clone(),
                node_id: "node-1".to_string(),
            }],
        );

        // Dynamically revoke the grant in the store
        proxy.store_mut().revoke_grant(
            user.principal_id(),
            OperationGrant::NodeControl {
                graph_id: graph_id.clone(),
                node_id: "node-1".to_string(),
            },
        );

        let request = AdmissionRequest {
            request_id: "req-revoked".to_string(),
            graph_id: graph_id.clone(),
            target_node_id: Some("node-1".to_string()),
            expected_graph_revision: None,
            expected_control_revision: None,
            expected_target_generation: None,
            operation: ControlOperation::Steer {
                invocation_id: "inv-1".to_string(),
                instruction: "change path".to_string(),
                follow_up: false,
            },
            timestamp_unix_ms: 1000,
        };

        let result = proxy.admit(&user, request);
        assert!(matches!(
            result,
            Err(AdmissionConflict::PermissionDenied { .. })
        ));
    }

    #[test]
    fn test_stop_requested_is_monotonic_and_blocks_steer_or_resume() {
        let (mut proxy, graph_id) = setup_proxy();
        let admin = VerifiedPrincipal::local_admin("admin");

        // Mark stop-requested on node-1
        proxy.store_mut().mark_stop_requested(&graph_id, "node-1");

        // Steer should be rejected due to monotonic stop
        let steer_req = AdmissionRequest {
            request_id: "req-steer-after-stop".to_string(),
            graph_id: graph_id.clone(),
            target_node_id: Some("node-1".to_string()),
            expected_graph_revision: None,
            expected_control_revision: None,
            expected_target_generation: None,
            operation: ControlOperation::Steer {
                invocation_id: "inv-1".to_string(),
                instruction: "try again".to_string(),
                follow_up: false,
            },
            timestamp_unix_ms: 1000,
        };

        match proxy.admit(&admin, steer_req) {
            Err(AdmissionConflict::StopMonotonicViolation { target, .. }) => {
                assert_eq!(target, "node-1");
            }
            other => panic!("expected StopMonotonicViolation, got {:?}", other),
        }

        // Resume should also be rejected
        let resume_req = AdmissionRequest {
            request_id: "req-resume-after-stop".to_string(),
            graph_id: graph_id.clone(),
            target_node_id: Some("node-1".to_string()),
            expected_graph_revision: None,
            expected_control_revision: None,
            expected_target_generation: None,
            operation: ControlOperation::Resume {
                scope: ControlScope::Node("node-1".to_string()),
            },
            timestamp_unix_ms: 1100,
        };

        match proxy.admit(&admin, resume_req) {
            Err(AdmissionConflict::StopMonotonicViolation { target, .. }) => {
                assert_eq!(target, "node-1");
            }
            other => panic!("expected StopMonotonicViolation, got {:?}", other),
        }
    }

    #[test]
    fn test_steer_races_with_completion_reports_invocation_settled() {
        let (mut proxy, graph_id) = setup_proxy();
        let admin = VerifiedPrincipal::local_admin("admin");

        // Mark invocation inv-abc as already settled
        proxy
            .store_mut()
            .mark_invocation_settled(&graph_id, "node-1", "inv-abc");

        let steer_req = AdmissionRequest {
            request_id: "req-steer-settled".to_string(),
            graph_id: graph_id.clone(),
            target_node_id: Some("node-1".to_string()),
            expected_graph_revision: None,
            expected_control_revision: None,
            expected_target_generation: None,
            operation: ControlOperation::Steer {
                invocation_id: "inv-abc".to_string(),
                instruction: "intervene late".to_string(),
                follow_up: false,
            },
            timestamp_unix_ms: 1000,
        };

        match proxy.admit(&admin, steer_req) {
            Err(AdmissionConflict::InvocationSettled {
                target_node_id,
                invocation_id,
                ..
            }) => {
                assert_eq!(target_node_id, "node-1");
                assert_eq!(invocation_id, "inv-abc");
            }
            other => panic!("expected InvocationSettled, got {:?}", other),
        }
    }

    #[test]
    fn test_resume_during_pause_negotiation_reports_pending_transition() {
        let (mut proxy, graph_id) = setup_proxy();
        let admin = VerifiedPrincipal::local_admin("admin");

        // Mark pause negotiating on node-1
        proxy
            .store_mut()
            .mark_pause_negotiating(&graph_id, "node-1");

        let resume_req = AdmissionRequest {
            request_id: "req-resume-pause".to_string(),
            graph_id: graph_id.clone(),
            target_node_id: Some("node-1".to_string()),
            expected_graph_revision: None,
            expected_control_revision: None,
            expected_target_generation: None,
            operation: ControlOperation::Resume {
                scope: ControlScope::Node("node-1".to_string()),
            },
            timestamp_unix_ms: 1000,
        };

        match proxy.admit(&admin, resume_req) {
            Err(AdmissionConflict::PendingTransition {
                target,
                current_state,
                ..
            }) => {
                assert_eq!(target, "node-1");
                assert_eq!(current_state, "pause_negotiating");
            }
            other => panic!("expected PendingTransition, got {:?}", other),
        }
    }

    #[test]
    fn test_graph_definition_revision_conflict_requires_rebase() {
        let (mut proxy, graph_id) = setup_proxy();
        let admin = VerifiedPrincipal::local_admin("admin");

        // Current graph revision is 1, client expects 0 (stale)
        let request = AdmissionRequest {
            request_id: "req-stale-rev".to_string(),
            graph_id: graph_id.clone(),
            target_node_id: None,
            expected_graph_revision: Some(0),
            expected_control_revision: None,
            expected_target_generation: None,
            operation: ControlOperation::StructuralProposal {
                definition_digest: "sha256-old".to_string(),
                proposed_revision: 2,
                content: json!({"patch": "edit"}),
            },
            timestamp_unix_ms: 1000,
        };

        match proxy.admit(&admin, request) {
            Err(AdmissionConflict::RevisionConflict {
                expected, current, ..
            }) => {
                assert_eq!(expected, 0);
                assert_eq!(current, 1);
            }
            other => panic!("expected RevisionConflict, got {:?}", other),
        }
    }

    #[test]
    fn test_competing_exclusive_node_control_revision_conflicts() {
        let (mut proxy, graph_id) = setup_proxy();
        let admin = VerifiedPrincipal::local_admin("admin");

        // Current control revision is 0, client expects 5
        let request = AdmissionRequest {
            request_id: "req-competing-control".to_string(),
            graph_id: graph_id.clone(),
            target_node_id: Some("node-1".to_string()),
            expected_graph_revision: Some(1),
            expected_control_revision: Some(5),
            expected_target_generation: None,
            operation: ControlOperation::Pause {
                scope: ControlScope::Node("node-1".to_string()),
            },
            timestamp_unix_ms: 1000,
        };

        match proxy.admit(&admin, request) {
            Err(AdmissionConflict::ControlRevisionConflict {
                expected, current, ..
            }) => {
                assert_eq!(expected, 5);
                assert_eq!(current, 0);
            }
            other => panic!("expected ControlRevisionConflict, got {:?}", other),
        }
    }

    #[test]
    fn test_stale_target_generation_rejected() {
        let (mut proxy, graph_id) = setup_proxy();
        let admin = VerifiedPrincipal::local_admin("admin");

        // Current target generation is 1, client expects 0
        let request = AdmissionRequest {
            request_id: "req-stale-gen".to_string(),
            graph_id: graph_id.clone(),
            target_node_id: Some("node-1".to_string()),
            expected_graph_revision: None,
            expected_control_revision: None,
            expected_target_generation: Some(0),
            operation: ControlOperation::Pause {
                scope: ControlScope::Node("node-1".to_string()),
            },
            timestamp_unix_ms: 1000,
        };

        match proxy.admit(&admin, request) {
            Err(AdmissionConflict::StaleTargetGeneration {
                expected_generation,
                current_generation,
                ..
            }) => {
                assert_eq!(expected_generation, 0);
                assert_eq!(current_generation, 1);
            }
            other => panic!("expected StaleTargetGeneration, got {:?}", other),
        }
    }

    #[test]
    fn test_graph_scope_admission_barrier_blocks_new_task_submission() {
        let (mut proxy, graph_id) = setup_proxy();
        let admin = VerifiedPrincipal::local_admin("admin");

        // Activate barrier
        proxy.store_mut().set_graph_barrier(&graph_id, true);

        let submit_req = AdmissionRequest {
            request_id: "req-submit-blocked".to_string(),
            graph_id: graph_id.clone(),
            target_node_id: Some("node-1".to_string()),
            expected_graph_revision: None,
            expected_control_revision: None,
            expected_target_generation: None,
            operation: ControlOperation::SubmitTask {
                input: json!({"task": 1}),
            },
            timestamp_unix_ms: 1000,
        };

        match proxy.admit(&admin, submit_req) {
            Err(AdmissionConflict::ScopeAdmissionBarrier { graph_id: gid, .. }) => {
                assert_eq!(gid, graph_id);
            }
            other => panic!("expected ScopeAdmissionBarrier, got {:?}", other),
        }
    }

    #[test]
    fn test_read_model_and_receipt_filtering_enforces_read_scopes() {
        let (proxy, graph_id) = setup_proxy();
        let authorized_user = VerifiedPrincipal::local_user(
            "alice",
            "sess-1",
            vec![OperationGrant::ReadScope {
                graph_id: graph_id.clone(),
            }],
        );
        let unauthorized_user = VerifiedPrincipal::local_user(
            "charlie",
            "sess-2",
            vec![OperationGrant::ReadScope {
                graph_id: "other-graph".to_string(),
            }],
        );

        let raw_graph = json!({"id": graph_id, "nodes": ["node-1"]});

        // Authorized user can view graph
        let viewed = proxy
            .filter_graph_view(&authorized_user, &graph_id, &raw_graph)
            .expect("should view");
        assert_eq!(viewed["id"], graph_id);

        // Unauthorized user is rejected
        let denied = proxy.filter_graph_view(&unauthorized_user, &graph_id, &raw_graph);
        assert!(matches!(
            denied,
            Err(AdmissionConflict::PermissionDenied { .. })
        ));

        // Receipt filtering
        let receipt1 = AdmissionReceipt {
            admitted_sequence: 1,
            request_id: "r1".to_string(),
            graph_id: graph_id.clone(),
            target_node_id: None,
            author_principal_id: "admin".to_string(),
            admitted_at_unix_ms: 1000,
            operation: ControlOperation::Pause {
                scope: ControlScope::Graph,
            },
            graph_revision: 1,
            control_revision: 1,
            is_replay: false,
        };
        let receipt2 = AdmissionReceipt {
            admitted_sequence: 2,
            request_id: "r2".to_string(),
            graph_id: "other-graph".to_string(),
            target_node_id: None,
            author_principal_id: "admin".to_string(),
            admitted_at_unix_ms: 1000,
            operation: ControlOperation::Pause {
                scope: ControlScope::Graph,
            },
            graph_revision: 1,
            control_revision: 1,
            is_replay: false,
        };

        let filtered = proxy
            .filter_admitted_receipts(&authorized_user, &[receipt1.clone(), receipt2])
            .unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].graph_id, graph_id);
    }

    #[test]
    fn test_admission_assigns_monotonic_sequences() {
        let (mut proxy, graph_id) = setup_proxy();
        let admin = VerifiedPrincipal::local_admin("admin-seq");

        let make_submit = |request_id: &str| AdmissionRequest {
            request_id: request_id.to_string(),
            graph_id: graph_id.clone(),
            target_node_id: Some("node-1".to_string()),
            expected_graph_revision: None,
            expected_control_revision: None,
            expected_target_generation: None,
            operation: ControlOperation::SubmitTask {
                input: json!({"task": request_id}),
            },
            timestamp_unix_ms: 1000,
        };

        let receipt1 = proxy
            .admit(&admin, make_submit("req-seq-1"))
            .expect("first");
        let receipt2 = proxy
            .admit(&admin, make_submit("req-seq-2"))
            .expect("second");
        assert_eq!(receipt1.admitted_sequence, 1);
        assert_eq!(receipt2.admitted_sequence, 2);

        // A replay returns the originally assigned sequence.
        let replay = proxy
            .admit(&admin, make_submit("req-seq-1"))
            .expect("replay");
        assert!(replay.is_replay);
        assert_eq!(replay.admitted_sequence, receipt1.admitted_sequence);
    }

    #[test]
    fn test_admitted_control_revision_advances_and_stale_competitor_conflicts() {
        let (mut proxy, graph_id) = setup_proxy();
        let admin = VerifiedPrincipal::local_admin("admin-cas");

        let make_pause = |request_id: &str, expected: Option<u64>| AdmissionRequest {
            request_id: request_id.to_string(),
            graph_id: graph_id.clone(),
            target_node_id: Some("node-1".to_string()),
            expected_graph_revision: None,
            expected_control_revision: expected,
            expected_target_generation: None,
            operation: ControlOperation::Pause {
                scope: ControlScope::Node("node-1".to_string()),
            },
            timestamp_unix_ms: 1000,
        };

        // The first matching control revision is admitted and advances the revision.
        let first = proxy
            .admit(&admin, make_pause("req-cas-1", Some(0)))
            .expect("first admitted");
        assert_eq!(first.control_revision, 1);

        // A competing exclusive control based on the stale revision conflicts.
        match proxy.admit(&admin, make_pause("req-cas-2", Some(0))) {
            Err(AdmissionConflict::ControlRevisionConflict {
                expected, current, ..
            }) => {
                assert_eq!(expected, 0);
                assert_eq!(current, 1);
            }
            other => panic!("expected ControlRevisionConflict, got {:?}", other),
        }

        // A control rebased on the advanced revision is admitted.
        let rebased = proxy
            .admit(&admin, make_pause("req-cas-3", Some(1)))
            .expect("rebased admitted");
        assert_eq!(rebased.control_revision, 2);
    }

    #[test]
    fn test_revocation_of_covering_grant_takes_effect_at_use() {
        let (mut proxy, graph_id) = setup_proxy();
        let user = VerifiedPrincipal::local_user(
            "dana",
            "sess-dana",
            vec![OperationGrant::GraphControl {
                graph_id: graph_id.clone(),
            }],
        );

        let steer_req = |request_id: &str| AdmissionRequest {
            request_id: request_id.to_string(),
            graph_id: graph_id.clone(),
            target_node_id: Some("node-1".to_string()),
            expected_graph_revision: None,
            expected_control_revision: None,
            expected_target_generation: None,
            operation: ControlOperation::Steer {
                invocation_id: "inv-1".to_string(),
                instruction: "adjust".to_string(),
                follow_up: false,
            },
            timestamp_unix_ms: 1000,
        };

        // A covering grant admits operations requiring a narrower grant.
        proxy
            .admit(&user, steer_req("req-cover-1"))
            .expect("covering grant admits");

        // Revoking the held covering grant denies use, even though the narrower
        // required grant was never individually revoked.
        proxy.store_mut().revoke_grant(
            user.principal_id(),
            OperationGrant::GraphControl {
                graph_id: graph_id.clone(),
            },
        );
        let result = proxy.admit(&user, steer_req("req-cover-2"));
        assert!(matches!(
            result,
            Err(AdmissionConflict::PermissionDenied { .. })
        ));

        // A principal holding two covering grants remains authorized through
        // the surviving grant when only one of them is revoked.
        let dual = VerifiedPrincipal::local_user(
            "erin",
            "sess-erin",
            vec![
                OperationGrant::GraphControl {
                    graph_id: graph_id.clone(),
                },
                OperationGrant::NodeControl {
                    graph_id: graph_id.clone(),
                    node_id: "node-1".to_string(),
                },
            ],
        );
        proxy.store_mut().revoke_grant(
            dual.principal_id(),
            OperationGrant::NodeControl {
                graph_id: graph_id.clone(),
                node_id: "node-1".to_string(),
            },
        );
        proxy
            .admit(&dual, steer_req("req-cover-3"))
            .expect("surviving covering grant still authorizes");
    }

    #[test]
    fn test_stop_requested_scope_blocks_new_task_submission() {
        let (mut proxy, graph_id) = setup_proxy();
        let admin = VerifiedPrincipal::local_admin("admin-stop");

        // An admitted node-scope stop records the stop-requested fact.
        let stop_req = AdmissionRequest {
            request_id: "req-stop-node".to_string(),
            graph_id: graph_id.clone(),
            target_node_id: Some("node-1".to_string()),
            expected_graph_revision: None,
            expected_control_revision: None,
            expected_target_generation: None,
            operation: ControlOperation::Stop {
                scope: ControlScope::Node("node-1".to_string()),
                reason: "obsolete".to_string(),
            },
            timestamp_unix_ms: 1000,
        };
        proxy.admit(&admin, stop_req).expect("stop admitted");

        let make_submit = |request_id: &str, node: &str| AdmissionRequest {
            request_id: request_id.to_string(),
            graph_id: graph_id.clone(),
            target_node_id: Some(node.to_string()),
            expected_graph_revision: None,
            expected_control_revision: None,
            expected_target_generation: None,
            operation: ControlOperation::SubmitTask {
                input: json!({"task": request_id}),
            },
            timestamp_unix_ms: 1100,
        };

        // New work in the stop-requested scope is rejected.
        match proxy.admit(&admin, make_submit("req-submit-stopped", "node-1")) {
            Err(AdmissionConflict::StopMonotonicViolation { target, .. }) => {
                assert_eq!(target, "node-1");
            }
            other => panic!("expected StopMonotonicViolation, got {:?}", other),
        }

        // A sibling node scope still admits new work.
        proxy
            .admit(&admin, make_submit("req-submit-sibling", "node-2"))
            .expect("sibling scope admits new work");
    }

    #[test]
    fn test_invocation_scoped_stop_does_not_fence_sibling_invocations() {
        let (mut proxy, graph_id) = setup_proxy();
        let admin = VerifiedPrincipal::local_admin("admin-inv-stop");

        let stop_inv = AdmissionRequest {
            request_id: "req-stop-inv".to_string(),
            graph_id: graph_id.clone(),
            target_node_id: Some("node-1".to_string()),
            expected_graph_revision: None,
            expected_control_revision: None,
            expected_target_generation: None,
            operation: ControlOperation::Stop {
                scope: ControlScope::Invocation {
                    node_id: "node-1".to_string(),
                    invocation_id: "inv-1".to_string(),
                },
                reason: "cancel one".to_string(),
            },
            timestamp_unix_ms: 1000,
        };
        proxy
            .admit(&admin, stop_inv)
            .expect("invocation stop admitted");

        let make_steer = |request_id: &str, invocation_id: &str| AdmissionRequest {
            request_id: request_id.to_string(),
            graph_id: graph_id.clone(),
            target_node_id: Some("node-1".to_string()),
            expected_graph_revision: None,
            expected_control_revision: None,
            expected_target_generation: None,
            operation: ControlOperation::Steer {
                invocation_id: invocation_id.to_string(),
                instruction: "adjust".to_string(),
                follow_up: false,
            },
            timestamp_unix_ms: 1100,
        };

        // Steer on the stopped invocation cannot resurrect it.
        match proxy.admit(&admin, make_steer("req-steer-stopped", "inv-1")) {
            Err(AdmissionConflict::StopMonotonicViolation { target, .. }) => {
                assert_eq!(target, "node-1/inv-1");
            }
            other => panic!("expected StopMonotonicViolation, got {:?}", other),
        }

        // A sibling invocation on the same node remains steerable.
        proxy
            .admit(&admin, make_steer("req-steer-sibling", "inv-2"))
            .expect("sibling invocation remains steerable");
    }

    #[test]
    fn test_pause_admission_marks_negotiation_until_cleared() {
        let (mut proxy, graph_id) = setup_proxy();
        let admin = VerifiedPrincipal::local_admin("admin-pause");

        let pause_req = AdmissionRequest {
            request_id: "req-pause-mark".to_string(),
            graph_id: graph_id.clone(),
            target_node_id: Some("node-1".to_string()),
            expected_graph_revision: None,
            expected_control_revision: None,
            expected_target_generation: None,
            operation: ControlOperation::Pause {
                scope: ControlScope::Node("node-1".to_string()),
            },
            timestamp_unix_ms: 1000,
        };
        proxy.admit(&admin, pause_req).expect("pause admitted");
        assert!(
            proxy
                .store()
                .is_pause_negotiating(&graph_id, "node-1")
                .unwrap()
        );

        let resume_req = AdmissionRequest {
            request_id: "req-resume-mark".to_string(),
            graph_id: graph_id.clone(),
            target_node_id: Some("node-1".to_string()),
            expected_graph_revision: None,
            expected_control_revision: None,
            expected_target_generation: None,
            operation: ControlOperation::Resume {
                scope: ControlScope::Node("node-1".to_string()),
            },
            timestamp_unix_ms: 1100,
        };
        match proxy.admit(&admin, resume_req.clone()) {
            Err(AdmissionConflict::PendingTransition { target, .. }) => {
                assert_eq!(target, "node-1");
            }
            other => panic!("expected PendingTransition, got {:?}", other),
        }

        // Once the negotiation marker clears, resume is admitted.
        proxy
            .store_mut()
            .clear_pause_negotiating(&graph_id, "node-1");
        proxy
            .admit(&admin, resume_req)
            .expect("resume admitted after negotiation clears");
    }
}
