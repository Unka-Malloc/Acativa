use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkflowDefinition {
    pub schema: String,
    pub metadata: WorkflowMetadata,
    #[serde(default)]
    pub limits: WorkflowLimits,
    #[serde(default)]
    pub actor_slots: Vec<ActorSlot>,
    #[serde(default)]
    pub runtimes: Vec<RuntimeRequirement>,
    #[serde(default)]
    pub worksets: Vec<WorksetTemplate>,
    pub initial: String,
    pub states: Vec<GraphState>,
    pub transitions: Vec<Transition>,
}

impl WorkflowDefinition {
    /// Whether the declared `schema` is the one the calling host accepts. The
    /// engine binds no schema identity of its own: the host names the schema
    /// vocabulary it compiles for.
    pub fn has_supported_schema(&self, supported: &crate::SchemaId) -> bool {
        self.schema == supported.as_str()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkflowMetadata {
    pub id: String,
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkflowLimits {
    pub max_parallelism: u8,
    pub max_workset_items: u16,
    pub max_attempts: u8,
}

impl Default for WorkflowLimits {
    fn default() -> Self {
        Self {
            max_parallelism: 8,
            max_workset_items: 256,
            max_attempts: 3,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BindingKind {
    Actor,
    Runtime,
    Workspace,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActorSlot {
    pub id: String,
    pub kind: BindingKind,
    pub label: String,
    #[serde(default = "default_true")]
    pub required: bool,
    #[serde(default)]
    pub session_policy: SessionPolicy,
    #[serde(default)]
    pub entry: bool,
    #[serde(default)]
    pub fallback: SlotFallbackPolicy,
}

impl ActorSlot {
    pub fn required_actor(id: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            kind: BindingKind::Actor,
            label: label.into(),
            required: true,
            session_policy: SessionPolicy::New,
            entry: true,
            fallback: SlotFallbackPolicy::default(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct SlotFallbackPolicy {
    pub after_transient_attempts: u8,
    pub on_quota: bool,
}

impl Default for SlotFallbackPolicy {
    fn default() -> Self {
        Self {
            after_transient_attempts: 2,
            on_quota: true,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SessionPolicy {
    #[default]
    New,
    Resume,
    Sticky,
}

/// An open runtime-kind vocabulary.
///
/// A runtime requirement names the kind of runtime a state needs; the set of
/// kinds is owned by the host, not by this engine, so any host-defined kind
/// (an interpreter, a container profile, a remote executor family) is
/// expressible. The value is the wire spelling of the kind; comparison is by
/// string equality.
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct RuntimeKind(pub String);

impl RuntimeKind {
    pub fn new(kind: impl Into<String>) -> Self {
        Self(kind.into())
    }

    /// The wire spelling of this kind.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for RuntimeKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl From<&str> for RuntimeKind {
    fn from(kind: &str) -> Self {
        Self(kind.to_owned())
    }
}

impl From<String> for RuntimeKind {
    fn from(kind: String) -> Self {
        Self(kind)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeRequirement {
    pub id: String,
    pub kind: RuntimeKind,
    #[serde(default)]
    pub version_requirement: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorksetTemplate {
    pub id: String,
    pub item_binding: String,
    #[serde(default)]
    pub predecessor_field: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum GraphStateKind {
    Pass,
    Choice,
    Fork,
    Join,
    Authorization,
    Actor,
    Script,
    Workset,
    Succeed,
    Fail,
    Blocked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GraphState {
    pub id: String,
    pub kind: GraphStateKind,
    pub label: String,
    #[serde(default)]
    pub instruction: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workset: Option<String>,
    #[serde(default)]
    pub retry: RetryPolicy,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct RetryPolicy {
    pub max_attempts: u8,
    pub transient_only: bool,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 1,
            transient_only: true,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Transition {
    pub id: String,
    pub from: String,
    pub to: String,
    pub event: TransitionEvent,
    /// Declared handoff mode. `flow` (the default when the field is absent)
    /// enters the target as soon as the edge is selected; `callback` first
    /// parks the run and waits for the decider's settlement.
    #[serde(default, skip_serializing_if = "TransitionMode::is_flow")]
    pub mode: TransitionMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guard: Option<GuardExpression>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TransitionMode {
    #[default]
    Flow,
    Callback,
}

impl TransitionMode {
    pub const fn is_flow(&self) -> bool {
        matches!(self, Self::Flow)
    }
}

/// One durable callback wait: the edge was selected but the declared target is
/// not entered until the run's designated decider settles it as a run input.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingCallback {
    pub state_id: String,
    pub state_visit: u64,
    pub transition_id: String,
    pub event: TransitionEvent,
    pub target: String,
}

/// The decider's settlement for one pending callback wait.
///
/// The decision is expressed in the decider's own vocabulary of graph
/// positions rather than a fixed engine vocabulary: [`Enter`](Self::Enter)
/// names the state to enter next, and the machine admits only the two lawful
/// names of one parked wait — the edge's declared target (advance) and its
/// completed state (return). Any other name is a conflict. A decider that
/// decides by majority, quorum, human review or any other policy reaches the
/// same contract; the machine does not know how the answer was derived.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CallbackDecision {
    /// Enter the named state. Lawful names are the parked edge's declared
    /// target and the completed state the edge left.
    Enter(String),
    /// Stop the run.
    Terminate,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TransitionEvent {
    Complete,
    Success,
    Failure,
}

impl TransitionEvent {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Success => "success",
            Self::Failure => "failure",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GuardExpression {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub equals: Option<Value>,
    #[serde(default)]
    pub exists: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum StrategyRunStatus {
    Pending,
    AuthorizationRequired,
    RuntimeMissing,
    Running,
    Waiting,
    Retryable,
    CancelRequested,
    CancelInDoubt,
    Blocked,
    Cancelled,
    Failed,
    Completed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FailureClass {
    Transient,
    Permanent,
    Authority,
    Runtime,
    Sandbox,
    InDoubt,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FallbackReceipt {
    pub fallback_from: String,
    pub fallback_to: String,
    pub reason: String,
    pub attempts: u8,
}

const fn default_true() -> bool {
    true
}

// ---------------------------------------------------------------------------
// Causal input ABI
//
// A node's input is not "whatever the run context happens to hold when an
// effect starts". It is the join of exactly the declared predecessor results
// and the exactly versioned shared resources named in an [`InputBinding`], and
// the binding is a value: two executions with equal bindings received equal
// inputs, and a run that cannot produce the binding cannot produce the input.
//
// Two independent versions live here and neither can stand in for the other:
// [`INPUT_ADAPTER_VERSION`] versions the *projection* (how a binding becomes an
// input), while the engine semantics line versions the machine that computes
// it. A plan that declares an adapter version this build does not project is
// refused rather than reinterpreted, so a stored version cannot be silently
// read as a different one.
// ---------------------------------------------------------------------------

/// The input projection this build executes.
///
/// This is a version, not a digest: no definition digest, run id, or other
/// content hash is a value of this type, and the projection refuses a plan that
/// declares anything else.
pub const INPUT_ADAPTER_VERSION: u32 = 1;

/// The shared resource the run context lives in: everything an effect publishes
/// under `context`.
pub const SHARED_CONTEXT_RESOURCE: &str = "context";

/// The shared resource workset items live in: everything an effect publishes
/// under `worksets`.
pub const SHARED_WORKSETS_RESOURCE: &str = "worksets";

/// The identity of one produced result.
///
/// A result belongs to a node *visit*, so a later visit of the same node is a
/// different result and can never be consumed as the earlier one. The digest
/// covers the content, which is what makes a duplicate idempotent and a
/// differing re-delivery an explicit conflict instead of an overwrite.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResultRef {
    pub run_id: String,
    pub node_id: String,
    pub node_visit: u64,
    pub digest: String,
    /// The effects that produced this result, sorted. A workset visit produces
    /// one result from several item effects; the identity is the visit, and
    /// these are its provenance.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub producers: Vec<String>,
}

/// One predecessor's contribution: the exact visit and result that fed the
/// successor, never the predecessor's "latest" value.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PredecessorInput {
    pub node_id: String,
    pub node_visit: u64,
    pub result: ResultRef,
}

/// The effect that wrote one shared value.
///
/// Provenance names the command, not the node visit's result: a command
/// identity is fixed when the effect is emitted, while a visit's accumulated
/// result is only final once the visit is. Recording the latter mid-visit would
/// make the stored value depend on how many of the visit's members had already
/// settled, which is completion order leaking into the state.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SharedWriter {
    pub run_id: String,
    pub node_id: String,
    pub node_visit: u64,
    pub command_id: String,
}

/// A shared resource read at the exact revisions the reader observed.
///
/// `revision` is the resource's own revision, which is the token a compare-and-
/// swap checks. `keys` carries the revision of *each key that already existed*
/// when the reader looked, because a whole-resource revision says nothing about
/// one key: two writers can leave the resource revision unchanged for a key
/// neither of them touched, and a reader that only recorded the resource
/// revision could not say which of two values of a key it actually saw.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SharedResourceRef {
    pub resource_id: String,
    pub revision: u64,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub keys: BTreeMap<String, u64>,
}

/// What composed one node visit's input.
///
/// Every field is an identity rather than a summary of one: the declared
/// predecessor results at their exact visits, the shared revisions the reader
/// observed, and the adapter that projected them. A reader of this value can
/// tell whether a node's input came from its declared dependencies, which is
/// exactly what a final-state check cannot tell.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InputBinding {
    pub run_id: String,
    pub node_id: String,
    pub node_visit: u64,
    /// Declared predecessor contributions in the definition's order. Arrival
    /// order is not part of this list, so completing B before A cannot change
    /// a binding unless the node declares that order matters.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub predecessors: Vec<PredecessorInput>,
    /// Shared resources read, in declaration order, at the revision observed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shared: Vec<SharedResourceRef>,
    pub input_adapter_version: u32,
    /// The arrival order of predecessor contributions, recorded only for a node
    /// that declares its business order sensitive. Empty means "order is not
    /// part of this input's meaning".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arrival_order: Vec<String>,
}

impl InputBinding {
    /// The lookup key of one node visit in the run's binding ledger.
    pub fn key(node_id: &str, node_visit: u64) -> String {
        format!("{node_id}\0{node_visit}")
    }

    /// A canonical digest of this binding: the identity a caller can persist
    /// beside a command to prove later which inputs it was computed from.
    pub fn digest(&self) -> String {
        let bytes = serde_json::to_vec(self).unwrap_or_default();
        sha256_hex(&bytes)
    }

    /// The revision this binding observed for one resource, if it read it.
    pub fn shared_revision(&self, resource_id: &str) -> Option<u64> {
        self.shared
            .iter()
            .find(|reference| reference.resource_id == resource_id)
            .map(|reference| reference.revision)
    }

    /// The revision this binding observed for one key, if the key existed and
    /// the binding read its resource.
    pub fn shared_key_revision(&self, resource_id: &str, key: &str) -> Option<u64> {
        self.shared
            .iter()
            .find(|reference| reference.resource_id == resource_id)
            .and_then(|reference| reference.keys.get(key).copied())
    }
}

/// How concurrent writers of one shared resource are reconciled.
///
/// There is deliberately no "last writer wins" variant: silently discarding a
/// differing value is the behaviour this contract removes. Every accepted
/// policy either refuses the conflict or was chosen in advance for it.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MergePolicy {
    /// Disjoint keys merge; a key already written by a different writer with
    /// different content is an explicit conflict. The default, because it is
    /// the only policy that accepts the common disjoint case without ever
    /// discarding a differing value.
    #[default]
    KeyUnion,
    /// The resource accepts writes from the one writer the plan names; any
    /// other writer is refused.
    Exclusive,
    /// Every write is checked against the revision the writer read.
    Cas,
    /// The resource holds a collection: a key already written is merged with
    /// the incoming value as a canonical set union of the two arrays.
    ///
    /// This is the policy for a key whose declared meaning is "the set of
    /// contributions from the members of one node visit" — the results a
    /// workset's items produce, for instance. It is the only merge of
    /// concurrent producers into one collection that is commutative,
    /// associative, idempotent and content preserving: completion order stays
    /// unobservable, a re-delivered contribution does not count twice, and no
    /// member's value is dropped. Its members must therefore be independent by
    /// construction; two writers disagreeing about *one* value still belong to
    /// a scalar key, where `KeyUnion` refuses the disagreement.
    Accumulate,
}

/// One shared resource a run's input plan declares.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SharedResourceDecl {
    pub id: String,
    #[serde(default)]
    pub merge: MergePolicy,
    /// The writer a `exclusive` resource accepts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub writer: Option<String>,
}

impl SharedResourceDecl {
    /// The merge policy this crate applies to one resource: disjoint keys
    /// merge, a differing value for one key is refused.
    pub fn key_union(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            merge: MergePolicy::KeyUnion,
            writer: None,
        }
    }

    /// Declare a resource whose keys are collections that accumulate the
    /// contributions of concurrent writers.
    pub fn accumulate(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            merge: MergePolicy::Accumulate,
            writer: None,
        }
    }
}

/// Whether a node's business depends on the order predecessor contributions
/// arrive in.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ContributionOrder {
    /// Contributions are ordered by the definition. The default: a node that
    /// says nothing has order independent inputs, so no arrival race can reach
    /// it.
    #[default]
    Declaration,
    /// The business is order sensitive and declares it, so the arrival order is
    /// recorded in the binding as an explicit fact instead of being inferred.
    Arrival,
}

/// What a run declares about its own causal inputs.
///
/// A node that declares nothing gets the safe default: it reads the declared
/// shared resources at the revision it observed, it sees only its declared
/// predecessors, and its contributions are ordered by the definition. The two
/// declarations that change that are `isolatedNodes`, which removes shared
/// reads entirely so a causally unrelated branch cannot reach the node's input,
/// and `orderSensitiveNodes`, which makes an arrival-order dependency explicit
/// rather than accidental.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InputPlan {
    pub input_adapter_version: u32,
    #[serde(default)]
    pub resources: Vec<SharedResourceDecl>,
    /// Nodes whose business depends on arrival order, and say so.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub order_sensitive_nodes: Vec<String>,
    /// Nodes that read no shared state at all.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub isolated_nodes: Vec<String>,
}

impl Default for InputPlan {
    fn default() -> Self {
        Self {
            input_adapter_version: INPUT_ADAPTER_VERSION,
            resources: vec![
                SharedResourceDecl::key_union(SHARED_CONTEXT_RESOURCE),
                SharedResourceDecl::key_union(SHARED_WORKSETS_RESOURCE),
            ],
            order_sensitive_nodes: Vec::new(),
            isolated_nodes: Vec::new(),
        }
    }
}

impl InputPlan {
    pub fn resource(&self, id: &str) -> Option<&SharedResourceDecl> {
        self.resources
            .iter()
            .find(|declaration| declaration.id == id)
    }

    pub fn contribution_order(&self, node_id: &str) -> ContributionOrder {
        if self
            .order_sensitive_nodes
            .iter()
            .any(|node| node == node_id)
        {
            ContributionOrder::Arrival
        } else {
            ContributionOrder::Declaration
        }
    }

    pub fn reads_shared_state(&self, node_id: &str) -> bool {
        !self.isolated_nodes.iter().any(|node| node == node_id)
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}
