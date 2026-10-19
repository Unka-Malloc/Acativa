//! Routing and subscription: feature indexes/selectors, frozen targets, cursor, and fair wake.
//!
//! Selectors address explicit node IDs or indexed characteristics: active lifecycle
//! state, actual adapter identity, declared work role, and supported operations.
//! A one-shot publication freezes its matched recipient IDs/generations at admission.
//! Queue bounds provide separate control/data capacities and fair service without
//! starvation.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::{Display, Formatter};
use uuid::Uuid;

/// Node lifecycle state for routed work.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NodeLifecycleState {
    Ready,
    Running,
    PauseRequested,
    Paused,
    Waiting,
    StopRequested,
    Stopped,
    Failed,
    Completed,
}

impl NodeLifecycleState {
    /// Whether the node is in an active (non-terminal) state.
    pub const fn is_active(&self) -> bool {
        matches!(
            self,
            Self::Ready
                | Self::Running
                | Self::PauseRequested
                | Self::Paused
                | Self::Waiting
                | Self::StopRequested
        )
    }

    /// Whether the node is in a terminal state.
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Stopped | Self::Failed | Self::Completed)
    }

    /// Whether the node can accept new work.
    pub const fn can_accept_new_work(&self) -> bool {
        matches!(self, Self::Ready | Self::Waiting)
    }

    /// Whether the node can accept control commands (pause, steer, stop).
    pub const fn can_accept_control(&self) -> bool {
        self.is_active()
    }

    /// Whether stop has been requested or reached for this node.
    pub const fn is_stop_requested(&self) -> bool {
        matches!(self, Self::StopRequested | Self::Stopped)
    }
}

/// Declared uniform semantic capabilities of a node.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NodeCapability {
    Submit,
    Steer,
    Pause,
    Resume,
    Stop,
    Observe,
}

/// Metadata describing an indexed node instance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeMetadata {
    pub node_id: String,
    pub generation: u64,
    pub graph_id: String,
    pub lifecycle_state: NodeLifecycleState,
    pub adapter_identity: String,
    pub work_role: String,
    pub capabilities: BTreeSet<NodeCapability>,
    pub active_invocation_id: Option<String>,
}

/// Inverted feature index over active nodes for efficient characteristic-based routing.
#[derive(Clone, Debug, Default)]
pub struct NodeFeatureIndex {
    nodes: BTreeMap<String, NodeMetadata>,
    by_lifecycle: BTreeMap<NodeLifecycleState, BTreeSet<String>>,
    by_adapter: BTreeMap<String, BTreeSet<String>>,
    by_work_role: BTreeMap<String, BTreeSet<String>>,
    by_capability: BTreeMap<NodeCapability, BTreeSet<String>>,
}

impl NodeFeatureIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, node_id: &str) -> Option<&NodeMetadata> {
        self.nodes.get(node_id)
    }

    pub fn count(&self) -> usize {
        self.nodes.len()
    }

    /// Register or update a node, modifying only the affected inverted index entries.
    pub fn register_or_update(&mut self, node: NodeMetadata) {
        if let Some(existing) = self.nodes.get(&node.node_id) {
            // Remove from existing index entries where characteristics changed
            if existing.lifecycle_state != node.lifecycle_state
                && let Some(set) = self.by_lifecycle.get_mut(&existing.lifecycle_state)
            {
                set.remove(&node.node_id);
            }
            if existing.adapter_identity != node.adapter_identity
                && let Some(set) = self.by_adapter.get_mut(&existing.adapter_identity)
            {
                set.remove(&node.node_id);
            }
            if existing.work_role != node.work_role
                && let Some(set) = self.by_work_role.get_mut(&existing.work_role)
            {
                set.remove(&node.node_id);
            }
            for cap in &existing.capabilities {
                if !node.capabilities.contains(cap)
                    && let Some(set) = self.by_capability.get_mut(cap)
                {
                    set.remove(&node.node_id);
                }
            }
        }

        // Insert into new index entries
        self.by_lifecycle
            .entry(node.lifecycle_state)
            .or_default()
            .insert(node.node_id.clone());
        self.by_adapter
            .entry(node.adapter_identity.clone())
            .or_default()
            .insert(node.node_id.clone());
        self.by_work_role
            .entry(node.work_role.clone())
            .or_default()
            .insert(node.node_id.clone());
        for cap in &node.capabilities {
            self.by_capability
                .entry(*cap)
                .or_default()
                .insert(node.node_id.clone());
        }

        self.nodes.insert(node.node_id.clone(), node);
    }

    /// Remove a node from all feature indexes.
    pub fn remove(&mut self, node_id: &str) -> Option<NodeMetadata> {
        if let Some(node) = self.nodes.remove(node_id) {
            if let Some(set) = self.by_lifecycle.get_mut(&node.lifecycle_state) {
                set.remove(node_id);
            }
            if let Some(set) = self.by_adapter.get_mut(&node.adapter_identity) {
                set.remove(node_id);
            }
            if let Some(set) = self.by_work_role.get_mut(&node.work_role) {
                set.remove(node_id);
            }
            for cap in &node.capabilities {
                if let Some(set) = self.by_capability.get_mut(cap) {
                    set.remove(node_id);
                }
            }
            Some(node)
        } else {
            None
        }
    }

    /// Match nodes matching the selector by intersecting/unioning index sets.
    pub fn query(&self, selector: &TargetSelector) -> BTreeSet<String> {
        match selector {
            TargetSelector::ExactNode(node_id) => {
                let mut set = BTreeSet::new();
                if self.nodes.contains_key(node_id) {
                    set.insert(node_id.clone());
                }
                set
            }
            TargetSelector::Lifecycle(state) => {
                self.by_lifecycle.get(state).cloned().unwrap_or_default()
            }
            TargetSelector::Adapter(adapter) => {
                self.by_adapter.get(adapter).cloned().unwrap_or_default()
            }
            TargetSelector::WorkRole(role) => {
                self.by_work_role.get(role).cloned().unwrap_or_default()
            }
            TargetSelector::Capability(cap) => {
                self.by_capability.get(cap).cloned().unwrap_or_default()
            }
            TargetSelector::Intersection(selectors) => {
                if selectors.is_empty() {
                    return BTreeSet::new();
                }
                let mut iter = selectors.iter();
                let mut result = self.query(iter.next().unwrap());
                for next_sel in iter {
                    let matching = self.query(next_sel);
                    result = result.intersection(&matching).cloned().collect();
                    if result.is_empty() {
                        break;
                    }
                }
                result
            }
            TargetSelector::Union(selectors) => {
                let mut result = BTreeSet::new();
                for sel in selectors {
                    result.extend(self.query(sel));
                }
                result
            }
            TargetSelector::AllActive => self
                .nodes
                .iter()
                .filter(|(_, meta)| meta.lifecycle_state.is_active())
                .map(|(id, _)| id.clone())
                .collect(),
        }
    }
}

/// Selector addressing explicit nodes or indexed characteristics.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TargetSelector {
    /// Direct address of a specific node.
    ExactNode(String),
    /// Nodes currently in a specific lifecycle state.
    Lifecycle(NodeLifecycleState),
    /// Nodes powered by a specific adapter.
    Adapter(String),
    /// Nodes declared with a specific work role tag.
    WorkRole(String),
    /// Nodes declaring support for a specific semantic capability.
    Capability(NodeCapability),
    /// Conjunction of multiple selectors.
    Intersection(Vec<TargetSelector>),
    /// Disjunction of multiple selectors.
    Union(Vec<TargetSelector>),
    /// All active nodes in the graph.
    AllActive,
}

/// Delivery mode for a publication.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DeliveryMode {
    /// Broadcast to all matching recipients.
    #[default]
    Broadcast,
    /// Dispatch to exactly one eligible recipient.
    DispatchOne,
}

/// Individual frozen recipient snapshot bound at admission.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FrozenTargetRecipient {
    /// Unique delivery identity for this recipient.
    pub delivery_id: String,
    /// Target node identity.
    pub node_id: String,
    /// Generation at time of admission.
    pub generation: u64,
    /// Lifecycle state at time of admission.
    pub admitted_state: NodeLifecycleState,
}

/// Set of target recipients frozen at queue admission time.
///
/// A one-shot publication freezes its matched recipient IDs/generations at
/// durable admission. Each recipient gets its own delivery identity and outcome;
/// later matching nodes do not silently receive it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FrozenTargets {
    /// Durable queue cursor at which targets were frozen.
    pub frozen_at_cursor: u64,
    /// Selected delivery mode.
    pub mode: DeliveryMode,
    /// Frozen recipient list.
    pub recipients: Vec<FrozenTargetRecipient>,
}

/// Live effect validity verification outcome for a frozen recipient.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RecipientEffectStatus {
    /// Recipient state and generation match; effect can proceed.
    Valid,
    /// State changed between admission and effect execution.
    StateChanged {
        expected: NodeLifecycleState,
        current: NodeLifecycleState,
    },
    /// Generation changed (e.g. node was recycled).
    GenerationStale { expected: u64, current: u64 },
    /// Target node no longer exists.
    NodeMissing,
}

impl FrozenTargets {
    /// Resolve selector against feature index and freeze matching recipients.
    pub fn resolve(
        index: &NodeFeatureIndex,
        cursor: u64,
        selector: &TargetSelector,
        mode: DeliveryMode,
    ) -> Self {
        let matching_ids = index.query(selector);
        let mut recipients = Vec::new();

        match mode {
            DeliveryMode::Broadcast => {
                for id in matching_ids {
                    if let Some(meta) = index.get(&id) {
                        recipients.push(FrozenTargetRecipient {
                            delivery_id: format!("del-{}", Uuid::new_v4()),
                            node_id: meta.node_id.clone(),
                            generation: meta.generation,
                            admitted_state: meta.lifecycle_state,
                        });
                    }
                }
            }
            DeliveryMode::DispatchOne => {
                // Deterministically pick the first eligible match (e.g. lowest ID)
                if let Some(id) = matching_ids.into_iter().next()
                    && let Some(meta) = index.get(&id)
                {
                    recipients.push(FrozenTargetRecipient {
                        delivery_id: format!("del-{}", Uuid::new_v4()),
                        node_id: meta.node_id.clone(),
                        generation: meta.generation,
                        admitted_state: meta.lifecycle_state,
                    });
                }
            }
        }

        Self {
            frozen_at_cursor: cursor,
            mode,
            recipients,
        }
    }

    /// Recheck live state and generation of all frozen recipients before effect execution.
    pub fn validate_before_effect(
        &self,
        index: &NodeFeatureIndex,
    ) -> Vec<(FrozenTargetRecipient, RecipientEffectStatus)> {
        self.recipients
            .iter()
            .map(|recipient| {
                let status = match index.get(&recipient.node_id) {
                    Some(live) => {
                        if live.generation != recipient.generation {
                            RecipientEffectStatus::GenerationStale {
                                expected: recipient.generation,
                                current: live.generation,
                            }
                        } else if live.lifecycle_state != recipient.admitted_state {
                            RecipientEffectStatus::StateChanged {
                                expected: recipient.admitted_state,
                                current: live.lifecycle_state,
                            }
                        } else {
                            RecipientEffectStatus::Valid
                        }
                    }
                    None => RecipientEffectStatus::NodeMissing,
                };
                (recipient.clone(), status)
            })
            .collect()
    }
}

/// Scope of a persistent subscription.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SubscriptionScope {
    Graph(String),
    Node { graph_id: String, node_id: String },
}

/// Predicate defining when a persistent subscription matches an event.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SubscriptionPredicate {
    OnLifecycleState(NodeLifecycleState),
    OnAnyTransition,
    OnExternalEvent { event_name: String },
    OnCustom(String),
}

/// Activation rule for a matched subscription.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ActivationRule {
    /// Emit notification only; do not auto-resume paused work.
    NotifyOnly,
    /// Declared and authorized rule to resume a paused node.
    AutoResume,
    /// Trigger a specific named state transition.
    TriggerTransition { target_state: String },
}

/// Persistent subscription matching future events with a durable cursor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Subscription {
    pub subscription_id: String,
    pub subscriber_id: String,
    pub scope: SubscriptionScope,
    pub predicate: SubscriptionPredicate,
    pub activation_rule: ActivationRule,
    pub durable_cursor: u64,
    pub is_control: bool,
    pub active: bool,
}

/// Subscription registry enforcing lifecycle and negotiation rules.
#[derive(Clone, Debug, Default)]
pub struct SubscriptionRegistry {
    subscriptions: BTreeMap<String, Subscription>,
}

impl SubscriptionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a persistent subscription.
    pub fn subscribe(&mut self, subscription: Subscription) {
        self.subscriptions
            .insert(subscription.subscription_id.clone(), subscription);
    }

    /// Unsubscribe by ID.
    pub fn unsubscribe(&mut self, subscription_id: &str) -> Option<Subscription> {
        self.subscriptions.remove(subscription_id)
    }

    /// Match active subscriptions for an event, respecting lifecycle restrictions.
    pub fn match_event(
        &self,
        scope: &SubscriptionScope,
        predicate: &SubscriptionPredicate,
        target_state: Option<NodeLifecycleState>,
    ) -> Vec<Subscription> {
        self.subscriptions
            .values()
            .filter(|sub| {
                if !sub.active {
                    return false;
                }
                // Scope match
                match (&sub.scope, scope) {
                    (SubscriptionScope::Graph(g1), SubscriptionScope::Graph(g2)) => g1 == g2,
                    (SubscriptionScope::Graph(g1), SubscriptionScope::Node { graph_id, .. }) => {
                        g1 == graph_id
                    }
                    (
                        SubscriptionScope::Node {
                            graph_id: g1,
                            node_id: n1,
                        },
                        SubscriptionScope::Node {
                            graph_id: g2,
                            node_id: n2,
                        },
                    ) => g1 == g2 && n1 == n2,
                    _ => false,
                }
            })
            .filter(|sub| {
                // Predicate match
                match (&sub.predicate, predicate) {
                    (
                        SubscriptionPredicate::OnLifecycleState(s1),
                        SubscriptionPredicate::OnLifecycleState(s2),
                    ) => s1 == s2,
                    (SubscriptionPredicate::OnAnyTransition, _) => true,
                    (
                        SubscriptionPredicate::OnExternalEvent { event_name: e1 },
                        SubscriptionPredicate::OnExternalEvent { event_name: e2 },
                    ) => e1 == e2,
                    (SubscriptionPredicate::OnCustom(c1), SubscriptionPredicate::OnCustom(c2)) => {
                        c1 == c2
                    }
                    _ => false,
                }
            })
            .filter(|sub| {
                // Rule: Stop-requested nodes cannot start new work from a data subscription.
                if let Some(state) = target_state {
                    if state.is_stop_requested() && !sub.is_control {
                        return false;
                    }
                    // Rule: Paused nodes retain control delivery by default;
                    // only explicitly declared and authorized AutoResume can resume them.
                    if state == NodeLifecycleState::Paused
                        && !sub.is_control
                        && sub.activation_rule != ActivationRule::AutoResume
                    {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect()
    }

    /// Update subscription cursor upon delivery receipt.
    pub fn advance_cursor(&mut self, subscription_id: &str, new_cursor: u64) {
        if let Some(sub) = self.subscriptions.get_mut(subscription_id)
            && new_cursor > sub.durable_cursor
        {
            sub.durable_cursor = new_cursor;
        }
    }
}

/// Channel classification for queue prioritization and fair dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ChannelKind {
    /// Control operations: pause, steer, stop, callback decisions.
    Control,
    /// Data operations: task inputs, batch worksets, stream outputs.
    Data,
}

/// Bounded limits for a channel.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QueueBounds {
    pub max_entries: usize,
    pub max_bytes: usize,
}

impl Default for QueueBounds {
    fn default() -> Self {
        Self {
            max_entries: 1024,
            max_bytes: 4 * 1024 * 1024, // 4 MB
        }
    }
}

/// An admitted message queued for execution.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QueuedItem {
    /// Monotonically increasing durable queue cursor.
    pub cursor: u64,
    pub channel: ChannelKind,
    pub item_id: String,
    pub payload_bytes: usize,
    pub content: Value,
    pub enqueued_at_unix_ms: i64,
}

/// Error returned when queue bounds are exceeded.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct QueueCapacityExceeded {
    pub channel: ChannelKind,
    pub current_entries: usize,
    pub current_bytes: usize,
    pub limit_entries: usize,
    pub limit_bytes: usize,
}

impl Display for QueueCapacityExceeded {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "queue capacity exceeded on {:?}: entries {}/{} bytes {}/{}",
            self.channel,
            self.current_entries,
            self.limit_entries,
            self.current_bytes,
            self.limit_bytes
        )
    }
}

impl std::error::Error for QueueCapacityExceeded {}

/// Fair dispatch queue maintaining separate Control and Data channels with
/// strict capacity bounds and a deficit/quantum fair arbiter to prevent starvation.
#[derive(Clone, Debug)]
pub struct FairDispatchQueue {
    control_bounds: QueueBounds,
    data_bounds: QueueBounds,
    control_queue: VecDeque<QueuedItem>,
    data_queue: VecDeque<QueuedItem>,
    control_bytes: usize,
    data_bytes: usize,
    next_cursor: u64,
    /// Historical replay log. Retention and truncation belong to the durable
    /// wiring; this in-memory leaf retains the full log.
    durable_log: Vec<QueuedItem>,
    /// Quantum: number of control items dispatched before checking data queue.
    control_quantum: usize,
    control_dispatched_in_quantum: usize,
}

impl FairDispatchQueue {
    pub fn new(
        control_bounds: QueueBounds,
        data_bounds: QueueBounds,
        control_quantum: usize,
    ) -> Self {
        Self {
            control_bounds,
            data_bounds,
            control_queue: VecDeque::new(),
            data_queue: VecDeque::new(),
            control_bytes: 0,
            data_bytes: 0,
            next_cursor: 1,
            durable_log: Vec::new(),
            control_quantum: control_quantum.max(1),
            control_dispatched_in_quantum: 0,
        }
    }

    pub fn current_cursor(&self) -> u64 {
        self.next_cursor
    }

    pub fn is_empty(&self) -> bool {
        self.control_queue.is_empty() && self.data_queue.is_empty()
    }

    pub fn control_len(&self) -> usize {
        self.control_queue.len()
    }

    pub fn data_len(&self) -> usize {
        self.data_queue.len()
    }

    /// Enqueue an item into its channel, enforcing separate bounds.
    pub fn enqueue(
        &mut self,
        channel: ChannelKind,
        item_id: impl Into<String>,
        content: Value,
        timestamp_unix_ms: i64,
    ) -> Result<u64, QueueCapacityExceeded> {
        let serialized = serde_json::to_vec(&content).unwrap_or_default();
        let payload_bytes = serialized.len();

        match channel {
            ChannelKind::Control => {
                if self.control_queue.len() + 1 > self.control_bounds.max_entries
                    || self.control_bytes + payload_bytes > self.control_bounds.max_bytes
                {
                    return Err(QueueCapacityExceeded {
                        channel,
                        current_entries: self.control_queue.len(),
                        current_bytes: self.control_bytes,
                        limit_entries: self.control_bounds.max_entries,
                        limit_bytes: self.control_bounds.max_bytes,
                    });
                }
                let cursor = self.next_cursor;
                self.next_cursor += 1;
                let item = QueuedItem {
                    cursor,
                    channel,
                    item_id: item_id.into(),
                    payload_bytes,
                    content,
                    enqueued_at_unix_ms: timestamp_unix_ms,
                };
                self.control_bytes += payload_bytes;
                self.control_queue.push_back(item.clone());
                self.durable_log.push(item);
                Ok(cursor)
            }
            ChannelKind::Data => {
                if self.data_queue.len() + 1 > self.data_bounds.max_entries
                    || self.data_bytes + payload_bytes > self.data_bounds.max_bytes
                {
                    return Err(QueueCapacityExceeded {
                        channel,
                        current_entries: self.data_queue.len(),
                        current_bytes: self.data_bytes,
                        limit_entries: self.data_bounds.max_entries,
                        limit_bytes: self.data_bounds.max_bytes,
                    });
                }
                let cursor = self.next_cursor;
                self.next_cursor += 1;
                let item = QueuedItem {
                    cursor,
                    channel,
                    item_id: item_id.into(),
                    payload_bytes,
                    content,
                    enqueued_at_unix_ms: timestamp_unix_ms,
                };
                self.data_bytes += payload_bytes;
                self.data_queue.push_back(item.clone());
                self.durable_log.push(item);
                Ok(cursor)
            }
        }
    }

    /// Fair dequeue implementing deficit/quantum fair arbiter.
    ///
    /// Control commands have priority up to `control_quantum` items, after which
    /// pending Data items are served, ensuring no control flood can starve background data.
    pub fn dequeue(&mut self) -> Option<QueuedItem> {
        if self.control_queue.is_empty() && self.data_queue.is_empty() {
            return None;
        }

        // If control queue is empty, must serve data
        if self.control_queue.is_empty() {
            self.control_dispatched_in_quantum = 0;
            return self.pop_data();
        }

        // If data queue is empty, must serve control
        if self.data_queue.is_empty() {
            return self.pop_control();
        }

        // Both have items: check quantum
        if self.control_dispatched_in_quantum < self.control_quantum {
            self.control_dispatched_in_quantum += 1;
            self.pop_control()
        } else {
            // Quantum exhausted: serve one data item and reset quantum
            self.control_dispatched_in_quantum = 0;
            self.pop_data()
        }
    }

    fn pop_control(&mut self) -> Option<QueuedItem> {
        if let Some(item) = self.control_queue.pop_front() {
            self.control_bytes = self.control_bytes.saturating_sub(item.payload_bytes);
            Some(item)
        } else {
            None
        }
    }

    fn pop_data(&mut self) -> Option<QueuedItem> {
        if let Some(item) = self.data_queue.pop_front() {
            self.data_bytes = self.data_bytes.saturating_sub(item.payload_bytes);
            Some(item)
        } else {
            None
        }
    }

    /// Replay messages from a durable cursor (catch-up upon reconnect or recovery).
    pub fn replay_from_cursor(&self, from_cursor: u64) -> Vec<QueuedItem> {
        self.durable_log
            .iter()
            .filter(|item| item.cursor >= from_cursor)
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_node(
        id: &str,
        generation: u64,
        state: NodeLifecycleState,
        adapter: &str,
        role: &str,
        caps: &[NodeCapability],
    ) -> NodeMetadata {
        NodeMetadata {
            node_id: id.to_string(),
            generation,
            graph_id: "graph-main".to_string(),
            lifecycle_state: state,
            adapter_identity: adapter.to_string(),
            work_role: role.to_string(),
            capabilities: caps.iter().copied().collect(),
            active_invocation_id: None,
        }
    }

    #[test]
    fn test_feature_index_registration_update_and_removal() {
        let mut index = NodeFeatureIndex::new();

        let n1 = sample_node(
            "node-1",
            1,
            NodeLifecycleState::Running,
            "agent:codex",
            "worker",
            &[NodeCapability::Submit, NodeCapability::Steer],
        );
        let n2 = sample_node(
            "node-2",
            1,
            NodeLifecycleState::Paused,
            "agent:kimi",
            "reviewer",
            &[NodeCapability::Pause, NodeCapability::Resume],
        );

        index.register_or_update(n1);
        index.register_or_update(n2);
        assert_eq!(index.count(), 2);

        // Query by lifecycle
        let running = index.query(&TargetSelector::Lifecycle(NodeLifecycleState::Running));
        assert_eq!(running.len(), 1);
        assert!(running.contains("node-1"));

        // Query by adapter
        let codex = index.query(&TargetSelector::Adapter("agent:codex".to_string()));
        assert_eq!(codex.len(), 1);
        assert!(codex.contains("node-1"));

        // Query by work role
        let reviewer = index.query(&TargetSelector::WorkRole("reviewer".to_string()));
        assert_eq!(reviewer.len(), 1);
        assert!(reviewer.contains("node-2"));

        // Query by capability
        let steerable = index.query(&TargetSelector::Capability(NodeCapability::Steer));
        assert_eq!(steerable.len(), 1);
        assert!(steerable.contains("node-1"));

        // Intersection query: running AND agent:codex
        let intersection = index.query(&TargetSelector::Intersection(vec![
            TargetSelector::Lifecycle(NodeLifecycleState::Running),
            TargetSelector::Adapter("agent:codex".to_string()),
        ]));
        assert_eq!(intersection.len(), 1);
        assert!(intersection.contains("node-1"));

        // Update node-1 state to Paused
        let mut n1_updated = index.get("node-1").unwrap().clone();
        n1_updated.lifecycle_state = NodeLifecycleState::Paused;
        index.register_or_update(n1_updated);

        // Old running index should be empty now, paused should have 2
        let running_after = index.query(&TargetSelector::Lifecycle(NodeLifecycleState::Running));
        assert!(running_after.is_empty());
        let paused_after = index.query(&TargetSelector::Lifecycle(NodeLifecycleState::Paused));
        assert_eq!(paused_after.len(), 2);

        // Remove node-2
        let removed = index.remove("node-2").expect("should remove");
        assert_eq!(removed.node_id, "node-2");
        assert_eq!(index.count(), 1);
        let reviewers_after = index.query(&TargetSelector::WorkRole("reviewer".to_string()));
        assert!(reviewers_after.is_empty());
    }

    #[test]
    fn test_frozen_targets_broadcast_vs_dispatch_one() {
        let mut index = NodeFeatureIndex::new();
        index.register_or_update(sample_node(
            "worker-a",
            1,
            NodeLifecycleState::Ready,
            "agent:codex",
            "worker",
            &[NodeCapability::Submit],
        ));
        index.register_or_update(sample_node(
            "worker-b",
            1,
            NodeLifecycleState::Ready,
            "agent:codex",
            "worker",
            &[NodeCapability::Submit],
        ));

        let selector = TargetSelector::WorkRole("worker".to_string());

        // Broadcast freezes all matches
        let broadcast = FrozenTargets::resolve(&index, 10, &selector, DeliveryMode::Broadcast);
        assert_eq!(broadcast.recipients.len(), 2);
        assert_eq!(broadcast.mode, DeliveryMode::Broadcast);
        assert_eq!(broadcast.frozen_at_cursor, 10);
        let ids: BTreeSet<_> = broadcast.recipients.iter().map(|r| &r.node_id).collect();
        assert!(ids.contains(&"worker-a".to_string()));
        assert!(ids.contains(&"worker-b".to_string()));

        // DispatchOne freezes exactly one worker
        let dispatch_one = FrozenTargets::resolve(&index, 11, &selector, DeliveryMode::DispatchOne);
        assert_eq!(dispatch_one.recipients.len(), 1);
        assert_eq!(dispatch_one.mode, DeliveryMode::DispatchOne);

        // Later additions do NOT affect the frozen targets
        index.register_or_update(sample_node(
            "worker-c",
            1,
            NodeLifecycleState::Ready,
            "agent:codex",
            "worker",
            &[NodeCapability::Submit],
        ));
        assert_eq!(broadcast.recipients.len(), 2);
    }

    #[test]
    fn test_frozen_targets_pre_effect_validation_detects_state_and_generation_changes() {
        let mut index = NodeFeatureIndex::new();
        index.register_or_update(sample_node(
            "node-x",
            1,
            NodeLifecycleState::Running,
            "agent:codex",
            "worker",
            &[NodeCapability::Steer],
        ));

        let selector = TargetSelector::ExactNode("node-x".to_string());
        let frozen = FrozenTargets::resolve(&index, 100, &selector, DeliveryMode::Broadcast);
        assert_eq!(frozen.recipients.len(), 1);

        // 1. Immediately valid
        let validation1 = frozen.validate_before_effect(&index);
        assert_eq!(validation1[0].1, RecipientEffectStatus::Valid);

        // 2. Node completed before steer takes effect
        let mut completed_node = index.get("node-x").unwrap().clone();
        completed_node.lifecycle_state = NodeLifecycleState::Completed;
        index.register_or_update(completed_node);

        let validation2 = frozen.validate_before_effect(&index);
        match &validation2[0].1 {
            RecipientEffectStatus::StateChanged { expected, current } => {
                assert_eq!(*expected, NodeLifecycleState::Running);
                assert_eq!(*current, NodeLifecycleState::Completed);
            }
            other => panic!("expected StateChanged, got {:?}", other),
        }

        // 3. Node generation bumped (recycled node)
        let mut recycled_node = index.get("node-x").unwrap().clone();
        recycled_node.generation = 2;
        index.register_or_update(recycled_node);

        let validation3 = frozen.validate_before_effect(&index);
        match &validation3[0].1 {
            RecipientEffectStatus::GenerationStale { expected, current } => {
                assert_eq!(*expected, 1);
                assert_eq!(*current, 2);
            }
            other => panic!("expected GenerationStale, got {:?}", other),
        }

        // 4. Node deleted
        index.remove("node-x");
        let validation4 = frozen.validate_before_effect(&index);
        assert_eq!(validation4[0].1, RecipientEffectStatus::NodeMissing);
    }

    #[test]
    fn test_persistent_subscriptions_matching_and_lifecycle_invariants() {
        let mut registry = SubscriptionRegistry::new();

        let sub_data = Subscription {
            subscription_id: "sub-data-1".to_string(),
            subscriber_id: "subscriber-a".to_string(),
            scope: SubscriptionScope::Graph("graph-1".to_string()),
            predicate: SubscriptionPredicate::OnExternalEvent {
                event_name: "webhook.github".to_string(),
            },
            activation_rule: ActivationRule::NotifyOnly,
            durable_cursor: 0,
            is_control: false,
            active: true,
        };

        let sub_control = Subscription {
            subscription_id: "sub-ctrl-1".to_string(),
            subscriber_id: "subscriber-b".to_string(),
            scope: SubscriptionScope::Graph("graph-1".to_string()),
            predicate: SubscriptionPredicate::OnExternalEvent {
                event_name: "webhook.github".to_string(),
            },
            activation_rule: ActivationRule::NotifyOnly,
            durable_cursor: 0,
            is_control: true,
            active: true,
        };

        registry.subscribe(sub_data);
        registry.subscribe(sub_control);

        let event_scope = SubscriptionScope::Graph("graph-1".to_string());
        let event_predicate = SubscriptionPredicate::OnExternalEvent {
            event_name: "webhook.github".to_string(),
        };

        // When target node is Running: both data and control match
        let matches_running = registry.match_event(
            &event_scope,
            &event_predicate,
            Some(NodeLifecycleState::Running),
        );
        assert_eq!(matches_running.len(), 2);

        // Rule: Stop-requested nodes cannot start new work from a data subscription
        let matches_stop = registry.match_event(
            &event_scope,
            &event_predicate,
            Some(NodeLifecycleState::StopRequested),
        );
        assert_eq!(matches_stop.len(), 1);
        assert!(matches_stop[0].is_control);

        // Rule: Paused nodes retain control delivery by default;
        // only declared AutoResume rule can resume them
        let matches_paused = registry.match_event(
            &event_scope,
            &event_predicate,
            Some(NodeLifecycleState::Paused),
        );
        assert_eq!(matches_paused.len(), 1);
        assert!(matches_paused[0].is_control);

        // If data subscription declares AutoResume, it can resume
        let sub_autoresume = Subscription {
            subscription_id: "sub-resume-1".to_string(),
            subscriber_id: "subscriber-c".to_string(),
            scope: SubscriptionScope::Graph("graph-1".to_string()),
            predicate: SubscriptionPredicate::OnExternalEvent {
                event_name: "webhook.github".to_string(),
            },
            activation_rule: ActivationRule::AutoResume,
            durable_cursor: 0,
            is_control: false,
            active: true,
        };
        registry.subscribe(sub_autoresume);

        let matches_paused_resumable = registry.match_event(
            &event_scope,
            &event_predicate,
            Some(NodeLifecycleState::Paused),
        );
        assert_eq!(matches_paused_resumable.len(), 2);

        // Cursor advance
        registry.advance_cursor("sub-ctrl-1", 42);
        assert_eq!(
            registry
                .subscriptions
                .get("sub-ctrl-1")
                .unwrap()
                .durable_cursor,
            42
        );
    }

    #[test]
    fn test_fair_dispatch_queue_separate_capacities_and_bounds_rejection() {
        let bounds = QueueBounds {
            max_entries: 2,
            max_bytes: 100,
        };
        let mut queue = FairDispatchQueue::new(bounds, bounds, 2);

        // Enqueue 2 control items (reaches entry bound)
        queue
            .enqueue(ChannelKind::Control, "c1", json!({"cmd": 1}), 1000)
            .expect("c1 succeeds");
        queue
            .enqueue(ChannelKind::Control, "c2", json!({"cmd": 2}), 1001)
            .expect("c2 succeeds");

        // 3rd control item rejected due to max_entries
        let err = queue.enqueue(ChannelKind::Control, "c3", json!({"cmd": 3}), 1002);
        assert!(matches!(err, Err(QueueCapacityExceeded { .. })));

        // But Data channel still has capacity!
        queue
            .enqueue(ChannelKind::Data, "d1", json!({"task": 1}), 1003)
            .expect("d1 succeeds");

        // Byte limit rejection
        let large_payload = json!({"data": "x".repeat(200)});
        let err_bytes = queue.enqueue(ChannelKind::Data, "d2", large_payload, 1004);
        assert!(matches!(err_bytes, Err(QueueCapacityExceeded { .. })));
    }

    #[test]
    fn test_fair_dispatch_queue_fair_arbiter_prevents_starvation() {
        let bounds = QueueBounds {
            max_entries: 100,
            max_bytes: 10_000,
        };
        // Quantum = 2: serve 2 control items, then 1 data item if present
        let mut queue = FairDispatchQueue::new(bounds, bounds, 2);

        // Enqueue 4 control items and 2 data items
        queue
            .enqueue(ChannelKind::Control, "c1", json!({"c": 1}), 1000)
            .unwrap();
        queue
            .enqueue(ChannelKind::Control, "c2", json!({"c": 2}), 1001)
            .unwrap();
        queue
            .enqueue(ChannelKind::Control, "c3", json!({"c": 3}), 1002)
            .unwrap();
        queue
            .enqueue(ChannelKind::Control, "c4", json!({"c": 4}), 1003)
            .unwrap();

        queue
            .enqueue(ChannelKind::Data, "d1", json!({"d": 1}), 1004)
            .unwrap();
        queue
            .enqueue(ChannelKind::Data, "d2", json!({"d": 2}), 1005)
            .unwrap();

        // Dequeue sequence should be: c1, c2, d1, c3, c4, d2
        let item1 = queue.dequeue().expect("item 1");
        assert_eq!(item1.item_id, "c1");
        assert_eq!(item1.channel, ChannelKind::Control);

        let item2 = queue.dequeue().expect("item 2");
        assert_eq!(item2.item_id, "c2");
        assert_eq!(item2.channel, ChannelKind::Control);

        // Control quantum exhausted! Next MUST be Data to prevent starvation!
        let item3 = queue.dequeue().expect("item 3");
        assert_eq!(item3.item_id, "d1");
        assert_eq!(item3.channel, ChannelKind::Data);

        let item4 = queue.dequeue().expect("item 4");
        assert_eq!(item4.item_id, "c3");
        assert_eq!(item4.channel, ChannelKind::Control);

        let item5 = queue.dequeue().expect("item 5");
        assert_eq!(item5.item_id, "c4");
        assert_eq!(item5.channel, ChannelKind::Control);

        let item6 = queue.dequeue().expect("item 6");
        assert_eq!(item6.item_id, "d2");
        assert_eq!(item6.channel, ChannelKind::Data);

        assert!(queue.is_empty());

        // Replay from durable cursor
        let replay_all = queue.replay_from_cursor(1);
        assert_eq!(replay_all.len(), 6);
        let replay_from_4 = queue.replay_from_cursor(4);
        assert_eq!(replay_from_4.len(), 3);
        assert_eq!(replay_from_4[0].cursor, 4);
    }
}
