use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::{FallbackReceipt, PendingCallback, StrategyRunStatus, WorkflowDefinition};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BindingCandidate {
    pub value_id: String,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub reasoning_effort: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BindingValue {
    pub slot_id: String,
    #[serde(default)]
    pub ordinal: u8,
    pub value_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub model: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reasoning_effort: String,
    #[serde(default)]
    pub revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StrategyAuthorization {
    pub definition_digest: String,
    pub semantics_digest: String,
    pub binding_digest: String,
    pub authorization_digest: String,
    pub revision: u64,
    pub active: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StrategyDefinitionSummary {
    pub definition_id: String,
    pub revision_digest: String,
    pub semantics_digest: String,
    pub name: String,
    pub version: String,
    pub imported_at_unix_ms: i64,
    #[serde(default)]
    pub authorized: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StrategyDefinition {
    #[serde(flatten)]
    pub summary: StrategyDefinitionSummary,
    pub workflow: WorkflowDefinition,
    pub asset_count: usize,
    pub bindings: Vec<BindingValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization: Option<StrategyAuthorization>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StrategyDiagnostic {
    pub code: String,
    pub component: String,
    pub retryable: bool,
    pub recovery: String,
    #[serde(default)]
    pub arguments: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StrategyProjection {
    pub schema: String,
    pub definition: StrategyDefinitionSummary,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    pub status: StrategyRunStatus,
    pub current_states: BTreeSet<String>,
    pub neighbor_states: BTreeSet<String>,
    pub allowed_operations: BTreeSet<String>,
    pub bindings: Vec<BindingValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostic: Option<StrategyDiagnostic>,
    pub history_count: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fallbacks: Vec<FallbackReceipt>,
    /// Callback-mode edges that settled and now wait for the run decider's
    /// settlement, in the deterministic order the waits were entered.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pending_callbacks: Vec<PendingCallback>,
    #[serde(default)]
    pub needs_human_input: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_session_id: Option<String>,
}

// Host-side items intentionally left to the product: the strategy wire error
// vocabulary, the ephemeral internal-definition prefix, and the coordinator
// projection policy. The generic DTOs above carry no product vocabulary.
