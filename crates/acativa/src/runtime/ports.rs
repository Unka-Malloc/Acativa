//! The facts and effects the workflow runtime reads but does not own.
//!
//! The runtime declares what it needs, and the host that composes it supplies
//! the implementations once, at its crate root. Nothing here names a host
//! module: a process that installs no [`HostPorts`] keeps every read absent
//! and every effect refused, so a missing installation is a typed refusal
//! rather than invented work.
use anyhow::{Result, anyhow, ensure};
use serde_json::Value;
use std::fmt::{Display, Formatter};
use std::path::Path;
use std::sync::{Arc, OnceLock};

use crate::workflow::machine::RunCommand;
use crate::{BindingValue, RuntimeKind};

/// The allowlisted model facts the runtime reads.
///
/// The port answers projections only — a display name, an allowlisted fact
/// document, task tags — never a credential, an endpoint or a raw catalog row.
/// What "the catalog" is stays the host's concern.
pub trait ModelFactsPort: Send + Sync {
    /// Human-facing display name for a model id, or the id itself.
    fn model_display_name(&self, model: &str) -> String;
    /// The allowlisted intelligence projection for a model id, when the
    /// host's catalog carries one. Unknown models stay absent rather than
    /// invented.
    fn project_allowlisted_model(&self, model: &str) -> Option<Value>;
    /// The curated task tags the host's catalog carries for a model id.
    fn task_tags_for_model(&self, model: &str) -> Vec<String>;
}

/// The numeric run usage ledger.
///
/// Every projection this port carries is rebuilt from typed run, binding and
/// command fields by the caller; input and output bodies never cross the seam.
pub trait UsageLedgerPort: Send + Sync {
    fn begin_graph_run(&self, payload: &Value) -> Result<()>;
    fn record_graph_command(&self, payload: &Value) -> Result<()>;
    fn workflow_report(&self, payload: &Value) -> Result<Value>;
}

/// One runtime the host resolved for one requirement.
///
/// The runtime never learns the executable path or the resolution root: it
/// carries the handle back to the same port for the effect, and the identity a
/// permit is bound to is the fingerprint the host published.
pub trait ResolvedRuntime: Send + Sync {
    fn fingerprint(&self) -> &str;
    /// The handle as `Any`, so the port that issued it recovers its own
    /// resolution without this crate naming that type.
    fn as_any(&self) -> &dyn std::any::Any;
}

/// The host's effect seam: runtime resolution, sandbox admission, actor and
/// script execution, lane dispatch and the owned-run stop record.
pub trait EffectPort: Send + Sync {
    /// The discovered runtime descriptors, already in their wire shape.
    fn runtime_descriptors(&self) -> Vec<Value>;

    /// The compatible runtime id for one requirement, when one is installed.
    fn compatible_runtime_id(&self, kind: RuntimeKind, version_requirement: &str)
    -> Option<String>;

    /// Resolve one exact runtime for a requirement.
    fn resolve_runtime(
        &self,
        runtime_id: &str,
        kind: RuntimeKind,
        version_requirement: &str,
    ) -> Result<Arc<dyn ResolvedRuntime>>;

    /// The stable fingerprint of one actor identity under a model and effort.
    fn actor_fingerprint(
        &self,
        value_id: &str,
        model: &str,
        reasoning_effort: &str,
    ) -> Result<String>;

    /// The capability probe answer for one actor identity, in the probe owner's
    /// own wire shape.
    ///
    /// Capability discovery is a host concern with a typed seam, so a binding
    /// check does not have to borrow the host lane's generic operation
    /// dispatcher to ask one question. A caller reads the answer as the probe
    /// owner published it.
    fn actor_capabilities(&self, value_id: &str) -> Result<Value>;

    /// Refuse a workspace outside the strategy sandbox policy.
    fn admit_strategy_cwd(&self, cwd: &str) -> Result<()>;

    /// Execute one script command under a consumed permit.
    fn execute_script(
        &self,
        command: &RunCommand,
        authorization_digest: &str,
        runtime: &Arc<dyn ResolvedRuntime>,
        revision_content: &Path,
        runtime_state_root: &Path,
        permit: &mut StrategyEffectPermit,
    ) -> Result<Value>;

    /// Execute one actor command under a consumed permit.
    fn execute_actor(
        &self,
        command: &RunCommand,
        authorization_digest: &str,
        binding: &BindingValue,
        permit: &mut StrategyEffectPermit,
        cwd: Option<&str>,
    ) -> Result<Value>;

    /// The predecessor locator a fallback carries for the failed command.
    fn predecessor_locator(&self, facts: &Value) -> Value;

    /// One operation through the host's own dispatch lane.
    fn dispatch_lane_operation(&self, operation: &str, params: &Value) -> Result<Value>;

    /// A fresh correlation id for one stop request.
    fn new_correlation_id(&self) -> String;

    /// Record one owned-run stop outcome in the durable local record.
    fn record_run_stop(
        &self,
        portable_root: &Path,
        correlation_id: &str,
        confirmed: bool,
    ) -> Result<()>;
}

/// One effect permit: the exact command, authorization and effect identity the
/// host issued it for.
///
/// The permit is data, not authority. Issuing it proves only that the runtime
/// assembled the three identities; the port that consumes it re-checks them
/// against its own resolution before any external work happens.
#[derive(Clone, Debug)]
pub struct StrategyEffectPermit {
    command_id: String,
    authorization_digest: String,
    effect_fingerprint: String,
    consumed: bool,
}

impl StrategyEffectPermit {
    pub fn issue(
        command_id: &str,
        authorization_digest: &str,
        effect_fingerprint: &str,
    ) -> Result<Self> {
        ensure!(
            !command_id.is_empty()
                && authorization_digest.len() == 64
                && effect_fingerprint.len() == 64,
            "strategy_permit_invalid"
        );
        Ok(Self {
            command_id: command_id.to_owned(),
            authorization_digest: authorization_digest.to_owned(),
            effect_fingerprint: effect_fingerprint.to_owned(),
            consumed: false,
        })
    }

    /// Consume the permit for exactly the effect it was issued for. A second
    /// consume, or a command that does not match the issued identities, fails
    /// instead of running anything.
    pub fn consume(
        &mut self,
        command: &RunCommand,
        authorization_digest: &str,
        effect_fingerprint: &str,
    ) -> Result<()> {
        ensure!(!self.consumed, "strategy_permit_consumed");
        ensure!(
            self.command_id == command.id
                && self.authorization_digest == authorization_digest
                && self.effect_fingerprint == effect_fingerprint,
            "strategy_permit_stale"
        );
        self.consumed = true;
        Ok(())
    }
}

/// The dispatch error one actor turn port may report.
///
/// The port carries its own error rather than the adapter registry's: the
/// runtime acts on the fact that the lane could not be reached, not on the
/// adapter's taxonomy, and the adapter owner supplies the detail the runtime
/// only quotes back into its own bounded failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActorTurnError {
    detail: String,
}

impl ActorTurnError {
    /// One refused or incomplete dispatch, with the owner's own detail.
    pub fn dispatch_failed(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }

    /// The owner's detail, quoted into the runtime's bounded failure.
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl Display for ActorTurnError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.detail)
    }
}

impl std::error::Error for ActorTurnError {}

// ------------------------------------------------------- host composition

/// Everything the runtime reads from the host that composes it.
///
/// The host installs one of these per process at its crate root. A process
/// that installs nothing keeps every port fail-closed: no effect runs, no fact
/// is invented, and the ledger records nothing.
#[derive(Clone)]
pub struct HostPorts {
    /// The allowlisted model facts.
    pub model: Arc<dyn ModelFactsPort>,
    /// The numeric run usage ledger.
    pub usage: Arc<dyn UsageLedgerPort>,
    /// The effect seam.
    pub effect: Arc<dyn EffectPort>,
}

impl HostPorts {
    /// The composition a process has when it installed none: every read is
    /// absent and every effect is refused, so a missing installation is a
    /// typed refusal rather than invented work.
    pub fn unavailable() -> Self {
        Self {
            model: Arc::new(UnavailableModelFacts),
            usage: Arc::new(UnavailableUsageLedger),
            effect: Arc::new(UnavailableEffect),
        }
    }
}

impl std::fmt::Debug for HostPorts {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("HostPorts").finish_non_exhaustive()
    }
}

static HOST_PORTS: OnceLock<HostPorts> = OnceLock::new();

/// Install the process-wide composition. The first installation wins; a later
/// one is ignored, so a host that composes the same answers twice stays one
/// composition.
pub fn install_host_ports(ports: HostPorts) {
    let _ = HOST_PORTS.set(ports);
}

/// The installed composition, or the refusing default.
pub fn host_ports() -> &'static HostPorts {
    HOST_PORTS.get_or_init(HostPorts::unavailable)
}

struct UnavailableModelFacts;

impl ModelFactsPort for UnavailableModelFacts {
    fn model_display_name(&self, model: &str) -> String {
        // Display typography is a pure naming projection, not a catalog
        // fact. The host answers the same function; an uninstalled catalog
        // still formats the id instead of publishing it raw.
        crate::util::model_naming::model_display_name(model)
    }

    fn project_allowlisted_model(&self, _model: &str) -> Option<Value> {
        None
    }

    fn task_tags_for_model(&self, _model: &str) -> Vec<String> {
        Vec::new()
    }
}

struct UnavailableUsageLedger;

impl UsageLedgerPort for UnavailableUsageLedger {
    fn begin_graph_run(&self, _payload: &Value) -> Result<()> {
        Ok(())
    }

    fn record_graph_command(&self, _payload: &Value) -> Result<()> {
        Ok(())
    }

    fn workflow_report(&self, _payload: &Value) -> Result<Value> {
        Err(anyhow!("workflow_host_port_unavailable"))
    }
}

struct UnavailableEffect;

impl EffectPort for UnavailableEffect {
    fn runtime_descriptors(&self) -> Vec<Value> {
        Vec::new()
    }

    fn compatible_runtime_id(
        &self,
        _kind: RuntimeKind,
        _version_requirement: &str,
    ) -> Option<String> {
        None
    }

    fn resolve_runtime(
        &self,
        _runtime_id: &str,
        _kind: RuntimeKind,
        _version_requirement: &str,
    ) -> Result<Arc<dyn ResolvedRuntime>> {
        Err(anyhow!("workflow_host_port_unavailable"))
    }

    fn actor_fingerprint(
        &self,
        _value_id: &str,
        _model: &str,
        _reasoning_effort: &str,
    ) -> Result<String> {
        Err(anyhow!("workflow_host_port_unavailable"))
    }

    fn actor_capabilities(&self, _value_id: &str) -> Result<Value> {
        Err(anyhow!("workflow_host_port_unavailable"))
    }

    fn admit_strategy_cwd(&self, _cwd: &str) -> Result<()> {
        Err(anyhow!("workflow_host_port_unavailable"))
    }

    fn execute_script(
        &self,
        _command: &RunCommand,
        _authorization_digest: &str,
        _runtime: &Arc<dyn ResolvedRuntime>,
        _revision_content: &Path,
        _runtime_state_root: &Path,
        _permit: &mut StrategyEffectPermit,
    ) -> Result<Value> {
        Err(anyhow!("workflow_host_port_unavailable"))
    }

    fn execute_actor(
        &self,
        _command: &RunCommand,
        _authorization_digest: &str,
        _binding: &BindingValue,
        _permit: &mut StrategyEffectPermit,
        _cwd: Option<&str>,
    ) -> Result<Value> {
        Err(anyhow!("workflow_host_port_unavailable"))
    }

    fn predecessor_locator(&self, _facts: &Value) -> Value {
        Value::Null
    }

    fn dispatch_lane_operation(&self, _operation: &str, _params: &Value) -> Result<Value> {
        Err(anyhow!("workflow_host_port_unavailable"))
    }

    fn new_correlation_id(&self) -> String {
        String::new()
    }

    fn record_run_stop(
        &self,
        _portable_root: &Path,
        _correlation_id: &str,
        _confirmed: bool,
    ) -> Result<()> {
        Ok(())
    }
}
