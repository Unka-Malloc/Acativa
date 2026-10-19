//! Generic effect-turn ports and in-process drive bookkeeping.
//!
//! A host's drive loop owns strategy composition; this module owns the
//! primitives every such loop needs so a cancellation that arrives while one
//! exact turn is still being prepared can never guess an identity:
//!
//! * [`ActorTurnPort`] — the host's dispatch seam for one actor-bound command.
//!   `open` registers the turn and returns its handle, `run` executes one
//!   opened turn to its terminal state, `cancel` signals one opened turn to
//!   stop, and `abandon` settles one opened turn that will never run.
//!   Composition happens where the persistent host runtime exists; the engine
//!   treats the port as opaque.
//! * [`RunWakePort`] — the notice seam for a run's designated coordinator.
//!   `wake` receives the coordinator's channel identity, its member identity,
//!   and the identifier-only notice part the host already persisted; it opens
//!   one new coordinator turn for that notice only when no turn of that
//!   identity is in flight.
//! * [`LiveTurnRegistration`], [`live_turn_owner`], [`DriveReservation`] and
//!   the cancelled-runs set — the in-process ownership facts a drive consults
//!   before touching durable state, so an ordinary drive batch performs no
//!   extra store read.

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, OnceLock};

use crate::ports::ActorTurnError;
use crate::workflow::machine::{CommandKind, RunCommand};

/// The dispatch seam for one host-bound actor command. `open` registers the
/// turn and returns its handle, `run` executes one opened turn to its
/// terminal state, `cancel` signals one opened turn to stop, and `abandon`
/// settles one opened turn that will never run. Composition happens where the
/// persistent host runtime exists; the engine treats the port as opaque.
pub type ActorTurnOpen =
    Arc<dyn Fn(&Value) -> std::result::Result<String, ActorTurnError> + Send + Sync>;
pub type ActorTurnRun =
    Arc<dyn Fn(&str, &Value) -> std::result::Result<Value, ActorTurnError> + Send + Sync>;
pub type ActorTurnCancel = Arc<dyn Fn(&str) -> TurnCancelDisposition + Send + Sync>;

pub struct ActorTurnPort {
    pub open: ActorTurnOpen,
    pub run: ActorTurnRun,
    pub cancel: ActorTurnCancel,
    pub abandon: Arc<dyn Fn(&str) + Send + Sync>,
}

/// The bounded outcome of one turn-cancel request routed through the port. The
/// port converts adapter control results into these facts, so a raw adapter
/// error can never fabricate an observed stop.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TurnCancelDisposition {
    /// The owning runtime accepted cancellation for the exact in-flight turn.
    Accepted,
    /// The owner has no active turn for that handle; the effect position stays
    /// unknown.
    NoActiveTurn,
    /// The owning runtime is unreachable from this process.
    Unavailable,
}

impl TurnCancelDisposition {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::NoActiveTurn => "no-active-turn",
            Self::Unavailable => "unavailable",
        }
    }
}

/// The live in-process owner of one (run, command) attempt.
///
/// The drive reserves the entry before the command becomes `Running`, so a
/// cancellation that arrives while the turn is still being prepared can wait
/// for the exact turn identity instead of guessing one.
type LiveTurnTable = Mutex<BTreeMap<(String, String), (String, Option<String>)>>;

fn live_turns() -> &'static LiveTurnTable {
    static TURNS: OnceLock<LiveTurnTable> = OnceLock::new();
    TURNS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// One drive-owned command attempt. `reserve` runs before the command becomes
/// `Running`; `attach` records the exact turn handle once the port opens it;
/// `Drop` removes the entry only when it is still this attempt's own.
pub struct LiveTurnRegistration {
    run_id: String,
    command_id: String,
    attempt_token: String,
    handle: Option<String>,
}

impl LiveTurnRegistration {
    pub fn reserve(run_id: &str, command_id: &str, attempt_token: &str) -> Self {
        let mut turns = live_turns()
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        turns.insert(
            (run_id.to_owned(), command_id.to_owned()),
            (attempt_token.to_owned(), None),
        );
        Self {
            run_id: run_id.to_owned(),
            command_id: command_id.to_owned(),
            attempt_token: attempt_token.to_owned(),
            handle: None,
        }
    }

    pub fn attach(&mut self, handle: &str) {
        let mut turns = live_turns()
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let key = (self.run_id.clone(), self.command_id.clone());
        let owned = turns
            .get(&key)
            .is_some_and(|(token, _)| token == &self.attempt_token);
        if owned || !turns.contains_key(&key) {
            turns.insert(key, (self.attempt_token.clone(), Some(handle.to_owned())));
        }
        self.handle = Some(handle.to_owned());
    }
}

impl Drop for LiveTurnRegistration {
    fn drop(&mut self) {
        let mut turns = live_turns()
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let key = (self.run_id.clone(), self.command_id.clone());
        if turns
            .get(&key)
            .is_some_and(|(token, _)| token == &self.attempt_token)
        {
            turns.remove(&key);
        }
    }
}

/// What this process knows about the live owner of one command attempt.
pub enum LiveTurnOwner {
    /// No in-process drive owns this attempt.
    Absent,
    /// The drive owns it and is preparing the turn; the handle is not yet
    /// known.
    Preparing,
    /// The exact turn handle executing this attempt.
    Ready(String),
}

pub fn live_turn_owner(run_id: &str, command_id: &str, attempt_token: &str) -> LiveTurnOwner {
    let turns = live_turns()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    match turns.get(&(run_id.to_owned(), command_id.to_owned())) {
        Some((token, Some(handle))) if token == attempt_token => {
            LiveTurnOwner::Ready(handle.clone())
        }
        Some((token, None)) if token == attempt_token => LiveTurnOwner::Preparing,
        _ => LiveTurnOwner::Absent,
    }
}

/// The notice seam for a run's designated coordinator. `wake` receives the
/// coordinator's channel identity, its member identity, and the
/// identifier-only notice part already appended to the host's durable
/// timeline; it opens one new coordinator turn for that notice only when no
/// turn of that identity is in flight. Composition happens where the
/// persistent host runtime exists.
pub type RunWake = Arc<dyn Fn(&str, &str, &Value) -> std::result::Result<(), String> + Send + Sync>;

pub struct RunWakePort {
    pub wake: RunWake,
}

/// Runs this process has cancelled since their drive started. The settle path
/// consults it before touching the durable run again, so an ordinary drive
/// batch performs no extra store read.
fn cancelled_runs() -> &'static Mutex<BTreeSet<String>> {
    static RUNS: OnceLock<Mutex<BTreeSet<String>>> = OnceLock::new();
    RUNS.get_or_init(|| Mutex::new(BTreeSet::new()))
}

pub fn mark_run_cancelled(run_id: &str) {
    cancelled_runs()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .insert(run_id.to_owned());
}

pub fn unmark_run_cancelled(run_id: &str) {
    cancelled_runs()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .remove(run_id);
}

pub fn cancellation_pending(run_id: &str) -> bool {
    cancelled_runs()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .contains(run_id)
}

fn driving_runs() -> &'static Mutex<BTreeSet<String>> {
    static RUNS: OnceLock<Mutex<BTreeSet<String>>> = OnceLock::new();
    RUNS.get_or_init(|| Mutex::new(BTreeSet::new()))
}

/// An in-process exclusive drive hold for one run. `acquire` returns `None`
/// while another drive of this process already owns the run; the hold releases
/// on drop, so a drive that exits early can never strand the run as driving.
pub struct DriveReservation {
    run_id: String,
}

impl DriveReservation {
    pub fn acquire(run_id: &str) -> Option<Self> {
        let mut driving = driving_runs()
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        driving.insert(run_id.to_owned()).then(|| Self {
            run_id: run_id.to_owned(),
        })
    }

    pub fn is_active(run_id: &str) -> bool {
        driving_runs()
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .contains(run_id)
    }
}

impl Drop for DriveReservation {
    fn drop(&mut self) {
        driving_runs()
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .remove(&self.run_id);
    }
}

/// One registered entry turn whose settlement is owed to the drive that runs
/// it. Dropping an armed registration abandons the handle with a typed code,
/// so a drive that exits, fails to claim, or claims another command first can
/// never leave a phantom active turn keeping the host's pane busy.
pub struct EntryTurnRegistration {
    slot_id: String,
    handle: String,
    params: Value,
    port: Arc<ActorTurnPort>,
    armed: bool,
}

impl EntryTurnRegistration {
    /// Register a pre-opened entry turn against the binding slot it will run.
    pub fn new(slot_id: String, handle: String, params: Value, port: Arc<ActorTurnPort>) -> Self {
        Self {
            slot_id,
            handle,
            params,
            port,
            armed: true,
        }
    }

    /// A turn opened inline by the drive owns the same abandonment guarantee
    /// as a pre-registered entry turn.
    pub fn ad_hoc(handle: String, params: Value, port: Arc<ActorTurnPort>) -> Self {
        Self::new(String::new(), handle, params, port)
    }

    /// Whether this registration is the exact first command of its slot: a
    /// first-visit, first-ordinal actor or workset-item command bound to the
    /// registered slot.
    pub fn matches(&self, command: &RunCommand) -> bool {
        !self.slot_id.is_empty()
            && matches!(command.kind, CommandKind::Actor | CommandKind::WorksetItem)
            && command.binding_id.as_deref() == Some(self.slot_id.as_str())
            && command.state_visit == 1
            && command.binding_ordinal == 0
    }

    /// Hand the registered turn to the drive's run path. From this point the
    /// dispatch completion authority owns its settlement.
    pub fn into_run(mut self) -> (String, Value) {
        self.armed = false;
        (self.handle.clone(), self.params.clone())
    }
}

impl Drop for EntryTurnRegistration {
    fn drop(&mut self) {
        if self.armed {
            (self.port.abandon)(&self.handle);
        }
    }
}
