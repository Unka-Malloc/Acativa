//! Host-wide unfinished-work read for the durable strategy store.
//!
//! The strategy database is the local authority for queued, paused, held and
//! unfinished workflow work. [`StrategyStore::unfinished_local_work`] answers
//! that question in one bounded read so a maintenance owner can refuse to
//! replace installed state while this host still owns workflow work.
//!
//! # What blocks, and what does not
//!
//! Every durable category of locally owned work participates, so a maintenance
//! decision cannot mistake a *request* for an observed exit:
//!
//! * An unfinished run (`strategy_runs.terminal=0`) blocks: its commands and
//!   transitions still have to settle. A run waiting on approval or a callback
//!   is not terminal, so it blocks too.
//! * A `pending` or `claimed` queue item blocks: `pending` is work this host
//!   queued, `claimed` is work a local claimant holds. A claimant that
//!   disconnected without settling leaves exactly this row.
//! * An in-flight or unresolved effect blocks. `claimed`, `running` and
//!   `cancel_requested` are work that has left, or is leaving, this host;
//!   `in_doubt` is work whose outcome could not be established. A cancellation
//!   request therefore does not prove idleness, a lost local carrier does not
//!   prove idleness, and an unknown effect position stays owned here until its
//!   owner resolves it. This is also how a run whose cancellation outcome is
//!   unknown is reported, since the run itself reaches a terminal status.
//! * An active pause request blocks: the graph is negotiating a pause and the
//!   paused work is still owned here.
//! * An active graph barrier blocks: the graph is deliberately held, and
//!   replacing the state it runs against would strand it.
//! * An unsettled invocation blocks. Today every writer records settlement in
//!   the same write that admits the invocation, so this arm covers records a
//!   recovery path has yet to settle rather than a normal transient.
//!
//! `workflow_transition_intents`, `workflow_control_admissions` and
//! `workflow_subscriptions` are delivery and idempotency records, not locally
//! owned tasks, so they never block on their own.

use anyhow::{Result, anyhow, ensure};
use rusqlite::Connection;
use serde::Serialize;
use std::path::{Path, PathBuf};

use super::store::{StoreDialect, preflight_existing_store};

/// Which durable workflow record still owns work.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum WorkflowWorkKind {
    /// A strategy run that has not reached a terminal snapshot.
    Run,
    /// A queued or claimed delivery item.
    QueueItem,
    /// An effect that has left, is leaving, or whose outcome is unknown.
    Effect,
    /// An invocation this host has not settled.
    Invocation,
    /// A graph negotiating a pause.
    PauseRequest,
    /// A deliberately held graph.
    GraphBarrier,
}

impl WorkflowWorkKind {
    /// The stable wire name, also used as the SQL discriminator.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Run => "workflow-run",
            Self::QueueItem => "workflow-queue-item",
            Self::Effect => "workflow-effect",
            Self::Invocation => "workflow-invocation",
            Self::PauseRequest => "workflow-pause-request",
            Self::GraphBarrier => "workflow-graph-barrier",
        }
    }
}

/// One durable workflow record that makes this host's work unfinished.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowWorkBlocker {
    pub kind: WorkflowWorkKind,
    /// The graph, run or command the record belongs to. Empty for a queue item,
    /// which is not bound to one graph; the run id for a run or effect.
    pub graph_id: String,
    /// Stable identity inside its kind: run id, queue item id, a command id, a
    /// stop/pause target, `node#invocation` for an invocation, or `graph` for a
    /// held graph.
    pub identity: String,
    /// The stored state that makes the record a blocker.
    pub state: String,
}

/// The bounded answer of one durable-workflow unfinished-work read.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnfinishedWorkflowWork {
    pub blockers: Vec<WorkflowWorkBlocker>,
    /// True when more blockers exist than
    /// [`MAX_UNFINISHED_WORKFLOW_WORK`] reports.
    pub truncated: bool,
}

impl UnfinishedWorkflowWork {
    /// The empty answer for a host that has no strategy database yet.
    pub fn empty() -> Self {
        Self {
            blockers: Vec::new(),
            truncated: false,
        }
    }

    /// No unfinished workflow work is recorded.
    pub fn is_idle(&self) -> bool {
        self.blockers.is_empty()
    }

    /// The reported blockers, in the read's deterministic order.
    pub fn blockers(&self) -> &[WorkflowWorkBlocker] {
        &self.blockers
    }
}

/// Upper bound on the blockers one read returns.
pub const MAX_UNFINISHED_WORKFLOW_WORK: usize = 128;

impl StoreDialect {
    /// The strategy database path for a data root under this dialect, without
    /// opening or creating the store.
    pub fn database_path(&self, portable_root: &Path) -> PathBuf {
        self.state_dir(portable_root).join("strategies.sqlite3")
    }
}

/// Every unfinished locally owned workflow task, read straight from the
/// strategy database without opening, initializing or mutating it.
///
/// A maintenance decision must never change the work it decides about, so it
/// uses this entry rather than [`StrategyStore::open`], which initializes the
/// schema. A data root without a database has no record, so it has no
/// unfinished workflow work either; a database that is not the current shape
/// or is missing a table this read needs is an error, because this reader
/// cannot repair it.
pub fn read_unfinished_local_work(
    portable_root: &Path,
    dialect: &StoreDialect,
) -> Result<UnfinishedWorkflowWork> {
    let path = dialect.database_path(portable_root);
    if !path.is_file() {
        return Ok(UnfinishedWorkflowWork::empty());
    }
    preflight_existing_store(&path)?;
    let connection = Connection::open_with_flags(
        &path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    for table in [
        "strategy_runs",
        "strategy_commands",
        "workflow_queue",
        "workflow_invocations",
        "workflow_pause_requests",
        "workflow_graph_state",
    ] {
        let exists: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
            [table],
            |row| row.get(0),
        )?;
        ensure!(exists, "workflow_schema_migration_required");
    }
    unfinished_local_work(&connection)
}

fn unfinished_local_work(connection: &Connection) -> Result<UnfinishedWorkflowWork> {
    let sql = format!(
        "SELECT kind, graph_id, identity, state FROM (
           SELECT '{run}' AS kind, run_id AS graph_id, run_id AS identity,
                  'unfinished' AS state
             FROM strategy_runs
            WHERE COALESCE(terminal, 0)=0
           UNION ALL
           SELECT '{queue}', '', item_id, status
             FROM workflow_queue
            WHERE status IN ('pending','claimed')
           UNION ALL
           SELECT '{effect}', run_id, command_id, status
             FROM strategy_commands
            WHERE status IN ('claimed','running','cancel-requested','in-doubt')
           UNION ALL
           SELECT '{invocation}', graph_id, node_id||'#'||invocation_id, 'unsettled'
             FROM workflow_invocations
            WHERE settled=0
           UNION ALL
           SELECT '{pause}', graph_id, target, 'pause-requested'
             FROM workflow_pause_requests
            WHERE active=1
           UNION ALL
           SELECT '{barrier}', graph_id, 'graph', 'barrier-active'
             FROM workflow_graph_state
            WHERE barrier_active=1
         )
         ORDER BY kind, graph_id, identity
         LIMIT {limit}",
        run = WorkflowWorkKind::Run.as_str(),
        queue = WorkflowWorkKind::QueueItem.as_str(),
        effect = WorkflowWorkKind::Effect.as_str(),
        invocation = WorkflowWorkKind::Invocation.as_str(),
        pause = WorkflowWorkKind::PauseRequest.as_str(),
        barrier = WorkflowWorkKind::GraphBarrier.as_str(),
        limit = MAX_UNFINISHED_WORKFLOW_WORK + 1,
    );
    let mut statement = connection.prepare(&sql)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let truncated = rows.len() > MAX_UNFINISHED_WORKFLOW_WORK;
    let mut blockers = Vec::with_capacity(rows.len().min(MAX_UNFINISHED_WORKFLOW_WORK));
    for (kind, graph_id, identity, state) in rows.into_iter().take(MAX_UNFINISHED_WORKFLOW_WORK) {
        let kind = match kind.as_str() {
            "workflow-run" => WorkflowWorkKind::Run,
            "workflow-queue-item" => WorkflowWorkKind::QueueItem,
            "workflow-effect" => WorkflowWorkKind::Effect,
            "workflow-invocation" => WorkflowWorkKind::Invocation,
            "workflow-pause-request" => WorkflowWorkKind::PauseRequest,
            "workflow-graph-barrier" => WorkflowWorkKind::GraphBarrier,
            other => return Err(anyhow!("workflow_work_kind_unknown: {other}")),
        };
        blockers.push(WorkflowWorkBlocker {
            kind,
            graph_id,
            identity,
            state,
        });
    }
    Ok(UnfinishedWorkflowWork {
        blockers,
        truncated,
    })
}
