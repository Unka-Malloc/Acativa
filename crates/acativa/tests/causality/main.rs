//! V7-C2 — causal input, joins, and pure state transitions.
//!
//! The plan asks for two things at once: a node's input must come only from its
//! declared dependencies and explicitly versioned shared reads, and a loop must
//! be separated by visit so an old visit can never satisfy a new join. The
//! evidence is differential. A reference reducer — a complete, straightforward
//! recomputation of the causal facts from the definition and the ordered outcome
//! log, with no ledgers, no deltas, and no shared state — is run beside the
//! incremental machine over enumerated orderings, and the two must agree. The
//! same enumeration is required to reach one canonical snapshot, so the machine
//! cannot be right "on average" over the orderings.
//!
//! What the reference covers: node visits and their declared predecessor
//! contributions, join epochs, and the visit each predecessor contributed at.
//! What it deliberately does not cover: command statuses, failure classes,
//! retry budgets, and result payloads. Those belong to sibling tasks; claiming
//! this file proves them would be a lie about its scope.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde_json::{Value, json};

use acativa::compile::CompiledWorkflow;
use acativa::{
    ActorSlot, CallbackDecision, FailureClass, GraphState, GraphStateKind, InputBinding, InputPlan,
    MergePolicy, ReducerEvent, RetryPolicy, RunSnapshot, SharedResourceDecl, StrategyRunStatus,
    Transition, TransitionEvent, TransitionMode, WorkflowDefinition, WorkflowLimits,
    WorkflowMetadata, WorksetTemplate, reduce,
};

/// Every causality fixture compiles under the crate's generic schema: the
/// same parameter a host binds its own identity to.
fn compile_workflow(
    definition: WorkflowDefinition,
) -> Result<CompiledWorkflow, acativa::WorkflowValidationFailure> {
    acativa::compile_workflow(
        definition,
        &acativa::SchemaId::new(acativa::GENERIC_WORKFLOW_SCHEMA),
    )
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn state(id: &str, kind: GraphStateKind) -> GraphState {
    GraphState {
        id: id.into(),
        kind,
        label: id.into(),
        instruction: String::new(),
        binding: None,
        runtime: None,
        entry: None,
        workset: None,
        retry: RetryPolicy::default(),
    }
}

fn actor(id: &str, slot: &str, instruction: &str) -> GraphState {
    GraphState {
        binding: Some(slot.into()),
        instruction: instruction.into(),
        ..state(id, GraphStateKind::Actor)
    }
}

fn edge(from: &str, to: &str, event: TransitionEvent, mode: TransitionMode) -> Transition {
    Transition {
        id: format!("{from}-{to}"),
        from: from.into(),
        to: to.into(),
        event,
        mode,
        guard: None,
    }
}

fn definition(
    id: &str,
    initial: &str,
    states: Vec<GraphState>,
    transitions: Vec<Transition>,
    worksets: Vec<WorksetTemplate>,
) -> WorkflowDefinition {
    WorkflowDefinition {
        schema: acativa::GENERIC_WORKFLOW_SCHEMA.into(),
        metadata: WorkflowMetadata {
            id: id.into(),
            name: id.into(),
            version: "1".into(),
            description: String::new(),
        },
        limits: WorkflowLimits::default(),
        actor_slots: if states.iter().any(|state| state.binding.is_some()) {
            vec![ActorSlot::required_actor("worker", "Worker")]
        } else {
            vec![]
        },
        runtimes: vec![],
        worksets,
        initial: initial.into(),
        states,
        transitions,
    }
}

/// A fork whose two branches reconverge on a join, then one effect state.
///
/// A branch edge into the join may be declared a callback, which is the only
/// way the IR can advance one branch's visit while the other branch is parked.
fn fork_join(branch_a_callback: bool, branch_b_callback: bool) -> CompiledWorkflow {
    let branch = |callback: bool| {
        if callback {
            TransitionMode::Callback
        } else {
            TransitionMode::Flow
        }
    };
    compile_workflow(definition(
        "fork-join",
        "start",
        vec![
            state("start", GraphStateKind::Pass),
            state("fan", GraphStateKind::Fork),
            state("branch-a", GraphStateKind::Pass),
            state("branch-b", GraphStateKind::Pass),
            state("join", GraphStateKind::Join),
            actor("c", "worker", "Consume the joined inputs."),
            state("done", GraphStateKind::Succeed),
            state("fail", GraphStateKind::Fail),
        ],
        vec![
            edge(
                "start",
                "fan",
                TransitionEvent::Complete,
                TransitionMode::Flow,
            ),
            edge(
                "fan",
                "branch-a",
                TransitionEvent::Complete,
                TransitionMode::Flow,
            ),
            edge(
                "fan",
                "branch-b",
                TransitionEvent::Complete,
                TransitionMode::Flow,
            ),
            edge(
                "branch-a",
                "join",
                TransitionEvent::Complete,
                branch(branch_a_callback),
            ),
            edge(
                "branch-b",
                "join",
                TransitionEvent::Complete,
                branch(branch_b_callback),
            ),
            edge("join", "c", TransitionEvent::Complete, TransitionMode::Flow),
            edge("c", "done", TransitionEvent::Success, TransitionMode::Flow),
            edge("c", "fail", TransitionEvent::Failure, TransitionMode::Flow),
        ],
        vec![],
    ))
    .expect("the fork/join fixture compiles")
}

/// The same fork/join with a callback on the join's own exit, which is the
/// reachable way to ask the machine to enter a join it has already decided.
fn fork_join_with_join_callback() -> CompiledWorkflow {
    compile_workflow(definition(
        "fork-join-callback",
        "start",
        vec![
            state("start", GraphStateKind::Pass),
            state("fan", GraphStateKind::Fork),
            state("branch-a", GraphStateKind::Pass),
            state("branch-b", GraphStateKind::Pass),
            state("join", GraphStateKind::Join),
            actor("c", "worker", "Consume the joined inputs."),
            state("done", GraphStateKind::Succeed),
            state("fail", GraphStateKind::Fail),
        ],
        vec![
            edge(
                "start",
                "fan",
                TransitionEvent::Complete,
                TransitionMode::Flow,
            ),
            edge(
                "fan",
                "branch-a",
                TransitionEvent::Complete,
                TransitionMode::Flow,
            ),
            edge(
                "fan",
                "branch-b",
                TransitionEvent::Complete,
                TransitionMode::Flow,
            ),
            edge(
                "branch-a",
                "join",
                TransitionEvent::Complete,
                TransitionMode::Flow,
            ),
            edge(
                "branch-b",
                "join",
                TransitionEvent::Complete,
                TransitionMode::Flow,
            ),
            edge(
                "join",
                "c",
                TransitionEvent::Complete,
                TransitionMode::Callback,
            ),
            edge("c", "done", TransitionEvent::Success, TransitionMode::Flow),
            edge("c", "fail", TransitionEvent::Failure, TransitionMode::Flow),
        ],
        vec![],
    ))
    .expect("the callback join fixture compiles")
}

fn tasks_template() -> WorksetTemplate {
    WorksetTemplate {
        id: "tasks".into(),
        item_binding: "id".into(),
        predecessor_field: String::new(),
    }
}

/// A workset whose items run concurrently, then one effect state that reads the
/// shared writes those items published.
fn workset_chain() -> CompiledWorkflow {
    compile_workflow(definition(
        "workset-chain",
        "tasks",
        vec![
            GraphState {
                kind: GraphStateKind::Workset,
                workset: Some("tasks".into()),
                ..actor("tasks", "worker", "Execute one item.")
            },
            actor("after", "worker", "Read what the items published."),
            state("done", GraphStateKind::Succeed),
            state("fail", GraphStateKind::Fail),
        ],
        vec![
            edge(
                "tasks",
                "after",
                TransitionEvent::Success,
                TransitionMode::Flow,
            ),
            edge(
                "tasks",
                "fail",
                TransitionEvent::Failure,
                TransitionMode::Flow,
            ),
            edge(
                "after",
                "done",
                TransitionEvent::Success,
                TransitionMode::Flow,
            ),
            edge(
                "after",
                "fail",
                TransitionEvent::Failure,
                TransitionMode::Flow,
            ),
        ],
        vec![tasks_template()],
    ))
    .expect("the workset fixture compiles")
}

// ---------------------------------------------------------------------------
// Driving
// ---------------------------------------------------------------------------

fn empty(run_id: &str) -> RunSnapshot {
    RunSnapshot::empty(run_id, "revision", "semantics")
}

fn start(workflow: &CompiledWorkflow, run_id: &str, input: Value) -> RunSnapshot {
    reduce(workflow, &empty(run_id), ReducerEvent::Start { input })
        .expect("the run starts")
        .snapshot
}

/// Claim and start one command, so the settlement arrives from a started
/// effect rather than a pending one.
fn running(workflow: &CompiledWorkflow, snapshot: &RunSnapshot, id: &str) -> RunSnapshot {
    let token = snapshot.commands[id].attempt_token.clone();
    let claimed = reduce(
        workflow,
        snapshot,
        ReducerEvent::CommandClaimed {
            command_id: id.into(),
            attempt_token: token.clone(),
        },
    )
    .expect("the command claims");
    reduce(
        workflow,
        &claimed.snapshot,
        ReducerEvent::CommandStarted {
            command_id: id.into(),
            attempt_token: token,
        },
    )
    .expect("the command starts")
    .snapshot
}

fn succeed(
    workflow: &CompiledWorkflow,
    snapshot: &RunSnapshot,
    id: &str,
    output: Value,
) -> RunSnapshot {
    let token = snapshot.commands[id].attempt_token.clone();
    reduce(
        workflow,
        snapshot,
        ReducerEvent::CommandSucceeded {
            command_id: id.into(),
            attempt_token: token,
            output,
        },
    )
    .expect("the effect settles")
    .snapshot
}

fn command_for<'a>(snapshot: &'a RunSnapshot, state_id: &str, item: Option<&str>) -> &'a str {
    snapshot
        .commands
        .values()
        .find(|command| {
            command.state_id == state_id
                && item.is_none_or(|item| command.item_id.as_deref() == Some(item))
                && !matches!(
                    command.status,
                    acativa::CommandStatus::Cancelled | acativa::CommandStatus::Succeeded
                )
        })
        .map(|command| command.id.as_str())
        .unwrap_or_else(|| panic!("a live command exists for {state_id}/{item:?}"))
}

/// The live command for one item of the visit the workset is currently on.
fn item_command<'a>(snapshot: &'a RunSnapshot, item: &str) -> &'a str {
    snapshot
        .commands
        .values()
        .find(|command| {
            command.item_id.as_deref() == Some(item)
                && command.state_visit
                    == snapshot
                        .state_visits
                        .get(&command.state_id)
                        .copied()
                        .unwrap_or(0)
                && !matches!(
                    command.status,
                    acativa::CommandStatus::Cancelled | acativa::CommandStatus::Succeeded
                )
        })
        .map(|command| command.id.as_str())
        .unwrap_or_else(|| panic!("a live item command exists for {item}"))
}

// ---------------------------------------------------------------------------
// The reference reducer
// ---------------------------------------------------------------------------

/// One ordered outcome the run produced, expressed without the machine's types
/// so the reference shares no code with it.
#[derive(Clone, Debug, PartialEq)]
enum Outcome {
    Decide { node: String, advance: bool },
}

/// The reference table: for every node visit, the declared predecessor
/// contributions it received, in the definition's order.
type CausalTable = BTreeMap<String, Vec<(String, u64)>>;

/// A complete, straightforward reference reducer for the causal input layer.
///
/// It replays the ordered outcome log over the definition from scratch every
/// time: no incremental ledger, no deltas, no shared resources, and no reuse of
/// anything the machine computed. It answers one question only — which
/// predecessor contributed to which node visit — and it answers it by walking
/// the graph directly. A disagreement with the machine's bindings is therefore
/// a real disagreement about the causal contract, not a difference in
/// bookkeeping.
struct Reference<'a> {
    workflow: &'a CompiledWorkflow,
    visits: BTreeMap<String, u64>,
    arrivals: BTreeMap<String, BTreeMap<String, u64>>,
    consumed: BTreeMap<String, u64>,
    table: CausalTable,
}

impl<'a> Reference<'a> {
    fn new(workflow: &'a CompiledWorkflow) -> Self {
        Self {
            workflow,
            visits: BTreeMap::new(),
            arrivals: BTreeMap::new(),
            consumed: BTreeMap::new(),
            table: CausalTable::new(),
        }
    }

    fn kind(&self, node: &str) -> GraphStateKind {
        self.workflow
            .definition()
            .states
            .iter()
            .find(|state| state.id == node)
            .expect("the reference only walks declared states")
            .kind
    }

    fn declared(&self, node: &str) -> Vec<String> {
        let mut predecessors = self
            .workflow
            .definition()
            .transitions
            .iter()
            .filter(|transition| transition.to == node)
            .map(|transition| transition.from.clone())
            .collect::<Vec<_>>();
        predecessors.sort();
        predecessors.dedup();
        predecessors
    }

    fn selected(&self, from: &str, event: TransitionEvent) -> Option<&'a Transition> {
        self.workflow
            .definition()
            .transitions
            .iter()
            .find(|transition| transition.from == from && transition.event == event)
    }

    fn visit_of(&self, node: &str) -> u64 {
        self.visits.get(node).copied().unwrap_or(0)
    }

    /// Enter one node with the predecessor that delivered it, or record nothing
    /// at all when a join has no complete epoch.
    fn enter(
        &mut self,
        node: &str,
        predecessor: Option<String>,
        automatic: &mut VecDeque<String>,
        pending: &mut VecDeque<(String, Option<String>)>,
    ) {
        let mut contributions = Vec::new();
        if self.kind(node) == GraphStateKind::Join {
            if let Some(predecessor) = predecessor {
                let visit = self.visit_of(&predecessor);
                self.arrivals
                    .entry(node.to_owned())
                    .or_default()
                    .insert(predecessor, visit);
            }
            let ledger = self.arrivals.get(node).cloned().unwrap_or_default();
            let epoch = ledger.values().copied().max().unwrap_or(0);
            let declared = self.declared(node);
            let complete = epoch > self.consumed.get(node).copied().unwrap_or(0)
                && declared
                    .iter()
                    .all(|predecessor| ledger.get(predecessor) == Some(&epoch));
            if !complete {
                // The reference does not enter the join, and it records nothing.
                return;
            }
            self.consumed.insert(node.to_owned(), epoch);
            contributions = declared
                .into_iter()
                .map(|predecessor| (predecessor.clone(), ledger[&predecessor]))
                .collect();
        } else if let Some(predecessor) = predecessor.clone() {
            contributions.push((predecessor.clone(), self.visit_of(&predecessor)));
        }
        let visit = self.visits.entry(node.to_owned()).or_default();
        *visit += 1;
        let visit = *visit;
        self.table.insert(format!("{node}\0{visit}"), contributions);
        match self.kind(node) {
            GraphStateKind::Pass
            | GraphStateKind::Choice
            | GraphStateKind::Join
            | GraphStateKind::Fork
            | GraphStateKind::Succeed
            | GraphStateKind::Fail
            | GraphStateKind::Blocked => automatic.push_back(node.to_owned()),
            _ => pending.push_back((node.to_owned(), None)),
        }
    }

    /// Complete one automatic node by taking its declared edge, parking a
    /// callback edge until the log's next decision names it.
    fn complete(
        &mut self,
        node: &str,
        event: TransitionEvent,
        automatic: &mut VecDeque<String>,
        pending: &mut VecDeque<(String, Option<String>)>,
    ) {
        let Some(transition) = self.selected(node, event) else {
            return;
        };
        let target = transition.to.clone();
        if transition.mode == TransitionMode::Callback {
            pending.push_back((node.to_owned(), Some(target)));
            return;
        }
        self.enter(&target, Some(node.to_owned()), automatic, pending);
    }

    fn drive(workflow: &'a CompiledWorkflow, outcomes: &[Outcome]) -> CausalTable {
        let mut reference = Self::new(workflow);
        let mut automatic = VecDeque::new();
        let mut pending = VecDeque::new();
        let mut remaining = VecDeque::from(outcomes.to_vec());
        let initial = workflow.definition().initial.clone();
        reference.enter(&initial, None, &mut automatic, &mut pending);
        let mut guard = 0;
        while !automatic.is_empty() || !pending.is_empty() {
            guard += 1;
            assert!(guard < 512, "the reference walk must terminate");
            if let Some(node) = automatic.pop_front() {
                if reference.kind(&node) != GraphStateKind::Fork {
                    reference.complete(
                        &node,
                        TransitionEvent::Complete,
                        &mut automatic,
                        &mut pending,
                    );
                    continue;
                }
                let targets = workflow
                    .definition()
                    .transitions
                    .iter()
                    .filter(|transition| {
                        transition.from == node && transition.event == TransitionEvent::Complete
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                for transition in targets {
                    if transition.mode == TransitionMode::Callback {
                        continue;
                    }
                    reference.enter(
                        &transition.to,
                        Some(node.clone()),
                        &mut automatic,
                        &mut pending,
                    );
                }
                continue;
            }
            let Some((node, parked)) = pending.pop_front() else {
                break;
            };
            let Some(outcome) = remaining.front().cloned() else {
                break;
            };
            match outcome {
                Outcome::Decide {
                    node: decided,
                    advance,
                } if decided == node => {
                    remaining.pop_front();
                    let target = parked.expect("only a parked callback edge decides");
                    if advance {
                        reference.enter(&target, Some(node), &mut automatic, &mut pending);
                    } else {
                        // A return re-enters the node as a new visit, which is
                        // exactly what makes the next arrival a later epoch.
                        reference.enter(&node, None, &mut automatic, &mut pending);
                    }
                }
                _ => break,
            }
        }
        reference.table
    }
}

fn reference_reduce(workflow: &CompiledWorkflow, outcomes: &[Outcome]) -> CausalTable {
    Reference::drive(workflow, outcomes)
}

/// The same table read out of the machine's own binding ledger.
fn machine_table(snapshot: &RunSnapshot) -> CausalTable {
    snapshot
        .bindings
        .iter()
        .map(|(key, binding)| {
            (
                key.clone(),
                binding
                    .predecessors
                    .iter()
                    .map(|contribution| (contribution.node_id.clone(), contribution.node_visit))
                    .collect(),
            )
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The delta oracle
// ---------------------------------------------------------------------------

/// Everything the delta claims, recomputed from the two snapshots alone.
///
/// This is the differential check on the incremental output: a consumer that
/// applied only the delta plus this step's snapshot must hold the same facts,
/// so the delta has to account for every structural difference and invent none.
fn assert_delta_is_honest(
    previous: &RunSnapshot,
    next: &RunSnapshot,
    delta: &acativa::ReducerDelta,
) {
    assert_eq!(delta.run_id, next.run_id);
    assert_eq!(delta.sequence, next.sequence);
    assert_eq!(delta.status_before, previous.status);
    assert_eq!(delta.status_after, next.status);
    assert_eq!(delta.applied, previous != next || delta.applied);

    let mut entered = Vec::new();
    for (node, visit) in &next.state_visits {
        let before = previous.state_visits.get(node).copied().unwrap_or(0);
        for step in (before + 1)..=*visit {
            entered.push((node.clone(), step));
        }
    }
    let mut claimed = delta
        .entered
        .iter()
        .map(|fact| (fact.node_id.clone(), fact.node_visit))
        .collect::<Vec<_>>();
    let unique = claimed.iter().collect::<BTreeSet<_>>();
    assert_eq!(
        unique.len(),
        claimed.len(),
        "the delta must name each entered visit exactly once"
    );
    claimed.sort();
    assert_eq!(claimed, entered, "the delta's entered visits must be exact");

    let binding_keys = next
        .bindings
        .iter()
        .filter(|(key, binding)| previous.bindings.get(*key) != Some(*binding))
        .map(|(key, _)| key.clone())
        .collect::<BTreeSet<_>>();
    let claimed_bindings = delta
        .bindings
        .iter()
        .map(|binding| InputBinding::key(&binding.node_id, binding.node_visit))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        claimed_bindings, binding_keys,
        "the delta's bindings must be exactly the ones the snapshot gained"
    );

    let mut writes = Vec::new();
    for (resource, state) in &next.shared {
        let before = previous.shared.get(resource);
        for (key, entry) in &state.keys {
            let prior = before.and_then(|before| before.keys.get(key));
            if prior != Some(entry) {
                writes.push((resource.clone(), key.clone(), entry.revision));
            }
        }
    }
    let mut claimed_writes = delta
        .shared_writes
        .iter()
        .filter(|receipt| !receipt.duplicate)
        .map(|receipt| {
            (
                receipt.resource_id.clone(),
                receipt.key.clone(),
                receipt.revision,
            )
        })
        .collect::<Vec<_>>();
    writes.sort();
    claimed_writes.sort();
    assert_eq!(
        claimed_writes, writes,
        "the delta's shared writes must be exactly the values the snapshot gained"
    );

    let mut settled = previous
        .commands
        .iter()
        .filter(|(id, command)| {
            next.commands
                .get(*id)
                .is_some_and(|after| after.status != command.status)
        })
        .map(|(id, _)| id.clone())
        .collect::<Vec<_>>();
    settled.sort();
    let mut claimed_settled = delta.settled_commands.clone();
    claimed_settled.sort();
    assert_eq!(
        claimed_settled, settled,
        "the delta must name every command whose status changed"
    );

    let mut claimed_emitted = delta.emitted_commands.clone();
    claimed_emitted.sort();
    let mut gained = next
        .commands
        .keys()
        .filter(|id| !previous.commands.contains_key(*id))
        .cloned()
        .collect::<Vec<_>>();
    gained.sort();
    assert_eq!(
        claimed_emitted, gained,
        "the delta's emitted commands must be exactly the new ones"
    );

    for satisfaction in &delta.joins_satisfied {
        let ledger = next
            .join_arrivals
            .get(&satisfaction.node_id)
            .expect("a satisfied join keeps its ledger");
        assert_eq!(
            ledger.consumed_epoch, satisfaction.epoch,
            "the ledger must record the epoch the delta claims"
        );
        let contributions = satisfaction
            .arrivals
            .iter()
            .map(|arrival| (arrival.node_id.clone(), arrival.node_visit))
            .collect::<Vec<_>>();
        assert!(
            contributions
                .iter()
                .all(|(_, visit)| *visit == satisfaction.epoch),
            "a join may only fire on one epoch's contributions"
        );
    }

    // The join ledger is causal state, not bookkeeping: an arrival recorded by
    // a step that did not fire the join must still be in that step's delta, or
    // a consumer that persists only deltas loses the contribution and the join
    // never closes after a restore. The check is a full diff of both ledgers.
    let mut expected_arrivals = Vec::new();
    for (join, ledger) in &next.join_arrivals {
        let before = previous.join_arrivals.get(join);
        let consumed_before = before.map_or(0, |before| before.consumed_epoch);
        if ledger.consumed_epoch != consumed_before {
            assert!(
                delta.joins_satisfied.iter().any(|satisfaction| {
                    satisfaction.node_id == *join && satisfaction.epoch == ledger.consumed_epoch
                }),
                "a consumed epoch must be reported as a satisfied join"
            );
        }
        for (predecessor, arrival) in &ledger.arrivals {
            let prior = before.and_then(|before| before.arrivals.get(predecessor));
            let unchanged = prior.is_some_and(|prior| {
                prior.node_visit == arrival.node_visit
                    && prior.arrival_ordinal == arrival.arrival_ordinal
                    && prior.result == arrival.result
            });
            if !unchanged {
                expected_arrivals.push((
                    join.clone(),
                    predecessor.clone(),
                    arrival.node_visit,
                    arrival.arrival_ordinal,
                    true,
                    None,
                ));
            }
        }
        let stale_before = before.map_or(0, |before| before.stale.len());
        for stale in ledger.stale.iter().skip(stale_before) {
            expected_arrivals.push((
                join.clone(),
                stale.predecessor.clone(),
                stale.node_visit,
                0,
                false,
                Some(stale.superseded_by),
            ));
        }
        let accepted_before = before.map_or(0, |before| before.arrival_count);
        let accepted = ledger.arrival_count.saturating_sub(accepted_before);
        let claimed_accepted = delta
            .join_arrivals
            .iter()
            .filter(|receipt| receipt.node_id == *join && receipt.accepted)
            .count() as u64;
        assert_eq!(
            claimed_accepted, accepted,
            "the delta's accepted arrivals must explain the ledger's arrival count"
        );
    }
    let mut claimed_arrivals = delta
        .join_arrivals
        .iter()
        .map(|receipt| {
            (
                receipt.node_id.clone(),
                receipt.predecessor.clone(),
                receipt.node_visit,
                receipt.arrival_ordinal,
                receipt.accepted,
                receipt.superseded_by,
            )
        })
        .collect::<Vec<_>>();
    expected_arrivals.sort();
    claimed_arrivals.sort();
    assert_eq!(
        claimed_arrivals, expected_arrivals,
        "the delta's join arrivals must be exactly the ledger changes of this step"
    );
}

// ---------------------------------------------------------------------------
// Fork / join
// ---------------------------------------------------------------------------

#[test]
fn a_join_fires_once_every_declared_predecessor_arrives_in_one_visit() {
    let workflow = fork_join(true, true);
    let snapshot = start(&workflow, "run-join", json!({}));
    assert_eq!(snapshot.status, StrategyRunStatus::Waiting);
    assert!(
        !snapshot.state_visits.contains_key("join"),
        "a parked branch has not arrived, so the join cannot have fired"
    );
    assert_eq!(snapshot.pending_callbacks.len(), 2);

    let first = reduce(
        &workflow,
        &snapshot,
        ReducerEvent::CallbackDecision {
            state_id: "branch-a".into(),
            state_visit: 1,
            decision: CallbackDecision::Enter("join".to_owned()),
        },
    )
    .expect("the first branch advances");
    assert!(
        !first.snapshot.state_visits.contains_key("join"),
        "one contribution is not the declared input set"
    );
    assert_eq!(first.snapshot.status, StrategyRunStatus::Waiting);

    let second = reduce(
        &workflow,
        &first.snapshot,
        ReducerEvent::CallbackDecision {
            state_id: "branch-b".into(),
            state_visit: 1,
            decision: CallbackDecision::Enter("join".to_owned()),
        },
    )
    .expect("the second branch advances");
    assert_eq!(second.snapshot.state_visits["join"], 1);
    assert_eq!(second.snapshot.status, StrategyRunStatus::Running);

    // The join's own binding is the whole epoch, in declared order.
    let binding = &second.snapshot.bindings[&InputBinding::key("join", 1)];
    assert_eq!(
        binding
            .predecessors
            .iter()
            .map(|contribution| (contribution.node_id.as_str(), contribution.node_visit))
            .collect::<Vec<_>>(),
        vec![("branch-a", 1), ("branch-b", 1)]
    );
    // The successor of the join sees exactly the join, at visit 1.
    let c_binding = second
        .snapshot
        .bindings
        .get(&InputBinding::key("c", 1))
        .or_else(|| {
            second
                .snapshot
                .bindings
                .get(&InputBinding::key("c", second.snapshot.state_visits["c"]))
        })
        .expect("the effect state is bound");
    assert_eq!(c_binding.predecessors.len(), 1);
    assert_eq!(c_binding.predecessors[0].node_id, "join");
    assert_eq!(c_binding.predecessors[0].node_visit, 1);
    assert_eq!(
        c_binding.predecessors[0].result.node_visit, 1,
        "a predecessor contribution names the visit, not the latest value"
    );
    // Every contribution a binding names is a predecessor the definition
    // declares for that node. Nothing else is exchanged with it.
    for binding in second.snapshot.bindings.values() {
        let declared = workflow.predecessors(&binding.node_id);
        for contribution in &binding.predecessors {
            assert!(
                declared.contains(&contribution.node_id),
                "{} bound {}, which the definition does not declare for it",
                binding.node_id,
                contribution.node_id
            );
        }
    }
    // The effect state declares one predecessor, so it sees one contribution:
    // a result is not broadcast to every successor just because it exists.
    assert!(
        second
            .snapshot
            .bindings
            .values()
            .filter(|binding| binding.node_id == "c")
            .all(|binding| binding.predecessors.len() == 1),
        "a node sees its declared input set and nothing else"
    );
}

/// A fork whose branches are two different Agent effects.
///
/// The join is the only place the two branches meet, so any context key one
/// Agent's input shows must have come from its own declared read, not from the
/// other branch's later write.
fn cross_agent_fork_join() -> CompiledWorkflow {
    let mut agent_b = ActorSlot::required_actor("agent-b", "Agent B");
    agent_b.entry = false;
    compile_workflow(WorkflowDefinition {
        schema: acativa::GENERIC_WORKFLOW_SCHEMA.into(),
        metadata: WorkflowMetadata {
            id: "cross-agent".into(),
            name: "Cross agent".into(),
            version: "1".into(),
            description: String::new(),
        },
        limits: WorkflowLimits::default(),
        actor_slots: vec![ActorSlot::required_actor("agent-a", "Agent A"), agent_b],
        runtimes: vec![],
        worksets: vec![],
        initial: "fan".into(),
        states: vec![
            state("fan", GraphStateKind::Fork),
            actor("a", "agent-a", "Produce A."),
            actor("b", "agent-b", "Produce B."),
            state("join", GraphStateKind::Join),
            actor("c", "agent-a", "Consume both."),
            state("done", GraphStateKind::Succeed),
            state("fail", GraphStateKind::Fail),
        ],
        transitions: vec![
            edge("fan", "a", TransitionEvent::Complete, TransitionMode::Flow),
            edge("fan", "b", TransitionEvent::Complete, TransitionMode::Flow),
            // An effect state routes on success and failure alike; both events
            // carry this branch's own boundary result into the join.
            Transition {
                id: "a-join-success".into(),
                from: "a".into(),
                to: "join".into(),
                event: TransitionEvent::Success,
                mode: TransitionMode::Flow,
                guard: None,
            },
            Transition {
                id: "a-join-failure".into(),
                from: "a".into(),
                to: "join".into(),
                event: TransitionEvent::Failure,
                mode: TransitionMode::Flow,
                guard: None,
            },
            Transition {
                id: "b-join-success".into(),
                from: "b".into(),
                to: "join".into(),
                event: TransitionEvent::Success,
                mode: TransitionMode::Flow,
                guard: None,
            },
            Transition {
                id: "b-join-failure".into(),
                from: "b".into(),
                to: "join".into(),
                event: TransitionEvent::Failure,
                mode: TransitionMode::Flow,
                guard: None,
            },
            edge("join", "c", TransitionEvent::Complete, TransitionMode::Flow),
            edge("c", "done", TransitionEvent::Success, TransitionMode::Flow),
            edge("c", "fail", TransitionEvent::Failure, TransitionMode::Flow),
        ],
    })
    .expect("the cross-agent fixture compiles")
}

#[test]
fn concurrent_agent_branches_keep_their_own_results_and_cannot_borrow_context() {
    let workflow = cross_agent_fork_join();
    let snapshot = start(&workflow, "run-cross-agent", json!({}));
    let a = command_for(&snapshot, "a", None).to_owned();
    let b = command_for(&snapshot, "b", None).to_owned();
    assert_ne!(a, b, "each branch owns its own effect");

    // Both branches were bound by the same fork step, before either wrote:
    // each one's declared read of `context` is the empty revision 0, so no
    // later write by the other branch can be part of its input.
    for (node, command) in [("a", &a), ("b", &b)] {
        let binding = &snapshot.bindings[&InputBinding::key(node, 1)];
        assert_eq!(binding.shared_revision("context"), Some(0));
        assert!(binding.shared_key_revision("context", "from-a").is_none());
        assert!(binding.shared_key_revision("context", "from-b").is_none());
        let projected = &snapshot.commands[command].input["context"];
        assert!(
            projected.get("context").is_none(),
            "{node} starts from the context revision it bound, not a sibling's"
        );
        assert_eq!(
            projected["predecessors"]["fan"]["nodeVisit"], 1,
            "{node} binds the fork, the one predecessor the definition declares"
        );
    }

    // A completes and publishes its own key. B was bound before that write, so
    // the input B's command carries cannot contain it.
    let mut snapshot = running(&workflow, &snapshot, &a);
    snapshot = succeed(
        &workflow,
        &snapshot,
        &a,
        json!({"context": {"from-a": "A"}}),
    );
    assert!(
        snapshot.commands[&b].input["context"]["context"]
            .get("from-a")
            .is_none(),
        "a concurrent Agent's result must not reach the other branch's input"
    );
    assert!(
        snapshot.bindings[&InputBinding::key("b", 1)]
            .shared_key_revision("context", "from-a")
            .is_none(),
        "the other branch's binding never observed the key"
    );

    // B completes with its own key. The join now binds each branch's own
    // result, and its input reads both declared keys at the revisions it saw.
    snapshot = running(&workflow, &snapshot, &b);
    snapshot = succeed(
        &workflow,
        &snapshot,
        &b,
        json!({"context": {"from-b": "B"}}),
    );
    assert_eq!(snapshot.state_visits["join"], 1);
    let binding = &snapshot.bindings[&InputBinding::key("join", 1)];
    assert_eq!(
        binding
            .predecessors
            .iter()
            .map(|contribution| (contribution.node_id.as_str(), contribution.node_visit))
            .collect::<Vec<_>>(),
        vec![("a", 1), ("b", 1)],
        "the join batches one result per declared predecessor"
    );
    for contribution in &binding.predecessors {
        let expected = match contribution.node_id.as_str() {
            "a" => &a,
            "b" => &b,
            other => panic!("the join bound an undeclared predecessor {other}"),
        };
        assert_eq!(
            contribution.result.producers,
            vec![expected.clone()],
            "the join binds {}'s own effect, not a context entry both could read",
            contribution.node_id
        );
    }
    let consume = command_for(&snapshot, "c", None).to_owned();
    let projected = &snapshot.commands[&consume].input["context"];
    assert_eq!(projected["context"]["from-a"], "A");
    assert_eq!(projected["context"]["from-b"], "B");
}

#[test]
fn a_join_input_does_not_depend_on_which_branch_arrived_first() {
    // Two arrival orders for one epoch. With both branch edges parked the
    // decider's settlements run in the parked order (a then b); with only
    // branch-a parked, branch-b reaches the join through its flow edge first
    // and branch-a arrives afterwards.
    let both_parked = drive_decisions(
        &fork_join(true, true),
        "run-order",
        &[("branch-a", true), ("branch-b", true)],
    );
    let flow_first = drive_decisions(&fork_join(true, false), "run-order", &[("branch-a", true)]);
    let expected = vec![("branch-a".to_owned(), 1), ("branch-b".to_owned(), 1)];
    for (name, snapshot) in [("both-parked", &both_parked), ("flow-first", &flow_first)] {
        assert_eq!(snapshot.state_visits["join"], 1, "{name}");
        let binding = &snapshot.bindings[&InputBinding::key("join", 1)];
        assert_eq!(
            binding
                .predecessors
                .iter()
                .map(|contribution| (contribution.node_id.clone(), contribution.node_visit))
                .collect::<Vec<_>>(),
            expected,
            "{name}: the declared input set is in definition order, not arrival order"
        );
        assert_eq!(binding.arrival_order, Vec::<String>::new(), "{name}");
    }
}

/// The targeted counterexample: an old visit must never satisfy a new join.
///
/// `branch-b` arrives at the join at visit 1 and the run parks `branch-a`. The
/// decider then returns `branch-a`, which runs again as visit 2, and advances it.
/// At that moment the set of *names* that have arrived is exactly the declared
/// predecessor set — which is the whole predicate a name-keyed join uses — while
/// the contributions come from two different visits. A name-keyed join fires
/// here and consumes a round that never existed as one instant of the run; the
/// predicate is asserted below so the counterexample is stated in the machine's
/// own recorded facts rather than in prose.
#[test]
fn an_earlier_visit_never_satisfies_a_new_join_round() {
    let workflow = fork_join(true, false);
    let started = start(&workflow, "run-epoch", json!({}));
    assert_eq!(started.status, StrategyRunStatus::Waiting);
    assert_eq!(started.state_visits["branch-b"], 1);
    assert_eq!(
        started.join_arrivals["join"]
            .arrivals
            .keys()
            .collect::<Vec<_>>(),
        vec!["branch-b"],
        "the flow branch arrived while the callback branch parked"
    );

    let returned = reduce(
        &workflow,
        &started,
        ReducerEvent::CallbackDecision {
            state_id: "branch-a".into(),
            state_visit: 1,
            decision: CallbackDecision::Enter("branch-a".to_owned()),
        },
    )
    .expect("the parked branch is re-entered");
    assert_eq!(
        returned.snapshot.state_visits["branch-a"], 2,
        "the re-entry is a new visit, not a repeat of visit 1"
    );
    assert_eq!(returned.snapshot.status, StrategyRunStatus::Waiting);

    let advanced = reduce(
        &workflow,
        &returned.snapshot,
        ReducerEvent::CallbackDecision {
            state_id: "branch-a".into(),
            state_visit: 2,
            decision: CallbackDecision::Enter("join".to_owned()),
        },
    )
    .expect("the second visit of the branch advances");
    let ledger = &advanced.snapshot.join_arrivals["join"];
    let arrived = ledger.arrivals.keys().cloned().collect::<BTreeSet<_>>();
    let declared = ["branch-a".to_owned(), "branch-b".to_owned()]
        .into_iter()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        arrived, declared,
        "the counterexample condition holds: every declared name has arrived"
    );
    assert_eq!(ledger.arrivals["branch-a"].node_visit, 2);
    assert_eq!(ledger.arrivals["branch-b"].node_visit, 1);
    assert!(
        !advanced.snapshot.state_visits.contains_key("join"),
        "a join may not fire on contributions from two different visits"
    );
    assert_eq!(advanced.snapshot.status, StrategyRunStatus::Waiting);
    assert_eq!(
        advanced.snapshot.diagnostic_code.as_deref(),
        Some("strategy_join_waiting"),
        "waiting on a mixed epoch is a named run fact, not a silent stall"
    );
    // The reference reaches the same verdict from the same outcome log.
    assert!(!machine_table(&advanced.snapshot).contains_key(&InputBinding::key("join", 1)));
    let reference = reference_reduce(
        &workflow,
        &[
            Outcome::Decide {
                node: "branch-a".into(),
                advance: false,
            },
            Outcome::Decide {
                node: "branch-a".into(),
                advance: true,
            },
        ],
    );
    assert!(
        !reference.contains_key(&InputBinding::key("join", 1)),
        "the reference refuses the mixed epoch from the same decision log"
    );
}

#[test]
fn a_join_epoch_is_consumed_and_cannot_fire_again() {
    let workflow = fork_join_with_join_callback();
    let fired = start(&workflow, "run-epoch-once", json!({}));
    assert_eq!(fired.status, StrategyRunStatus::Waiting);
    assert_eq!(fired.state_visits["join"], 1);
    let ledger = &fired.join_arrivals["join"];
    assert_eq!(ledger.consumed_epoch, 1, "the epoch is consumed on firing");
    assert_eq!(
        ledger
            .arrivals
            .values()
            .map(|arrival| arrival.node_visit)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([1])
    );

    // Returning into the join carries no new arrival, so it cannot open a
    // second round on the epoch the join already consumed.
    let returned = reduce(
        &workflow,
        &fired,
        ReducerEvent::CallbackDecision {
            state_id: "join".into(),
            state_visit: 1,
            decision: CallbackDecision::Enter("join".to_owned()),
        },
    )
    .expect("the return applies");
    assert_eq!(
        returned.snapshot.state_visits["join"], 1,
        "a consumed epoch is not re-entered as a new visit"
    );
    assert_eq!(returned.snapshot.status, StrategyRunStatus::Waiting);
    assert_eq!(
        returned.snapshot.diagnostic_code.as_deref(),
        Some("strategy_join_waiting")
    );
    assert!(returned.emitted_commands.is_empty());
}

#[test]
fn a_repeated_arrival_cannot_be_counted_twice() {
    let workflow = fork_join(true, false);
    let started = start(&workflow, "run-duplicate-arrival", json!({}));
    let joined = drive_decisions(&workflow, "run-duplicate-arrival", &[("branch-a", true)]);
    assert!(started.state_visits.contains_key("branch-b"));
    assert_eq!(joined.state_visits["join"], 1);
    let ledger = joined.join_arrivals["join"].clone();
    assert_eq!(ledger.arrivals.len(), 2);
    assert_eq!(ledger.arrival_count, 2);
    assert_eq!(ledger.consumed_epoch, 1);
    // The supersession path - an arrival from a visit older than one already
    // recorded - is unreachable here: a branch that has arrived at the join
    // cannot be re-entered, because the wait that could re-enter it is the one
    // that just consumed it. The ledger field exists so that if the IR ever
    // admits it, it is a recorded fact and not a silent drop.
    assert!(ledger.stale.is_empty());

    // Replaying the same decision cannot arrive a second time: the wait it
    // settled is gone, so it is stale by identity rather than counted again.
    let replay = reduce(
        &workflow,
        &joined,
        ReducerEvent::CallbackDecision {
            state_id: "branch-a".into(),
            state_visit: 1,
            decision: CallbackDecision::Enter("join".to_owned()),
        },
    )
    .expect_err("a consumed wait cannot be settled twice");
    assert!(
        replay.to_string().contains("strategy_callback_stale"),
        "{replay}"
    );
}

// ---------------------------------------------------------------------------
// Shared reads and writes
// ---------------------------------------------------------------------------

fn plan_with(resources: Vec<SharedResourceDecl>, isolated: Vec<&str>) -> InputPlan {
    InputPlan {
        resources,
        isolated_nodes: isolated.into_iter().map(str::to_owned).collect(),
        ..InputPlan::default()
    }
}

#[test]
fn disjoint_shared_keys_merge_and_a_conflicting_key_is_an_explicit_error() {
    let workflow = workset_chain();
    let input = json!({"worksets": {"tasks": [{"id": "a"}, {"id": "b"}]}});

    // Non-conflicting keys: each item writes its own context key.
    let mut snapshot = start(&workflow, "run-disjoint", input.clone());
    let a = item_command(&snapshot, "a").to_owned();
    let b = item_command(&snapshot, "b").to_owned();
    snapshot = running(&workflow, &snapshot, &a);
    snapshot = running(&workflow, &snapshot, &b);
    snapshot = succeed(&workflow, &snapshot, &a, json!({"context": {"from-a": 1}}));
    snapshot = succeed(&workflow, &snapshot, &b, json!({"context": {"from-b": 2}}));
    assert_eq!(snapshot.shared["context"].keys["from-a"].value, 1);
    assert_eq!(snapshot.shared["context"].keys["from-b"].value, 2);
    assert_eq!(
        snapshot.shared["context"].keys["from-a"]
            .writers
            .iter()
            .map(|writer| (writer.node_id.as_str(), writer.node_visit))
            .collect::<Vec<_>>(),
        vec![("tasks", 1)],
        "the writer names the node visit"
    );
    // The provenance names the exact effect, not the visit's accumulated
    // result: a visit-level digest would change as its siblings settled, which
    // would make the stored value depend on completion order.
    for (key, command) in [("from-a", &a), ("from-b", &b)] {
        assert_eq!(
            snapshot.shared["context"].keys[key]
                .writers
                .iter()
                .map(|writer| writer.command_id.as_str())
                .collect::<Vec<_>>(),
            vec![command.as_str()],
            "the writer names the command that produced the value"
        );
    }
    // Each key carries its own revision, so nothing in the snapshot counts
    // writes to *other* keys.
    assert_eq!(snapshot.shared["context"].keys["from-a"].revision, 1);
    assert_eq!(snapshot.shared["context"].keys["from-b"].revision, 1);
    assert_eq!(
        snapshot.shared["context"].revision, 2,
        "the resource revision counts accepted writes and is the CAS token"
    );
    assert_eq!(snapshot.status, StrategyRunStatus::Running);
    let after = snapshot.state_visits["after"];
    let binding = &snapshot.bindings[&InputBinding::key("after", after)];
    assert_eq!(binding.predecessors.len(), 1);
    assert_eq!(binding.predecessors[0].node_id, "tasks");
    assert_eq!(
        binding.predecessors[0].node_visit, 1,
        "the successor binds the workset visit that produced the items"
    );

    // Conflicting content for one key: refused, in either completion order.
    for order in [["a", "b"], ["b", "a"]] {
        let mut snapshot = start(&workflow, "run-conflict", input.clone());
        let first = item_command(&snapshot, "a").to_owned();
        let second = item_command(&snapshot, "b").to_owned();
        snapshot = running(&workflow, &snapshot, &first);
        snapshot = running(&workflow, &snapshot, &second);
        let order = [order[0], order[1]].map(|item| match item {
            "a" => first.clone(),
            _ => second.clone(),
        });
        let mut failed = None;
        for id in order {
            let token = snapshot.commands[&id].attempt_token.clone();
            let outcome = reduce(
                &workflow,
                &snapshot,
                ReducerEvent::CommandSucceeded {
                    command_id: id.clone(),
                    attempt_token: token,
                    output: json!({"context": {"winner": id}}),
                },
            );
            match outcome {
                Ok(output) => snapshot = output.snapshot,
                Err(error) => {
                    failed = Some(error.to_string());
                    break;
                }
            }
        }
        let message = failed.expect("two writers cannot both own one key");
        assert!(
            message.contains("strategy_shared_write_conflict"),
            "the conflict is named, not resolved by arrival order: {message}"
        );
    }
}

#[test]
fn a_duplicated_result_is_idempotent_and_a_differing_one_is_a_conflict() {
    let workflow = workset_chain();
    let mut snapshot = start(
        &workflow,
        "run-duplicate",
        json!({"worksets": {"tasks": [{"id": "a"}]}}),
    );
    let item = item_command(&snapshot, "a").to_owned();
    snapshot = running(&workflow, &snapshot, &item);
    snapshot = succeed(
        &workflow,
        &snapshot,
        &item,
        json!({"context": {"note": "x"}}),
    );
    let revision = snapshot.shared["context"].revision;

    let token = snapshot.commands[&item].attempt_token.clone();
    let duplicate = reduce(
        &workflow,
        &snapshot,
        ReducerEvent::CommandSucceeded {
            command_id: item.clone(),
            attempt_token: token.clone(),
            output: json!({"context": {"note": "x"}}),
        },
    )
    .expect("an identical re-delivery is idempotent");
    assert!(!duplicate.applied, "a duplicate changes nothing");
    assert_eq!(duplicate.snapshot, snapshot);
    assert_eq!(duplicate.snapshot.shared["context"].revision, revision);

    let conflict = reduce(
        &workflow,
        &snapshot,
        ReducerEvent::CommandSucceeded {
            command_id: item,
            attempt_token: token,
            output: json!({"context": {"note": "y"}}),
        },
    )
    .expect_err("differing content for one settled command is a conflict");
    assert!(
        conflict.to_string().contains("strategy_callback_conflict"),
        "{conflict}"
    );
}

#[test]
fn a_shared_write_must_name_the_revision_the_writer_read() {
    let workflow = workset_chain();
    let plan = plan_with(
        vec![
            SharedResourceDecl::key_union(acativa::SHARED_CONTEXT_RESOURCE),
            SharedResourceDecl::key_union(acativa::SHARED_WORKSETS_RESOURCE),
        ],
        vec!["after"],
    );
    let declared = reduce(
        &workflow,
        &empty("run-unread"),
        ReducerEvent::InputPlanDeclared { plan },
    )
    .expect("the plan is declared before the run starts");
    assert_eq!(declared.snapshot.status, StrategyRunStatus::Pending);
    let snapshot = reduce(
        &workflow,
        &declared.snapshot,
        ReducerEvent::Start {
            input: json!({"worksets": {"tasks": [{"id": "a"}]}}),
        },
    )
    .expect("the declared plan admits the run")
    .snapshot;

    // `after` is declared isolated, so it reads no shared state and therefore
    // cannot name a revision to write against.
    let binding = &snapshot.bindings[&InputBinding::key("tasks", 1)];
    assert!(
        binding
            .shared_revision(acativa::SHARED_CONTEXT_RESOURCE)
            .is_some(),
        "an ordinary node reads the declared resources at a recorded revision"
    );

    let item = item_command(&snapshot, "a").to_owned();
    let snapshot = running(&workflow, &snapshot, &item);
    let snapshot = succeed(&workflow, &snapshot, &item, json!({}));
    let node = command_for(&snapshot, "after", None).to_owned();
    let after_binding =
        &snapshot.bindings[&InputBinding::key("after", snapshot.state_visits["after"])];
    assert!(
        after_binding.shared.is_empty(),
        "an isolated node's binding names no shared resource, so no unrelated \
         branch can reach its input"
    );
    let token = snapshot.commands[&node].attempt_token.clone();
    let refused = reduce(
        &workflow,
        &snapshot,
        ReducerEvent::CommandSucceeded {
            command_id: node,
            attempt_token: token,
            output: json!({"context": {"unread": true}}),
        },
    )
    .expect_err("writing state the writer never read is refused");
    assert!(
        refused.to_string().contains("strategy_shared_write_unread"),
        "{refused}"
    );
}

#[test]
fn an_undeclared_shared_resource_and_a_foreign_adapter_version_are_both_refused() {
    let workflow = workset_chain();
    let foreign = InputPlan {
        input_adapter_version: 99,
        ..InputPlan::default()
    };
    let refused = reduce(
        &workflow,
        &empty("run-adapter"),
        ReducerEvent::InputPlanDeclared { plan: foreign },
    )
    .expect_err("a projection this build does not implement is refused");
    assert!(
        refused
            .to_string()
            .contains("strategy_input_adapter_mismatch"),
        "{refused}"
    );

    // A declared plan with an adapter version this build executes still refuses
    // a resource it never declared.
    let plan = plan_with(vec![SharedResourceDecl::key_union("context")], vec![]);
    let snapshot = reduce(
        &workflow,
        &empty("run-undeclared"),
        ReducerEvent::InputPlanDeclared { plan },
    )
    .and_then(|output| {
        reduce(
            &workflow,
            &output.snapshot,
            ReducerEvent::Start {
                input: json!({"worksets": {"tasks": [{"id": "a"}]}}),
            },
        )
    })
    .expect("the plan admits the run")
    .snapshot;
    let item = item_command(&snapshot, "a").to_owned();
    let snapshot = running(&workflow, &snapshot, &item);
    let token = snapshot.commands[&item].attempt_token.clone();
    let refused = reduce(
        &workflow,
        &snapshot,
        ReducerEvent::CommandSucceeded {
            command_id: item,
            attempt_token: token,
            output: json!({"worksets": {"tasks": []}}),
        },
    )
    .expect_err("a write to an undeclared resource is refused");
    assert!(
        refused
            .to_string()
            .contains("strategy_shared_resource_undeclared"),
        "{refused}"
    );
}

#[test]
fn a_cas_resource_refuses_the_second_writer_and_an_exclusive_one_refuses_everyone_else() {
    let workflow = workset_chain();
    let input = json!({"worksets": {"tasks": [{"id": "a"}, {"id": "b"}]}});

    // Both items run against revision 0. The first write moves the resource to
    // revision 1, so the second writer's CAS no longer holds.
    let mut snapshot = start(&workflow, "run-cas", input.clone());
    let a = item_command(&snapshot, "a").to_owned();
    let b = item_command(&snapshot, "b").to_owned();
    snapshot = running(&workflow, &snapshot, &a);
    snapshot = running(&workflow, &snapshot, &b);
    assert_eq!(
        snapshot.bindings[&InputBinding::key("tasks", 1)].shared_revision("context"),
        Some(0),
        "both item commands were bound before either wrote"
    );
    let cas = InputPlan {
        resources: vec![SharedResourceDecl {
            id: "context".into(),
            merge: MergePolicy::Cas,
            writer: None,
        }],
        ..InputPlan::default()
    };
    let declared = reduce(
        &workflow,
        &empty("run-cas-plan"),
        ReducerEvent::InputPlanDeclared { plan: cas },
    )
    .expect("the plan declares")
    .snapshot;
    let mut declared = reduce(
        &workflow,
        &declared,
        ReducerEvent::Start {
            input: input.clone(),
        },
    )
    .expect("start")
    .snapshot;
    let a = item_command(&declared, "a").to_owned();
    let b = item_command(&declared, "b").to_owned();
    declared = running(&workflow, &declared, &a);
    declared = running(&workflow, &declared, &b);
    declared = succeed(&workflow, &declared, &a, json!({"context": {"from-a": 1}}));
    assert_eq!(declared.shared["context"].revision, 1);
    let token = declared.commands[&b].attempt_token.clone();
    let refused = reduce(
        &workflow,
        &declared,
        ReducerEvent::CommandSucceeded {
            command_id: b,
            attempt_token: token,
            output: json!({"context": {"from-b": 2}}),
        },
    )
    .expect_err("a CAS resource refuses a writer whose revision moved");
    assert!(
        refused
            .to_string()
            .contains("strategy_shared_write_conflict"),
        "{refused}"
    );
}

#[test]
fn an_exclusive_resource_accepts_only_the_writer_the_plan_names() {
    let workflow = workset_chain();
    let plan = InputPlan {
        resources: vec![
            SharedResourceDecl {
                id: "context".into(),
                merge: MergePolicy::Exclusive,
                writer: Some("after".into()),
            },
            SharedResourceDecl::key_union(acativa::SHARED_WORKSETS_RESOURCE),
        ],
        ..InputPlan::default()
    };
    let declared = reduce(
        &workflow,
        &empty("run-exclusive"),
        ReducerEvent::InputPlanDeclared { plan },
    )
    .expect("the plan declares")
    .snapshot;
    let mut snapshot = reduce(
        &workflow,
        &declared,
        ReducerEvent::Start {
            input: json!({"worksets": {"tasks": [{"id": "a"}]}}),
        },
    )
    .expect("start")
    .snapshot;
    let item = item_command(&snapshot, "a").to_owned();
    snapshot = running(&workflow, &snapshot, &item);
    let token = snapshot.commands[&item].attempt_token.clone();
    let refused = reduce(
        &workflow,
        &snapshot,
        ReducerEvent::CommandSucceeded {
            command_id: item,
            attempt_token: token,
            output: json!({"context": {"from-item": 1}}),
        },
    )
    .expect_err("a dedicated resource admits only its declared writer");
    assert!(
        refused
            .to_string()
            .contains("strategy_shared_write_conflict"),
        "{refused}"
    );
}

#[test]
fn only_a_node_that_declares_order_sensitivity_records_an_arrival_order() {
    let workflow = fork_join(true, true);
    let default_order = drive_decisions(
        &workflow,
        "run-order-default",
        &[("branch-a", true), ("branch-b", true)],
    );
    assert!(
        default_order.bindings[&InputBinding::key("join", 1)]
            .arrival_order
            .is_empty(),
        "a node that says nothing has order independent inputs"
    );

    let plan = InputPlan {
        order_sensitive_nodes: vec!["join".into()],
        ..InputPlan::default()
    };
    let declared = reduce(
        &workflow,
        &empty("run-order-declared"),
        ReducerEvent::InputPlanDeclared { plan },
    )
    .expect("the plan declares")
    .snapshot;
    let mut snapshot = reduce(
        &workflow,
        &declared,
        ReducerEvent::Start { input: json!({}) },
    )
    .expect("start")
    .snapshot;
    for node in ["branch-a", "branch-b"] {
        snapshot = reduce(
            &workflow,
            &snapshot,
            ReducerEvent::CallbackDecision {
                state_id: node.into(),
                state_visit: snapshot.state_visits[node],
                decision: CallbackDecision::Enter(snapshot.pending_callbacks[0].target.clone()),
            },
        )
        .expect("advance")
        .snapshot;
    }
    let binding = &snapshot.bindings[&InputBinding::key("join", 1)];
    assert_eq!(
        binding.arrival_order,
        vec!["branch-a".to_owned(), "branch-b".to_owned()],
        "a node that declares order sensitivity records the order it observed"
    );
    // The declared contributions stay in definition order either way: the
    // recorded order is evidence about the business, not a different input.
    assert_eq!(
        binding
            .predecessors
            .iter()
            .map(|contribution| contribution.node_id.as_str())
            .collect::<Vec<_>>(),
        vec!["branch-a", "branch-b"]
    );
}

/// A workset that accumulates its members' results into a dedicated resource.
///
/// This is the production shape for concurrent accumulation: the bag lives in
/// its own declared resource with an `accumulate` policy, while `worksets` (the
/// item declarations) and `context` keep the scalar default, so a divergent
/// scalar write is still refused instead of being unioned.
fn accumulating_plan() -> InputPlan {
    InputPlan {
        resources: vec![
            SharedResourceDecl::key_union(acativa::SHARED_CONTEXT_RESOURCE),
            SharedResourceDecl::key_union(acativa::SHARED_WORKSETS_RESOURCE),
            SharedResourceDecl::accumulate("worksetResults"),
        ],
        ..InputPlan::default()
    }
}

fn declared_start(workflow: &CompiledWorkflow, run_id: &str, input: Value) -> RunSnapshot {
    let declared = reduce(
        workflow,
        &empty(run_id),
        ReducerEvent::InputPlanDeclared {
            plan: accumulating_plan(),
        },
    )
    .expect("the plan declares before the run starts")
    .snapshot;
    reduce(workflow, &declared, ReducerEvent::Start { input })
        .expect("the declared plan admits the run")
        .snapshot
}

fn accumulate_output(item_id: &str) -> Value {
    json!({
        "context": {format!("from-{item_id}"): item_id},
        "shared": {"worksetResults": {"tasks": [item_id]}},
    })
}

#[test]
fn an_accumulating_resource_reaches_one_value_in_every_completion_order() {
    let workflow = workset_chain();
    let input = json!({"worksets": {"tasks": [
        {"id": "a"},
        {"id": "b"},
        {"id": "c"}
    ]}});
    let orders = [["a", "b", "c"], ["c", "b", "a"], ["b", "c", "a"]];
    let mut seen = BTreeSet::new();
    for order in orders {
        let mut snapshot = declared_start(&workflow, "run-accumulate", input.clone());
        for item in order {
            snapshot = running(&workflow, &snapshot, item_command(&snapshot, item));
        }
        for item in order {
            let command = item_command(&snapshot, item).to_owned();
            snapshot = succeed(&workflow, &snapshot, &command, accumulate_output(item));
        }
        assert_eq!(snapshot.status, StrategyRunStatus::Running);
        let entry = &snapshot.shared["worksetResults"].keys["tasks"];
        assert_eq!(
            entry.value,
            json!(["a", "b", "c"]),
            "the collection is canonical: {order:?}"
        );
        assert_eq!(
            entry.revision, 3,
            "one accepted contribution per member, whatever the order"
        );
        assert_eq!(
            entry
                .writers
                .iter()
                .map(|writer| writer.node_id.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["tasks"]),
            "every contributing member is named, not just the last one"
        );
        // The per-item context keys are disjoint, so they still merge by key.
        for item in ["a", "b", "c"] {
            let key = format!("from-{item}");
            assert_eq!(snapshot.shared["context"].keys[&key].value, item);
        }
        // The successor reads the accumulated bag at the revisions it bound.
        let after = snapshot.state_visits["after"];
        let binding = &snapshot.bindings[&InputBinding::key("after", after)];
        assert_eq!(
            binding.shared_key_revision("worksetResults", "tasks"),
            Some(3)
        );
        seen.insert(serde_json::to_vec(&snapshot).expect("the snapshot encodes"));
    }
    assert_eq!(
        seen.len(),
        1,
        "every completion order must reach one canonical snapshot"
    );
}

#[test]
fn an_accumulated_contribution_is_idempotent_and_a_scalar_key_is_still_refused() {
    let workflow = workset_chain();
    let input = json!({"worksets": {"tasks": [{"id": "a"}, {"id": "b"}]}});
    let mut snapshot = declared_start(&workflow, "run-accumulate-idempotent", input);
    let a = item_command(&snapshot, "a").to_owned();
    let b = item_command(&snapshot, "b").to_owned();
    snapshot = running(&workflow, &snapshot, &a);
    snapshot = running(&workflow, &snapshot, &b);
    snapshot = succeed(&workflow, &snapshot, &a, accumulate_output("a"));
    let after_first = snapshot.shared["worksetResults"].keys["tasks"].clone();
    assert_eq!(after_first.value, json!(["a"]));
    assert_eq!(after_first.revision, 1);

    // Re-delivering the contribution the collection already holds is the same
    // write: the value, the revision and the contributor set all stand.
    let reread = snapshot.clone();
    let token = snapshot.commands[&a].attempt_token.clone();
    let duplicate = reduce(
        &workflow,
        &snapshot,
        ReducerEvent::CommandSucceeded {
            command_id: a,
            attempt_token: token,
            output: accumulate_output("a"),
        },
    )
    .expect("a duplicate result is idempotent");
    assert!(!duplicate.applied);
    assert_eq!(duplicate.snapshot, reread);

    // The bag accumulates, but a scalar key on an `accumulate` resource cannot:
    // the policy is about collections, and a scalar value has no canonical
    // union to fall back on.
    let scalar = json!({
        "shared": {"worksetResults": {"tasks": {"not": "an array"}}},
    });
    let token = snapshot.commands[&b].attempt_token.clone();
    let refused = reduce(
        &workflow,
        &snapshot,
        ReducerEvent::CommandSucceeded {
            command_id: b,
            attempt_token: token,
            output: scalar,
        },
    )
    .expect_err("a scalar write into a collection key is refused");
    assert!(
        refused
            .to_string()
            .contains("strategy_shared_write_conflict"),
        "{refused}"
    );
}

// ---------------------------------------------------------------------------
// Visit separation
// ---------------------------------------------------------------------------

#[test]
fn a_loop_separates_its_rounds_by_visit() {
    let workflow = compile_workflow(definition(
        "workset-loop",
        "tasks",
        vec![
            GraphState {
                kind: GraphStateKind::Workset,
                workset: Some("tasks".into()),
                ..actor("tasks", "worker", "Execute one item.")
            },
            actor("repeat", "worker", "Continue the next visit."),
            state("done", GraphStateKind::Succeed),
            state("fail", GraphStateKind::Fail),
        ],
        vec![
            Transition {
                id: "again".into(),
                from: "tasks".into(),
                to: "repeat".into(),
                event: TransitionEvent::Success,
                mode: TransitionMode::Flow,
                guard: Some(acativa::GuardExpression {
                    path: "context.again".into(),
                    equals: Some(true.into()),
                    exists: false,
                }),
            },
            edge(
                "tasks",
                "done",
                TransitionEvent::Success,
                TransitionMode::Flow,
            ),
            edge(
                "tasks",
                "fail",
                TransitionEvent::Failure,
                TransitionMode::Flow,
            ),
            edge(
                "repeat",
                "tasks",
                TransitionEvent::Success,
                TransitionMode::Flow,
            ),
            edge(
                "repeat",
                "fail",
                TransitionEvent::Failure,
                TransitionMode::Flow,
            ),
        ],
        vec![tasks_template()],
    ))
    .expect("the loop fixture compiles");

    let mut snapshot = start(
        &workflow,
        "run-loop",
        json!({"worksets": {"tasks": [{"id": "same"}]}}),
    );
    let first = item_command(&snapshot, "same").to_owned();
    snapshot = running(&workflow, &snapshot, &first);
    snapshot = succeed(
        &workflow,
        &snapshot,
        &first,
        json!({"context": {"again": true}}),
    );
    assert_eq!(
        snapshot.state_visits["tasks"], 1,
        "the first round is visit 1"
    );
    assert_eq!(snapshot.state_visits["repeat"], 1);
    let repeat = command_for(&snapshot, "repeat", None).to_owned();
    snapshot = running(&workflow, &snapshot, &repeat);
    snapshot = succeed(&workflow, &snapshot, &repeat, json!({}));
    assert_eq!(snapshot.state_visits["tasks"], 2);
    let second = item_command(&snapshot, "same").to_owned();
    assert_ne!(
        second, first,
        "a new visit owns a new effect identity for the same item"
    );

    // The second round's binding names the second visit of its predecessor and
    // the shared revision that round actually read.
    let binding = &snapshot.bindings[&InputBinding::key("tasks", 2)];
    assert_eq!(binding.node_visit, 2);
    assert_eq!(binding.predecessors.len(), 1);
    assert_eq!(binding.predecessors[0].node_id, "repeat");
    assert_eq!(binding.predecessors[0].node_visit, 1);
    assert!(
        snapshot.bindings[&InputBinding::key("tasks", 1)] != *binding,
        "the two visits are different bindings, so an old one cannot stand in"
    );
    assert_eq!(
        binding.shared_revision("context"),
        Some(snapshot.shared["context"].revision),
        "the second visit reads the revision it observed, not a stale one"
    );
}

// ---------------------------------------------------------------------------
// Differential consistency
// ---------------------------------------------------------------------------

#[test]
#[allow(clippy::type_complexity)]
fn the_incremental_ledger_agrees_with_the_reference_over_every_ordering() {
    // Two orderings of one epoch. With both branch edges parked the decider's
    // decisions run in the parked order; with only branch-a parked, branch-b
    // arrives through its flow edge first and branch-a advances afterwards.
    // The declared input set must not depend on which of the two that was.
    let cases: [(&str, bool, bool, Vec<(&str, bool)>, Vec<Outcome>); 2] = [
        (
            "both-parked-a-then-b",
            true,
            true,
            vec![("branch-a", true), ("branch-b", true)],
            vec![
                Outcome::Decide {
                    node: "branch-a".into(),
                    advance: true,
                },
                Outcome::Decide {
                    node: "branch-b".into(),
                    advance: true,
                },
            ],
        ),
        (
            "b-flow-first-then-a",
            true,
            false,
            vec![("branch-a", true)],
            vec![Outcome::Decide {
                node: "branch-a".into(),
                advance: true,
            }],
        ),
    ];
    let mut join_contributions = BTreeSet::new();
    for (name, parked_a, parked_b, decisions, outcomes) in cases {
        let workflow = fork_join(parked_a, parked_b);
        let reference = reference_reduce(&workflow, &outcomes);
        let snapshot = drive_decisions(&workflow, "run-differential", &decisions);
        let machine = machine_table(&snapshot);
        for (key, contributions) in &reference {
            assert_eq!(
                machine.get(key),
                Some(contributions),
                "{name}: the incremental ledger disagrees with the reference at {key:?}"
            );
        }
        // The machine may hold a binding the reference walk never derived only
        // when that visit had no declared predecessor at all.
        for (key, contributions) in &machine {
            assert!(
                reference.contains_key(key) || contributions.is_empty(),
                "{name}: the machine bound {key:?} to contributions the reference never derived"
            );
        }
        join_contributions.insert(machine[&InputBinding::key("join", 1)].clone());
    }
    assert_eq!(
        join_contributions,
        BTreeSet::from([vec![("branch-a".to_owned(), 1), ("branch-b".to_owned(), 1)]]),
        "both orderings must bind the join to the same declared contributions"
    );
}

/// Drive one run through an ordered list of callback decisions.
fn drive_decisions(
    workflow: &CompiledWorkflow,
    run_id: &str,
    decisions: &[(&str, bool)],
) -> RunSnapshot {
    let mut snapshot = start(workflow, run_id, json!({}));
    for (node, advance) in decisions {
        let visit = snapshot.state_visits[*node];
        snapshot = reduce(
            workflow,
            &snapshot,
            ReducerEvent::CallbackDecision {
                state_id: (*node).into(),
                state_visit: visit,
                decision: CallbackDecision::Enter(if *advance {
                    snapshot.pending_callbacks[0].target.clone()
                } else {
                    (*node).to_owned()
                }),
            },
        )
        .expect("the decider's decision applies")
        .snapshot;
    }
    snapshot
}

#[test]
fn the_reference_and_the_machine_agree_on_the_mixed_epoch_counterexample() {
    let workflow = fork_join(true, false);
    // The reference already knows the verdict for this ordering: branch-b is a
    // flow branch that arrives at visit 1, branch-a is returned and advanced at
    // visit 2, and a join never closes on two visits.
    let reference = reference_reduce(
        &workflow,
        &[
            Outcome::Decide {
                node: "branch-a".into(),
                advance: false,
            },
            Outcome::Decide {
                node: "branch-a".into(),
                advance: true,
            },
        ],
    );
    assert!(
        !reference.contains_key(&InputBinding::key("join", 1)),
        "the reference refuses the mixed epoch from the same decision log"
    );

    let started = start(&workflow, "run-mixed", json!({}));
    let returned = reduce(
        &workflow,
        &started,
        ReducerEvent::CallbackDecision {
            state_id: "branch-a".into(),
            state_visit: 1,
            decision: CallbackDecision::Enter("branch-a".to_owned()),
        },
    )
    .expect("return")
    .snapshot;
    let advanced = reduce(
        &workflow,
        &returned,
        ReducerEvent::CallbackDecision {
            state_id: "branch-a".into(),
            state_visit: 2,
            decision: CallbackDecision::Enter("join".to_owned()),
        },
    )
    .expect("advance")
    .snapshot;
    let machine = machine_table(&advanced);
    assert_eq!(
        machine.contains_key(&InputBinding::key("join", 1)),
        reference.contains_key(&InputBinding::key("join", 1)),
        "the machine and the reference must agree on whether the join closed"
    );
}

#[test]
fn every_step_reports_a_delta_that_accounts_for_the_whole_change() {
    let workflow = workset_chain();
    let mut snapshot = empty("run-delta");
    let plan = InputPlan::default();
    let mut events = vec![
        ReducerEvent::InputPlanDeclared { plan },
        ReducerEvent::Start {
            input: json!({"worksets": {"tasks": [{"id": "a"}, {"id": "b"}]}}),
        },
    ];
    let mut a = None;
    let mut b = None;
    for event in events.drain(..) {
        let output = reduce(&workflow, &snapshot, event).expect("the step applies");
        let next = output.snapshot;
        assert_delta_is_honest(&snapshot, &next, &output.delta);
        snapshot = next;
        for (id, command) in &snapshot.commands {
            match command.item_id.as_deref() {
                Some("a") => a = Some(id.clone()),
                Some("b") => b = Some(id.clone()),
                _ => {}
            }
        }
    }
    let (a, b) = (
        a.expect("item a is scheduled"),
        b.expect("item b is scheduled"),
    );
    for id in [&a, &b] {
        for event in [
            ReducerEvent::CommandClaimed {
                command_id: id.clone(),
                attempt_token: snapshot.commands[id].attempt_token.clone(),
            },
            ReducerEvent::CommandStarted {
                command_id: id.clone(),
                attempt_token: snapshot.commands[id].attempt_token.clone(),
            },
        ] {
            let output = reduce(&workflow, &snapshot, event).expect("the step applies");
            let next = output.snapshot;
            assert_delta_is_honest(&snapshot, &next, &output.delta);
            snapshot = next;
        }
    }
    let outputs = [
        (a, json!({"context": {"from-a": 1}})),
        (b, json!({"context": {"from-b": 2}})),
    ];
    for (id, value) in outputs {
        let token = snapshot.commands[&id].attempt_token.clone();
        let output = reduce(
            &workflow,
            &snapshot,
            ReducerEvent::CommandSucceeded {
                command_id: id,
                attempt_token: token,
                output: value,
            },
        )
        .expect("the item settles");
        let next = output.snapshot;
        assert_delta_is_honest(&snapshot, &next, &output.delta);
        snapshot = next;
    }
    assert_eq!(snapshot.state_visits["after"], 1);
    let after = command_for(&snapshot, "after", None).to_owned();
    let token = snapshot.commands[&after].attempt_token.clone();
    let output = reduce(
        &workflow,
        &snapshot,
        ReducerEvent::CommandSucceeded {
            command_id: after,
            attempt_token: token,
            output: json!({}),
        },
    )
    .expect("the successor settles");
    assert_delta_is_honest(&snapshot, &output.snapshot, &output.delta);
    assert_eq!(output.snapshot.status, StrategyRunStatus::Completed);
    // The successor boundary result is a name a later run can hand over.
    let boundary = output
        .delta
        .results
        .iter()
        .find(|result| result.node_id == "after")
        .expect("the boundary result is reported");
    assert_eq!(boundary.node_visit, 1);
    assert_eq!(boundary.run_id, output.snapshot.run_id);
    assert!(!boundary.digest.is_empty());
}

#[test]
fn every_step_reports_the_join_arrivals_it_recorded() {
    let workflow = fork_join(true, false);
    let mut snapshot = empty("run-delta-join");

    // Start: the flow branch arrives at the join while the callback branch
    // parks. The arrival is causal state, so the step that recorded it must
    // name it even though the join did not fire.
    let output = reduce(
        &workflow,
        &snapshot,
        ReducerEvent::Start { input: json!({}) },
    )
    .expect("the run starts");
    assert_delta_is_honest(&snapshot, &output.snapshot, &output.delta);
    let arrival = output
        .delta
        .join_arrivals
        .iter()
        .find(|receipt| receipt.predecessor == "branch-b")
        .expect("the recorded arrival is in the delta");
    assert!(arrival.accepted);
    assert_eq!(arrival.node_visit, 1);
    assert_eq!(arrival.arrival_ordinal, 1);
    assert!(output.delta.joins_satisfied.is_empty());
    snapshot = output.snapshot;

    // Return branch-a: a new visit, no arrival at the join.
    let output = reduce(
        &workflow,
        &snapshot,
        ReducerEvent::CallbackDecision {
            state_id: "branch-a".into(),
            state_visit: 1,
            decision: CallbackDecision::Enter("branch-a".to_owned()),
        },
    )
    .expect("the parked branch is re-entered");
    assert_delta_is_honest(&snapshot, &output.snapshot, &output.delta);
    assert!(
        output.delta.join_arrivals.is_empty(),
        "a return records no arrival"
    );
    snapshot = output.snapshot;

    // Advance the new visit: the arrival is recorded, the mixed epoch does not
    // fire, and a consumer that applied only the delta still holds the
    // contribution that a later visit will have to match.
    let output = reduce(
        &workflow,
        &snapshot,
        ReducerEvent::CallbackDecision {
            state_id: "branch-a".into(),
            state_visit: 2,
            decision: CallbackDecision::Enter("join".to_owned()),
        },
    )
    .expect("the second visit advances");
    assert_delta_is_honest(&snapshot, &output.snapshot, &output.delta);
    let arrival = output
        .delta
        .join_arrivals
        .iter()
        .find(|receipt| receipt.predecessor == "branch-a")
        .expect("the new arrival is in the delta");
    assert!(arrival.accepted);
    assert_eq!(arrival.node_visit, 2);
    assert!(output.delta.joins_satisfied.is_empty());
    assert_eq!(
        output.snapshot.join_arrivals["join"].arrivals["branch-a"].node_visit, 2,
        "the delta's arrival is the ledger's arrival"
    );

    // A delta is a persisted value: it round-trips, and a delta written before
    // this field existed still loads as "no arrivals".
    let encoded = serde_json::to_vec(&output.delta).expect("the delta encodes");
    let restored: acativa::ReducerDelta =
        serde_json::from_slice(&encoded).expect("the delta decodes");
    assert_eq!(restored, output.delta);
    let mut legacy: Value = serde_json::from_slice(&encoded).expect("the delta is a value");
    legacy
        .as_object_mut()
        .expect("the delta is an object")
        .remove("joinArrivals");
    let restored: acativa::ReducerDelta =
        serde_json::from_value(legacy).expect("a delta without the field still loads");
    assert!(restored.join_arrivals.is_empty());
}

// ---------------------------------------------------------------------------
// Targeted refusals
// ---------------------------------------------------------------------------

#[test]
fn a_run_never_mutates_its_own_declared_input() {
    let workflow = workset_chain();
    let input = json!({"worksets": {"tasks": [{"id": "a"}]}, "task": "keep"});
    let mut snapshot = start(&workflow, "run-input", input.clone());
    assert_eq!(snapshot.input, input);
    let item = item_command(&snapshot, "a").to_owned();
    snapshot = running(&workflow, &snapshot, &item);
    snapshot = succeed(
        &workflow,
        &snapshot,
        &item,
        json!({"context": {"note": "written"}}),
    );
    assert_eq!(
        snapshot.input, input,
        "shared writes live in their own versioned resource, not in the run input"
    );
    assert_eq!(snapshot.shared["context"].keys["note"].value, "written");
}

#[test]
fn a_failed_effect_contributes_no_result_but_still_binds_the_successor() {
    let workflow = workset_chain();
    let mut snapshot = start(
        &workflow,
        "run-failure",
        json!({"worksets": {"tasks": [{"id": "a"}]}}),
    );
    let item = item_command(&snapshot, "a").to_owned();
    snapshot = running(&workflow, &snapshot, &item);
    let token = snapshot.commands[&item].attempt_token.clone();
    snapshot = reduce(
        &workflow,
        &snapshot,
        ReducerEvent::CommandFailed {
            command_id: item,
            attempt_token: token,
            class: FailureClass::Permanent,
            code: "effect_failed".into(),
        },
    )
    .expect("the failure settles")
    .snapshot;
    assert_eq!(snapshot.status, StrategyRunStatus::Failed);
    let binding = &snapshot.bindings[&InputBinding::key("fail", 1)];
    assert_eq!(binding.predecessors.len(), 1);
    assert_eq!(binding.predecessors[0].node_id, "tasks");
    assert!(
        binding.predecessors[0].result.producers.is_empty(),
        "a failed visit produced no effect result, and the binding says so"
    );
}
