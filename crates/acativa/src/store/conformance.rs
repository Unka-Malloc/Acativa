//! Independent bounded synthetic conformance model for the closed strategy
//! collaboration DSL contract.
//!
//! This module is test-only. It does not read implementation text; it builds
//! small workflows, bounded JSON payloads, empty and dependency-ordered
//! worksets, retry/fallback/failure sequences, reversed outcome orders, and
//! multi-run durable claims, then compares observable canonical snapshots,
//! emitted commands, transition targets, and capacity counts with the frozen
//! semantic table.

use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::time::{SystemTime, UNIX_EPOCH};

use super::StrategyStore;
use crate::workflow::machine::fallback_reason;
use crate::{
    ActorSlot, BindingKind, CallbackDecision, CommandStatus, CompiledWorkflow, FailureClass,
    GraphState, GraphStateKind, GuardExpression, MAX_ACTIVE_EFFECTS, ReducerEvent, RetryPolicy,
    RunCommand, RunSnapshot, RuntimeKind, RuntimeRequirement, StrategyRunStatus, Transition,
    TransitionEvent, TransitionMode, WorkflowDefinition, WorkflowLimits, WorkflowMetadata,
    WorksetTemplate, reduce,
};

/// Every conformance fixture compiles under the crate's generic schema: the
/// same parameter a host binds its own identity to.
fn compile_workflow(
    definition: WorkflowDefinition,
) -> Result<CompiledWorkflow, crate::WorkflowValidationFailure> {
    crate::compile_workflow(
        definition,
        &crate::SchemaId::new(crate::GENERIC_WORKFLOW_SCHEMA),
    )
}

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

fn guard(path: &str, equals: Value) -> GuardExpression {
    GuardExpression {
        path: path.into(),
        equals: Some(equals),
        exists: false,
    }
}

fn edge(
    id: &str,
    from: &str,
    to: &str,
    event: TransitionEvent,
    expression: Option<GuardExpression>,
) -> Transition {
    Transition {
        id: id.into(),
        from: from.into(),
        to: to.into(),
        event,
        mode: TransitionMode::Flow,
        guard: expression,
    }
}

fn callback_edge(
    id: &str,
    from: &str,
    to: &str,
    event: TransitionEvent,
    expression: Option<GuardExpression>,
) -> Transition {
    Transition {
        mode: TransitionMode::Callback,
        ..edge(id, from, to, event, expression)
    }
}

fn defn(
    initial: &str,
    states: Vec<GraphState>,
    transitions: Vec<Transition>,
    slots: Vec<ActorSlot>,
    worksets: Vec<WorksetTemplate>,
    limits: WorkflowLimits,
) -> WorkflowDefinition {
    WorkflowDefinition {
        schema: crate::GENERIC_WORKFLOW_SCHEMA.into(),
        metadata: WorkflowMetadata {
            id: "conformance.workflow".into(),
            name: "Conformance".into(),
            version: "1".into(),
            description: String::new(),
        },
        limits,
        actor_slots: slots,
        runtimes: vec![],
        worksets,
        initial: initial.into(),
        states,
        transitions,
    }
}

fn assert_accept(name: &str, workflow: WorkflowDefinition) {
    assert!(
        compile_workflow(workflow).is_ok(),
        "compiler case `{name}` must be accepted"
    );
}

fn assert_reject(name: &str, workflow: WorkflowDefinition) {
    assert!(
        compile_workflow(workflow).is_err(),
        "compiler case `{name}` must be rejected"
    );
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

fn worker_slot() -> ActorSlot {
    let mut slot = ActorSlot::required_actor("worker", "Worker");
    slot.fallback.after_transient_attempts = 3;
    slot
}

fn runtime_slot() -> ActorSlot {
    let mut slot = ActorSlot::required_actor("py", "Python");
    slot.kind = BindingKind::Runtime;
    slot.entry = false;
    slot
}

fn tasks_template() -> WorksetTemplate {
    WorksetTemplate {
        id: "tasks".into(),
        item_binding: "id".into(),
        predecessor_field: "prerequisites".into(),
    }
}

fn workset_states(probe: bool) -> (Vec<GraphState>, Vec<Transition>) {
    let tasks = GraphState {
        id: "tasks".into(),
        kind: GraphStateKind::Workset,
        label: "Tasks".into(),
        instruction: String::new(),
        binding: Some("worker".into()),
        runtime: None,
        entry: None,
        workset: Some("tasks".into()),
        retry: RetryPolicy {
            max_attempts: 2,
            transient_only: true,
        },
    };
    let mut transitions = vec![edge(
        "tasks-done",
        "tasks",
        "done",
        TransitionEvent::Success,
        None,
    )];
    let states = if probe {
        transitions.push(edge(
            "tasks-failed-a",
            "tasks",
            "fail-a",
            TransitionEvent::Failure,
            Some(guard("code", json!("effect_a"))),
        ));
        transitions.push(edge(
            "tasks-failed-other",
            "tasks",
            "fail-other",
            TransitionEvent::Failure,
            None,
        ));
        vec![
            tasks,
            state("done", GraphStateKind::Succeed),
            state("fail-a", GraphStateKind::Fail),
            state("fail-other", GraphStateKind::Fail),
        ]
    } else {
        transitions.push(edge(
            "tasks-failed",
            "tasks",
            "fail",
            TransitionEvent::Failure,
            None,
        ));
        vec![
            tasks,
            state("done", GraphStateKind::Succeed),
            state("fail", GraphStateKind::Fail),
        ]
    };
    (states, transitions)
}

fn workset_workflow(limits: WorkflowLimits) -> CompiledWorkflow {
    let (states, transitions) = workset_states(false);
    compile_workflow(defn(
        "tasks",
        states,
        transitions,
        vec![worker_slot()],
        vec![tasks_template()],
        limits,
    ))
    .unwrap()
}

/// Workset with an observable failure probe: the `failure` edge is guarded on
/// the selected command's `code`, so tests can see which stable identity was
/// selected without depending on unobservable payload internals.
fn workset_probe_workflow(limits: WorkflowLimits) -> CompiledWorkflow {
    let (states, transitions) = workset_states(true);
    compile_workflow(defn(
        "tasks",
        states,
        transitions,
        vec![worker_slot()],
        vec![tasks_template()],
        limits,
    ))
    .unwrap()
}

fn actor_loop_workflow(
    limits: WorkflowLimits,
    retry_max_attempts: u8,
    slot_after_transient: u8,
) -> CompiledWorkflow {
    let mut slot = worker_slot();
    slot.fallback.after_transient_attempts = slot_after_transient;
    compile_workflow(defn(
        "work",
        vec![
            GraphState {
                id: "work".into(),
                kind: GraphStateKind::Actor,
                label: "Work".into(),
                instruction: String::new(),
                binding: Some("worker".into()),
                runtime: None,
                entry: None,
                workset: None,
                retry: RetryPolicy {
                    max_attempts: retry_max_attempts,
                    transient_only: true,
                },
            },
            state("done", GraphStateKind::Succeed),
            state("fail", GraphStateKind::Fail),
        ],
        vec![
            edge(
                "work-again",
                "work",
                "work",
                TransitionEvent::Success,
                Some(guard("context.again", json!(true))),
            ),
            edge("work-done", "work", "done", TransitionEvent::Success, None),
            edge(
                "work-failed",
                "work",
                "fail",
                TransitionEvent::Failure,
                None,
            ),
        ],
        vec![slot],
        vec![],
        limits,
    ))
    .unwrap()
}

fn start_run(workflow: &CompiledWorkflow, input: Value) -> (RunSnapshot, Vec<RunCommand>) {
    let output = reduce(
        workflow,
        &RunSnapshot::empty("conformance-run", "revision", "semantics"),
        ReducerEvent::Start { input },
    )
    .unwrap();
    (output.snapshot, output.emitted_commands)
}

fn fence(snapshot: &RunSnapshot, workflow: &CompiledWorkflow, command: &RunCommand) -> RunSnapshot {
    let claimed = reduce(
        workflow,
        snapshot,
        ReducerEvent::CommandClaimed {
            command_id: command.id.clone(),
            attempt_token: command.attempt_token.clone(),
        },
    )
    .unwrap()
    .snapshot;
    reduce(
        workflow,
        &claimed,
        ReducerEvent::CommandStarted {
            command_id: command.id.clone(),
            attempt_token: command.attempt_token.clone(),
        },
    )
    .unwrap()
    .snapshot
}

fn find_item<'a>(commands: &'a [RunCommand], item_id: &str) -> &'a RunCommand {
    commands
        .iter()
        .find(|command| command.item_id.as_deref() == Some(item_id))
        .unwrap_or_else(|| panic!("command for item `{item_id}` not emitted"))
}

#[test]
fn typed_event_vocabulary_is_closed_and_kebab_case() {
    for event in [
        TransitionEvent::Complete,
        TransitionEvent::Success,
        TransitionEvent::Failure,
    ] {
        let wire = serde_json::to_string(&event).unwrap();
        assert_eq!(wire, format!("\"{}\"", event.as_str()));
        assert_eq!(
            serde_json::from_str::<TransitionEvent>(&wire).unwrap(),
            event
        );
    }
    assert!(serde_json::from_str::<TransitionEvent>("\"cancel\"").is_err());
    assert!(serde_json::from_str::<TransitionEvent>("\"Complete\"").is_err());
}

#[test]
fn typed_mode_vocabulary_is_closed_and_kebab_case() {
    assert_eq!(
        serde_json::from_str::<TransitionMode>("\"flow\"").unwrap(),
        TransitionMode::Flow
    );
    assert_eq!(
        serde_json::from_str::<TransitionMode>("\"callback\"").unwrap(),
        TransitionMode::Callback
    );
    assert!(serde_json::from_str::<TransitionMode>("\"warp\"").is_err());
    assert!(serde_json::from_str::<TransitionMode>("\"Flow\"").is_err());
}

#[test]
fn callback_edges_park_and_the_decision_settles_the_wait() {
    let workflow = compile_workflow(defn(
        "work",
        vec![
            GraphState {
                id: "work".into(),
                kind: GraphStateKind::Actor,
                label: "Work".into(),
                instruction: String::new(),
                binding: Some("worker".into()),
                runtime: None,
                entry: None,
                workset: None,
                retry: RetryPolicy::default(),
            },
            state("done", GraphStateKind::Succeed),
            state("fail", GraphStateKind::Fail),
        ],
        vec![
            callback_edge("review", "work", "done", TransitionEvent::Success, None),
            edge(
                "work-failed",
                "work",
                "fail",
                TransitionEvent::Failure,
                None,
            ),
        ],
        vec![worker_slot()],
        vec![],
        WorkflowLimits::default(),
    ))
    .unwrap();
    let (snapshot, commands) = start_run(&workflow, json!({}));
    let snapshot = fence(&snapshot, &workflow, &commands[0]);
    let parked = reduce(
        &workflow,
        &snapshot,
        ReducerEvent::CommandSucceeded {
            command_id: commands[0].id.clone(),
            attempt_token: commands[0].attempt_token.clone(),
            output: json!({"ok": true}),
        },
    )
    .unwrap();
    assert_eq!(parked.snapshot.status, StrategyRunStatus::Waiting);
    assert!(parked.emitted_commands.is_empty());
    assert_eq!(parked.snapshot.pending_callbacks.len(), 1);
    assert_eq!(parked.snapshot.pending_callbacks[0].transition_id, "review");

    let terminated = reduce(
        &workflow,
        &parked.snapshot,
        ReducerEvent::CallbackDecision {
            state_id: "work".into(),
            state_visit: 1,
            decision: CallbackDecision::Terminate,
        },
    )
    .unwrap();
    assert_eq!(terminated.snapshot.status, StrategyRunStatus::Cancelled);
    assert!(terminated.snapshot.pending_callbacks.is_empty());

    let advanced = reduce(
        &workflow,
        &parked.snapshot,
        ReducerEvent::CallbackDecision {
            state_id: "work".into(),
            state_visit: 1,
            decision: CallbackDecision::Enter("done".to_owned()),
        },
    )
    .unwrap();
    assert_eq!(advanced.snapshot.status, StrategyRunStatus::Completed);
    assert_eq!(
        advanced.snapshot.completed_states,
        BTreeSet::from(["work".to_owned(), "done".to_owned()])
    );
}

#[test]
fn compiler_class_table_accepts_only_total_routing() {
    let limits = WorkflowLimits::default();

    // Pass: exactly one unguarded complete edge.
    assert_accept(
        "pass-ok",
        defn(
            "start",
            vec![
                state("start", GraphStateKind::Pass),
                state("done", GraphStateKind::Succeed),
            ],
            vec![edge(
                "finish",
                "start",
                "done",
                TransitionEvent::Complete,
                None,
            )],
            vec![],
            vec![],
            limits.clone(),
        ),
    );
    assert_reject(
        "pass-no-edge",
        defn(
            "start",
            vec![
                state("start", GraphStateKind::Pass),
                state("done", GraphStateKind::Succeed),
            ],
            vec![],
            vec![],
            vec![],
            limits.clone(),
        ),
    );
    assert_reject(
        "pass-guarded-complete",
        defn(
            "start",
            vec![
                state("start", GraphStateKind::Pass),
                state("done", GraphStateKind::Succeed),
            ],
            vec![edge(
                "finish",
                "start",
                "done",
                TransitionEvent::Complete,
                Some(guard("mode", json!("fast"))),
            )],
            vec![],
            vec![],
            limits.clone(),
        ),
    );
    assert_reject(
        "pass-success-event",
        defn(
            "start",
            vec![
                state("start", GraphStateKind::Pass),
                state("done", GraphStateKind::Succeed),
            ],
            vec![edge(
                "finish",
                "start",
                "done",
                TransitionEvent::Success,
                None,
            )],
            vec![],
            vec![],
            limits.clone(),
        ),
    );

    // A sequential join is defined only when it has one guaranteed arrival.
    assert_accept(
        "sequential-join-ok",
        defn(
            "start",
            vec![
                state("start", GraphStateKind::Pass),
                state("join", GraphStateKind::Join),
                state("done", GraphStateKind::Succeed),
            ],
            vec![
                edge(
                    "start-join",
                    "start",
                    "join",
                    TransitionEvent::Complete,
                    None,
                ),
                edge("finish", "join", "done", TransitionEvent::Complete, None),
            ],
            vec![],
            vec![],
            limits.clone(),
        ),
    );
    assert_reject(
        "initial-join-without-arrival",
        defn(
            "join",
            vec![
                state("join", GraphStateKind::Join),
                state("done", GraphStateKind::Succeed),
            ],
            vec![edge(
                "finish",
                "join",
                "done",
                TransitionEvent::Complete,
                None,
            )],
            vec![],
            vec![],
            limits.clone(),
        ),
    );
    assert_reject(
        "choice-cannot-feed-a-multi-arrival-join",
        defn(
            "pick",
            vec![
                state("pick", GraphStateKind::Choice),
                state("a", GraphStateKind::Pass),
                state("b", GraphStateKind::Pass),
                state("join", GraphStateKind::Join),
                state("done", GraphStateKind::Succeed),
            ],
            vec![
                edge(
                    "pick-a",
                    "pick",
                    "a",
                    TransitionEvent::Complete,
                    Some(guard("mode", json!("a"))),
                ),
                edge("pick-b", "pick", "b", TransitionEvent::Complete, None),
                edge("a-join", "a", "join", TransitionEvent::Complete, None),
                edge("b-join", "b", "join", TransitionEvent::Complete, None),
                edge("finish", "join", "done", TransitionEvent::Complete, None),
            ],
            vec![],
            vec![],
            limits.clone(),
        ),
    );

    // Choice: guarded edges plus one unguarded fallback.
    assert_accept(
        "choice-single-guard-plus-fallback",
        defn(
            "pick",
            vec![
                state("pick", GraphStateKind::Choice),
                state("done", GraphStateKind::Succeed),
            ],
            vec![
                edge(
                    "fast",
                    "pick",
                    "done",
                    TransitionEvent::Complete,
                    Some(guard("mode", json!("fast"))),
                ),
                edge("other", "pick", "done", TransitionEvent::Complete, None),
            ],
            vec![],
            vec![],
            limits.clone(),
        ),
    );
    assert_accept(
        "choice-equality-partition",
        defn(
            "pick",
            vec![
                state("pick", GraphStateKind::Choice),
                state("fast", GraphStateKind::Succeed),
                state("slow", GraphStateKind::Succeed),
                state("other", GraphStateKind::Succeed),
            ],
            vec![
                edge(
                    "pick-fast",
                    "pick",
                    "fast",
                    TransitionEvent::Complete,
                    Some(guard("mode", json!("fast"))),
                ),
                edge(
                    "pick-slow",
                    "pick",
                    "slow",
                    TransitionEvent::Complete,
                    Some(guard("mode", json!("slow"))),
                ),
                edge(
                    "pick-other",
                    "pick",
                    "other",
                    TransitionEvent::Complete,
                    None,
                ),
            ],
            vec![],
            vec![],
            limits.clone(),
        ),
    );
    assert_reject(
        "choice-single-wrong-event",
        defn(
            "pick",
            vec![
                state("pick", GraphStateKind::Choice),
                state("done", GraphStateKind::Succeed),
            ],
            vec![edge(
                "wrong",
                "pick",
                "done",
                TransitionEvent::Success,
                None,
            )],
            vec![],
            vec![],
            limits.clone(),
        ),
    );
    assert_reject(
        "choice-missing-fallback",
        defn(
            "pick",
            vec![
                state("pick", GraphStateKind::Choice),
                state("done", GraphStateKind::Succeed),
            ],
            vec![edge(
                "only-guard",
                "pick",
                "done",
                TransitionEvent::Complete,
                Some(guard("mode", json!("fast"))),
            )],
            vec![],
            vec![],
            limits.clone(),
        ),
    );
    assert_reject(
        "choice-duplicate-guard",
        defn(
            "pick",
            vec![
                state("pick", GraphStateKind::Choice),
                state("done", GraphStateKind::Succeed),
            ],
            vec![
                edge(
                    "fast-a",
                    "pick",
                    "done",
                    TransitionEvent::Complete,
                    Some(guard("mode", json!("fast"))),
                ),
                edge(
                    "fast-b",
                    "pick",
                    "done",
                    TransitionEvent::Complete,
                    Some(guard("mode", json!("fast"))),
                ),
                edge("other", "pick", "done", TransitionEvent::Complete, None),
            ],
            vec![],
            vec![],
            limits.clone(),
        ),
    );
    assert_reject(
        "choice-mixed-guard-paths",
        defn(
            "pick",
            vec![
                state("pick", GraphStateKind::Choice),
                state("done", GraphStateKind::Succeed),
            ],
            vec![
                edge(
                    "mode-fast",
                    "pick",
                    "done",
                    TransitionEvent::Complete,
                    Some(guard("mode", json!("fast"))),
                ),
                edge(
                    "speed-slow",
                    "pick",
                    "done",
                    TransitionEvent::Complete,
                    Some(guard("speed", json!("slow"))),
                ),
                edge("other", "pick", "done", TransitionEvent::Complete, None),
            ],
            vec![],
            vec![],
            limits.clone(),
        ),
    );
    assert_reject(
        "choice-exists-and-equality-mix",
        defn(
            "pick",
            vec![
                state("pick", GraphStateKind::Choice),
                state("done", GraphStateKind::Succeed),
            ],
            vec![
                edge(
                    "exists",
                    "pick",
                    "done",
                    TransitionEvent::Complete,
                    Some(GuardExpression {
                        path: "mode".into(),
                        equals: None,
                        exists: true,
                    }),
                ),
                edge(
                    "equals",
                    "pick",
                    "done",
                    TransitionEvent::Complete,
                    Some(guard("mode", json!("fast"))),
                ),
                edge("other", "pick", "done", TransitionEvent::Complete, None),
            ],
            vec![],
            vec![],
            limits.clone(),
        ),
    );
    assert_reject(
        "choice-two-fallbacks",
        defn(
            "pick",
            vec![
                state("pick", GraphStateKind::Choice),
                state("done", GraphStateKind::Succeed),
            ],
            vec![
                edge("first", "pick", "done", TransitionEvent::Complete, None),
                edge("second", "pick", "done", TransitionEvent::Complete, None),
            ],
            vec![],
            vec![],
            limits.clone(),
        ),
    );

    // Fork: at least two unguarded complete edges to distinct targets.
    assert_reject(
        "fork-one-branch",
        defn(
            "fork",
            vec![
                state("fork", GraphStateKind::Fork),
                state("a", GraphStateKind::Pass),
                state("done", GraphStateKind::Succeed),
            ],
            vec![
                edge("fa", "fork", "a", TransitionEvent::Complete, None),
                edge("ad", "a", "done", TransitionEvent::Complete, None),
            ],
            vec![],
            vec![],
            limits.clone(),
        ),
    );
    assert_reject(
        "fork-guarded-branch",
        defn(
            "fork",
            vec![
                state("fork", GraphStateKind::Fork),
                state("a", GraphStateKind::Pass),
                state("b", GraphStateKind::Pass),
                state("done", GraphStateKind::Succeed),
            ],
            vec![
                edge(
                    "fa",
                    "fork",
                    "a",
                    TransitionEvent::Complete,
                    Some(guard("mode", json!("fast"))),
                ),
                edge("fb", "fork", "b", TransitionEvent::Complete, None),
                edge("ad", "a", "done", TransitionEvent::Complete, None),
                edge("bd", "b", "done", TransitionEvent::Complete, None),
            ],
            vec![],
            vec![],
            limits.clone(),
        ),
    );
    assert_reject(
        "fork-duplicate-target",
        defn(
            "fork",
            vec![
                state("fork", GraphStateKind::Fork),
                state("a", GraphStateKind::Pass),
                state("done", GraphStateKind::Succeed),
            ],
            vec![
                edge("fa1", "fork", "a", TransitionEvent::Complete, None),
                edge("fa2", "fork", "a", TransitionEvent::Complete, None),
                edge("ad", "a", "done", TransitionEvent::Complete, None),
            ],
            vec![],
            vec![],
            limits.clone(),
        ),
    );

    // Authorization: total success and failure routing.
    assert_accept(
        "authorization-ok",
        defn(
            "authorize",
            vec![
                state("authorize", GraphStateKind::Authorization),
                state("done", GraphStateKind::Succeed),
                state("blocked", GraphStateKind::Blocked),
            ],
            vec![
                edge(
                    "granted",
                    "authorize",
                    "done",
                    TransitionEvent::Success,
                    None,
                ),
                edge(
                    "denied",
                    "authorize",
                    "blocked",
                    TransitionEvent::Failure,
                    None,
                ),
            ],
            vec![],
            vec![],
            limits.clone(),
        ),
    );
    assert_reject(
        "authorization-missing-failure",
        defn(
            "authorize",
            vec![
                state("authorize", GraphStateKind::Authorization),
                state("done", GraphStateKind::Succeed),
            ],
            vec![edge(
                "granted",
                "authorize",
                "done",
                TransitionEvent::Success,
                None,
            )],
            vec![],
            vec![],
            limits.clone(),
        ),
    );
    assert_reject(
        "authorization-missing-success",
        defn(
            "authorize",
            vec![
                state("authorize", GraphStateKind::Authorization),
                state("blocked", GraphStateKind::Blocked),
            ],
            vec![edge(
                "denied",
                "authorize",
                "blocked",
                TransitionEvent::Failure,
                None,
            )],
            vec![],
            vec![],
            limits.clone(),
        ),
    );

    // Actor: total success and failure routing, plus guarded loops.
    let actor_states = || {
        vec![
            GraphState {
                id: "work".into(),
                kind: GraphStateKind::Actor,
                label: "Work".into(),
                instruction: String::new(),
                binding: Some("worker".into()),
                runtime: None,
                entry: None,
                workset: None,
                retry: RetryPolicy::default(),
            },
            state("done", GraphStateKind::Succeed),
            state("fail", GraphStateKind::Fail),
        ]
    };
    assert_accept(
        "actor-ok",
        defn(
            "work",
            actor_states(),
            vec![
                edge("work-done", "work", "done", TransitionEvent::Success, None),
                edge(
                    "work-failed",
                    "work",
                    "fail",
                    TransitionEvent::Failure,
                    None,
                ),
            ],
            vec![worker_slot()],
            vec![],
            limits.clone(),
        ),
    );
    assert_reject(
        "actor-missing-failure",
        defn(
            "work",
            actor_states(),
            vec![edge(
                "work-done",
                "work",
                "done",
                TransitionEvent::Success,
                None,
            )],
            vec![worker_slot()],
            vec![],
            limits.clone(),
        ),
    );
    assert_reject(
        "actor-extra-complete-event",
        defn(
            "work",
            actor_states(),
            vec![
                edge("work-done", "work", "done", TransitionEvent::Success, None),
                edge(
                    "work-failed",
                    "work",
                    "fail",
                    TransitionEvent::Failure,
                    None,
                ),
                edge(
                    "work-complete",
                    "work",
                    "done",
                    TransitionEvent::Complete,
                    None,
                ),
            ],
            vec![worker_slot()],
            vec![],
            limits.clone(),
        ),
    );
    let mut optional_worker = worker_slot();
    optional_worker.required = false;
    assert_reject(
        "actor-optional-binding",
        defn(
            "work",
            actor_states(),
            vec![
                edge("work-done", "work", "done", TransitionEvent::Success, None),
                edge(
                    "work-failed",
                    "work",
                    "fail",
                    TransitionEvent::Failure,
                    None,
                ),
            ],
            vec![optional_worker],
            vec![],
            limits.clone(),
        ),
    );
    assert_accept(
        "actor-guarded-success-and-fallback",
        defn(
            "work",
            actor_states(),
            vec![
                edge(
                    "work-again",
                    "work",
                    "work",
                    TransitionEvent::Success,
                    Some(guard("context.again", json!(true))),
                ),
                edge("work-done", "work", "done", TransitionEvent::Success, None),
                edge(
                    "work-failed",
                    "work",
                    "fail",
                    TransitionEvent::Failure,
                    None,
                ),
            ],
            vec![worker_slot()],
            vec![],
            limits.clone(),
        ),
    );

    // Script: verified runtime plus total success and failure routing.
    let script_states = || {
        vec![
            GraphState {
                id: "run".into(),
                kind: GraphStateKind::Script,
                label: "Run".into(),
                instruction: String::new(),
                binding: None,
                runtime: Some("py".into()),
                entry: Some("scripts/run.py".into()),
                workset: None,
                retry: RetryPolicy::default(),
            },
            state("done", GraphStateKind::Succeed),
            state("fail", GraphStateKind::Fail),
        ]
    };
    let script_definition = |include_failure: bool| {
        let mut workflow = defn(
            "run",
            script_states(),
            vec![edge(
                "run-done",
                "run",
                "done",
                TransitionEvent::Success,
                None,
            )],
            vec![],
            vec![],
            limits.clone(),
        );
        if include_failure {
            workflow.transitions.push(edge(
                "run-failed",
                "run",
                "fail",
                TransitionEvent::Failure,
                None,
            ));
        }
        workflow.runtimes = vec![RuntimeRequirement {
            id: "py".into(),
            kind: RuntimeKind::new("python"),
            version_requirement: String::new(),
        }];
        workflow.actor_slots.push(runtime_slot());
        workflow
    };
    assert_accept("script-ok", script_definition(true));
    assert_reject("script-missing-failure", script_definition(false));
    let mut missing_runtime_binding = script_definition(true);
    missing_runtime_binding.actor_slots.clear();
    assert_reject("script-missing-runtime-binding", missing_runtime_binding);

    // Workset: template reference plus total success and failure routing.
    assert_accept(
        "workset-ok",
        defn(
            "tasks",
            vec![
                GraphState {
                    id: "tasks".into(),
                    kind: GraphStateKind::Workset,
                    label: "Tasks".into(),
                    instruction: String::new(),
                    binding: Some("worker".into()),
                    runtime: None,
                    entry: None,
                    workset: Some("tasks".into()),
                    retry: RetryPolicy::default(),
                },
                state("done", GraphStateKind::Succeed),
                state("fail", GraphStateKind::Fail),
            ],
            vec![
                edge(
                    "tasks-done",
                    "tasks",
                    "done",
                    TransitionEvent::Success,
                    None,
                ),
                edge(
                    "tasks-failed",
                    "tasks",
                    "fail",
                    TransitionEvent::Failure,
                    None,
                ),
            ],
            vec![worker_slot()],
            vec![tasks_template()],
            limits.clone(),
        ),
    );
    assert_reject(
        "workset-missing-failure",
        defn(
            "tasks",
            vec![
                GraphState {
                    id: "tasks".into(),
                    kind: GraphStateKind::Workset,
                    label: "Tasks".into(),
                    instruction: String::new(),
                    binding: Some("worker".into()),
                    runtime: None,
                    entry: None,
                    workset: Some("tasks".into()),
                    retry: RetryPolicy::default(),
                },
                state("done", GraphStateKind::Succeed),
            ],
            vec![edge(
                "tasks-done",
                "tasks",
                "done",
                TransitionEvent::Success,
                None,
            )],
            vec![worker_slot()],
            vec![tasks_template()],
            limits.clone(),
        ),
    );
    let (workset_states, workset_transitions) = workset_states(false);
    let mut conflicting_fields = tasks_template();
    conflicting_fields.predecessor_field = conflicting_fields.item_binding.clone();
    assert_reject(
        "workset-item-and-predecessor-field-conflict",
        defn(
            "tasks",
            workset_states,
            workset_transitions,
            vec![worker_slot()],
            vec![conflicting_fields],
            limits.clone(),
        ),
    );

    // Terminals have no outgoing edge.
    assert_accept(
        "terminal-blocked-ok",
        defn(
            "start",
            vec![
                state("start", GraphStateKind::Pass),
                state("blocked", GraphStateKind::Blocked),
            ],
            vec![edge(
                "finish",
                "start",
                "blocked",
                TransitionEvent::Complete,
                None,
            )],
            vec![],
            vec![],
            limits.clone(),
        ),
    );
    assert_reject(
        "terminal-with-outgoing-edge",
        defn(
            "start",
            vec![
                state("start", GraphStateKind::Pass),
                state("blocked", GraphStateKind::Blocked),
                state("after", GraphStateKind::Succeed),
            ],
            vec![
                edge(
                    "finish",
                    "start",
                    "blocked",
                    TransitionEvent::Complete,
                    None,
                ),
                edge(
                    "blocked-after",
                    "blocked",
                    "after",
                    TransitionEvent::Complete,
                    None,
                ),
            ],
            vec![],
            vec![],
            limits.clone(),
        ),
    );
}

#[test]
fn structured_parallel_regions_compile_and_reduce() {
    let limits = WorkflowLimits::default();
    assert_accept(
        "region-ok",
        defn(
            "fork",
            vec![
                state("fork", GraphStateKind::Fork),
                state("branch-a", GraphStateKind::Pass),
                state("branch-b", GraphStateKind::Pass),
                state("join", GraphStateKind::Join),
                state("done", GraphStateKind::Succeed),
            ],
            vec![
                edge("fa", "fork", "branch-a", TransitionEvent::Complete, None),
                edge("fb", "fork", "branch-b", TransitionEvent::Complete, None),
                edge("aj", "branch-a", "join", TransitionEvent::Complete, None),
                edge("bj", "branch-b", "join", TransitionEvent::Complete, None),
                edge("jd", "join", "done", TransitionEvent::Complete, None),
            ],
            vec![],
            vec![],
            limits.clone(),
        ),
    );
    let workflow = compile_workflow(defn(
        "fork",
        vec![
            state("fork", GraphStateKind::Fork),
            state("branch-a", GraphStateKind::Pass),
            state("branch-b", GraphStateKind::Pass),
            state("join", GraphStateKind::Join),
            state("done", GraphStateKind::Succeed),
        ],
        vec![
            edge("fa", "fork", "branch-a", TransitionEvent::Complete, None),
            edge("fb", "fork", "branch-b", TransitionEvent::Complete, None),
            edge("aj", "branch-a", "join", TransitionEvent::Complete, None),
            edge("bj", "branch-b", "join", TransitionEvent::Complete, None),
            edge("jd", "join", "done", TransitionEvent::Complete, None),
        ],
        vec![],
        vec![],
        limits.clone(),
    ))
    .unwrap();
    let (snapshot, commands) = start_run(&workflow, json!({}));
    assert!(commands.is_empty());
    assert_eq!(snapshot.status, StrategyRunStatus::Completed);
    assert!(snapshot.active_states.is_empty());
    assert!(snapshot.completed_states.contains("done"));

    assert_accept(
        "two-disjoint-regions",
        defn(
            "fork-1",
            vec![
                state("fork-1", GraphStateKind::Fork),
                state("a1", GraphStateKind::Pass),
                state("b1", GraphStateKind::Pass),
                state("join-1", GraphStateKind::Join),
                state("fork-2", GraphStateKind::Fork),
                state("a2", GraphStateKind::Pass),
                state("b2", GraphStateKind::Pass),
                state("join-2", GraphStateKind::Join),
                state("done", GraphStateKind::Succeed),
            ],
            vec![
                edge("f1a", "fork-1", "a1", TransitionEvent::Complete, None),
                edge("f1b", "fork-1", "b1", TransitionEvent::Complete, None),
                edge("a1j", "a1", "join-1", TransitionEvent::Complete, None),
                edge("b1j", "b1", "join-1", TransitionEvent::Complete, None),
                edge("j1f2", "join-1", "fork-2", TransitionEvent::Complete, None),
                edge("f2a", "fork-2", "a2", TransitionEvent::Complete, None),
                edge("f2b", "fork-2", "b2", TransitionEvent::Complete, None),
                edge("a2j", "a2", "join-2", TransitionEvent::Complete, None),
                edge("b2j", "b2", "join-2", TransitionEvent::Complete, None),
                edge("j2d", "join-2", "done", TransitionEvent::Complete, None),
            ],
            vec![],
            vec![],
            limits.clone(),
        ),
    );

    assert_reject(
        "region-branch-has-two-final-predecessors",
        defn(
            "fork",
            vec![
                state("fork", GraphStateKind::Fork),
                state("branch-a", GraphStateKind::Choice),
                state("a-fast", GraphStateKind::Pass),
                state("a-other", GraphStateKind::Pass),
                state("branch-b", GraphStateKind::Pass),
                state("join", GraphStateKind::Join),
                state("done", GraphStateKind::Succeed),
            ],
            vec![
                edge("fa", "fork", "branch-a", TransitionEvent::Complete, None),
                edge("fb", "fork", "branch-b", TransitionEvent::Complete, None),
                edge(
                    "a-fast-route",
                    "branch-a",
                    "a-fast",
                    TransitionEvent::Complete,
                    Some(guard("mode", json!("fast"))),
                ),
                edge(
                    "a-other-route",
                    "branch-a",
                    "a-other",
                    TransitionEvent::Complete,
                    None,
                ),
                edge(
                    "a-fast-join",
                    "a-fast",
                    "join",
                    TransitionEvent::Complete,
                    None,
                ),
                edge(
                    "a-other-join",
                    "a-other",
                    "join",
                    TransitionEvent::Complete,
                    None,
                ),
                edge(
                    "b-join",
                    "branch-b",
                    "join",
                    TransitionEvent::Complete,
                    None,
                ),
                edge("finish", "join", "done", TransitionEvent::Complete, None),
            ],
            vec![],
            vec![],
            limits.clone(),
        ),
    );

    // Nested fork inside a branch.
    assert_reject(
        "region-nested-fork",
        defn(
            "fork",
            vec![
                state("fork", GraphStateKind::Fork),
                state("nested", GraphStateKind::Fork),
                state("a", GraphStateKind::Pass),
                state("b", GraphStateKind::Pass),
                state("join", GraphStateKind::Join),
                state("done", GraphStateKind::Succeed),
            ],
            vec![
                edge("fn", "fork", "nested", TransitionEvent::Complete, None),
                edge("na", "nested", "a", TransitionEvent::Complete, None),
                edge("nb", "nested", "b", TransitionEvent::Complete, None),
                edge("aj", "a", "join", TransitionEvent::Complete, None),
                edge("bj", "b", "join", TransitionEvent::Complete, None),
                edge("jd", "join", "done", TransitionEvent::Complete, None),
            ],
            vec![],
            vec![],
            limits.clone(),
        ),
    );
    // A branch whose choice fallback exits into a terminal.
    assert_reject(
        "region-branch-terminal",
        defn(
            "fork",
            vec![
                state("fork", GraphStateKind::Fork),
                state("branch-a", GraphStateKind::Choice),
                state("branch-b", GraphStateKind::Pass),
                state("join", GraphStateKind::Join),
                state("done", GraphStateKind::Succeed),
                state("blocked", GraphStateKind::Blocked),
            ],
            vec![
                edge("fa", "fork", "branch-a", TransitionEvent::Complete, None),
                edge("fb", "fork", "branch-b", TransitionEvent::Complete, None),
                edge(
                    "aj",
                    "branch-a",
                    "join",
                    TransitionEvent::Complete,
                    Some(guard("mode", json!("fast"))),
                ),
                edge(
                    "ablk",
                    "branch-a",
                    "blocked",
                    TransitionEvent::Complete,
                    None,
                ),
                edge("bj", "branch-b", "join", TransitionEvent::Complete, None),
                edge("jd", "join", "done", TransitionEvent::Complete, None),
            ],
            vec![],
            vec![],
            limits.clone(),
        ),
    );
    // Branches exit into a terminal instead of a join.
    assert_reject(
        "region-missing-join",
        defn(
            "fork",
            vec![
                state("fork", GraphStateKind::Fork),
                state("branch-a", GraphStateKind::Pass),
                state("branch-b", GraphStateKind::Pass),
                state("done", GraphStateKind::Succeed),
            ],
            vec![
                edge("fa", "fork", "branch-a", TransitionEvent::Complete, None),
                edge("fb", "fork", "branch-b", TransitionEvent::Complete, None),
                edge("ad", "branch-a", "done", TransitionEvent::Complete, None),
                edge("bd", "branch-b", "done", TransitionEvent::Complete, None),
            ],
            vec![],
            vec![],
            limits.clone(),
        ),
    );
    // Cross-region edge: a later fork enters a branch already covered by the
    // first region, so the graph cannot be decomposed into disjoint regions.
    assert_reject(
        "region-cross-edge",
        defn(
            "fork-1",
            vec![
                state("fork-1", GraphStateKind::Fork),
                state("fork-2", GraphStateKind::Fork),
                state("a", GraphStateKind::Pass),
                state("b", GraphStateKind::Pass),
                state("c", GraphStateKind::Pass),
                state("join", GraphStateKind::Join),
                state("after", GraphStateKind::Pass),
                state("done", GraphStateKind::Succeed),
            ],
            vec![
                edge("f1a", "fork-1", "a", TransitionEvent::Complete, None),
                edge("f1b", "fork-1", "b", TransitionEvent::Complete, None),
                edge("aj", "a", "join", TransitionEvent::Complete, None),
                edge("bj", "b", "join", TransitionEvent::Complete, None),
                edge("ja", "join", "after", TransitionEvent::Complete, None),
                edge("af2", "after", "fork-2", TransitionEvent::Complete, None),
                edge("f2b", "fork-2", "b", TransitionEvent::Complete, None),
                edge("f2c", "fork-2", "c", TransitionEvent::Complete, None),
                edge("cj", "c", "join", TransitionEvent::Complete, None),
            ],
            vec![],
            vec![],
            limits.clone(),
        ),
    );
}

#[test]
fn choice_guard_partition_selects_one_edge_for_bounded_values() {
    let workflow = compile_workflow(defn(
        "pick",
        vec![
            state("pick", GraphStateKind::Choice),
            state("fast", GraphStateKind::Succeed),
            state("slow", GraphStateKind::Succeed),
            state("other", GraphStateKind::Succeed),
        ],
        vec![
            edge(
                "pick-fast",
                "pick",
                "fast",
                TransitionEvent::Complete,
                Some(guard("mode", json!("fast"))),
            ),
            edge(
                "pick-slow",
                "pick",
                "slow",
                TransitionEvent::Complete,
                Some(guard("mode", json!("slow"))),
            ),
            edge(
                "pick-other",
                "pick",
                "other",
                TransitionEvent::Complete,
                None,
            ),
        ],
        vec![],
        vec![],
        WorkflowLimits::default(),
    ))
    .unwrap();
    for (input, expected) in [
        (json!({"mode": "fast"}), "fast"),
        (json!({"mode": "slow"}), "slow"),
        (json!({"mode": "unknown"}), "other"),
        (json!({}), "other"),
    ] {
        let (snapshot, commands) = start_run(&workflow, input);
        assert!(commands.is_empty());
        assert_eq!(snapshot.status, StrategyRunStatus::Completed);
        assert!(
            snapshot.completed_states.contains(expected),
            "expected terminal `{expected}`, got {:?}",
            snapshot.completed_states
        );
    }
}

#[test]
fn empty_and_nonempty_worksets_both_take_success() {
    let workflow = workset_workflow(WorkflowLimits::default());
    let (snapshot, commands) = start_run(&workflow, json!({"worksets": {"tasks": []}}));
    assert!(commands.is_empty(), "empty worksets emit no item commands");
    assert_eq!(snapshot.status, StrategyRunStatus::Completed);
    assert!(snapshot.completed_states.contains("done"));
    assert!(snapshot.active_states.is_empty());

    let (mut snapshot, commands) = start_run(
        &workflow,
        json!({"worksets": {"tasks": [{"id": "a"}, {"id": "b"}]}}),
    );
    assert_eq!(commands.len(), 2);
    assert_eq!(snapshot.status, StrategyRunStatus::Running);
    for command in &commands {
        snapshot = fence(&snapshot, &workflow, command);
    }
    for command in &commands {
        snapshot = reduce(
            &workflow,
            &snapshot,
            ReducerEvent::CommandSucceeded {
                command_id: command.id.clone(),
                attempt_token: command.attempt_token.clone(),
                output: json!({}),
            },
        )
        .unwrap()
        .snapshot;
    }
    assert_eq!(snapshot.status, StrategyRunStatus::Completed);
    assert!(snapshot.completed_states.contains("done"));
    assert!(snapshot.active_states.is_empty());
}

#[test]
fn empty_worksets_cannot_form_an_automatic_success_cycle() {
    let workset = GraphState {
        id: "tasks".into(),
        kind: GraphStateKind::Workset,
        label: "Tasks".into(),
        instruction: String::new(),
        binding: Some("worker".into()),
        runtime: None,
        entry: None,
        workset: Some("tasks".into()),
        retry: RetryPolicy::default(),
    };
    assert_reject(
        "workset-empty-success-cycle",
        defn(
            "tasks",
            vec![workset.clone(), state("failed", GraphStateKind::Fail)],
            vec![
                edge("repeat", "tasks", "tasks", TransitionEvent::Success, None),
                edge("failed", "tasks", "failed", TransitionEvent::Failure, None),
            ],
            vec![worker_slot()],
            vec![tasks_template()],
            WorkflowLimits::default(),
        ),
    );
    assert_accept(
        "workset-failure-cycle-still-has-an-effect-boundary",
        defn(
            "tasks",
            vec![workset, state("done", GraphStateKind::Succeed)],
            vec![
                edge("done", "tasks", "done", TransitionEvent::Success, None),
                edge(
                    "retry-visit",
                    "tasks",
                    "tasks",
                    TransitionEvent::Failure,
                    None,
                ),
            ],
            vec![worker_slot()],
            vec![tasks_template()],
            WorkflowLimits::default(),
        ),
    );
}

#[test]
fn workset_final_failure_is_taken_once_with_lowest_stable_identity() {
    let workflow = workset_probe_workflow(WorkflowLimits::default());
    for fail_first in [true, false] {
        let (mut snapshot, commands) = start_run(
            &workflow,
            json!({"worksets": {"tasks": [{"id": "a"}, {"id": "b"}]}}),
        );
        let (a, b) = (find_item(&commands, "a"), find_item(&commands, "b"));
        for command in &commands {
            snapshot = fence(&snapshot, &workflow, command);
        }
        let first = if fail_first { b } else { a };
        let second = if fail_first { a } else { b };
        let (first_code, second_code) = if fail_first {
            ("effect_b", "effect_a")
        } else {
            ("effect_a", "effect_b")
        };
        snapshot = reduce(
            &workflow,
            &snapshot,
            ReducerEvent::CommandFailed {
                command_id: first.id.clone(),
                attempt_token: first.attempt_token.clone(),
                class: FailureClass::Permanent,
                code: first_code.into(),
            },
        )
        .unwrap()
        .snapshot;
        assert_eq!(
            snapshot.status,
            StrategyRunStatus::Running,
            "failure must wait while another fenced command is unsettled"
        );
        snapshot = reduce(
            &workflow,
            &snapshot,
            ReducerEvent::CommandFailed {
                command_id: second.id.clone(),
                attempt_token: second.attempt_token.clone(),
                class: FailureClass::Permanent,
                code: second_code.into(),
            },
        )
        .unwrap()
        .snapshot;
        assert_eq!(snapshot.status, StrategyRunStatus::Failed);
        assert!(snapshot.active_states.is_empty());
        assert!(
            snapshot.state_visits.contains_key("fail-a"),
            "lowest failed identity must be selected, visits: {:?}",
            snapshot.state_visits
        );
        assert!(
            !snapshot.state_visits.contains_key("fail-other")
                && !snapshot.state_visits.contains_key("done"),
            "the failure edge must fire exactly once to the selected terminal"
        );
    }

    // A lower item that succeeded must not shadow the failed higher item.
    let (mut snapshot, commands) = start_run(
        &workflow,
        json!({"worksets": {"tasks": [{"id": "a"}, {"id": "b"}]}}),
    );
    let (a, b) = (find_item(&commands, "a"), find_item(&commands, "b"));
    for command in &commands {
        snapshot = fence(&snapshot, &workflow, command);
    }
    snapshot = reduce(
        &workflow,
        &snapshot,
        ReducerEvent::CommandSucceeded {
            command_id: a.id.clone(),
            attempt_token: a.attempt_token.clone(),
            output: json!({}),
        },
    )
    .unwrap()
    .snapshot;
    snapshot = reduce(
        &workflow,
        &snapshot,
        ReducerEvent::CommandFailed {
            command_id: b.id.clone(),
            attempt_token: b.attempt_token.clone(),
            class: FailureClass::Permanent,
            code: "effect_b".into(),
        },
    )
    .unwrap()
    .snapshot;
    assert_eq!(snapshot.status, StrategyRunStatus::Failed);
    assert!(
        snapshot.state_visits.contains_key("fail-other"),
        "only the failed item identity may select the failure route, visits: {:?}",
        snapshot.state_visits
    );
    assert!(!snapshot.state_visits.contains_key("fail-a"));
    // Failure was taken once: a later duplicate success is a no-op.
    let duplicate = reduce(
        &workflow,
        &snapshot,
        ReducerEvent::CommandSucceeded {
            command_id: a.id.clone(),
            attempt_token: a.attempt_token.clone(),
            output: json!({}),
        },
    )
    .unwrap();
    assert!(!duplicate.applied);
    assert_eq!(duplicate.snapshot, snapshot);
}

#[test]
fn workset_failure_stops_admitting_dependents_and_cancels_unfenced_pending() {
    let workflow = workset_probe_workflow(WorkflowLimits::default());
    // b gates c: when b fails, c must never be issued and the still-pending
    // sibling a is cancelled before the single failure transition.
    let (mut snapshot, commands) = start_run(
        &workflow,
        json!({"worksets": {"tasks": [
            {"id": "a"},
            {"id": "b", "prerequisites": []},
            {"id": "c", "prerequisites": ["b"]}
        ]}}),
    );
    assert_eq!(commands.len(), 2);
    assert!(
        !commands
            .iter()
            .any(|command| command.item_id.as_deref() == Some("c"))
    );
    let b = find_item(&commands, "b");
    snapshot = reduce(
        &workflow,
        &snapshot,
        ReducerEvent::CommandFailed {
            command_id: b.id.clone(),
            attempt_token: b.attempt_token.clone(),
            class: FailureClass::Permanent,
            code: "effect_b".into(),
        },
    )
    .unwrap()
    .snapshot;
    assert_eq!(snapshot.status, StrategyRunStatus::Failed);
    assert!(
        snapshot
            .commands
            .values()
            .any(|command| command.status == CommandStatus::Cancelled),
        "unfenced pending siblings must be cancelled on final failure"
    );
    assert!(
        !snapshot
            .commands
            .values()
            .any(|command| command.item_id.as_deref() == Some("c")),
        "dependent items must never be admitted after final failure"
    );
    assert!(snapshot.state_visits.contains_key("fail-other"));
    assert!(
        reduce(
            &workflow,
            &snapshot,
            ReducerEvent::RetryRequested {
                command_id: b.id.clone(),
            },
        )
        .is_err(),
        "no retry may be admitted after the final workset failure"
    );
}

#[test]
fn final_workset_failure_cancels_an_unfenced_retry_lineage() {
    let workflow = workset_probe_workflow(WorkflowLimits::default());
    let (mut snapshot, commands) = start_run(
        &workflow,
        json!({"worksets": {"tasks": [{"id": "a"}, {"id": "b"}]}}),
    );
    let a = find_item(&commands, "a").clone();
    let b = find_item(&commands, "b").clone();
    for command in &commands {
        snapshot = fence(&snapshot, &workflow, command);
    }
    snapshot = reduce(
        &workflow,
        &snapshot,
        ReducerEvent::CommandFailed {
            command_id: a.id.clone(),
            attempt_token: a.attempt_token,
            class: FailureClass::Transient,
            code: "effect_temporarily_unavailable".into(),
        },
    )
    .unwrap()
    .snapshot;
    assert_eq!(snapshot.commands[&a.id].status, CommandStatus::Retryable);
    snapshot = reduce(
        &workflow,
        &snapshot,
        ReducerEvent::CommandFailed {
            command_id: b.id,
            attempt_token: b.attempt_token,
            class: FailureClass::Permanent,
            code: "effect_b".into(),
        },
    )
    .unwrap()
    .snapshot;
    assert_eq!(snapshot.status, StrategyRunStatus::Failed);
    assert_eq!(snapshot.commands[&a.id].status, CommandStatus::Cancelled);
}

#[test]
fn concurrent_workset_fallback_and_fencing_are_order_independent() {
    let workflow = workset_probe_workflow(WorkflowLimits::default());
    let drive = |quota_first: bool, in_doubt: bool| {
        let (mut snapshot, commands) = start_run(
            &workflow,
            json!({"worksets": {"tasks": [{"id": "a"}, {"id": "b"}]}}),
        );
        snapshot.slot_candidate_counts.insert("worker".into(), 2);
        let a = find_item(&commands, "a").clone();
        let b = find_item(&commands, "b").clone();
        for command in &commands {
            snapshot = fence(&snapshot, &workflow, command);
        }
        let outcomes = if quota_first {
            vec![
                (a.clone(), FailureClass::Permanent, "quota_exhausted"),
                (
                    b,
                    if in_doubt {
                        FailureClass::InDoubt
                    } else {
                        FailureClass::Permanent
                    },
                    if in_doubt {
                        "effect_outcome_unknown"
                    } else {
                        "effect_b"
                    },
                ),
            ]
        } else {
            vec![
                (
                    b,
                    if in_doubt {
                        FailureClass::InDoubt
                    } else {
                        FailureClass::Permanent
                    },
                    if in_doubt {
                        "effect_outcome_unknown"
                    } else {
                        "effect_b"
                    },
                ),
                (a.clone(), FailureClass::Permanent, "quota_exhausted"),
            ]
        };
        for (index, (command, class, code)) in outcomes.into_iter().enumerate() {
            snapshot = reduce(
                &workflow,
                &snapshot,
                ReducerEvent::CommandFailed {
                    command_id: command.id,
                    attempt_token: command.attempt_token,
                    class,
                    code: code.into(),
                },
            )
            .unwrap()
            .snapshot;
            if index == 0 && quota_first {
                assert!(
                    fallback_reason(&workflow, &snapshot, &snapshot.commands[&a.id]).is_none(),
                    "fallback must wait for every concurrently fenced sibling"
                );
            }
        }
        snapshot
    };

    let final_a = drive(true, false);
    let final_b = drive(false, false);
    assert_eq!(final_a, final_b);
    assert_eq!(final_a.status, StrategyRunStatus::Failed);
    assert!(final_a.fallbacks.is_empty());

    let fenced_a = drive(true, true);
    let fenced_b = drive(false, true);
    assert_eq!(fenced_a, fenced_b);
    assert_eq!(fenced_a.status, StrategyRunStatus::CancelInDoubt);
    assert!(fenced_a.active_states.contains("tasks"));
    assert!(!fenced_a.state_visits.contains_key("fail-other"));
}

#[test]
fn equivalent_concurrent_outcome_orders_reach_one_canonical_snapshot() {
    let workflow = workset_probe_workflow(WorkflowLimits::default());
    let input = json!({"worksets": {"tasks": [
        {"id": "a"},
        {"id": "b"},
        {"id": "c"}
    ]}});

    fn drive(workflow: &CompiledWorkflow, input: Value, outcomes: &[(&str, bool)]) -> RunSnapshot {
        let (mut snapshot, commands) = start_run(workflow, input);
        for command in &commands {
            snapshot = fence(&snapshot, workflow, command);
        }
        for (item_id, succeeds) in outcomes {
            let command = find_item(&commands, item_id).clone();
            snapshot = if *succeeds {
                // Context and worksets are key-union resources: disjoint keys
                // merge in every order, and a second value for one key is a
                // conflict. Each member therefore writes its own key.
                reduce(
                    workflow,
                    &snapshot,
                    ReducerEvent::CommandSucceeded {
                        command_id: command.id.clone(),
                        attempt_token: command.attempt_token.clone(),
                        output: json!({
                            "context": {format!("from-{item_id}"): item_id},
                        }),
                    },
                )
            } else {
                reduce(
                    workflow,
                    &snapshot,
                    ReducerEvent::CommandFailed {
                        command_id: command.id.clone(),
                        attempt_token: command.attempt_token.clone(),
                        class: FailureClass::Permanent,
                        code: "effect_b".into(),
                    },
                )
            }
            .unwrap()
            .snapshot;
        }
        snapshot
    }

    let permutations = [
        [("a", true), ("b", true), ("c", true)],
        [("a", true), ("c", true), ("b", true)],
        [("b", true), ("a", true), ("c", true)],
        [("b", true), ("c", true), ("a", true)],
        [("c", true), ("a", true), ("b", true)],
        [("c", true), ("b", true), ("a", true)],
    ];
    let reference = serde_json::to_vec(&drive(&workflow, input.clone(), &permutations[0])).unwrap();
    for order in &permutations[1..] {
        let snapshot = drive(&workflow, input.clone(), order);
        assert_eq!(
            serde_json::to_vec(&snapshot).unwrap(),
            reference,
            "success completion order changed the canonical snapshot"
        );
        assert_eq!(snapshot.status, StrategyRunStatus::Completed);
        assert!(!snapshot.merge_sources.is_empty());
    }

    let failure_orders = [
        [("b", false), ("a", true), ("c", true)],
        [("a", true), ("b", false), ("c", true)],
        [("a", true), ("c", true), ("b", false)],
        [("b", false), ("c", true), ("a", true)],
        [("c", true), ("b", false), ("a", true)],
        [("c", true), ("a", true), ("b", false)],
    ];
    let reference =
        serde_json::to_vec(&drive(&workflow, input.clone(), &failure_orders[0])).unwrap();
    for order in &failure_orders[1..] {
        let snapshot = drive(&workflow, input.clone(), order);
        assert_eq!(
            serde_json::to_vec(&snapshot).unwrap(),
            reference,
            "failure completion order changed the canonical snapshot"
        );
        assert_eq!(snapshot.status, StrategyRunStatus::Failed);
        assert!(snapshot.state_visits.contains_key("fail-other"));
    }
}

#[test]
fn retry_and_fallback_lineage_never_exceed_global_max_attempts() {
    let workflow = actor_loop_workflow(
        WorkflowLimits {
            max_parallelism: 8,
            max_workset_items: 256,
            max_attempts: 2,
        },
        3,
        3,
    );
    let mut empty = RunSnapshot::empty("lineage-run", "revision", "semantics");
    empty.slot_candidate_counts.insert("worker".into(), 2);
    let started = reduce(&workflow, &empty, ReducerEvent::Start { input: json!({}) }).unwrap();
    let command = started.emitted_commands[0].clone();
    assert_eq!(command.attempt, 1);
    let failed = reduce(
        &workflow,
        &started.snapshot,
        ReducerEvent::CommandFailed {
            command_id: command.id.clone(),
            attempt_token: command.attempt_token.clone(),
            class: FailureClass::Transient,
            code: "effect_temporarily_unavailable".into(),
        },
    )
    .unwrap();
    assert_eq!(failed.snapshot.status, StrategyRunStatus::Retryable);
    let retried = reduce(
        &workflow,
        &failed.snapshot,
        ReducerEvent::RetryRequested {
            command_id: command.id,
        },
    )
    .unwrap();
    assert_eq!(retried.emitted_commands[0].attempt, 2);
    let retry_command = retried.emitted_commands[0].clone();
    let exhausted = reduce(
        &workflow,
        &retried.snapshot,
        ReducerEvent::CommandFailed {
            command_id: retry_command.id.clone(),
            attempt_token: retry_command.attempt_token.clone(),
            class: FailureClass::Transient,
            code: "effect_temporarily_unavailable".into(),
        },
    )
    .unwrap();
    assert_eq!(
        exhausted.snapshot.commands[&retry_command.id].status,
        CommandStatus::Failed
    );
    assert_eq!(exhausted.snapshot.status, StrategyRunStatus::Failed);
    assert_eq!(
        exhausted
            .snapshot
            .attempt_lineage
            .get("work\u{0}1\u{0}worker")
            .copied(),
        Some(2)
    );
    let fallback = reduce(
        &workflow,
        &exhausted.snapshot,
        ReducerEvent::FallbackIssued {
            failed_command_id: retry_command.id.clone(),
            next_ordinal: 1,
            locator: json!({"locatorUnavailable": true}),
            from_value_id: "agent:primary".into(),
            to_value_id: "agent:fallback".into(),
            reason: "transient-exhausted".into(),
            attempts: 2,
        },
    );
    assert!(
        fallback
            .unwrap_err()
            .to_string()
            .contains("strategy_attempt_budget_exhausted"),
        "fallback admission must respect the global maxAttempts lineage"
    );

    // With a larger global budget the same sequence may fall back exactly once.
    let workflow = actor_loop_workflow(
        WorkflowLimits {
            max_parallelism: 8,
            max_workset_items: 256,
            max_attempts: 3,
        },
        2,
        2,
    );
    let mut empty = RunSnapshot::empty("lineage-run-2", "revision", "semantics");
    empty.slot_candidate_counts.insert("worker".into(), 2);
    let started = reduce(&workflow, &empty, ReducerEvent::Start { input: json!({}) }).unwrap();
    let command = started.emitted_commands[0].clone();
    let failed = reduce(
        &workflow,
        &started.snapshot,
        ReducerEvent::CommandFailed {
            command_id: command.id.clone(),
            attempt_token: command.attempt_token.clone(),
            class: FailureClass::Transient,
            code: "effect_temporarily_unavailable".into(),
        },
    )
    .unwrap();
    let retried = reduce(
        &workflow,
        &failed.snapshot,
        ReducerEvent::RetryRequested {
            command_id: command.id,
        },
    )
    .unwrap();
    let retry_command = retried.emitted_commands[0].clone();
    let exhausted = reduce(
        &workflow,
        &retried.snapshot,
        ReducerEvent::CommandFailed {
            command_id: retry_command.id.clone(),
            attempt_token: retry_command.attempt_token.clone(),
            class: FailureClass::Transient,
            code: "effect_temporarily_unavailable".into(),
        },
    )
    .unwrap();
    assert_eq!(exhausted.snapshot.status, StrategyRunStatus::Running);
    assert!(exhausted.snapshot.active_states.contains("work"));
    assert!(!exhausted.snapshot.state_visits.contains_key("fail"));
    let next = reduce(
        &workflow,
        &exhausted.snapshot,
        ReducerEvent::FallbackIssued {
            failed_command_id: retry_command.id.clone(),
            next_ordinal: 1,
            locator: json!({"locatorUnavailable": true}),
            from_value_id: "agent:primary".into(),
            to_value_id: "agent:fallback".into(),
            reason: "transient-exhausted".into(),
            attempts: 2,
        },
    )
    .unwrap();
    assert_eq!(next.emitted_commands[0].binding_ordinal, 1);
    assert_eq!(
        next.snapshot.commands[&retry_command.id].status,
        CommandStatus::Cancelled
    );
    assert_eq!(next.snapshot.status, StrategyRunStatus::Running);
    assert_eq!(
        next.snapshot
            .attempt_lineage
            .get("work\u{0}1\u{0}worker")
            .copied(),
        Some(3),
        "the lineage must stop exactly at maxAttempts"
    );
}

#[test]
fn authority_and_runtime_failures_are_recoverable_only_with_a_retry_lineage() {
    let recoverable = actor_loop_workflow(WorkflowLimits::default(), 2, 2);
    let started = reduce(
        &recoverable,
        &RunSnapshot::empty("authority-run", "revision", "semantics"),
        ReducerEvent::Start { input: json!({}) },
    )
    .unwrap();
    let command = started.emitted_commands[0].clone();
    let failed = reduce(
        &recoverable,
        &started.snapshot,
        ReducerEvent::CommandFailed {
            command_id: command.id.clone(),
            attempt_token: command.attempt_token,
            class: FailureClass::Authority,
            code: "authorization_required".into(),
        },
    )
    .unwrap();
    assert_eq!(
        failed.snapshot.status,
        StrategyRunStatus::AuthorizationRequired
    );
    assert_eq!(
        failed.snapshot.commands[&command.id].status,
        CommandStatus::Retryable
    );
    let retried = reduce(
        &recoverable,
        &failed.snapshot,
        ReducerEvent::RetryRequested {
            command_id: command.id,
        },
    )
    .unwrap();
    assert_eq!(retried.emitted_commands[0].attempt, 2);

    let exhausted = actor_loop_workflow(WorkflowLimits::default(), 1, 1);
    let started = reduce(
        &exhausted,
        &RunSnapshot::empty("runtime-run", "revision", "semantics"),
        ReducerEvent::Start { input: json!({}) },
    )
    .unwrap();
    let command = started.emitted_commands[0].clone();
    let failed = reduce(
        &exhausted,
        &started.snapshot,
        ReducerEvent::CommandFailed {
            command_id: command.id,
            attempt_token: command.attempt_token,
            class: FailureClass::Runtime,
            code: "runtime_unavailable".into(),
        },
    )
    .unwrap();
    assert_eq!(failed.snapshot.status, StrategyRunStatus::Failed);
    assert!(failed.snapshot.state_visits.contains_key("fail"));
}

#[test]
fn attempt_lineage_resets_for_a_new_state_visit() {
    let workflow = actor_loop_workflow(
        WorkflowLimits {
            max_parallelism: 8,
            max_workset_items: 256,
            max_attempts: 1,
        },
        3,
        3,
    );
    let started = reduce(
        &workflow,
        &RunSnapshot::empty("visit-run", "revision", "semantics"),
        ReducerEvent::Start { input: json!({}) },
    )
    .unwrap();
    let command = started.emitted_commands[0].clone();
    assert_eq!(command.attempt, 1);
    let looped = reduce(
        &workflow,
        &started.snapshot,
        ReducerEvent::CommandSucceeded {
            command_id: command.id.clone(),
            attempt_token: command.attempt_token.clone(),
            output: json!({"context": {"again": true}}),
        },
    )
    .unwrap();
    assert_eq!(looped.snapshot.state_visits["work"], 2);
    assert_eq!(looped.emitted_commands.len(), 1);
    assert_eq!(looped.emitted_commands[0].attempt, 1);
    assert_eq!(looped.emitted_commands[0].state_visit, 2);
    assert_eq!(
        looped
            .snapshot
            .attempt_lineage
            .get("work\u{0}1\u{0}worker")
            .copied(),
        Some(1)
    );
    assert_eq!(
        looped
            .snapshot
            .attempt_lineage
            .get("work\u{0}2\u{0}worker")
            .copied(),
        Some(1)
    );
}

#[test]
fn fallback_ordinal_resets_for_a_new_state_visit() {
    let workflow = actor_loop_workflow(
        WorkflowLimits {
            max_parallelism: 8,
            max_workset_items: 256,
            max_attempts: 3,
        },
        1,
        1,
    );
    let mut empty = RunSnapshot::empty("fallback-visit-run", "revision", "semantics");
    empty.slot_candidate_counts.insert("worker".into(), 2);
    let started = reduce(&workflow, &empty, ReducerEvent::Start { input: json!({}) }).unwrap();
    let primary = started.emitted_commands[0].clone();
    let failed = reduce(
        &workflow,
        &started.snapshot,
        ReducerEvent::CommandFailed {
            command_id: primary.id.clone(),
            attempt_token: primary.attempt_token,
            class: FailureClass::Transient,
            code: "effect_temporarily_unavailable".into(),
        },
    )
    .unwrap();
    let fallback = reduce(
        &workflow,
        &failed.snapshot,
        ReducerEvent::FallbackIssued {
            failed_command_id: primary.id,
            next_ordinal: 1,
            locator: json!({"locatorUnavailable": true}),
            from_value_id: "agent:primary".into(),
            to_value_id: "agent:fallback".into(),
            reason: "transient-exhausted".into(),
            attempts: 1,
        },
    )
    .unwrap();
    let fallback_command = fallback.emitted_commands[0].clone();
    let looped = reduce(
        &workflow,
        &fallback.snapshot,
        ReducerEvent::CommandSucceeded {
            command_id: fallback_command.id,
            attempt_token: fallback_command.attempt_token,
            output: json!({
                "context": {"again": true},
                "nativeSessionId": "fallback-session"
            }),
        },
    )
    .unwrap();
    assert_eq!(looped.snapshot.state_visits["work"], 2);
    assert_eq!(looped.emitted_commands[0].binding_ordinal, 0);
    assert_eq!(looped.emitted_commands[0].resume_session_id, None);
}

fn register_workset_run(
    store: &StrategyStore,
    revision_nonce: u64,
    max_parallelism: u8,
    items: usize,
    idempotency_key: &str,
) -> RunSnapshot {
    let revision = format!("{:064x}", revision_nonce);
    let workflow = workset_workflow(WorkflowLimits {
        max_parallelism,
        max_workset_items: 256,
        max_attempts: 3,
    });
    store
        .register_definition(
            &revision,
            &format!("{:064x}", revision_nonce + 50),
            workflow.definition(),
            1,
            1,
        )
        .unwrap();
    store
        .update_binding(&revision, "worker", "agent:test", "", "", None)
        .unwrap();
    let preview = store.authorization_preview(&revision).unwrap();
    store
        .grant_authorization(&revision, &preview.authorization_digest)
        .unwrap();
    let items_value = Value::Array(
        (0..items)
            .map(|index| json!({"id": format!("item-{index}")}))
            .collect(),
    );
    store
        .start_run(
            &revision,
            json!({"worksets": {"tasks": items_value}}),
            idempotency_key,
            None,
            None,
        )
        .unwrap()
}

#[test]
fn durable_claim_bounds_each_run_and_releases_capacity_in_stable_order() {
    let store = StrategyStore::open_in_memory().unwrap();
    let run = register_workset_run(&store, 1, 2, 4, "claim-limit-run");
    let mut claimed = Vec::new();
    for _ in 0..2 {
        let command = store
            .claim_next_command(&run.run_id, "claimant", now_ms() + 60_000)
            .unwrap()
            .expect("capacity must admit two claims");
        claimed.push(command);
    }
    assert!(
        claimed[0].id < claimed[1].id,
        "claims must be stable-ordered"
    );
    assert!(
        store
            .claim_next_command(&run.run_id, "claimant", now_ms() + 60_000)
            .unwrap()
            .is_none(),
        "run maxParallelism must cap claims"
    );
    store
        .apply_owned_event(
            &run.run_id,
            "claimant",
            ReducerEvent::CommandSucceeded {
                command_id: claimed[0].id.clone(),
                attempt_token: claimed[0].attempt_token.clone(),
                output: json!({}),
            },
        )
        .unwrap();
    let next = store
        .claim_next_command(&run.run_id, "claimant", now_ms() + 60_000)
        .unwrap()
        .expect("released capacity must admit the next stable command");
    assert!(
        next.id > claimed[1].id,
        "the next pending command must be claimable"
    );
    assert!(
        store
            .claim_next_command(&run.run_id, "claimant", now_ms() + 60_000)
            .unwrap()
            .is_none(),
        "capacity must remain capped after the next claim"
    );
}

#[test]
fn durable_claim_never_exceeds_the_engine_ceiling_across_runs() {
    let store = StrategyStore::open_in_memory().unwrap();
    let run_a = register_workset_run(&store, 10, 8, 6, "engine-ceiling-a");
    let run_b = register_workset_run(&store, 11, 8, 6, "engine-ceiling-b");
    let mut claimed = Vec::new();
    for run in [&run_a, &run_b] {
        for _ in 0..4 {
            let command = store
                .claim_next_command(&run.run_id, "claimant", now_ms() + 60_000)
                .unwrap()
                .expect("engine ceiling not yet reached");
            claimed.push(command);
        }
    }
    assert_eq!(claimed.len(), MAX_ACTIVE_EFFECTS);
    assert!(
        store
            .claim_next_command(&run_a.run_id, "claimant", now_ms() + 60_000)
            .unwrap()
            .is_none(),
        "the engine-wide effect ceiling must reject further claims"
    );
    store
        .apply_owned_event(
            &run_a.run_id,
            "claimant",
            ReducerEvent::CommandSucceeded {
                command_id: claimed[0].id.clone(),
                attempt_token: claimed[0].attempt_token.clone(),
                output: json!({}),
            },
        )
        .unwrap();
    let released = store
        .claim_next_command(&run_b.run_id, "claimant", now_ms() + 60_000)
        .unwrap()
        .expect("releasing one effect must admit the next claim");
    assert!(released.id.starts_with("command:"));
}

#[test]
fn a_partially_acknowledged_cancel_stays_in_doubt() {
    let store = StrategyStore::open_in_memory().unwrap();
    let run = register_workset_run(&store, 20, 2, 2, "cancel-in-doubt");
    let first = store
        .claim_next_command(&run.run_id, "claimant", now_ms() + 60_000)
        .unwrap()
        .expect("first claim");
    let second = store
        .claim_next_command(&run.run_id, "claimant", now_ms() + 60_000)
        .unwrap()
        .expect("second claim");
    for command in [&first, &second] {
        store
            .apply_owned_event(
                &run.run_id,
                "claimant",
                ReducerEvent::CommandStarted {
                    command_id: command.id.clone(),
                    attempt_token: command.attempt_token.clone(),
                },
            )
            .unwrap();
    }
    store
        .apply_event(&run.run_id, ReducerEvent::CancelRequested)
        .unwrap();

    // One position's outcome is unknowable; the other acknowledges its cancel.
    store
        .apply_owned_event(
            &run.run_id,
            "claimant",
            ReducerEvent::CancellationUnknown {
                command_id: first.id.clone(),
                attempt_token: first.attempt_token.clone(),
            },
        )
        .unwrap();
    store
        .apply_owned_event(
            &run.run_id,
            "claimant",
            ReducerEvent::CancellationAcknowledged {
                command_id: second.id.clone(),
                attempt_token: second.attempt_token.clone(),
            },
        )
        .unwrap();

    let snapshot = store.run(&run.run_id).unwrap();
    assert_eq!(
        snapshot.commands[&second.id].status,
        CommandStatus::Cancelled
    );
    assert_eq!(snapshot.commands[&first.id].status, CommandStatus::InDoubt);
    assert_eq!(
        snapshot.status,
        StrategyRunStatus::CancelInDoubt,
        "a run with an in-doubt position may never report Cancelled"
    );
}
