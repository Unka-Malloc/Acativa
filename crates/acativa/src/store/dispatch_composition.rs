//! Composition fixtures joining the pure dispatch owner to the durable store.
//!
//! `crate::workflow::dispatch` decides; `StrategyStore` persists and fences. A
//! fixture that exercised only one of them could agree with itself while the
//! two disagreed in production, so every case below drives the real SQLite
//! store through a scenario, reads back the rows the store actually wrote, and
//! then asserts that the pure verdict reached from those rows is the rule the
//! store behaved by.
//!
//! Every fixture is synthetic: an in-memory schema, one actor slot and no
//! runtime, context, document or live agent.

use rusqlite::Connection;
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

use super::StrategyStore;
use crate::workflow::dispatch::{
    ClaimLease, ClaimVerdict, CompletionVerdict, DispatchDecision, DispatchGate, DispatchIntent,
    DispatchRecipient, DispatchRefusal, EffectCompletion, EffectProgress, RecoveryVerdict,
    claim_effect, recover_claim, settle_effect,
};
use crate::{
    ActorSlot, CommandKind, CommandStatus, FailureClass, GraphState, GraphStateKind, ReducerEvent,
    RetryPolicy, StrategyRunStatus, Transition, TransitionEvent, TransitionMode,
    WorkflowDefinition, WorkflowLimits, WorkflowMetadata,
};

const REVISION_GRANT: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const REVISION_HELD: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const REVISION_IN_DOUBT: &str = "3333333333333333333333333333333333333333333333333333333333333333";
const REVISION_COMPLETION: &str =
    "4444444444444444444444444444444444444444444444444444444444444444";
const REVISION_STOP: &str = "5555555555555555555555555555555555555555555555555555555555555555";

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the clock is after the epoch")
        .as_millis() as i64
}

fn workflow() -> WorkflowDefinition {
    WorkflowDefinition {
        schema: crate::GENERIC_WORKFLOW_SCHEMA.into(),
        metadata: WorkflowMetadata {
            id: "dispatch-composition".into(),
            name: "Dispatch composition".into(),
            version: "1".into(),
            description: String::new(),
        },
        limits: WorkflowLimits::default(),
        actor_slots: vec![ActorSlot::required_actor("worker", "Worker")],
        runtimes: vec![],
        worksets: vec![],
        initial: "work".into(),
        states: vec![
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
                    max_attempts: 2,
                    transient_only: true,
                },
            },
            GraphState {
                id: "done".into(),
                kind: GraphStateKind::Succeed,
                label: "Done".into(),
                instruction: String::new(),
                binding: None,
                runtime: None,
                entry: None,
                workset: None,
                retry: RetryPolicy::default(),
            },
            GraphState {
                id: "failed".into(),
                kind: GraphStateKind::Fail,
                label: "Failed".into(),
                instruction: String::new(),
                binding: None,
                runtime: None,
                entry: None,
                workset: None,
                retry: RetryPolicy::default(),
            },
        ],
        // An effect state routes both of its outcomes: an actor effect that
        // fails terminally has to have somewhere to go, which is why the
        // validator requires the failure edge and why
        // `normalize_legacy_workflow` repairs stored definitions that lack it.
        transitions: vec![
            Transition {
                id: "done".into(),
                from: "work".into(),
                to: "done".into(),
                event: TransitionEvent::Success,
                mode: TransitionMode::Flow,
                guard: None,
            },
            Transition {
                id: "failed".into(),
                from: "work".into(),
                to: "failed".into(),
                event: TransitionEvent::Failure,
                mode: TransitionMode::Flow,
                guard: None,
            },
        ],
    }
}

/// One authorized definition with one started run, through the real store.
struct Fixture {
    store: StrategyStore,
    run_id: String,
    /// The authorization the store committed for this revision.
    ///
    /// The granted authorization is the authority a dispatch carries. A preview
    /// taken afterwards projects the *next* authorization revision, so it names
    /// a grant the store never recorded and can never fence an effect.
    authorization_digest: String,
}

impl Fixture {
    fn open(revision: &'static str, idempotency_key: &str) -> Self {
        let store = StrategyStore::open_in_memory().expect("an in-memory strategy store");
        store
            .register_definition(revision, revision, &workflow(), 1, 1)
            .expect("the definition registers");
        store
            .update_binding(revision, "worker", "agent:test", "", "", None)
            .expect("the actor slot binds");
        let preview = store
            .authorization_preview(revision)
            .expect("an authorization preview");
        let authorization = store
            .grant_authorization(revision, &preview.authorization_digest)
            .expect("the revision is authorized");
        let run = store
            .start_run(revision, json!({}), idempotency_key, None, None)
            .expect("the run starts");
        Self {
            store,
            run_id: run.run_id,
            authorization_digest: authorization.authorization_digest,
        }
    }

    fn snapshot(&self) -> crate::RunSnapshot {
        self.store.run(&self.run_id).expect("the run reads back")
    }

    /// The actor effect this run emitted, which is what a dispatch routes.
    fn actor_command(&self) -> crate::RunCommand {
        self.snapshot()
            .commands
            .into_values()
            .find(|command| command.kind == CommandKind::Actor)
            .expect("the actor state emits one actor command")
    }

    fn claim(&self, owner: &str) -> crate::RunCommand {
        self.store
            .claim_next_command(&self.run_id, owner, now_ms() + 600_000)
            .expect("the claim transaction commits")
            .expect("the pending actor command is claimable")
    }

    /// The persisted lease columns, which are the only lease authority.
    fn persisted_lease(&self, command_id: &str) -> (Option<String>, i64, String) {
        let connection = Connection::open(self.store.db_path()).expect("the store file opens");
        connection
            .query_row(
                "SELECT lease_owner, COALESCE(lease_until, 0), status
                   FROM strategy_commands WHERE command_id=?1",
                [command_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("the claimed row exists")
    }

    /// Move the lease clock into the past without touching effect progress, so
    /// the persisted clock is what expires the claim.
    fn expire_lease(&self, command_id: &str) {
        let connection = Connection::open(self.store.db_path()).expect("the store file opens");
        connection
            .execute(
                "UPDATE strategy_commands SET lease_until=0 WHERE command_id=?1",
                [command_id],
            )
            .expect("the lease clock is persisted");
    }

    /// The pure claim the store persisted, read from the store's own columns.
    fn claim_lease(&self, command_id: &str, attempt_token: &str) -> ClaimLease {
        let (owner, lease_until_unix_ms, _) = self.persisted_lease(command_id);
        ClaimLease {
            command_id: command_id.to_owned(),
            attempt_token: attempt_token.to_owned(),
            owner: owner.expect("a claimed row records its owner"),
            lease_until_unix_ms,
        }
    }

    /// The dispatch intent a host would build for this run's actor effect.
    ///
    /// It carries the authority the store committed, which is what this host's
    /// own dispatch path reads back from the definition it authorized under.
    fn actor_intent(&self, command: &crate::RunCommand) -> DispatchIntent {
        DispatchIntent {
            run_id: self.run_id.clone(),
            command_id: command.id.clone(),
            attempt_token: command.attempt_token.clone(),
            kind: command.kind,
            recipient: DispatchRecipient::Actor {
                binding_id: command
                    .binding_id
                    .clone()
                    .expect("an actor command names its binding"),
                runtime_id: command.runtime_id.clone().unwrap_or_default(),
            },
            state_id: command.state_id.clone(),
            state_visit: command.state_visit,
            input_digest: command.input_digest.clone(),
            grant_digest: Some(self.authorization_digest.clone()),
        }
    }
}

#[test]
fn the_dispatch_gate_admits_exactly_the_authority_the_store_committed() {
    let fixture = Fixture::open(REVISION_GRANT, "dispatch-gate");
    let command = fixture.actor_command();
    let intent = fixture.actor_intent(&command);
    assert!(
        intent.routing_matches_kind(),
        "an actor effect routes to an actor recipient"
    );

    let committed = DispatchGate {
        committed_grant_digest: intent.grant_digest.clone(),
        ..DispatchGate::default()
    };
    assert_eq!(committed.evaluate(&intent), DispatchDecision::Dispatch);
    let committed_grant = intent
        .grant_digest
        .clone()
        .expect("the intent carries the committed digest");

    // A gate that observed no committed authority refuses the same intent, and
    // the store agrees: it issues no effect permit for a digest it never
    // recorded.
    assert_eq!(
        DispatchGate::default().evaluate(&intent),
        DispatchDecision::Refuse(DispatchRefusal::AuthorityMissing)
    );
    let claimed = fixture.claim("first-owner");
    fixture
        .store
        .apply_owned_event(
            &fixture.run_id,
            "first-owner",
            ReducerEvent::CommandStarted {
                command_id: claimed.id.clone(),
                attempt_token: claimed.attempt_token.clone(),
            },
        )
        .expect("the effect starts");
    assert!(
        fixture
            .store
            .authorize_effect(
                &fixture.run_id,
                &claimed.id,
                &claimed.attempt_token,
                "0000000000000000000000000000000000000000000000000000000000000000",
                "first-owner",
                now_ms() + 600_000,
            )
            .is_err(),
        "the store refuses an effect permit for authority it never committed"
    );
    // The committed digest is the one that permits the effect.
    fixture
        .store
        .authorize_effect(
            &fixture.run_id,
            &claimed.id,
            &claimed.attempt_token,
            &committed_grant,
            "first-owner",
            now_ms() + 600_000,
        )
        .expect("the committed authority permits the effect");
}

#[test]
fn an_unexpired_claim_is_held_whoever_owned_it_and_whatever_happened_to_its_process() {
    let fixture = Fixture::open(REVISION_HELD, "held-claim");
    let claimed = fixture.claim("first-owner");
    assert_eq!(fixture.persisted_lease(&claimed.id).2, "claimed");

    let lease = fixture.claim_lease(&claimed.id, &claimed.attempt_token);
    assert!(lease.is_unexpired_at(now_ms()));
    assert!(
        matches!(
            recover_claim(&lease, EffectProgress::NeverStarted, now_ms()),
            RecoveryVerdict::Held { .. }
        ),
        "an unexpired claim stays held; process exit is not an input"
    );

    // A second owner may not take an unexpired claim, and the store retries
    // nothing while the claim it recorded is still valid.
    assert!(matches!(
        claim_effect(
            &fixture.actor_intent(&claimed),
            Some(&lease),
            EffectProgress::NeverStarted,
            "second-owner",
            now_ms(),
            now_ms() + 60_000,
        ),
        ClaimVerdict::Held { .. }
    ));
    assert!(
        !fixture
            .store
            .recover_next_expired_command(&fixture.run_id)
            .expect("recovery reads the lease clock")
    );
    let held = fixture.snapshot();
    assert_eq!(held.commands[&claimed.id].status, CommandStatus::Claimed);
    assert_eq!(held.commands[&claimed.id].attempt, claimed.attempt);
    assert!(
        !held
            .commands
            .values()
            .any(|command| command.attempt > claimed.attempt),
        "an unexpired claim is never repeated"
    );
}

#[test]
fn an_expired_in_flight_claim_stays_in_doubt_and_is_never_repeated() {
    let fixture = Fixture::open(REVISION_IN_DOUBT, "in-doubt-claim");
    let claimed = fixture.claim("first-owner");
    fixture
        .store
        .apply_owned_event(
            &fixture.run_id,
            "first-owner",
            ReducerEvent::CommandStarted {
                command_id: claimed.id.clone(),
                attempt_token: claimed.attempt_token.clone(),
            },
        )
        .expect("the effect starts");
    fixture.expire_lease(&claimed.id);
    assert_eq!(fixture.persisted_lease(&claimed.id).2, "running");
    assert_eq!(
        fixture.persisted_lease(&claimed.id).1,
        0,
        "the persisted clock, not the process, is what expired"
    );

    let lease = fixture.claim_lease(&claimed.id, &claimed.attempt_token);
    match recover_claim(&lease, EffectProgress::InFlight, now_ms()) {
        RecoveryVerdict::InDoubt { class, code, .. } => {
            assert_eq!(class, FailureClass::InDoubt);
            assert_eq!(code, "effect_outcome_unknown");
        }
        other => panic!("an expired in-flight claim must stay in doubt, got {other:?}"),
    }

    // The store applies the same rule: the attempt is recorded in doubt and no
    // second attempt is created for an effect that may already have left.
    assert!(
        fixture
            .store
            .recover_next_expired_command(&fixture.run_id)
            .expect("recovery reads the lease clock")
    );
    let recovered = fixture.snapshot();
    assert_eq!(
        recovered.commands[&claimed.id].status,
        CommandStatus::InDoubt
    );
    assert_eq!(
        recovered.commands[&claimed.id].failure_code.as_deref(),
        Some("effect_outcome_unknown")
    );
    assert_eq!(recovered.status, StrategyRunStatus::CancelInDoubt);
    assert!(
        !recovered
            .commands
            .values()
            .any(|command| command.attempt > claimed.attempt),
        "an in-doubt effect is never blindly repeated"
    );
}

#[test]
fn a_foreign_or_repeated_owner_result_cannot_settle_the_attempt() {
    let fixture = Fixture::open(REVISION_COMPLETION, "completion-owner");
    let claimed = fixture.claim("first-owner");
    fixture
        .store
        .apply_owned_event(
            &fixture.run_id,
            "first-owner",
            ReducerEvent::CommandStarted {
                command_id: claimed.id.clone(),
                attempt_token: claimed.attempt_token.clone(),
            },
        )
        .expect("the effect starts");
    let lease = fixture.claim_lease(&claimed.id, &claimed.attempt_token);

    // A result carrying a foreign attempt token is refused by the store and
    // rejected by the pure owner, which is the same verdict from the same row.
    assert!(
        fixture
            .store
            .apply_owned_event(
                &fixture.run_id,
                "first-owner",
                ReducerEvent::CommandSucceeded {
                    command_id: claimed.id.clone(),
                    attempt_token: "attempt:someone-else".into(),
                    output: json!({ "ok": true }),
                },
            )
            .is_err(),
        "a stale token cannot settle an attempt even for the recorded owner"
    );
    // And a caller that is not the lease owner is refused outright, valid
    // token or not — settlement proves ownership, not just token knowledge.
    assert!(
        fixture
            .store
            .apply_owned_event(
                &fixture.run_id,
                "someone-else",
                ReducerEvent::CommandSucceeded {
                    command_id: claimed.id.clone(),
                    attempt_token: claimed.attempt_token.clone(),
                    output: json!({ "ok": true }),
                },
            )
            .is_err(),
        "a foreign claimant cannot settle the owner's attempt"
    );
    assert!(
        fixture
            .store
            .apply_event(
                &fixture.run_id,
                ReducerEvent::CommandSucceeded {
                    command_id: claimed.id.clone(),
                    attempt_token: claimed.attempt_token.clone(),
                    output: json!({ "ok": true }),
                },
            )
            .is_err(),
        "an unauthenticated caller cannot settle a leased attempt"
    );
    let foreign = EffectCompletion {
        command_id: claimed.id.clone(),
        attempt_token: "attempt:someone-else".into(),
        owner: "first-owner".into(),
        output_digest: "digest:foreign".into(),
    };
    assert_eq!(
        settle_effect(&lease, EffectProgress::InFlight, None, &foreign),
        CompletionVerdict::RejectedStaleOwner
    );

    // The recorded owner settles once.
    fixture
        .store
        .apply_owned_event(
            &fixture.run_id,
            "first-owner",
            ReducerEvent::CommandSucceeded {
                command_id: claimed.id.clone(),
                attempt_token: claimed.attempt_token.clone(),
                output: json!({ "ok": true }),
            },
        )
        .expect("the recorded owner settles its attempt");
    let settled = fixture.snapshot();
    assert_eq!(
        settled.commands[&claimed.id].status,
        CommandStatus::Succeeded
    );
    let digest = settled.commands[&claimed.id]
        .output_digest
        .clone()
        .expect("a settled attempt records its output digest");

    let accepted = EffectCompletion {
        command_id: claimed.id.clone(),
        attempt_token: claimed.attempt_token.clone(),
        owner: "first-owner".into(),
        output_digest: digest.clone(),
    };
    assert_eq!(
        settle_effect(&lease, EffectProgress::Settled, Some(&digest), &accepted),
        CompletionVerdict::Duplicate,
        "the same owner reporting the same result settles nothing twice"
    );
    let conflicting = EffectCompletion {
        output_digest: "digest:different".into(),
        ..accepted
    };
    assert_eq!(
        settle_effect(&lease, EffectProgress::Settled, Some(&digest), &conflicting),
        CompletionVerdict::RejectedConflict
    );

    // Re-reporting at the store leaves the settled attempt exactly as it was.
    let _ = fixture.store.apply_owned_event(
        &fixture.run_id,
        "first-owner",
        ReducerEvent::CommandSucceeded {
            command_id: claimed.id.clone(),
            attempt_token: claimed.attempt_token.clone(),
            output: json!({ "ok": true }),
        },
    );
    let after = fixture.snapshot();
    assert_eq!(
        after.commands[&claimed.id].output_digest.as_deref(),
        Some(digest.as_str())
    );
    assert_eq!(after.commands[&claimed.id].attempt, claimed.attempt);
}

#[test]
fn a_stop_refuses_new_dispatch_and_leaves_the_in_flight_attempt_unresolved() {
    let fixture = Fixture::open(REVISION_STOP, "stopped-claim");
    let claimed = fixture.claim("first-owner");
    fixture
        .store
        .apply_owned_event(
            &fixture.run_id,
            "first-owner",
            ReducerEvent::CommandStarted {
                command_id: claimed.id.clone(),
                attempt_token: claimed.attempt_token.clone(),
            },
        )
        .expect("the effect starts");
    fixture
        .store
        .apply_event(&fixture.run_id, ReducerEvent::CancelRequested)
        .expect("the stop request is durable");

    let intent = fixture.actor_intent(&claimed);
    let stopped = DispatchGate {
        committed_grant_digest: intent.grant_digest.clone(),
        stop_requested: true,
        ..DispatchGate::default()
    };
    assert_eq!(
        stopped.evaluate(&intent),
        DispatchDecision::Refuse(DispatchRefusal::StopRequested)
    );

    // The store agrees on the same run: a stop prevents new dispatch.
    assert!(
        fixture
            .store
            .claim_next_command(&fixture.run_id, "second-owner", now_ms() + 600_000)
            .expect("the claim transaction commits")
            .is_none(),
        "a stopped run hands out no further effect"
    );

    // The request itself is not an observation: the in-flight claim keeps its
    // own status and is not reported as settled or rolled back.
    let after = fixture.snapshot();
    assert_eq!(
        after.commands[&claimed.id].status,
        CommandStatus::CancelRequested
    );
    assert_eq!(after.status, StrategyRunStatus::CancelRequested);
    assert!(after.commands[&claimed.id].output_digest.is_none());
    assert!(after.commands[&claimed.id].failure_code.is_none());
}
