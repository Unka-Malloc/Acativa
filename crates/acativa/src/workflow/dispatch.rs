//! Pure durable-dispatch decisions for the strategy engine.
//!
//! Dispatch is the boundary between durable intent and an external effect. The
//! store commits authority and the dispatch intent first; only then may an
//! adapter leave the host. This module owns the *decisions* taken at that
//! boundary so every host reaches the same verdict from the same durable facts,
//! without SQLite, a clock of its own, or a process identity.
//!
//! # What this module refuses to know
//!
//! A previous host process disappearing is **not** an input to any decision
//! here. There is deliberately no `host_restarted`, `process_exited` or
//! `previous_pid` field anywhere in this module, because process exit alone is
//! not lease revocation, not effect loss, and not authority to repeat an
//! external effect. Recovery is decided only from the persisted lease clock and
//! the persisted effect progress:
//!
//! * an **unexpired** claim is [`RecoveryVerdict::Held`] — the claimant still
//!   owns it, whoever that claimant was and whatever happened to its process;
//! * an **expired** claim whose effect never started is
//!   [`RecoveryVerdict::Reclaimable`];
//! * an **expired** claim whose effect was already in flight is
//!   [`RecoveryVerdict::InDoubt`] and is never blindly repeated;
//! * a **settled** claim is [`RecoveryVerdict::AlreadyCompleted`].

use serde::{Deserialize, Serialize};

use crate::FailureClass;
use crate::machine::CommandKind;

/// Who performs one dispatched effect. The recipient is frozen into the
/// dispatch intent so routing cannot drift between admission and execution.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "recipient", rename_all = "camelCase")]
pub enum DispatchRecipient {
    /// Authority itself is the effect: the grant is committed before any actor
    /// may run, so the authorization command has no external destination.
    Authorization { semantics_digest: String },
    /// A bound actor turn through one runtime slot.
    Actor {
        binding_id: String,
        runtime_id: String,
    },
    /// A named script entry through one runtime slot.
    Script { runtime_id: String, entry: String },
    /// One item of a workset template.
    WorksetItem {
        item_id: String,
        binding_ordinal: u8,
    },
}

impl DispatchRecipient {
    /// The [`CommandKind`] this recipient is only ever routed for.
    pub const fn command_kind(&self) -> CommandKind {
        match self {
            Self::Authorization { .. } => CommandKind::Authorization,
            Self::Actor { .. } => CommandKind::Actor,
            Self::Script { .. } => CommandKind::Script,
            Self::WorksetItem { .. } => CommandKind::WorksetItem,
        }
    }

    /// The stable routing key: kind plus destination. Two intents with the same
    /// key are the same delivery target and must serialize on one claim.
    pub fn routing_key(&self) -> String {
        match self {
            Self::Authorization { semantics_digest } => {
                format!("authorization\u{0}{semantics_digest}")
            }
            Self::Actor {
                binding_id,
                runtime_id,
            } => format!("actor\u{0}{binding_id}\u{0}{runtime_id}"),
            Self::Script { runtime_id, entry } => format!("script\u{0}{runtime_id}\u{0}{entry}"),
            Self::WorksetItem {
                item_id,
                binding_ordinal,
            } => format!("workset-item\u{0}{item_id}\u{0}{binding_ordinal}"),
        }
    }
}

/// The durable record committed before an effect leaves the host.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DispatchIntent {
    pub run_id: String,
    pub command_id: String,
    pub attempt_token: String,
    pub kind: CommandKind,
    pub recipient: DispatchRecipient,
    pub state_id: String,
    pub state_visit: u64,
    pub input_digest: String,
    /// Digest of the committed authority this dispatch runs under. `None` means
    /// no authority has been committed, which refuses the dispatch rather than
    /// letting an adapter find out later.
    pub grant_digest: Option<String>,
}

impl DispatchIntent {
    /// A dispatch intent may only be committed when its kind and recipient
    /// agree. This is the kind+recipient routing invariant, checked once here
    /// instead of at each adapter.
    pub fn routing_matches_kind(&self) -> bool {
        self.recipient.command_kind() == self.kind
    }

    /// Identity of one exact effect attempt. A completion that does not carry
    /// this exact identity is a late or duplicated owner result.
    pub fn attempt_identity(&self) -> String {
        format!("{}\u{0}{}", self.command_id, self.attempt_token)
    }
}

/// Why a dispatch was refused before any effect was attempted.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DispatchRefusal {
    /// The intent's kind and recipient disagree.
    Misrouted,
    /// No authority digest was committed for this dispatch.
    AuthorityMissing,
    /// A stop covers this target, so no new effect may start.
    StopRequested,
    /// The graph is deliberately held.
    BarrierActive,
    /// The intent belongs to a superseded state visit.
    Superseded,
    /// This exact attempt already settled.
    AlreadySettled,
}

/// The durable facts a dispatch gate reads. All of them are persisted before
/// the decision is taken.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DispatchGate {
    /// Authority digest currently committed for the run.
    pub committed_grant_digest: Option<String>,
    /// True while a stop covers the graph, this node, or this invocation.
    pub stop_requested: bool,
    /// True while the graph is deliberately held.
    pub barrier_active: bool,
    /// The current state visit for `state_id`, when the run has one.
    pub current_state_visit: Option<u64>,
    /// Attempt identities that already settled.
    pub settled_attempts: Vec<String>,
}

/// The verdict of the dispatch gate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "decision", rename_all = "kebab-case")]
pub enum DispatchDecision {
    /// Authority is committed and the target is free; the effect may start.
    Dispatch,
    /// The effect must not start, with the durable reason.
    Refuse(DispatchRefusal),
}

impl DispatchDecision {
    pub fn is_dispatch(&self) -> bool {
        matches!(self, Self::Dispatch)
    }

    pub fn refusal(&self) -> Option<DispatchRefusal> {
        match self {
            Self::Refuse(reason) => Some(*reason),
            Self::Dispatch => None,
        }
    }
}

impl DispatchGate {
    /// Decide whether one dispatch intent may leave the host.
    ///
    /// Routing agreement is checked first because a misrouted intent can never
    /// be made safe by later facts; authority, stop, barrier and state-visit
    /// fencing follow in a fixed order so the reported refusal is deterministic.
    pub fn evaluate(&self, intent: &DispatchIntent) -> DispatchDecision {
        if !intent.routing_matches_kind() {
            return DispatchDecision::Refuse(DispatchRefusal::Misrouted);
        }
        if self.settled_attempts.contains(&intent.attempt_identity()) {
            return DispatchDecision::Refuse(DispatchRefusal::AlreadySettled);
        }
        match (&intent.grant_digest, &self.committed_grant_digest) {
            (Some(required), Some(committed)) if required == committed => {}
            _ => return DispatchDecision::Refuse(DispatchRefusal::AuthorityMissing),
        }
        if self.stop_requested {
            return DispatchDecision::Refuse(DispatchRefusal::StopRequested);
        }
        if self.barrier_active {
            return DispatchDecision::Refuse(DispatchRefusal::BarrierActive);
        }
        if let Some(current) = self.current_state_visit
            && intent.state_visit != current
        {
            return DispatchDecision::Refuse(DispatchRefusal::Superseded);
        }
        DispatchDecision::Dispatch
    }
}

/// One exact effect claim.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaimLease {
    pub command_id: String,
    pub attempt_token: String,
    pub owner: String,
    pub lease_until_unix_ms: i64,
}

impl ClaimLease {
    pub fn attempt_identity(&self) -> String {
        format!("{}\u{0}{}", self.command_id, self.attempt_token)
    }

    pub fn is_unexpired_at(&self, now_unix_ms: i64) -> bool {
        self.lease_until_unix_ms > now_unix_ms
    }
}

/// How far the effect behind a claim actually got. This is persisted by the
/// adapter at its own safe boundary; it is the only progress authority.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EffectProgress {
    /// The claim was taken but the adapter has not begun the effect.
    NeverStarted,
    /// The adapter began the effect and has not reported settlement.
    InFlight,
    /// The effect reached its own safe boundary and was recorded.
    Settled,
}

/// The outcome of trying to take one effect claim.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "claim", rename_all = "camelCase")]
pub enum ClaimVerdict {
    /// This caller now owns the exact effect attempt.
    Granted { lease: ClaimLease },
    /// Another owner holds an unexpired claim. The caller must not dispatch.
    Held {
        owner: String,
        lease_until_unix_ms: i64,
    },
    /// An expired claim never started, so this attempt may be re-dispatched.
    Reclaimable { previous_owner: String },
    /// An expired claim was in flight; the outcome is unknown and must not be
    /// repeated by this caller.
    InDoubt { previous_owner: String },
    /// The attempt already settled; no second effect is permitted.
    AlreadySettled,
    /// The attempt identity belongs to a different command or token.
    IdentityConflict,
}

/// Take the claim for one dispatch intent, or report why it cannot be taken.
///
/// The only clock input is the persisted lease expiry. No argument describes
/// the previous host process, so an unexpired claim held by a dead process is
/// still [`ClaimVerdict::Held`].
pub fn claim_effect(
    intent: &DispatchIntent,
    existing: Option<&ClaimLease>,
    progress: EffectProgress,
    owner: &str,
    now_unix_ms: i64,
    lease_until_unix_ms: i64,
) -> ClaimVerdict {
    if lease_until_unix_ms <= now_unix_ms {
        // A lease that expires at or before its own acquisition cannot fence
        // anything, so it is refused before any state changes.
        return ClaimVerdict::IdentityConflict;
    }
    match existing {
        None => {
            if progress == EffectProgress::Settled {
                return ClaimVerdict::AlreadySettled;
            }
            ClaimVerdict::Granted {
                lease: ClaimLease {
                    command_id: intent.command_id.clone(),
                    attempt_token: intent.attempt_token.clone(),
                    owner: owner.to_owned(),
                    lease_until_unix_ms,
                },
            }
        }
        Some(lease) => {
            if lease.attempt_identity() != intent.attempt_identity() {
                return ClaimVerdict::IdentityConflict;
            }
            if progress == EffectProgress::Settled {
                return ClaimVerdict::AlreadySettled;
            }
            if lease.is_unexpired_at(now_unix_ms) {
                return ClaimVerdict::Held {
                    owner: lease.owner.clone(),
                    lease_until_unix_ms: lease.lease_until_unix_ms,
                };
            }
            match progress {
                EffectProgress::NeverStarted => ClaimVerdict::Reclaimable {
                    previous_owner: lease.owner.clone(),
                },
                EffectProgress::InFlight => ClaimVerdict::InDoubt {
                    previous_owner: lease.owner.clone(),
                },
                EffectProgress::Settled => ClaimVerdict::AlreadySettled,
            }
        }
    }
}

/// What a recovering host may conclude about one persisted claim.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "recovery", rename_all = "camelCase")]
pub enum RecoveryVerdict {
    /// The lease is still valid. It stays exactly as persisted, including a
    /// claim whose owning process is gone.
    Held {
        owner: String,
        lease_until_unix_ms: i64,
    },
    /// The lease expired before the effect started; the attempt may be
    /// re-dispatched against the same attempt identity.
    Reclaimable { previous_owner: String },
    /// The lease expired while the effect was in flight. The outcome is
    /// unknown and stays owned by the previous owner until it is resolved.
    InDoubt {
        previous_owner: String,
        class: FailureClass,
        code: &'static str,
    },
    /// The effect already settled.
    AlreadyCompleted,
}

/// Recover one persisted claim from its lease clock and effect progress.
///
/// This is the whole recovery authority. It takes no process-exit input by
/// construction, so no host may convert "my predecessor exited" into a
/// repeated external effect.
pub fn recover_claim(
    lease: &ClaimLease,
    progress: EffectProgress,
    now_unix_ms: i64,
) -> RecoveryVerdict {
    if progress == EffectProgress::Settled {
        return RecoveryVerdict::AlreadyCompleted;
    }
    if lease.is_unexpired_at(now_unix_ms) {
        return RecoveryVerdict::Held {
            owner: lease.owner.clone(),
            lease_until_unix_ms: lease.lease_until_unix_ms,
        };
    }
    match progress {
        EffectProgress::NeverStarted => RecoveryVerdict::Reclaimable {
            previous_owner: lease.owner.clone(),
        },
        EffectProgress::InFlight => RecoveryVerdict::InDoubt {
            previous_owner: lease.owner.clone(),
            class: FailureClass::InDoubt,
            code: "effect_outcome_unknown",
        },
        EffectProgress::Settled => RecoveryVerdict::AlreadyCompleted,
    }
}

/// A completion reported by an owner of one exact effect attempt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EffectCompletion {
    pub command_id: String,
    pub attempt_token: String,
    pub owner: String,
    pub output_digest: String,
}

/// The verdict on one reported completion.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "completion", rename_all = "kebab-case")]
pub enum CompletionVerdict {
    /// The one owner of this attempt settled it; successors may be admitted.
    Accepted,
    /// The same owner re-reported the same result. It is recorded once and
    /// releases no successor a second time.
    Duplicate,
    /// A different owner, or a stale attempt token, reported a result. The
    /// result is not applied and no effect or successor is released.
    RejectedStaleOwner,
    /// The attempt settled with a different result than the one reported.
    RejectedConflict,
}

/// Decide one reported completion against the exact claim that owns it.
///
/// Duplicate completions and late owner results therefore cannot duplicate
/// effects or release invalid successors: only the first matching completion is
/// [`CompletionVerdict::Accepted`], and every other report is inert.
pub fn settle_effect(
    lease: &ClaimLease,
    progress: EffectProgress,
    recorded_output_digest: Option<&str>,
    completion: &EffectCompletion,
) -> CompletionVerdict {
    if lease.command_id != completion.command_id || lease.attempt_token != completion.attempt_token
    {
        return CompletionVerdict::RejectedStaleOwner;
    }
    if lease.owner != completion.owner {
        return CompletionVerdict::RejectedStaleOwner;
    }
    if progress == EffectProgress::Settled {
        return match recorded_output_digest {
            Some(recorded) if recorded == completion.output_digest => CompletionVerdict::Duplicate,
            _ => CompletionVerdict::RejectedConflict,
        };
    }
    CompletionVerdict::Accepted
}

/// One successor edge whose target may be released by a settled effect.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SuccessorEdge {
    pub from_state_id: String,
    pub from_state_visit: u64,
    pub to_state_id: String,
}

/// Why a successor release was refused.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SuccessorRefusal {
    /// A barrier holds the graph, so no successor may start yet.
    BarrierActive,
    /// A stop covers the graph, so no successor may start.
    StopRequested,
    /// The settling effect belongs to a superseded state visit.
    Superseded,
    /// The settling attempt is not the admitted attempt for this edge.
    NotAdmitted,
}

/// The verdict on releasing the successors of one settled effect.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "admission", rename_all = "kebab-case")]
pub enum SuccessorAdmission {
    /// Exactly these successors may now be admitted.
    Admitted { successors: Vec<SuccessorEdge> },
    /// No successor is released, with the durable reason.
    Refused(SuccessorRefusal),
}

impl SuccessorAdmission {
    pub fn is_admitted(&self) -> bool {
        matches!(self, Self::Admitted { .. })
    }

    pub fn admitted_successors(&self) -> &[SuccessorEdge] {
        match self {
            Self::Admitted { successors } => successors,
            Self::Refused(_) => &[],
        }
    }
}

/// The durable facts fencing one successor release.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SuccessorGate {
    pub barrier_active: bool,
    pub stop_requested: bool,
    /// The current visit of the state the effect settled in.
    pub current_state_visit: Option<u64>,
    /// Attempt identities admitted to release successors.
    pub admitted_attempts: Vec<String>,
}

impl SuccessorGate {
    /// Release the successors of one settled effect.
    ///
    /// An exhausted set of edges admits nothing rather than reporting a
    /// refusal, because a terminal effect legitimately has no successor.
    pub fn release(
        &self,
        lease: &ClaimLease,
        edges: &[SuccessorEdge],
        from_state_id: &str,
        from_state_visit: u64,
    ) -> SuccessorAdmission {
        if !self.admitted_attempts.contains(&lease.attempt_identity()) {
            return SuccessorAdmission::Refused(SuccessorRefusal::NotAdmitted);
        }
        if self.stop_requested {
            return SuccessorAdmission::Refused(SuccessorRefusal::StopRequested);
        }
        if self.barrier_active {
            return SuccessorAdmission::Refused(SuccessorRefusal::BarrierActive);
        }
        if let Some(current) = self.current_state_visit
            && current != from_state_visit
        {
            return SuccessorAdmission::Refused(SuccessorRefusal::Superseded);
        }
        SuccessorAdmission::Admitted {
            successors: edges
                .iter()
                .filter(|edge| {
                    edge.from_state_id == from_state_id && edge.from_state_visit == from_state_visit
                })
                .cloned()
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn intent(visit: u64, grant: Option<&str>) -> DispatchIntent {
        DispatchIntent {
            run_id: "run-1".into(),
            command_id: "command-1".into(),
            attempt_token: "attempt-1".into(),
            kind: CommandKind::Actor,
            recipient: DispatchRecipient::Actor {
                binding_id: "binding-1".into(),
                runtime_id: "runtime-1".into(),
            },
            state_id: "state-1".into(),
            state_visit: visit,
            input_digest: "digest-input".into(),
            grant_digest: grant.map(str::to_owned),
        }
    }

    fn lease(owner: &str, until: i64) -> ClaimLease {
        ClaimLease {
            command_id: "command-1".into(),
            attempt_token: "attempt-1".into(),
            owner: owner.into(),
            lease_until_unix_ms: until,
        }
    }

    fn completion(owner: &str, digest: &str) -> EffectCompletion {
        EffectCompletion {
            command_id: "command-1".into(),
            attempt_token: "attempt-1".into(),
            owner: owner.into(),
            output_digest: digest.into(),
        }
    }

    fn edge(visit: u64) -> SuccessorEdge {
        SuccessorEdge {
            from_state_id: "state-1".into(),
            from_state_visit: visit,
            to_state_id: "state-2".into(),
        }
    }

    #[test]
    fn dispatch_requires_committed_authority_before_the_effect() {
        let gate = DispatchGate::default();
        assert_eq!(
            gate.evaluate(&intent(1, None)).refusal(),
            Some(DispatchRefusal::AuthorityMissing)
        );
        assert_eq!(
            gate.evaluate(&intent(1, Some("grant-1"))).refusal(),
            Some(DispatchRefusal::AuthorityMissing)
        );

        let committed = DispatchGate {
            committed_grant_digest: Some("grant-1".into()),
            ..DispatchGate::default()
        };
        assert!(
            committed
                .evaluate(&intent(1, Some("grant-1")))
                .is_dispatch()
        );
        assert_eq!(
            committed.evaluate(&intent(1, Some("grant-2"))).refusal(),
            Some(DispatchRefusal::AuthorityMissing)
        );
    }

    #[test]
    fn dispatch_refuses_misrouted_kind_and_recipient_pairs() {
        let mut misrouted = intent(1, Some("grant-1"));
        misrouted.kind = CommandKind::Script;
        let gate = DispatchGate {
            committed_grant_digest: Some("grant-1".into()),
            ..DispatchGate::default()
        };
        assert_eq!(
            gate.evaluate(&misrouted).refusal(),
            Some(DispatchRefusal::Misrouted)
        );
    }

    #[test]
    fn stop_and_barrier_each_refuse_new_dispatch() {
        let base = DispatchGate {
            committed_grant_digest: Some("grant-1".into()),
            ..DispatchGate::default()
        };
        let stopped = DispatchGate {
            stop_requested: true,
            ..base.clone()
        };
        assert_eq!(
            stopped.evaluate(&intent(1, Some("grant-1"))).refusal(),
            Some(DispatchRefusal::StopRequested)
        );
        let held = DispatchGate {
            barrier_active: true,
            ..base.clone()
        };
        assert_eq!(
            held.evaluate(&intent(1, Some("grant-1"))).refusal(),
            Some(DispatchRefusal::BarrierActive)
        );
        let superseded = DispatchGate {
            current_state_visit: Some(2),
            ..base
        };
        assert_eq!(
            superseded.evaluate(&intent(1, Some("grant-1"))).refusal(),
            Some(DispatchRefusal::Superseded)
        );
    }

    #[test]
    fn granted_claim_is_exclusive_and_a_second_owner_is_held() {
        let request = intent(1, Some("grant-1"));
        let first = claim_effect(
            &request,
            None,
            EffectProgress::NeverStarted,
            "owner-a",
            1_000,
            2_000,
        );
        let ClaimVerdict::Granted { lease: held } = first else {
            panic!("first claim must be granted");
        };
        assert_eq!(held.owner, "owner-a");

        let second = claim_effect(
            &request,
            Some(&held),
            EffectProgress::NeverStarted,
            "owner-b",
            1_500,
            2_500,
        );
        assert_eq!(
            second,
            ClaimVerdict::Held {
                owner: "owner-a".into(),
                lease_until_unix_ms: 2_000,
            }
        );
    }

    #[test]
    fn an_unexpired_claim_survives_its_owner_process_exiting() {
        // Recovery is a function of the lease clock and the recorded progress
        // only. There is no argument that could carry "the previous process
        // exited", so a live lease cannot be revoked by a restart.
        let held = lease("owner-a", 2_000);
        assert_eq!(
            recover_claim(&held, EffectProgress::NeverStarted, 1_500),
            RecoveryVerdict::Held {
                owner: "owner-a".into(),
                lease_until_unix_ms: 2_000,
            }
        );
        assert_eq!(
            recover_claim(&held, EffectProgress::InFlight, 1_500),
            RecoveryVerdict::Held {
                owner: "owner-a".into(),
                lease_until_unix_ms: 2_000,
            }
        );
    }

    #[test]
    fn expired_claims_separate_never_started_from_in_flight() {
        let expired = lease("owner-a", 1_000);
        assert_eq!(
            recover_claim(&expired, EffectProgress::NeverStarted, 1_000),
            RecoveryVerdict::Reclaimable {
                previous_owner: "owner-a".into(),
            }
        );
        assert_eq!(
            recover_claim(&expired, EffectProgress::InFlight, 5_000),
            RecoveryVerdict::InDoubt {
                previous_owner: "owner-a".into(),
                class: FailureClass::InDoubt,
                code: "effect_outcome_unknown",
            }
        );
        assert_eq!(
            recover_claim(&expired, EffectProgress::Settled, 5_000),
            RecoveryVerdict::AlreadyCompleted
        );
    }

    #[test]
    fn an_expired_in_flight_claim_is_never_reclaimed_by_another_owner() {
        let expired = lease("owner-a", 1_000);
        assert_eq!(
            claim_effect(
                &intent(1, Some("grant-1")),
                Some(&expired),
                EffectProgress::InFlight,
                "owner-b",
                5_000,
                6_000,
            ),
            ClaimVerdict::InDoubt {
                previous_owner: "owner-a".into(),
            }
        );
    }

    #[test]
    fn an_attempt_with_a_foreign_token_or_command_is_an_identity_conflict() {
        let mut request = intent(1, Some("grant-1"));
        request.attempt_token = "attempt-2".into();
        assert_eq!(
            claim_effect(
                &request,
                Some(&lease("owner-a", 2_000)),
                EffectProgress::NeverStarted,
                "owner-b",
                1_000,
                3_000,
            ),
            ClaimVerdict::IdentityConflict
        );
        assert_eq!(
            claim_effect(
                &intent(1, Some("grant-1")),
                None,
                EffectProgress::NeverStarted,
                "owner-b",
                1_000,
                1_000,
            ),
            ClaimVerdict::IdentityConflict
        );
    }

    #[test]
    fn a_settled_attempt_cannot_be_claimed_again() {
        let request = intent(1, Some("grant-1"));
        assert_eq!(
            claim_effect(
                &request,
                Some(&lease("owner-a", 1_000)),
                EffectProgress::Settled,
                "owner-b",
                5_000,
                6_000,
            ),
            ClaimVerdict::AlreadySettled
        );
        assert_eq!(
            claim_effect(
                &request,
                None,
                EffectProgress::Settled,
                "owner-b",
                5_000,
                6_000,
            ),
            ClaimVerdict::AlreadySettled
        );
    }

    #[test]
    fn duplicate_completions_are_inert_and_late_owners_are_rejected() {
        let held = lease("owner-a", 2_000);
        assert_eq!(
            settle_effect(
                &held,
                EffectProgress::InFlight,
                None,
                &completion("owner-a", "output-1")
            ),
            CompletionVerdict::Accepted
        );
        assert_eq!(
            settle_effect(
                &held,
                EffectProgress::Settled,
                Some("output-1"),
                &completion("owner-a", "output-1")
            ),
            CompletionVerdict::Duplicate
        );
        assert_eq!(
            settle_effect(
                &held,
                EffectProgress::Settled,
                Some("output-1"),
                &completion("owner-a", "output-2")
            ),
            CompletionVerdict::RejectedConflict
        );
        assert_eq!(
            settle_effect(
                &held,
                EffectProgress::InFlight,
                None,
                &completion("owner-b", "output-1")
            ),
            CompletionVerdict::RejectedStaleOwner
        );
    }

    #[test]
    fn a_late_result_from_an_older_attempt_token_is_rejected() {
        let mut late = completion("owner-a", "output-1");
        late.attempt_token = "attempt-0".into();
        assert_eq!(
            settle_effect(
                &lease("owner-a", 2_000),
                EffectProgress::InFlight,
                None,
                &late
            ),
            CompletionVerdict::RejectedStaleOwner
        );
    }

    #[test]
    fn successors_are_released_only_for_the_admitted_attempt() {
        let held = lease("owner-a", 2_000);
        let gate = SuccessorGate {
            admitted_attempts: vec![held.attempt_identity()],
            ..SuccessorGate::default()
        };
        let admission = gate.release(&held, &[edge(1)], "state-1", 1);
        assert!(admission.is_admitted());
        assert_eq!(admission.admitted_successors(), &[edge(1)]);

        let foreign = SuccessorGate {
            admitted_attempts: vec!["command-9\u{0}attempt-9".into()],
            ..SuccessorGate::default()
        };
        assert_eq!(
            foreign.release(&held, &[edge(1)], "state-1", 1),
            SuccessorAdmission::Refused(SuccessorRefusal::NotAdmitted)
        );
    }

    #[test]
    fn barriers_stops_and_stale_visits_hold_successors() {
        let held = lease("owner-a", 2_000);
        let admitted = vec![held.attempt_identity()];
        let barrier = SuccessorGate {
            barrier_active: true,
            admitted_attempts: admitted.clone(),
            ..SuccessorGate::default()
        };
        assert_eq!(
            barrier.release(&held, &[edge(1)], "state-1", 1),
            SuccessorAdmission::Refused(SuccessorRefusal::BarrierActive)
        );
        let stopped = SuccessorGate {
            stop_requested: true,
            admitted_attempts: admitted.clone(),
            ..SuccessorGate::default()
        };
        assert_eq!(
            stopped.release(&held, &[edge(1)], "state-1", 1),
            SuccessorAdmission::Refused(SuccessorRefusal::StopRequested)
        );
        let superseded = SuccessorGate {
            current_state_visit: Some(3),
            admitted_attempts: admitted,
            ..SuccessorGate::default()
        };
        assert_eq!(
            superseded.release(&held, &[edge(1)], "state-1", 1),
            SuccessorAdmission::Refused(SuccessorRefusal::Superseded)
        );
    }

    #[test]
    fn unrelated_successors_of_another_visit_are_not_released() {
        let held = lease("owner-a", 2_000);
        let gate = SuccessorGate {
            admitted_attempts: vec![held.attempt_identity()],
            ..SuccessorGate::default()
        };
        let admission = gate.release(&held, &[edge(1), edge(2)], "state-1", 1);
        assert_eq!(admission.admitted_successors(), &[edge(1)]);
    }

    #[test]
    fn a_terminal_effect_admits_an_empty_successor_set() {
        let held = lease("owner-a", 2_000);
        let gate = SuccessorGate {
            admitted_attempts: vec![held.attempt_identity()],
            ..SuccessorGate::default()
        };
        let admission = gate.release(&held, &[], "state-1", 1);
        assert!(admission.is_admitted());
        assert!(admission.admitted_successors().is_empty());
    }

    #[test]
    fn routing_keys_separate_kinds_and_destinations() {
        let actor = DispatchRecipient::Actor {
            binding_id: "binding-1".into(),
            runtime_id: "runtime-1".into(),
        };
        let other_runtime = DispatchRecipient::Actor {
            binding_id: "binding-1".into(),
            runtime_id: "runtime-2".into(),
        };
        let item = DispatchRecipient::WorksetItem {
            item_id: "binding-1".into(),
            binding_ordinal: 1,
        };
        assert_ne!(actor.routing_key(), other_runtime.routing_key());
        assert_ne!(actor.routing_key(), item.routing_key());
        assert_eq!(actor.command_kind(), CommandKind::Actor);
        assert_eq!(item.command_kind(), CommandKind::WorksetItem);
    }

    #[test]
    fn an_already_settled_attempt_refuses_redispatch() {
        let request = intent(1, Some("grant-1"));
        let gate = DispatchGate {
            committed_grant_digest: Some("grant-1".into()),
            settled_attempts: vec![request.attempt_identity()],
            ..DispatchGate::default()
        };
        assert_eq!(
            gate.evaluate(&request).refusal(),
            Some(DispatchRefusal::AlreadySettled)
        );
    }
}
