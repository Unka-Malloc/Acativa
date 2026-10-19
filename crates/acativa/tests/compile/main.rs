//! V7-C1 — plan identity, retention, and the legacy-run interpreter check.
//!
//! Three claims live here, and each one is a claim about what is *impossible*
//! rather than about what happens to work today:
//!
//! * A definition content digest cannot stand in for an engine or compiler
//!   semantics version. The types make that a compile error at the call site and
//!   a typed refusal at the wire boundary, and the fixture below carries a real
//!   checkpoint that recorded the digest where a version belongs.
//! * A plan retained for a store is the definition plus the binding identity.
//!   There is no second compiled form to drift: the lowered plan is rebuilt, and
//!   the rebuilt plan carries the identity it already had.
//! * An old run bound to semantics this build does not execute is handed off
//!   rather than advanced, and the compatible interpreter for it is a real,
//!   expressible thing rather than an assumption.

use serde::Deserialize;
use serde_json::json;

use acativa::compile::{
    CompiledWorkflow, CompilerSemantics, DefinitionRevision, EngineSemantics, HandoffReason,
    InterpreterProfile, LoweringCapabilities, LoweringRefusal, PlanKey, PlanMismatch,
    RecordedPlanKey, RetainedPlan, RunAdmission,
};
use acativa::{ReducerEvent, RunSnapshot, SchemaId, compile_workflow_source, reduce};

/// The fixture files describe one legacy workflow and the runs bound to it. The
/// workflow is stored exactly as a package stores `workflow.json` — canonical
/// bytes, so `legacy_workflow.json` deliberately has no trailing newline — which
/// is what makes the revision pin below a pin on real input rather than on a
/// convenience copy.
const LEGACY_WORKFLOW: &str = include_str!("fixtures/legacy_workflow.json");
const LEGACY_RUNS: &str = include_str!("fixtures/legacy_runs.json");

const FIXTURE_SCHEMA: &str = "acativa.legacy-run-fixture.v1";

/// The workflow schema the fixture definition declares and this test compiles
/// under — the crate's generic identity, bound the way a host binds its own.
fn fixture_supported_schema() -> SchemaId {
    SchemaId::new(acativa::GENERIC_WORKFLOW_SCHEMA)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LegacyFixture {
    schema: String,
    runs: Vec<LegacyRun>,
}

impl LegacyFixture {
    fn load() -> Self {
        let fixture: Self = serde_json::from_str(LEGACY_RUNS).expect("the run fixture decodes");
        assert_eq!(fixture.schema, FIXTURE_SCHEMA);
        fixture
    }

    fn run(&self, name: &str) -> &LegacyRun {
        self.runs
            .iter()
            .find(|run| run.name == name)
            .unwrap_or_else(|| panic!("the fixture has a run named {name}"))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LegacyRun {
    name: String,
    /// The checkpoint as the old build wrote it. Today's reader still loads it:
    /// the type did not have to change for a run to be old.
    snapshot: RunSnapshot,
    /// The binding the old build recorded beside the checkpoint.
    recorded_plan_key: RecordedPlanKey,
}

/// The fixture workflow, compiled from the bytes a store would hand over.
fn fixture_workflow() -> CompiledWorkflow {
    let compiled = compile_workflow_source(LEGACY_WORKFLOW.as_bytes(), &fixture_supported_schema())
        .unwrap_or_else(|failure| panic!("the fixture workflow compiles: {failure}"));
    assert_eq!(
        serde_json::to_vec(compiled.definition()).expect("the definition re-encodes"),
        LEGACY_WORKFLOW.as_bytes(),
        "the fixture definition is canonical, exactly as a stored workflow.json is"
    );
    compiled
}

fn fixture_revision() -> DefinitionRevision {
    DefinitionRevision::of(fixture_workflow().definition()).expect("the fixture definition digests")
}

fn fixture_key(
    compiler_semantics: CompilerSemantics,
    engine_semantics: EngineSemantics,
    capabilities: LoweringCapabilities,
) -> PlanKey {
    PlanKey::for_definition(
        fixture_workflow().definition(),
        compiler_semantics,
        engine_semantics,
        capabilities,
    )
    .expect("the fixture key types")
}

/// One deterministic machine trace. Two lowerings of the same definition, read
/// through the same plan, must produce the same trace.
fn trace(plan: &CompiledWorkflow) -> serde_json::Value {
    let empty = RunSnapshot::empty("run-trace", "revision", "semantics");
    let output = reduce(
        plan,
        &empty,
        ReducerEvent::Start {
            input: json!({"task": "fixture"}),
        },
    )
    .expect("the fixture run starts");
    json!({
        "snapshot": serde_json::to_value(&output.snapshot).expect("the snapshot encodes"),
        "commands": serde_json::to_value(&output.emitted_commands).expect("commands encode"),
    })
}

#[test]
fn the_fixture_pins_the_revision_every_run_was_bound_to() {
    let fixture = LegacyFixture::load();
    let revision = fixture_revision();
    assert_eq!(
        revision.as_str(),
        "b227d67a05749e60ddeaea2af38c0519a9c7cbbb8340360d0b14ea88c515f7bf",
        "the pinned revision is the fixture definition's own digest"
    );
    for run in &fixture.runs {
        assert_eq!(
            run.recorded_plan_key.definition_revision,
            revision.as_str(),
            "run {} is bound to the fixture revision",
            run.name
        );
    }
}

#[test]
fn an_old_run_stays_on_a_compatible_interpreter() {
    let fixture = LegacyFixture::load();
    let older = fixture.run("engine-semantics-v0");
    let this_build = InterpreterProfile::current(LoweringCapabilities::none());

    // This build executes its own engine semantics, so it must not advance a run
    // bound to an earlier version of that line.
    assert_eq!(
        this_build.admit_recorded(&older.recorded_plan_key),
        RunAdmission::Handoff {
            reason: HandoffReason::EngineSemantics
        }
    );

    // The checkpoint itself loads, and it is a real resting checkpoint: the run
    // was mid-flight under semantics this build does not claim.
    assert_eq!(older.snapshot.run_id, "run-legacy-v0");
    assert_eq!(older.snapshot.sequence, 3);
    assert!(older.snapshot.active_states.contains("review"));

    // The compatible interpreter is a profile that declares the run's semantics,
    // and it is the same lowering: the identity does not move between them.
    let bound = older
        .recorded_plan_key
        .typed()
        .expect("the recorded binding types");
    let compatible = InterpreterProfile::new(
        bound.compiler_semantics(),
        bound.engine_semantics(),
        LoweringCapabilities::none(),
    );
    assert_eq!(
        compatible.admit_recorded(&older.recorded_plan_key),
        RunAdmission::Compatible
    );
    assert_eq!(compatible.key_for(fixture_revision()), bound);
    assert_eq!(
        this_build
            .key_for(fixture_revision())
            .binding_digest()
            .len(),
        64
    );
    assert_ne!(
        this_build.key_for(fixture_revision()).binding_digest(),
        bound.binding_digest(),
        "the two interpreters hold different identities for the same revision"
    );

    // Recording this build's own binding and reading it back yields exactly the
    // key it was recorded from, so a binding survives a store round trip.
    let this_build_key = this_build.key_for(fixture_revision());
    let recorded = RecordedPlanKey::from(&this_build_key);
    assert_eq!(
        recorded.typed().expect("the recorded binding types"),
        this_build_key
    );
}

#[test]
fn an_opaque_semantics_digest_is_never_reinterpreted() {
    let fixture = LegacyFixture::load();
    let opaque = fixture.run("opaque-semantics-digest");
    let this_build = InterpreterProfile::current(LoweringCapabilities::none());

    // The old build recorded the definition's content digest as the semantics it
    // ran under. That is not a version of any semantics line, so it cannot be
    // read as one — by the semantics type or by the record.
    assert_eq!(
        opaque.snapshot.semantics_digest,
        opaque.recorded_plan_key.compiler_semantics
    );
    assert_eq!(
        opaque.recorded_plan_key.compiler_semantics,
        fixture_revision().as_str()
    );
    assert!(
        CompilerSemantics::from_wire(&opaque.recorded_plan_key.compiler_semantics).is_err(),
        "a content digest is not a compiler semantics version"
    );
    assert!(
        opaque.recorded_plan_key.typed().is_err(),
        "the record cannot be typed into a plan key"
    );
    // With no provable binding, the run is handed off rather than restarted here.
    assert_eq!(
        this_build.admit_recorded(&opaque.recorded_plan_key),
        RunAdmission::Handoff {
            reason: HandoffReason::UnprovenSemantics
        }
    );
}

#[test]
fn a_run_bound_to_older_compiler_semantics_is_handed_off_not_relowered() {
    let fixture = LegacyFixture::load();
    let older = fixture.run("compiler-semantics-v0");
    let this_build = InterpreterProfile::current(LoweringCapabilities::none());

    // The definition revision is the same input; the lowering semantics are
    // not, so this build must not advance the run.
    assert_eq!(
        this_build.admit_recorded(&older.recorded_plan_key),
        RunAdmission::Handoff {
            reason: HandoffReason::CompilerSemantics
        }
    );

    // The checkpoint is still a real resting checkpoint, so it can be handed to
    // the interpreter that does lower v0 rather than restarted here.
    assert_eq!(older.snapshot.run_id, "run-legacy-compiler-v0");
    assert_eq!(older.snapshot.sequence, 4);
    assert!(older.snapshot.active_states.contains("review"));

    // That interpreter is a real, expressible thing, and its identity for the
    // same revision is a different plan.
    let bound = older
        .recorded_plan_key
        .typed()
        .expect("the recorded binding types");
    let compatible = InterpreterProfile::new(
        bound.compiler_semantics(),
        bound.engine_semantics(),
        LoweringCapabilities::none(),
    );
    assert_eq!(
        compatible.admit_recorded(&older.recorded_plan_key),
        RunAdmission::Compatible
    );
    let older_key = compatible.key_for(fixture_revision());
    let current_key = this_build.key_for(fixture_revision());
    assert_eq!(
        older_key.definition_revision(),
        current_key.definition_revision(),
        "both interpreters lower the same definition bytes"
    );
    assert_ne!(older_key.binding_digest(), current_key.binding_digest());

    // This build has no lowering for that key at all: it cannot produce an
    // index and call it the v0 lowering.
    assert!(matches!(
        this_build.lowerable(&older_key),
        Err(LoweringRefusal::CompilerSemantics { .. })
    ));
    assert!(compatible.lowerable(&older_key).is_ok());
}

#[test]
fn a_record_that_omits_part_of_the_identity_is_refused() {
    // Every field is part of the identity, so a record that does not carry one
    // is not completed with an assumed default: it is refused at the wire
    // boundary.
    let incomplete = json!({
        "definitionRevision": fixture_revision().as_str(),
        "compilerSemantics": CompilerSemantics::CURRENT.wire(),
        "engineSemantics": EngineSemantics::CURRENT.wire(),
    });
    assert!(
        serde_json::from_value::<RecordedPlanKey>(incomplete.clone()).is_err(),
        "a record without its capabilities is not a complete key"
    );

    // The complete record types into exactly the key it records.
    let mut complete = incomplete;
    complete["loweringCapabilities"] = json!([]);
    let recorded: RecordedPlanKey =
        serde_json::from_value(complete).expect("the complete record decodes");
    assert_eq!(
        recorded.typed().expect("the complete record types"),
        fixture_key(
            CompilerSemantics::CURRENT,
            EngineSemantics::CURRENT,
            LoweringCapabilities::none(),
        )
    );
}

#[test]
fn a_content_digest_is_not_a_semantics_version_anywhere() {
    let revision = fixture_revision();
    let digest = revision.as_str();

    // Not through the version constructors...
    assert!(CompilerSemantics::from_wire(digest).is_err());
    assert!(EngineSemantics::from_wire(digest).is_err());
    // ...not through a line that does not own the version...
    assert!(CompilerSemantics::from_wire(&EngineSemantics::CURRENT.wire()).is_err());
    assert!(EngineSemantics::from_wire(&CompilerSemantics::CURRENT.wire()).is_err());
    // ...and not through a version that does not exist yet.
    assert!(CompilerSemantics::version(CompilerSemantics::CURRENT.version_of() + 1).is_err());
    assert!(EngineSemantics::version(EngineSemantics::CURRENT.version_of() + 1).is_err());

    // The typed key refuses the same substitution on the wire.
    let mut record = json!({
        "definitionRevision": digest,
        "compilerSemantics": CompilerSemantics::CURRENT.version_of(),
        "engineSemantics": EngineSemantics::CURRENT.version_of(),
        "loweringCapabilities": [],
    });
    assert!(
        serde_json::from_value::<PlanKey>(record.clone()).is_ok(),
        "a typed key decodes"
    );
    record["engineSemantics"] = json!(digest);
    assert!(
        serde_json::from_value::<PlanKey>(record.clone()).is_err(),
        "a digest cannot be decoded as an engine semantics version"
    );
    record["engineSemantics"] = json!(EngineSemantics::CURRENT.version_of() + 1);
    assert!(
        serde_json::from_value::<PlanKey>(record).is_err(),
        "an engine version this build does not declare is refused on the wire"
    );
}

#[test]
fn the_revision_and_each_semantics_separate_identities() {
    let revision = fixture_revision();
    let earlier = EngineSemantics::version(EngineSemantics::CURRENT.version_of() - 1)
        .expect("an earlier version of the line is nameable");

    // Same revision, different engine semantics: a different plan identity.
    let current_key = fixture_key(
        CompilerSemantics::CURRENT,
        EngineSemantics::CURRENT,
        LoweringCapabilities::none(),
    );
    let earlier_key = fixture_key(
        CompilerSemantics::CURRENT,
        earlier,
        LoweringCapabilities::none(),
    );
    assert_ne!(current_key, earlier_key);
    assert_ne!(current_key.binding_digest(), earlier_key.binding_digest());
    assert_eq!(
        current_key.definition_revision(),
        earlier_key.definition_revision(),
        "the revision is the same input in both keys"
    );

    // Same semantics, a different definition: a different identity too.
    let mut edited = fixture_workflow().into_definition();
    edited.metadata.version = "2".into();
    let edited_key = PlanKey::for_definition(
        &edited,
        CompilerSemantics::CURRENT,
        EngineSemantics::CURRENT,
        LoweringCapabilities::none(),
    )
    .expect("the edited key types");
    assert_ne!(current_key, edited_key);
    assert_ne!(current_key.binding_digest(), edited_key.binding_digest());
    assert_ne!(*edited_key.definition_revision(), revision);

    // The identity is a function of the key alone: asking twice never moves it.
    let rebuilt_key = fixture_key(
        CompilerSemantics::CURRENT,
        EngineSemantics::CURRENT,
        LoweringCapabilities::none(),
    );
    assert_eq!(rebuilt_key, current_key);
    assert_eq!(rebuilt_key.binding_digest(), current_key.binding_digest());
}

#[test]
fn lowering_capabilities_are_canonical_namespaced_and_checked() {
    let declared = LoweringCapabilities::declare([
        "vendor.example/render",
        "acativa.workflow/graph",
        "vendor.example/render",
    ])
    .expect("the tags are namespaced");
    let reversed =
        LoweringCapabilities::declare(["acativa.workflow/graph", "vendor.example/render"])
            .expect("the tags are namespaced");
    assert_eq!(declared, reversed, "declaration order does not matter");
    assert_eq!(declared.len(), 2, "a repeated tag is declared once");

    let with_capability = fixture_key(
        CompilerSemantics::CURRENT,
        EngineSemantics::CURRENT,
        declared.clone(),
    );
    let with_reversed = fixture_key(
        CompilerSemantics::CURRENT,
        EngineSemantics::CURRENT,
        reversed,
    );
    assert_eq!(with_capability, with_reversed);
    assert_eq!(
        with_capability.binding_digest(),
        with_reversed.binding_digest()
    );

    for invalid in [
        "render",
        "Vendor.Example/render",
        "vendor/render",
        "",
        "vendor.example/",
    ] {
        assert!(
            LoweringCapabilities::declare([invalid]).is_err(),
            "{invalid} is not a namespaced capability tag"
        );
    }

    // A host that does not declare the capability is told which one is missing,
    // rather than lowered approximately.
    let host = InterpreterProfile::current(LoweringCapabilities::none());
    assert_eq!(
        host.lowerable(&with_capability),
        Err(LoweringRefusal::MissingCapability {
            capability: "acativa.workflow/graph".into()
        })
    );
    assert_eq!(
        host.admit_run(&with_capability),
        RunAdmission::MissingCapability {
            capability: "acativa.workflow/graph".into()
        }
    );
    // The engine semantics travels in the identity without blocking lowering:
    // the index is a function of the definition and the lowering semantics.
    // This host declares the capabilities, so the only difference left between
    // the two keys is the engine version.
    let earlier_engine = fixture_key(
        CompilerSemantics::CURRENT,
        EngineSemantics::version(EngineSemantics::CURRENT.version_of() - 1).expect("nameable"),
        declared.clone(),
    );
    let capable_host = InterpreterProfile::current(declared);
    let current_engine = fixture_key(
        CompilerSemantics::CURRENT,
        EngineSemantics::CURRENT,
        capable_host.lowering_capabilities().clone(),
    );
    assert!(capable_host.lowerable(&earlier_engine).is_ok());
    assert!(capable_host.lowerable(&current_engine).is_ok());
    assert_eq!(
        capable_host.admit_run(&earlier_engine),
        RunAdmission::Handoff {
            reason: HandoffReason::EngineSemantics
        }
    );
    assert_eq!(
        capable_host.admit_run(&current_engine),
        RunAdmission::Compatible
    );
}

#[test]
fn a_retained_plan_holds_the_definition_and_the_identity_only() {
    let compiled = fixture_workflow();
    let key = fixture_key(
        CompilerSemantics::CURRENT,
        EngineSemantics::CURRENT,
        LoweringCapabilities::none(),
    );
    let retained = RetainedPlan::of(&compiled, key.clone()).expect("the plan is the key's plan");
    let bytes = retained.to_wire_bytes().expect("the retained form encodes");

    // What a store persists is exactly the definition and the binding identity.
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("the form decodes");
    assert_eq!(
        value
            .as_object()
            .expect("the retained form is an object")
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["definition", "key"],
        "nothing else is persisted"
    );
    let text = String::from_utf8(bytes.clone()).expect("the retained form is text");
    for index in [
        "stateIndexes",
        "transitionIndexes",
        "outgoingIndexes",
        "predecessors",
        "reachable",
    ] {
        assert!(
            !text.contains(index),
            "no second compiled form is persisted: {index}"
        );
    }

    // Reading it back checks the pair against itself, then rebuilds the plan.
    let read = RetainedPlan::from_wire_bytes(&bytes).expect("the retained pair is consistent");
    assert_eq!(read.key(), &key);
    assert_eq!(read.binding_digest(), key.binding_digest());
    assert_eq!(
        read.retained_bytes().expect("the retained form encodes"),
        bytes.len()
    );
    let rebuilt = read
        .rebuild(&fixture_supported_schema())
        .expect("the retained definition still compiles");
    assert_eq!(
        DefinitionRevision::of(rebuilt.definition()).expect("the rebuilt plan digests"),
        *key.definition_revision(),
        "the rebuild carries the identity the key records"
    );
    assert_eq!(
        trace(&rebuilt),
        trace(&compiled),
        "the rebuilt lowering is the same lowering"
    );
}

#[test]
fn a_retained_pair_that_drifted_is_refused() {
    let compiled = fixture_workflow();
    let key = fixture_key(
        CompilerSemantics::CURRENT,
        EngineSemantics::CURRENT,
        LoweringCapabilities::none(),
    );
    let bytes = RetainedPlan::of(&compiled, key.clone())
        .expect("the plan is the key's plan")
        .to_wire_bytes()
        .expect("the retained form encodes");

    // A plan that is not the key's plan cannot be filed under it.
    let mut edited = fixture_workflow().into_definition();
    edited.metadata.version = "2".into();
    let other = compile_workflow_source(
        serde_json::to_vec(&edited)
            .expect("the edited definition encodes")
            .as_slice(),
        &fixture_supported_schema(),
    )
    .expect("the edited definition compiles");
    assert!(matches!(
        RetainedPlan::of(&other, key.clone()),
        Err(PlanMismatch::RevisionDrift { .. })
    ));

    // A persisted pair that drifts after the fact is refused when it is read.
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).expect("the form decodes");
    value["definition"]["metadata"]["version"] = json!("2");
    assert!(matches!(
        RetainedPlan::from_wire_bytes(&serde_json::to_vec(&value).expect("the form encodes")),
        Err(PlanMismatch::RevisionDrift { .. })
    ));
    // And an unknown field is refused instead of silently ignored.
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).expect("the form decodes");
    value["compiledIndexes"] = json!({});
    assert!(matches!(
        RetainedPlan::from_wire_bytes(&serde_json::to_vec(&value).expect("the form encodes")),
        Err(PlanMismatch::PlanEncoding { .. })
    ));
}
