use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Display, Formatter};

use crate::{
    GraphState, GuardExpression, Transition, TransitionEvent, WorkflowDefinition,
    analysis::AnalyzedWorkflow,
};

#[derive(Clone, Debug)]
pub struct CompiledWorkflow {
    pub(crate) definition: WorkflowDefinition,
    state_indexes: BTreeMap<String, usize>,
    transition_indexes: BTreeMap<(String, TransitionEvent), Vec<usize>>,
    outgoing_indexes: BTreeMap<String, Vec<usize>>,
    predecessors: BTreeMap<String, BTreeSet<String>>,
    reachable: BTreeSet<String>,
}

impl CompiledWorkflow {
    pub fn definition(&self) -> &WorkflowDefinition {
        &self.definition
    }

    pub fn into_definition(self) -> WorkflowDefinition {
        self.definition
    }
    pub fn state(&self, id: &str) -> Option<&GraphState> {
        self.state_indexes
            .get(id)
            .map(|index| &self.definition.states[*index])
    }

    pub fn transitions(
        &self,
        from: &str,
        event: TransitionEvent,
    ) -> impl Iterator<Item = &Transition> {
        self.transition_indexes
            .get(&(from.to_owned(), event))
            .into_iter()
            .flatten()
            .map(|index| &self.definition.transitions[*index])
    }

    pub fn outgoing(&self, from: &str) -> impl Iterator<Item = &Transition> {
        self.outgoing_indexes
            .get(from)
            .into_iter()
            .flatten()
            .map(|index| &self.definition.transitions[*index])
    }

    pub fn predecessors(&self, state: &str) -> &BTreeSet<String> {
        static EMPTY: std::sync::LazyLock<BTreeSet<String>> =
            std::sync::LazyLock::new(BTreeSet::new);
        self.predecessors.get(state).unwrap_or(&EMPTY)
    }

    pub fn reachable(&self) -> &BTreeSet<String> {
        &self.reachable
    }

    pub fn select_transition<'a>(
        &'a self,
        from: &str,
        event: TransitionEvent,
        payload: &serde_json::Value,
    ) -> Result<Option<&'a Transition>> {
        let candidates = self.transitions(from, event).collect::<Vec<_>>();
        let mut selected = None;
        let mut fallback = None;
        for transition in candidates {
            match &transition.guard {
                Some(guard) if guard_matches(guard, payload) => {
                    ensure!(selected.is_none(), "graph_guard_ambiguous_at_runtime");
                    selected = Some(transition);
                }
                Some(_) => {}
                None => fallback = Some(transition),
            }
        }
        Ok(selected.or(fallback))
    }
}

/// Lower one definition that has already passed semantic analysis. This phase
/// only materializes immutable lookup facts; it does not validate source
/// semantics a second time.
pub(crate) fn compile_validated_workflow(analyzed: AnalyzedWorkflow) -> CompiledWorkflow {
    let definition = analyzed.into_definition();
    let state_indexes = definition
        .states
        .iter()
        .enumerate()
        .map(|(index, state)| (state.id.clone(), index))
        .collect::<BTreeMap<_, _>>();
    let mut transition_indexes = BTreeMap::<(String, TransitionEvent), Vec<usize>>::new();
    let mut outgoing_indexes = BTreeMap::<String, Vec<usize>>::new();
    let mut predecessors = BTreeMap::<String, BTreeSet<String>>::new();
    for (index, transition) in definition.transitions.iter().enumerate() {
        transition_indexes
            .entry((transition.from.clone(), transition.event))
            .or_default()
            .push(index);
        outgoing_indexes
            .entry(transition.from.clone())
            .or_default()
            .push(index);
        predecessors
            .entry(transition.to.clone())
            .or_default()
            .insert(transition.from.clone());
    }
    // Semantic analysis rejects every unreachable state, so the complete
    // validated state set is the reachability fact. Do not walk the graph a
    // second time during lowering.
    let reachable = definition
        .states
        .iter()
        .map(|state| state.id.clone())
        .collect();
    CompiledWorkflow {
        definition,
        state_indexes,
        transition_indexes,
        outgoing_indexes,
        predecessors,
        reachable,
    }
}

#[cfg(test)]
fn compile_workflow(
    definition: WorkflowDefinition,
) -> std::result::Result<CompiledWorkflow, crate::WorkflowValidationFailure> {
    crate::compile_workflow(
        definition,
        &crate::SchemaId::new(crate::GENERIC_WORKFLOW_SCHEMA),
    )
}

// ---------------------------------------------------------------------------
// Plan identity
//
// Everything below answers one question: what is the identity of a lowered
// plan? The identity is exactly the inputs lowering and execution depend on,
// each one typed so that no caller can substitute one for another. A definition
// content digest is a `DefinitionRevision` and nothing else: it is not a value
// of either semantics line, and the semantics types can only hold a version of
// the line that declares them. A digest therefore cannot stand in for an engine
// version by accident, and — because those constructors are the only way to
// build the values at all — not on purpose either.
// ---------------------------------------------------------------------------

/// The persisted identity lines a host binds to plan identity.
///
/// The lines are the host's persisted/wire vocabulary, exactly like
/// [`crate::SchemaId`]: a version value names "a version of this line", and the
/// line itself decides which recorded strings a host accepts as its own. A
/// host that binds `licoup.workflow.compiler` cannot read, and must not be
/// read by, a record that declares `acativa.workflow.compiler` — the wire
/// forms differ on purpose.
///
/// All three fields are `'static`: persisted identity is a property a build
/// carries, not a value it loads.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PlanIdentity {
    /// The compiler-semantics line, e.g. `"acativa.workflow.compiler"`.
    pub compiler_semantics: &'static str,
    /// The engine-semantics line, e.g. `"acativa.workflow.engine"`.
    pub engine_semantics: &'static str,
    /// The binding-identity encoding prefix, e.g.
    /// `"acativa.workflow.plan-key.v1"`. It enters every binding digest, so two
    /// identities produce different digests for the same plan.
    pub plan_key_schema: &'static str,
}

impl PlanIdentity {
    pub const fn new(
        compiler_semantics: &'static str,
        engine_semantics: &'static str,
        plan_key_schema: &'static str,
    ) -> Self {
        Self {
            compiler_semantics,
            engine_semantics,
            plan_key_schema,
        }
    }
}

/// The compiler semantics line this crate lowers under in its own fixtures.
const COMPILER_SEMANTICS_LINE: &str = "acativa.workflow.compiler";
/// The version of [`COMPILER_SEMANTICS_LINE`] this build lowers under.
///
/// This version is the identity of the whole lowering contract: the schema this
/// build accepts (the host-bound schema identity), the limits that decide whether a
/// definition is admissible (`MAX_GRAPH_STATES`, `MAX_GRAPH_TRANSITIONS`,
/// `MAX_BINDING_SLOTS`, `MAX_RUNTIME_REQUIREMENTS`, `MAX_WORKSET_ITEMS`,
/// `MAX_RETRY_ATTEMPTS`, `MAX_ACTIVE_EFFECTS`), and the index construction in
/// [`compile_validated_workflow`]. Changing any of those changes which
/// definitions lower and how, so it must bump this version rather than ride
/// along under the old one.
const COMPILER_SEMANTICS_VERSION: u16 = 1;
/// The engine semantics line this crate owns: how a lowered plan executes.
const ENGINE_SEMANTICS_LINE: &str = "acativa.workflow.engine";
/// The version of [`ENGINE_SEMANTICS_LINE`] this build executes.
///
/// This version is the identity of the execution contract: what the machine in
/// `machine` does with a snapshot and an event. A change there changes what a
/// persisted run means, which is a new version of this line, not an edit to an
/// old one.
const ENGINE_SEMANTICS_VERSION: u16 = 1;

/// Prefix of the binding-identity encoding. Changing it changes every identity,
/// so it carries the version of the identity scheme itself.
const BINDING_IDENTITY_SCHEMA: &str = "acativa.workflow.plan-key.v1";

/// The identity lines Acativa's own fixtures and conformance suite bind. A
/// product host binds its own lines at the same parameter so its persisted
/// plan records keep their existing spellings.
pub const ACATIVA_PLAN_IDENTITY: PlanIdentity = PlanIdentity::new(
    COMPILER_SEMANTICS_LINE,
    ENGINE_SEMANTICS_LINE,
    BINDING_IDENTITY_SCHEMA,
);
/// Longest recorded value echoed back in a diagnostic.
const MAX_ECHOED_VALUE: usize = 64;
/// Longest accepted capability tag, e.g. `vendor.example/render`.
const MAX_CAPABILITY_LENGTH: usize = 128;

/// A version of this crate's compiler semantics line.
///
/// The payload is a version number of a line this crate declares, so the values
/// that exist are "an earlier version of this line" or "the version this build
/// lowers under". Nothing else is expressible: in particular a content digest
/// has no path into this type.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "u16", into = "u16")]
pub struct CompilerSemantics(u16);

impl CompilerSemantics {
    /// The semantics this build lowers under.
    pub const CURRENT: Self = Self(COMPILER_SEMANTICS_VERSION);

    /// Name a version of the compiler semantics line `identity` binds.
    ///
    /// A version newer than this build is refused: only lowering behavior that
    /// exists can be named. An earlier version is nameable, because a run may
    /// still be bound to it, even though this build is not its interpreter.
    pub fn version(
        identity: &PlanIdentity,
        version: u16,
    ) -> std::result::Result<Self, PlanInputError> {
        semantics_version(
            identity.compiler_semantics,
            COMPILER_SEMANTICS_VERSION,
            version,
        )
        .map(Self)
    }

    /// `version` under Acativa's own identity lines — the generic dialect.
    pub fn generic_version(version: u16) -> std::result::Result<Self, PlanInputError> {
        Self::version(&ACATIVA_PLAN_IDENTITY, version)
    }

    pub const fn version_of(self) -> u16 {
        self.0
    }

    /// The recorded form under `identity`'s lines:
    /// `acativa.workflow.compiler.v1` for [`ACATIVA_PLAN_IDENTITY`].
    pub fn wire(self, identity: &PlanIdentity) -> String {
        semantics_wire(identity.compiler_semantics, self.0)
    }

    /// The recorded form under Acativa's own identity lines.
    pub fn generic_wire(self) -> String {
        self.wire(&ACATIVA_PLAN_IDENTITY)
    }

    pub fn from_wire(
        identity: &PlanIdentity,
        value: &str,
    ) -> std::result::Result<Self, PlanInputError> {
        parse_semantics_wire(
            identity.compiler_semantics,
            COMPILER_SEMANTICS_VERSION,
            value,
        )
        .map(Self)
    }

    /// `from_wire` under Acativa's own identity lines.
    pub fn generic_from_wire(value: &str) -> std::result::Result<Self, PlanInputError> {
        Self::from_wire(&ACATIVA_PLAN_IDENTITY, value)
    }
}

impl From<CompilerSemantics> for u16 {
    fn from(semantics: CompilerSemantics) -> Self {
        semantics.0
    }
}

impl TryFrom<u16> for CompilerSemantics {
    type Error = PlanInputError;

    /// Names a version of Acativa's own compiler line. A host binding other
    /// lines calls [`CompilerSemantics::version`] with its `PlanIdentity`.
    fn try_from(version: u16) -> std::result::Result<Self, Self::Error> {
        Self::generic_version(version)
    }
}

/// A version of this crate's engine semantics line: how a lowered plan executes.
///
/// Same shape and same guarantee as [`CompilerSemantics`]: engine behavior has
/// versions, and a definition digest is not one of them.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "u16", into = "u16")]
pub struct EngineSemantics(u16);

impl EngineSemantics {
    /// The semantics this build executes.
    pub const CURRENT: Self = Self(ENGINE_SEMANTICS_VERSION);

    /// Name a version of the engine semantics line `identity` binds.
    pub fn version(
        identity: &PlanIdentity,
        version: u16,
    ) -> std::result::Result<Self, PlanInputError> {
        semantics_version(identity.engine_semantics, ENGINE_SEMANTICS_VERSION, version).map(Self)
    }

    /// `version` under Acativa's own identity lines — the generic dialect.
    pub fn generic_version(version: u16) -> std::result::Result<Self, PlanInputError> {
        Self::version(&ACATIVA_PLAN_IDENTITY, version)
    }

    pub const fn version_of(self) -> u16 {
        self.0
    }

    /// The recorded form under `identity`'s lines:
    /// `acativa.workflow.engine.v1` for [`ACATIVA_PLAN_IDENTITY`].
    pub fn wire(self, identity: &PlanIdentity) -> String {
        semantics_wire(identity.engine_semantics, self.0)
    }

    /// The recorded form under Acativa's own identity lines.
    pub fn generic_wire(self) -> String {
        self.wire(&ACATIVA_PLAN_IDENTITY)
    }

    pub fn from_wire(
        identity: &PlanIdentity,
        value: &str,
    ) -> std::result::Result<Self, PlanInputError> {
        parse_semantics_wire(identity.engine_semantics, ENGINE_SEMANTICS_VERSION, value).map(Self)
    }

    /// `from_wire` under Acativa's own identity lines.
    pub fn generic_from_wire(value: &str) -> std::result::Result<Self, PlanInputError> {
        Self::from_wire(&ACATIVA_PLAN_IDENTITY, value)
    }
}

impl From<EngineSemantics> for u16 {
    fn from(semantics: EngineSemantics) -> Self {
        semantics.0
    }
}

impl TryFrom<u16> for EngineSemantics {
    type Error = PlanInputError;

    /// Names a version of Acativa's own engine line. A host binding other
    /// lines calls [`EngineSemantics::version`] with its `PlanIdentity`.
    fn try_from(version: u16) -> std::result::Result<Self, Self::Error> {
        Self::generic_version(version)
    }
}

/// The content revision of one workflow definition.
///
/// The digest identifies *what* was compiled. It says nothing about *how* it is
/// compiled or executed, which is why it is a distinct type from both semantics
/// lines rather than a string that could be passed as either.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct DefinitionRevision(String);

impl DefinitionRevision {
    /// Digest one definition's canonical encoding.
    pub fn of(definition: &WorkflowDefinition) -> std::result::Result<Self, PlanInputError> {
        let bytes = serde_json::to_vec(definition).map_err(PlanInputError::PlanEncoding)?;
        Ok(Self(sha256_hex(&bytes)))
    }

    /// Type a recorded digest.
    pub fn from_wire(value: &str) -> std::result::Result<Self, PlanInputError> {
        let hex = value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        if !hex {
            return Err(PlanInputError::DefinitionRevision {
                value: clipped(value).to_owned(),
            });
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for DefinitionRevision {
    type Error = PlanInputError;

    fn try_from(value: String) -> std::result::Result<Self, Self::Error> {
        Self::from_wire(&value)
    }
}

impl From<DefinitionRevision> for String {
    fn from(revision: DefinitionRevision) -> Self {
        revision.0
    }
}

/// Capabilities that change lowering, and therefore enter the plan identity.
///
/// Tags are namespaced (`vendor.example/render`) and the set is canonical:
/// sorted, deduplicated, and validated, so two callers that declare the same
/// capabilities in a different order form one identity. The set is deliberately
/// conservative — a capability that turns out not to change lowering costs a
/// duplicate entry, while omitting one that does would serve a wrong plan.
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "Vec<String>", into = "Vec<String>")]
pub struct LoweringCapabilities(BTreeSet<String>);

impl LoweringCapabilities {
    /// No declaration: a plan whose lowering depends on nothing optional.
    pub fn none() -> Self {
        Self(BTreeSet::new())
    }

    /// Declare lowering-relevant capabilities. Order does not matter; tags are
    /// validated and canonicalized.
    pub fn declare<I, S>(tags: I) -> std::result::Result<Self, PlanInputError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut declared = BTreeSet::new();
        for tag in tags {
            declared.insert(validate_capability(tag.as_ref())?.to_owned());
        }
        Ok(Self(declared))
    }

    pub fn contains(&self, tag: &str) -> bool {
        self.0.contains(tag)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(String::as_str)
    }

    /// The first capability this set requires that `other` does not declare.
    pub fn missing_from<'a>(&'a self, other: &Self) -> Option<&'a str> {
        self.0
            .iter()
            .find(|tag| !other.0.contains(*tag))
            .map(String::as_str)
    }
}

impl TryFrom<Vec<String>> for LoweringCapabilities {
    type Error = PlanInputError;

    fn try_from(values: Vec<String>) -> std::result::Result<Self, Self::Error> {
        Self::declare(values)
    }
}

impl From<LoweringCapabilities> for Vec<String> {
    fn from(capabilities: LoweringCapabilities) -> Self {
        capabilities.0.into_iter().collect()
    }
}

/// The identity of one lowered plan: every input that determines it.
///
/// The three semantics of the contract are separate fields, so an entry lowered
/// under one engine semantics can never be served under another, and a caller
/// cannot reach a key by hashing something: the fields are typed values, not
/// strings to concatenate.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlanKey {
    definition_revision: DefinitionRevision,
    compiler_semantics: CompilerSemantics,
    engine_semantics: EngineSemantics,
    lowering_capabilities: LoweringCapabilities,
}

impl PlanKey {
    pub fn new(
        definition_revision: DefinitionRevision,
        compiler_semantics: CompilerSemantics,
        engine_semantics: EngineSemantics,
        lowering_capabilities: LoweringCapabilities,
    ) -> Self {
        Self {
            definition_revision,
            compiler_semantics,
            engine_semantics,
            lowering_capabilities,
        }
    }

    /// The key one definition has under one semantics configuration.
    pub fn for_definition(
        definition: &WorkflowDefinition,
        compiler_semantics: CompilerSemantics,
        engine_semantics: EngineSemantics,
        lowering_capabilities: LoweringCapabilities,
    ) -> std::result::Result<Self, PlanInputError> {
        Ok(Self::new(
            DefinitionRevision::of(definition)?,
            compiler_semantics,
            engine_semantics,
            lowering_capabilities,
        ))
    }

    pub fn definition_revision(&self) -> &DefinitionRevision {
        &self.definition_revision
    }

    pub fn compiler_semantics(&self) -> CompilerSemantics {
        self.compiler_semantics
    }

    pub fn engine_semantics(&self) -> EngineSemantics {
        self.engine_semantics
    }

    pub fn lowering_capabilities(&self) -> &LoweringCapabilities {
        &self.lowering_capabilities
    }

    /// The canonical encoding of every field, in fixed order, under the
    /// binding-identity schema `identity` binds. Validated tags cannot contain
    /// the separators, so the encoding is unambiguous.
    pub fn canonical_bytes(&self, identity: &PlanIdentity) -> Vec<u8> {
        let capabilities = self
            .lowering_capabilities
            .iter()
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{}\0revision\0{}\0compiler\0{}\0engine\0{}\0capabilities\0{}\0",
            identity.plan_key_schema,
            self.definition_revision.as_str(),
            self.compiler_semantics.version_of(),
            self.engine_semantics.version_of(),
            capabilities
        )
        .into_bytes()
    }

    /// The stable identity of this plan under `identity`'s lines.
    ///
    /// It is derived from the key alone, so rebuilding a plan that a cache
    /// evicted reproduces this value instead of minting a new one, and a run
    /// bound to it stays bound. Two identities digest the same key differently
    /// on purpose: their persisted records must never alias.
    pub fn binding_digest(&self, identity: &PlanIdentity) -> String {
        sha256_hex(&self.canonical_bytes(identity))
    }
}

/// A plan binding as a checkpoint recorded it: untrusted wire values.
///
/// This is what an older build wrote and what a store reads back. Typing it is
/// the boundary where "the recorded value is a version of the line it claims"
/// is established, so a definition digest recorded in a semantics slot is
/// refused here rather than silently reused as a version.
///
/// Every field is part of the identity, so none of them is optional: a record
/// that omits one is not completed with an assumed default, it is refused.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordedPlanKey {
    pub definition_revision: String,
    pub compiler_semantics: String,
    pub engine_semantics: String,
    pub lowering_capabilities: Vec<String>,
}

impl RecordedPlanKey {
    /// The recorded form of `key` under `identity`'s lines — this is what a
    /// checkpoint persists, so the lines are the host's own vocabulary.
    pub fn record(key: &PlanKey, identity: &PlanIdentity) -> Self {
        Self {
            definition_revision: key.definition_revision().as_str().to_owned(),
            compiler_semantics: key.compiler_semantics().wire(identity),
            engine_semantics: key.engine_semantics().wire(identity),
            lowering_capabilities: key
                .lowering_capabilities()
                .iter()
                .map(str::to_owned)
                .collect(),
        }
    }

    /// Type the record under `identity`'s lines. A record that declares a
    /// different line is refused rather than reinterpreted.
    pub fn typed(&self, identity: &PlanIdentity) -> std::result::Result<PlanKey, PlanInputError> {
        Ok(PlanKey::new(
            DefinitionRevision::from_wire(&self.definition_revision)?,
            CompilerSemantics::from_wire(identity, &self.compiler_semantics)?,
            EngineSemantics::from_wire(identity, &self.engine_semantics)?,
            LoweringCapabilities::declare(self.lowering_capabilities.iter().map(String::as_str))?,
        ))
    }
}

impl From<&PlanKey> for RecordedPlanKey {
    /// Records under Acativa's own identity lines. A host binding other lines
    /// calls [`RecordedPlanKey::record`] with its `PlanIdentity`.
    fn from(key: &PlanKey) -> Self {
        Self::record(key, &ACATIVA_PLAN_IDENTITY)
    }
}

/// What one interpreter can lower and what it may advance.
///
/// A profile is a *configuration of this build*, not a second implementation:
/// it declares which semantics this process acts as. Two profiles that declare
/// the same semantics are interchangeable; one that declares an older version
/// is how a compatible interpreter is expressed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterpreterProfile {
    compiler_semantics: CompilerSemantics,
    engine_semantics: EngineSemantics,
    lowering_capabilities: LoweringCapabilities,
}

impl InterpreterProfile {
    pub fn new(
        compiler_semantics: CompilerSemantics,
        engine_semantics: EngineSemantics,
        lowering_capabilities: LoweringCapabilities,
    ) -> Self {
        Self {
            compiler_semantics,
            engine_semantics,
            lowering_capabilities,
        }
    }

    /// The semantics this build lowers and executes.
    pub fn current(lowering_capabilities: LoweringCapabilities) -> Self {
        Self::new(
            CompilerSemantics::CURRENT,
            EngineSemantics::CURRENT,
            lowering_capabilities,
        )
    }

    pub fn compiler_semantics(&self) -> CompilerSemantics {
        self.compiler_semantics
    }

    pub fn engine_semantics(&self) -> EngineSemantics {
        self.engine_semantics
    }

    pub fn lowering_capabilities(&self) -> &LoweringCapabilities {
        &self.lowering_capabilities
    }

    /// The key one definition revision has under this profile.
    pub fn key_for(&self, definition_revision: DefinitionRevision) -> PlanKey {
        PlanKey::new(
            definition_revision,
            self.compiler_semantics,
            self.engine_semantics,
            self.lowering_capabilities.clone(),
        )
    }

    /// Whether this profile can lower a plan for `key`.
    ///
    /// Lowering is a function of the definition, the compiler semantics, and
    /// the declared capabilities. The engine semantics travels in the key so
    /// identities never alias, and decides run admission instead: an index is
    /// still the index of its definition, but the run bound to it may not be
    /// advanced here.
    pub fn lowerable(&self, key: &PlanKey) -> std::result::Result<(), LoweringRefusal> {
        if key.compiler_semantics() != self.compiler_semantics {
            return Err(LoweringRefusal::CompilerSemantics {
                build: self.compiler_semantics,
                bound: key.compiler_semantics(),
            });
        }
        match key
            .lowering_capabilities()
            .missing_from(&self.lowering_capabilities)
        {
            Some(capability) => Err(LoweringRefusal::MissingCapability {
                capability: capability.to_owned(),
            }),
            None => Ok(()),
        }
    }

    /// Whether this profile may advance a run bound to `key`.
    pub fn admit_run(&self, bound: &PlanKey) -> RunAdmission {
        if let Some(capability) = bound
            .lowering_capabilities()
            .missing_from(&self.lowering_capabilities)
        {
            return RunAdmission::MissingCapability {
                capability: capability.to_owned(),
            };
        }
        if bound.compiler_semantics() != self.compiler_semantics {
            return RunAdmission::Handoff {
                reason: HandoffReason::CompilerSemantics,
            };
        }
        if bound.engine_semantics() != self.engine_semantics {
            return RunAdmission::Handoff {
                reason: HandoffReason::EngineSemantics,
            };
        }
        RunAdmission::Compatible
    }

    /// Whether this profile may advance a run from the binding a checkpoint
    /// recorded, typed under `identity`'s lines. A record that cannot be typed
    /// — including one declaring a line `identity` does not bind — is handed
    /// off: an unprovable binding is never reinterpreted as this profile's
    /// semantics.
    pub fn admit_recorded(
        &self,
        recorded: &RecordedPlanKey,
        identity: &PlanIdentity,
    ) -> RunAdmission {
        match recorded.typed(identity) {
            Ok(key) => self.admit_run(&key),
            Err(_) => RunAdmission::Handoff {
                reason: HandoffReason::UnprovenSemantics,
            },
        }
    }
}

/// Why a profile cannot lower a plan for a key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LoweringRefusal {
    /// The plan's indices are only meaningful under the lowering that produced
    /// them, and this profile lowers other semantics.
    CompilerSemantics {
        build: CompilerSemantics,
        bound: CompilerSemantics,
    },
    /// The plan needs a lowering capability this profile does not declare.
    MissingCapability { capability: String },
}

impl Display for LoweringRefusal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CompilerSemantics { build, bound } => write!(
                formatter,
                "plan_compiler_semantics_mismatch: build {} bound {}",
                build.version_of(),
                bound.version_of()
            ),
            Self::MissingCapability { capability } => {
                write!(formatter, "plan_capability_missing: {capability}")
            }
        }
    }
}

impl std::error::Error for LoweringRefusal {}

/// What may happen to a run bound to one plan key.
///
/// `Handoff` means this build must not advance the run. The run continues on
/// exactly one of the three paths the causal-input contract permits — a
/// compatible interpreter that declares the bound semantics, a migration whose
/// tests cover them, or the previous instance until a safe handover point — and
/// is never advanced here under semantics it was not bound to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RunAdmission {
    Compatible,
    /// The run's plan needs a capability this profile does not declare. The
    /// run is not reinterpreted: the capability is provisioned, or the run is
    /// handed off.
    MissingCapability {
        capability: String,
    },
    Handoff {
        reason: HandoffReason,
    },
}

/// Why a run cannot be advanced here. The reason names the input that changed,
/// not the path chosen for it: which of the three permitted paths applies is an
/// operator decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandoffReason {
    CompilerSemantics,
    EngineSemantics,
    /// The recorded binding cannot be matched to a version this build declares.
    UnprovenSemantics,
}

/// What a store persists for a plan: the definition and its binding identity.
///
/// This is deliberately not a serialized plan. The lowered form is an index
/// over the definition, it is rebuilt on load, and keeping a second compiled
/// copy — on disk or anywhere else — would create a second authority that can
/// drift from the definition it claims to describe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedPlan {
    definition: WorkflowDefinition,
    key: PlanKey,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RetainedPlanWire {
    definition: WorkflowDefinition,
    key: PlanKey,
}

impl RetainedPlan {
    /// Pair a lowered plan with the key it was lowered for.
    ///
    /// The pair is checked against itself here, which is what makes it
    /// impossible to file a plan under a key that describes a different
    /// definition: a plan served under a key must be that key's plan.
    pub fn of(
        compiled: &CompiledWorkflow,
        key: PlanKey,
    ) -> std::result::Result<Self, PlanMismatch> {
        Self::pair(compiled.definition().clone(), key)
    }

    pub fn definition(&self) -> &WorkflowDefinition {
        &self.definition
    }

    pub fn key(&self) -> &PlanKey {
        &self.key
    }

    /// The identity a run stays bound to, whether the lowered form exists now
    /// or has to be rebuilt, digested under `identity`'s lines.
    pub fn binding_digest(&self, identity: &PlanIdentity) -> String {
        self.key.binding_digest(identity)
    }

    /// The canonical bytes a store persists.
    pub fn to_wire_bytes(&self) -> std::result::Result<Vec<u8>, PlanMismatch> {
        serde_json::to_vec(&RetainedPlanWire {
            definition: self.definition.clone(),
            key: self.key.clone(),
        })
        .map_err(|error| PlanMismatch::from(PlanInputError::PlanEncoding(error)))
    }

    /// Bytes this plan charges a cache that retains it.
    pub fn retained_bytes(&self) -> std::result::Result<usize, PlanMismatch> {
        self.to_wire_bytes().map(|bytes| bytes.len())
    }

    /// Read back what a store persisted, checking the pair before accepting it
    /// so a drifted store cannot fabricate a binding identity.
    pub fn from_wire_bytes(bytes: &[u8]) -> std::result::Result<Self, PlanMismatch> {
        let wire: RetainedPlanWire = serde_json::from_slice(bytes)
            .map_err(|error| PlanMismatch::from(PlanInputError::PlanEncoding(error)))?;
        Self::pair(wire.definition, wire.key)
    }

    /// Rebuild the authority: lower the retained definition again.
    ///
    /// Lowering is this build's compiler, so the caller admits the key first:
    /// a key bound to compiler semantics this build does not implement is
    /// handed off rather than rebuilt here. `supported_schema` is the same
    /// host-bound schema identity the original lowering was admitted under.
    pub fn rebuild(
        &self,
        supported_schema: &crate::SchemaId,
    ) -> std::result::Result<CompiledWorkflow, crate::WorkflowValidationFailure> {
        crate::compile_workflow(self.definition.clone(), supported_schema)
    }

    fn pair(
        definition: WorkflowDefinition,
        key: PlanKey,
    ) -> std::result::Result<Self, PlanMismatch> {
        let actual = DefinitionRevision::of(&definition)?;
        if actual != *key.definition_revision() {
            return Err(PlanMismatch::RevisionDrift {
                recorded: key.definition_revision().as_str().to_owned(),
                actual: actual.as_str().to_owned(),
            });
        }
        Ok(Self { definition, key })
    }
}

/// Why a plan and its recorded identity do not agree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlanMismatch {
    /// The definition's digest is not the revision the key records.
    RevisionDrift { recorded: String, actual: String },
    /// The canonical plan encoding could not be produced or read.
    PlanEncoding { message: String },
}

/// Why a plan input could not be built from its recorded form.
#[derive(Debug)]
pub enum PlanInputError {
    /// A semantics value is not a version of the line that owns it. A content
    /// digest is the usual case: it is not a version.
    SemanticsVersion { line: &'static str, value: String },
    /// A definition revision is not the digest of a definition.
    DefinitionRevision { value: String },
    /// A lowering capability is not a namespaced tag.
    LoweringCapability { value: String },
    /// The canonical plan encoding could not be produced or read.
    PlanEncoding(serde_json::Error),
}

impl Display for PlanInputError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SemanticsVersion { line, value } => {
                write!(
                    formatter,
                    "plan_semantics_version_invalid: {line} does not own {value}"
                )
            }
            Self::DefinitionRevision { value } => {
                write!(formatter, "plan_definition_revision_invalid: {value}")
            }
            Self::LoweringCapability { value } => {
                write!(formatter, "plan_lowering_capability_invalid: {value}")
            }
            Self::PlanEncoding(error) => write!(formatter, "plan_encoding_invalid: {error}"),
        }
    }
}

impl std::error::Error for PlanInputError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::PlanEncoding(error) => Some(error),
            _ => None,
        }
    }
}

impl Display for PlanMismatch {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RevisionDrift { recorded, actual } => {
                write!(
                    formatter,
                    "plan_revision_drift: recorded {recorded} actual {actual}"
                )
            }
            Self::PlanEncoding { message } => write!(formatter, "plan_encoding_invalid: {message}"),
        }
    }
}

impl std::error::Error for PlanMismatch {}

impl From<PlanInputError> for PlanMismatch {
    fn from(error: PlanInputError) -> Self {
        Self::PlanEncoding {
            message: error.to_string(),
        }
    }
}

/// A version of `line` at or below the version this build implements.
fn semantics_version(
    line: &'static str,
    current: u16,
    version: u16,
) -> std::result::Result<u16, PlanInputError> {
    if version > current {
        return Err(PlanInputError::SemanticsVersion {
            line,
            value: version.to_string(),
        });
    }
    Ok(version)
}

fn semantics_wire(line: &str, version: u16) -> String {
    format!("{line}.v{version}")
}

fn parse_semantics_wire(
    line: &'static str,
    current: u16,
    value: &str,
) -> std::result::Result<u16, PlanInputError> {
    let invalid = || PlanInputError::SemanticsVersion {
        line,
        value: clipped(value).to_owned(),
    };
    let version = value
        .strip_prefix(line)
        .and_then(|rest| rest.strip_prefix(".v"))
        .and_then(|version| version.parse::<u16>().ok())
        .ok_or_else(invalid)?;
    semantics_version(line, current, version).map_err(|_| invalid())
}

fn validate_capability(tag: &str) -> std::result::Result<&str, PlanInputError> {
    let invalid = || PlanInputError::LoweringCapability {
        value: clipped(tag).to_owned(),
    };
    if tag.is_empty() || tag.len() > MAX_CAPABILITY_LENGTH {
        return Err(invalid());
    }
    let Some((namespace, name)) = tag.split_once('/') else {
        return Err(invalid());
    };
    if !valid_namespace(namespace) || !valid_capability_name(name) {
        return Err(invalid());
    }
    Ok(tag)
}

fn valid_namespace(namespace: &str) -> bool {
    namespace.contains('.')
        && namespace.split('.').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

fn valid_capability_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
}

fn clipped(value: &str) -> &str {
    match value.char_indices().nth(MAX_ECHOED_VALUE) {
        Some((index, _)) => &value[..index],
        None => value,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn guard_matches(guard: &GuardExpression, payload: &serde_json::Value) -> bool {
    let value = guard
        .path
        .split('.')
        .filter(|part| !part.is_empty())
        .try_fold(payload, |value, part| value.get(part));
    if guard.exists && value.is_none() {
        return false;
    }
    guard
        .equals
        .as_ref()
        .is_none_or(|expected| value == Some(expected))
}

pub(super) fn valid_instruction(value: &str) -> bool {
    value == value.trim()
        && !value.is_empty()
        && value.len() <= 16 * 1024
        && !value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ActorSlot, GraphStateKind, RetryPolicy, TransitionMode, WorkflowLimits, WorkflowMetadata,
    };
    use serde_json::Value;

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

    fn workflow(states: Vec<GraphState>, transitions: Vec<Transition>) -> WorkflowDefinition {
        WorkflowDefinition {
            schema: crate::GENERIC_WORKFLOW_SCHEMA.into(),
            metadata: WorkflowMetadata {
                id: "test.workflow".into(),
                name: "Test".into(),
                version: "1".into(),
                description: String::new(),
            },
            limits: WorkflowLimits::default(),
            actor_slots: vec![],
            runtimes: vec![],
            worksets: vec![],
            initial: states[0].id.clone(),
            states,
            transitions,
        }
    }

    #[test]
    fn compiles_pipeline_in_linear_time_indexes() {
        let compiled = compile_workflow(workflow(
            vec![
                state("start", GraphStateKind::Pass),
                state("done", GraphStateKind::Succeed),
            ],
            vec![Transition {
                id: "finish".into(),
                from: "start".into(),
                to: "done".into(),
                event: TransitionEvent::Complete,
                mode: TransitionMode::Flow,
                guard: None,
            }],
        ))
        .unwrap();
        assert_eq!(compiled.reachable().len(), 2);
        assert_eq!(
            compiled
                .transitions("start", TransitionEvent::Complete)
                .count(),
            1
        );
    }

    #[test]
    fn transition_mode_defaults_to_flow_and_rejects_unknown_values() {
        let transition = |mode: Option<&str>| {
            let mut value = serde_json::json!({
                "id": "next",
                "from": "start",
                "to": "done",
                "event": "complete"
            });
            if let Some(mode) = mode {
                value["mode"] = mode.into();
            }
            serde_json::from_value::<Transition>(value)
        };
        assert_eq!(transition(None).unwrap().mode, TransitionMode::Flow);
        assert_eq!(transition(Some("flow")).unwrap().mode, TransitionMode::Flow);
        assert_eq!(
            transition(Some("callback")).unwrap().mode,
            TransitionMode::Callback
        );
        assert!(transition(Some("warp")).is_err(), "unknown mode decodes");
        // Flow is the canonical default: it never lands in the stored bytes.
        let serialized = serde_json::to_value(transition(None).unwrap()).unwrap();
        assert!(serialized.get("mode").is_none());
        let serialized = serde_json::to_value(transition(Some("callback")).unwrap()).unwrap();
        assert_eq!(serialized["mode"], "callback");
    }

    #[test]
    fn flow_mode_targets_may_not_leave_actor_binding_empty() {
        let build = |entry_mode: TransitionMode| {
            let mut definition = workflow(
                vec![
                    state("start", GraphStateKind::Pass),
                    state("review", GraphStateKind::Actor),
                    state("done", GraphStateKind::Succeed),
                ],
                vec![
                    Transition {
                        id: "begin".into(),
                        from: "start".into(),
                        to: "review".into(),
                        event: TransitionEvent::Complete,
                        mode: entry_mode,
                        guard: None,
                    },
                    Transition {
                        id: "reviewed".into(),
                        from: "review".into(),
                        to: "done".into(),
                        event: TransitionEvent::Success,
                        mode: TransitionMode::Flow,
                        guard: None,
                    },
                    Transition {
                        id: "review-failed".into(),
                        from: "review".into(),
                        to: "done".into(),
                        event: TransitionEvent::Failure,
                        mode: TransitionMode::Flow,
                        guard: None,
                    },
                ],
            );
            definition.actor_slots = vec![ActorSlot::required_actor("worker", "Worker")];
            definition
        };
        // A callback-only target may defer its binding to the decider settlement.
        assert!(compile_workflow(build(TransitionMode::Callback)).is_ok());
        // A flow-entered actor state may not leave its binding empty: no
        // decider fills parameters on the flow path.
        let error = compile_workflow(build(TransitionMode::Flow)).unwrap_err();
        assert!(
            error.diagnostics.iter().any(|diagnostic| {
                diagnostic.code == crate::WorkflowDiagnosticCode::WorkflowFlowTargetIncomplete
            }),
            "flow target with empty binding rejected with the rule: {error}"
        );
        let mut initial_actor = build(TransitionMode::Callback);
        initial_actor.initial = "review".into();
        let error = compile_workflow(initial_actor).unwrap_err();
        assert!(
            error.diagnostics.iter().any(|diagnostic| {
                diagnostic.code == crate::WorkflowDiagnosticCode::WorkflowFlowTargetIncomplete
            }),
            "the initial state is flow-entered: {error}"
        );
    }

    #[test]
    fn fork_branch_edges_must_stay_flow_mode() {
        let mut definition = workflow(
            vec![
                state("fork", GraphStateKind::Fork),
                state("branch-a", GraphStateKind::Pass),
                state("branch-b", GraphStateKind::Pass),
                state("join", GraphStateKind::Join),
                state("done", GraphStateKind::Succeed),
            ],
            vec![
                Transition {
                    id: "fa".into(),
                    from: "fork".into(),
                    to: "branch-a".into(),
                    event: TransitionEvent::Complete,
                    mode: TransitionMode::Callback,
                    guard: None,
                },
                Transition {
                    id: "fb".into(),
                    from: "fork".into(),
                    to: "branch-b".into(),
                    event: TransitionEvent::Complete,
                    mode: TransitionMode::Flow,
                    guard: None,
                },
                Transition {
                    id: "aj".into(),
                    from: "branch-a".into(),
                    to: "join".into(),
                    event: TransitionEvent::Complete,
                    mode: TransitionMode::Flow,
                    guard: None,
                },
                Transition {
                    id: "bj".into(),
                    from: "branch-b".into(),
                    to: "join".into(),
                    event: TransitionEvent::Complete,
                    mode: TransitionMode::Flow,
                    guard: None,
                },
                Transition {
                    id: "jd".into(),
                    from: "join".into(),
                    to: "done".into(),
                    event: TransitionEvent::Complete,
                    mode: TransitionMode::Flow,
                    guard: None,
                },
            ],
        );
        let error = compile_workflow(definition.clone()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("workflow_transition_mode_invalid"),
            "callback fan-out rejected: {error}"
        );
        definition.transitions[0].mode = TransitionMode::Flow;
        assert!(compile_workflow(definition).is_ok());
    }

    #[test]
    fn actor_graphs_require_exactly_one_declared_entry() {
        let mut definition = workflow(
            vec![
                state("start", GraphStateKind::Pass),
                state("done", GraphStateKind::Succeed),
            ],
            vec![Transition {
                id: "finish".into(),
                from: "start".into(),
                to: "done".into(),
                event: TransitionEvent::Complete,
                mode: TransitionMode::Flow,
                guard: None,
            }],
        );
        definition.actor_slots = vec![ActorSlot::required_actor("entry", "Entry"), {
            let mut slot = ActorSlot::required_actor("worker-a", "Worker");
            slot.entry = false;
            slot
        }];
        definition.actor_slots[0].entry = false;
        assert!(compile_workflow(definition.clone()).is_err());
        definition.actor_slots[1].entry = true;
        definition.actor_slots[0].entry = true;
        assert!(compile_workflow(definition).is_err());
    }

    #[test]
    fn rejects_effect_free_cycle() {
        let result = compile_workflow(workflow(
            vec![
                state("first", GraphStateKind::Choice),
                state("second", GraphStateKind::Choice),
                state("done", GraphStateKind::Succeed),
            ],
            vec![
                Transition {
                    id: "a".into(),
                    from: "first".into(),
                    to: "second".into(),
                    event: TransitionEvent::Complete,
                    mode: TransitionMode::Flow,
                    guard: None,
                },
                Transition {
                    id: "b".into(),
                    from: "second".into(),
                    to: "first".into(),
                    event: TransitionEvent::Complete,
                    mode: TransitionMode::Flow,
                    guard: Some(GuardExpression {
                        path: "loop".into(),
                        equals: Some(true.into()),
                        exists: false,
                    }),
                },
                Transition {
                    id: "c".into(),
                    from: "second".into(),
                    to: "done".into(),
                    event: TransitionEvent::Complete,
                    mode: TransitionMode::Flow,
                    guard: None,
                },
            ],
        ));
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("workflow_effect_cycle")
        );
    }

    #[test]
    fn rejects_unknown_transition_events() {
        let json = serde_json::json!({
            "schema": crate::GENERIC_WORKFLOW_SCHEMA,
            "metadata": {
                "id": "test.workflow",
                "name": "Test",
                "version": "1",
                "description": ""
            },
            "limits": {},
            "actorSlots": [],
            "runtimes": [],
            "worksets": [],
            "initial": "start",
            "states": [
                {"id": "start", "kind": "pass", "label": "start", "retry": {}},
                {"id": "done", "kind": "succeed", "label": "done", "retry": {}}
            ],
            "transitions": [
                {"id": "next", "from": "start", "to": "done", "event": "jump"}
            ]
        });
        let decoded = serde_json::from_value::<WorkflowDefinition>(json);
        assert!(decoded.is_err(), "unknown event decoded: {decoded:?}");
        let definition = serde_json::from_value::<WorkflowDefinition>(serde_json::json!({
            "schema": crate::GENERIC_WORKFLOW_SCHEMA,
            "metadata": {
                "id": "test.workflow",
                "name": "Test",
                "version": "1",
                "description": ""
            },
            "limits": {},
            "actorSlots": [],
            "runtimes": [],
            "worksets": [],
            "initial": "start",
            "states": [
                {"id": "start", "kind": "pass", "label": "start", "retry": {}},
                {"id": "done", "kind": "succeed", "label": "done", "retry": {}}
            ],
            "transitions": [
                {"id": "next", "from": "start", "to": "done", "event": "complete"}
            ]
        }))
        .unwrap();
        assert_eq!(definition.transitions[0].event, TransitionEvent::Complete);
    }

    #[test]
    fn guard_partitions_require_fallback_and_same_path_equality() {
        let choice = |guards: Vec<GuardExpression>| {
            let mut transitions = guards
                .into_iter()
                .enumerate()
                .map(|(index, guard)| Transition {
                    id: format!("guard-{index}"),
                    from: "pick".into(),
                    to: "done".into(),
                    event: TransitionEvent::Complete,
                    mode: TransitionMode::Flow,
                    guard: Some(guard),
                })
                .collect::<Vec<_>>();
            transitions.push(Transition {
                id: "fallback".into(),
                from: "pick".into(),
                to: "done".into(),
                event: TransitionEvent::Complete,
                mode: TransitionMode::Flow,
                guard: None,
            });
            workflow(
                vec![
                    state("pick", GraphStateKind::Choice),
                    state("done", GraphStateKind::Succeed),
                ],
                transitions,
            )
        };
        let guard = |path: &str, value: Option<Value>, exists: bool| GuardExpression {
            path: path.into(),
            equals: value,
            exists,
        };
        assert!(compile_workflow(choice(vec![guard("mode", Some("fast".into()), false)])).is_ok());
        assert!(
            compile_workflow(choice(vec![
                guard("mode", Some("fast".into()), false),
                guard("other", Some("fast".into()), false),
            ]))
            .unwrap_err()
            .to_string()
            .contains("workflow_guard_ambiguous")
        );
        assert!(
            compile_workflow(choice(vec![
                guard("mode", Some("fast".into()), false),
                guard("mode", Some("fast".into()), false),
            ]))
            .unwrap_err()
            .to_string()
            .contains("workflow_guard_ambiguous")
        );
        assert!(
            compile_workflow(choice(vec![
                guard("mode", Some("fast".into()), false),
                guard("mode", None, true),
            ]))
            .unwrap_err()
            .to_string()
            .contains("workflow_guard_ambiguous")
        );
        let missing_fallback = workflow(
            vec![
                state("pick", GraphStateKind::Choice),
                state("done", GraphStateKind::Succeed),
            ],
            vec![Transition {
                id: "only-guard".into(),
                from: "pick".into(),
                to: "done".into(),
                event: TransitionEvent::Complete,
                mode: TransitionMode::Flow,
                guard: Some(guard("mode", Some("fast".into()), false)),
            }],
        );
        assert!(
            compile_workflow(missing_fallback)
                .unwrap_err()
                .to_string()
                .contains("workflow_guard_ambiguous")
        );
    }

    #[test]
    fn effect_states_require_total_success_and_failure_routing() {
        let mut definition = workflow(
            vec![
                state("plan", GraphStateKind::Actor),
                state("done", GraphStateKind::Succeed),
            ],
            vec![Transition {
                id: "plan-ready".into(),
                from: "plan".into(),
                to: "done".into(),
                event: TransitionEvent::Success,
                mode: TransitionMode::Flow,
                guard: None,
            }],
        );
        definition.actor_slots = vec![ActorSlot::required_actor("entry", "Entry")];
        definition.states[0].binding = Some("entry".into());
        assert!(
            compile_workflow(definition.clone())
                .unwrap_err()
                .to_string()
                .contains("workflow_routing_invalid")
        );
        definition.transitions.push(Transition {
            id: "plan-failed".into(),
            from: "plan".into(),
            to: "done".into(),
            event: TransitionEvent::Failure,
            mode: TransitionMode::Flow,
            guard: None,
        });
        assert!(compile_workflow(definition).is_ok());
    }

    #[test]
    fn structured_fork_join_regions_compile() {
        let result = compile_workflow(workflow(
            vec![
                state("fork", GraphStateKind::Fork),
                state("branch-a", GraphStateKind::Pass),
                state("branch-b", GraphStateKind::Pass),
                state("join", GraphStateKind::Join),
                state("done", GraphStateKind::Succeed),
            ],
            vec![
                Transition {
                    id: "fa".into(),
                    from: "fork".into(),
                    to: "branch-a".into(),
                    event: TransitionEvent::Complete,
                    mode: TransitionMode::Flow,
                    guard: None,
                },
                Transition {
                    id: "fb".into(),
                    from: "fork".into(),
                    to: "branch-b".into(),
                    event: TransitionEvent::Complete,
                    mode: TransitionMode::Flow,
                    guard: None,
                },
                Transition {
                    id: "aj".into(),
                    from: "branch-a".into(),
                    to: "join".into(),
                    event: TransitionEvent::Complete,
                    mode: TransitionMode::Flow,
                    guard: None,
                },
                Transition {
                    id: "bj".into(),
                    from: "branch-b".into(),
                    to: "join".into(),
                    event: TransitionEvent::Complete,
                    mode: TransitionMode::Flow,
                    guard: None,
                },
                Transition {
                    id: "jd".into(),
                    from: "join".into(),
                    to: "done".into(),
                    event: TransitionEvent::Complete,
                    mode: TransitionMode::Flow,
                    guard: None,
                },
            ],
        ));
        assert!(result.is_ok(), "structured fork/join rejected: {result:?}");
    }

    #[test]
    fn malformed_parallel_regions_are_rejected() {
        let base_states = || {
            vec![
                state("fork", GraphStateKind::Fork),
                state("branch-a", GraphStateKind::Pass),
                state("branch-b", GraphStateKind::Pass),
                state("join", GraphStateKind::Join),
                state("done", GraphStateKind::Succeed),
            ]
        };
        let base_edges = || {
            vec![
                Transition {
                    id: "fa".into(),
                    from: "fork".into(),
                    to: "branch-a".into(),
                    event: TransitionEvent::Complete,
                    mode: TransitionMode::Flow,
                    guard: None,
                },
                Transition {
                    id: "fb".into(),
                    from: "fork".into(),
                    to: "branch-b".into(),
                    event: TransitionEvent::Complete,
                    mode: TransitionMode::Flow,
                    guard: None,
                },
                Transition {
                    id: "aj".into(),
                    from: "branch-a".into(),
                    to: "join".into(),
                    event: TransitionEvent::Complete,
                    mode: TransitionMode::Flow,
                    guard: None,
                },
                Transition {
                    id: "bj".into(),
                    from: "branch-b".into(),
                    to: "join".into(),
                    event: TransitionEvent::Complete,
                    mode: TransitionMode::Flow,
                    guard: None,
                },
                Transition {
                    id: "jd".into(),
                    from: "join".into(),
                    to: "done".into(),
                    event: TransitionEvent::Complete,
                    mode: TransitionMode::Flow,
                    guard: None,
                },
            ]
        };
        let assert_rejected = |definition: WorkflowDefinition| {
            let states = definition
                .states
                .iter()
                .map(|state| state.id.clone())
                .collect::<Vec<_>>();
            let error = compile_workflow(definition).unwrap_err().to_string();
            assert!(
                error.contains("workflow_topology_invalid"),
                "malformed region accepted with error: {error}; states: {states:?}"
            );
        };
        let mut missing_join = base_states();
        missing_join[4] = state("done", GraphStateKind::Succeed);
        let mut edges = base_edges();
        edges[2] = Transition {
            id: "ad".into(),
            from: "branch-a".into(),
            to: "done".into(),
            event: TransitionEvent::Complete,
            mode: TransitionMode::Flow,
            guard: None,
        };
        assert_rejected(workflow(missing_join, edges));

        let shared = base_states();
        let mut edges = base_edges();
        edges[3] = Transition {
            id: "ba".into(),
            from: "branch-b".into(),
            to: "branch-a".into(),
            event: TransitionEvent::Complete,
            mode: TransitionMode::Flow,
            guard: None,
        };
        assert_rejected(workflow(shared, edges));

        let mut nested = base_states();
        nested.insert(3, state("nested-fork", GraphStateKind::Fork));
        let mut edges = base_edges();
        edges[1] = Transition {
            id: "fn".into(),
            from: "fork".into(),
            to: "nested-fork".into(),
            event: TransitionEvent::Complete,
            mode: TransitionMode::Flow,
            guard: None,
        };
        edges.push(Transition {
            id: "nj".into(),
            from: "nested-fork".into(),
            to: "join".into(),
            event: TransitionEvent::Complete,
            mode: TransitionMode::Flow,
            guard: None,
        });
        edges.push(Transition {
            id: "nb".into(),
            from: "nested-fork".into(),
            to: "branch-b".into(),
            event: TransitionEvent::Complete,
            mode: TransitionMode::Flow,
            guard: None,
        });
        assert_rejected(workflow(nested, edges));

        let mut terminal_branch = base_states();
        terminal_branch[2] = state("branch-terminal", GraphStateKind::Succeed);
        let mut edges = base_edges();
        edges[1] = Transition {
            id: "ft".into(),
            from: "fork".into(),
            to: "branch-terminal".into(),
            event: TransitionEvent::Complete,
            mode: TransitionMode::Flow,
            guard: None,
        };
        edges.remove(3);
        assert_rejected(workflow(terminal_branch, edges));

        let cyclic = base_states();
        let mut edges = base_edges();
        edges[2] = Transition {
            id: "ab".into(),
            from: "branch-a".into(),
            to: "branch-b".into(),
            event: TransitionEvent::Complete,
            mode: TransitionMode::Flow,
            guard: None,
        };
        edges[3] = Transition {
            id: "ba".into(),
            from: "branch-b".into(),
            to: "branch-a".into(),
            event: TransitionEvent::Complete,
            mode: TransitionMode::Flow,
            guard: None,
        };
        assert_rejected(workflow(cyclic, edges));

        let extra_predecessor = vec![
            state("choice", GraphStateKind::Choice),
            state("fork", GraphStateKind::Fork),
            state("branch-a", GraphStateKind::Pass),
            state("branch-b", GraphStateKind::Pass),
            state("join", GraphStateKind::Join),
            state("extra", GraphStateKind::Pass),
            state("done", GraphStateKind::Succeed),
        ];
        let edges = vec![
            Transition {
                id: "cf".into(),
                from: "choice".into(),
                to: "fork".into(),
                event: TransitionEvent::Complete,
                mode: TransitionMode::Flow,
                guard: Some(GuardExpression {
                    path: "mode".into(),
                    equals: Some("parallel".into()),
                    exists: false,
                }),
            },
            Transition {
                id: "ce".into(),
                from: "choice".into(),
                to: "extra".into(),
                event: TransitionEvent::Complete,
                mode: TransitionMode::Flow,
                guard: None,
            },
            Transition {
                id: "fa".into(),
                from: "fork".into(),
                to: "branch-a".into(),
                event: TransitionEvent::Complete,
                mode: TransitionMode::Flow,
                guard: None,
            },
            Transition {
                id: "fb".into(),
                from: "fork".into(),
                to: "branch-b".into(),
                event: TransitionEvent::Complete,
                mode: TransitionMode::Flow,
                guard: None,
            },
            Transition {
                id: "aj".into(),
                from: "branch-a".into(),
                to: "join".into(),
                event: TransitionEvent::Complete,
                mode: TransitionMode::Flow,
                guard: None,
            },
            Transition {
                id: "bj".into(),
                from: "branch-b".into(),
                to: "join".into(),
                event: TransitionEvent::Complete,
                mode: TransitionMode::Flow,
                guard: None,
            },
            Transition {
                id: "ej".into(),
                from: "extra".into(),
                to: "join".into(),
                event: TransitionEvent::Complete,
                mode: TransitionMode::Flow,
                guard: None,
            },
            Transition {
                id: "jd".into(),
                from: "join".into(),
                to: "done".into(),
                event: TransitionEvent::Complete,
                mode: TransitionMode::Flow,
                guard: None,
            },
        ];
        assert_rejected(workflow(extra_predecessor, edges));

        let fork_only = workflow(
            vec![
                state("fork", GraphStateKind::Fork),
                state("branch-a", GraphStateKind::Pass),
                state("done", GraphStateKind::Succeed),
            ],
            vec![
                Transition {
                    id: "fa".into(),
                    from: "fork".into(),
                    to: "branch-a".into(),
                    event: TransitionEvent::Complete,
                    mode: TransitionMode::Flow,
                    guard: None,
                },
                Transition {
                    id: "ad".into(),
                    from: "branch-a".into(),
                    to: "done".into(),
                    event: TransitionEvent::Complete,
                    mode: TransitionMode::Flow,
                    guard: None,
                },
            ],
        );
        assert!(
            compile_workflow(fork_only)
                .unwrap_err()
                .to_string()
                .contains("workflow_routing_invalid")
        );
    }
}
