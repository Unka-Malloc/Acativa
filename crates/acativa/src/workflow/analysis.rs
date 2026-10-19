//! Privacy-safe, deterministic workflow validation.
//!
//! The raw-value pass owns schema shape and resource facts. Semantic passes
//! consume only a fully typed definition and gate reference/topology checks on
//! validity-tagged indexes so one malformed fact does not create cascades.

use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::{Display, Formatter};

use crate::compile::{CompiledWorkflow, compile_validated_workflow, valid_instruction};
use crate::diagnostic::{
    PreflightDiagnostic, WorkflowDiagnosticActualKind as ActualKind,
    WorkflowDiagnosticCode as Code, WorkflowDiagnosticExpected as Expected,
    WorkflowDiagnosticRecovery as Recovery, WorkflowDiagnosticStage as Stage,
};
use crate::syntax::{ParsedWorkflow, from_definition, parse, parse_value};
use crate::{
    BindingKind, GraphStateKind, MAX_ACTIVE_EFFECTS, MAX_BINDING_SLOTS, MAX_GRAPH_STATES,
    MAX_GRAPH_TRANSITIONS, MAX_RETRY_ATTEMPTS, MAX_RUNTIME_REQUIREMENTS, MAX_WORKSET_ITEMS,
    SchemaId, TransitionEvent, TransitionMode, WorkflowDefinition,
};

const MAX_DIAGNOSTICS: usize = 128;
const MAX_RELATED_PATHS: usize = 8;

#[derive(Clone, Debug)]
pub struct WorkflowValidation {
    pub definition: Option<WorkflowDefinition>,
    pub diagnostics: Vec<PreflightDiagnostic>,
}

#[derive(Clone, Debug)]
pub struct WorkflowValidationFailure {
    pub diagnostics: Vec<PreflightDiagnostic>,
}

/// A canonical definition that has passed the single semantic analysis pass.
/// Lowering is the only consumer of this phase marker.
#[derive(Clone, Debug)]
pub struct AnalyzedWorkflow {
    definition: WorkflowDefinition,
    source: Option<Value>,
}

impl AnalyzedWorkflow {
    pub(crate) fn into_definition(self) -> WorkflowDefinition {
        self.definition
    }

    pub fn source(&self) -> Option<&Value> {
        self.source.as_ref()
    }
}

impl Display for WorkflowValidationFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(
            self.diagnostics
                .first()
                .map_or("workflow_invalid", |diagnostic| diagnostic.code.wire()),
        )
    }
}

impl std::error::Error for WorkflowValidationFailure {}

pub fn compile_workflow_source(
    source: &[u8],
    supported_schema: &SchemaId,
) -> Result<CompiledWorkflow, WorkflowValidationFailure> {
    Ok(compile_validated_workflow(analyze(
        parse(source)?,
        supported_schema,
    )?))
}

pub fn compile_workflow_value(
    value: &Value,
    supported_schema: &SchemaId,
) -> Result<CompiledWorkflow, WorkflowValidationFailure> {
    Ok(compile_validated_workflow(analyze(
        parse_value(value)?,
        supported_schema,
    )?))
}

pub fn validate_workflow_value(value: &Value, supported_schema: &SchemaId) -> WorkflowValidation {
    match parse_value(value) {
        Ok(parsed) => {
            let definition = parsed.definition.clone();
            match analyze(parsed, supported_schema) {
                Ok(_) => WorkflowValidation {
                    definition: Some(definition),
                    diagnostics: Vec::new(),
                },
                Err(failure) => WorkflowValidation {
                    definition: Some(definition),
                    diagnostics: failure.diagnostics,
                },
            }
        }
        Err(failure) => WorkflowValidation {
            definition: None,
            diagnostics: failure.diagnostics,
        },
    }
}

pub fn analyze(
    parsed: ParsedWorkflow,
    supported_schema: &SchemaId,
) -> Result<AnalyzedWorkflow, WorkflowValidationFailure> {
    let mut diagnostics = parsed.diagnostics;
    collect_semantic_diagnostics(&parsed.definition, supported_schema, &mut diagnostics);
    normalize(&mut diagnostics);
    if diagnostics.is_empty() {
        Ok(AnalyzedWorkflow {
            definition: parsed.definition,
            source: parsed.source,
        })
    } else {
        Err(WorkflowValidationFailure { diagnostics })
    }
}

pub(crate) fn compile_workflow_definition(
    definition: WorkflowDefinition,
    supported_schema: &SchemaId,
) -> Result<CompiledWorkflow, WorkflowValidationFailure> {
    Ok(compile_validated_workflow(analyze(
        from_definition(definition),
        supported_schema,
    )?))
}

pub(crate) fn syntax_diagnostic(line: usize, column: usize) -> PreflightDiagnostic {
    let mut result = diagnostic(
        Code::WorkflowSyntaxInvalid,
        Stage::WorkflowParse,
        None,
        Recovery::CorrectField,
    );
    result.line = u64::try_from(line).ok();
    result.column = u64::try_from(column).ok();
    result.recovery = None;
    result
}

pub(crate) fn shape_diagnostic() -> PreflightDiagnostic {
    diagnostic(
        Code::WorkflowShapeInvalid,
        Stage::WorkflowParse,
        Some(""),
        Recovery::CorrectField,
    )
}

pub(crate) fn parse_diagnostics(value: &Value) -> Vec<PreflightDiagnostic> {
    let mut diagnostics = Vec::new();
    validate_raw_workflow(value, &mut diagnostics);
    normalize(&mut diagnostics);
    diagnostics
}

fn diagnostic(
    code: Code,
    stage: Stage,
    path: Option<&str>,
    recovery: Recovery,
) -> PreflightDiagnostic {
    PreflightDiagnostic {
        code,
        stage,
        path: path.map(str::to_owned),
        related_paths: Vec::new(),
        actual: None,
        limit: None,
        expected: None,
        actual_kind: None,
        recovery: Some(recovery),
        line: None,
        column: None,
    }
}

fn push(diagnostics: &mut Vec<PreflightDiagnostic>, value: PreflightDiagnostic) {
    if diagnostics.len() < MAX_DIAGNOSTICS {
        diagnostics.push(value);
    }
}

fn normalize(diagnostics: &mut Vec<PreflightDiagnostic>) {
    diagnostics.sort_by(|left, right| {
        left.stage
            .cmp(&right.stage)
            .then_with(|| left.path.cmp(&right.path))
            .then_with(|| left.code.cmp(&right.code))
            .then_with(|| left.related_paths.cmp(&right.related_paths))
    });
    diagnostics.dedup();
    diagnostics.truncate(MAX_DIAGNOSTICS);
}

fn actual_kind(value: &Value) -> ActualKind {
    match value {
        Value::Null => ActualKind::Null,
        Value::Bool(_) => ActualKind::Boolean,
        Value::Number(_) => ActualKind::Number,
        Value::String(_) => ActualKind::String,
        Value::Array(_) => ActualKind::Array,
        Value::Object(_) => ActualKind::Object,
    }
}

fn shape_error(
    diagnostics: &mut Vec<PreflightDiagnostic>,
    path: &str,
    expected: Expected,
    actual: ActualKind,
) {
    let mut value = diagnostic(
        Code::WorkflowFieldTypeInvalid,
        Stage::WorkflowParse,
        Some(path),
        Recovery::CorrectField,
    );
    value.expected = Some(expected);
    value.actual_kind = Some(actual);
    push(diagnostics, value);
}

fn value_error(
    diagnostics: &mut Vec<PreflightDiagnostic>,
    path: &str,
    expected: Expected,
    actual: ActualKind,
) {
    let mut value = diagnostic(
        Code::WorkflowFieldValueInvalid,
        Stage::WorkflowParse,
        Some(path),
        Recovery::CorrectField,
    );
    value.expected = Some(expected);
    value.actual_kind = Some(actual);
    push(diagnostics, value);
}

fn required_error(diagnostics: &mut Vec<PreflightDiagnostic>, path: &str) {
    let mut value = diagnostic(
        Code::WorkflowRequiredFieldMissing,
        Stage::WorkflowParse,
        Some(path),
        Recovery::AddRequiredField,
    );
    value.actual_kind = Some(ActualKind::Missing);
    push(diagnostics, value);
}

fn object<'a>(
    value: &'a Value,
    path: &str,
    allowed: &[&str],
    required: &[&str],
    diagnostics: &mut Vec<PreflightDiagnostic>,
) -> Option<&'a Map<String, Value>> {
    let Some(object) = value.as_object() else {
        shape_error(diagnostics, path, Expected::Object, actual_kind(value));
        return None;
    };
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        push(
            diagnostics,
            diagnostic(
                Code::WorkflowUnknownField,
                Stage::WorkflowParse,
                Some(path),
                Recovery::RemoveUnknownField,
            ),
        );
    }
    for field in required {
        if !object.contains_key(*field) {
            required_error(diagnostics, &join(path, field));
        }
    }
    Some(object)
}

fn array<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    path: &str,
    required: bool,
    diagnostics: &mut Vec<PreflightDiagnostic>,
) -> Option<&'a Vec<Value>> {
    match object.get(field) {
        Some(Value::Array(values)) => Some(values),
        Some(value) => {
            shape_error(diagnostics, path, Expected::Array, actual_kind(value));
            None
        }
        None if required => {
            required_error(diagnostics, path);
            None
        }
        None => None,
    }
}

fn string<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    path: &str,
    required: bool,
    diagnostics: &mut Vec<PreflightDiagnostic>,
) -> Option<&'a str> {
    match object.get(field) {
        Some(Value::String(value)) => Some(value),
        Some(value) => {
            shape_error(diagnostics, path, Expected::String, actual_kind(value));
            None
        }
        None if required => {
            required_error(diagnostics, path);
            None
        }
        None => None,
    }
}

fn boolean(
    object: &Map<String, Value>,
    field: &str,
    path: &str,
    diagnostics: &mut Vec<PreflightDiagnostic>,
) {
    if let Some(value) = object.get(field)
        && !value.is_boolean()
    {
        shape_error(diagnostics, path, Expected::Boolean, actual_kind(value));
    }
}

fn integer(
    object: &Map<String, Value>,
    field: &str,
    path: &str,
    maximum: u64,
    diagnostics: &mut Vec<PreflightDiagnostic>,
) {
    let Some(value) = object.get(field) else {
        return;
    };
    match value.as_u64() {
        Some(number) if number <= maximum => {}
        Some(number) => {
            let mut error = diagnostic(
                Code::WorkflowFieldValueInvalid,
                Stage::WorkflowParse,
                Some(path),
                Recovery::CorrectField,
            );
            error.expected = Some(Expected::Integer);
            error.actual_kind = Some(ActualKind::Number);
            error.actual = Some(number);
            error.limit = Some(maximum);
            push(diagnostics, error);
        }
        None => shape_error(diagnostics, path, Expected::Integer, actual_kind(value)),
    }
}

fn enum_string(
    object: &Map<String, Value>,
    field: &str,
    path: &str,
    required: bool,
    allowed: &[&str],
    diagnostics: &mut Vec<PreflightDiagnostic>,
) {
    if let Some(value) = string(object, field, path, required, diagnostics)
        && !allowed.contains(&value)
    {
        value_error(diagnostics, path, Expected::EnumValue, ActualKind::String);
    }
}

fn join(parent: &str, field: &str) -> String {
    if parent.is_empty() {
        format!("/{field}")
    } else {
        format!("{parent}/{field}")
    }
}

fn validate_raw_workflow(value: &Value, diagnostics: &mut Vec<PreflightDiagnostic>) {
    let Some(root) = object(
        value,
        "",
        &[
            "schema",
            "metadata",
            "limits",
            "actorSlots",
            "runtimes",
            "worksets",
            "initial",
            "states",
            "transitions",
        ],
        &["schema", "metadata", "initial", "states", "transitions"],
        diagnostics,
    ) else {
        return;
    };
    string(root, "schema", "/schema", true, diagnostics);
    string(root, "initial", "/initial", true, diagnostics);

    if let Some(metadata) = root.get("metadata")
        && let Some(metadata) = object(
            metadata,
            "/metadata",
            &["id", "name", "version", "description"],
            &["id", "name", "version"],
            diagnostics,
        )
    {
        string(metadata, "id", "/metadata/id", true, diagnostics);
        string(metadata, "name", "/metadata/name", true, diagnostics);
        string(metadata, "version", "/metadata/version", true, diagnostics);
        string(
            metadata,
            "description",
            "/metadata/description",
            false,
            diagnostics,
        );
    }
    if let Some(limits) = root.get("limits")
        && let Some(limits) = object(
            limits,
            "/limits",
            &["maxParallelism", "maxWorksetItems", "maxAttempts"],
            &[],
            diagnostics,
        )
    {
        integer(
            limits,
            "maxParallelism",
            "/limits/maxParallelism",
            u8::MAX as u64,
            diagnostics,
        );
        integer(
            limits,
            "maxWorksetItems",
            "/limits/maxWorksetItems",
            u16::MAX as u64,
            diagnostics,
        );
        integer(
            limits,
            "maxAttempts",
            "/limits/maxAttempts",
            u8::MAX as u64,
            diagnostics,
        );
    }

    if let Some(values) = array(root, "actorSlots", "/actorSlots", false, diagnostics) {
        resource_limit(
            diagnostics,
            Code::WorkflowBindingLimit,
            "/actorSlots",
            values.len(),
            MAX_BINDING_SLOTS,
        );
        for (index, value) in values.iter().enumerate() {
            validate_raw_actor_slot(value, index, diagnostics);
        }
    }
    if let Some(values) = array(root, "runtimes", "/runtimes", false, diagnostics) {
        resource_limit(
            diagnostics,
            Code::WorkflowRuntimeLimit,
            "/runtimes",
            values.len(),
            MAX_RUNTIME_REQUIREMENTS,
        );
        for (index, value) in values.iter().enumerate() {
            validate_raw_runtime(value, index, diagnostics);
        }
    }
    if let Some(values) = array(root, "worksets", "/worksets", false, diagnostics) {
        for (index, value) in values.iter().enumerate() {
            validate_raw_workset(value, index, diagnostics);
        }
    }
    if let Some(values) = array(root, "states", "/states", true, diagnostics) {
        resource_range(
            diagnostics,
            Code::WorkflowStateLimit,
            "/states",
            values.len(),
            1,
            MAX_GRAPH_STATES,
        );
        for (index, value) in values.iter().enumerate() {
            validate_raw_state(value, index, diagnostics);
        }
    }
    if let Some(values) = array(root, "transitions", "/transitions", true, diagnostics) {
        resource_range(
            diagnostics,
            Code::WorkflowTransitionLimit,
            "/transitions",
            values.len(),
            1,
            MAX_GRAPH_TRANSITIONS,
        );
        for (index, value) in values.iter().enumerate() {
            validate_raw_transition(value, index, diagnostics);
        }
    }
}

fn validate_raw_actor_slot(
    value: &Value,
    index: usize,
    diagnostics: &mut Vec<PreflightDiagnostic>,
) {
    let path = format!("/actorSlots/{index}");
    let Some(slot) = object(
        value,
        &path,
        &[
            "id",
            "kind",
            "label",
            "required",
            "sessionPolicy",
            "entry",
            "fallback",
        ],
        &["id", "kind", "label"],
        diagnostics,
    ) else {
        return;
    };
    string(slot, "id", &join(&path, "id"), true, diagnostics);
    enum_string(
        slot,
        "kind",
        &join(&path, "kind"),
        true,
        &["actor", "runtime", "workspace"],
        diagnostics,
    );
    string(slot, "label", &join(&path, "label"), true, diagnostics);
    boolean(slot, "required", &join(&path, "required"), diagnostics);
    enum_string(
        slot,
        "sessionPolicy",
        &join(&path, "sessionPolicy"),
        false,
        &["new", "resume", "sticky"],
        diagnostics,
    );
    boolean(slot, "entry", &join(&path, "entry"), diagnostics);
    if let Some(fallback) = slot.get("fallback")
        && let Some(fallback) = object(
            fallback,
            &join(&path, "fallback"),
            &["afterTransientAttempts", "onQuota"],
            &[],
            diagnostics,
        )
    {
        integer(
            fallback,
            "afterTransientAttempts",
            &format!("{path}/fallback/afterTransientAttempts"),
            u8::MAX as u64,
            diagnostics,
        );
        boolean(
            fallback,
            "onQuota",
            &format!("{path}/fallback/onQuota"),
            diagnostics,
        );
    }
}

fn validate_raw_runtime(value: &Value, index: usize, diagnostics: &mut Vec<PreflightDiagnostic>) {
    let path = format!("/runtimes/{index}");
    let Some(runtime) = object(
        value,
        &path,
        &["id", "kind", "versionRequirement"],
        &["id", "kind"],
        diagnostics,
    ) else {
        return;
    };
    string(runtime, "id", &join(&path, "id"), true, diagnostics);
    // The runtime kind vocabulary is host-owned: any non-empty string names a
    // kind, so this layer checks shape only.
    string(runtime, "kind", &join(&path, "kind"), true, diagnostics);
    string(
        runtime,
        "versionRequirement",
        &join(&path, "versionRequirement"),
        false,
        diagnostics,
    );
}

fn validate_raw_workset(value: &Value, index: usize, diagnostics: &mut Vec<PreflightDiagnostic>) {
    let path = format!("/worksets/{index}");
    let Some(workset) = object(
        value,
        &path,
        &["id", "itemBinding", "predecessorField"],
        &["id", "itemBinding"],
        diagnostics,
    ) else {
        return;
    };
    string(workset, "id", &join(&path, "id"), true, diagnostics);
    string(
        workset,
        "itemBinding",
        &join(&path, "itemBinding"),
        true,
        diagnostics,
    );
    string(
        workset,
        "predecessorField",
        &join(&path, "predecessorField"),
        false,
        diagnostics,
    );
}

fn validate_raw_state(value: &Value, index: usize, diagnostics: &mut Vec<PreflightDiagnostic>) {
    let path = format!("/states/{index}");
    let Some(state) = object(
        value,
        &path,
        &[
            "id",
            "kind",
            "label",
            "instruction",
            "binding",
            "runtime",
            "entry",
            "workset",
            "retry",
        ],
        &["id", "kind", "label"],
        diagnostics,
    ) else {
        return;
    };
    string(state, "id", &join(&path, "id"), true, diagnostics);
    enum_string(
        state,
        "kind",
        &join(&path, "kind"),
        true,
        &[
            "pass",
            "choice",
            "fork",
            "join",
            "authorization",
            "actor",
            "script",
            "workset",
            "succeed",
            "fail",
            "blocked",
        ],
        diagnostics,
    );
    string(state, "label", &join(&path, "label"), true, diagnostics);
    for field in ["instruction", "binding", "runtime", "entry", "workset"] {
        string(state, field, &join(&path, field), false, diagnostics);
    }
    if let Some(retry) = state.get("retry")
        && let Some(retry) = object(
            retry,
            &join(&path, "retry"),
            &["maxAttempts", "transientOnly"],
            &[],
            diagnostics,
        )
    {
        integer(
            retry,
            "maxAttempts",
            &format!("{path}/retry/maxAttempts"),
            u8::MAX as u64,
            diagnostics,
        );
        boolean(
            retry,
            "transientOnly",
            &format!("{path}/retry/transientOnly"),
            diagnostics,
        );
    }
}

fn validate_raw_transition(
    value: &Value,
    index: usize,
    diagnostics: &mut Vec<PreflightDiagnostic>,
) {
    let path = format!("/transitions/{index}");
    let Some(transition) = object(
        value,
        &path,
        &["id", "from", "to", "event", "mode", "guard"],
        &["id", "from", "to", "event"],
        diagnostics,
    ) else {
        return;
    };
    for field in ["id", "from", "to"] {
        string(transition, field, &join(&path, field), true, diagnostics);
    }
    enum_string(
        transition,
        "event",
        &join(&path, "event"),
        true,
        &["complete", "success", "failure"],
        diagnostics,
    );
    enum_string(
        transition,
        "mode",
        &join(&path, "mode"),
        false,
        &["callback", "flow"],
        diagnostics,
    );
    if let Some(guard) = transition.get("guard")
        && let Some(guard) = object(
            guard,
            &join(&path, "guard"),
            &["path", "equals", "exists"],
            &["path"],
            diagnostics,
        )
    {
        string(
            guard,
            "path",
            &format!("{path}/guard/path"),
            true,
            diagnostics,
        );
        boolean(
            guard,
            "exists",
            &format!("{path}/guard/exists"),
            diagnostics,
        );
    }
}

fn resource_limit(
    diagnostics: &mut Vec<PreflightDiagnostic>,
    code: Code,
    path: &str,
    actual: usize,
    limit: usize,
) {
    if actual <= limit {
        return;
    }
    let mut value = diagnostic(
        code,
        Stage::WorkflowCompile,
        Some(path),
        Recovery::ReduceResource,
    );
    value.actual = Some(actual as u64);
    value.limit = Some(limit as u64);
    push(diagnostics, value);
}

fn resource_range(
    diagnostics: &mut Vec<PreflightDiagnostic>,
    code: Code,
    path: &str,
    actual: usize,
    minimum: usize,
    maximum: usize,
) {
    if (minimum..=maximum).contains(&actual) {
        return;
    }
    let mut value = diagnostic(
        code,
        Stage::WorkflowCompile,
        Some(path),
        Recovery::ReduceResource,
    );
    value.actual = Some(actual as u64);
    value.limit = Some(maximum as u64);
    push(diagnostics, value);
}

fn collect_semantic_diagnostics(
    definition: &WorkflowDefinition,
    supported_schema: &SchemaId,
    diagnostics: &mut Vec<PreflightDiagnostic>,
) {
    if !definition.has_supported_schema(supported_schema) {
        semantic_error(
            diagnostics,
            Code::WorkflowSchemaUnsupported,
            "/schema",
            Recovery::CorrectField,
            Expected::SupportedSchema,
        );
    }
    if !is_identifier(&definition.metadata.id) {
        semantic_error(
            diagnostics,
            Code::WorkflowMetadataIdInvalid,
            "/metadata/id",
            Recovery::CorrectField,
            Expected::Identifier,
        );
    }
    if !valid_text(&definition.metadata.name, 128) {
        semantic_error(
            diagnostics,
            Code::WorkflowMetadataNameInvalid,
            "/metadata/name",
            Recovery::CorrectField,
            Expected::NonEmptyText,
        );
    }
    if !valid_text(&definition.metadata.version, 64) {
        semantic_error(
            diagnostics,
            Code::WorkflowMetadataVersionInvalid,
            "/metadata/version",
            Recovery::CorrectField,
            Expected::NonEmptyText,
        );
    }
    resource_range(
        diagnostics,
        Code::WorkflowStateLimit,
        "/states",
        definition.states.len(),
        1,
        MAX_GRAPH_STATES,
    );
    resource_range(
        diagnostics,
        Code::WorkflowTransitionLimit,
        "/transitions",
        definition.transitions.len(),
        1,
        MAX_GRAPH_TRANSITIONS,
    );
    resource_limit(
        diagnostics,
        Code::WorkflowBindingLimit,
        "/actorSlots",
        definition.actor_slots.len(),
        MAX_BINDING_SLOTS,
    );
    resource_limit(
        diagnostics,
        Code::WorkflowRuntimeLimit,
        "/runtimes",
        definition.runtimes.len(),
        MAX_RUNTIME_REQUIREMENTS,
    );
    numeric_range(
        diagnostics,
        Code::WorkflowParallelismInvalid,
        "/limits/maxParallelism",
        definition.limits.max_parallelism as usize,
        1,
        MAX_ACTIVE_EFFECTS,
    );
    numeric_range(
        diagnostics,
        Code::WorkflowWorksetLimitInvalid,
        "/limits/maxWorksetItems",
        definition.limits.max_workset_items as usize,
        1,
        MAX_WORKSET_ITEMS,
    );
    numeric_range(
        diagnostics,
        Code::WorkflowRetryLimitInvalid,
        "/limits/maxAttempts",
        definition.limits.max_attempts as usize,
        1,
        MAX_RETRY_ATTEMPTS as usize,
    );

    let binding_counts = counts(definition.actor_slots.iter().map(|slot| slot.id.as_str()));
    let mut binding_slots = BTreeMap::new();
    let mut actor_entries = Vec::new();
    let actor_count = definition
        .actor_slots
        .iter()
        .filter(|slot| slot.kind == BindingKind::Actor)
        .count();
    for (index, slot) in definition.actor_slots.iter().enumerate() {
        let path = format!("/actorSlots/{index}");
        if !is_identifier(&slot.id) {
            semantic_error(
                diagnostics,
                Code::WorkflowBindingIdInvalid,
                &format!("{path}/id"),
                Recovery::CorrectField,
                Expected::Identifier,
            );
        } else if binding_counts.get(&slot.id).copied().unwrap_or(0) > 1 {
            let first = definition
                .actor_slots
                .iter()
                .position(|candidate| candidate.id == slot.id);
            if first != Some(index) {
                duplicate_error(
                    diagnostics,
                    Code::WorkflowBindingDuplicate,
                    &format!("{path}/id"),
                    first.map(|first| format!("/actorSlots/{first}/id")),
                );
            }
        } else {
            binding_slots.insert(slot.id.as_str(), slot);
        }
        if !valid_text(&slot.label, 128) {
            semantic_error(
                diagnostics,
                Code::WorkflowBindingLabelInvalid,
                &format!("{path}/label"),
                Recovery::CorrectField,
                Expected::NonEmptyText,
            );
        }
        if !(1..=MAX_RETRY_ATTEMPTS).contains(&slot.fallback.after_transient_attempts) {
            numeric_error(
                diagnostics,
                Code::WorkflowFallbackInvalid,
                &format!("{path}/fallback/afterTransientAttempts"),
                slot.fallback.after_transient_attempts as usize,
                MAX_RETRY_ATTEMPTS as usize,
            );
        }
        if slot.entry {
            if slot.kind == BindingKind::Actor {
                actor_entries.push(index);
            } else {
                semantic_error(
                    diagnostics,
                    Code::WorkflowEntrySlotInvalid,
                    &format!("{path}/entry"),
                    Recovery::CorrectField,
                    Expected::EnumValue,
                );
            }
        }
    }
    if actor_count > 0 && actor_entries.len() != 1 {
        let mut value = diagnostic(
            Code::WorkflowEntrySlotInvalid,
            Stage::WorkflowCompile,
            Some("/actorSlots"),
            Recovery::CorrectField,
        );
        value.related_paths = actor_entries
            .into_iter()
            .take(MAX_RELATED_PATHS)
            .map(|index| format!("/actorSlots/{index}/entry"))
            .collect();
        push(diagnostics, value);
    }

    let runtime_counts = counts(
        definition
            .runtimes
            .iter()
            .map(|runtime| runtime.id.as_str()),
    );
    let mut runtimes = BTreeSet::new();
    for (index, runtime) in definition.runtimes.iter().enumerate() {
        let path = format!("/runtimes/{index}");
        if !is_identifier(&runtime.id) {
            semantic_error(
                diagnostics,
                Code::WorkflowRuntimeIdInvalid,
                &format!("{path}/id"),
                Recovery::CorrectField,
                Expected::Identifier,
            );
        } else if runtime_counts.get(&runtime.id).copied().unwrap_or(0) > 1 {
            let first = definition
                .runtimes
                .iter()
                .position(|candidate| candidate.id == runtime.id);
            if first != Some(index) {
                duplicate_error(
                    diagnostics,
                    Code::WorkflowRuntimeIdInvalid,
                    &format!("{path}/id"),
                    first.map(|first| format!("/runtimes/{first}/id")),
                );
            }
        } else {
            runtimes.insert(runtime.id.as_str());
            let binding_invalid = match binding_slots.get(runtime.id.as_str()) {
                Some(slot) => slot.kind != BindingKind::Runtime || !slot.required,
                None => !binding_counts.contains_key(runtime.id.as_str()),
            };
            if binding_invalid {
                semantic_error(
                    diagnostics,
                    Code::WorkflowRuntimeBindingInvalid,
                    &format!("{path}/id"),
                    Recovery::CorrectReference,
                    Expected::ExistingReference,
                );
            }
        }
    }
    for (index, slot) in definition.actor_slots.iter().enumerate() {
        if slot.kind == BindingKind::Runtime
            && binding_counts.get(&slot.id).copied().unwrap_or(0) == 1
            && !runtimes.contains(slot.id.as_str())
            && !runtime_counts.contains_key(slot.id.as_str())
        {
            semantic_error(
                diagnostics,
                Code::WorkflowRuntimeBindingInvalid,
                &format!("/actorSlots/{index}/id"),
                Recovery::CorrectReference,
                Expected::ExistingReference,
            );
        }
    }

    let workset_counts = counts(
        definition
            .worksets
            .iter()
            .map(|workset| workset.id.as_str()),
    );
    let mut worksets = BTreeSet::new();
    for (index, workset) in definition.worksets.iter().enumerate() {
        let path = format!("/worksets/{index}");
        if !is_identifier(&workset.id) {
            semantic_error(
                diagnostics,
                Code::WorkflowWorksetIdInvalid,
                &format!("{path}/id"),
                Recovery::CorrectField,
                Expected::Identifier,
            );
        } else if workset_counts.get(&workset.id).copied().unwrap_or(0) > 1 {
            let first = definition
                .worksets
                .iter()
                .position(|candidate| candidate.id == workset.id);
            if first != Some(index) {
                duplicate_error(
                    diagnostics,
                    Code::WorkflowWorksetIdInvalid,
                    &format!("{path}/id"),
                    first.map(|first| format!("/worksets/{first}/id")),
                );
            }
        } else {
            worksets.insert(workset.id.as_str());
        }
        if !is_identifier(&workset.item_binding) {
            semantic_error(
                diagnostics,
                Code::WorkflowWorksetItemBindingInvalid,
                &format!("{path}/itemBinding"),
                Recovery::CorrectField,
                Expected::Identifier,
            );
        }
        if !workset.predecessor_field.is_empty() && !is_identifier(&workset.predecessor_field) {
            semantic_error(
                diagnostics,
                Code::WorkflowWorksetPredecessorFieldInvalid,
                &format!("{path}/predecessorField"),
                Recovery::CorrectField,
                Expected::Identifier,
            );
        }
        if !workset.predecessor_field.is_empty()
            && workset.predecessor_field == workset.item_binding
        {
            semantic_error(
                diagnostics,
                Code::WorkflowWorksetFieldConflict,
                &path,
                Recovery::CorrectField,
                Expected::UniqueId,
            );
        }
    }

    collect_state_and_transition_diagnostics(
        definition,
        &binding_slots,
        &binding_counts,
        &runtimes,
        &runtime_counts,
        &worksets,
        &workset_counts,
        diagnostics,
    );
}

#[allow(clippy::too_many_arguments)]
fn collect_state_and_transition_diagnostics(
    definition: &WorkflowDefinition,
    binding_slots: &BTreeMap<&str, &super::ActorSlot>,
    binding_counts: &BTreeMap<String, usize>,
    runtimes: &BTreeSet<&str>,
    runtime_counts: &BTreeMap<String, usize>,
    worksets: &BTreeSet<&str>,
    workset_counts: &BTreeMap<String, usize>,
    diagnostics: &mut Vec<PreflightDiagnostic>,
) {
    let flow_entered: BTreeSet<&str> = definition
        .transitions
        .iter()
        .filter(|transition| transition.mode == TransitionMode::Flow)
        .map(|transition| transition.to.as_str())
        .chain([definition.initial.as_str()])
        .collect();
    let state_counts = counts(definition.states.iter().map(|state| state.id.as_str()));
    let mut states = BTreeMap::new();
    for (index, state) in definition.states.iter().enumerate() {
        let path = format!("/states/{index}");
        if !is_identifier(&state.id) {
            semantic_error(
                diagnostics,
                Code::WorkflowStateIdInvalid,
                &format!("{path}/id"),
                Recovery::CorrectField,
                Expected::Identifier,
            );
        } else if state_counts.get(&state.id).copied().unwrap_or(0) > 1 {
            let first = definition
                .states
                .iter()
                .position(|candidate| candidate.id == state.id);
            if first != Some(index) {
                duplicate_error(
                    diagnostics,
                    Code::WorkflowStateDuplicate,
                    &format!("{path}/id"),
                    first.map(|first| format!("/states/{first}/id")),
                );
            }
        } else {
            states.insert(state.id.as_str(), index);
        }
        if !valid_text(&state.label, 128) {
            semantic_error(
                diagnostics,
                Code::WorkflowStateLabelInvalid,
                &format!("{path}/label"),
                Recovery::CorrectField,
                Expected::NonEmptyText,
            );
        }
        if !state.instruction.is_empty() && !valid_instruction(&state.instruction) {
            semantic_error(
                diagnostics,
                Code::WorkflowStateInstructionInvalid,
                &format!("{path}/instruction"),
                Recovery::CorrectField,
                Expected::NonEmptyText,
            );
        }
        if !(1..=MAX_RETRY_ATTEMPTS).contains(&state.retry.max_attempts) {
            numeric_error(
                diagnostics,
                Code::WorkflowStateRetryInvalid,
                &format!("{path}/retry/maxAttempts"),
                state.retry.max_attempts as usize,
                MAX_RETRY_ATTEMPTS as usize,
            );
        }
        collect_state_field_diagnostics(
            state,
            &path,
            binding_slots,
            binding_counts,
            runtimes,
            runtime_counts,
            worksets,
            workset_counts,
            &flow_entered,
            diagnostics,
        );
    }

    if !states.contains_key(definition.initial.as_str())
        && !state_counts.contains_key(definition.initial.as_str())
    {
        semantic_error(
            diagnostics,
            Code::WorkflowInitialUnknown,
            "/initial",
            Recovery::CorrectReference,
            Expected::ExistingReference,
        );
    }

    let transition_counts = counts(
        definition
            .transitions
            .iter()
            .map(|transition| transition.id.as_str()),
    );
    let mut valid_transitions = Vec::new();
    let mut tainted_from = BTreeSet::new();
    for (index, transition) in definition.transitions.iter().enumerate() {
        let path = format!("/transitions/{index}");
        let mut valid = true;
        if !is_identifier(&transition.id) {
            semantic_error(
                diagnostics,
                Code::WorkflowTransitionIdInvalid,
                &format!("{path}/id"),
                Recovery::CorrectField,
                Expected::Identifier,
            );
            valid = false;
        } else if transition_counts.get(&transition.id).copied().unwrap_or(0) > 1 {
            let first = definition
                .transitions
                .iter()
                .position(|candidate| candidate.id == transition.id);
            if first != Some(index) {
                duplicate_error(
                    diagnostics,
                    Code::WorkflowTransitionDuplicate,
                    &format!("{path}/id"),
                    first.map(|first| format!("/transitions/{first}/id")),
                );
            }
            valid = false;
        }
        for (field, target) in [
            ("from", transition.from.as_str()),
            ("to", transition.to.as_str()),
        ] {
            if !states.contains_key(target) {
                if !state_counts.contains_key(target) {
                    semantic_error(
                        diagnostics,
                        Code::WorkflowTransitionStateUnknown,
                        &format!("{path}/{field}"),
                        Recovery::CorrectReference,
                        Expected::ExistingReference,
                    );
                }
                valid = false;
            }
        }
        if transition
            .guard
            .as_ref()
            .is_some_and(|guard| !valid_guard(guard))
        {
            semantic_error(
                diagnostics,
                Code::WorkflowGuardInvalid,
                &format!("{path}/guard"),
                Recovery::CorrectRouting,
                Expected::ValidRouting,
            );
            valid = false;
        }
        // Fork fan-out is structural; a fork branch edge must stay `flow`.
        if transition.mode != TransitionMode::Flow
            && states
                .get(transition.from.as_str())
                .is_some_and(|state_index| {
                    definition.states[*state_index].kind == GraphStateKind::Fork
                })
        {
            semantic_error(
                diagnostics,
                Code::WorkflowTransitionModeInvalid,
                &format!("{path}/mode"),
                Recovery::CorrectRouting,
                Expected::ValidRouting,
            );
            valid = false;
        }
        if valid {
            valid_transitions.push(index);
        } else if states.contains_key(transition.from.as_str()) {
            tainted_from.insert(transition.from.as_str());
        }
    }
    let routing_start = diagnostics.len();
    collect_routing_diagnostics(
        definition,
        &states,
        &valid_transitions,
        &tainted_from,
        diagnostics,
    );
    let routing_ready = !diagnostics[routing_start..].iter().any(|diagnostic| {
        matches!(
            diagnostic.code,
            Code::WorkflowRoutingInvalid
                | Code::WorkflowGuardInvalid
                | Code::WorkflowGuardAmbiguous
        )
    });
    let references_ready = states.len() == definition.states.len()
        && valid_transitions.len() == definition.transitions.len()
        && states.contains_key(definition.initial.as_str());
    if references_ready && routing_ready {
        let topology_ready = collect_parallel_topology_diagnostics(
            definition,
            &states,
            &valid_transitions,
            diagnostics,
        );
        if topology_ready {
            collect_reachability_diagnostics(definition, &states, &valid_transitions, diagnostics);
            collect_effect_cycle_diagnostics(definition, &states, &valid_transitions, diagnostics);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn collect_state_field_diagnostics(
    state: &super::GraphState,
    path: &str,
    binding_slots: &BTreeMap<&str, &super::ActorSlot>,
    binding_counts: &BTreeMap<String, usize>,
    runtimes: &BTreeSet<&str>,
    runtime_counts: &BTreeMap<String, usize>,
    worksets: &BTreeSet<&str>,
    workset_counts: &BTreeMap<String, usize>,
    flow_entered: &BTreeSet<&str>,
    diagnostics: &mut Vec<PreflightDiagnostic>,
) {
    let forbidden = |values: &[bool]| values.iter().any(|value| *value);
    match state.kind {
        GraphStateKind::Actor => {
            match state.binding.as_deref() {
                Some(id) => {
                    let binding_invalid = match binding_slots.get(id) {
                        Some(slot) => slot.kind != BindingKind::Actor || !slot.required,
                        None => !binding_counts.contains_key(id),
                    };
                    if binding_invalid {
                        semantic_error(
                            diagnostics,
                            Code::WorkflowActorBindingInvalid,
                            &format!("{path}/binding"),
                            Recovery::CorrectReference,
                            Expected::ExistingReference,
                        );
                    }
                }
                // Flow-mode targets execute without a decider settlement, so a
                // flow-entered actor state may not leave its binding empty.
                None if flow_entered.contains(state.id.as_str()) => {
                    let mut value = diagnostic(
                        Code::WorkflowFlowTargetIncomplete,
                        Stage::WorkflowCompile,
                        Some(&format!("{path}/binding")),
                        Recovery::AddRequiredField,
                    );
                    value.expected = Some(Expected::ExistingReference);
                    value.actual_kind = Some(ActualKind::Missing);
                    push(diagnostics, value);
                }
                None => {}
            }
            if forbidden(&[
                state.runtime.is_some(),
                state.entry.is_some(),
                state.workset.is_some(),
            ]) {
                semantic_error(
                    diagnostics,
                    Code::WorkflowStateFieldInvalid,
                    path,
                    Recovery::CorrectField,
                    Expected::EnumValue,
                );
            }
        }
        GraphStateKind::Script => {
            if forbidden(&[
                state.binding.is_some(),
                state.workset.is_some(),
                !state.instruction.is_empty(),
            ]) {
                semantic_error(
                    diagnostics,
                    Code::WorkflowStateFieldInvalid,
                    path,
                    Recovery::CorrectField,
                    Expected::EnumValue,
                );
            }
            let runtime_invalid = match state.runtime.as_deref() {
                Some(id) => !runtimes.contains(id) && !runtime_counts.contains_key(id),
                None => true,
            };
            if runtime_invalid {
                semantic_error(
                    diagnostics,
                    Code::WorkflowScriptRuntimeInvalid,
                    &format!("{path}/runtime"),
                    Recovery::CorrectReference,
                    Expected::ExistingReference,
                );
            }
            match state.entry.as_deref() {
                None => semantic_error(
                    diagnostics,
                    Code::WorkflowScriptEntryMissing,
                    &format!("{path}/entry"),
                    Recovery::AddRequiredField,
                    Expected::String,
                ),
                Some(entry) if !valid_script_entry(entry) => semantic_error(
                    diagnostics,
                    Code::WorkflowScriptEntryInvalid,
                    &format!("{path}/entry"),
                    Recovery::CorrectField,
                    Expected::NonEmptyText,
                ),
                Some(_) => {}
            }
        }
        GraphStateKind::Workset => {
            let workset_invalid = match state.workset.as_deref() {
                Some(id) => !worksets.contains(id) && !workset_counts.contains_key(id),
                None => true,
            };
            if workset_invalid {
                semantic_error(
                    diagnostics,
                    Code::WorkflowWorksetReferenceInvalid,
                    &format!("{path}/workset"),
                    Recovery::CorrectReference,
                    Expected::ExistingReference,
                );
            }
            let binding_invalid = match state.binding.as_deref() {
                Some(id) => match binding_slots.get(id) {
                    Some(slot) => slot.kind != BindingKind::Actor || !slot.required,
                    None => !binding_counts.contains_key(id),
                },
                None => true,
            };
            if binding_invalid {
                semantic_error(
                    diagnostics,
                    Code::WorkflowWorksetBindingInvalid,
                    &format!("{path}/binding"),
                    Recovery::CorrectReference,
                    Expected::ExistingReference,
                );
            }
            if state.runtime.is_some() || state.entry.is_some() {
                semantic_error(
                    diagnostics,
                    Code::WorkflowStateFieldInvalid,
                    path,
                    Recovery::CorrectField,
                    Expected::EnumValue,
                );
            }
        }
        _ => {
            if forbidden(&[
                state.binding.is_some(),
                state.runtime.is_some(),
                state.entry.is_some(),
                state.workset.is_some(),
                !state.instruction.is_empty(),
            ]) {
                semantic_error(
                    diagnostics,
                    Code::WorkflowStateFieldInvalid,
                    path,
                    Recovery::CorrectField,
                    Expected::EnumValue,
                );
            }
        }
    }
}

fn collect_routing_diagnostics(
    definition: &WorkflowDefinition,
    states: &BTreeMap<&str, usize>,
    valid_transitions: &[usize],
    tainted_from: &BTreeSet<&str>,
    diagnostics: &mut Vec<PreflightDiagnostic>,
) {
    let mut outgoing = BTreeMap::<&str, Vec<usize>>::new();
    for index in valid_transitions {
        outgoing
            .entry(definition.transitions[*index].from.as_str())
            .or_default()
            .push(*index);
    }
    for (state_id, state_index) in states {
        if tainted_from.contains(state_id) {
            continue;
        }
        let state = &definition.states[*state_index];
        let edges = outgoing.get(state_id).cloned().unwrap_or_default();
        let success = edges
            .iter()
            .filter(|index| definition.transitions[**index].event == TransitionEvent::Success)
            .count();
        let failure = edges
            .iter()
            .filter(|index| definition.transitions[**index].event == TransitionEvent::Failure)
            .count();
        let valid = match state.kind {
            GraphStateKind::Succeed | GraphStateKind::Fail | GraphStateKind::Blocked => {
                edges.is_empty()
            }
            GraphStateKind::Pass | GraphStateKind::Join => {
                edges.len() == 1
                    && definition.transitions[edges[0]].event == TransitionEvent::Complete
                    && definition.transitions[edges[0]].guard.is_none()
            }
            GraphStateKind::Choice => {
                !edges.is_empty()
                    && edges.iter().all(|index| {
                        definition.transitions[*index].event == TransitionEvent::Complete
                    })
            }
            GraphStateKind::Fork => {
                edges.len() >= 2
                    && edges.iter().all(|index| {
                        let transition = &definition.transitions[*index];
                        transition.event == TransitionEvent::Complete && transition.guard.is_none()
                    })
                    && edges
                        .iter()
                        .map(|index| definition.transitions[*index].to.as_str())
                        .collect::<BTreeSet<_>>()
                        .len()
                        == edges.len()
            }
            GraphStateKind::Authorization
            | GraphStateKind::Actor
            | GraphStateKind::Script
            | GraphStateKind::Workset => {
                success > 0
                    && failure > 0
                    && edges.iter().all(|index| {
                        matches!(
                            definition.transitions[*index].event,
                            TransitionEvent::Success | TransitionEvent::Failure
                        )
                    })
            }
        };
        if !valid {
            let mut value = diagnostic(
                Code::WorkflowRoutingInvalid,
                Stage::WorkflowCompile,
                Some(&format!("/states/{state_index}")),
                Recovery::CorrectRouting,
            );
            value.expected = Some(Expected::ValidRouting);
            value.related_paths = edges
                .iter()
                .take(MAX_RELATED_PATHS)
                .map(|index| format!("/transitions/{index}"))
                .collect();
            push(diagnostics, value);
            continue;
        }
        collect_guard_group_diagnostics(definition, *state_index, &edges, diagnostics);
    }
}

fn collect_guard_group_diagnostics(
    definition: &WorkflowDefinition,
    state_index: usize,
    edges: &[usize],
    diagnostics: &mut Vec<PreflightDiagnostic>,
) {
    let mut by_event = BTreeMap::<TransitionEvent, Vec<usize>>::new();
    for index in edges {
        by_event
            .entry(definition.transitions[*index].event)
            .or_default()
            .push(*index);
    }
    for indexes in by_event.values() {
        if definition.states[state_index].kind == GraphStateKind::Fork {
            continue;
        }
        let fallbacks = indexes
            .iter()
            .filter(|index| definition.transitions[**index].guard.is_none())
            .count();
        let guarded = indexes.len().saturating_sub(fallbacks);
        let duplicate_guard = indexes.iter().enumerate().any(|(left_position, left)| {
            let left = definition.transitions[*left].guard.as_ref();
            left.is_some()
                && indexes
                    .iter()
                    .skip(left_position + 1)
                    .any(|right| definition.transitions[*right].guard.as_ref() == left)
        });
        let guard_paths = indexes
            .iter()
            .filter_map(|index| definition.transitions[*index].guard.as_ref())
            .map(|guard| guard.path.as_str())
            .collect::<BTreeSet<_>>();
        let non_equality_partition = guarded > 1
            && indexes.iter().any(|index| {
                definition.transitions[*index]
                    .guard
                    .as_ref()
                    .is_some_and(|guard| guard.equals.is_none())
            });
        let ambiguous = fallbacks > 1
            || (guarded > 0 && fallbacks != 1)
            || (guarded == 0 && indexes.len() > 1)
            || guard_paths.len() > 1
            || non_equality_partition
            || duplicate_guard;
        if ambiguous {
            let mut value = diagnostic(
                Code::WorkflowGuardAmbiguous,
                Stage::WorkflowCompile,
                Some(&format!("/states/{state_index}")),
                Recovery::CorrectRouting,
            );
            value.expected = Some(Expected::ValidRouting);
            value.related_paths = indexes
                .iter()
                .take(MAX_RELATED_PATHS)
                .map(|index| format!("/transitions/{index}/guard"))
                .collect();
            push(diagnostics, value);
        }
    }
}

fn collect_parallel_topology_diagnostics(
    definition: &WorkflowDefinition,
    states: &BTreeMap<&str, usize>,
    valid_transitions: &[usize],
    diagnostics: &mut Vec<PreflightDiagnostic>,
) -> bool {
    let mut outgoing = BTreeMap::<&str, Vec<usize>>::new();
    let mut predecessors = BTreeMap::<&str, BTreeSet<&str>>::new();
    for index in valid_transitions {
        let transition = &definition.transitions[*index];
        outgoing
            .entry(transition.from.as_str())
            .or_default()
            .push(*index);
        predecessors
            .entry(transition.to.as_str())
            .or_default()
            .insert(transition.from.as_str());
    }
    let mut matched_joins = BTreeSet::new();
    let mut valid = true;
    for (fork_index, fork) in definition
        .states
        .iter()
        .enumerate()
        .filter(|(_, state)| state.kind == GraphStateKind::Fork)
    {
        let branches = outgoing
            .get(fork.id.as_str())
            .into_iter()
            .flatten()
            .copied()
            .collect::<Vec<_>>();
        let fork_valid = validate_parallel_fork(
            definition,
            states,
            &outgoing,
            &predecessors,
            fork.id.as_str(),
            &branches,
            &mut matched_joins,
        );
        if !fork_valid {
            let mut value = diagnostic(
                Code::WorkflowTopologyInvalid,
                Stage::WorkflowCompile,
                Some(&format!("/states/{fork_index}")),
                Recovery::CorrectTopology,
            );
            value.expected = Some(Expected::ValidTopology);
            value.related_paths = branches
                .iter()
                .take(MAX_RELATED_PATHS)
                .map(|index| format!("/transitions/{index}"))
                .collect();
            push(diagnostics, value);
            valid = false;
        }
    }
    for (index, state) in definition.states.iter().enumerate() {
        if state.kind != GraphStateKind::Join {
            continue;
        }
        let predecessor_count = predecessors.get(state.id.as_str()).map_or(0, BTreeSet::len);
        if predecessor_count != 1 && !matched_joins.contains(state.id.as_str()) {
            let mut value = diagnostic(
                Code::WorkflowTopologyInvalid,
                Stage::WorkflowCompile,
                Some(&format!("/states/{index}")),
                Recovery::CorrectTopology,
            );
            value.expected = Some(Expected::ValidTopology);
            push(diagnostics, value);
            valid = false;
        }
    }
    valid
}

fn validate_parallel_fork(
    definition: &WorkflowDefinition,
    states: &BTreeMap<&str, usize>,
    outgoing: &BTreeMap<&str, Vec<usize>>,
    predecessors: &BTreeMap<&str, BTreeSet<&str>>,
    fork_id: &str,
    branches: &[usize],
    matched_joins: &mut BTreeSet<String>,
) -> bool {
    if branches.len() < 2 {
        return false;
    }
    let mut join_id: Option<&str> = None;
    let mut covered = BTreeSet::new();
    let mut exits = BTreeSet::new();
    for branch_index in branches {
        let start = definition.transitions[*branch_index].to.as_str();
        let mut branch = BTreeSet::new();
        let mut branch_exits = BTreeSet::new();
        let mut queue = VecDeque::from([start]);
        while let Some(node) = queue.pop_front() {
            if !branch.insert(node) {
                continue;
            }
            let Some(index) = states.get(node) else {
                return false;
            };
            let state = &definition.states[*index];
            match state.kind {
                GraphStateKind::Fork
                | GraphStateKind::Succeed
                | GraphStateKind::Fail
                | GraphStateKind::Blocked => return false,
                GraphStateKind::Join => {
                    if join_id.is_some_and(|expected| expected != node) {
                        return false;
                    }
                    join_id = Some(node);
                    continue;
                }
                _ => {}
            }
            if covered.contains(node) {
                return false;
            }
            for transition_index in outgoing.get(node).into_iter().flatten() {
                let target = definition.transitions[*transition_index].to.as_str();
                let target_state = &definition.states[states[target]];
                match target_state.kind {
                    GraphStateKind::Fork
                    | GraphStateKind::Succeed
                    | GraphStateKind::Fail
                    | GraphStateKind::Blocked => return false,
                    GraphStateKind::Join => {
                        if join_id.is_some_and(|expected| expected != target) {
                            return false;
                        }
                        join_id = Some(target);
                        exits.insert(node);
                        branch_exits.insert(node);
                    }
                    _ => queue.push_back(target),
                }
            }
        }
        if branch.is_empty()
            || branch_exits.len() != 1
            || branch_has_cycle(definition, outgoing, &branch)
        {
            return false;
        }
        for node in &branch {
            if *node == start || Some(*node) == join_id {
                continue;
            }
            if predecessors
                .get(node)
                .is_some_and(|entering| entering.iter().any(|from| !branch.contains(from)))
            {
                return false;
            }
        }
        if !predecessors
            .get(start)
            .is_some_and(|entering| entering.len() == 1 && entering.contains(fork_id))
        {
            return false;
        }
        covered.extend(branch);
    }
    let Some(join) = join_id else {
        return false;
    };
    if predecessors.get(join).is_none_or(|items| items != &exits) {
        return false;
    }
    matched_joins.insert(join.to_owned())
}

fn branch_has_cycle(
    definition: &WorkflowDefinition,
    outgoing: &BTreeMap<&str, Vec<usize>>,
    branch: &BTreeSet<&str>,
) -> bool {
    fn visit<'a>(
        definition: &'a WorkflowDefinition,
        outgoing: &BTreeMap<&'a str, Vec<usize>>,
        branch: &BTreeSet<&'a str>,
        node: &'a str,
        visiting: &mut BTreeSet<&'a str>,
        visited: &mut BTreeSet<&'a str>,
    ) -> bool {
        if visiting.contains(node) {
            return true;
        }
        if !visited.insert(node) {
            return false;
        }
        visiting.insert(node);
        for transition_index in outgoing.get(node).into_iter().flatten() {
            let target = definition.transitions[*transition_index].to.as_str();
            if branch.contains(target)
                && visit(definition, outgoing, branch, target, visiting, visited)
            {
                return true;
            }
        }
        visiting.remove(node);
        false
    }

    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    branch.iter().copied().any(|node| {
        visit(
            definition,
            outgoing,
            branch,
            node,
            &mut visiting,
            &mut visited,
        )
    })
}

fn collect_effect_cycle_diagnostics(
    definition: &WorkflowDefinition,
    states: &BTreeMap<&str, usize>,
    valid_transitions: &[usize],
    diagnostics: &mut Vec<PreflightDiagnostic>,
) {
    let mut adjacency = BTreeMap::<usize, Vec<usize>>::new();
    for transition_index in valid_transitions {
        let transition = &definition.transitions[*transition_index];
        let from = states[transition.from.as_str()];
        let automatic = match definition.states[from].kind {
            GraphStateKind::Pass
            | GraphStateKind::Choice
            | GraphStateKind::Fork
            | GraphStateKind::Join => true,
            GraphStateKind::Workset => transition.event == TransitionEvent::Success,
            _ => false,
        };
        if automatic {
            adjacency
                .entry(from)
                .or_default()
                .push(states[transition.to.as_str()]);
        }
    }
    let mut visited = BTreeSet::new();
    let mut stack = Vec::new();
    let mut positions = BTreeMap::new();
    let mut cycles = BTreeSet::<Vec<usize>>::new();
    for state in 0..definition.states.len() {
        collect_cycles(
            state,
            &adjacency,
            &mut visited,
            &mut stack,
            &mut positions,
            &mut cycles,
        );
    }
    for cycle in cycles {
        let Some(primary) = cycle.first().copied() else {
            continue;
        };
        let mut value = diagnostic(
            Code::WorkflowEffectCycle,
            Stage::WorkflowCompile,
            Some(&format!("/states/{primary}")),
            Recovery::CorrectTopology,
        );
        value.expected = Some(Expected::ValidTopology);
        value.related_paths = cycle
            .iter()
            .skip(1)
            .take(MAX_RELATED_PATHS)
            .map(|index| format!("/states/{index}"))
            .collect();
        push(diagnostics, value);
    }
}

fn collect_cycles(
    node: usize,
    adjacency: &BTreeMap<usize, Vec<usize>>,
    visited: &mut BTreeSet<usize>,
    stack: &mut Vec<usize>,
    positions: &mut BTreeMap<usize, usize>,
    cycles: &mut BTreeSet<Vec<usize>>,
) {
    if visited.contains(&node) {
        return;
    }
    positions.insert(node, stack.len());
    stack.push(node);
    for target in adjacency.get(&node).into_iter().flatten() {
        if let Some(position) = positions.get(target).copied() {
            let mut cycle = stack[position..].to_vec();
            cycle.sort_unstable();
            cycle.dedup();
            cycles.insert(cycle);
        } else {
            collect_cycles(*target, adjacency, visited, stack, positions, cycles);
        }
    }
    stack.pop();
    positions.remove(&node);
    visited.insert(node);
}

fn collect_reachability_diagnostics(
    definition: &WorkflowDefinition,
    states: &BTreeMap<&str, usize>,
    valid_transitions: &[usize],
    diagnostics: &mut Vec<PreflightDiagnostic>,
) {
    if states.len() != definition.states.len()
        || !states.contains_key(definition.initial.as_str())
        || valid_transitions.len() != definition.transitions.len()
    {
        return;
    }
    let mut outgoing = BTreeMap::<&str, Vec<&str>>::new();
    for index in valid_transitions {
        let transition = &definition.transitions[*index];
        outgoing
            .entry(transition.from.as_str())
            .or_default()
            .push(transition.to.as_str());
    }
    let mut reachable = BTreeSet::new();
    let mut queue = VecDeque::from([definition.initial.as_str()]);
    while let Some(state) = queue.pop_front() {
        if !reachable.insert(state) {
            continue;
        }
        queue.extend(outgoing.get(state).into_iter().flatten().copied());
    }
    for (state_id, index) in states {
        if !reachable.contains(state_id) {
            semantic_error(
                diagnostics,
                Code::WorkflowStateUnreachable,
                &format!("/states/{index}"),
                Recovery::CorrectTopology,
                Expected::ValidTopology,
            );
        }
    }
    if !definition.states.iter().any(|state| {
        reachable.contains(state.id.as_str())
            && matches!(
                state.kind,
                GraphStateKind::Succeed | GraphStateKind::Fail | GraphStateKind::Blocked
            )
    }) {
        semantic_error(
            diagnostics,
            Code::WorkflowTerminalUnreachable,
            "/states",
            Recovery::CorrectTopology,
            Expected::ValidTopology,
        );
    }
}

fn counts<'a>(values: impl Iterator<Item = &'a str>) -> BTreeMap<String, usize> {
    let mut result = BTreeMap::new();
    for value in values {
        *result.entry(value.to_owned()).or_insert(0) += 1;
    }
    result
}

fn semantic_error(
    diagnostics: &mut Vec<PreflightDiagnostic>,
    code: Code,
    path: &str,
    recovery: Recovery,
    expected: Expected,
) {
    let mut value = diagnostic(code, Stage::WorkflowCompile, Some(path), recovery);
    value.expected = Some(expected);
    push(diagnostics, value);
}

fn duplicate_error(
    diagnostics: &mut Vec<PreflightDiagnostic>,
    code: Code,
    path: &str,
    related: Option<String>,
) {
    let mut value = diagnostic(
        code,
        Stage::WorkflowCompile,
        Some(path),
        Recovery::RemoveDuplicate,
    );
    value.expected = Some(Expected::UniqueId);
    if let Some(related) = related.filter(|related| related != path) {
        value.related_paths.push(related);
    }
    push(diagnostics, value);
}

fn numeric_range(
    diagnostics: &mut Vec<PreflightDiagnostic>,
    code: Code,
    path: &str,
    actual: usize,
    minimum: usize,
    maximum: usize,
) {
    if (minimum..=maximum).contains(&actual) {
        return;
    }
    numeric_error(diagnostics, code, path, actual, maximum);
}

fn numeric_error(
    diagnostics: &mut Vec<PreflightDiagnostic>,
    code: Code,
    path: &str,
    actual: usize,
    limit: usize,
) {
    let mut value = diagnostic(
        code,
        Stage::WorkflowCompile,
        Some(path),
        Recovery::ReduceResource,
    );
    value.actual = Some(actual as u64);
    value.limit = Some(limit as u64);
    value.expected = Some(Expected::Integer);
    push(diagnostics, value);
}

fn is_identifier(value: &str) -> bool {
    let mut characters = value.chars();
    characters
        .next()
        .is_some_and(|first| first.is_ascii_lowercase())
        && value.len() <= 96
        && characters.all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || matches!(character, '-' | '_' | '.')
        })
}

fn valid_text(value: &str, maximum: usize) -> bool {
    value == value.trim()
        && !value.is_empty()
        && value.len() <= maximum
        && !value.chars().any(char::is_control)
}

fn valid_script_entry(value: &str) -> bool {
    value.starts_with("scripts/")
        && value.len() <= 240
        && !value.contains('\\')
        && !value.contains('\0')
        && value
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn valid_guard(guard: &super::GuardExpression) -> bool {
    !guard.path.is_empty()
        && guard.path.len() <= 256
        && guard.path.split('.').all(is_identifier)
        && (guard.exists || guard.equals.is_some())
        && guard.equals.as_ref().is_none_or(|value| {
            serde_json::to_vec(value).is_ok_and(|bytes| bytes.len() <= 4 * 1024)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_schema() -> SchemaId {
        SchemaId::new(crate::GENERIC_WORKFLOW_SCHEMA)
    }

    fn valid_workflow() -> Value {
        json!({
            "schema": crate::GENERIC_WORKFLOW_SCHEMA,
            "metadata": {
                "id": "collab-synthetic",
                "name": "Synthetic",
                "version": "1"
            },
            "limits": {
                "maxParallelism": 2,
                "maxWorksetItems": 16,
                "maxAttempts": 2
            },
            "actorSlots": [{
                "id": "actor",
                "kind": "actor",
                "label": "Actor",
                "required": true,
                "entry": true
            }],
            "runtimes": [],
            "worksets": [],
            "initial": "run",
            "states": [
                {"id": "run", "kind": "actor", "label": "Run", "binding": "actor"},
                {"id": "done", "kind": "succeed", "label": "Done"},
                {"id": "failed", "kind": "fail", "label": "Failed"}
            ],
            "transitions": [
                {"id": "done", "from": "run", "to": "done", "event": "success"},
                {"id": "failed", "from": "run", "to": "failed", "event": "failure"}
            ]
        })
    }

    #[test]
    fn syntax_failure_exposes_only_fixed_numeric_location() {
        let failure = compile_workflow_source(br#"{"schema":"#, &test_schema()).unwrap_err();
        let serialized = serde_json::to_value(&failure.diagnostics).unwrap();
        let object = serialized[0].as_object().unwrap();
        assert_eq!(object["code"], json!("workflow_syntax_invalid"));
        assert_eq!(object["stage"], json!("workflow/parse"));
        assert!(object["line"].is_u64());
        assert!(object["column"].is_u64());
        assert_eq!(object.len(), 4);
    }

    #[test]
    fn raw_shape_pass_aggregates_independent_failures_without_values() {
        let sentinel = "private-workspace-sentinel";
        let value = json!({
            "schema": crate::GENERIC_WORKFLOW_SCHEMA,
            "metadata": {"id": sentinel, "name": 7},
            "initial": false,
            "states": [sentinel, {"kind": "unknown", "label": []}],
            "transitions": [{"id": sentinel, "from": 4, "event": "unknown"}],
            "unknownSecretField": sentinel
        });
        let validation = validate_workflow_value(&value, &test_schema());
        assert!(validation.definition.is_none());
        assert!(validation.diagnostics.len() >= 6);
        let serialized = serde_json::to_string(&validation.diagnostics).unwrap();
        assert!(!serialized.contains(sentinel));
        assert!(!serialized.contains("unknownSecretField"));
        assert!(
            validation
                .diagnostics
                .windows(2)
                .all(|pair| pair[0].stage <= pair[1].stage)
        );
    }

    #[test]
    fn semantic_passes_keep_independent_facts_and_suppress_reference_cascades() {
        let mut value = valid_workflow();
        value["metadata"]["id"] = json!("INVALID-PRIVATE-VALUE");
        value["metadata"]["name"] = json!(" private-name ");
        value["limits"]["maxParallelism"] = json!(0);
        value["limits"]["maxWorksetItems"] = json!(MAX_WORKSET_ITEMS + 1);
        value["actorSlots"].as_array_mut().unwrap().push(json!({
            "id": "actor",
            "kind": "actor",
            "label": "Duplicate"
        }));
        value["states"][0]["binding"] = json!("missing-slot");
        value["states"].as_array_mut().unwrap().push(json!({
            "id": "orphan",
            "kind": "pass",
            "label": "Orphan"
        }));
        value["transitions"][0]["to"] = json!("missing-state");

        let first = validate_workflow_value(&value, &test_schema()).diagnostics;
        let second = validate_workflow_value(&value, &test_schema()).diagnostics;
        assert_eq!(first, second);
        for expected in [
            Code::WorkflowMetadataIdInvalid,
            Code::WorkflowMetadataNameInvalid,
            Code::WorkflowParallelismInvalid,
            Code::WorkflowWorksetLimitInvalid,
            Code::WorkflowBindingDuplicate,
            Code::WorkflowActorBindingInvalid,
            Code::WorkflowTransitionStateUnknown,
        ] {
            assert!(
                first.iter().any(|diagnostic| diagnostic.code == expected),
                "missing {expected:?}; diagnostics={first:?}"
            );
        }
        assert_eq!(
            first
                .iter()
                .filter(|diagnostic| diagnostic.code == Code::WorkflowTransitionStateUnknown)
                .count(),
            1
        );
        assert!(
            !first
                .iter()
                .any(|diagnostic| diagnostic.code == Code::WorkflowStateUnreachable)
        );
        let serialized = serde_json::to_string(&first).unwrap();
        assert!(!serialized.contains("INVALID-PRIVATE-VALUE"));
        assert!(!serialized.contains("private-name"));
    }

    #[test]
    fn valid_value_compiles_through_the_shared_entrypoint() {
        assert!(compile_workflow_value(&valid_workflow(), &test_schema()).is_ok());
    }

    #[test]
    fn source_value_and_typed_entries_share_one_ordered_diagnostic_path() {
        let mut value = valid_workflow();
        value["transitions"][0]["to"] = json!("missing-state");
        let source = serde_json::to_vec(&value).unwrap();
        let typed: WorkflowDefinition = serde_json::from_value(value.clone()).unwrap();

        let from_source = compile_workflow_source(&source, &test_schema())
            .unwrap_err()
            .diagnostics;
        let from_value = compile_workflow_value(&value, &test_schema())
            .unwrap_err()
            .diagnostics;
        let from_typed = crate::compile_workflow(typed, &test_schema())
            .unwrap_err()
            .diagnostics;
        assert_eq!(from_source, from_value);
        assert_eq!(from_value, from_typed);
        assert!(from_source.iter().any(|diagnostic| {
            diagnostic.code == Code::WorkflowTransitionStateUnknown
                && diagnostic.path.as_deref() == Some("/transitions/0/to")
        }));
    }

    #[test]
    fn source_and_typed_entries_execute_the_same_machine_trace() {
        let value = valid_workflow();
        let source = serde_json::to_vec(&value).unwrap();
        let typed: WorkflowDefinition = serde_json::from_value(value).unwrap();
        let source_plan = compile_workflow_source(&source, &test_schema()).unwrap();
        let typed_plan = crate::compile_workflow(typed, &test_schema()).unwrap();
        let snapshot = crate::RunSnapshot::empty("run", "revision", "semantics");
        let event = crate::ReducerEvent::Start {
            input: json!({"task": "synthetic"}),
        };
        let from_source = crate::reduce(&source_plan, &snapshot, event.clone()).unwrap();
        let from_typed = crate::reduce(&typed_plan, &snapshot, event).unwrap();
        assert_eq!(from_source, from_typed);
    }

    #[test]
    fn transition_mode_is_enum_checked_and_defaults_to_flow() {
        let mut value = valid_workflow();
        value["transitions"][0]["mode"] = json!("callback");
        let validation = validate_workflow_value(&value, &test_schema());
        assert!(
            validation.diagnostics.is_empty(),
            "callback mode is valid: {:?}",
            validation.diagnostics
        );
        assert_eq!(
            validation.definition.unwrap().transitions[0].mode,
            super::TransitionMode::Callback
        );

        let mut invalid = valid_workflow();
        invalid["transitions"][0]["mode"] = json!("warp");
        let validation = validate_workflow_value(&invalid, &test_schema());
        assert!(
            validation
                .diagnostics
                .iter()
                .any(
                    |diagnostic| diagnostic.code == Code::WorkflowFieldValueInvalid
                        && diagnostic.path.as_deref() == Some("/transitions/0/mode")
                ),
            "unknown mode is a field-value diagnostic: {:?}",
            validation.diagnostics
        );
    }

    #[test]
    fn flow_mode_targets_may_not_leave_key_fields_empty() {
        let mut value = valid_workflow();
        value["states"].as_array_mut().unwrap().insert(
            1,
            json!({"id": "review", "kind": "actor", "label": "Review"}),
        );
        value["transitions"] = json!([
            {"id": "to-review", "from": "run", "to": "review", "event": "success", "mode": "flow"},
            {"id": "reviewed", "from": "review", "to": "done", "event": "success"},
            {"id": "review-failed", "from": "review", "to": "failed", "event": "failure"},
            {"id": "failed", "from": "run", "to": "failed", "event": "failure"}
        ]);
        let validation = validate_workflow_value(&value, &test_schema());
        assert!(
            validation
                .diagnostics
                .iter()
                .any(
                    |diagnostic| diagnostic.code == Code::WorkflowFlowTargetIncomplete
                        && diagnostic.path.as_deref() == Some("/states/1/binding")
                ),
            "flow target with empty binding states the rule: {:?}",
            validation.diagnostics
        );
        assert!(
            compile_workflow_value(&value, &test_schema())
                .unwrap_err()
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == Code::WorkflowFlowTargetIncomplete)
        );

        // The same shape is valid when every edge into the target is a
        // callback: the decider settlement stands between the states.
        value["transitions"][0]["mode"] = json!("callback");
        let validation = validate_workflow_value(&value, &test_schema());
        assert!(
            validation
                .diagnostics
                .iter()
                .all(|diagnostic| diagnostic.code != Code::WorkflowFlowTargetIncomplete),
            "callback-only targets may defer the binding: {:?}",
            validation.diagnostics
        );
        assert!(compile_workflow_value(&value, &test_schema()).is_ok());
    }

    #[test]
    fn fork_branch_edges_reject_callback_mode() {
        let mut value = valid_workflow();
        value["transitions"][0]["mode"] = json!("flow");
        value["transitions"][1]["mode"] = json!("callback");
        let validation = validate_workflow_value(&value, &test_schema());
        assert!(
            validation
                .diagnostics
                .iter()
                .all(|diagnostic| diagnostic.code != Code::WorkflowTransitionModeInvalid),
            "non-fork callback edges are valid: {:?}",
            validation.diagnostics
        );
    }
}
