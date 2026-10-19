use serde_json::Value;

use crate::{
    WorkflowDefinition, WorkflowDiagnosticStage, WorkflowValidationFailure,
    analysis::{parse_diagnostics, shape_diagnostic, syntax_diagnostic},
};

/// Parsed workflow source. The JSON value retains source-level field paths;
/// semantic analysis consumes the canonical definition.
#[derive(Clone, Debug)]
pub struct ParsedWorkflow {
    pub(crate) definition: WorkflowDefinition,
    pub(crate) source: Option<Value>,
    pub(crate) diagnostics: Vec<crate::PreflightDiagnostic>,
}

impl ParsedWorkflow {
    pub fn definition(&self) -> &WorkflowDefinition {
        &self.definition
    }

    pub fn source(&self) -> Option<&Value> {
        self.source.as_ref()
    }
}

pub fn parse(source: &[u8]) -> Result<ParsedWorkflow, WorkflowValidationFailure> {
    let value: Value =
        serde_json::from_slice(source).map_err(|error| WorkflowValidationFailure {
            diagnostics: vec![syntax_diagnostic(error.line(), error.column())],
        })?;
    parse_value(&value)
}

pub(crate) fn parse_value(value: &Value) -> Result<ParsedWorkflow, WorkflowValidationFailure> {
    let diagnostics = parse_diagnostics(value);
    if diagnostics
        .iter()
        .any(|diagnostic| diagnostic.stage == WorkflowDiagnosticStage::WorkflowParse)
    {
        return Err(WorkflowValidationFailure { diagnostics });
    }
    let definition =
        serde_json::from_value(value.clone()).map_err(|_| WorkflowValidationFailure {
            diagnostics: vec![shape_diagnostic()],
        })?;
    Ok(ParsedWorkflow {
        definition,
        source: Some(value.clone()),
        diagnostics,
    })
}

pub(crate) fn from_definition(definition: WorkflowDefinition) -> ParsedWorkflow {
    ParsedWorkflow {
        definition,
        source: None,
        diagnostics: Vec::new(),
    }
}
