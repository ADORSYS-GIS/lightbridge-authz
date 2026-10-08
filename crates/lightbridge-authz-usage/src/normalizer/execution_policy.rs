//! Which execution-grain sources may have an unplaced span stored, and what happens to the spans
//! that may not (#769). Split out of `execution_grain.rs` to satisfy the LoC gate
//! (lightbridge-governance#172); `parse_execution_grain` is still the one classifier.
//!
//! ## Why this exists
//!
//! `parse_execution_grain` places a span as a tool call (it names a tool), a model call (it names
//! a model), or -- for everything else -- a real execution. That last branch was unconditional, so
//! any span a source happened to export became an "agent run". In production (2026-10-08) VS Code
//! Copilot Chat spans arrived labelled `claude-code` (the collector's static `X-Source`) and every
//! one of them that named neither a `model` nor a `tool_name` -- `execute_tool`, `vscode.chat.*`
//! timing spans -- was stored as an execution: 528,244 rows in 30 days, 4 with a model call.
//!
//! ## The rule
//!
//! A source is VERIFIED when its execution-span shape has been checked against real telemetry.
//! A verified source keeps the classifier's original behaviour exactly. An UNVERIFIED source never
//! has a span stored on the strength of "it was not a model or tool call": such a span, and a
//! model/tool call with no parent to hang off, is DROPPED and counted -- never stored, and never
//! allowed to reject the rest of the batch.

use std::collections::BTreeSet;

use tracing::warn;

/// Sources whose execution-grain span shape is verified against real telemetry.
///
/// `opencode`: production, 2026-10-08 -- 591 of its 620 executions carry a model call and 506 a
/// tool call, at about one execution per trace. `claude-code`, `codex` and `microsoft-foundry`
/// have no verified TRACE shape yet (their normalizers' keys are log-event names, and Codex's own
/// module says so); add one here only with a captured payload committed as its fixture.
pub const VERIFIED_EXECUTION_SOURCES: [&str; 1] = ["opencode"];

pub fn is_verified_execution_source(source: &str) -> bool {
    VERIFIED_EXECUTION_SOURCES.contains(&source)
}

/// How many distinct span NAMES a drop report carries -- enough to recognise the producer, bounded
/// so a runaway emitter cannot grow one log line without limit.
const MAX_REPORTED_NAMES: usize = 5;

/// The spans an unverified source sent that could not be placed. Names only: a span's attributes
/// can carry user and repository identifiers, and are never recorded here.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DroppedSpans {
    count: usize,
    names: BTreeSet<String>,
}

impl DroppedSpans {
    pub fn record(&mut self, span_name: &str) {
        self.count += 1;
        if self.names.len() < MAX_REPORTED_NAMES {
            self.names.insert(span_name.to_string());
        }
    }

    pub fn count(&self) -> usize {
        self.count
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.names.iter().map(String::as_str)
    }

    /// One structured event per batch that dropped anything. The rate of these, by `source`, is
    /// the signal that a producer changed shape or is mislabelled; a metric replaces it once this
    /// service exports metrics at all (#639).
    pub fn report(&self, source: &str) {
        if self.count == 0 {
            return;
        }
        let names: Vec<&str> = self.names().collect();
        warn!(
            source,
            dropped_spans = self.count,
            span_names = ?names,
            "execution grain: dropped spans from an unverified source (#769)"
        );
    }
}
