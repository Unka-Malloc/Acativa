//! Generic collaboration-strategy compiler and transition machine.
//!
//! Definitions are parsed and analyzed once into immutable indexes. Run-state
//! changes are pure: callers persist the returned snapshot and commands, then
//! execute effects through their owning adapters.

pub mod analysis;
pub mod compile;
pub mod diagnostic;
pub mod dispatch;
pub mod ir;
pub mod machine;
pub mod strategy;
pub mod syntax;

// The IR is the module's shared vocabulary: `super::Type` resolves to it.
pub use ir::*;
