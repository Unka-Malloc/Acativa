# Acativa

**Acativa — Multi-Agent Collaboration Strategy Compiler.** A generic Rust
runtime that compiles multi-agent collaboration strategies into immutable plans
and executes them as durable state machines. It covers both centralized and
decentralized collaboration topologies: pipelines, branching flows,
self-looping agent cycles and custom routing strategies are all expressed in
the same strategy model and compiled through the same engine.

Acativa is host-agnostic. It carries no product schema, package format or
host-vocabulary dependency — a host binds its own schema identity, persisted
vocabulary and effect implementations at every admission boundary through the
port traits the engine defines.

## What it provides

- **Strategy compilation** (`acativa::workflow`) — a canonical strategy
  definition language with source parsing, diagnostics, semantic analysis and
  one-pass lowering into an immutable `CompiledWorkflow` plan. Plan identity
  separates content digest, compiler semantics and interpreter profile, so runs
  stay bound to the exact revision and semantics they were admitted under.
- **Durable state machines** (`acativa::store`) — persisted run reduction,
  dispatch intents, claim leases, queues, routing and subscriptions on SQLite
  (WAL). Runs survive process restarts; recovery re-derives dispatch state from
  the store rather than from memory.
- **Runtime & ports** (`acativa::runtime`) — effect drivers, node execution,
  adapters and the `ports` contract surface a host implements: actor turns,
  wake notification, cancellation and recheck. The engine never talks to an
  agent, model or transport directly — effects flow through host-owned ports.
- **Safe primitives** (`acativa::util`) — append-locked files, atomic
  replacement, path hardening, safe ZIP archive extraction and SQLite
  contract helpers, usable by hosts building their own persistence or
  package import.

## Layering

```text
host            ──►  acativa::runtime  ──►  acativa::store  ──►  acativa::workflow
(composes ports)     (executes effects)     (persists state)     (pure machine)
```

`workflow` is a pure machine — deterministic, no I/O. `store` owns durable
state and dispatch intent. `runtime` executes effects through the host's
ports. A host composes the three; it does not modify them.

## Minimal usage

```rust
use acativa::{compile_workflow, SchemaId, WorkflowDefinition};

// Parse/validate a host-defined strategy definition and lower it to a plan.
let definition: WorkflowDefinition = /* host-supplied definition */;
let plan = compile_workflow(
    definition,
    &SchemaId::new("your-product.workflow.v1"),
)?;
```

The host then opens a `store` instance under its own schema identity, admits
runs against the compiled plan, and drives `runtime::service` with port
implementations that reach its own agents, models and transports.

## Repository layout

```text
crates/acativa/src/
├── workflow/   IR, syntax, diagnostics, analysis, compile, dispatch, machine
├── store/      admission, commit, conformance, control, queue, routing,
│               subscriptions, durable store
├── runtime/    adapters, drivers, node execution, port contracts, recheck
└── util/       file security, safe archives, SQLite contracts, model naming
```

Tests live in `crates/acativa/tests/` — the `causality` suite proves the
state-machine invariants over all observable orderings and the `compile`
suite pins plan-identity and lowering-semantics behavior.

## Guarantees

- **Immutable revisions** — a compiled plan and every binding on it are
  content-addressed; a run is bound to the exact revision it authorized.
- **Durable reduction** — run state is rebuilt from persisted events, not
  from process memory.
- **Bounded effects** — dispatch is lease-based with explicit verdicts; a
  crashed claim is recovered, never duplicated silently.
- **Zero host coupling** — the crate depends only on general-purpose
  libraries (`serde`, `rusqlite`, `sha2`, `thiserror`, `anyhow`, `zip`,
  `flate2`, `uuid`, `nix`); every product identifier enters as a parameter.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
