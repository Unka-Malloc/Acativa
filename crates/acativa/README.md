# acativa

Multi-Agent Collaboration Strategy Compiler — a generic runtime, state
machine and durable strategy store for centralized and decentralized
multi-agent collaboration.

`acativa` is host-agnostic. It compiles a workflow definition into a checked
plan, reduces run events into deterministic snapshots, persists runs, commands
and delivery intent in a durable SQLite store, and executes effects through
host-owned adapters and ports. It carries no product schema, package format
or host-vocabulary dependency: a host binds its own schema identity,
persisted vocabulary and effect implementations at every admission boundary.

## Layout

- `workflow` — definition IR, syntax-independent validation, diagnostic
  codes, the schema-parameterized compiler, the deterministic run machine and
  pure dispatch planning.
- `store` — the durable strategy store: admission, routing, controlled state,
  queues, subscriptions, commit decoration and dispatch composition over
  SQLite.
- `runtime` — capability adapters, node facades, the continuous node driver,
  host effect ports and evolution seams.
- `util` — host-agnostic support: private-path hardening, atomic writes,
  bounded archive extraction, SQLite schema-contract comparison and display
  naming.

## Identity model

A host names the workflow schema it accepts with `SchemaId` and hands it to
`compile_workflow` / `compile_workflow_source`. Compiled plans carry a
`PlanKey` — the definition revision plus the compiler semantics, engine
semantics and lowering capability identities — so a retained plan is always
verified against the exact identity it was lowered under, and an old run is
either re-admitted or handed off, never silently re-lowered.

## License

AGPL-3.0-or-later. See `LICENSE` and `NOTICE` in the repository root.
