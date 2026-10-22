# Agent rules for Acativa

Acativa is a host-neutral strategy compiler and durable runtime: it owns
the workflow state machine, the store, and the dispatch contracts — it
does not launch agents, custody credentials, or talk to transports. The
host supplies effects through the ports in `crates/acativa/src/runtime/`
and binds its own identity through `StoreDialect`.

## Verify

`scripts/verify.sh`
