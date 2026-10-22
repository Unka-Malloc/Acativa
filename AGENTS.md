# Agent rules for Acativa

## Environment fidelity (hard rule)

Agent infrastructure never launches an agent with an empty or minimal
"no variables" environment — the user's machine is the source of
truth. Presets, cards and specs declare how every needed value is
*resolved* from the real environment: host environment variables
(PATH and friends), values inside configuration files (TOML, YAML or
JSON — read by key lookup, never copied by hand), and every model or
provider the agent can use. The custody layer resolves those
declarations into concrete values before spawn; the child receives
the user's real environment plus explicit overrides.

An agent started "clean" loses the user's configuration, credentials,
providers and tools — that is a defect, not hardening. Security lives
in *where* values resolve (locally, at the custody boundary) and
*what* may cross a remote boundary (literal values, not references) —
never in running with no environment at all.

## Verify

`scripts/verify.sh`
