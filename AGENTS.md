# Agent rules for Acativa

## Environment fidelity (hard rule)

Host-environment fidelity is an explicit grant, never a default. The
engine's default for every launched agent is a sanitized environment:
presets, cards and specs declare how each needed value is *resolved*
from the user's real environment — host environment variables (PATH
and friends), values inside configuration files (TOML, YAML or JSON —
read by key lookup, never copied by hand), and the declared models or
providers — and a value crosses a remote boundary only as a resolved
literal, never as a reference.

When the host makes its own explicit opt-in to host-environment
fidelity, the custody layer resolves the declared values locally and
the child receives the user's real environment plus explicit
overrides. A fidelity launch that silently drops the user's
configuration, credentials, providers and tools is a defect — but so
is an agent that inherits ambient credentials without that grant.
Security lives in *where* values resolve (locally, at the custody
boundary) and *what* may cross a remote boundary, and in fidelity
being a deliberate grant.

## Verify

`scripts/verify.sh`
