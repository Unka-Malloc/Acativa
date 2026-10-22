#!/usr/bin/env bash
# Single-shot verification gate for the acativa workspace: format, lint, test.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
