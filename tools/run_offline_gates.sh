#!/usr/bin/env bash
# Runs the full offline gate set from CONTRIBUTING.md in dependency order and
# prints a summary. Exits non-zero if any gate fails.
#
# Required: stable Rust, python3. Optional steps are skipped with a note when
# their toolchain is missing (+1.97, +nightly, cargo-fuzz, cargo-deny,
# cargo-audit, node/npm, go). Logs land in target/gate-logs/<step>.log.
set -u
cd "$(dirname "$0")/.."
mkdir -p target/gate-logs
overall=0
width=30

step() { # step <name> <cmd...>
  local name=$1
  shift
  local start=$SECONDS log="target/gate-logs/${name//\//_}.log"
  if "$@" >"$log" 2>&1; then
    printf '%-*s ok\n' "$width" "$name"
  else
    printf '%-*s FAILED  (log: %s)\n' "$width" "$name" "$log"
    overall=1
  fi
}

skip() { # skip <name> <reason>
  printf '%-*s skip    (%s)\n' "$width" "$1" "$2"
}

have() { command -v "$1" >/dev/null 2>&1; }
toolchain() { rustup toolchain list 2>/dev/null | grep -q "^$1-"; }

echo "== Confidential Inference SDK offline gates =="

step "fmt" cargo fmt --all -- --check
step "clippy" cargo clippy --workspace --all-targets --locked -- -D warnings
step "tests" cargo test --workspace --locked
if toolchain 1.97; then
  step "msrv-check" cargo +1.97 check --workspace --locked --all-targets
else
  skip "msrv-check" "rustup toolchain 1.97 not installed"
fi
step "demo" cargo run -p confidential-demo --locked
# The language bindings load this shared library; build it before them.
step "ffi-build" cargo build -p confidential-inference-ffi --locked

if have python3; then
  step "python-bindings" python3 -m unittest discover -s bindings/python/tests
  step "tools-tests" python3 -m unittest discover -s tools -p 'test_*.py'
  step "normative-fixtures" python3 tools/check_normative_fixtures.py
  step "ffi-exports" python3 tools/check_ffi_exports.py
  step "supply-chain-policy" python3 tools/check_supply_chain_policy.py
  if git diff --quiet && git diff --cached --quiet; then
    step "release-packaging" python3 tools/check_release_packaging.py --require-clean
  else
    skip "release-packaging" "working tree is dirty (commit for --require-clean)"
    step "release-packaging" python3 tools/check_release_packaging.py
  fi
else
  skip "python-bindings/tools/policies" "python3 not found"
fi

if have npm; then
  if [ ! -d bindings/node/node_modules ]; then
    step "node-deps" bash -c 'cd bindings/node && npm ci'
  fi
  step "node-bindings" bash -c 'cd bindings/node && npm test'
else
  skip "node-bindings" "npm not found"
fi
if have go; then
  step "go-bindings" bash -c 'cd bindings/go && go test -race -count=1 ./...'
else
  skip "go-bindings" "go not found"
fi

if have cargo-deny; then step "cargo-deny" cargo deny check; else skip "cargo-deny" "not installed"; fi
if have cargo-audit; then step "cargo-audit" cargo audit; else skip "cargo-audit" "not installed"; fi
if toolchain nightly && have cargo-fuzz; then
  step "fuzz-build" cargo +nightly fuzz build
else
  skip "fuzz-build" "needs +nightly and cargo-fuzz (and a C++ compiler)"
fi

echo "== done =="
exit $overall
