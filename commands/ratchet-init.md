---
description: Wire ratchet into this repo — vendor the engine, scaffold ratchet.toml, add the CI step.
allowed-tools: Bash(mkdir *), Bash(cp *), Bash(python3 *)
---

!`mkdir -p "$CLAUDE_PROJECT_DIR/.ratchet" && cp "${CLAUDE_PLUGIN_ROOT}/ratchet.py" "$CLAUDE_PROJECT_DIR/.ratchet/ratchet.py" && python3 "$CLAUDE_PROJECT_DIR/.ratchet/ratchet.py" init --config "$CLAUDE_PROJECT_DIR/ratchet.toml" 2>&1`

The engine is now vendored at `.ratchet/ratchet.py` and a starter `ratchet.toml` exists. Now:

1. Read `ratchet.toml` and propose checks specific to this project's stack — secret
   shapes, forbidden commands, code↔docs/test coupling, gate-defining
   `protected_path`s, and a `run` block wiring the repo's real lint/test command.
   Show the diff and ask before writing.
2. Add the change-layer CI job at `.github/workflows/ratchet.yml` that runs
   `python3 .ratchet/ratchet.py check` with `actions/checkout` (`fetch-depth: 0`) and
   `actions/setup-python`.
3. Remind me to commit `.ratchet/ratchet.py`, `ratchet.toml`, and the workflow — that's what
   makes the gate hold for every clone, with no npm and no binary download.
