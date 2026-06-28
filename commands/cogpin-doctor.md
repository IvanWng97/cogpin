---
description: Diagnose cogpin's wiring in this repo — both layers, with a one-line fix for anything missing.
allowed-tools: Bash(python3 *)
---

!`E="${CLAUDE_PROJECT_DIR:-.}/.cogpin/cogpin.py"; [ -f "$E" ] || E="${CLAUDE_PLUGIN_ROOT}/cogpin.py"; python3 "$E" doctor --cwd "${CLAUDE_PROJECT_DIR:-.}" 2>&1`

Read the diagnosis above (it prefers the vendored `.cogpin/cogpin.py` — the engine
CI and pre-push actually run — and falls back to the plugin engine if not yet
vendored). Confirm the `✓` checks in one line, then walk through each `~` / `✗` with
the exact fix shown. The two load-bearing failures are a missing/uncompilable engine
and an invalid `cogpin.toml`; everything else is advisory (CI is the authoritative
gate). If the change layer is ready, say so plainly.
