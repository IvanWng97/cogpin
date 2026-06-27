---
description: Show which CLAUDE.md house-rules are NOT yet bound by a ratchet check — prose with no mechanism.
allowed-tools: Bash(python3 *)
---

!`E="${CLAUDE_PROJECT_DIR:-.}/.ratchet/ratchet.py"; [ -f "$E" ] || E="${CLAUDE_PLUGIN_ROOT}/ratchet.py"; python3 "$E" gaps --cwd "${CLAUDE_PROJECT_DIR:-.}" 2>&1`

Summarize the gaps above. Lead with the **UNBOUND** house-rules — prose the repo
states but no ratchet check enforces — and name the suggested primitive for each.
Then list any **bound-but-advisory** (`warn`) rules that have a mechanism but no
teeth yet, and which could be promoted to a `kind="fact"` block. This is advisory and
never gates; if every rule is bound, say so in one line. To bind the open ones,
draft them into `ratchet.toml.draft` (`/ratchet-init` re-runs the same draft flow).
