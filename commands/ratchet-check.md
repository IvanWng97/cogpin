---
description: Run the ratchet Definition-of-Done gate and report blocking vs advisory findings.
allowed-tools: Bash(python3 *)
---

Change-layer gate output for the committed range:

!`python3 "${CLAUDE_PLUGIN_ROOT}/ratchet.py" check --cwd "${CLAUDE_PROJECT_DIR:-.}"`

Summarize the result: list each `[BLOCK]` finding with the exact change that clears it, then any advisory `warn` items. If the gate is clean, say so in one line.
