# ratchet is installed

The **agent layer** is live: `--no-verify` and other forbidden git ops are denied
in real time (`PreToolUse`), and a cheap Definition-of-Done check runs at the end
of each turn (`Stop`).

One more step gets you the **authoritative change layer** (CI + pre-push,
base-pinned, un-bypassable). Inside Claude Code, run once per repo:

    /ratchet-init

It installs the change layer in one shot — vendors the single-file engine to
`.ratchet/ratchet.py`, scaffolds `ratchet.toml`, wires a pre-push managed block
(coexisting with any husky/lefthook/pre-commit you already run), and adds
`.github/workflows/ratchet.yml` — then drafts a project-specific policy from your
`CLAUDE.md` house rules **as `ratchet.toml.draft` for you to review and rename**.
Commit the engine, config, and workflow and every clone meets the same gate — no npm,
no package manager, one stdlib-Python file.

Then, any time:

- `/ratchet-doctor` — confirm both layers are wired (one-line fix for anything off).
- `/ratchet-gaps` — which `CLAUDE.md` rules are still prose with no mechanism.
- `/ratchet-check` — the gate's verdict on your current branch.

> Requires `python3 ≥ 3.11` on PATH (the engine is stdlib-only; 3.11 is the `tomllib`
> floor). Using Codex or another agent? The change layer is tool-agnostic — point its
> pre-command hook at `python3 .ratchet/ratchet.py check` (see the README).
