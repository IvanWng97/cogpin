# cogpin is installed

The **agent layer** is live: `--no-verify` and other forbidden git ops are denied
in real time (`PreToolUse`), and a cheap Definition-of-Done check runs at the end
of each turn (`Stop`).

One more step gets you the **authoritative change layer** (CI + pre-push,
base-pinned, un-bypassable). Inside Claude Code, run once per repo:

    /cogpin-init

It installs the change layer in one shot — vendors the single-file engine to
`.cogpin/cogpin.py`, scaffolds `cogpin.toml`, wires a pre-push managed block
(coexisting with any husky/lefthook/pre-commit you already run), and adds
`.github/workflows/cogpin.yml` — then drafts a project-specific policy from your
`CLAUDE.md` house rules **as `cogpin.toml.draft` for you to review and rename**.
Commit the engine, config, and workflow and every clone meets the same gate — no npm,
no package manager, one stdlib-Python file.

Then, any time:

- `/cogpin-doctor` — confirm both layers are wired (one-line fix for anything off).
- `/cogpin-gaps` — which `CLAUDE.md` rules are still prose with no mechanism.
- `/cogpin-check` — the gate's verdict on your current branch.

> Requires `python3 ≥ 3.11` on PATH (the engine is stdlib-only; 3.11 is the `tomllib`
> floor). Using Codex or another agent? The change layer is tool-agnostic — point its
> pre-command hook at `python3 .cogpin/cogpin.py check` (see the README).
