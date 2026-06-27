# ratchet is installed

The **agent layer** is live: `--no-verify` and other forbidden git ops are denied
in real time (`PreToolUse`), and a cheap Definition-of-Done check runs at the end
of each turn (`Stop`).

One more step gets you the **authoritative change layer** (CI + pre-push,
base-pinned, un-bypassable). Inside Claude Code, run once per repo:

    /ratchet-init

It vendors the single-file engine into the repo, scaffolds `ratchet.toml`, and adds
the CI step. Commit them and every clone meets the same gate — no npm, no package
manager, one stdlib-Python file.

Tune `ratchet.toml` for your stack, then `/ratchet-check` any time to see the gate's
verdict on your current branch.
