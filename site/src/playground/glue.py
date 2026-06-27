"""Browser glue for the ratchet playground.

Runs the REAL engine (`import ratchet`) against a DiffFacts built from the editor's
mini-diff — no git, no subprocess, so the exact same code runs locally (python3)
AND in Pyodide (CPython in WASM). Entry point for the page: `run_json(toml, scen)`.

Mini-diff scenario format (one item per line):
    A path/to/file        a file added    (name-status A)
    M path/to/file        a file modified (name-status M)
    D path/to/file        a file deleted  (name-status D)
    + <code>              an added line   in the most-recent file
    - <code>              a removed line  in the most-recent file
    $ <shell command>     an agent command (forbid_command / forbid_commit_on_branch)
    @ <branch>            the current branch (for forbid_commit_on_branch)
    pr> <text>            a PR-body line (marker_present / cooccur)
    approvals> a, b       reviewer approvals (protected_path)
    # comment / blank     ignored
"""

from __future__ import annotations

import json

import ratchet

_STATUS = {"A": ratchet.ADDED, "M": ratchet.MODIFIED, "D": ratchet.DELETED}


def _parse(scenario_text):
    changed, added, removed = [], [], []
    command, branch, pr_lines, approvals = "", None, [], None
    cur = None
    for line in (scenario_text or "").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if line.startswith("pr>"):
            pr_lines.append(line[3:].lstrip())
            continue
        if line.startswith("approvals>"):
            approvals = [a.strip() for a in line[len("approvals>"):].split(",") if a.strip()]
            continue
        marker, rest = line[0], (line[2:] if len(line) > 1 else "")
        if marker in _STATUS and len(line) > 1 and line[1] == " ":
            cur = rest.strip()
            changed.append((_STATUS[marker], cur))
        elif marker == "+":
            if cur is not None:
                added.append((cur, rest))
        elif marker == "-":
            if cur is not None:
                removed.append((cur, rest))
        elif marker == "$":
            command = rest.strip()
        elif marker == "@":
            branch = rest.strip() or None
    return {
        "changed": changed, "added": added, "removed": removed,
        "command": command, "branch": branch,
        "pr_body": "\n".join(pr_lines) if pr_lines else None,
        "approvals": approvals,
    }


def run(toml_text, scenario_text):
    out = {"ok": True, "error": None, "change_findings": [], "agent_denials": [], "summary": ""}
    try:
        cfg = ratchet.Config.parse(toml_text)
    except ratchet.ConfigError as e:
        out["ok"] = False
        out["error"] = str(e)
        out["summary"] = "config invalid — block-requires-fact or a structural rule failed"
        return out

    p = _parse(scenario_text)
    facts = ratchet.DiffFacts(
        added=p["added"], removed=p["removed"], changed=p["changed"],
        pr_body=p["pr_body"], approvals=p["approvals"],
    )
    # change layer — skip `run` blocks (no shell in the browser)
    for f in ratchet.run_change(cfg, facts, allow_run=False):
        out["change_findings"].append({"sev": f.severity, "id": f.id, "reason": f.reason})
    # agent layer — command gate + branch gate, only if a command was supplied
    if p["command"]:
        cmd = ratchet.CommandFacts(command=p["command"])
        for f in ratchet.run_command_gate(cfg, cmd) + ratchet.run_branch_gate(cfg, cmd, p["branch"]):
            out["agent_denials"].append({"sev": f.severity, "id": f.id, "reason": f.reason})

    nb = sum(1 for f in out["change_findings"] if f["sev"] == "block")
    nw = sum(1 for f in out["change_findings"] if f["sev"] == "warn")
    nd = sum(1 for f in out["agent_denials"] if f["sev"] == "block")
    if nd:
        out["summary"] = "agent layer: DENIED — this command is blocked in real time"
    elif nb:
        out["summary"] = "change layer: definition-of-done NOT met (%d blocking, %d warning)" % (nb, nw)
    else:
        out["summary"] = "ok — %d advisory warning(s)" % nw
    return out


def run_json(toml_text, scenario_text):
    """Pyodide-friendly: return a JSON string so the page parses one value."""
    return json.dumps(run(toml_text, scenario_text))
