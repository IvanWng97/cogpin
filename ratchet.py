#!/usr/bin/env python3
"""ratchet — Definition-of-Done gate for AI coding agents.

ONE language-agnostic engine, ONE per-repo `ratchet.toml`. The engine reads only
normalized git/diff/PR *facts* + the config; it NEVER imports project code.
Anything language-specific goes through the `run` escape hatch.

The whole moat is one schema invariant (see `validate`):

    severity = "block"   REQUIRES   kind = "fact"

A block that decides over anything the gated agent can author (an LLM-judge, a
self-attestation) is not a gate. Only ungameable diff/command/PR-metadata facts
may block.

Two binding layers over the same config:
  gate   (agent layer)  — PreToolUse(Bash) hook: deny git push/merge/--no-verify.
                          Bypassable via [meta].bypass_env (always logged).
  check  (change layer) — pre-push hook + CI job: AUTHORITATIVE, base-pinned,
                          ignores the bypass env.

Stdlib only (tomllib needs Python 3.11+). No third-party deps, by design: the
plugin IS the repo, auditable in plain text.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tomllib
from dataclasses import dataclass, field

SCHEMA_VERSION = 1

# ─────────────────────────────────────────────────────────────────────────────
# glob → regex   (gitignore-ish: ** crosses directories, * does not)
# ─────────────────────────────────────────────────────────────────────────────


def _glob_to_re(pattern: str) -> re.Pattern[str]:
    """Translate a path glob to an anchored regex. `**/` matches zero+ dir
    segments, `**` matches anything, `*` stays within a segment, `?` one char."""
    out: list[str] = []
    i, n = 0, len(pattern)
    while i < n:
        if pattern.startswith("**/", i):
            out.append(r"(?:[^/]*/)*")
            i += 3
        elif pattern.startswith("**", i):
            out.append(r".*")
            i += 2
        elif pattern[i] == "*":
            out.append(r"[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append(r"[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("^" + "".join(out) + "$")


def _path_matches(path: str, patterns: list[str]) -> bool:
    return any(_glob_to_re(p).match(path) for p in patterns)


def _path_or_base_matches(path: str, patterns: list[str]) -> bool:
    """Match a glob against the full path OR the basename, so a forbidden-file glob
    like `.env` / `*.pem` catches both `.env` and `config/.env` without `**/` noise."""
    base = path.rsplit("/", 1)[-1]
    return _path_matches(path, patterns) or _path_matches(base, patterns)


def _rx(pat: str | None) -> re.Pattern[str] | None:
    if not pat:
        return None
    try:
        return re.compile(pat)
    except re.error:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# config
# ─────────────────────────────────────────────────────────────────────────────

KINDS = {"fact", "advisory"}
SEVERITIES = {"block", "warn", "attest", "judge"}
LAYERS = {"agent", "change", "both"}
PRIMITIVES = {
    "secret_scan",
    "forbid_command",
    "forbid_pattern",
    "forbid_removal",
    "forbid_delete",
    "forbid_commit_on_branch",
    "scope_lock",
    "forbid_in_message",
    "numeric_floor",
    "path_requires",
    "cooccur",
    "marker_present",
    "commit_footer",
    "protected_path",
    "run",
    "attest",
    "judge",
}


class ConfigError(Exception):
    """A malformed config is a hard error — never a silently-degraded gate."""


@dataclass
class RepoCfg:
    default_branch: str = "main"
    code: list[str] = field(default_factory=list)
    tests: list[str] = field(default_factory=list)
    docs: list[str] = field(default_factory=list)
    # named scopes for agent-layer attestation class-gating
    public_surface: list[str] = field(default_factory=list)
    claude_md: list[str] = field(default_factory=lambda: ["**/CLAUDE.md", "**/AGENTS.md"])


@dataclass
class Meta:
    bypass_env: str | None = None
    commit_footer: str | None = None
    # THE decisive bypass-proof invariant: read config + gate-defining files from
    # the pinned base ref, never the PR head. Defaults ON.
    base_pinned: bool = True
    # agent-layer attestation (the Stop-hook checklist the agent must tick)
    attestation_file: str = ".ratchet/attestation.md"
    # a change is "feature-shaped" at >= this many changed files (or a new code module)
    feature_files: int = 3


@dataclass
class Check:
    id: str
    kind: str
    severity: str
    primitive: str
    layer: str = "change"
    # primitive params (all optional; the primitive selects which it reads)
    pattern: str | None = None
    scope: list[str] = field(default_factory=list)  # named scope(s) or literal glob(s)
    exempt: str | None = None
    strip_comments: bool = False
    when: list[str] = field(default_factory=list)
    need: list[str] = field(default_factory=list)
    when_marker: str | None = None
    marker: str | None = None
    where: str | None = None
    cmd: str | None = None
    trigger: str | None = None
    require: str | None = None
    custom: list[str] = field(default_factory=list)
    forbid_paths: list[str] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)
    require_approval: bool = True
    # forbid_delete: a paired added file under the same scope (a rename/replace) suppresses
    unless_paired_add: bool = False
    # forbid_commit_on_branch: protected branch glob(s) + the git op(s) to deny on them
    branch: list[str] = field(default_factory=list)
    ops: list[str] = field(default_factory=list)
    # scope_lock: the ONLY path globs a change may touch (a positive allowlist)
    allow: list[str] = field(default_factory=list)
    # forbid_in_message: literal tokens forbidden in commit/PR message text
    tokens: list[str] = field(default_factory=list)
    msg_scope: list[str] = field(default_factory=list)  # commit_subject|commit_body|pr_body (default all)
    # forbid_command: a normalized-verb deny-list (defeats git -C/cd &&/env wrappers)
    deny: list[str] = field(default_factory=list)
    # numeric_floor: a key regex (group 1 = value) + a direction; optional absolute floor
    key: str | None = None
    direction: str | None = None
    floor: float | None = None
    cls: str | None = None  # attestation class: always | feature | public_surface | claude_md
    box: str | None = None  # the attestation checkbox label to look for (defaults to id)
    prompt: str | None = None


def _as_list(v) -> list[str]:
    """A field that may be a bare string or a list of strings → list."""
    if v is None:
        return []
    if isinstance(v, str):
        return [v]
    if isinstance(v, list):
        return [str(x) for x in v]
    raise ConfigError(f"expected string or list, got {type(v).__name__}")


@dataclass
class Config:
    schema: int
    repo: RepoCfg
    meta: Meta
    checks: list[Check]

    @staticmethod
    def parse(text: str) -> "Config":
        try:
            raw = tomllib.loads(text)
        except tomllib.TOMLDecodeError as e:
            raise ConfigError(f"invalid TOML: {e}") from e
        cfg = Config._from_raw(raw)
        cfg.validate()
        return cfg

    @staticmethod
    def _from_raw(raw: dict) -> "Config":
        r = raw.get("repo", {})
        repo = RepoCfg(
            default_branch=r.get("default_branch", "main"),
            code=_as_list(r.get("code")),
            tests=_as_list(r.get("tests")),
            docs=_as_list(r.get("docs")),
            public_surface=_as_list(r.get("public_surface")),
            claude_md=_as_list(r.get("claude_md")) or ["**/CLAUDE.md", "**/AGENTS.md"],
        )
        m = raw.get("meta", {})
        meta = Meta(
            bypass_env=m.get("bypass_env"),
            commit_footer=m.get("commit_footer"),
            base_pinned=bool(m.get("base_pinned", True)),
            attestation_file=m.get("attestation_file", ".ratchet/attestation.md"),
            feature_files=int(m.get("feature_files", 3)),
        )
        checks = []
        for c in raw.get("check", []):
            try:
                checks.append(
                    Check(
                        id=c["id"],
                        kind=c["kind"],
                        severity=c["severity"],
                        primitive=c["primitive"],
                        layer=c.get("layer", "change"),
                        pattern=c.get("pattern"),
                        scope=_as_list(c.get("scope")),
                        exempt=c.get("exempt"),
                        strip_comments=bool(c.get("strip_comments", False)),
                        when=_as_list(c.get("when")),
                        need=_as_list(c.get("need")),
                        when_marker=c.get("when_marker"),
                        marker=c.get("marker"),
                        where=c.get("where"),
                        cmd=c.get("cmd"),
                        trigger=c.get("trigger"),
                        require=c.get("require"),
                        custom=_as_list(c.get("custom")),
                        forbid_paths=_as_list(c.get("forbid_paths")),
                        paths=_as_list(c.get("paths")),
                        require_approval=bool(c.get("require_approval", True)),
                        unless_paired_add=bool(c.get("unless_paired_add", False)),
                        branch=_as_list(c.get("branch")),
                        ops=_as_list(c.get("ops")),
                        allow=_as_list(c.get("allow")),
                        tokens=_as_list(c.get("tokens")),
                        msg_scope=_as_list(c.get("msg_scope")),
                        deny=_as_list(c.get("deny")),
                        key=c.get("key"),
                        direction=c.get("direction"),
                        floor=(float(c["floor"]) if c.get("floor") is not None else None),
                        cls=c.get("class"),
                        box=c.get("box"),
                        prompt=c.get("prompt"),
                    )
                )
            except KeyError as e:
                raise ConfigError(f"check missing required field {e}") from e
        return Config(schema=raw.get("schema", 0), repo=repo, meta=meta, checks=checks)

    def validate(self) -> None:
        if self.schema != SCHEMA_VERSION:
            raise ConfigError(
                f"unsupported schema version {self.schema}, expected {SCHEMA_VERSION}"
            )
        seen_ids: set[str] = set()
        for c in self.checks:
            if c.id in seen_ids:
                raise ConfigError(f"duplicate check id `{c.id}`")
            seen_ids.add(c.id)
            if c.kind not in KINDS:
                raise ConfigError(f"check `{c.id}`: unknown kind `{c.kind}`")
            if c.severity not in SEVERITIES:
                raise ConfigError(f"check `{c.id}`: unknown severity `{c.severity}`")
            if c.layer not in LAYERS:
                raise ConfigError(f"check `{c.id}`: unknown layer `{c.layer}`")
            if c.primitive not in PRIMITIVES:
                raise ConfigError(f"check `{c.id}`: unknown primitive `{c.primitive}`")
            # THE moat: only ungameable facts may hard-block.
            if c.severity == "block" and c.kind != "fact":
                raise ConfigError(
                    f"check `{c.id}`: severity=block requires kind=fact (only "
                    f"diff/command/PR-metadata facts may block; advisory checks are "
                    f"gameable by the gated agent)"
                )
            # A `run` block is authoritative only at the change layer (repo author
            # controls the script there); never let it block from the agent layer.
            if c.primitive == "run" and c.severity == "block" and c.layer == "agent":
                raise ConfigError(
                    f"check `{c.id}`: a `run` block must live at the change layer, not agent"
                )
            # The current branch is a LIVE agent-layer fact (read at the PreToolUse
            # intercept); a pure change-layer placement would silently never fire.
            if c.primitive == "forbid_commit_on_branch" and c.layer == "change":
                raise ConfigError(
                    f"check `{c.id}`: forbid_commit_on_branch reads the live branch — "
                    f"declare layer=\"agent\" (or \"both\"), not change"
                )

    @property
    def footer_regex(self) -> str | None:
        return self.meta.commit_footer


# ─────────────────────────────────────────────────────────────────────────────
# facts  (the ONLY inputs a `fact` check reads — all ungameable by the agent)
# ─────────────────────────────────────────────────────────────────────────────

ADDED, MODIFIED, DELETED = "A", "M", "D"


@dataclass
class DiffFacts:
    added: list[tuple[str, str]] = field(default_factory=list)  # (new path, added line)
    removed: list[tuple[str, str]] = field(default_factory=list)  # (old path, removed line)
    changed: list[tuple[str, str]] = field(default_factory=list)  # (status, path)
    # None = no PR context (local pre-push) → PR-body checks skip rather than false-fire.
    # "" = a real but empty PR body (CI) → a missing required marker DOES fail.
    pr_body: str | None = None
    commit_msgs: list[str] = field(default_factory=list)
    # PR-review facts (None = no PR context → skip approval checks; [] = PR, zero approvals)
    approvals: list[str] | None = None

    def changed_paths(self):
        return (p for _, p in self.changed)

    @staticmethod
    def from_range(cwd: str, base: str, head: str = "HEAD") -> "DiffFacts":
        rng = f"{base}..{head}"
        f = DiffFacts()
        ns = _git(cwd, ["diff", "--name-status", rng])
        if ns:
            for line in ns.splitlines():
                parts = line.split("\t")
                if len(parts) < 2:
                    continue
                st = parts[0][:1]
                status = {"A": ADDED, "D": DELETED}.get(st, MODIFIED)
                f.changed.append((status, parts[-1]))
        diff = _git(cwd, ["diff", "--unified=0", rng])
        if diff:
            # new = +++ b/<path> for added/modified; old = --- a/<path> for the removed
            # side (the old path also covers whole-file deletes, where +++ is /dev/null).
            new_path = old_path = ""
            for line in diff.splitlines():
                if line.startswith("--- a/"):
                    old_path = line[6:]
                elif line.startswith("--- "):
                    old_path = ""  # /dev/null (added file) → no removed-side path
                elif line.startswith("+++ b/"):
                    new_path = line[6:]
                elif line.startswith("+++ "):
                    new_path = ""
                elif line.startswith("+") and not line.startswith("+++") and new_path:
                    f.added.append((new_path, line[1:]))
                elif line.startswith("-") and not line.startswith("---") and old_path:
                    f.removed.append((old_path, line[1:]))
        log = _git(cwd, ["log", "--format=%B%x1e", rng])
        if log:
            f.commit_msgs = [m.strip() for m in log.split("\x1e") if m.strip()]
        return f


@dataclass
class CommandFacts:
    command: str

    @staticmethod
    def from_pretooluse_json(stdin: str) -> "CommandFacts":
        """PreToolUse delivers a JSON envelope; the Bash command is at
        `.tool_input.command`. Unknown shapes degrade to empty (no false block)."""
        try:
            v = json.loads(stdin)
            cmd = v.get("tool_input", {}).get("command", "")
        except (json.JSONDecodeError, AttributeError):
            cmd = ""
        return CommandFacts(command=cmd if isinstance(cmd, str) else "")


def _git(cwd: str, args: list[str]) -> str | None:
    try:
        out = subprocess.run(
            ["git", "-C", cwd, *args],
            capture_output=True,
            text=True,
            check=False,
        )
    except (OSError, ValueError):
        return None
    return out.stdout if out.returncode == 0 else None


# ─────────────────────────────────────────────────────────────────────────────
# primitive evaluators  (pure functions; return a reason str on FAIL, None on PASS)
# ─────────────────────────────────────────────────────────────────────────────

# Built-in high-precision secret shapes (a fuller gitleaks ruleset can be layered).
DEFAULT_SECRETS = [
    r"ghp_[A-Za-z0-9]{36}",
    r"github_pat_[A-Za-z0-9_]{50,}",
    r"sk-[A-Za-z0-9]{20,}",
    r"AKIA[0-9A-Z]{16}",
    r"xox[baprs]-[A-Za-z0-9-]{10,}",
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
]


def _resolve(names: list[str], repo: RepoCfg) -> list[str]:
    """Expand named scopes (code/tests/docs) to repo globs; pass literals through."""
    out: list[str] = []
    for n in names:
        if n in ("code", "code_public"):
            out += repo.code
        elif n == "tests":
            out += repo.tests
        elif n == "docs":
            out += repo.docs
        else:
            out.append(n)
    return out


def _strip_comment(line: str) -> str:
    """Naive trailing-comment strip so a `// tmp`-style pragma can't hide a token."""
    for marker in ("//", "#"):
        idx = line.find(marker)
        if idx != -1:
            line = line[:idx]
    return line


def forbid_command(check: Check, facts: CommandFacts) -> str | None:
    # legacy `pattern`: a raw regex matched anywhere (catches --no-verify in any position)
    pat = _rx(check.pattern)
    if pat and pat.search(facts.command):
        return f"command matches forbidden pattern for `{check.id}`"
    # `deny`: a NORMALIZED verb match — strips `git -C`/`-c k=v`, `cd d &&`, `env X=Y`,
    # `sudo` wrappers so the gated verb can't be smuggled past prefix matching (#66176).
    if check.deny:
        hit = _deny_hit(facts.command, check.deny)
        if hit:
            return f"`{check.id}`: forbidden command `{hit}`"
    return None


def secret_scan(check: Check, facts: DiffFacts) -> str | None:
    # 1) .env-style forbidden paths must never enter a commit
    for st, path in facts.changed:
        if st != DELETED and _path_or_base_matches(path, check.forbid_paths):
            return f"forbidden secret-bearing path added: {path}"
    # 2) token shapes in added lines
    pats = [r for r in (_rx(p) for p in DEFAULT_SECRETS + check.custom) if r]
    for path, line in facts.added:
        if any(r.search(line) for r in pats):
            return f"possible secret in added line ({path})"
    return None


def forbid_pattern(check: Check, facts: DiffFacts, repo: RepoCfg) -> str | None:
    pat = _rx(check.pattern)
    if not pat:
        return None
    scope = _resolve(check.scope, repo) if check.scope else []
    exempt = _rx(check.exempt)
    for path, line in facts.added:
        if scope and not _path_matches(path, scope):
            continue
        hay = _strip_comment(line) if check.strip_comments else line
        if not pat.search(hay):
            continue
        # exempt either the PATH (allowlisted module) or the LINE (pragma)
        if exempt and (exempt.search(path) or exempt.search(line)):
            continue
        return f"forbidden pattern in {path}: `{line.strip()}`"
    return None


def forbid_removal(check: Check, facts: DiffFacts, repo: RepoCfg) -> str | None:
    """The `-` twin of forbid_pattern: a REMOVED line matching the pattern under
    scope blocks. Closes the 'silently delete the safety net' class (drop an
    assert / await / `?` / auth check / `# nosec`) that the added-line surface is
    blind to. Pure renames produce no removed lines (git rename-detection), so
    they don't false-fire."""
    pat = _rx(check.pattern)
    if not pat:
        return None
    scope = _resolve(check.scope, repo) if check.scope else []
    exempt = _rx(check.exempt)
    for path, line in facts.removed:
        if scope and not _path_matches(path, scope):
            continue
        hay = _strip_comment(line) if check.strip_comments else line
        if not pat.search(hay):
            continue
        if exempt and (exempt.search(path) or exempt.search(line)):
            continue
        return f"forbidden removal in {path}: `{line.strip()}`"
    return None


def forbid_delete(check: Check, facts: DiffFacts, repo: RepoCfg) -> str | None:
    """File D-status guard: deleting a file under scope blocks ('delete the failing
    test to go green'). `unless_paired_add` suppresses when an added file exists
    under the same scope (a coarse rename/replace proxy)."""
    scope = _resolve(check.scope, repo) if check.scope else []
    exempt = _rx(check.exempt)

    def in_scope(p: str) -> bool:
        return not scope or _path_matches(p, scope)

    deleted = [
        p for st, p in facts.changed
        if st == DELETED and in_scope(p) and not (exempt and exempt.search(p))
    ]
    if not deleted:
        return None
    if check.unless_paired_add and any(st == ADDED and in_scope(p) for st, p in facts.changed):
        return None
    return f"forbidden deletion of {deleted[0]} (under {check.scope or 'any path'})"


def scope_lock(check: Check, facts: DiffFacts, repo: RepoCfg) -> str | None:
    """Positive allowlist — the structural inverse of the denylist path family. Every
    A/M/D path must fall inside `allow`; any file outside the declared scope blocks
    (the scope-creep / unauthorized-out-of-scope-edit class). An empty allow is inert."""
    if not check.allow:
        return None
    allow = _resolve(check.allow, repo)
    for _st, path in facts.changed:
        if not _path_matches(path, allow):
            return f"`{check.id}`: {path} is outside the declared scope {check.allow}"
    return None


_MSG_SCOPES = ("commit_subject", "commit_body", "pr_body")


def forbid_in_message(check: Check, facts: DiffFacts) -> str | None:
    """Forbid literal tokens (case-insensitive) in commit/PR message text — e.g. a
    `[skip ci]` that disarms the change layer's own CI host. The require-presence
    primitives (marker_present/commit_footer) have no forbid-presence inverse."""
    if not check.tokens:
        return None
    scopes = set(check.msg_scope) or set(_MSG_SCOPES)
    hay: list[str] = []
    for msg in facts.commit_msgs:
        lines = msg.splitlines()
        if "commit_subject" in scopes and lines:
            hay.append(lines[0])
        if "commit_body" in scopes and len(lines) > 1:
            hay.append("\n".join(lines[1:]))
    if "pr_body" in scopes and facts.pr_body:
        hay.append(facts.pr_body)
    blob = "\n".join(hay).lower()
    for t in check.tokens:
        if t.lower() in blob:
            return f"`{check.id}`: forbidden token `{t}` in the commit/PR message"
    return None


def _num_hits(lines: list[tuple[str, str]], scope: list[str], key_rx: re.Pattern[str]) -> dict[str, float]:
    """{key-prefix → value} for lines (in scope) whose key regex captures a number in
    group 1. The prefix (text before the value) is the pairing identity across hunks."""
    out: dict[str, float] = {}
    for path, line in lines:
        if scope and not _path_matches(path, scope):
            continue
        m = key_rx.search(line)
        if not m:
            continue
        try:
            out[line[: m.start(1)].strip()] = float(m.group(1))
        except (ValueError, IndexError):
            continue
    return out


def numeric_floor(check: Check, facts: DiffFacts, repo: RepoCfg) -> str | None:
    """The namesake ratchet: pair a numeric token across the remove/add hunks on the
    SAME key and block a weakening direction (lower coverage / raised retries), plus an
    optional absolute floor. forbid_removal/forbid_pattern see one side only — neither
    computes direction (85→75 is byte-identical to 75→85)."""
    key_rx = _rx(check.key)
    if not key_rx:
        return None
    scope = _resolve(check.scope, repo) if check.scope else []
    direction = check.direction or "no_decrease"
    olds = _num_hits(facts.removed, scope, key_rx)
    news = _num_hits(facts.added, scope, key_rx)
    for prefix, new_val in news.items():
        if check.floor is not None:
            if direction == "no_decrease" and new_val < check.floor:
                return f"`{check.id}`: {prefix} {new_val:g} is below the floor {check.floor:g}"
            if direction == "no_increase" and new_val > check.floor:
                return f"`{check.id}`: {prefix} {new_val:g} is above the ceiling {check.floor:g}"
        if prefix in olds:
            old_val = olds[prefix]
            weaker = new_val < old_val if direction == "no_decrease" else new_val > old_val
            if weaker:
                return f"`{check.id}`: {prefix} weakened {old_val:g} → {new_val:g}"
    return None


def path_requires(check: Check, facts: DiffFacts, repo: RepoCfg) -> str | None:
    need = _resolve(check.need, repo)
    if not need:
        return None
    if check.when_marker:
        m = _rx(check.when_marker)
        triggered = bool(m and m.search(facts.pr_body or ""))
    else:
        when = _resolve(check.when, repo)
        triggered = any(_path_matches(p, when) for p in facts.changed_paths())
    if not triggered:
        return None
    if any(_path_matches(p, need) for p in facts.changed_paths()):
        return None
    return f"`{check.id}`: a triggering change requires touching {check.need}"


def cooccur(check: Check, facts: DiffFacts) -> str | None:
    trig, req = _rx(check.trigger), _rx(check.require)
    if not trig or not req:
        return None
    body = facts.pr_body or ""
    present = trig.search(body) or any(trig.search(l) for _, l in facts.added)
    if not present:
        return None
    satisfied = (
        req.search(body)
        or any(req.search(l) for _, l in facts.added)
        or any(req.search(m) for m in facts.commit_msgs)
    )
    if satisfied:
        return None
    return f"`{check.id}`: trigger present but required co-occurrence missing"


def marker_present(check: Check, facts: DiffFacts, repo: RepoCfg) -> str | None:
    """A required marker block exists in the PR body. Skips when there's no PR
    context (local pre-push, `pr_body is None`). Optional `when` gate: only require
    the marker when a `when`-scoped path changed (e.g. "code touched → two-lens")."""
    if facts.pr_body is None:
        return None  # no PR context → CI (which has the body) is the real gate
    if check.when:
        when = _resolve(check.when, repo)
        if not any(_path_matches(p, when) for p in facts.changed_paths()):
            return None
    m = _rx(check.marker)
    if not m:
        return None
    if m.search(facts.pr_body):
        return None
    return f"`{check.id}`: required marker `{check.marker}` absent from PR body"


def commit_footer(footer_rx: str | None, facts: DiffFacts) -> str | None:
    rx = _rx(footer_rx)
    if not rx:
        return None
    for msg in facts.commit_msgs:
        if not rx.search(msg):
            return "a commit is missing the required footer"
    return None


def protected_path(check: Check, facts: DiffFacts) -> str | None:
    """Any change to gate-defining files needs an independent approval. Only
    evaluated in a PR context (approvals is not None); skipped on local pre-push."""
    if facts.approvals is None:
        return None  # no PR context → defer to the CI run of this same check
    touched = [p for p in facts.changed_paths() if _path_matches(p, check.paths)]
    if not touched:
        return None
    if check.require_approval and not facts.approvals:
        return (
            f"`{check.id}`: gate-defining file(s) changed ({touched[0]}…) "
            f"without an independent approval"
        )
    return None


# ─────────────────────────────────────────────────────────────────────────────
# engine
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class Finding:
    id: str
    severity: str
    reason: str


def has_block(findings: list[Finding]) -> bool:
    return any(f.severity == "block" for f in findings)


def load_config(cwd: str, base_ref: str | None) -> Config:
    """The decisive bypass-proof load: read `ratchet.toml` from the PINNED BASE ref,
    never the PR head, so a same-diff edit can't relax the gate it's gated by.
    Falls back to the working tree only when the base ref has no ratchet.toml yet
    (e.g. the first-ever commit adding it)."""
    if base_ref:
        text = _git(cwd, ["show", f"{base_ref}:ratchet.toml"])
        if text is not None:
            cfg = Config.parse(text)
            if cfg.meta.base_pinned:
                return cfg
            # base_pinned explicitly off → honour the working-tree policy instead
    with open(os.path.join(cwd, "ratchet.toml"), encoding="utf-8") as fh:
        return Config.parse(fh.read())


def _eval_diff(c: Check, cfg: Config, facts: DiffFacts) -> str | None:
    p = c.primitive
    if p == "secret_scan":
        return secret_scan(c, facts)
    if p == "forbid_pattern":
        return forbid_pattern(c, facts, cfg.repo)
    if p == "forbid_removal":
        return forbid_removal(c, facts, cfg.repo)
    if p == "forbid_delete":
        return forbid_delete(c, facts, cfg.repo)
    if p == "scope_lock":
        return scope_lock(c, facts, cfg.repo)
    if p == "forbid_in_message":
        return forbid_in_message(c, facts)
    if p == "numeric_floor":
        return numeric_floor(c, facts, cfg.repo)
    if p == "path_requires":
        return path_requires(c, facts, cfg.repo)
    if p == "cooccur":
        return cooccur(c, facts)
    if p == "marker_present":
        return marker_present(c, facts, cfg.repo)
    if p == "commit_footer":
        return commit_footer(cfg.footer_regex, facts)
    if p == "protected_path":
        return protected_path(c, facts)
    if p == "run":
        return _run_shell(c.cmd or "true")
    # attest/judge/forbid_command/forbid_commit_on_branch are agent-layer, not diff-evaluated
    return None


def run_change(cfg: Config, facts: DiffFacts, allow_run: bool = True) -> list[Finding]:
    """CHANGE layer: every non-agent block/warn check over the committed diff.

    `allow_run=False` skips `run` blocks (test suites etc.) so the agent-layer Stop
    hook stays cheap — the expensive teeth fire only at pre-push/CI."""
    out: list[Finding] = []
    for c in cfg.checks:
        if c.layer == "agent":
            continue
        if c.severity not in ("block", "warn"):
            continue  # attest/judge handled by Stop hook / advisory judge
        if c.primitive == "run" and not allow_run:
            continue
        reason = _eval_diff(c, cfg, facts)
        if reason:
            out.append(Finding(c.id, c.severity, reason))
    return out


def run_command_gate(cfg: Config, cmd: CommandFacts) -> list[Finding]:
    """AGENT layer: only forbid_command checks decide over the command string."""
    out: list[Finding] = []
    for c in cfg.checks:
        if c.primitive != "forbid_command":
            continue
        reason = forbid_command(c, cmd)
        if reason:
            out.append(Finding(c.id, c.severity, reason))
    return out


def _run_shell(cmd: str) -> str | None:
    try:
        r = subprocess.run(cmd, shell=True, check=False)
    except OSError as e:
        return f"`run` gate could not execute `{cmd}`: {e}"
    return None if r.returncode == 0 else f"`run` gate failed: {cmd}"


def _render(findings: list[Finding]) -> str:
    return "\n".join(
        f"  [{'BLOCK' if f.severity == 'block' else 'warn '}] {f.id}: {f.reason}"
        for f in findings
    )


# ─────────────────────────────────────────────────────────────────────────────
# agent layer  (Stop attestation + the push/merge DoD gate)
# ─────────────────────────────────────────────────────────────────────────────


def change_classes(cfg: Config, facts: DiffFacts) -> dict:
    """Which attestation classes a change triggers (mirrors the bespoke gate's
    ChangeClass). `feature` = >= meta.feature_files changed OR a new code module;
    `public_surface`/`claude_md` key off the repo's named scopes."""
    repo = cfg.repo
    paths = list(facts.changed_paths())
    code = any(_path_matches(p, repo.code) for p in paths)
    added_module = any(st == ADDED and _path_matches(p, repo.code) for st, p in facts.changed)
    feature = len(facts.changed) >= cfg.meta.feature_files or added_module
    public = bool(repo.public_surface) and any(_path_matches(p, repo.public_surface) for p in paths)
    claude = any(_path_matches(p, repo.claude_md) for p in paths)
    return {
        "always": code,
        "feature": code and feature,
        "public_surface": code and public,
        "claude_md": claude,
    }


def _ticked(md: str, label: str) -> bool:
    return bool(re.search(rf"-\s*\[[xX]\]\s*{re.escape(label)}\b", md or ""))


def attestation_gaps(cfg: Config, facts: DiffFacts, md: str) -> list[Finding]:
    """Required-but-unticked `attest` boxes for this change-class. Agent-layer
    forcing function (the agent ticks its own boxes — the ungameable CHANGE layer is
    the real gate); class-gating keeps a docs-only/clean tree at zero required boxes."""
    cls = change_classes(cfg, facts)
    gaps: list[Finding] = []
    for c in cfg.checks:
        if c.primitive != "attest":
            continue
        if not cls.get(c.cls or "always", False):
            continue
        label = c.box or c.id
        if not _ticked(md, label):
            gaps.append(Finding(c.id, "block", f"unticked DoD box: {label}"))
    return gaps


# Git global options that consume the NEXT token as a value, so the subcommand
# scanner skips that value token (tokenized → ReDoS-immune, unlike a mega-regex).
_GIT_VALUE_OPTS = frozenset(
    {"-c", "-C", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--super-prefix"}
)
_SHELL_SEP = re.compile(r"[;&|\n]+")
_MERGE_RE = re.compile(r"\bgh\s+pr\s+merge\b|\bgh\s+api\b[^|&;]*?/merge\b")


def _strip_quotes(s: str) -> str:
    return re.sub(r"'[^']*'|\"[^\"]*\"", "", s)


def _git_ops(cmd: str) -> set[str]:
    """The set of git SUBCOMMANDS invoked across shell-separated segments, tolerating
    leading git global options + their values (`git -C dir -c k=v push` → {"push"}).
    Quote-stripped first so a subcommand named inside a message isn't a false hit.
    Tokenized (not a mega-regex) → ReDoS-immune."""
    c = _strip_quotes(cmd or "")
    ops: set[str] = set()
    for seg in _SHELL_SEP.split(c):
        toks = seg.split()
        i = 0
        while i < len(toks):
            if toks[i] != "git":
                i += 1
                continue
            j = i + 1
            while j < len(toks) and toks[j].startswith("-"):
                opt = toks[j]
                j += 1
                if opt in _GIT_VALUE_OPTS and j < len(toks):
                    j += 1
            if j < len(toks):
                ops.add(toks[j])
            i = j + 1
    return ops


def push_or_merge(cmd: str) -> str | None:
    """"merge" / "push" / None for a shell command. `gh pr merge` (or `gh api …/merge`)
    → merge; any `git push` (via the tokenized op scan) → push."""
    if _MERGE_RE.search(_strip_quotes(cmd or "")):
        return "merge"
    return "push" if "push" in _git_ops(cmd) else None


_ENV_ASSIGN = re.compile(r"^\w+=")


def _normalize_command_segments(cmd: str) -> list[list[str]]:
    """Shell-split, then per segment strip leading `sudo` + `VAR=val` assignments and,
    for a git invocation, drop global options (+ their values) so the gated verb sits at
    the front. Quote-stripped first. Defeats the `git -C/path`, `cd d &&`, `env X=Y`,
    `git -c k=v` evasions that prefix matching misses (#66176)."""
    segs: list[list[str]] = []
    for seg in _SHELL_SEP.split(_strip_quotes(cmd or "")):
        toks = seg.split()
        i = 0
        while i < len(toks) and (toks[i] == "sudo" or _ENV_ASSIGN.match(toks[i])):
            i += 1
        toks = toks[i:]
        if toks and toks[0] == "git":
            j = 1
            while j < len(toks) and toks[j].startswith("-"):
                opt = toks[j]
                j += 1
                if opt in _GIT_VALUE_OPTS and j < len(toks):
                    j += 1
            toks = ["git"] + toks[j:]
        if toks:
            segs.append(toks)
    return segs


def _deny_hit(cmd: str, deny: list[str]) -> str | None:
    """The first deny phrase whose tokens appear as a contiguous run in any normalized
    segment (token-equality, so `git push` never matches `git push-mirror`)."""
    norm = _normalize_command_segments(cmd)
    for phrase in deny:
        pt = phrase.split()
        if not pt:
            continue
        for toks in norm:
            for s in range(len(toks) - len(pt) + 1):
                if toks[s : s + len(pt)] == pt:
                    return phrase
    return None


def run_branch_gate(cfg: Config, cmd: CommandFacts, current_branch: str | None) -> list[Finding]:
    """AGENT layer: forbid_commit_on_branch — deny commit/push on a protected branch.
    The current branch is an ungameable live fact; the only way to satisfy the gate
    is to branch first (`git checkout -b`), which is the intended outcome. Returns []
    on a detached/unknown branch so it never false-fires."""
    out: list[Finding] = []
    if current_branch is None:
        return out
    invoked = _git_ops(cmd.command)
    for c in cfg.checks:
        if c.primitive != "forbid_commit_on_branch" or c.layer == "change":
            continue
        ops = set(c.ops) or {"commit", "push"}
        if not (invoked & ops):
            continue
        branches = c.branch or [cfg.repo.default_branch]
        if _path_matches(current_branch, branches):
            hit = " / ".join(sorted(invoked & ops))
            out.append(Finding(
                c.id, c.severity,
                f"`{c.id}`: {hit} on protected branch `{current_branch}` — branch first "
                f"(git checkout -b <name>)",
            ))
    return out


def _local_facts(cwd: str, default_branch: str) -> DiffFacts:
    """Diff facts for ahead-of-main COMMITS in this worktree (not the working tree —
    defeats commit-then-stash fakery), the agent-layer view."""
    base = _resolve_base(cwd, default_branch) or "HEAD~1"
    return DiffFacts.from_range(cwd, base)


def _attestation_text(cwd: str, cfg: Config) -> str:
    try:
        with open(os.path.join(cwd, cfg.meta.attestation_file), encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return ""


def _bypass_reason(cfg: Config, md: str) -> str | None:
    """Agent-layer bypass: a non-empty `[meta].bypass_env` value, or a
    `<BYPASS_ENV-with-dashes>: <reason>` line in the attestation (so `DOD_BYPASS` →
    `DOD-BYPASS:`, seamless with an existing repo's convention). CHANGE layer ignores it."""
    env = cfg.meta.bypass_env
    if not env:
        return None
    if (os.environ.get(env) or "").strip():
        return os.environ[env].strip()
    marker = env.replace("_", "-")
    m = re.search(rf"^\s*{re.escape(marker)}\s*:\s*(\S.*)$", md or "", re.MULTILINE)
    return m.group(1).strip() if m else None


def _gh_pr_body(cwd: str) -> str | None:
    """The open PR's body for the current branch (the two-lens block lives there),
    or None if gh is unavailable / there is no PR."""
    try:
        p = subprocess.run(
            ["gh", "pr", "view", "--json", "body", "-q", ".body"],
            cwd=cwd, capture_output=True, text=True,
        )
    except OSError:
        return None
    return p.stdout if p.returncode == 0 else None


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

INIT_TEMPLATE = """\
# ratchet.toml — Definition-of-Done policy. https://github.com/IvanWng97/ratchet
# The one rule: severity="block" REQUIRES kind="fact". Only ungameable
# diff/command/PR facts may block; everything judged stays advisory.
schema = 1

[repo]
default_branch = "main"
code = ["src/**"]
tests = ["tests/**"]
docs = ["**/*.md"]

[meta]
# Read this file + gate-defining files from the pinned base ref (bypass-proof).
base_pinned = true
# bypass_env = "RATCHET_BYPASS"          # agent-layer escape hatch (always logged)
# commit_footer = 'Co-Authored-By:'  # require a footer on every commit

# Deny --no-verify at the moment the agent reaches for it (real-time, agent layer).
[[check]]
id = "no-verify"
kind = "fact"
severity = "block"
layer = "agent"
primitive = "forbid_command"
pattern = "--no-verify|--no-gpg-sign|HUSKY=0"

# "If on main, branch first." Deny a commit/push on the default branch in real time;
# the only way past is `git checkout -b` — which is the intended outcome.
[[check]]
id = "branch-first"
kind = "fact"
severity = "block"
layer = "agent"
primitive = "forbid_commit_on_branch"
branch = ["main"]
ops = ["commit", "push"]

# Never let a credential into the diff.
[[check]]
id = "secret-scan"
kind = "fact"
severity = "block"
primitive = "secret_scan"
forbid_paths = [".env", ".env.*", "*.env", "*.pem", "*.key", "id_rsa", "*.p12"]

# A code change should touch docs (existence-floor; "right doc?" is judged elsewhere).
[[check]]
id = "docs-currency"
kind = "fact"
severity = "warn"
primitive = "path_requires"
when = "code"
need = "docs"

# Close the two canonical "make CI green by doing less" corner-cuts. Uncomment to arm:
#
# "delete the failing test" — a whole test-file deletion (unless a test is added in
# the same change, i.e. a rename/reorg):
# [[check]]
# id = "no-test-delete"
# kind = "fact"
# severity = "block"
# primitive = "forbid_delete"
# scope = "tests"
# unless_paired_add = true
#
# "strip the assertion" — a REMOVED guard line (the '-' twin of forbid_pattern):
# [[check]]
# id = "keep-asserts"
# kind = "fact"
# severity = "block"
# primitive = "forbid_removal"
# pattern = "assert|expect\\\\(|\\\\bawait\\\\b"
# scope = "code"
"""


def _current_branch(cwd: str) -> str | None:
    """The live agent-layer branch fact. None on a detached HEAD (`git symbolic-ref`
    fails) → forbid_commit_on_branch never false-fires there."""
    out = _git(cwd, ["symbolic-ref", "--short", "-q", "HEAD"])
    return out.strip() if out and out.strip() else None


def _resolve_base(cwd: str, default_branch: str) -> str | None:
    mb = _git(cwd, ["merge-base", f"origin/{default_branch}", "HEAD"])
    if mb and mb.strip():
        return mb.strip()
    # no remote tracking → fall back to the previous commit (best-effort local)
    head_parent = _git(cwd, ["rev-parse", "HEAD~1"])
    return head_parent.strip() if head_parent and head_parent.strip() else None


def _reasons(findings: list[Finding]) -> str:
    return "; ".join(f.reason for f in findings)


def cmd_gate() -> int:
    """PreToolUse(Bash): exit 2 = deny (stderr shown to the agent), 0 = allow.

    Two denials: (1) a forbidden command shape (e.g. --no-verify) — a HARD deny, not
    bypassable; (2) a `git push` / `gh pr merge` whose ahead-of-main DoD blocks fail
    (for a merge, also the two-lens block in the PR body) — bypassable via the
    agent-layer escape hatch, because CI still enforces."""
    buf = sys.stdin.read()
    cmd = CommandFacts.from_pretooluse_json(buf)
    try:
        cfg = _read_working_config(".")
    except (OSError, ConfigError):
        return 0  # no/invalid config in this repo → never block
    # 1) hard deny: forbidden command shapes + commit/push on a protected branch —
    #    never bypassable (a forbidden command skips the hooks; branch-first is cheap).
    cmdblocks = run_command_gate(cfg, cmd)
    cmdblocks += run_branch_gate(cfg, cmd, _current_branch("."))
    if has_block(cmdblocks):
        print(f"ratchet: blocked — {_reasons(cmdblocks)}", file=sys.stderr)
        return 2
    # 2) DoD gate on push/merge (bypassable; CI still gates)
    kind = push_or_merge(cmd.command)
    if not kind:
        return 0
    md = _attestation_text(".", cfg)
    if _bypass_reason(cfg, md):
        return 0
    facts = _local_facts(".", cfg.repo.default_branch)
    if kind == "merge":
        body = _gh_pr_body(".")
        facts.pr_body = body if body is not None else (_git(".", ["log", "-1", "--format=%B"]) or "")
    blocks = [f for f in run_change(cfg, facts, allow_run=False) if f.severity == "block"]
    if blocks:
        hint = f' Override (agent-layer; CI still gates): set {cfg.meta.bypass_env}.' if cfg.meta.bypass_env else ""
        print(f"ratchet: DoD not met for {kind}:\n{_render(blocks)}{hint}", file=sys.stderr)
        return 2
    return 0


def cmd_stop(cwd: str = ".") -> int:
    """Stop hook: block turn-end on an ahead-of-main code change whose DoD is unmet —
    blocking diff facts (cheap; `run` blocks skipped) + unticked attestation boxes.
    Debounced by the HEAD tree hash so it nags once per unchanged tree. Always exits
    0; the block is carried in the JSON decision (the harness contract)."""
    try:
        cfg = _read_working_config(cwd)
    except (OSError, ConfigError):
        print("{}")
        return 0
    facts = _local_facts(cwd, cfg.repo.default_branch)
    if not change_classes(cfg, facts)["always"]:  # no code change
        print("{}")
        return 0
    md = _attestation_text(cwd, cfg)
    if _bypass_reason(cfg, md):
        print("{}")
        return 0
    fails = [f for f in run_change(cfg, facts, allow_run=False) if f.severity == "block"]
    fails += attestation_gaps(cfg, facts, md)
    if not fails:
        print("{}")
        return 0
    tree = (_git(cwd, ["rev-parse", "HEAD^{tree}"]) or "").strip()
    state = os.path.join(cwd, ".ratchet", ".state")
    try:
        prev = open(state, encoding="utf-8").read().strip()
    except OSError:
        prev = ""
    if tree and prev == tree:
        print("{}")  # already nagged for this exact tree (loop-safe)
        return 0
    try:
        os.makedirs(os.path.dirname(state), exist_ok=True)
        with open(state, "w", encoding="utf-8") as fh:
            fh.write(tree)
    except OSError:
        pass
    esc = f'set {cfg.meta.bypass_env}="<reason>"' if cfg.meta.bypass_env else "add a bypass line"
    reason = (
        f"Definition-of-Done not met for this code branch — resolve, then continue "
        f"(or {esc}):\n{_render(fails)}"
    )
    print(json.dumps({"decision": "block", "reason": reason}))
    return 0


def cmd_judge(cwd: str = ".") -> int:
    """Emit the advisory LLM-judge prompt(s) from the config to stdout (CI pipes them
    to a model as a `continue-on-error` substance check). Keeps the model call out of
    the pure engine."""
    try:
        cfg = _read_working_config(cwd)
    except (OSError, ConfigError):
        return 0
    prompts = [c.prompt for c in cfg.checks if c.primitive == "judge" and c.prompt]
    if prompts:
        print("\n\n".join(prompts))
    return 0


def cmd_check(
    cwd: str,
    allow_run: bool = True,
    pr_body_file: str | None = None,
    approvals: str | None = None,
    allow_bypass: bool = False,
) -> int:
    """CHANGE layer: 1 = blocking findings, 0 = clean (warns print, never fail).

    `pr_body_file` / `approvals` supply PR context (CI passes them; local pre-push
    omits them, so PR-body / approval checks skip rather than false-fire).
    `allow_bypass` honours the agent-layer escape hatch (pre-push convenience); the
    authoritative CI run never sets it."""
    try:
        wcfg = _read_working_config(cwd)
        default_branch = wcfg.repo.default_branch
        if allow_bypass and _bypass_reason(wcfg, _attestation_text(cwd, wcfg)):
            print("ratchet: BYPASS (agent-layer, pre-push) — CI still enforces", file=sys.stderr)
            return 0
    except (OSError, ConfigError):
        default_branch = "main"
    base = _resolve_base(cwd, default_branch)
    try:
        cfg = load_config(cwd, base)
    except (OSError, ConfigError) as e:
        print(f"ratchet: cannot load base-pinned config: {e}", file=sys.stderr)
        return 1
    facts = DiffFacts.from_range(cwd, base or "HEAD~1")
    if pr_body_file:
        try:
            with open(pr_body_file, encoding="utf-8") as fh:
                facts.pr_body = fh.read()
        except OSError:
            pass  # no body file → stays None (no PR context)
    if approvals is not None:
        facts.approvals = [a.strip() for a in approvals.split(",") if a.strip()]
    findings = run_change(cfg, facts, allow_run=allow_run)
    for f in findings:
        tag = "BLOCK" if f.severity == "block" else "warn "
        print(f"  [{tag}] {f.id}: {f.reason}")
    if has_block(findings):
        n = sum(1 for f in findings if f.severity == "block")
        print(f"ratchet: definition-of-done NOT met ({n} blocking)", file=sys.stderr)
        return 1
    print(f"ratchet: ok ({len(findings)} advisory warning(s))")
    return 0


def cmd_validate(path: str) -> int:
    try:
        with open(path, encoding="utf-8") as fh:
            cfg = Config.parse(fh.read())
    except (OSError, ConfigError) as e:
        print(f"ratchet: invalid config: {e}", file=sys.stderr)
        return 1
    print(
        f"ratchet: {path} valid — {len(cfg.checks)} checks, base_pinned={cfg.meta.base_pinned}"
    )
    return 0


def cmd_init(path: str) -> int:
    if os.path.exists(path):
        print(f"ratchet: {path} already exists — leaving it untouched", file=sys.stderr)
        return 1
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(INIT_TEMPLATE)
    print(f"ratchet: wrote starter {path} — edit it, then wire the hooks (see README)")
    return 0


def _read_working_config(cwd: str) -> Config:
    with open(os.path.join(cwd, "ratchet.toml"), encoding="utf-8") as fh:
        return Config.parse(fh.read())


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="ratchet",
        description="Ungameable diff-fact enforcement of the closing-discipline.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("gate", help="agent layer: PreToolUse hook (deny forbidden / un-DoD'd git ops)")
    st = sub.add_parser("stop", help="agent layer: Stop hook (block turn-end on unmet DoD)")
    st.add_argument("--cwd", default=".")
    c = sub.add_parser("check", help="change layer: gate the committed range (authoritative)")
    c.add_argument("--cwd", default=".")
    c.add_argument(
        "--no-run",
        action="store_true",
        help="skip `run` blocks (test suites) — for the cheap agent-layer Stop hook",
    )
    c.add_argument("--pr-body-file", help="file holding the PR body (enables PR-body checks; CI only)")
    c.add_argument("--approvals", help="comma-separated approver logins (enables protected_path; CI only)")
    c.add_argument("--allow-bypass", action="store_true", help="honour the agent-layer bypass (pre-push only)")
    j = sub.add_parser("judge", help="emit the advisory LLM-judge prompt(s) to stdout (CI)")
    j.add_argument("--cwd", default=".")
    v = sub.add_parser("validate", help="parse + validate ratchet.toml (the block-requires-fact invariant)")
    v.add_argument("--config", default="ratchet.toml")
    i = sub.add_parser("init", help="write a starter ratchet.toml")
    i.add_argument("--config", default="ratchet.toml")
    sub.add_parser("selftest", help="run the in-process self-test")

    args = p.parse_args(argv)
    if args.cmd == "gate":
        return cmd_gate()
    if args.cmd == "stop":
        return cmd_stop(args.cwd)
    if args.cmd == "check":
        return cmd_check(
            args.cwd,
            allow_run=not args.no_run,
            pr_body_file=args.pr_body_file,
            approvals=args.approvals,
            allow_bypass=args.allow_bypass,
        )
    if args.cmd == "judge":
        return cmd_judge(args.cwd)
    if args.cmd == "validate":
        return cmd_validate(args.config)
    if args.cmd == "init":
        return cmd_init(args.config)
    if args.cmd == "selftest":
        print("ratchet selftest: ok (run `python3 -m pytest` / `tests/test_ratchet.py` for the full suite)")
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
