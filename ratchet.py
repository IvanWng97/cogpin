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
from dataclasses import dataclass, field, replace

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


@dataclass
class Meta:
    bypass_env: str | None = None
    commit_footer: str | None = None
    # THE decisive bypass-proof invariant: read config + gate-defining files from
    # the pinned base ref, never the PR head. Defaults ON.
    base_pinned: bool = True


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
    cls: str | None = None  # attestation class
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
        )
        m = raw.get("meta", {})
        meta = Meta(
            bypass_env=m.get("bypass_env"),
            commit_footer=m.get("commit_footer"),
            base_pinned=bool(m.get("base_pinned", True)),
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
                        cls=c.get("class"),
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

    @property
    def footer_regex(self) -> str | None:
        return self.meta.commit_footer


# ─────────────────────────────────────────────────────────────────────────────
# facts  (the ONLY inputs a `fact` check reads — all ungameable by the agent)
# ─────────────────────────────────────────────────────────────────────────────

ADDED, MODIFIED, DELETED = "A", "M", "D"


@dataclass
class DiffFacts:
    added: list[tuple[str, str]] = field(default_factory=list)  # (path, added line)
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
            cur = ""
            for line in diff.splitlines():
                if line.startswith("+++ b/"):
                    cur = line[6:]
                elif line.startswith("+") and not line.startswith("+++") and cur:
                    f.added.append((cur, line[1:]))
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
    pat = _rx(check.pattern)
    if pat and pat.search(facts.command):
        return f"command matches forbidden pattern for `{check.id}`"
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
    return None  # attest/judge/forbid_command are not diff-evaluated here


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
"""


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
    """PreToolUse: exit 2 = deny (stderr shown to the agent), 0 = allow."""
    buf = sys.stdin.read()
    cmd = CommandFacts.from_pretooluse_json(buf)
    try:
        cfg = _read_working_config(".")
    except (OSError, ConfigError):
        return 0  # no/invalid config in this repo → never block
    findings = run_command_gate(cfg, cmd)
    if not has_block(findings):
        return 0
    env = cfg.meta.bypass_env
    if env and os.environ.get(env) is not None:
        print(
            f"ratchet: BYPASS via {env} — {_reasons(findings)} (change layer still enforces)",
            file=sys.stderr,
        )
        return 0
    print(f"ratchet: blocked — {_reasons(findings)}", file=sys.stderr)
    return 2


def cmd_check(
    cwd: str,
    allow_run: bool = True,
    pr_body_file: str | None = None,
    approvals: str | None = None,
) -> int:
    """CHANGE layer: 1 = blocking findings, 0 = clean (warns print, never fail).

    `pr_body_file` / `approvals` supply PR context (CI passes them; local pre-push
    omits them, so PR-body / approval checks skip rather than false-fire)."""
    try:
        default_branch = _read_working_config(cwd).repo.default_branch
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
    sub.add_parser("gate", help="agent layer: PreToolUse hook (deny a forbidden command)")
    c = sub.add_parser("check", help="change layer: gate the committed range (authoritative)")
    c.add_argument("--cwd", default=".")
    c.add_argument(
        "--no-run",
        action="store_true",
        help="skip `run` blocks (test suites) — for the cheap agent-layer Stop hook",
    )
    c.add_argument("--pr-body-file", help="file holding the PR body (enables PR-body checks; CI only)")
    c.add_argument("--approvals", help="comma-separated approver logins (enables protected_path; CI only)")
    v = sub.add_parser("validate", help="parse + validate ratchet.toml (the block-requires-fact invariant)")
    v.add_argument("--config", default="ratchet.toml")
    i = sub.add_parser("init", help="write a starter ratchet.toml")
    i.add_argument("--config", default="ratchet.toml")
    sub.add_parser("selftest", help="run the in-process self-test")

    args = p.parse_args(argv)
    if args.cmd == "gate":
        return cmd_gate()
    if args.cmd == "check":
        return cmd_check(
            args.cwd,
            allow_run=not args.no_run,
            pr_body_file=args.pr_body_file,
            approvals=args.approvals,
        )
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
