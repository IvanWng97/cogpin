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
import tempfile
import tomllib
from dataclasses import dataclass, field, fields

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


def _path_tail_matches(path: str, patterns: list[str]) -> bool:
    """Match a glob against the path OR any of its trailing segment-runs, so an ABSOLUTE
    tool path (`/abs/repo/.github/workflows/x.yml`) still matches a repo-relative
    multi-segment glob (`.github/workflows/**`) — `_path_or_base_matches` only tries the
    full string + basename, which silently misses such globs for the live Write/Edit gate.
    Backslashes normalize to `/` so a Windows tool path is covered too."""
    norm = path.replace("\\", "/")
    segs = norm.split("/")
    cands = [norm] + ["/".join(segs[i:]) for i in range(1, len(segs))]
    return any(_path_matches(c, patterns) for c in cands)


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
_ANY_LAYER = frozenset({"agent", "change", "both"})
_AGENT_ONLY = frozenset({"agent", "both"})  # live-signal primitives: a change placement never fires


@dataclass(frozen=True)
class Spec:
    """The intrinsic, declarative facts about a primitive — its single source of truth.
    `kind` is its NATURE: an advisory primitive decides over no fact, so it can never block,
    whatever the author labels (the moat checks the label; _ADVISORY_ONLY rejects the lie).
    `layers` is the allowed placement — a live-signal primitive (it reads an agent-layer fact)
    is agent-only, so a change-layer placement would silently never fire."""
    kind: str
    layers: frozenset[str] = _ANY_LAYER


# THE primitive registry: one Spec per primitive is the single source for the name set
# (PRIMITIVES), the fact/advisory split (_ADVISORY_ONLY + the moat-mislabel guard), and the
# layer-placement rule (validate). Adding a primitive is ONE entry here, not parallel-list edits.
# The evaluator FN, its typed call, and the gate-runner routing stay EXPLICIT in _eval_diff / the
# runners (the table holds no callable — that keeps mypy's per-call arity check and the route test).
PRIMITIVE_SPECS: dict[str, "Spec"] = {
    "secret_scan": Spec("fact"),
    "forbid_command": Spec("fact"),
    "forbid_pattern": Spec("fact"),
    "forbid_removal": Spec("fact"),
    "forbid_delete": Spec("fact"),
    "forbid_commit_on_branch": Spec("fact", _AGENT_ONLY),
    "scope_lock": Spec("fact"),
    "self_protect": Spec("fact", _AGENT_ONLY),
    "forbid_in_message": Spec("fact"),
    "require_message_pattern": Spec("fact"),
    "numeric_floor": Spec("fact"),
    "change_budget": Spec("fact"),
    "file_must_contain": Spec("fact"),
    "max_added_file_bytes": Spec("fact"),
    "path_requires": Spec("fact"),
    "cooccur": Spec("fact"),
    "marker_present": Spec("fact"),
    "commit_footer": Spec("fact"),
    "protected_path": Spec("fact"),
    "require_approval_from": Spec("fact"),
    "pattern_requires_approval": Spec("fact"),
    "approval_policy": Spec("fact"),
    "require_checks_green": Spec("fact"),
    "run": Spec("fact"),
    "attest": Spec("advisory"),
    "judge": Spec("advisory"),
}
PRIMITIVES = frozenset(PRIMITIVE_SPECS)
# advisory-by-nature primitives (decide over no fact → can never block, whatever the `kind` label).
_ADVISORY_ONLY = frozenset(n for n, s in PRIMITIVE_SPECS.items() if s.kind == "advisory")


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
    # forbid_pattern / forbid_removal / secret_scan / file_must_contain: the match + its scope
    pattern: str | None = None
    scope: list[str] = field(default_factory=list)  # named scope(s) or literal glob(s)
    exempt: str | None = None
    strip_comments: bool = False
    # path_requires: a `when`-scoped change requires a `need`-scoped change too
    when: list[str] = field(default_factory=list)
    need: list[str] = field(default_factory=list)
    # require_checks_green: check names to EXCLUDE (denylist complement of `need`) — chiefly
    # ratchet's OWN job, which is still pending while it gates the same workflow run.
    ignore: list[str] = field(default_factory=list)
    when_marker: str | None = None      # path_requires: a PR-body marker as the `when` trigger
    marker: str | None = None           # marker_present: the block that must appear in the PR body
    cmd: str | None = None              # run: the shell command (its exit code is the fact)
    # cooccur: if `trigger` appears (diff/PR/commit), `require` must appear too
    trigger: str | None = None
    require: str | None = None
    custom: list[str] = field(default_factory=list)        # secret_scan: extra secret-token regexes
    forbid_paths: list[str] = field(default_factory=list)  # secret_scan: forbidden file-path globs
    paths: list[str] = field(default_factory=list)         # protected_path / self_protect: gate-file globs
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
    # change_budget: count ceilings over the diff (None = no cap on that axis)
    max_added: int | None = None
    max_removed: int | None = None
    max_files: int | None = None
    max_file_added: int | None = None
    # file_must_contain: the A/M/D status it gates (default "A" = added files only)
    status: str | None = None
    # max_added_file_bytes: a per-file byte ceiling (KB) + whether binary blobs are allowed
    maxkb: int | None = None
    allow_binary: bool = False
    # require_approval_from / pattern_requires_approval / approval_policy: reviewer-identity
    # facts from the PR API. exclude_author/exclude_bot are the single vocabulary all three share.
    approvers: list[str] = field(default_factory=list)
    exclude_author: bool = False
    exclude_bot: bool = False
    # approval_policy: deeper approval-state requirements
    require_fresh: bool = False
    no_changes_requested: bool = False
    min_approvals: int | None = None
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


def _as_int(v) -> int | None:
    """An optional integer field → int or None (a non-int is a hard config error)."""
    if v is None:
        return None
    if isinstance(v, bool) or not isinstance(v, int):
        raise ConfigError(f"expected integer, got {type(v).__name__}")
    return v


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
                        ignore=_as_list(c.get("ignore")),
                        when_marker=c.get("when_marker"),
                        marker=c.get("marker"),
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
                        max_added=_as_int(c.get("max_added")),
                        max_removed=_as_int(c.get("max_removed")),
                        max_files=_as_int(c.get("max_files")),
                        max_file_added=_as_int(c.get("max_file_added")),
                        status=c.get("status"),
                        maxkb=_as_int(c.get("maxkb")),
                        allow_binary=bool(c.get("allow_binary", False)),
                        approvers=_as_list(c.get("require_approval_from")),
                        exclude_author=bool(c.get("exclude_author", False)),
                        exclude_bot=bool(c.get("exclude_bot", False)),
                        require_fresh=bool(c.get("require_fresh", False)),
                        no_changes_requested=bool(c.get("no_changes_requested", False)),
                        min_approvals=_as_int(c.get("min_approvals")),
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
            # The moat trusts the `kind` LABEL, but attest/judge decide over no fact — a
            # `kind="fact"` on them is a lie that ships a `block` which silently never fires
            # (they aren't in the diff dispatch). Reject the mislabel at parse time.
            if c.primitive in _ADVISORY_ONLY and c.kind != "advisory":
                raise ConfigError(
                    f"check `{c.id}`: {c.primitive} is advisory by nature — kind must be "
                    f'"advisory" (it decides over no ungameable fact, so it can never block)'
                )
            # A `run` block is authoritative only at the change layer (repo author
            # controls the script there); never let it block from the agent layer.
            if c.primitive == "run" and c.severity == "block" and c.layer == "agent":
                raise ConfigError(
                    f"check `{c.id}`: a `run` block must live at the change layer, not agent"
                )
            # Placement: a live-signal primitive (forbid_commit_on_branch reads the current
            # branch, self_protect the live Write/Edit target — both at the PreToolUse intercept)
            # would silently never fire at the change layer. The allowed layers live in the
            # primitive's Spec, so there is no per-primitive guard to forget (the change-layer
            # twin of self_protect is protected_path).
            if c.layer not in PRIMITIVE_SPECS[c.primitive].layers:
                raise ConfigError(
                    f"check `{c.id}`: {c.primitive} reads a live agent-layer signal — declare "
                    f'layer "agent" or "both", not "{c.layer}"'
                )
            # numeric_floor's `direction` selects both the floor/ceiling branch and the
            # pairing arm; a typo'd value would silently disable the floor and invert the
            # pairing — a fail-OPEN gate. Constrain it like the other enums.
            if c.primitive == "numeric_floor" and c.direction not in (None, "no_decrease", "no_increase"):
                raise ConfigError(
                    f"check `{c.id}`: numeric_floor direction must be 'no_decrease' or "
                    f"'no_increase', got `{c.direction}`"
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
    # Structured PR-review API facts (None = no PR context → the reviewer-identity
    # primitives skip). Each review: {login, state, commit_id, is_bot, author_association}.
    reviews: list[dict] | None = None
    head_sha: str | None = None  # PR head commit, for the freshness check
    pr_author: str | None = None  # to exclude self-approval
    checks: list[dict] | None = None  # status checks: [{name, conclusion}]
    file_sizes: dict | None = None  # {path → bytes}; -1 marks a binary blob

    def changed_paths(self):
        return (p for _, p in self.changed)

    @staticmethod
    def from_range(cwd: str, base: str, head: str = "HEAD") -> "DiffFacts":
        rng = f"{base}..{head}"
        f = DiffFacts()
        # core.quotepath=false emits non-ASCII paths RAW (UTF-8), not octal-escaped as
        # `"caf\303\251.txt"`, so a path round-trips to `cat-file -s` (max_added_file_bytes)
        # and to scope matching. Control chars (newline/tab/quote) stay escaped regardless,
        # so the tab/newline record framing below is never broken by a path.
        ns = _git(cwd, ["-c", "core.quotepath=false", "diff", "--name-status", rng])
        if ns:
            # split("\n"), NOT splitlines(): the latter also breaks on \v \f \x1c-\x1e \x85
            # U+2028/U+2029 — bytes git emits verbatim inside a unicode path, which would
            # split one record into two and drop the tail (a false-negative).
            for line in ns.split("\n"):
                parts = line.split("\t")
                if len(parts) < 2:
                    continue
                st = parts[0][:1]
                status = {"A": ADDED, "D": DELETED}.get(st, MODIFIED)
                f.changed.append((status, parts[-1]))
        diff = _git(cwd, ["-c", "core.quotepath=false", "diff", "--unified=0", rng])
        if diff:
            # +++ b/<path> / --- a/<path> are FILE HEADERS, but a removed/added CONTENT line
            # can itself start with `--- `/`+++ ` (an SQL/Lua `-- ` comment renders as
            # `--- …` under a single `-` marker). Disambiguate by hunk state: headers sit in
            # the per-file preamble (before the first `@@`); attribute +/- to a path only
            # inside a hunk body. Else one such line poisons path attribution for the whole
            # file — a scoped forbid_removal/secret_scan false-negative.
            new_path = old_path = ""
            in_hunk = False
            for raw in diff.split("\n"):
                # split("\n") + rstrip("\r"): preserve CRLF normalization (git terminates
                # lines with \n; a CRLF file's content keeps its trailing \r) WITHOUT
                # splitlines()'s over-eager break on \v \f \x85 U+2028/9 inside a content
                # line, which would sever an added line and drop the post-separator token.
                line = raw.rstrip("\r")
                if line.startswith("diff --git "):
                    in_hunk = False  # next file's preamble begins
                elif line.startswith("@@"):
                    in_hunk = True
                elif not in_hunk and line.startswith("--- "):
                    old_path = line[6:] if line.startswith("--- a/") else ""
                elif not in_hunk and line.startswith("+++ "):
                    new_path = line[6:] if line.startswith("+++ b/") else ""
                elif in_hunk and line.startswith("+") and new_path:
                    f.added.append((new_path, line[1:]))
                elif in_hunk and line.startswith("-") and old_path:
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
        _name, ti = _pretooluse_tool(stdin)
        return CommandFacts.from_tool_input(ti)

    @staticmethod
    def from_tool_input(ti: dict) -> "CommandFacts":
        """The command from a `tool_input` dict, coerced to '' unless it's a real string —
        the single home for the 'degrade to empty command' rule (the hook and the
        PreToolUse gate both go through here)."""
        cmd = ti.get("command", "")
        return CommandFacts(command=cmd if isinstance(cmd, str) else "")


def _pretooluse_tool(stdin: str) -> tuple[str, dict]:
    """`(tool_name, tool_input)` from a PreToolUse envelope. Unknown shapes degrade to
    `("", {})` so the gate never false-blocks on a malformed payload."""
    try:
        v = json.loads(stdin)
        if not isinstance(v, dict):
            return "", {}
        ti = v.get("tool_input")
        return (v.get("tool_name") or "", ti if isinstance(ti, dict) else {})
    except json.JSONDecodeError:
        return "", {}


def _git(cwd: str, args: list[str]) -> str | None:
    try:
        out = subprocess.run(
            ["git", "-C", cwd, *args],
            capture_output=True,
            text=True,
            # surrogateescape round-trips ANY bytes losslessly: a non-UTF-8 byte in the
            # diff (a latin-1 source line, a near-binary blob git treats as text) must NOT
            # raise the strict locale decode — that's a ValueError, swallowed below to None,
            # which empties DiffFacts and SILENTLY PASSES the content scanners on the
            # authoritative layer. ASCII-shaped facts (secrets, tokens) still match the
            # valid spans; the engine's own stdout uses errors="replace" (cmd CLI setup),
            # so a stray surrogate can't crash a later print.
            encoding="utf-8",
            errors="surrogateescape",
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
        return "command matches the forbidden pattern"
    # `deny`: a NORMALIZED verb match — strips `git -C`/`-c k=v`, `cd d &&`, `env X=Y`,
    # `sudo` wrappers so the gated verb can't be smuggled past prefix matching (#66176).
    if check.deny:
        hit = _deny_hit(facts.command, check.deny)
        if hit:
            return f"forbidden command `{hit}`"
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
    """An ADDED line in scope matching `pattern` blocks (minus `exempt` paths/lines) —
    the denylist anchor the rest of the family is described against."""
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
            return f"{path} is outside the declared scope {check.allow}"
    return None


# The agent file-mutating tools whose tool_input carries the target path.
WRITE_TOOLS = frozenset({"Write", "Edit", "MultiEdit", "NotebookEdit"})


def self_protect(check: Check, tool_name: str, file_path: str) -> str | None:
    """Agent-layer real-time gate: a Write/Edit to a gate-defining file (the
    `ratchet.toml`, the engine, the hook `settings.json`) is denied at the PreToolUse
    intercept — the agent can't quietly loosen the gate it's gated by mid-session.
    The change-layer twin is `protected_path` (which demands an independent PR
    approval); this is the live forcing function. Non-write tools pass through."""
    if tool_name not in WRITE_TOOLS or not file_path:
        return None
    if _path_tail_matches(file_path, check.paths):
        return (
            f"{file_path} is a protected gate-defining file — change it "
            f"in a reviewed PR, not in-session"
        )
    return None


_MSG_SCOPES = ("commit_subject", "commit_body", "pr_body")


def _msg_targets(facts: DiffFacts, scopes: set[str]) -> list[str]:
    """The commit/PR message strings selected by `scopes` (commit_subject/body/pr_body)."""
    out: list[str] = []
    for msg in facts.commit_msgs:
        lines = msg.split("\n")  # not splitlines(): a U+2028/NEL in a body must not re-split
        if "commit_subject" in scopes and lines:
            out.append(lines[0])
        if "commit_body" in scopes and len(lines) > 1:
            out.append("\n".join(lines[1:]))
    if "pr_body" in scopes and facts.pr_body:
        out.append(facts.pr_body)
    return out


def forbid_in_message(check: Check, facts: DiffFacts) -> str | None:
    """Forbid literal tokens (case-insensitive) in commit/PR message text — e.g. a
    `[skip ci]` that disarms the change layer's own CI host. The require-presence
    primitives (marker_present/commit_footer) have no forbid-presence inverse."""
    if not check.tokens:
        return None
    blob = "\n".join(_msg_targets(facts, set(check.msg_scope) or set(_MSG_SCOPES))).lower()
    for t in check.tokens:
        if t.lower() in blob:
            return f"forbidden token `{t}` in the commit/PR message"
    return None


def require_message_pattern(check: Check, facts: DiffFacts) -> str | None:
    """Every selected commit/PR message MUST match a required regex — e.g.
    Conventional Commits on the subject. The require-presence twin of
    forbid_in_message. `msg_scope` defaults to `commit_subject` (not all scopes — a
    body rarely has a single required shape). Skips when there are no messages."""
    pat = _rx(check.pattern)
    if not pat:
        return None
    for t in _msg_targets(facts, set(check.msg_scope) or {"commit_subject"}):
        if not pat.search(t):
            return f"message `{t[:50]}` does not match required `{check.pattern}`"
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
            # `floor` doubles as a CEILING under direction="no_increase" (block when the value
            # rises past it) — one field, two meanings selected by `direction`.
            if direction == "no_decrease" and new_val < check.floor:
                return f"{prefix} {new_val:g} is below the floor {check.floor:g}"
            if direction == "no_increase" and new_val > check.floor:
                return f"{prefix} {new_val:g} is above the ceiling {check.floor:g}"
        if prefix in olds:
            old_val = olds[prefix]
            weaker = new_val < old_val if direction == "no_decrease" else new_val > old_val
            if weaker:
                return f"{prefix} weakened {old_val:g} → {new_val:g}"
    return None


def change_budget(check: Check, facts: DiffFacts, repo: RepoCfg) -> str | None:
    """Count ceilings over the diff (optionally scoped): total added/removed lines,
    changed files, or per-file added lines. A blast-radius cap — the mega-diff /
    scope-explosion class a reviewer can't eyeball. Usually severity="warn" (a budget
    is advisory by nature; raise to a hard cap only on a generated/locked tree)."""
    scope = _resolve(check.scope, repo) if check.scope else []

    def keep(path: str) -> bool:
        return not scope or _path_matches(path, scope)

    added = [(p, l) for p, l in facts.added if keep(p)]
    removed = [(p, l) for p, l in facts.removed if keep(p)]
    files = [p for _st, p in facts.changed if keep(p)]
    if check.max_added is not None and len(added) > check.max_added:
        return f"{len(added)} added lines exceed the budget {check.max_added}"
    if check.max_removed is not None and len(removed) > check.max_removed:
        return f"{len(removed)} removed lines exceed the budget {check.max_removed}"
    if check.max_files is not None and len(files) > check.max_files:
        return f"{len(files)} changed files exceed the budget {check.max_files}"
    if check.max_file_added is not None:
        per: dict[str, int] = {}
        for p, _l in added:
            per[p] = per.get(p, 0) + 1
        worst = max(per.items(), key=lambda kv: kv[1], default=None)
        if worst and worst[1] > check.max_file_added:
            return f"{worst[0]} adds {worst[1]} lines, over the per-file budget {check.max_file_added}"
    return None


def file_must_contain(check: Check, facts: DiffFacts, repo: RepoCfg) -> str | None:
    """Positive content floor: every changed file matching scope + `status` must add
    at least one line matching `pattern` (e.g. an SPDX header on each NEW source file,
    a `@generated` marker). The structural inverse of forbid_pattern. `status`
    defaults to "A" — gate added files only."""
    pat = _rx(check.pattern)
    if not pat:
        return None
    scope = _resolve(check.scope, repo) if check.scope else []
    want = (check.status or ADDED).upper()
    targets = [p for st, p in facts.changed if st == want and (not scope or _path_matches(p, scope))]
    if not targets:
        return None
    by_path: dict[str, list[str]] = {}
    for p, l in facts.added:
        by_path.setdefault(p, []).append(l)
    for p in targets:
        if not any(pat.search(l) for l in by_path.get(p, [])):
            return f"{p} must add a line matching `{check.pattern}`"
    return None


def max_added_file_bytes(check: Check, facts: DiffFacts, repo: RepoCfg) -> str | None:
    """Per-file byte ceiling on added/modified files (the committed-blob / vendored-
    artifact / accidental-binary class). `file_sizes` maps path → bytes, with -1
    marking a binary blob. None = no size facts (the agent-layer view, no git) →
    skip. `allow_binary=false` blocks any binary regardless of size."""
    if facts.file_sizes is None:
        return None
    scope = _resolve(check.scope, repo) if check.scope else []
    cap = (check.maxkb or 0) * 1024
    for path, size in facts.file_sizes.items():
        if scope and not _path_matches(path, scope):
            continue
        if size < 0:
            if not check.allow_binary:
                return f"{path} is a binary blob (keep it out of the diff or set allow_binary)"
            continue
        if cap and size > cap:
            return f"{path} is {size} bytes, over the {check.maxkb}KB cap"
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
    return f"a triggering change requires touching {check.need}"


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
    return "trigger present but required co-occurrence missing"


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
    return f"required marker `{check.marker}` absent from PR body"


def commit_footer(check: Check, footer_rx: str | None, facts: DiffFacts) -> str | None:
    # meta-driven: the footer regex is [meta].commit_footer, not a per-check field — hence the
    # extra arg vs the rest of the family. `check` is kept for call-signature parity with the
    # dispatch (the renderer now owns the id, so the reason itself no longer reads it).
    rx = _rx(footer_rx)
    if not rx:
        return None
    for msg in facts.commit_msgs:
        if not rx.search(msg):
            return "a commit is missing the required footer"
    return None


def _approved_reviews(
    facts: DiffFacts,
    *,
    exclude_author: bool = False,
    exclude_bot: bool = False,
    fresh_only: bool = False,
) -> list[dict]:
    """The APPROVED reviews, filtered by the policy flags a given gate requires — the shared
    core of the PR-approval family, so each call states its policy explicitly instead of
    re-deriving it three times. `fresh_only` is FAIL-CLOSED: once the head SHA is known, a
    review counts only if its `commit_id` equals it — a stale approval (left before a later
    commit) OR one with no recorded commit does NOT qualify. That is the freshness defence
    behind gate-file protection (the 'approve-benign-then-push-malicious' bypass)."""
    out: list[dict] = []
    for rv in facts.reviews or []:
        if (rv.get("state") or "").upper() != "APPROVED":
            continue
        login = rv.get("login") or ""
        if exclude_author and facts.pr_author and login == facts.pr_author:
            continue
        if exclude_bot and rv.get("is_bot"):
            continue
        if fresh_only and facts.head_sha and rv.get("commit_id") != facts.head_sha:
            continue
        out.append(rv)
    return out


def _qualifying_approvers(facts: DiffFacts) -> set[str]:
    """APPROVED reviewers that may satisfy gate-file protection: non-author, non-bot, and
    fresh on the current head. A stale / bot / self approval does NOT qualify — that is what
    stops the 'approve-benign-then-push-malicious' bypass."""
    return {lg for rv in _approved_reviews(facts, exclude_author=True, exclude_bot=True, fresh_only=True)
            if (lg := rv.get("login"))}


def protected_path(check: Check, facts: DiffFacts) -> str | None:
    """Any change to gate-defining files needs an independent approval. Only evaluated
    in a PR context; skipped on local pre-push. When the richer `reviews` fact is present
    (CI), the approval must be FRESH + human + non-author (`_qualifying_approvers`); the
    flat `approvals` list is only a degraded fallback when no review metadata is supplied."""
    if facts.reviews is None and facts.approvals is None:
        return None  # no PR context → defer to the CI run of this same check
    touched = [p for p in facts.changed_paths() if _path_matches(p, check.paths)]
    if not touched or not check.require_approval:
        return None
    if facts.reviews is not None:
        if _qualifying_approvers(facts):
            return None
        return (
            f"gate-defining file(s) changed ({touched[0]}…) without a "
            f"fresh independent approval (non-author, non-bot, on the current head)"
        )
    if facts.approvals:  # degraded: a flat approvals list with no metadata to verify freshness
        return None
    return (
        f"gate-defining file(s) changed ({touched[0]}…) "
        f"without an independent approval"
    )


def _approver_logins(facts: DiffFacts, exclude_author: bool, exclude_bot: bool = False) -> set[str]:
    """The set of logins with a current APPROVED review (the PR author optionally excluded,
    so a self-approval never satisfies a reviewer-identity gate; bots optionally excluded
    too). An empty login (a deleted/ghost account → null) never qualifies."""
    return {lg for rv in _approved_reviews(facts, exclude_author=exclude_author, exclude_bot=exclude_bot)
            if (lg := rv.get("login"))}


def require_approval_from(check: Check, facts: DiffFacts) -> str | None:
    """CODEOWNERS-lite: if any file under `paths` changed, require an APPROVED review
    from one of `require_approval_from` (optionally excluding the PR author).
    reviews=None → no PR context (local pre-push) → skip; CI supplies the reviews."""
    if facts.reviews is None or not check.paths:
        return None
    touched = [p for p in facts.changed_paths() if _path_matches(p, check.paths)]
    if not touched:
        return None
    approvers = _approver_logins(facts, check.exclude_author, check.exclude_bot)
    allowed = set(check.approvers)
    if approvers & allowed:
        return None
    return (
        f"{touched[0]} requires an approval from {sorted(allowed)} "
        f"(have: {sorted(approvers) or 'none'})"
    )


def pattern_requires_approval(check: Check, facts: DiffFacts, repo: RepoCfg) -> str | None:
    """Change-as-trigger gate: if an ADDED line in scope matches `pattern` (a new
    dependency line, an `unsafe {`, a new `allow(...)` lint-suppression), require a
    (non-author) approval. reviews=None → skip. The content twin of
    require_approval_from."""
    if facts.reviews is None:
        return None
    pat = _rx(check.pattern)
    if not pat:
        return None
    scope = _resolve(check.scope, repo) if check.scope else []
    hit = next(
        ((p, l) for p, l in facts.added if (not scope or _path_matches(p, scope)) and pat.search(l)),
        None,
    )
    if not hit:
        return None
    if _approver_logins(facts, check.exclude_author, check.exclude_bot):
        return None
    return f"`{hit[1].strip()}` in {hit[0]} requires an independent approval"


def approval_policy(check: Check, facts: DiffFacts) -> str | None:
    """Deeper approval-state requirements the bare 'approved' badge can't express:
    `require_fresh` (the approval is on the current head_sha, not a stale earlier commit),
    `exclude_author` / `exclude_bot`, `no_changes_requested` (no outstanding
    CHANGES_REQUESTED), and a `min_approvals` floor. reviews=None → skip.
    (Renamed from `approval_state_depth` in 0.x — the old name described nothing.)"""
    if facts.reviews is None:
        return None
    if check.no_changes_requested and any(
            (rv.get("state") or "").upper() == "CHANGES_REQUESTED" for rv in facts.reviews):
        return "an outstanding CHANGES_REQUESTED review must be resolved"
    valid = _approved_reviews(
        facts,
        exclude_author=check.exclude_author,
        exclude_bot=check.exclude_bot,
        fresh_only=check.require_fresh,
    )
    # Count DISTINCT non-empty logins, not raw review submissions — GitHub returns one node
    # per submission, so one reviewer re-approving must not satisfy a min_approvals=2 floor.
    approvers = {lg for rv in valid if (lg := rv.get("login"))}
    need = check.min_approvals if check.min_approvals is not None else 1
    if len(approvers) < need:
        return (
            f"{len(approvers)} qualifying approval(s), need {need} "
            f"(distinct, fresh/human/non-author)"
        )
    return None


def require_checks_green(check: Check, facts: DiffFacts) -> str | None:
    """Every required status check must have concluded `success`. checks=None → no PR
    context → skip. A pending check (null/empty conclusion) blocks — the change isn't
    proven green yet.

    `need` narrows to an allowlist of check names; `ignore` is the denylist complement
    (all green EXCEPT these). When ratchet runs as a job in the SAME workflow it gates,
    its own check is still pending at query time and would self-block — exclude it via
    `ignore = ["<ratchet job name>"]` (or `need` only the others). See SCHEMA.md."""
    if facts.checks is None:
        return None
    want = set(check.need)
    skip = set(check.ignore)
    present = {(ck.get("name") or ""): (ck.get("conclusion") or "").lower()
               for ck in facts.checks if (ck.get("name") or "") not in skip}
    if want:
        # allowlist: every NAMED-required check must be present AND success. A required check
        # that never reported (workflow removed in the PR head, not yet registered) is
        # `missing`, not green — it must NOT pass vacuously (a fail-open on the named case).
        for name in sorted(want):
            concl = present.get(name)
            if concl != "success":
                return f"required check `{name}` is `{concl or 'missing'}`, not success"
        return None
    for name, concl in present.items():
        if concl != "success":
            return f"check `{name}` is `{concl or 'pending'}`, not success"
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
    if p == "require_message_pattern":
        return require_message_pattern(c, facts)
    if p == "numeric_floor":
        return numeric_floor(c, facts, cfg.repo)
    if p == "change_budget":
        return change_budget(c, facts, cfg.repo)
    if p == "file_must_contain":
        return file_must_contain(c, facts, cfg.repo)
    if p == "max_added_file_bytes":
        return max_added_file_bytes(c, facts, cfg.repo)
    if p == "path_requires":
        return path_requires(c, facts, cfg.repo)
    if p == "cooccur":
        return cooccur(c, facts)
    if p == "marker_present":
        return marker_present(c, facts, cfg.repo)
    if p == "commit_footer":
        return commit_footer(c, cfg.footer_regex, facts)
    if p == "protected_path":
        return protected_path(c, facts)
    if p == "require_approval_from":
        return require_approval_from(c, facts)
    if p == "pattern_requires_approval":
        return pattern_requires_approval(c, facts, cfg.repo)
    if p == "approval_policy":
        return approval_policy(c, facts)
    if p == "require_checks_green":
        return require_checks_green(c, facts)
    if p == "run":
        return _run_shell(c.cmd or "true")
    # attest/judge/forbid_command/forbid_commit_on_branch/self_protect are agent-layer
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


def run_self_protect_gate(cfg: Config, tool_name: str, file_path: str) -> list[Finding]:
    """AGENT layer: self_protect checks decide over a Write/Edit's target path."""
    out: list[Finding] = []
    for c in cfg.checks:
        if c.primitive != "self_protect" or c.layer == "change":
            continue
        reason = self_protect(c, tool_name, file_path)
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
# Split on shell separators AND grouping punctuation so a glued subshell verb (`(git push)`,
# `$(git commit)`, `{git push;}`) can't hide the gated git verb behind a `(`/`{` from the
# tokenized op scan — `( git push )` was already caught; the glued `(git` was the gap.
_SHELL_SEP = re.compile(r"[;&|\n(){}]+")
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
            encoding="utf-8", errors="surrogateescape",  # never strict-decode-crash on a body byte
        )
    except OSError:
        return None
    return p.stdout if p.returncode == 0 else None


def _read_json(path: str):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None


def _load_reviews(path: str) -> list[dict] | None:
    """Normalize a reviews array into the engine's review shape. Tolerates both the nested
    GraphQL `{author:{login,is_bot}, commit:{oid}}` form and a flat
    `{login,is_bot,commit_id}` form. NOTE: `gh pr view --json reviews` omits the review's
    commit oid, so freshness (require_fresh / protected_path) can't be verified from it —
    use action.yml's GraphQL query when --head-sha is in play. None on a
    missing/garbled file (→ checks skip)."""
    raw = _read_json(path)
    if not isinstance(raw, list):
        return None
    out: list[dict] = []
    for rv in raw:
        if not isinstance(rv, dict):
            continue
        author = rv.get("author")
        author = author if isinstance(author, dict) else {}
        commit = rv.get("commit")
        commit = commit if isinstance(commit, dict) else {}
        out.append({
            "login": rv.get("login") or author.get("login") or "",
            "state": rv.get("state") or "",
            "commit_id": rv.get("commit_id") or commit.get("oid") or "",
            "is_bot": bool(rv.get("is_bot", author.get("is_bot", False))),
            "author_association": rv.get("author_association") or rv.get("authorAssociation") or "",
        })
    return out


def _load_checks(path: str) -> list[dict] | None:
    """Normalize a `gh pr checks --json name,state` (or hand-rolled) array into
    `[{name, conclusion}]`. `conclusion` falls back to `state`/`status` (gh emits
    SUCCESS/FAILURE/PENDING under `state`). None on a missing/garbled file (→ skip)."""
    raw = _read_json(path)
    if not isinstance(raw, list):
        return None
    out: list[dict] = []
    for ck in raw:
        if not isinstance(ck, dict):
            continue
        concl = ck.get("conclusion")
        if concl in (None, ""):
            concl = ck.get("state") or ck.get("status")
        out.append({"name": ck.get("name") or ck.get("context") or "", "conclusion": concl})
    return out


def _populate_file_sizes(cwd: str, base: str, head: str, facts: DiffFacts) -> None:
    """Byte size of each added/modified blob at `head` (-1 = binary, per numstat's
    `-\t-`). Only run when a max_added_file_bytes check exists (N `cat-file` calls)."""
    sizes: dict[str, int] = {}
    binary: set[str] = set()
    # core.quotepath=false so a non-ASCII path matches facts.changed (same setting in
    # from_range) AND resolves under `cat-file -s` below — else the blob is silently
    # dropped from `sizes` and an over-cap file with a unicode name escapes the ceiling.
    numstat = _git(cwd, ["-c", "core.quotepath=false", "diff", "--numstat", f"{base}..{head}"]) or ""
    for line in numstat.split("\n"):
        parts = line.split("\t")
        if len(parts) >= 3 and parts[0] == "-" and parts[1] == "-":
            binary.add(parts[-1])
    for st, path in facts.changed:
        if st == DELETED:
            continue
        if path in binary:
            sizes[path] = -1
            continue
        s = _git(cwd, ["cat-file", "-s", f"{head}:{path}"])
        if s and s.strip().isdigit():
            sizes[path] = int(s.strip())
    facts.file_sizes = sizes


# ─────────────────────────────────────────────────────────────────────────────
# repo introspection  (suggest / gaps / draft-lint — the AI-assisted `init` surface)
#
# The DETERMINISTIC half of config authoring: extract ungameable repo facts (tracked
# paths → globs, the test command, the default branch) + scan CLAUDE.md/AGENTS.md for
# house-rules that map to primitives. The engine NEVER writes the live config and makes
# NO judgments — the host agent does generation (selecting + tuning from these facts),
# the human arms it. Pure functions + a thin acquisition layer, same split as
# DiffFacts.from_range. No model, no network. (Full design: docs/coverage-map.md.)
# ─────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Lang:
    name: str
    exts: tuple[str, ...]
    code_globs: tuple[str, ...]  # most-specific first; guess_globs keeps only matchers
    test_globs: tuple[str, ...]


# Order is the tie-break for `guess_globs` (a repo with equal counts picks the earlier).
_LANG_PROFILES: tuple[Lang, ...] = (
    Lang("rust", (".rs",), ("crates/*/src/**/*.rs", "src/**/*.rs"),
         ("crates/*/tests/**/*.rs", "tests/**/*.rs", "crates/*/src/**/*_tests.rs")),
    Lang("python", (".py",), ("src/**/*.py", "*.py"),
         ("tests/**/*.py", "**/test_*.py", "**/*_test.py")),
    Lang("node", (".ts", ".tsx", ".js", ".jsx"),
         ("src/**/*.ts", "src/**/*.tsx", "src/**/*.js", "*.ts", "*.js"),
         ("**/*.test.ts", "**/*.spec.ts", "**/*.test.js", "test/**", "tests/**")),
    Lang("go", (".go",), ("*.go", "cmd/**/*.go", "internal/**/*.go", "pkg/**/*.go"),
         ("**/*_test.go",)),
    Lang("ruby", (".rb",), ("lib/**/*.rb", "app/**/*.rb", "*.rb"),
         ("spec/**/*.rb", "test/**/*.rb")),
    Lang("java", (".java",), ("src/main/**/*.java",), ("src/test/**/*.java",)),
)


def guess_globs(paths: list[str]) -> tuple[list[str], list[str], list[str]]:
    """(code, tests, docs) globs for a tracked-path list. Picks the dominant language by
    code-extension file count (ties by `_LANG_PROFILES` order), then keeps ONLY the globs
    that actually match ≥1 path via the engine's own `_glob_to_re` (so a flat repo emits
    `*.py`, not `src/**/*.py`). docs default `["**/*.md"]`, plus `docs/**` iff a docs/ path
    exists. Empty/garbled tree → ([], [], ["**/*.md"]) — never raises."""
    docs = ["**/*.md"]
    if any(p.startswith("docs/") for p in paths):
        docs.append("docs/**")
    if not paths:
        return ([], [], docs)
    best: Lang | None = None
    best_n = 0
    for lang in _LANG_PROFILES:
        n = sum(1 for p in paths if p.endswith(lang.exts))
        if n > best_n:
            best_n, best = n, lang
    if not best:
        return ([], [], docs)

    def keep(globs: tuple[str, ...]) -> list[str]:
        return [g for g in globs if any(_glob_to_re(g).match(p) for p in paths)]

    code = keep(best.code_globs) or [f"**/*{best.exts[0]}"]
    tests = keep(best.test_globs)
    return (code, tests, docs)


def detect_test_command(cwd: str) -> tuple[str | None, str | None]:
    """(cmd, source). Manifests are parsed as TEXT, NEVER executed. Priority: justfile >
    package.json > pyproject > Makefile > Cargo.toml. A malformed manifest degrades to the
    next source (never raises)."""
    def rd(name: str) -> str | None:
        try:
            # errors="replace": a non-UTF-8 byte in an incidental manifest must DEGRADE to
            # the next source, not raise — UnicodeDecodeError is a ValueError, not an
            # OSError, so a bare `except OSError` would break the "never raises" contract.
            with open(os.path.join(cwd, name), encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except OSError:
            return None

    for jf in ("justfile", "Justfile", ".justfile"):
        t = rd(jf)
        if t and re.search(r"^test\b[^\n]*:", t, re.M):
            return ("just test", jf)
    pj = rd("package.json")
    if pj:
        try:
            ts = (json.loads(pj).get("scripts") or {}).get("test")
            if ts and "no test specified" not in ts:
                return ("npm test", "package.json")
        except (json.JSONDecodeError, AttributeError):
            pass
    pp = rd("pyproject.toml")
    if pp:
        try:
            tool = tomllib.loads(pp).get("tool", {})
            # `tool` is normally a table, but valid TOML allows `tool = 5`; guard the type
            # before iterating so a scalar/array doesn't raise TypeError past the except.
            if isinstance(tool, dict) and (
                any(k.startswith("pytest") for k in tool) or "poetry" in tool
            ):
                return ("python3 -m pytest -q", "pyproject.toml")
        except tomllib.TOMLDecodeError:
            pass
    for mk in ("Makefile", "makefile", "GNUmakefile"):
        t = rd(mk)
        if t and re.search(r"^test:", t, re.M):
            return ("make test", mk)
    if rd("Cargo.toml") is not None:
        return ("cargo test", "Cargo.toml")
    return (None, None)


def _tracked_paths(cwd: str) -> list[str]:
    """`git ls-files`; fallback to a bounded os.walk (skipping the usual build/vendor dirs)
    if not a git repo. Always slash-separated. Never raises."""
    out = _git(cwd, ["ls-files"])
    if out is not None:
        return [ln for ln in out.splitlines() if ln]
    skip = {".git", "node_modules", "target", ".venv", "venv", "dist", "build", "__pycache__", ".mypy_cache"}
    paths: list[str] = []
    for root, dirs, files in os.walk(cwd):
        dirs[:] = [d for d in dirs if d not in skip]
        for f in files:
            paths.append(os.path.relpath(os.path.join(root, f), cwd).replace(os.sep, "/"))
    return paths


def _detect_default_branch(cwd: str) -> str:
    """`refs/remotes/origin/HEAD` → strip `origin/`; else the current branch if it's a
    conventional default; else "main"."""
    out = _git(cwd, ["symbolic-ref", "--short", "-q", "refs/remotes/origin/HEAD"])
    if out and out.strip():
        return out.strip().split("/", 1)[-1]
    cur = _current_branch(cwd)
    return cur if cur in ("main", "master", "trunk") else "main"


@dataclass
class HouseRuleHit:
    suggested_id: str
    keyword: str
    primitive: str
    params: dict  # seed [[check]] params (a vetted catalog — generation is SELECTION)
    confidence: str  # "high" | "medium" | "low"
    layer: str = "change"
    render: str = "warn"  # "block" (safe-core) | "warn" | "commented" | "judge"
    match_token: str | None = None  # is_bound discriminator (None = primitive presence suffices)
    rule_text: str = ""  # the EXACT triggering CLAUDE.md line — the evidence a human audits
    source: str = ""
    rationale: str = ""


@dataclass
class RepoScan:
    default_branch: str
    code: list[str]
    tests: list[str]
    docs: list[str]
    test_cmd: str | None
    test_cmd_source: str | None
    claude_md_paths: list[str]
    house_rules: list[HouseRuleHit]


@dataclass
class LintFinding:
    level: str  # "error" (agent must fix) | "warn" (informational) | "todo" (human review item)
    check_id: str | None
    msg: str


@dataclass(frozen=True)
class _Rule:
    rid: str
    pattern: str  # case-insensitive line regex
    primitive: str
    params: dict
    layer: str
    render: str
    conf: str
    match_token: str | None = None


# The CLAUDE.md keyword → primitive catalog. The first five (safe-core) are ALSO emitted
# unconditionally by render_suggest_toml; rows below them render only on a keyword hit.
# `render`: block (safe-core, all fact-kind) · warn · commented (needs human params / runs a
# command) · judge (advisory, never blocks). Provenance: docs/coverage-map.md.
HOUSE_RULE_MAP: tuple[_Rule, ...] = (
    _Rule("no-verify", r"--no-?verify|skip.*hooks|HUSKY=0|SKIP_PREFLIGHT", "forbid_command",
          {"pattern": "--no-verify|--no-gpg-sign|HUSKY=0"}, "agent", "block", "high", "--no-verify"),
    _Rule("branch-first", r"branch first|never commit.*(to )?(main|master)|work in a (git )?worktree|branch off",
          "forbid_commit_on_branch", {}, "agent", "block", "high"),
    _Rule("secret-scan", r"no secrets?|(don'?t|never|do not) commit.*(secret|credential)|\.env\b|API key", "secret_scan",
          {"forbid_paths": [".env", ".env.*", "*.pem", "*.key", "id_rsa", "*.p12"]}, "change", "block", "high"),
    _Rule("self-protect", r"don'?t (edit|weaken).*(gate|config)|protected (files|paths)", "self_protect",
          {"paths": ["ratchet.toml", ".ratchet/**", ".github/workflows/**"]}, "agent", "block", "high"),
    _Rule("no-force-push", r"never (force.?push|push.*--force)|don'?t force-?push", "forbid_command",
          {"deny": ["git push --force", "git push -f"]}, "agent", "warn", "medium", "--force"),
    _Rule("tests-pass", r"run the tests|tests? (must )?pass|all tests green|preflight|make.*test", "run",
          {}, "change", "commented", "high"),
    _Rule("docs-currency", r"update (the )?docs|keep docs current|docs.?currency|update (the )?README|update CLAUDE\.md",
          "path_requires", {"when": "code", "need": "docs"}, "change", "warn", "high"),
    _Rule("two-lens-review", r"two-?lens review|review before merge|\d+\+? reviewers|code review (is )?required",
          "marker_present", {"marker": r"(?i)two-lens-review\s*:", "when": "code"}, "change", "warn", "high", "two-lens"),
    _Rule("no-test-delete", r"don'?t delete.*tests?|delete the failing test", "forbid_delete",
          {"scope": "tests", "unless_paired_add": True}, "change", "warn", "medium"),
    _Rule("keep-asserts", r"keep the assert|don'?t (strip|remove).*(assert|guard|await)", "forbid_removal",
          {"pattern": r"assert|expect\(|\bawait\b", "scope": "tests"}, "change", "warn", "medium", "assert"),
    _Rule("no-debug-print", r"no (println|console\.log|print).*(prod|production)|use (tracing|logging)|no debug prints?",
          "forbid_pattern", {"pattern": r"console\.log\(|\bprintln!|System\.out\.print|fmt\.Print", "scope": "code",
                             "strip_comments": True}, "change", "warn", "medium", "console.log"),
    _Rule("attest-tdd", r"\bTDD\b|failing test first|test-?driven", "attest",
          {"class": "always", "box": "TDD"}, "agent", "warn", "medium", "TDD"),
    _Rule("no-test-skips", r"no.*(it|test|describe)\.only|no focused tests|no test skips?", "forbid_pattern",
          {"pattern": r"\.only\(|@pytest\.mark\.skip", "scope": "tests"}, "change", "warn", "medium", ".only"),
    _Rule("conventional-commits", r"conventional commits|commit message format", "require_message_pattern",
          {"pattern": r"^(feat|fix|docs|chore|refactor|test|ci|build|perf)(\(.+\))?!?: ",
           "msg_scope": ["commit_subject"]}, "change", "warn", "medium"),
    _Rule("commit-footer", r"Co-Authored-By|commit footer|sign-?off|trailer", "commit_footer",
          {}, "change", "warn", "medium"),
    _Rule("scope-lock", r"stay in scope|don'?t touch unrelated|scope ?lock", "scope_lock",
          {"allow": ["TODO"]}, "change", "commented", "low"),
    _Rule("coverage-ratchet", r"coverage|fail_under|don'?t lower (coverage|the threshold)", "numeric_floor",
          {"key": r"fail_under\s*=\s*([0-9.]+)", "direction": "no_decrease",
           "scope": ["pyproject.toml", "setup.cfg", ".coveragerc"]}, "change", "warn", "medium"),
    _Rule("no-skip-ci", r"\[skip ci\]|\[ci skip\]|don'?t disable CI", "forbid_in_message",
          {"tokens": ["[skip ci]", "[ci skip]"]}, "change", "warn", "medium"),
    _Rule("no-fat-blobs", r"no (large|fat) files|no binar|don'?t commit (build artifacts|blobs)",
          "max_added_file_bytes", {"maxkb": 256, "allow_binary": False}, "change", "warn", "low"),
    _Rule("require-owner-approval", r"CODEOWNERS|owner approval|approval from|security review", "require_approval_from",
          {"paths": ["TODO"], "require_approval_from": ["TODO"], "exclude_author": True}, "change", "commented", "low"),
    _Rule("ledger-trace", r"REVIEW-LEDGER|ledger trace|adjudication", "path_requires",
          {"when": "code", "need": ["**/REVIEW-LEDGER.md"]}, "change", "warn", "low"),
    _Rule("deferral-has-issue", r"defer|follow-?up issue|track.*(deferred|GitHub issue)", "cooccur",
          {"trigger": r"defer|follow-?up|TODO", "require": r"#\d+"}, "change", "warn", "low"),
    _Rule("semantic-judge", r"don'?t (loosen|weaken).*(assert|validation)|no fake (impl|implementation)|tautolog|no mock.*to pass",
          "judge", {}, "change", "judge", "low"),
)

# The five always-emitted block ids (gate-self-protection is a universal default).
SAFE_CORE_IDS = ("no-verify", "branch-first", "secret-scan", "self-protect", "protected-gate-files")
_CONF_ORDER = {"high": 0, "medium": 1, "low": 2}


def scan_house_rules(text: str, *, source: str, default_branch: str,
                     test_cmd: str | None) -> list[HouseRuleHit]:
    """Run HOUSE_RULE_MAP line-by-line (case-insensitive) over one CLAUDE.md/AGENTS.md.
    Each hit carries the EXACT triggering line as `rule_text`. Dedup by suggested_id
    (first match wins). The two dynamic rows are templated with default_branch / test_cmd."""
    hits: list[HouseRuleHit] = []
    seen: set[str] = set()
    for line in text.splitlines():
        for rule in HOUSE_RULE_MAP:
            if rule.rid in seen or not re.search(rule.pattern, line, re.I):
                continue
            params = dict(rule.params)
            conf = rule.conf
            if rule.rid == "branch-first":
                params = {"branch": [default_branch], "ops": ["commit", "push"]}
            elif rule.rid == "tests-pass":
                params = {"cmd": test_cmd or "TODO: your test command"}
                conf = "high" if test_cmd else "low"
            elif rule.rid == "semantic-judge":
                params = {"prompt": line.strip()}
            hits.append(HouseRuleHit(
                suggested_id=rule.rid, keyword=rule.pattern, primitive=rule.primitive,
                params=params, confidence=conf, layer=rule.layer, render=rule.render,
                match_token=rule.match_token, rule_text=line.strip(), source=source))
            seen.add(rule.rid)
    return hits


def rank_house_rules(hits: list[HouseRuleHit]) -> list[HouseRuleHit]:
    """Stable sort: confidence (high→low) then HOUSE_RULE_MAP table order."""
    order = {r.rid: i for i, r in enumerate(HOUSE_RULE_MAP)}
    return sorted(hits, key=lambda h: (_CONF_ORDER.get(h.confidence, 3), order.get(h.suggested_id, 999)))


def scan_repo(cwd: str) -> RepoScan:
    """Orchestrate the deterministic facts: tracked paths → globs; default branch; test
    command; each CLAUDE.md/AGENTS.md → scan_house_rules → dedup → rank."""
    paths = _tracked_paths(cwd)
    code, tests, docs = guess_globs(paths)
    branch = _detect_default_branch(cwd)
    cmd, src = detect_test_command(cwd)
    cm_paths = [p for p in paths if _path_matches(p, ["**/CLAUDE.md", "**/AGENTS.md"])]
    hits: list[HouseRuleHit] = []
    seen: set[str] = set()
    for cp in cm_paths:
        try:
            # errors="replace": a non-UTF-8 byte in a CLAUDE.md/AGENTS.md must skip-or-degrade
            # (the scanner is regex-over-text), never crash the whole introspection sweep with
            # an uncaught UnicodeDecodeError (a ValueError, not the OSError caught here).
            with open(os.path.join(cwd, cp), encoding="utf-8", errors="replace") as fh:
                txt = fh.read()
        except OSError:
            continue
        for h in scan_house_rules(txt, source=cp, default_branch=branch, test_cmd=cmd):
            if h.suggested_id in seen:
                continue
            seen.add(h.suggested_id)
            hits.append(h)
    return RepoScan(default_branch=branch, code=code, tests=tests, docs=docs,
                    test_cmd=cmd, test_cmd_source=src, claude_md_paths=cm_paths,
                    house_rules=rank_house_rules(hits))


_REVIEW_MARKER = "# TODO(ratchet:review)"
_DRAFT_BANNER = (
    "# ratchet.toml.draft — drafted by `ratchet suggest` + your review. This is NOT the\n"
    "# live gate: only the five safe-core checks have teeth; everything else is warn +\n"
    "# a `# TODO(ratchet:review)` marker. Arm a rule = set it to `block` AND delete its\n"
    "# marker. When `ratchet draft-lint` exits 0, `mv ratchet.toml.draft ratchet.toml`."
)
# git's well-known empty tree — HEAD vs this = every committed line as `added` (for --simulate).
_EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
_MATCH_EVERYTHING = frozenset({"", ".*", ".+", ".*?", "(.*)", "^.*$", ".*$", "^.*"})
_SAFE_CMD_CORPUS = ("git push origin feat", "git commit -m x", "git status", "npm test", "cargo test")
# The two `Check` fields whose TOML key differs from the attribute name.
_FIELD_ALIASES = {"approvers": "require_approval_from", "cls": "class"}
# Every accepted [[check]] TOML key — DERIVED from the Check dataclass (+ the two aliases) so a
# new field is auto-allowlisted and a removed one auto-drops: the parse/known-key/dataclass trio
# can't drift (the dead-`where` class). draft-lint rejects any key not in here.
_KNOWN_CHECK_KEYS = frozenset(_FIELD_ALIASES.get(f.name, f.name) for f in fields(Check))


def _toml_str(s: str) -> str:
    """TOML scalar string — a single-quote literal (no escaping) unless it contains a
    single quote or newline, in which case a basic double-quoted string with escapes."""
    if "'" not in s and "\n" not in s:
        return f"'{s}'"
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _toml_val(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, list):
        return "[" + ", ".join(_toml_val(x) for x in v) + "]"
    return _toml_str(str(v))


def _render_check(rid, kind, severity, primitive, params, layer=None, comment=False) -> str:
    lines = ["[[check]]", f"id = {_toml_str(rid)}", f"kind = {_toml_str(kind)}",
             f"severity = {_toml_str(severity)}"]
    if layer and layer != "change":
        lines.append(f"layer = {_toml_str(layer)}")
    lines.append(f"primitive = {_toml_str(primitive)}")
    for k, val in params.items():
        lines.append(f"{k} = {_toml_val(val)}")
    block = "\n".join(lines)
    return "\n".join("# " + ln for ln in block.splitlines()) if comment else block


def _safe_core_block(branch: str) -> str:
    paths = ["ratchet.toml", ".ratchet/**", ".github/workflows/**"]
    return "\n\n".join([
        _render_check("no-verify", "fact", "block", "forbid_command",
                      {"pattern": "--no-verify|--no-gpg-sign|HUSKY=0"}, layer="agent"),
        _render_check("branch-first", "fact", "block", "forbid_commit_on_branch",
                      {"branch": [branch], "ops": ["commit", "push"]}, layer="agent"),
        _render_check("secret-scan", "fact", "block", "secret_scan",
                      {"forbid_paths": [".env", ".env.*", "*.pem", "*.key", "id_rsa", "*.p12"]}),
        _render_check("self-protect", "fact", "block", "self_protect", {"paths": paths}, layer="agent"),
        # Born `warn`: requires an INDEPENDENT approver, which a solo repo has none of — a hard
        # block would be unclearable. Promote to severity="block" once a second reviewer /
        # CODEOWNERS exists (then it's the bypass-proof keystone; the engine demands a fresh,
        # non-bot, non-author approval). The agent-layer `self-protect` above already hard-blocks
        # in-session edits regardless.
        "# promote to severity=\"block\" once you have an independent reviewer (see README)\n"
        + _render_check("protected-gate-files", "fact", "warn", "protected_path", {"paths": paths}),
    ])


def _render_hit(h: HouseRuleHit) -> str:
    marker = f'{_REVIEW_MARKER}: from {h.source} "{h.rule_text[:60]}" — verify scope, watch a PR, then promote.'
    if h.primitive == "judge":
        kind, sev = "advisory", "judge"
    elif h.primitive == "attest":
        kind, sev = "advisory", "attest"
    else:
        kind, sev = "fact", "warn"
    commented = h.render in ("commented", "judge")
    return marker + "\n" + _render_check(h.suggested_id, kind, sev, h.primitive, h.params,
                                         layer=h.layer, comment=commented)


def render_suggest_toml(scan: RepoScan) -> str:
    """A deterministic ALL-WARN (+commented/judge) starter draft, guaranteed to parse. The
    only `block` checks are the five safe-core ids; everything inferred is warn + a marker
    (or commented). The host agent models its hand-authored draft on this."""
    out = [_DRAFT_BANNER, "", "schema = 1", "", "[repo]",
           f"default_branch = {_toml_str(scan.default_branch)}"]
    if scan.code:
        out.append(f"code = {_toml_val(scan.code)}")
    if scan.tests:
        out.append(f"tests = {_toml_val(scan.tests)}")
    out.append(f"docs = {_toml_val(scan.docs)}")
    out += ["", "[meta]", "base_pinned = true", "",
            "# ── safe core: always armed, all kind=fact ─────────────────────────────────",
            _safe_core_block(scan.default_branch)]
    for h in scan.house_rules:
        if h.suggested_id in SAFE_CORE_IDS:
            continue
        out += ["", _render_hit(h)]
    return "\n".join(out) + "\n"


def _scan_to_dict(scan: RepoScan) -> dict:
    return {
        "default_branch": scan.default_branch, "code": scan.code, "tests": scan.tests,
        "docs": scan.docs, "test_cmd": scan.test_cmd, "test_cmd_source": scan.test_cmd_source,
        "claude_md_paths": scan.claude_md_paths,
        "house_rules": [{
            "suggested_id": h.suggested_id, "primitive": h.primitive, "confidence": h.confidence,
            "render": h.render, "layer": h.layer, "params": h.params, "rule_text": h.rule_text,
            "source": h.source, "match_token": h.match_token,
        } for h in scan.house_rules],
    }


def is_bound(hit: HouseRuleHit, checks: list[Check]) -> tuple[bool, Check | None]:
    """Bound iff a check with `hit.primitive` exists AND (match_token is None OR the token
    appears in that check's discriminating text). The token refinement stops two different
    forbid_pattern rules from aliasing."""
    for c in checks:
        if c.primitive != hit.primitive:
            continue
        if hit.match_token is None:
            return (True, c)
        hay = " ".join(filter(None, [
            c.pattern, c.marker, c.key, " ".join(c.deny), " ".join(c.allow),
            " ".join(c.tokens), " ".join(c.need),
        ])).lower()
        if hit.match_token.lower() in hay:
            return (True, c)
    return (False, None)


def _marked_ids(text: str) -> set[str]:
    """Ids of UNCOMMENTED checks carrying a `# TODO(ratchet:review)` marker directly above
    (only blank lines may intervene). An intervening comment — e.g. a commented-out check —
    ENDS the association, so a marker above a commented block never binds to a LATER live
    `[[check]]` (which would mis-flag that check in draft-lint)."""
    lines = text.splitlines()
    marked: set[str] = set()
    for i, line in enumerate(lines):
        if not line.lstrip().startswith(_REVIEW_MARKER):
            continue
        for j in range(i + 1, min(i + 12, len(lines))):
            sj = lines[j].strip()
            if sj == "":
                continue
            if sj == "[[check]]":
                for k in range(j + 1, min(j + 8, len(lines))):
                    m = re.match(r'\s*id\s*=\s*["\']([^"\']+)', lines[k])
                    if m:
                        marked.add(m.group(1))
                        break
            break
    return marked


def draft_lint(text: str, *, existing_cfg: Config | None,
               head_facts: DiffFacts | None) -> list[LintFinding]:
    """Strict superset of Config.validate that gates the agent-authored draft. error =
    agent must fix; todo = the human's review marker; warn = informational. (See the
    module-level design notes + docs/coverage-map.md.)"""
    try:
        cfg = Config.parse(text)
    except ConfigError as e:
        return [LintFinding("error", None, f"config invalid: {e}")]
    findings: list[LintFinding] = []
    # 2 — every regex field compiles + isn't a match-everything no-op
    for c in cfg.checks:
        rx_fields = [c.pattern, c.exempt, c.key, c.marker, c.when_marker, c.trigger, c.require, *c.custom]
        for val in rx_fields:
            if not val:
                continue
            try:
                re.compile(val)
            except re.error:
                findings.append(LintFinding("error", c.id, f"invalid regex: {val!r}"))
        if c.pattern is not None and c.pattern in _MATCH_EVERYTHING:
            findings.append(LintFinding("error", c.id, "pattern matches everything → enforces nothing"))
    # 3 — no unknown/typo'd keys (closes the _from_raw silent-drop hole)
    try:
        for ct in tomllib.loads(text).get("check", []):
            cid = ct.get("id", "?")
            for k in ct:
                if k not in _KNOWN_CHECK_KEYS:
                    findings.append(LintFinding("error", cid, f"unknown check key `{k}`"))
    except tomllib.TOMLDecodeError:
        pass
    # 4 — base_pinned must be true
    if not cfg.meta.base_pinned:
        findings.append(LintFinding("error", None, "base_pinned must be true"))
    # 5 — the safe-core ids present. Four are solo-satisfiable facts → must be block. The
    # fifth, `protected-gate-files`, needs an INDEPENDENT approver no solo repo has, so it is
    # born `warn` (loud, not an unclearable wall) and promoted to block once a reviewer/
    # CODEOWNERS exists — present at warn-or-block, never absent.
    by_id = {c.id: c for c in cfg.checks}
    for sid in SAFE_CORE_IDS:
        sc = by_id.get(sid)
        if sc is None:
            findings.append(LintFinding("error", sid, f"safe-core `{sid}` must be present"))
        elif sid == "protected-gate-files":
            if sc.severity not in ("warn", "block"):
                findings.append(LintFinding("error", sid, "`protected-gate-files` must be warn or block"))
        elif sc.severity != "block":
            findings.append(LintFinding("error", sid, f"safe-core `{sid}` must be present at severity=block"))
    # 6 — born-warn: a marked check cannot be block (arming = deleting the marker)
    marked = _marked_ids(text)
    for c in cfg.checks:
        if c.id in marked and c.severity == "block":
            findings.append(LintFinding("error", c.id, "a # TODO(ratchet:review) check cannot be block — review, then arm"))
    # 7 — additive-only vs the base config (gaps mode)
    if existing_cfg is not None:
        for ec in existing_cfg.checks:
            dc = by_id.get(ec.id)
            if dc is None:
                findings.append(LintFinding("error", ec.id, "an existing check was dropped from the draft"))
            elif ec.severity == "block" and dc.severity != "block":
                findings.append(LintFinding("error", ec.id, "an existing block check was weakened"))
    # 8 — no secret leaked into a copied command string
    if any(re.search(p, text) for p in DEFAULT_SECRETS):
        findings.append(LintFinding("error", None, "a secret-shaped token is present in the draft text"))
    # 9 — over-broad forbid_command (matches a known-safe command)
    for c in cfg.checks:
        if c.primitive != "forbid_command":
            continue
        for cmd in _SAFE_CMD_CORPUS:
            if (c.deny and _deny_hit(cmd, c.deny)) or (c.pattern and re.search(c.pattern, cmd)):
                findings.append(LintFinding("warn", c.id, f"forbid_command matches a known-safe command: {cmd!r}"))
                break
    # 10 — simulate: any block that would fire on existing HEAD code (never executes `run`)
    if head_facts is not None:
        for f in run_change(cfg, head_facts, allow_run=False):
            lvl = "error" if f.severity == "block" else "warn"
            findings.append(LintFinding(lvl, f.id, f"would fire on existing HEAD code: {f.reason}"))
    # 11 — one todo per remaining review marker LINE (the human's load-bearing act)
    n_markers = sum(1 for ln in text.splitlines() if ln.lstrip().startswith(_REVIEW_MARKER))
    for _ in range(n_markers):
        findings.append(LintFinding("todo", None, "unresolved # TODO(ratchet:review) — arm + delete it, or just delete to keep advisory"))
    return findings


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


class BaseUnreachable(RuntimeError):
    """The trusted base ref is unresolvable in the authoritative path — fail closed rather
    than silently narrow the diff to HEAD~1 (which an earlier PR commit controls)."""


def _resolve_base(cwd: str, default_branch: str, *, authoritative: bool = False) -> str | None:
    mb = _git(cwd, ["merge-base", f"origin/{default_branch}", "HEAD"])
    if mb and mb.strip():
        return mb.strip()
    head_parent = _git(cwd, ["rev-parse", "HEAD~1"])
    parent = head_parent.strip() if head_parent and head_parent.strip() else None
    if authoritative:
        if parent is not None:
            # CI passed a TRUSTED --default-branch, so origin/<it> MUST be fetchable; it
            # isn't, yet HEAD has history. Narrowing to HEAD~1 would diff against a
            # PR-controlled commit (the base-pinning bypass). Refuse.
            raise BaseUnreachable(default_branch)
        # parent is None for TWO reasons: a true ROOT commit (no prior commit to hide a
        # weakening in → safe to degrade to the working tree) OR a SHALLOW clone
        # (actions/checkout's DEFAULT is depth-1, so HEAD~1 is simply unfetched). The
        # latter MUST fail closed — an empty/narrowed diff would silently PASS a change
        # the full diff blocks. `--is-shallow-repository` tells them apart.
        if (_git(cwd, ["rev-parse", "--is-shallow-repository"]) or "").strip() == "true":
            raise BaseUnreachable(default_branch)
    return parent  # local/best-effort: the previous commit, or None at the repo root


def _reasons(findings: list[Finding]) -> str:
    return "; ".join(f"{f.id}: {f.reason}" for f in findings)


def cmd_gate() -> int:
    """PreToolUse(Bash): exit 2 = deny (stderr shown to the agent), 0 = allow.

    Two denials: (1) a forbidden command shape (e.g. --no-verify) — a HARD deny, not
    bypassable; (2) a `git push` / `gh pr merge` whose ahead-of-main DoD blocks fail
    (for a merge, also the two-lens block in the PR body) — bypassable via the
    agent-layer escape hatch, because CI still enforces."""
    buf = sys.stdin.read()
    tool_name, tool_input = _pretooluse_tool(buf)
    try:
        cfg = _read_working_config(".")
    except (OSError, ConfigError):
        return 0  # no/invalid config in this repo → never block
    # 0) a Write/Edit to a gate-defining file — a HARD deny (self_protect), so the
    #    agent can't loosen its own gate mid-session. Routed here when the hook matcher
    #    fires on a write tool; a Bash payload simply has no write path.
    if tool_name in WRITE_TOOLS:
        fp = tool_input.get("file_path") or tool_input.get("notebook_path") or ""
        spblocks = run_self_protect_gate(cfg, tool_name, fp if isinstance(fp, str) else "")
        if has_block(spblocks):
            print(f"ratchet: blocked — {_reasons(spblocks)}", file=sys.stderr)
            return 2
        return 0
    cmd = CommandFacts.from_tool_input(tool_input)
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
    reviews_file: str | None = None,
    head_sha: str | None = None,
    pr_author: str | None = None,
    checks_file: str | None = None,
    allow_bypass: bool = False,
    default_branch_arg: str | None = None,
) -> int:
    """CHANGE layer: 1 = blocking findings, 0 = clean (warns print, never fail).

    `pr_body_file` / `approvals` / `reviews_file` / `head_sha` / `pr_author` /
    `checks_file` supply PR context (CI passes them; local pre-push omits them, so
    PR-body / reviewer-identity / checks-green checks skip rather than false-fire).
    `allow_bypass` honours the agent-layer escape hatch (pre-push convenience); the
    authoritative CI run never sets it."""
    try:
        wcfg = _read_working_config(cwd)
        # The base branch NAME comes from a TRUSTED CLI flag (CI passes the repo's real
        # default) when given, falling back to the working-tree config only for local use.
        # Never let the PR-head config's default_branch SELECT the base — that is the
        # base-pinning bypass (rename it to an unfetched ref → silent HEAD~1 fallback).
        default_branch = default_branch_arg or wcfg.repo.default_branch
        if allow_bypass and _bypass_reason(wcfg, _attestation_text(cwd, wcfg)):
            print("ratchet: BYPASS (agent-layer, pre-push) — CI still enforces", file=sys.stderr)
            return 0
    except (OSError, ConfigError):
        default_branch = default_branch_arg or "main"
    try:
        base = _resolve_base(cwd, default_branch, authoritative=default_branch_arg is not None)
    except BaseUnreachable:
        print(
            f"ratchet: base ref origin/{default_branch} is unreachable — refusing to gate a "
            f"narrowed diff (set 'fetch-depth: 0' on actions/checkout)", file=sys.stderr,
        )
        return 1
    try:
        cfg = load_config(cwd, base)
    except (OSError, ConfigError) as e:
        print(f"ratchet: cannot load base-pinned config: {e}", file=sys.stderr)
        return 1
    head = "HEAD"
    facts = DiffFacts.from_range(cwd, base or "HEAD~1", head)
    if pr_body_file:
        try:
            with open(pr_body_file, encoding="utf-8") as fh:
                facts.pr_body = fh.read()
        except OSError:
            pass  # no body file → stays None (no PR context)
    if approvals is not None:
        facts.approvals = [a.strip() for a in approvals.split(",") if a.strip()]
    if reviews_file:
        # A requested-but-garbled reviews file FAILS CLOSED (→ [], no qualifying approver),
        # never silently downgrading to trust the unverified flat --approvals string.
        facts.reviews = _load_reviews(reviews_file) or []
    facts.head_sha = head_sha or (_git(cwd, ["rev-parse", head]) or "").strip() or None
    facts.pr_author = pr_author
    if checks_file and os.path.exists(checks_file):
        # Requested AND present: a garbled/unreadable file FAILS CLOSED (→ [], so a
        # `need`-scoped require_checks_green blocks `missing`) rather than silently skipping
        # a check we were told to enforce. A genuinely ABSENT path leaves checks=None →
        # skip (no PR context) — the documented degrade, never a false-block.
        facts.checks = _load_checks(checks_file) or []
    if any(c.primitive == "max_added_file_bytes" for c in cfg.checks):
        _populate_file_sizes(cwd, base or "HEAD~1", head, facts)
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


def _config_advisories(cfg: Config) -> list[str]:
    """Non-fatal config-shape foot-guns: a valid config can still be a trap. Surfaced by
    `validate` (and never fail it) so the racy shape is caught at author time, not in a
    blocked PR."""
    out = []
    for c in cfg.checks:
        if c.primitive == "require_checks_green" and not c.need and not c.ignore:
            out.append(
                f"`{c.id}` (require_checks_green) sets neither `need` nor `ignore`: run inside "
                "the workflow it gates, ratchet's own still-pending check self-blocks. Set "
                '`ignore = ["<ratchet job name>"]`, or `need` only the other checks.'
            )
    return out


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
    for note in _config_advisories(cfg):
        print(f"ratchet: note: {note}", file=sys.stderr)
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
    # errors="replace" so a non-UTF-8 ratchet.toml surfaces as a ConfigError (bad TOML),
    # which callers already handle, rather than an uncaught UnicodeDecodeError that would
    # crash the gate hook (the gate must never block/traceback on a malformed config).
    with open(os.path.join(cwd, "ratchet.toml"), encoding="utf-8", errors="replace") as fh:
        return Config.parse(fh.read())


def cmd_suggest(cwd: str = ".", fmt: str = "json") -> int:
    """Extract repo facts → JSON (the contract the host agent consumes) or an all-warn
    starter draft. Writes NOTHING — the agent authors `ratchet.toml.draft`, never this."""
    scan = scan_repo(cwd)
    print(json.dumps(_scan_to_dict(scan), indent=2) if fmt == "json" else render_suggest_toml(scan))
    return 0


def cmd_gaps(cwd: str = ".", fmt: str = "text") -> int:
    """Advisory: which CLAUDE.md house-rules NO check binds (prose vs mechanism, on the
    repo it guards). Always exit 0 — it never gates."""
    try:
        cfg = _read_working_config(cwd)
    except (OSError, ConfigError):
        print("ratchet: no ratchet.toml — run /ratchet-init first")
        return 0
    scan = scan_repo(cwd)
    if not scan.house_rules:
        print("ratchet: no CLAUDE.md/AGENTS.md house-rules found")
        return 0
    rows = []
    for h in scan.house_rules:
        bound, c = is_bound(h, cfg.checks)
        if h.render == "judge":
            bucket = "not-mechanizable"
        elif bound and c and c.severity == "block":
            bucket = "bound-block"
        elif bound:
            bucket = "bound-warn"
        else:
            bucket = "unbound"
        rows.append((h, bound, c, bucket))
    if fmt == "json":
        print(json.dumps([{
            "rule_id": h.suggested_id, "primitive": h.primitive, "bound": b,
            "check_id": (c.id if c else None), "severity": (c.severity if c else None),
            "evidence": h.rule_text, "bucket": bk,
        } for h, b, c, bk in rows], indent=2))
        return 0
    unbound = [r for r in rows if r[3] == "unbound"]
    bound_block = [r for r in rows if r[3] == "bound-block"]
    bound_warn = [r for r in rows if r[3] == "bound-warn"]
    if unbound:
        print("✗ UNBOUND — prose with no mechanism (the headline):")
        for h, _b, _c, _bk in unbound:
            print(f'    {h.suggested_id}: "{h.rule_text[:70]}"  → suggest `{h.primitive}`')
    if bound_warn:
        print("~ bound but advisory only (warn — no teeth yet):")
        for h, _b, c, _bk in bound_warn:
            print(f"    {h.suggested_id} → {c.id if c else '?'} (warn)")
    if bound_block:
        print("✓ enforced (block):")
        for h, _b, c, _bk in bound_block:
            print(f"    {h.suggested_id} → {c.id if c else '?'}")
    nb = len(bound_block) + len(bound_warn)
    print(f"\nratchet: {len(rows)} house-rule(s) · {nb} bound · {len(unbound)} unbound — advisory only")
    return 0


def cmd_draft_lint(cwd: str = ".", config: str = "ratchet.toml.draft", simulate: bool = False) -> int:
    """Strict-validate the agent-authored draft (superset of validate). Exit 0 iff
    structure is clean AND zero review markers remain; else 1."""
    try:
        # errors="replace" so a non-UTF-8 draft fails as a clean ConfigError (bad structure)
        # below, not an uncaught UnicodeDecodeError traceback.
        with open(os.path.join(cwd, config), encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        print(f"ratchet: no draft at {config} — run `ratchet suggest` / `/ratchet-init` first", file=sys.stderr)
        return 1
    existing = None
    try:
        existing = load_config(cwd, _resolve_base(cwd, _detect_default_branch(cwd)))
    except (OSError, ConfigError):
        pass
    head_facts = DiffFacts.from_range(cwd, _EMPTY_TREE, "HEAD") if simulate else None
    findings = draft_lint(text, existing_cfg=existing, head_facts=head_facts)
    tags = {"error": "ERROR", "warn": "warn ", "todo": "TODO "}
    for f in findings:
        loc = f"{f.check_id}: " if f.check_id else ""
        print(f"  [{tags[f.level]}] {loc}{f.msg}")
    blocking = sum(1 for f in findings if f.level in ("error", "todo"))
    if blocking:
        print(f"ratchet: draft not ready ({blocking} item(s) to resolve)", file=sys.stderr)
        return 1
    print("ratchet: draft OK — `mv ratchet.toml.draft ratchet.toml` to arm it")
    return 0


# ─────────────────────────────────────────────────────────────────────────────
# WIRING  —  install / uninstall / doctor  (the adoption surface)
# ─────────────────────────────────────────────────────────────────────────────
#
# The agent layer keeps `${CLAUDE_PLUGIN_ROOT}/ratchet.py` (the var exists only
# in-session). The CHANGE layer must run in CI / a teammate's pre-push / a fresh
# clone where that var is undefined and base-pinning needs the engine + config in
# git history — so `install` VENDORS the engine to `.ratchet/ratchet.py`
# (committed, base-pinnable, offline) and wires a sentinel-delimited managed block
# into the effective pre-push, coexisting with husky/lefthook/pre-commit/hooksPath.

RATCHET_BEGIN = "# >>> ratchet (managed block) >>>"
RATCHET_END = "# <<< ratchet <<<"

PREPUSH_BLOCK = f"""\
{RATCHET_BEGIN}
if [ -f .ratchet/ratchet.py ] && command -v python3 >/dev/null 2>&1; then
    python3 .ratchet/ratchet.py check --cwd . --allow-bypass < /dev/null || exit 1
fi
{RATCHET_END}
"""

CI_WORKFLOW = """\
name: ratchet
on:
  pull_request: {}
  push:
    branches: [main]
permissions:
  contents: read
  pull-requests: read
  checks: read
jobs:
  ratchet:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
        with:
          fetch-depth: 0
      - uses: IvanWng97/ratchet@v0
"""

LEFTHOOK_SNIPPET = """\
# lefthook detected — add to lefthook.yml, then `lefthook install`:
pre-push:
  commands:
    ratchet:
      run: python3 .ratchet/ratchet.py check --cwd .
"""

PRECOMMIT_SNIPPET = """\
# pre-commit detected — add to .pre-commit-config.yaml
# (default_install_hook_types: [pre-push]); then `pre-commit install`:
- repo: local
  hooks:
    - id: ratchet
      name: ratchet (Definition-of-Done)
      entry: python3 .ratchet/ratchet.py check --cwd .
      language: system
      stages: [pre-push]
      pass_filenames: false
      always_run: true
"""


def _slurp(path: str) -> str:
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return ""


def _repo_root(cwd: str) -> str | None:
    out = _git(cwd, ["rev-parse", "--show-toplevel"])
    return out.strip() if out else None


def _is_within(path: str, root: str) -> bool:
    rp, rr = os.path.realpath(path), os.path.realpath(root)
    return rp == rr or rp.startswith(rr + os.sep)


def _atomic_write(path: str, text: str, *, mode: int = 0o644, confine: str | None = None) -> None:
    """Write `text` to `path` atomically, WRITING THROUGH a symlink to its realpath
    target (stow-safe — never replaces the symlink with a regular file): mkstemp in
    the real directory + os.replace onto the real file. `confine` (when set) refuses a
    write whose realpath escapes that root — for committed gate files (engine/config) a
    repo that ships `.ratchet/ratchet.py` as a symlink to `../../etc/…` must NOT make
    `install` clobber an arbitrary path on a victim's clone; the pre-push hook write
    deliberately omits `confine` because a stow-symlinked hook is intended."""
    real = os.path.realpath(path)
    if confine is not None and not _is_within(real, confine):
        raise OSError(f"refusing to write {path}: resolves outside the repo ({real})")
    d = os.path.dirname(real) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".ratchet-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(tmp, mode)
        os.replace(tmp, real)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _replace_or_append_block(cur: str, block: str) -> str:
    """Replace the sentinel-delimited managed block in `cur` with `block`, else append.
    Byte-idempotent: a second call with the same block reproduces the input."""
    block = block if block.endswith("\n") else block + "\n"
    bi = cur.find(RATCHET_BEGIN)
    if bi == -1:
        if cur and not cur.endswith("\n"):
            cur += "\n"
        return cur + block
    ei = cur.find(RATCHET_END, bi)
    if ei == -1:  # malformed begin-without-end → replace to EOF
        return cur[:bi] + block
    nl = cur.find("\n", ei)
    tail = cur[nl + 1:] if nl != -1 else ""
    return cur[:bi] + block + tail


def _strip_block(cur: str) -> str:
    """Remove exactly the sentinel span (uninstall). No-op when absent."""
    bi = cur.find(RATCHET_BEGIN)
    if bi == -1:
        return cur
    ei = cur.find(RATCHET_END, bi)
    if ei == -1:
        return cur[:bi]
    nl = cur.find("\n", ei)
    tail = cur[nl + 1:] if nl != -1 else ""
    return cur[:bi] + tail


def _ensure_gitignore(root: str) -> None:
    """Scoped + idempotent: ignore `.ratchet/.state` (the debounce state) — NEVER the
    whole `.ratchet/` dir, which would un-commit the vendored engine."""
    p = os.path.join(root, ".gitignore")
    line = ".ratchet/.state"
    cur = _slurp(p)
    if line in {ln.strip() for ln in cur.splitlines()}:
        return
    sep = "" if (not cur or cur.endswith("\n")) else "\n"
    _atomic_write(p, cur + sep + line + "\n", confine=root)


def _detect_hook_manager(root: str) -> str | None:
    for name in ("lefthook.yml", "lefthook.yaml", "lefthook.toml"):
        if os.path.exists(os.path.join(root, name)):
            return "lefthook"
    if os.path.exists(os.path.join(root, ".pre-commit-config.yaml")):
        return "pre-commit"
    if os.path.isdir(os.path.join(root, ".husky")):
        return "husky"
    return None


def _effective_hook_target(cwd: str, root: str) -> tuple[str, str]:
    """Where (and whether) to write the pre-push block. First match wins:
      lefthook / pre-commit present → emit a snippet, write NOTHING (they regenerate
      their own hook). husky → `.husky/pre-push`. core.hooksPath inside the repo →
      that dir. else the worktree-aware `.git/hooks`. An absolute/out-of-repo
      hooksPath (a shared global dir) or a non-repo → skip (vendor/config/CI still go).
    Returns (action, payload): "write"→abs pre-push path; "snippet:<mgr>"→text; "skip"→reason."""
    mgr = _detect_hook_manager(root)
    if mgr == "lefthook":
        return ("snippet:lefthook", LEFTHOOK_SNIPPET)
    if mgr == "pre-commit":
        return ("snippet:pre-commit", PRECOMMIT_SNIPPET)
    if mgr == "husky":
        return ("write", os.path.join(root, ".husky", "pre-push"))
    hooks_path = (_git(cwd, ["config", "--get", "core.hooksPath"]) or "").strip()
    if hooks_path:
        abs_hooks = hooks_path if os.path.isabs(hooks_path) else os.path.normpath(os.path.join(root, hooks_path))
        if _is_within(abs_hooks, root):
            return ("write", os.path.join(abs_hooks, "pre-push"))
        return ("skip", f"core.hooksPath is outside the repo ({hooks_path}) — a shared global hooks dir; "
                        "add the pre-push block there by hand, or rely on CI")
    gh = _git(cwd, ["rev-parse", "--git-path", "hooks"])
    if not gh:
        return ("skip", "not a git repository")
    abs_gh = gh.strip()
    if not os.path.isabs(abs_gh):
        abs_gh = os.path.normpath(os.path.join(cwd, abs_gh))
    return ("write", os.path.join(abs_gh, "pre-push"))


def _vendor_engine(root: str) -> str | None:
    """Copy this running engine → `.ratchet/ratchet.py`. Returns the dest, or None when
    it would self-reference (running `install` FROM the already-vendored copy → never
    truncate the file we're executing)."""
    src = os.path.realpath(__file__)
    dst = os.path.join(root, ".ratchet", "ratchet.py")
    if os.path.realpath(dst) == src:
        return None
    _atomic_write(dst, _slurp(src), mode=0o644, confine=root)
    return dst


def _exec_mode(real: str) -> int:
    """The mode for an (atomic re-)write of a hook file: PRESERVE an existing file's perms
    and only ensure +x — appending the managed block must not widen a husky / `.githooks`
    hook to 0o755. A brand-new hook ratchet authors is 0o755."""
    if os.path.exists(real):
        return (os.stat(real).st_mode & 0o777) | 0o111
    return 0o755


def _install_prepush(target_path: str) -> None:
    """Append/replace the managed block in the effective pre-push (write-through a
    symlink to its realpath; chmod +x). Skips the write when already byte-identical."""
    real = os.path.realpath(target_path)
    if os.path.exists(real):
        cur = _slurp(real)
        new = _replace_or_append_block(cur, PREPUSH_BLOCK)
    else:
        cur = ""
        new = "#!/bin/sh\n" + PREPUSH_BLOCK
    if new != cur:
        _atomic_write(target_path, new, mode=_exec_mode(real))
        return
    st = os.stat(real)
    if not st.st_mode & 0o111:
        os.chmod(real, (st.st_mode & 0o777) | 0o111)


def _write_ci(root: str, branch: str = "main") -> str | None:
    """Scaffold the change-layer CI workflow IF ABSENT (non-clobber), with the push-trigger
    branch set to the repo's real default branch."""
    p = os.path.join(root, ".github", "workflows", "ratchet.yml")
    if os.path.exists(p):
        return None
    _atomic_write(p, CI_WORKFLOW.replace("branches: [main]", f"branches: [{branch}]"), mode=0o644, confine=root)
    return p


def _scaffold_config(branch: str) -> str:
    """The starter `ratchet.toml`, with the detected default branch substituted for the
    `main` default (so base-pinning + branch-first are correct on master/trunk repos)."""
    if branch == "main":
        return INIT_TEMPLATE
    return (INIT_TEMPLATE
            .replace('default_branch = "main"', f'default_branch = "{branch}"')
            .replace('branch = ["main"]', f'branch = ["{branch}"]'))


def _protects_gate_files(cfg: Config) -> bool:
    """True iff some protected_path/self_protect check's globs cover the engine, `ratchet.toml`,
    AND the CI workflow (doctor #8 — the engine-neuter defense). The engine is matched at the
    vendored `.ratchet/ratchet.py` OR a root `ratchet.py` (ratchet's own repo)."""
    for c in cfg.checks:
        if c.primitive not in ("protected_path", "self_protect") or not c.paths:
            continue
        covers_engine = _path_matches(".ratchet/ratchet.py", c.paths) or _path_matches("ratchet.py", c.paths)
        covers_config = _path_matches("ratchet.toml", c.paths)
        covers_ci = _path_matches(".github/workflows/ratchet.yml", c.paths)
        if covers_engine and covers_config and covers_ci:
            return True
    return False


def cmd_install(cwd: str = ".", vendor: bool = True, config: bool = True,
                hook: bool = True, ci: bool = True, gitignore: bool = True) -> int:
    """Idempotent, non-clobbering wiring of the change layer. No flags ⇒ do all five.
    Touches only plumbing (vendor / scaffold / hook / CI / gitignore) — never authors a
    check's severity/kind, so the block-requires-fact moat is untouched."""
    root = _repo_root(cwd)
    if root is None:
        print("ratchet: not a git repository — run `git init` first", file=sys.stderr)
        return 1
    branch = _detect_default_branch(cwd)
    did: list[str] = []
    if vendor:
        dst = _vendor_engine(root)
        did.append("vendored .ratchet/ratchet.py" if dst else "engine already vendored (self) — skipped")
    if config:
        cfg_path = os.path.join(root, "ratchet.toml")
        if os.path.exists(cfg_path):
            did.append("ratchet.toml exists — left untouched")
        else:
            _atomic_write(cfg_path, _scaffold_config(branch), confine=root)
            did.append(f"wrote starter ratchet.toml (default_branch={branch})")
    if gitignore:
        _ensure_gitignore(root)
        did.append("ensured .gitignore covers .ratchet/.state")
    if hook:
        action, payload = _effective_hook_target(cwd, root)
        if action == "write":
            _install_prepush(payload)
            did.append(f"wired pre-push managed block ({os.path.realpath(payload)})")
        elif action.startswith("snippet:"):
            did.append(f"{action.split(':', 1)[1]} detected — wrote nothing; add this snippet:\n\n{payload}")
        else:
            did.append(f"pre-push skipped — {payload}")
    if ci:
        did.append("scaffolded .github/workflows/ratchet.yml" if _write_ci(root, branch)
                   else ".github/workflows/ratchet.yml exists — left untouched")
    print("ratchet install:")
    for d in did:
        print(f"  • {d}")
    if vendor or config or ci:
        print("\nnext: `git add .ratchet/ratchet.py ratchet.toml .github/workflows/ratchet.yml` "
              "& commit, then `ratchet doctor`")
    return 0


def cmd_uninstall(cwd: str = ".") -> int:
    """Conservative: strip ONLY the local pre-push managed block. Never `git rm`
    committed source (engine / config / workflow) — that is an explicit reviewable change."""
    root = _repo_root(cwd)
    if root is None:
        print("ratchet: not a git repository", file=sys.stderr)
        return 1
    action, payload = _effective_hook_target(cwd, root)
    if action != "write":
        msg = (f"hooks managed by {action.split(':', 1)[1]} — remove the ratchet snippet by hand"
               if action.startswith("snippet:") else payload)
        print(f"ratchet uninstall: {msg}")
        return 0
    real = os.path.realpath(payload)
    cur = _slurp(real)
    if not os.path.exists(real) or RATCHET_BEGIN not in cur:
        print("ratchet uninstall: no managed block in the pre-push — nothing to strip")
        return 0
    stripped = _strip_block(cur)
    if stripped.strip() in ("", "#!/bin/sh"):  # only our shebang remains → we authored it
        os.remove(real)
        print(f"ratchet uninstall: removed the ratchet-authored pre-push hook ({real})")
    else:
        _atomic_write(payload, stripped, mode=_exec_mode(real))
        print(f"ratchet uninstall: stripped the managed block, kept the rest ({real})")
    print("note: committed .ratchet/ratchet.py, ratchet.toml and the CI workflow are NOT removed "
          "(remove them in a reviewed change)")
    return 0


def cmd_doctor(cwd: str = ".", as_json: bool = False) -> int:
    """Read-only diagnosis of both layers. Exit 1 ONLY on a hard change-layer failure
    (engine missing / won't compile, or config invalid); everything else is advisory."""
    root = _repo_root(cwd)
    base_dir = root or cwd
    rows: list[tuple[str, str, str]] = []

    def add(status: str, label: str, fix: str = "") -> None:
        rows.append((status, label, fix))

    if sys.version_info >= (3, 11):
        add("ok", f"python {sys.version_info.major}.{sys.version_info.minor} ≥ 3.11")
    else:
        add("warn", f"python {sys.version_info.major}.{sys.version_info.minor} < 3.11", "tomllib needs 3.11+")

    hard_fail = False
    eng = os.path.join(base_dir, ".ratchet", "ratchet.py")
    if os.path.exists(eng):
        try:
            compile(_slurp(eng), eng, "exec")  # syntax-check; writes no __pycache__
            add("ok", ".ratchet/ratchet.py present and compiles")
        except SyntaxError as e:
            add("fail", ".ratchet/ratchet.py does not compile", str(e).splitlines()[0])
            hard_fail = True
    else:
        add("fail", ".ratchet/ratchet.py missing", "run `ratchet install` (or /ratchet-init) to vendor the engine")
        hard_fail = True

    cfg: Config | None = None
    cfg_path = os.path.join(base_dir, "ratchet.toml")
    if os.path.exists(cfg_path):
        try:
            cfg = Config.parse(_slurp(cfg_path))
            add("ok", f"ratchet.toml valid — {len(cfg.checks)} checks, base_pinned={cfg.meta.base_pinned}")
        except (OSError, ConfigError) as e:
            add("fail", "ratchet.toml invalid", str(e))
            hard_fail = True
    else:
        add("fail", "ratchet.toml missing", "run `ratchet install` / `/ratchet-init`")
        hard_fail = True

    if root:
        action, payload = _effective_hook_target(cwd, root)
        if action == "write":
            real = os.path.realpath(payload)
            if os.path.exists(real) and RATCHET_BEGIN in _slurp(real):
                add("ok", f"pre-push managed block present ({real})")
            else:
                add("warn", "pre-push managed block absent", "run `ratchet install` (CI is the authoritative gate)")
        elif action.startswith("snippet:"):
            add("warn", f"hooks managed by {action.split(':', 1)[1]} — snippet expected (not auto-written)",
                "add the ratchet snippet from `ratchet install`")
        else:
            add("warn", f"pre-push not wired — {payload}", "rely on CI")

    wf = os.path.join(base_dir, ".github", "workflows", "ratchet.yml")
    if os.path.exists(wf) and "ratchet" in _slurp(wf):
        add("ok", ".github/workflows/ratchet.yml references ratchet")
    else:
        add("warn", "CI workflow absent", "run `ratchet install` to scaffold .github/workflows/ratchet.yml")

    default_branch = cfg.repo.default_branch if cfg else _detect_default_branch(cwd)
    base = _resolve_base(cwd, default_branch)
    if base:
        add("ok", f"base ref reachable ({base})")
    else:
        add("warn", "base ref unreachable", "shallow clone? set `fetch-depth: 0` — base-pinning degrades")

    if base and cfg and cfg.meta.base_pinned:
        bc = _git(cwd, ["show", f"{base}:ratchet.toml"])
        add("ok" if bc else "warn",
            "base-pinned config readable" if bc else "base-pinned config not yet in the base ref (first commit?)")
    else:
        add("skip", "base-pinning off or no base ref")

    if cfg:
        covered = _protects_gate_files(cfg)
        add("ok" if covered else "warn",
            "gate files covered by protected_path/self_protect" if covered else "gate files not self-protected",
            "" if covered else "add a protected_path covering .ratchet/** + ratchet.toml + .github/workflows/** "
                               "(the action's rev-pinned engine already covers GitHub CI)")

    if os.environ.get("CLAUDE_PLUGIN_ROOT"):
        add("ok", "agent layer: CLAUDE_PLUGIN_ROOT set (plugin active in-session)")
    else:
        add("skip", "agent layer: run /ratchet-doctor inside Claude Code to verify the plugin")

    if as_json:
        print(json.dumps([{"status": s, "label": lbl, "fix": fx} for s, lbl, fx in rows], indent=2))
    else:
        glyph = {"ok": "✓", "warn": "~", "fail": "✗", "skip": "·"}
        for s, lbl, fx in rows:
            print(f"  {glyph[s]} {lbl}")
            if fx and s in ("warn", "fail"):
                print(f"      → {fx}")
        print()
        if hard_fail:
            print("ratchet doctor: change layer NOT ready (fix the ✗ above)", file=sys.stderr)
        else:
            print("ratchet doctor: change layer ready")
    return 1 if hard_fail else 0


def main(argv: list[str] | None = None) -> int:
    # The renders carry non-ASCII glyphs (the `─` rule in suggest, doctor's ✓/~/✗/·);
    # a Windows console/pipe defaults to cp1252 and would UnicodeEncodeError on them.
    # Force UTF-8 at the CLI boundary only (a library must not reconfigure global streams).
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except (AttributeError, ValueError):
            pass
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
    c.add_argument("--reviews-file", help="JSON reviews array login/state/commit_id/is_bot (CI only). Freshness needs the commit oid — use action.yml's GraphQL query, not `gh pr view`")
    c.add_argument("--head-sha", help="PR head commit SHA (freshness for approval_policy; CI only)")
    c.add_argument("--pr-author", help="PR author login (excludes self-approval; CI only)")
    c.add_argument("--checks-file", help="JSON from `gh pr checks --json name,state` (require_checks_green; CI only)")
    c.add_argument("--default-branch", help="trusted base branch name (CI passes the repo's real default; overrides ratchet.toml so the base can't be redirected from the PR head)")
    c.add_argument("--allow-bypass", action="store_true", help="honour the agent-layer bypass (pre-push only)")
    j = sub.add_parser("judge", help="emit the advisory LLM-judge prompt(s) to stdout (CI)")
    j.add_argument("--cwd", default=".")
    v = sub.add_parser("validate", help="parse + validate ratchet.toml (the block-requires-fact invariant)")
    v.add_argument("--config", default="ratchet.toml")
    i = sub.add_parser("init", help="write a starter ratchet.toml")
    i.add_argument("--config", default="ratchet.toml")
    sg = sub.add_parser("suggest", help="extract repo facts → a ranked draft policy (for /ratchet-init; never writes)")
    sg.add_argument("--cwd", default=".")
    sg.add_argument("--format", choices=["json", "toml"], default="json")
    dl = sub.add_parser("draft-lint", help="strict-validate a drafted policy (superset of validate; gates on TODO markers)")
    dl.add_argument("--cwd", default=".")
    dl.add_argument("--config", default="ratchet.toml.draft")
    dl.add_argument("--simulate", action="store_true", help="also flag any block that would fire on existing HEAD code")
    gp = sub.add_parser("gaps", help="advisory: which CLAUDE.md house-rules are NOT bound by a ratchet check")
    gp.add_argument("--cwd", default=".")
    gp.add_argument("--format", choices=["text", "json"], default="text")
    ins = sub.add_parser("install", help="wire the change layer: vendor engine + scaffold config/hook/CI (idempotent)")
    ins.add_argument("--cwd", default=".")
    ins.add_argument("--no-vendor", action="store_true", help="skip vendoring .ratchet/ratchet.py")
    ins.add_argument("--no-config", action="store_true", help="skip writing a starter ratchet.toml")
    ins.add_argument("--no-hook", action="store_true", help="skip wiring the pre-push hook")
    ins.add_argument("--no-ci", action="store_true", help="skip scaffolding the CI workflow")
    ins.add_argument("--no-gitignore", action="store_true", help="skip the .gitignore entry")
    un = sub.add_parser("uninstall", help="strip the local pre-push managed block (never removes committed source)")
    un.add_argument("--cwd", default=".")
    dr = sub.add_parser("doctor", help="diagnose both layers (read-only; exit 1 only on a hard change-layer failure)")
    dr.add_argument("--cwd", default=".")
    dr.add_argument("--json", action="store_true", help="emit the per-check status array")
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
            reviews_file=args.reviews_file,
            head_sha=args.head_sha,
            pr_author=args.pr_author,
            checks_file=args.checks_file,
            allow_bypass=args.allow_bypass,
            default_branch_arg=args.default_branch,
        )
    if args.cmd == "judge":
        return cmd_judge(args.cwd)
    if args.cmd == "validate":
        return cmd_validate(args.config)
    if args.cmd == "init":
        return cmd_init(args.config)
    if args.cmd == "suggest":
        return cmd_suggest(args.cwd, fmt=args.format)
    if args.cmd == "draft-lint":
        return cmd_draft_lint(args.cwd, args.config, args.simulate)
    if args.cmd == "gaps":
        return cmd_gaps(args.cwd, fmt=args.format)
    if args.cmd == "install":
        return cmd_install(
            args.cwd,
            vendor=not args.no_vendor,
            config=not args.no_config,
            hook=not args.no_hook,
            ci=not args.no_ci,
            gitignore=not args.no_gitignore,
        )
    if args.cmd == "uninstall":
        return cmd_uninstall(args.cwd)
    if args.cmd == "doctor":
        return cmd_doctor(args.cwd, as_json=args.json)
    if args.cmd == "selftest":
        print("ratchet selftest: ok (run `python3 -m pytest` / `tests/test_ratchet.py` for the full suite)")
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
