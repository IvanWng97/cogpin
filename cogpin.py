#!/usr/bin/env python3
"""cogpin — Definition-of-Done gate for AI coding agents.

ONE language-agnostic engine, ONE per-repo `cogpin.toml`. The engine reads only
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
import ast
import json
import os
import re
import shlex
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
    is agent-only, so a change-layer placement would silently never fire.
    `provenance` is the NATURE OF THE FACT SOURCE: an "environment" fact is produced by
    git / the harness / the PR API independent of the gated agent's say-so (a real diff, a
    file status, a branch, a CI conclusion, a non-author approval) — it cannot be fabricated,
    so it MAY hard-block. An "agent" fact is a self-authored token that merely CLAIMS an
    out-of-band event happened (a typed review marker, a ticked attestation box) — the agent
    can satisfy it without the requirement holding, so it may only warn/attest. The tightened
    moat (invariant #1): `block` REQUIRES `kind="fact"` AND `provenance="environment"`."""
    kind: str
    layers: frozenset[str] = _ANY_LAYER
    provenance: str = "environment"


# THE primitive registry: one Spec per primitive is the single source for the name set
# (PRIMITIVES), the fact/advisory split (_ADVISORY_ONLY + the moat-mislabel guard), and the
# layer-placement rule (validate). Adding a primitive is ONE entry here, not parallel-list edits.
# The evaluator FN, its typed call, and the gate-runner routing stay EXPLICIT in _eval_diff / the
# runners (the table holds no callable — that keeps mypy's per-call arity check and the route test).
PRIMITIVE_SPECS: dict[str, "Spec"] = {
    "secret_scan": Spec("fact"),
    "forbid_command": Spec("fact", _AGENT_ONLY),  # live-signal: reads the live command string
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
    # marker_present's PASS is a self-typed marker the agent writes that merely CLAIMS an
    # out-of-band event (a two-lens review occurred) — it can be satisfied without the event,
    # so it is agent-provenance: a forcing-function nag (warn), never a hard block. To truly
    # gate a review, use a real non-author approval (require_approval_from / approval_policy).
    "marker_present": Spec("fact", provenance="agent"),
    "commit_footer": Spec("fact"),
    "protected_path": Spec("fact"),
    "require_approval_from": Spec("fact"),
    "pattern_requires_approval": Spec("fact"),
    "approval_policy": Spec("fact"),
    "require_checks_green": Spec("fact"),
    "run": Spec("fact"),
    "attest": Spec("advisory", provenance="agent"),
    "judge": Spec("advisory", provenance="agent"),
}
PRIMITIVES = frozenset(PRIMITIVE_SPECS)
# advisory-by-nature primitives (decide over no fact → can never block, whatever the `kind` label).
_ADVISORY_ONLY = frozenset(n for n, s in PRIMITIVE_SPECS.items() if s.kind == "advisory")
# agent-provenance primitives: their PASS is a self-authored claim token, not an environment
# fact → they may only warn/attest, never block (the second clause of the tightened moat).
_AGENT_PROVENANCE = frozenset(n for n, s in PRIMITIVE_SPECS.items() if s.provenance != "environment")

# Per-primitive LOAD-BEARING params (#45): a check missing these loads clean but is a silent
# no-op — the evaluator early-returns None / matches nothing, so the gate never fires and the
# adopter believes a toothless check holds. Each value is an AND-list of OR-groups: at least one
# field in EVERY group must be present. Primitives with a documented empty/default mode are
# ABSENT here on purpose (secret_scan→DEFAULT_SECRETS, forbid_delete→all deletions,
# forbid_commit_on_branch→default branch+ops, require_checks_green→bare all-green, approval_policy
# →min-1, max_added_file_bytes→still blocks binaries, attest/judge→advisory).
_REQUIRED_PARAMS: dict[str, tuple[tuple[str, ...], ...]] = {
    "forbid_pattern": (("pattern",),),
    "forbid_removal": (("pattern",),),
    "require_message_pattern": (("pattern",),),
    "file_must_contain": (("pattern",),),
    "pattern_requires_approval": (("pattern",),),
    "marker_present": (("marker",),),
    "forbid_in_message": (("tokens",),),
    "numeric_floor": (("key",),),
    "scope_lock": (("allow",),),
    "self_protect": (("paths",),),
    "protected_path": (("paths",),),
    "run": (("cmd",),),
    "cooccur": (("trigger",), ("require",)),                 # both, else inert
    "require_approval_from": (("paths",), ("approvers",)),   # no paths→inert; no approvers→unclearable
    "path_requires": (("need",), ("when", "when_marker")),   # need AND a trigger
    "forbid_command": (("pattern", "deny"),),               # at least one
    "change_budget": (("max_added", "max_removed", "max_files", "max_file_added"),),
}


def _present(val: object) -> bool:
    """A config value counts as SUPPLIED iff it is not None / "" / [] — but 0 IS supplied (a
    `change_budget` cap of 0 is a real, strict ceiling, not a missing field)."""
    return val is not None and val != "" and val != []



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
    attestation_file: str = ".cogpin/attestation.md"
    # a change is "feature-shaped" at >= this many changed files (or a new code module)
    feature_files: int = 3


# backends `capability emit` knows how to render to; an unknown backend is a config error
# (a declared-but-unrenderable floor is misleading). Only claude-code is emitted today.
_CAPABILITY_BACKENDS = frozenset({"claude-code", "bubblewrap", "docker", "seccomp"})


@dataclass
class Capability:
    """A DECLARED capability floor — POLICY, not enforcement. cogpin records and compares
    this stanza and can EMIT it to a harness's native enforcement (`cogpin capability emit`),
    but it NEVER reads it during gate/check evaluation and NEVER confines a syscall itself.
    The OS/harness is the boundary; cogpin only declares the posture (see docs/composition.md).
    Its integrity comes for free: it lives in cogpin.toml, which is self_protect'd and read
    from the pinned base ref — so the floor is base-pinned without any new machinery."""
    no_network: bool = False
    fs_confine: list[str] = field(default_factory=list)
    deny_paths: list[str] = field(default_factory=list)
    allow_commands: list[str] = field(default_factory=list)
    deny_commands: list[str] = field(default_factory=list)
    backend: str = "claude-code"

    def is_empty(self) -> bool:
        return not (self.no_network or self.fs_confine or self.deny_paths
                    or self.allow_commands or self.deny_commands)


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
    # cogpin's OWN job, which is still pending while it gates the same workflow run.
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


def _regex_field_values(c: "Check") -> list[str]:
    """The one source of truth for which Check fields are regexes — consumed by BOTH
    Config.validate (the fail-loud compile guard) and draft_lint. A field added to only
    one of the two sites would silently re-open the regex fail-open hole."""
    return [v for v in (c.pattern, c.exempt, c.key, c.marker, c.when_marker, c.trigger, c.require, *c.custom) if v]


@dataclass
class Config:
    schema: int
    repo: RepoCfg
    meta: Meta
    checks: list[Check]
    capability: Capability = field(default_factory=Capability)

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
            attestation_file=m.get("attestation_file", ".cogpin/attestation.md"),
            feature_files=int(m.get("feature_files", 3)),
        )
        cap = raw.get("capability", {})
        capability = Capability(
            no_network=bool(cap.get("no_network", False)),
            fs_confine=_as_list(cap.get("fs_confine")),
            deny_paths=_as_list(cap.get("deny_paths")),
            allow_commands=_as_list(cap.get("allow_commands")),
            deny_commands=_as_list(cap.get("deny_commands")),
            backend=cap.get("backend", "claude-code"),
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
        return Config(schema=raw.get("schema", 0), repo=repo, meta=meta, checks=checks,
                      capability=capability)

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
            # THE moat (two clauses): only an ungameable, ENVIRONMENT-provenance fact may
            # hard-block. (1) kind=fact — an advisory judgment is gameable by the gated agent.
            if c.severity == "block" and c.kind != "fact":
                raise ConfigError(
                    f"check `{c.id}`: severity=block requires kind=fact (only "
                    f"diff/command/PR-metadata facts may block; advisory checks are "
                    f"gameable by the gated agent)"
                )
            # (2) provenance=environment — a fact whose PASS is a self-authored token (a typed
            # marker, a ticked box) merely CLAIMS an out-of-band event; the agent can satisfy it
            # without the requirement holding, so it may only warn/attest. Closes the principal-
            # agent hole inside the fact set (e.g. a self-typed two-lens marker hard-blocking).
            if c.severity == "block" and c.primitive in _AGENT_PROVENANCE:
                raise ConfigError(
                    f"check `{c.id}`: severity=block requires an environment-provenance fact, but "
                    f"`{c.primitive}` reads an agent-authored token that only CLAIMS an out-of-band "
                    f"event — use severity=warn (a forcing-function nag), or back the requirement "
                    f"with a real environment fact: require_approval_from / approval_policy (a "
                    f"non-author approval) or require_checks_green (a CI conclusion)"
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
            if c.primitive == "run" and c.layer == "agent":
                raise ConfigError(
                    f"check `{c.id}`: a `run` check must live at the change layer, not agent "
                    f"(no agent-layer runner dispatches it — it would silently never fire)"
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
            # Every populated regex field must COMPILE — an uncompilable pattern makes its
            # primitive return None (a silent PASS), disabling a block gate on an author typo.
            # (draft_lint compiles these too; the authoritative validate path must as well.)
            for _rxv in _regex_field_values(c):
                try:
                    re.compile(_rxv)
                except (re.error, TypeError) as _e:
                    raise ConfigError(f"check `{c.id}`: invalid regex {_rxv!r}: {_e}")
            # Typed string-enums: an unknown member selects zero targets → a vacuous PASS (the
            # same fail-open class as `direction`). msg_scope drives the message primitives;
            # status the file_must_contain A/M/D filter (compared upper-cased).
            _bad_scope = [sc for sc in c.msg_scope if sc not in _MSG_SCOPES]
            if _bad_scope:
                raise ConfigError(
                    f"check `{c.id}`: unknown msg_scope {_bad_scope} (known: {', '.join(_MSG_SCOPES)})"
                )
            if c.status is not None and (not isinstance(c.status, str) or c.status.upper() not in (ADDED, MODIFIED, DELETED)):
                raise ConfigError(
                    f"check `{c.id}`: status must be one of A/M/D, got `{c.status}`"
                )
            # Load-bearing params (#45): a primitive missing the field(s) it cannot function
            # without LOADS clean but is a silent no-op (its evaluator early-returns None). Placed
            # LAST so a more-fundamental error (bad regex / enum / layer) still surfaces first.
            for _group in _REQUIRED_PARAMS.get(c.primitive, ()):
                if not any(_present(getattr(c, _f, None)) for _f in _group):
                    # name the TOML KEY, not the internal attr (approvers ← require_approval_from),
                    # so the fix the message points at is the one the user can actually type.
                    _names = " or ".join(f"`{_FIELD_ALIASES.get(_f, _f)}`" for _f in _group)
                    raise ConfigError(
                        f"check `{c.id}`: {c.primitive} requires {_names} — without it the check "
                        f"loads clean but can never do useful work (it never fires, or with a "
                        f"partial config can never be satisfied)"
                    )
            # commit_footer's load-bearing param is META-scoped ([meta].commit_footer), not a Check
            # attribute — so it can't live in _REQUIRED_PARAMS, but a footer-less one is the same
            # #45 silent no-op (_rx(None) → None → the evaluator early-returns).
            if c.primitive == "commit_footer" and not _present(self.meta.commit_footer):
                raise ConfigError(
                    f"check `{c.id}`: commit_footer requires `[meta].commit_footer` (the footer "
                    f"regex) — without it the check loads clean but never fires"
                )
        # [capability] is a DECLARATION (policy), never a [[check]] — it can't block (a
        # primitive="capability" already fails "unknown primitive" above). The only validation
        # is well-formedness: an unknown backend is a config error (a floor that can't be
        # rendered is misleading). List shapes are coerced by _as_list; no_network by bool.
        if self.capability.backend not in _CAPABILITY_BACKENDS:
            raise ConfigError(
                f"[capability] unknown backend `{self.capability.backend}` "
                f"(known: {', '.join(sorted(_CAPABILITY_BACKENDS))})"
            )

    @property
    def footer_regex(self) -> str | None:
        return self.meta.commit_footer


# ─────────────────────────────────────────────────────────────────────────────
# facts  (the ONLY inputs a `fact` check reads — all ungameable by the agent)
# ─────────────────────────────────────────────────────────────────────────────

ADDED, MODIFIED, DELETED = "A", "M", "D"


def _parse_unified_added_removed(diff: str) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    """The shared body parse — walk a unified diff, attributing +/- CONTENT lines to the
    +++ b/ / --- a/ path of the hunk they sit in. Both acquisition paths (git `from_range`
    and the fixture `from_unified_diff`) run this ONE battle-tested loop so they can't drift.

    +++ b/<path> / --- a/<path> are FILE HEADERS, but a removed/added CONTENT line can itself
    start with `--- `/`+++ ` (an SQL/Lua `-- ` comment renders as `--- …` under a single `-`
    marker). Disambiguate by hunk state: headers sit in the per-file preamble (before the first
    `@@`); attribute +/- to a path only inside a hunk body. Else one such line poisons path
    attribution for the whole file — a scoped forbid_removal/secret_scan false-negative."""
    added: list[tuple[str, str]] = []
    removed: list[tuple[str, str]] = []
    new_path = old_path = ""
    in_hunk = False
    # split("\n") + rstrip("\r"): preserve CRLF normalization (git terminates lines with \n; a
    # CRLF file's content keeps its trailing \r) WITHOUT splitlines()'s over-eager break on
    # \v \f \x85 U+2028/9 inside a content line, which would sever an added line and drop the
    # post-separator token (a false-negative).
    for raw in diff.split("\n"):
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
            added.append((new_path, line[1:]))
        elif in_hunk and line.startswith("-") and old_path:
            removed.append((old_path, line[1:]))
    return added, removed


def _changed_from_headers(diff: str) -> list[tuple[str, str]]:
    """Derive (status, path) per file from a unified diff's HEADERS — the `--name-status`
    equivalent for a fixture with no git to query. Handles adds (`new file mode`), deletes
    (`deleted file mode`), renames (`rename to` → MODIFIED on the new path, matching
    name-status's R→M coalesce) and binary blobs (`Binary files a/X and b/Y differ`, which
    carry no +++/--- header). Header lines are read only in the per-file preamble (before the
    first `@@`) so a content line starting with `--- `/`+++ ` can't be mistaken for a header."""
    changed: list[tuple[str, str]] = []
    status = MODIFIED
    new_path = old_path = rename_to = dg_path = ""
    in_body = seen = False

    def flush() -> None:
        # dg_path (parsed from the `diff --git a/X b/Y` line) is the LAST resort — it catches a
        # pure mode-only (chmod) file, which emits no +++/---/rename/binary line (from_range
        # reports it via --name-status, so match that). Ambiguous if a path contains " b/"; the
        # +++ b/ path is always preferred when present.
        if seen and (path := rename_to or new_path or old_path or dg_path):
            changed.append((status, path))

    for raw in diff.split("\n"):
        line = raw.rstrip("\r")
        if line.startswith("diff --git "):
            flush()
            status, new_path, old_path, rename_to = MODIFIED, "", "", ""
            body = line[len("diff --git "):]
            i = body.rfind(" b/")
            dg_path = body[i + 3:] if i != -1 and body.startswith("a/") else ""
            in_body, seen = False, True
        elif in_body:
            continue  # past the first @@: only content, never a header
        elif line.startswith("@@"):
            in_body = True
        elif line.startswith("new file mode"):
            status = ADDED
        elif line.startswith("deleted file mode"):
            status = DELETED
        elif line.startswith("rename to "):
            rename_to = line[len("rename to "):]
        elif line.startswith("--- "):
            old_path = line[6:] if line.startswith("--- a/") else ""
        elif line.startswith("+++ "):
            new_path = line[6:] if line.startswith("+++ b/") else ""
        elif line.startswith("Binary files "):
            # a binary blob has no +++/--- header — the only path source is this line:
            # `Binary files a/X and b/Y differ` (a/X or b/Y is /dev/null for a delete/add).
            body = line[len("Binary files "):]
            if body.endswith(" differ"):
                body = body[: -len(" differ")]
            a, _, b = body.partition(" and ")
            if b.startswith("b/"):
                new_path = b[2:]
            if a.startswith("a/"):
                old_path = a[2:]
    flush()
    return changed


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
            f.added, f.removed = _parse_unified_added_removed(diff)
        log = _git(cwd, ["log", "--format=%B%x1e", rng])
        if log:
            f.commit_msgs = [m.strip() for m in log.split("\x1e") if m.strip()]
        return f

    @staticmethod
    def from_unified_diff(text: str) -> "DiffFacts":
        """Acquisition source #3 (#18): build DiffFacts from a raw git-format unified diff (a
        fixture file) so a consumer can regression-test cogpin.toml against crafted diffs.
        Reuses the SAME added/removed body parse as from_range; derives `changed` from the file
        headers (a fixture has no git to query for `--name-status`). REQUIRES git format (the
        `diff --git` header) — a plain `diff -u` carries no rename/delete/binary status, so
        accepting it would silently under-populate `changed` and read as a false-clean."""
        if "diff --git " not in text:
            raise ValueError(
                "not a git-format unified diff (no `diff --git` header) — generate the fixture "
                "with `git diff` / `git format-patch`, not plain `diff -u`"
            )
        f = DiffFacts()
        f.added, f.removed = _parse_unified_added_removed(text)
        f.changed = _changed_from_headers(text)
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
    `cogpin.toml`, the engine, the hook `settings.json`) is denied at the PreToolUse
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
    """The one-way floor: pair a numeric token across the remove/add hunks on the
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
    # A `block` cooccur must rest ONLY on environment evidence (the diff): pr_body and
    # commit_msgs are agent-authored, so allowing them to satisfy a block would let the
    # gated agent type the require token to clear the gate without the requirement holding
    # (the marker_present hole). They stay available to a `warn` (a forcing-function nag),
    # keeping cooccur block-capable for its constitutive diff-only use (migration→rollback).
    env_only = check.severity == "block"
    body = "" if env_only else (facts.pr_body or "")
    msgs: list[str] = [] if env_only else facts.commit_msgs
    present = trig.search(body) or any(trig.search(l) for _, l in facts.added)
    if not present:
        return None
    satisfied = (
        req.search(body)
        or any(req.search(l) for _, l in facts.added)
        or any(req.search(m) for m in msgs)
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
    (all green EXCEPT these). When cogpin runs as a job in the SAME workflow it gates,
    its own check is still pending at query time and would self-block — exclude it via
    `ignore = ["<cogpin job name>"]` (or `need` only the others). See SCHEMA.md."""
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
    """The decisive bypass-proof load: read `cogpin.toml` from the PINNED BASE ref,
    never the PR head, so a same-diff edit can't relax the gate it's gated by.
    Falls back to the working tree only when the base ref has no cogpin.toml yet
    (e.g. the first-ever commit adding it)."""
    if base_ref:
        text = _git(cwd, ["show", f"{base_ref}:cogpin.toml"])
        if text is not None:
            cfg = Config.parse(text)
            if cfg.meta.base_pinned:
                return cfg
            # base_pinned explicitly off → honour the working-tree policy instead
    with open(os.path.join(cwd, "cogpin.toml"), encoding="utf-8") as fh:
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
def _cmd_name(tok: str) -> str:
    """Bare command name of a token — strips a leading path so a path-qualified invocation
    (`/usr/bin/gh`, `./gh`, `bin/gh`) maps to its basename. Split on `/` (a shell path is
    always `/`-separated, OS-independent); shlex already un-escapes a backslash-quoted name."""
    return tok.rsplit("/", 1)[-1]


def _seg_is_gh_merge(toks: list[str]) -> bool:
    """`gh pr merge …` (contiguous tokens) or `gh api … <…/merge> …` within ONE shell
    segment. Token-equality (basename-matched, so `/usr/bin/gh` still counts), NOT a regex
    over the re-joined string — so a phrase merely naming the verb in a quoted string
    (`echo "gh pr merge"`, one shlex token) can't match, while a real `gh pr "merge" 7`
    (three tokens) and a backtick/path-qualified invocation still do. (A wrapper that hides
    the verb in a quoted command argument — `bash -c "gh pr merge"` — is one inert token by
    the same property that kills the false positive; a static scanner can't see into it, and
    the old regex missed it too. The pre-push/CI change layer is the backstop for git push;
    gh-merge basename-matching is the extra hardening for the one path it can't backstop.)"""
    for i in range(len(toks) - 1):
        if _cmd_name(toks[i]) != "gh":
            continue
        rest = toks[i + 1:]
        if rest[:2] == ["pr", "merge"]:
            return True
        if rest[0] == "api" and any("/merge" in t for t in rest[1:]):
            return True
    return False


_CONT_RE = re.compile(r"\\\r?\n")          # backslash-newline shell line-continuation
_SEG_PUNCT = "();<>|&{}`"                      # operators that bound a command segment (incl. ` cmd-subst)
_OP_TOKEN = re.compile(rf"^[{re.escape(_SEG_PUNCT)}]+$")


def _shell_segments(cmd: str) -> list[list[str]]:
    """Tokenize a shell command into operator-bounded segments with REAL quote handling:
    shlex strips quote GLYPHS but keeps quoted CONTENT as one token, so `git "push"` →
    ['git','push'] is caught (a shell runs the real verb) while `echo "git push"` stays
    ['echo','git push'] — one token, no false hit. Backslash-newline continuations fold first.
    On a lexer error (unbalanced quotes) it degrades to a glyph-strip split that errs toward
    DETECTION — over-denying a malformed command is the safe direction for a deny gate."""
    cmd = _CONT_RE.sub("", cmd or "")
    try:
        lex = shlex.shlex(cmd, posix=True, punctuation_chars=_SEG_PUNCT)
        lex.whitespace_split = True
        lex.commenters = ""  # '#' never hides a verb from a deny-scanner
        toks = list(lex)
    except ValueError:
        glyphs = cmd.replace('"', "").replace("'", "")
        return [t for t in (seg.split() for seg in _SHELL_SEP.split(glyphs)) if t]
    segs: list[list[str]] = []
    cur: list[str] = []
    for t in toks:
        if _OP_TOKEN.match(t):
            if cur:
                segs.append(cur)
                cur = []
        else:
            cur.append(t)
    if cur:
        segs.append(cur)
    return segs


def _git_ops(cmd: str) -> set[str]:
    """The set of git SUBCOMMANDS invoked across shell-separated segments, tolerating
    leading git global options + their values (`git -C dir -c k=v push` → {"push"}).
    shlex-tokenized so a verb named inside a quoted message stays one token (no false hit)
    while a quoted verb (`git "push"`) is still caught. Tokenized → ReDoS-immune."""
    ops: set[str] = set()
    for toks in _shell_segments(cmd):
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
    for seg in _shell_segments(cmd):
        if _seg_is_gh_merge(seg):
            return "merge"
    return "push" if "push" in _git_ops(cmd) else None


_ENV_ASSIGN = re.compile(r"^\w+=")


def _normalize_command_segments(cmd: str) -> list[list[str]]:
    """Shell-split, then per segment strip leading `sudo` + `VAR=val` assignments and,
    for a git invocation, drop global options (+ their values) so the gated verb sits at
    the front. shlex-tokenized (quote glyphs removed, quoted content kept whole), so a
    quoted verb can't hide. Defeats the `git -C/path`, `cd d &&`, `env X=Y`, `git -c k=v`,
    and `git "push"` evasions that prefix matching misses (#66176)."""
    segs: list[list[str]] = []
    for toks in _shell_segments(cmd):
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
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        # absent / unreadable / not-JSON / not-UTF-8 all collapse to "no usable doc" → None, so
        # every caller degrades safe (a fail-closed gate or a default) instead of crashing.
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
    SUCCESS/FAILURE/PENDING under `state`). Returns None on a missing/garbled file — a
    REQUESTED-but-unparseable `--checks-file` makes callers FAIL CLOSED (exit 2); a genuinely
    absent path is the caller's `checks=None` skip (no PR context)."""
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


@dataclass(frozen=True)
class LangScope:
    name: str
    file_count: int
    code: list[str]
    tests: list[str]


# A secondary language needs a REAL area, not a stray file or two. An ABSOLUTE floor, never a
# fraction: a 200-file TS site in a 5000-file Rust repo is ~3.8%, so any fraction gate high
# enough to drop 3 stray files also drops the real site (under-coverage = the cardinal sin).
# No max-language cap: the flat union must cover EVERY floor-clearing language (a cap would
# leave the lowest-ranked langs' files matched by no glob — the same under-coverage), and the
# breakdown is bounded by _LANG_PROFILES (≤6) anyway.
_SECONDARY_MIN_FILES = 10


def guess_scopes(paths: list[str]) -> list[LangScope]:
    """Per-language (code, tests) scopes for the languages PRESENT in a tracked-path list,
    dominant-first — the polyglot generalization of the old single-dominant pick (#19). The
    dominant language (most code files) is always included; a SECONDARY enters only at
    `>= min(_SECONDARY_MIN_FILES, dominant_count)` files (the clamp lets a near-parity
    secondary in on a tiny repo while 3-in-5000 stays out). Globs are kept only if they match
    ≥1 path; if a lang's structured globs ALL miss (a flat/non-src layout), it falls back to
    `**/*{ext}` for EACH of its extensions actually present — never a single ext that could
    match nothing (a `.tsx`-only node tree must not fall back to a dead `**/*.ts`). Empty/
    garbled tree → []. Never raises."""
    if not paths:
        return []
    present = sorted(
        ((n, i, lang) for i, lang in enumerate(_LANG_PROFILES)
         if (n := sum(1 for p in paths if p.endswith(lang.exts))) > 0),  # n>0: a zero-match lang is never selected
        key=lambda t: (-t[0], t[1]),  # count desc, then _LANG_PROFILES order (the old tie-break)
    )
    if not present:
        return []
    floor = min(_SECONDARY_MIN_FILES, present[0][0])

    def keep(globs: tuple[str, ...]) -> list[str]:
        return [g for g in globs if any(_glob_to_re(g).match(p) for p in paths)]

    out: list[LangScope] = []
    for rank, (n, _i, lang) in enumerate(present):
        if rank >= 1 and n < floor:
            break  # sorted desc → every later lang is also below the floor
        # fallback over the PRESENT extensions only, so a multi-ext lang (node: .ts/.tsx/.js/
        # .jsx) whose curated globs miss still emits a glob that matches its actual files.
        fallback = [f"**/*{e}" for e in lang.exts if any(p.endswith(e) for p in paths)]
        out.append(LangScope(lang.name, n, keep(lang.code_globs) or fallback, keep(lang.test_globs)))
    return out


def _flat_globs(scopes: list[LangScope], paths: list[str]) -> tuple[list[str], list[str], list[str]]:
    """Flatten per-language scopes into the (code, tests, docs) `[repo]` defaults: code/tests
    are the dominant-first union (first-wins dedup, each lang's most-specific-first order
    preserved); docs default `["**/*.md"]` + `docs/**` iff a docs/ path exists."""
    docs = ["**/*.md"]
    if any(p.startswith("docs/") for p in paths):
        docs.append("docs/**")

    def _union(lists: list[list[str]]) -> list[str]:
        out: list[str] = []
        seen: set[str] = set()
        for lst in lists:
            for g in lst:
                if g not in seen:
                    seen.add(g)
                    out.append(g)
        return out

    return (_union([s.code for s in scopes]), _union([s.tests for s in scopes]), docs)


def guess_globs(paths: list[str]) -> tuple[list[str], list[str], list[str]]:
    """(code, tests, docs) globs — the FLAT union over `guess_scopes` (every detected language),
    kept for the `[repo]` defaults + the single-language contract (a one-lang repo's output is
    byte-identical to the old dominant pick). Empty/garbled tree → ([], [], ["**/*.md"])."""
    return _flat_globs(guess_scopes(paths), paths)


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
    # Per-language breakdown (dominant-first) so the host agent can author PER-SUBTREE checks —
    # the merged code/tests above is a blob that can't express a JS-only or Rust-only rule (#19).
    languages: list[LangScope] = field(default_factory=list)


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
          {"paths": ["cogpin.toml", ".cogpin/**", ".github/workflows/**"]}, "agent", "block", "high"),
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
    _Rule("coverage-floor", r"coverage|fail_under|don'?t lower (coverage|the threshold)", "numeric_floor",
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
    languages = guess_scopes(paths)             # per-language breakdown (#19); scanned once...
    code, tests, docs = _flat_globs(languages, paths)  # ...and flattened to the [repo] defaults
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
                    house_rules=rank_house_rules(hits), languages=languages)


_REVIEW_MARKER = "# TODO(cogpin:review)"
_DRAFT_BANNER = (
    "# cogpin.toml.draft — drafted by `cogpin suggest` + your review. This is NOT the\n"
    "# live gate: only the five safe-core checks have teeth; everything else is warn +\n"
    "# a `# TODO(cogpin:review)` marker. Arm a rule = set it to `block` AND delete its\n"
    "# marker. When `cogpin draft-lint` exits 0, `mv cogpin.toml.draft cogpin.toml`."
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
    paths = ["cogpin.toml", ".cogpin/**", ".github/workflows/**"]
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
    if len(scan.languages) > 1:
        # name the folded-in languages so a human sees the [repo] globs span >1 language and can
        # split them into per-subtree checks from the `languages` breakdown (suggest --format json).
        out.append("# detected: " + ", ".join(f"{ls.name}({ls.file_count})" for ls in scan.languages))
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
        # per-language breakdown (dominant-first) — the host agent's contract for authoring
        # per-subtree checks (a `console.log` forbid on JS-only, `println!` on Rust-only). The
        # flat code/tests above stay the [repo] defaults; this decomposes them by language (#19).
        "languages": [{"name": ls.name, "file_count": ls.file_count, "code": ls.code,
                       "tests": ls.tests} for ls in scan.languages],
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
    """Ids of UNCOMMENTED checks carrying a `# TODO(cogpin:review)` marker directly above
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
        for val in _regex_field_values(c):
            try:
                re.compile(val)
            except (re.error, TypeError):
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
            findings.append(LintFinding("error", c.id, "a # TODO(cogpin:review) check cannot be block — review, then arm"))
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
        findings.append(LintFinding("todo", None, "unresolved # TODO(cogpin:review) — arm + delete it, or just delete to keep advisory"))
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

INIT_TEMPLATE = """\
# cogpin.toml — Definition-of-Done policy. https://github.com/IvanWng97/cogpin
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
# bypass_env = "COGPIN_BYPASS"          # agent-layer escape hatch (always logged)
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
            print(f"cogpin: blocked — {_reasons(spblocks)}", file=sys.stderr)
            return 2
        return 0
    cmd = CommandFacts.from_tool_input(tool_input)
    # 1) hard deny: forbidden command shapes + commit/push on a protected branch —
    #    never bypassable (a forbidden command skips the hooks; branch-first is cheap).
    cmdblocks = run_command_gate(cfg, cmd)
    cmdblocks += run_branch_gate(cfg, cmd, _current_branch("."))
    if has_block(cmdblocks):
        print(f"cogpin: blocked — {_reasons(cmdblocks)}", file=sys.stderr)
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
        print(f"cogpin: DoD not met for {kind}:\n{_render(blocks)}{hint}", file=sys.stderr)
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
        # The gate fail-OPENS on an unloadable config — but it must NOT do so SILENTLY (#16).
        # A PRESENT-but-unloadable cogpin.toml (bad TOML, a primitive a stale engine doesn't
        # know, or an unreadable file) means the real-time gate is OFF; say so on stderr, once
        # per turn-end. Keyed on EXISTENCE, not the exception type — a present-but-unreadable
        # file raises OSError too, so branching on ConfigError-vs-OSError would miss it. An
        # absent config is genuinely nothing to gate → stay silent. The decision still rides
        # stdout as "{}" (stderr-only notice keeps the Stop-hook JSON contract intact).
        if os.path.exists(os.path.join(cwd, "cogpin.toml")):
            print("cogpin: cogpin.toml present but the agent-layer engine can't load it — "
                  "real-time gate OFF this turn; run `cogpin doctor`", file=sys.stderr)
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
    state = os.path.join(cwd, ".cogpin", ".state")
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
    report_only: bool = False,
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
            print("cogpin: BYPASS (agent-layer, pre-push) — CI still enforces", file=sys.stderr)
            return 0
    except (OSError, ConfigError):
        default_branch = default_branch_arg or "main"
    try:
        base = _resolve_base(cwd, default_branch, authoritative=default_branch_arg is not None)
    except BaseUnreachable:
        print(
            f"cogpin: base ref origin/{default_branch} is unreachable — refusing to gate a "
            f"narrowed diff (set 'fetch-depth: 0' on actions/checkout)", file=sys.stderr,
        )
        return 1
    try:
        cfg = load_config(cwd, base)
    except (OSError, ConfigError) as e:
        # stay fail-CLOSED (return 1). When the cause is an unknown-primitive / unsupported-schema
        # ConfigError, the vendored engine running this check is stale relative to the config it
        # gates (#16) — name that, instead of the opaque "cannot load config".
        _es = str(e)
        if "unsupported schema" in _es:
            hint = " — the vendored engine is behind this config's schema; run `cogpin update`"
        elif "unknown primitive" in _es:
            hint = (" — check SCHEMA.md for the valid primitive names (or run `cogpin update` "
                    "only if your engine is genuinely behind the docs)")
        else:
            hint = ""
        print(f"cogpin: cannot load base-pinned config: {e}{hint}", file=sys.stderr)
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
        # Requested AND present but UNPARSEABLE → FAIL CLOSED (exit 2), mirroring cmd_fixture.
        # `or []` here was the M3 fail-open: a corrupt file → None → [] passes a BARE
        # require_checks_green vacuously (an empty set bare-iterates to nothing). A genuinely
        # ABSENT path still leaves checks=None → skip (no PR context) — the documented degrade.
        facts.checks = _load_checks(checks_file)
        if facts.checks is None:
            print(f"cogpin: cannot parse --checks-file (expected a JSON array): {checks_file}",
                  file=sys.stderr)
            return 2
    if any(c.primitive == "max_added_file_bytes" for c in cfg.checks):
        _populate_file_sizes(cwd, base or "HEAD~1", head, facts)
    findings = run_change(cfg, facts, allow_run=allow_run)
    for f in findings:
        tag = "BLOCK" if f.severity == "block" else "warn "
        print(f"  [{tag}] {f.id}: {f.reason}")
    if has_block(findings):
        n = sum(1 for f in findings if f.severity == "block")
        # report-only is the global ROLLOUT switch (distinct from per-check severity="warn"):
        # run the AUTHORITATIVE policy non-failing over real PRs, then flip it off to enforce.
        # It suppresses ONLY blocking-FINDING failures — the fail-CLOSED infra errors above
        # (BaseUnreachable, an unloadable base-pinned config) still return 1, so a shadow run
        # can't go green while the gate never actually evaluated the diff.
        if report_only:
            print(f"cogpin: report-only — {n} blocking finding(s) WOULD fail "
                  "(exit 0; remove --report-only / set report-only:false to enforce)")
            return 0
        print(f"cogpin: definition-of-done NOT met ({n} blocking)", file=sys.stderr)
        return 1
    print(f"cogpin: ok ({len(findings)} advisory warning(s))")
    return 0


# change-layer checks backtest can't evaluate without a checkout (`run`) or PR context
# (approvals / reviews / status checks). Counted + named so a clean backtest is never
# misread as "fully calibrated" when the real teeth weren't exercised.
_BACKTEST_BLIND = frozenset({
    "run", "protected_path", "require_approval_from", "pattern_requires_approval",
    "approval_policy", "require_checks_green",
})


def _backtest_blind(cfg: Config) -> list[str]:
    """Check ids backtest CANNOT evaluate (no checkout → no `run`; no PR context → no
    approvals/reviews/checks). Beyond the run/approval primitives this also names the
    pr_body-TRIGGERED block variants — a path_requires gated on a `when_marker`, and a message
    check scoped ONLY to `pr_body` — because both read facts.pr_body, which backtest leaves
    empty, so they'd silently never fire and a clean report would overstate coverage."""
    out = []
    for c in cfg.checks:
        if c.primitive in _BACKTEST_BLIND:
            out.append(c.id)
        elif c.primitive == "path_requires" and c.when_marker:
            out.append(c.id)
        elif (c.primitive in ("require_message_pattern", "forbid_in_message")
              and c.msg_scope and all(s == "pr_body" for s in c.msg_scope)):
            out.append(c.id)
    return sorted(out)


def cmd_backtest(cwd: str = ".", rng: str = "", config: str | None = None,
                 fail_on_block: bool = False) -> int:
    """Replay the CURRENT change-layer policy over a range of merged history — the
    "would this policy have false-blocked?" calibration (#17). A pure REPORT (exit 0) unless
    --fail-on-block (1 if any commit would block); exit 2 = couldn't run (bad range / shallow
    clone / unloadable config). Uses the WORKING-tree config (you're testing your CANDIDATE
    policy against history, not auditing what the old gate did) and covers only DIFF-FACT
    checks — `run` and PR-context checks are skipped (and named in the summary)."""
    if config and not os.path.exists(config):
        # _slurp swallows OSError → "" → a typo'd path would misreport as "schema version 0";
        # name the real cause instead. Still fail-CLOSED (exit 2), never a false-clean.
        print(f"cogpin: no such config file: {config}", file=sys.stderr)
        return 2
    try:
        cfg = Config.parse(_slurp(config)) if config else _read_working_config(cwd)
    except (OSError, ConfigError) as e:
        print(f"cogpin: cannot load config: {e}", file=sys.stderr)
        return 2
    if (_git(cwd, ["rev-parse", "--is-shallow-repository"]) or "").strip() == "true":
        print("cogpin: shallow clone — backtest can't diff commits against their parents; "
              "fetch full history first (`git fetch --unshallow`)", file=sys.stderr)
        return 2
    # One enumeration call. %x1e field framing (a subject can contain a tab) + split('\n')
    # records — NOT splitlines(), which over-breaks on \v\f\x85/U+2028/9 a subject may carry.
    # --first-parent so each node is one merged PR (squash) or the full net merge diff
    # (merge-commit), never a dive into second-parent ancestry.
    raw = _git(cwd, ["log", "--reverse", "--first-parent", "--format=%H%x1e%h%x1e%P%x1e%s", rng])
    if raw is None:   # git error (bad range) — distinct from "" (valid, zero commits)
        print(f"cogpin: invalid range `{rng}` (git could not resolve it)", file=sys.stderr)
        return 2
    rows = [r for r in raw.split("\n") if r]
    if not rows:
        print(f"cogpin: no commits in range `{rng}`")
        return 0
    sizes_needed = any(c.primitive == "max_added_file_bytes" for c in cfg.checks)
    blind = _backtest_blind(cfg)
    would_block = evaluated = 0
    for rec in rows:
        parts = rec.split("\x1e")
        if len(parts) < 4:
            continue
        full, short, parents, subject = parts[0], parts[1], parts[2].split(), parts[3]
        if not parents:   # root commit has no parent → no diff to evaluate
            continue
        parent = parents[0]
        evaluated += 1
        facts = DiffFacts.from_range(cwd, parent, full)
        if sizes_needed:
            _populate_file_sizes(cwd, parent, full, facts)
        blocks = sorted({f.id for f in run_change(cfg, facts, allow_run=False)
                         if f.severity == "block"})
        if blocks:
            would_block += 1
            print(f"  ✗ {short} {subject[:60]} → {', '.join(blocks)}")
        else:
            print(f"  ✓ {short} {subject[:60]}")
    print(f"\ncogpin backtest: {would_block}/{evaluated} commit(s) would block "
          "(first-parent; per-commit ≈ per-PR on squash/merge-commit workflows)")
    if blind:
        print(f"  note: {len(blind)} check(s) NOT evaluated by backtest — they need a `run` or "
              f"PR context (approvals/reviews/checks): {', '.join(blind)}")
    return 1 if (fail_on_block and would_block) else 0


# Primitives a DIFF fixture decides from the diff ALONE (added/removed/changed) — always
# evaluable. Everything NOT classified as evaluable below is blind by DEFAULT, so a `run`,
# an agent-layer/advisory check, OR a future un-classified primitive errors on --expect (exit 2)
# rather than ever passing vacuously. Fixture mode fails toward "can't evaluate", never a
# false-clean (invariant #5). Mirror this when adding a diff-evaluated primitive.
_FIXTURE_DIFF_ONLY = frozenset({
    "secret_scan", "forbid_pattern", "forbid_removal", "forbid_delete", "scope_lock",
    "numeric_floor", "change_budget", "file_must_contain", "cooccur",
})


def _fixture_evaluable(c: Check, facts: DiffFacts) -> bool:
    """Can a diff fixture (+ the supplied PR context) actually DECIDE this check — i.e. would
    _eval_diff reach a real verdict rather than skip on an absent fact? Mirrors each primitive's
    own fact reads. Default (an un-listed primitive — `run`, max_added_file_bytes, the agent-only
    forbid_command/forbid_commit_on_branch/self_protect, attest/judge) is FALSE: blind."""
    p = c.primitive
    if p in _FIXTURE_DIFF_ONLY:
        return True
    if p == "path_requires":            # diff-only UNLESS gated on a pr_body marker
        return facts.pr_body is not None if c.when_marker else True
    if p == "marker_present":           # reads pr_body only
        return facts.pr_body is not None
    if p == "commit_footer":            # reads commit_msgs (no diff carries them)
        return bool(facts.commit_msgs)
    if p in ("require_message_pattern", "forbid_in_message"):
        scopes = set(c.msg_scope) or (
            {"commit_subject"} if p == "require_message_pattern" else set(_MSG_SCOPES))
        if (scopes & {"commit_subject", "commit_body"}) and not facts.commit_msgs:
            return False
        if "pr_body" in scopes and facts.pr_body is None:
            return False
        return True
    if p == "protected_path":           # reads approvals OR reviews
        return facts.approvals is not None or facts.reviews is not None
    if p in ("require_approval_from", "pattern_requires_approval", "approval_policy"):
        return facts.reviews is not None  # read reviews ONLY — flat --approvals is insufficient
    if p == "require_checks_green":
        return facts.checks is not None
    return False


def _fixture_blind(cfg: Config, facts: DiffFacts) -> set[str]:
    """Check ids a fixture eval CANNOT decide given the SUPPLIED context — named so an `--expect`
    over one errors (exit 2) instead of silently mis-passing (the false-clean this feature exists
    to prevent). A check is blind if run_change would SKIP it in fixture mode (agent layer, or an
    attest/judge severity that never yields a block/warn finding) or if _eval_diff would return a
    vacuous None for want of a fact the diff doesn't carry (see _fixture_evaluable)."""
    out: set[str] = set()
    for c in cfg.checks:
        if c.layer == "agent" or c.severity not in ("block", "warn"):
            out.add(c.id)              # run_change never produces a finding for these
        elif not _fixture_evaluable(c, facts):
            out.add(c.id)
    return out


def cmd_fixture(
    cwd: str,
    diff_file: str | None,
    expect_block: str | None = None,
    expect_clean: str | None = None,
    pr_body_file: str | None = None,
    approvals: str | None = None,
    reviews_file: str | None = None,
    head_sha: str | None = None,
    pr_author: str | None = None,
    checks_file: str | None = None,
    commit_msg: str | None = None,
) -> int:
    """Config-as-code fixture testing (#18): evaluate the WORKING-tree policy against a crafted
    unified-diff fixture and assert per-check expectations — turning cogpin.toml into tested
    code. Uses the working config (you test the policy you're EDITING, not a base pin), and
    never runs `run` blocks (allow_run=False). A unified diff carries no commit messages, so
    commit-message checks (commit_footer, commit-scoped require_message_pattern/forbid_in_message)
    are blind unless --commit-msg supplies one. Exit 0 = expectations met (or, with no
    expectations, a finding preview); 1 = an expectation was VIOLATED (the test failed);
    2 = couldn't run the test (no/bad diff, config, or context file; unknown or un-evaluable
    --expect id)."""
    if not diff_file:
        print("cogpin: --expect-block/--expect-clean require --diff-file (a fixture to assert "
              "against)", file=sys.stderr)
        return 2
    try:
        cfg = _read_working_config(cwd)
    except (OSError, ConfigError) as e:
        print(f"cogpin: cannot load cogpin.toml: {e}", file=sys.stderr)
        return 2
    if not os.path.exists(diff_file):
        print(f"cogpin: no such diff file: {diff_file}", file=sys.stderr)
        return 2
    try:
        with open(diff_file, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as e:
        print(f"cogpin: cannot read diff file: {e}", file=sys.stderr)
        return 2
    try:
        facts = DiffFacts.from_unified_diff(text)
    except ValueError as e:
        print(f"cogpin: {diff_file}: {e}", file=sys.stderr)
        return 2
    # Layer in any supplied context — a fixture CAN carry it (a body/commit message, a reviews/
    # checks JSON), which is what makes the message/approval/checks/pr_body checks testable here.
    # A flag that's SUPPLIED-but-unreadable is a test-authoring error → exit 2 (vs not supplied →
    # the fact stays None → the check is blinded). Coercing a garbled file to [] would defeat
    # blind detection and yield a false-clean — the bug this whole feature exists to prevent.
    if pr_body_file is not None:
        if not os.path.exists(pr_body_file):
            print(f"cogpin: no such --pr-body-file: {pr_body_file}", file=sys.stderr)
            return 2
        with open(pr_body_file, encoding="utf-8", errors="replace") as fh:
            facts.pr_body = fh.read()
    if commit_msg is not None:
        facts.commit_msgs = [commit_msg]
    if approvals is not None:
        facts.approvals = [a.strip() for a in approvals.split(",") if a.strip()]
    if reviews_file is not None:
        if not os.path.exists(reviews_file):
            print(f"cogpin: no such --reviews-file: {reviews_file}", file=sys.stderr)
            return 2
        facts.reviews = _load_reviews(reviews_file)
        if facts.reviews is None:
            print(f"cogpin: cannot parse --reviews-file (expected a JSON array): {reviews_file}",
                  file=sys.stderr)
            return 2
    if head_sha:
        facts.head_sha = head_sha
    facts.pr_author = pr_author
    if checks_file is not None:
        if not os.path.exists(checks_file):
            print(f"cogpin: no such --checks-file: {checks_file}", file=sys.stderr)
            return 2
        facts.checks = _load_checks(checks_file)
        if facts.checks is None:
            print(f"cogpin: cannot parse --checks-file (expected a JSON array): {checks_file}",
                  file=sys.stderr)
            return 2

    want_block = [s.strip() for s in (expect_block or "").split(",") if s.strip()]
    want_clean = [s.strip() for s in (expect_clean or "").split(",") if s.strip()]
    findings = run_change(cfg, facts, allow_run=False)
    for f in findings:
        tag = "BLOCK" if f.severity == "block" else "warn "
        print(f"  [{tag}] {f.id}: {f.reason}")
    if not want_block and not want_clean:
        # a fixture with no expectations is a preview ("what would fire?") — exit 0, nothing
        # to assert. The --expect flags are what turn it into a pass/fail regression test.
        print(f"cogpin: {len(findings)} finding(s) over {diff_file} (no --expect assertions)")
        return 0
    # Validate the expectation ids BEFORE asserting — a typo or an un-evaluable check would
    # otherwise read as a silent pass/fail, the exact false-confidence fixtures exist to kill.
    ids = {c.id for c in cfg.checks}
    unknown = sorted({i for i in want_block + want_clean if i not in ids})
    if unknown:
        print(f"cogpin: --expect names check id(s) not in cogpin.toml: {', '.join(unknown)}",
              file=sys.stderr)
        return 2
    overlap = sorted(set(want_block) & set(want_clean))
    if overlap:
        print(f"cogpin: check id(s) in BOTH --expect-block and --expect-clean: "
              f"{', '.join(overlap)}", file=sys.stderr)
        return 2
    blind = sorted((set(want_block) | set(want_clean)) & _fixture_blind(cfg, facts))
    if blind:
        print(f"cogpin: --expect names check(s) this fixture can't evaluate (a diff alone can't "
              f"decide them): a `run` needs a checkout; max_added_file_bytes needs blob sizes; "
              f"an agent-layer or attest/judge check yields no change-layer finding; and message/"
              f"approval/checks/pr_body checks need --commit-msg / --reviews-file / --checks-file / "
              f"--pr-body-file: {', '.join(blind)}", file=sys.stderr)
        return 2
    blocked = {f.id for f in findings if f.severity == "block"}
    fired = {f.id for f in findings}
    failures = []
    for i in want_block:
        if i not in blocked:
            failures.append(f"expected BLOCK from `{i}` — "
                            + ("it fired as warn, not block" if i in fired else "it did not fire"))
    for i in want_clean:
        if i in fired:
            failures.append(f"expected `{i}` CLEAN — it fired ({'block' if i in blocked else 'warn'})")
    if failures:
        for msg in failures:
            print(f"  ✗ {msg}", file=sys.stderr)
        print(f"cogpin: fixture {diff_file}: {len(failures)} expectation(s) FAILED",
              file=sys.stderr)
        return 1
    print(f"cogpin: fixture {diff_file}: all {len(want_block) + len(want_clean)} "
          "expectation(s) met")
    return 0


def _config_advisories(cfg: Config) -> list[str]:
    """Non-fatal config-shape foot-guns: a valid config can still be a trap. Surfaced by
    `validate` (and never fail it) so the racy shape is caught at author time, not in a
    blocked PR."""
    out = []
    for c in cfg.checks:
        if c.primitive != "require_checks_green":
            continue
        if not c.need:
            # No allowlist (bare OR ignore-only) → it bare-iterates whatever checks the PR API
            # returns, so an EMPTY set (a removed/renamed check, an `ignore` covering them all, a
            # checks-fetch hiccup) passes vacuously. Only `need` names a check that MUST be
            # present-and-green, failing closed on a missing one. ONE coherent note per check:
            # `need` is the fix; `ignore` alone patches only the self-block and LEAVES this vacuum
            # (so we don't offer it as a clean remedy — that would loop the user back to this note).
            msg = (
                f"`{c.id}` (require_checks_green) has no `need`: an empty/shrunken check set "
                "passes vacuously (it can't detect a REMOVED or unreported required check). Name "
                'what must be green — `need = ["<job>"]` (the only fail-closed form) — or rely on '
                "branch-protection required contexts for removal-detection."
            )
            if not c.ignore:
                msg += (
                    " Bare additionally self-blocks if cogpin runs in the workflow it gates: "
                    "`need` the OTHER checks clears both that and the vacuum above; `ignore`-ing "
                    "the cogpin job alone fixes only the self-block (this note stays)."
                )
            out.append(msg)
    return out


def cmd_validate(path: str) -> int:
    try:
        with open(path, encoding="utf-8") as fh:
            cfg = Config.parse(fh.read())
    except FileNotFoundError:
        print(f"cogpin: config file not found: {path} (expected a .toml file)", file=sys.stderr)
        return 1
    except IsADirectoryError:
        print(f"cogpin: expected a file, not a directory: {path} (pass the path to a cogpin.toml)",
              file=sys.stderr)
        return 1
    except (OSError, ConfigError) as e:
        print(f"cogpin: invalid config: {e}", file=sys.stderr)
        return 1
    print(
        f"cogpin: {path} valid — {len(cfg.checks)} checks, base_pinned={cfg.meta.base_pinned}"
    )
    for note in _config_advisories(cfg):
        print(f"cogpin: note: {note}", file=sys.stderr)
    return 0


def cmd_init(path: str) -> int:
    if os.path.exists(path):
        print(f"cogpin: {path} already exists — leaving it untouched", file=sys.stderr)
        return 1
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(INIT_TEMPLATE)
    print(f"cogpin: wrote starter {path} — edit it, then wire the hooks (see README)")
    return 0


def _read_working_config(cwd: str) -> Config:
    # errors="replace" so a non-UTF-8 cogpin.toml surfaces as a ConfigError (bad TOML),
    # which callers already handle, rather than an uncaught UnicodeDecodeError that would
    # crash the gate hook (the gate must never block/traceback on a malformed config).
    with open(os.path.join(cwd, "cogpin.toml"), encoding="utf-8", errors="replace") as fh:
        return Config.parse(fh.read())


def cmd_suggest(cwd: str = ".", fmt: str = "json") -> int:
    """Extract repo facts → JSON (the contract the host agent consumes) or an all-warn
    starter draft. Writes NOTHING — the agent authors `cogpin.toml.draft`, never this."""
    scan = scan_repo(cwd)
    print(json.dumps(_scan_to_dict(scan), indent=2) if fmt == "json" else render_suggest_toml(scan))
    return 0


def cmd_gaps(cwd: str = ".", fmt: str = "text") -> int:
    """Advisory: which CLAUDE.md house-rules NO check binds (prose vs mechanism, on the
    repo it guards). Always exit 0 — it never gates."""
    try:
        cfg = _read_working_config(cwd)
    except (OSError, ConfigError):
        print("cogpin: no cogpin.toml — run /cogpin-init first")
        return 0
    scan = scan_repo(cwd)
    if not scan.house_rules:
        print("cogpin: no CLAUDE.md/AGENTS.md house-rules found")
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
    print(f"\ncogpin: {len(rows)} house-rule(s) · {nb} bound · {len(unbound)} unbound — advisory only")
    return 0


def cmd_draft_lint(cwd: str = ".", config: str = "cogpin.toml.draft", simulate: bool = False) -> int:
    """Strict-validate the agent-authored draft (superset of validate). Exit 0 iff
    structure is clean AND zero review markers remain; else 1."""
    try:
        # errors="replace" so a non-UTF-8 draft fails as a clean ConfigError (bad structure)
        # below, not an uncaught UnicodeDecodeError traceback.
        with open(os.path.join(cwd, config), encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        print(f"cogpin: no draft at {config} — run `cogpin suggest` / `/cogpin-init` first", file=sys.stderr)
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
        print(f"cogpin: draft not ready ({blocking} item(s) to resolve)", file=sys.stderr)
        return 1
    print("cogpin: draft OK — `mv cogpin.toml.draft cogpin.toml` to arm it")
    return 0


# ─────────────────────────────────────────────────────────────────────────────
# WIRING  —  install / uninstall / doctor  (the adoption surface)
# ─────────────────────────────────────────────────────────────────────────────
#
# The agent layer keeps `${CLAUDE_PLUGIN_ROOT}/cogpin.py` (the var exists only
# in-session). The CHANGE layer must run in CI / a teammate's pre-push / a fresh
# clone where that var is undefined and base-pinning needs the engine + config in
# git history — so `install` VENDORS the engine to `.cogpin/cogpin.py`
# (committed, base-pinnable, offline) and wires a sentinel-delimited managed block
# into the effective pre-push, coexisting with husky/lefthook/pre-commit/hooksPath.

COGPIN_BEGIN = "# >>> cogpin (managed block) >>>"
COGPIN_END = "# <<< cogpin <<<"

PREPUSH_BLOCK = f"""\
{COGPIN_BEGIN}
if [ -f .cogpin/cogpin.py ] && command -v python3 >/dev/null 2>&1; then
    python3 .cogpin/cogpin.py check --cwd . --allow-bypass < /dev/null || exit 1
fi
{COGPIN_END}
"""

CI_WORKFLOW = """\
name: cogpin
on:
  pull_request: {}
  push:
    branches: [main]
permissions:
  contents: read
  pull-requests: read
  checks: read
jobs:
  cogpin:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
        with:
          fetch-depth: 0
      - uses: IvanWng97/cogpin@v0
"""

LEFTHOOK_SNIPPET = """\
# lefthook detected — add to lefthook.yml, then `lefthook install`:
pre-push:
  commands:
    cogpin:
      run: python3 .cogpin/cogpin.py check --cwd .
"""

PRECOMMIT_SNIPPET = """\
# pre-commit detected — add to .pre-commit-config.yaml
# (default_install_hook_types: [pre-push]); then `pre-commit install`:
- repo: local
  hooks:
    - id: cogpin
      name: cogpin (Definition-of-Done)
      entry: python3 .cogpin/cogpin.py check --cwd .
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
    repo that ships `.cogpin/cogpin.py` as a symlink to `../../etc/…` must NOT make
    `install` clobber an arbitrary path on a victim's clone; the pre-push hook write
    deliberately omits `confine` because a stow-symlinked hook is intended."""
    real = os.path.realpath(path)
    if confine is not None and not _is_within(real, confine):
        raise OSError(f"refusing to write {path}: resolves outside the repo ({real})")
    d = os.path.dirname(real) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".cogpin-", suffix=".tmp")
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
    bi = cur.find(COGPIN_BEGIN)
    if bi == -1:
        if cur and not cur.endswith("\n"):
            cur += "\n"
        return cur + block
    ei = cur.find(COGPIN_END, bi)
    if ei == -1:  # malformed begin-without-end → replace to EOF
        return cur[:bi] + block
    nl = cur.find("\n", ei)
    tail = cur[nl + 1:] if nl != -1 else ""
    return cur[:bi] + block + tail


def _strip_block(cur: str) -> str:
    """Remove exactly the sentinel span (uninstall). No-op when absent."""
    bi = cur.find(COGPIN_BEGIN)
    if bi == -1:
        return cur
    ei = cur.find(COGPIN_END, bi)
    if ei == -1:
        return cur[:bi]
    nl = cur.find("\n", ei)
    tail = cur[nl + 1:] if nl != -1 else ""
    return cur[:bi] + tail


def _ensure_gitignore(root: str) -> None:
    """Scoped + idempotent: ignore `.cogpin/.state` (the debounce state) — NEVER the
    whole `.cogpin/` dir, which would un-commit the vendored engine."""
    p = os.path.join(root, ".gitignore")
    line = ".cogpin/.state"
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
    """Copy this running engine → `.cogpin/cogpin.py`. Returns the dest, or None when
    it would self-reference (running `install` FROM the already-vendored copy → never
    truncate the file we're executing)."""
    src = os.path.realpath(__file__)
    dst = os.path.join(root, ".cogpin", "cogpin.py")
    if os.path.realpath(dst) == src:
        return None
    _atomic_write(dst, _slurp(src), mode=0o644, confine=root)
    return dst


def _extract_engine_meta(src: str) -> tuple[set[str], int | None]:
    """STATICALLY read an engine source's known-primitive set + SCHEMA_VERSION, WITHOUT
    executing it (it may be a stale or foreign vendored copy — never import/exec untrusted
    or version-skewed code). AST only; degrades safe — a syntax error returns (set(), None)
    so callers flag "can't determine" rather than crash. Handles PRIMITIVE_SPECS written as
    an ANNOTATED dict (`PRIMITIVE_SPECS: dict[...] = {...}` → an ast.AnnAssign, NOT ast.Assign)
    and falls back to an old `PRIMITIVES = frozenset({...})` / bare-set literal."""
    try:
        tree = ast.parse(src)
    except (SyntaxError, ValueError):
        return set(), None

    def _targets(node: ast.AST) -> list[str]:
        if isinstance(node, ast.Assign):
            return [t.id for t in node.targets if isinstance(t, ast.Name)]
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            return [node.target.id]
        return []

    def _str_consts(elts: list[ast.expr]) -> set[str]:
        return {e.value for e in elts if isinstance(e, ast.Constant) and isinstance(e.value, str)}

    prims: set[str] = set()
    schema: int | None = None
    for node in tree.body:
        names = _targets(node)
        val = getattr(node, "value", None)
        if "PRIMITIVE_SPECS" in names and isinstance(val, ast.Dict):
            prims |= {k.value for k in val.keys
                      if isinstance(k, ast.Constant) and isinstance(k.value, str)}
        elif "PRIMITIVES" in names and not prims:
            # very old engines: a `frozenset({...})` call or a bare set/list literal
            if isinstance(val, ast.Call) and val.args and isinstance(val.args[0], (ast.Set, ast.List, ast.Tuple)):
                prims |= _str_consts(val.args[0].elts)
            elif isinstance(val, (ast.Set, ast.List, ast.Tuple)):
                prims |= _str_consts(val.elts)
        if "SCHEMA_VERSION" in names and isinstance(val, ast.Constant) and isinstance(val.value, int):
            schema = val.value
    return prims, schema


def _engine_skew(vendored_src: str, cfg_primitives: set[str], cfg_schema: int,
                 running_schema: int) -> list[tuple[str, str, str]]:
    """Compare a VENDORED engine source against the config it must serve + the running engine.
    PURE (cmd_doctor does the I/O and passes RAW config values, so detection works even when
    the running engine can't validate the config — the exact skew case). Returns (status,
    label, fix) rows. The VENDORED .cogpin/cogpin.py drives the CHANGE layer (the pre-push
    hook / CI); too old for its config, that layer fails CLOSED — it rejects a config it can't
    parse and over-blocks the push with a confusing "cannot load config" (#16). These rows name
    the real cause and point at `cogpin update`. (The agent-layer fail-OPEN half of #16 — the
    PLUGIN engine, not this vendored copy — is surfaced separately by cmd_stop's notice.)"""
    rows: list[tuple[str, str, str]] = []
    vend_prims, vend_schema = _extract_engine_meta(vendored_src)
    if not vend_prims:
        rows.append(("warn", "vendored engine: can't determine its primitive set (very old or unparseable copy)",
                     "run `cogpin update` to re-vendor the active engine"))
    else:
        unknown = sorted(p for p in cfg_primitives if p and p not in vend_prims)
        if unknown:
            rows.append(("fail", f"vendored engine is STALE — config uses {', '.join(unknown)} that "
                                 ".cogpin/cogpin.py doesn't know; the change-layer gate (pre-push/CI) "
                                 "will reject this config",
                         "run `cogpin update` to re-vendor the active engine"))
    if vend_schema is not None and cfg_schema and vend_schema != cfg_schema:
        rows.append(("fail", f"vendored engine schema v{vend_schema} ≠ config schema v{cfg_schema} "
                             "(the change layer will reject the config)", "run `cogpin update`"))
    elif vend_schema is not None and running_schema and vend_schema != running_schema:
        rows.append(("warn", f"vendored engine schema v{vend_schema} differs from the active engine "
                             f"v{running_schema}", "run `cogpin update` to align"))
    return rows


def cmd_update(cwd: str = ".") -> int:
    """Re-vendor the RUNNING engine → `.cogpin/cogpin.py` — the first-class update path for
    #16's stale-engine skew (no more "remember to re-run install"). Copies the running engine
    verbatim (no content injection), exactly like install; a vendored-engine diff is still
    gated by the change layer (protected_path + base-pin) on the PR, so this is not a
    self_protect bypass. Idempotent: a no-op + report when already current."""
    root = _repo_root(cwd)
    if root is None:
        print("cogpin: not a git repository — run `git init` first", file=sys.stderr)
        return 1
    dst = os.path.join(root, ".cogpin", "cogpin.py")
    running = os.path.realpath(__file__)
    if os.path.realpath(dst) == running:
        print("cogpin: cannot update from the vendored copy itself — run via the plugin engine "
              "(inside Claude Code, or `python3 <plugin>/cogpin.py update`)", file=sys.stderr)
        return 1
    new_src = _slurp(running)
    old_src = _slurp(dst) if os.path.exists(dst) else ""
    if old_src == new_src:
        print(f"cogpin: .cogpin/cogpin.py already current (schema v{SCHEMA_VERSION})")
        return 0
    _, old_schema = _extract_engine_meta(old_src) if old_src else (set(), None)
    if _vendor_engine(root) is None:   # self-reference already excluded above; defensive
        print("cogpin: could not re-vendor the engine", file=sys.stderr)
        return 1
    old_desc = (f"schema v{old_schema}" if old_schema is not None
                else ("absent" if not old_src else "unknown schema"))
    print(f"cogpin: re-vendored .cogpin/cogpin.py ({old_desc} → schema v{SCHEMA_VERSION})")
    return 0


def _exec_mode(real: str) -> int:
    """The mode for an (atomic re-)write of a hook file: PRESERVE an existing file's perms
    and only ensure +x — appending the managed block must not widen a husky / `.githooks`
    hook to 0o755. A brand-new hook cogpin authors is 0o755."""
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
    p = os.path.join(root, ".github", "workflows", "cogpin.yml")
    if os.path.exists(p):
        return None
    _atomic_write(p, CI_WORKFLOW.replace("branches: [main]", f"branches: [{branch}]"), mode=0o644, confine=root)
    return p


def _scaffold_config(branch: str) -> str:
    """The starter `cogpin.toml`, with the detected default branch substituted for the
    `main` default (so base-pinning + branch-first are correct on master/trunk repos)."""
    if branch == "main":
        return INIT_TEMPLATE
    return (INIT_TEMPLATE
            .replace('default_branch = "main"', f'default_branch = "{branch}"')
            .replace('branch = ["main"]', f'branch = ["{branch}"]'))


def _protects_gate_files(cfg: Config) -> bool:
    """True iff some protected_path/self_protect check's globs cover the engine, `cogpin.toml`,
    AND the CI workflow (doctor #8 — the engine-neuter defense). The engine is matched at the
    vendored `.cogpin/cogpin.py` OR a root `cogpin.py` (cogpin's own repo)."""
    for c in cfg.checks:
        if c.primitive not in ("protected_path", "self_protect") or not c.paths:
            continue
        covers_engine = _path_matches(".cogpin/cogpin.py", c.paths) or _path_matches("cogpin.py", c.paths)
        covers_config = _path_matches("cogpin.toml", c.paths)
        covers_ci = _path_matches(".github/workflows/cogpin.yml", c.paths)
        if covers_engine and covers_config and covers_ci:
            return True
    return False


def _str_list(v: object) -> list[str]:
    """The str-only members of v if v is a list, else []. Guards against a settings.json (or
    sidecar) whose `deny`/`allow` is a bare string — iterating that would shatter it into
    characters and pollute the reconciled set."""
    return [e for e in v if isinstance(e, str)] if isinstance(v, list) else []


def _emit_claude_code(cap: Capability) -> tuple[list[str], list[str], list[str]]:
    """Render a declared Capability floor to (deny, allow, warnings) for Claude Code
    settings.json permissions. PURE — no I/O. `warnings` flag the postures settings.json
    cannot actually GUARANTEE (egress, fs confinement) so emit never oversells: cogpin
    declares the intent, the OS/harness is the boundary (see docs/composition.md)."""
    deny: list[str] = []
    allow: list[str] = []
    warns: list[str] = []
    for p in cap.deny_paths:
        deny += [f"Read({p})", f"Edit({p})", f"Write({p})"]
    for v in cap.deny_commands:
        deny.append(f"Bash({v}:*)")
    if cap.no_network:
        deny += ["WebFetch", "WebSearch", "Bash(curl:*)", "Bash(wget:*)", "Bash(nc:*)"]
        warns.append("no_network: settings.json denies the common egress verbs but CANNOT "
                     "guarantee no network — real egress control is an OS/harness sandbox concern")
    for v in cap.allow_commands:
        allow.append(f"Bash({v}:*)")
    if cap.allow_commands:
        warns.append("allow_commands: for a TRUE allowlist set permissions.defaultMode to 'ask' "
                     "or 'deny' in settings.json yourself — cogpin only adds the allow entries")
    if cap.fs_confine:
        warns.append(f"fs_confine {cap.fs_confine}: settings.json cannot confine the filesystem "
                     "to a root — the declaration is recorded, but real confinement is an OS concern")
    return list(dict.fromkeys(deny)), list(dict.fromkeys(allow)), warns


def cmd_capability_emit(cwd: str = ".", backend: str | None = None, dry_run: bool = False) -> int:
    """Compile the declared `[capability]` floor to the harness's native enforcement file.
    GENERATE, never contain: cogpin writes the policy the harness will enforce and exits —
    it is never in the syscall path. Idempotent + non-clobbering: it manages only the entries
    it itself emitted (recorded in `.cogpin/capability-emitted.json`), never user-authored ones."""
    root = _repo_root(cwd) or cwd
    try:
        cfg = _read_working_config(root)
    except (OSError, ConfigError) as e:
        print(f"cogpin: cannot read [capability] from cogpin.toml: {e}", file=sys.stderr)
        return 1
    cap = cfg.capability
    target = backend or cap.backend
    if target != "claude-code":
        print(f"cogpin: [capability] declared for backend `{target}` — cogpin does not emit for "
              f"it; wire your sandbox manually (cogpin declares the floor, the OS enforces)",
              file=sys.stderr)
        return 0
    # _emit_claude_code returns ([],[],[]) for an empty floor — reconcile still runs so that
    # EMPTYING the stanza RETRACTS what was emitted before; the per-key removal contract must
    # hold for the all-empty transition, not just one key dropped from a non-empty stanza.
    deny, allow, warns = _emit_claude_code(cap)
    settings_path = os.path.join(root, ".claude", "settings.json")
    sidecar_path = os.path.join(root, ".cogpin", "capability-emitted.json")
    raw = _read_json(settings_path)
    # FAIL CLOSED on a present-but-unusable settings.json: _read_json maps both "absent" and
    # "garbled" to None, and a valid-but-non-object (a JSON array/string) parses to a non-dict —
    # either way, proceeding would replace the user's file with a cogpin-only document and
    # silently destroy their keys. Only an ABSENT file is a clean slate to write.
    if os.path.exists(settings_path) and not isinstance(raw, dict):
        print(f"cogpin: refusing to emit — {settings_path} exists but isn't a JSON object "
              f"(fix or remove it first); not overwriting it", file=sys.stderr)
        return 1
    settings = raw if isinstance(raw, dict) else {}
    prior = _read_json(sidecar_path)
    prior = prior if isinstance(prior, dict) else {}
    prior_deny, prior_allow = _str_list(prior.get("deny")), _str_list(prior.get("allow"))
    # Warnings describe the DECLARED floor (postures settings.json can't truly guarantee — e.g.
    # fs_confine, no_network egress). Surface them on every path that got this far, INCLUDING the
    # declared-but-nothing-to-render case below, so a non-enforceable declaration is never silently
    # swallowed (fs_confine renders no deny/allow entries, only a warning).
    for w in warns:
        print(f"cogpin: warning — {w}", file=sys.stderr)
    if not deny and not allow and not prior_deny and not prior_allow:
        # nothing emitted before AND nothing to render now. Distinguish a truly empty stanza from
        # one that IS declared but renders no settings.json entries (e.g. fs_confine only), so the
        # user isn't told their floor doesn't exist.
        msg = ("no [capability] floor declared" if cap.is_empty()
               else "[capability] declared but nothing is enforceable via settings.json (see warnings)")
        print(f"cogpin: {msg} — nothing to emit", file=sys.stderr)
        return 0
    perms = settings.get("permissions")
    perms = perms if isinstance(perms, dict) else {}
    cur_deny, cur_allow = _str_list(perms.get("deny")), _str_list(perms.get("allow"))
    # Drop ONLY the entries cogpin emitted last time (preserve user-authored ones), then append
    # the freshly-rendered managed set deduped → idempotent (same stanza ⇒ byte-identical) and
    # non-clobbering. deny AND allow are reconciled symmetrically: a key emptied (or the whole
    # stanza removed) deletes its managed entries; a now-empty list deletes the key entirely so
    # the rendered output never carries a vestigial `"allow": []` / `"deny": []` / `permissions`.
    user_deny = [e for e in cur_deny if e not in prior_deny]
    user_allow = [e for e in cur_allow if e not in prior_allow]
    # The sidecar is cogpin's OWNERSHIP ledger — record only entries cogpin actually added
    # (managed MINUS any that already existed as user-authored), NOT the full render. Otherwise a
    # user-authored entry that string-collides with a managed one (e.g. a hand-written
    # `Bash(curl:*)` deny alongside `no_network`) gets claimed as managed → silently deleted on a
    # later retract, and the array reorders between identical emits (non-idempotent).
    owned_deny = [e for e in deny if e not in user_deny]
    owned_allow = [e for e in allow if e not in user_allow]
    final = {"deny": user_deny + owned_deny, "allow": user_allow + owned_allow}
    for k, v in final.items():
        if v:
            perms[k] = v
        elif k in perms:
            del perms[k]
    if perms:
        settings["permissions"] = perms
    elif "permissions" in settings:
        del settings["permissions"]
    rendered = json.dumps(settings, indent=2) + "\n"
    if dry_run:
        print(rendered, end="")
        return 0
    _atomic_write(settings_path, rendered, confine=root)
    _atomic_write(sidecar_path, json.dumps({"deny": owned_deny, "allow": owned_allow}, indent=2) + "\n", confine=root)
    if deny or allow:
        print(f"cogpin: emitted {len(deny)} deny + {len(allow)} allow entries to "
              f".claude/settings.json (backend: claude-code) — the harness enforces, not cogpin")
    else:
        print("cogpin: retracted all cogpin-managed capability entries from .claude/settings.json")
    return 0


def cmd_install(cwd: str = ".", vendor: bool = True, config: bool = True,
                hook: bool = True, ci: bool = True, gitignore: bool = True) -> int:
    """Idempotent, non-clobbering wiring of the change layer. No flags ⇒ do all five.
    Touches only plumbing (vendor / scaffold / hook / CI / gitignore) — never authors a
    check's severity/kind, so the block-requires-fact moat is untouched."""
    root = _repo_root(cwd)
    if root is None:
        print("cogpin: not a git repository — run `git init` first", file=sys.stderr)
        return 1
    branch = _detect_default_branch(cwd)
    did: list[str] = []
    if vendor:
        dst = _vendor_engine(root)
        did.append("vendored .cogpin/cogpin.py" if dst else "engine already vendored (self) — skipped")
    if config:
        cfg_path = os.path.join(root, "cogpin.toml")
        if os.path.exists(cfg_path):
            did.append("cogpin.toml exists — left untouched")
        else:
            _atomic_write(cfg_path, _scaffold_config(branch), confine=root)
            did.append(f"wrote starter cogpin.toml (default_branch={branch})")
    if gitignore:
        _ensure_gitignore(root)
        did.append("ensured .gitignore covers .cogpin/.state")
    if hook:
        action, payload = _effective_hook_target(cwd, root)
        if action == "write":
            _install_prepush(payload)
            _mgr = _detect_hook_manager(root)  # in the write branch this is "husky" or None
            _how = (f"via {_mgr} → {os.path.realpath(payload)}" if _mgr
                    else f"directly → {os.path.realpath(payload)} (no hook manager detected)")
            did.append(f"wired pre-push managed block {_how}")
        elif action.startswith("snippet:"):
            did.append(f"{action.split(':', 1)[1]} detected — wrote nothing; add this snippet:\n\n{payload}")
        else:
            did.append(f"pre-push skipped — {payload}")
    if ci:
        did.append("scaffolded .github/workflows/cogpin.yml" if _write_ci(root, branch)
                   else ".github/workflows/cogpin.yml exists — left untouched")
    print("cogpin install:")
    for d in did:
        print(f"  • {d}")
    if vendor or config or ci:
        print("\nnext: `git add .cogpin/cogpin.py cogpin.toml .github/workflows/cogpin.yml` "
              "& commit, then `cogpin doctor`")
    return 0


def cmd_uninstall(cwd: str = ".") -> int:
    """Conservative: strip ONLY the local pre-push managed block. Never `git rm`
    committed source (engine / config / workflow) — that is an explicit reviewable change."""
    root = _repo_root(cwd)
    if root is None:
        print("cogpin: not a git repository", file=sys.stderr)
        return 1
    action, payload = _effective_hook_target(cwd, root)
    if action != "write":
        msg = (f"hooks managed by {action.split(':', 1)[1]} — remove the cogpin snippet by hand"
               if action.startswith("snippet:") else payload)
        print(f"cogpin uninstall: {msg}")
        return 0
    real = os.path.realpath(payload)
    cur = _slurp(real)
    if not os.path.exists(real) or COGPIN_BEGIN not in cur:
        print("cogpin uninstall: no managed block in the pre-push — nothing to strip")
        return 0
    stripped = _strip_block(cur)
    if stripped.strip() in ("", "#!/bin/sh"):  # only our shebang remains → we authored it
        os.remove(real)
        print(f"cogpin uninstall: removed the cogpin-authored pre-push hook ({real})")
    else:
        _atomic_write(payload, stripped, mode=_exec_mode(real))
        print(f"cogpin uninstall: stripped the managed block, kept the rest ({real})")
    print("note: committed .cogpin/cogpin.py, cogpin.toml and the CI workflow are NOT removed "
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
    engine_compiles = False
    eng = os.path.join(base_dir, ".cogpin", "cogpin.py")
    if os.path.exists(eng):
        try:
            compile(_slurp(eng), eng, "exec")  # syntax-check; writes no __pycache__
            add("ok", ".cogpin/cogpin.py present and compiles")
            engine_compiles = True
        except SyntaxError as e:
            add("fail", ".cogpin/cogpin.py does not compile", str(e).splitlines()[0])
            hard_fail = True
    else:
        add("fail", ".cogpin/cogpin.py missing", "run `cogpin install` (or /cogpin-init) to vendor the engine")
        hard_fail = True

    cfg: Config | None = None
    cfg_path = os.path.join(base_dir, "cogpin.toml")
    if os.path.exists(cfg_path):
        try:
            cfg = Config.parse(_slurp(cfg_path))
            add("ok", f"cogpin.toml valid — {len(cfg.checks)} checks, base_pinned={cfg.meta.base_pinned}")
        except (OSError, ConfigError) as e:
            add("fail", "cogpin.toml invalid", str(e))
            # an unknown-primitive / unsupported-schema ConfigError from the RUNNING engine is
            # the stale-engine signature, not a bad config — name the real cause + remedy (#16).
            if any(s in str(e) for s in ("unknown primitive", "unsupported schema")):
                add("warn", "↳ the running engine may be stale relative to this config",
                    "reinstall the plugin, or run `cogpin update` to re-vendor the engine")
            hard_fail = True
    else:
        add("fail", "cogpin.toml missing", "run `cogpin install` / `/cogpin-init`")
        hard_fail = True

    # engine/config SKEW (#16): the vendored engine drives the CHANGE layer (pre-push/CI); too
    # old for the config (unknown primitive / schema mismatch) it fails CLOSED — rejecting a
    # config it can't parse and over-blocking with a confusing "cannot load config". Derive the
    # config's primitives + schema from a RAW parse — independent of the running engine's
    # validate(), which is exactly what breaks in the skew case — then compare against the
    # VENDORED engine's static metadata.
    if engine_compiles and os.path.exists(cfg_path):
        try:
            raw = tomllib.loads(_slurp(cfg_path))
        except (OSError, ValueError):
            raw = {}
        raw_checks = raw.get("check", [])
        cfg_prims: set[str] = {p for c in raw_checks if isinstance(c, dict)
                               if isinstance(p := c.get("primitive"), str)}
        raw_schema = raw.get("schema", 0)
        cfg_schema = raw_schema if isinstance(raw_schema, int) else 0
        for s, lbl, fx in _engine_skew(_slurp(eng), cfg_prims, cfg_schema, SCHEMA_VERSION):
            add(s, lbl, fx)
            if s == "fail":
                hard_fail = True

    if root:
        action, payload = _effective_hook_target(cwd, root)
        if action == "write":
            real = os.path.realpath(payload)
            if os.path.exists(real) and COGPIN_BEGIN in _slurp(real):
                add("ok", f"pre-push managed block present ({real})")
            else:
                add("warn", "pre-push managed block absent", "run `cogpin install` (CI is the authoritative gate)")
        elif action.startswith("snippet:"):
            add("warn", f"hooks managed by {action.split(':', 1)[1]} — snippet expected (not auto-written)",
                "add the cogpin snippet from `cogpin install`")
        else:
            add("warn", f"pre-push not wired — {payload}", "rely on CI")

    wf = os.path.join(base_dir, ".github", "workflows", "cogpin.yml")
    if os.path.exists(wf) and "cogpin" in _slurp(wf):
        add("ok", ".github/workflows/cogpin.yml references cogpin")
    else:
        add("warn", "CI workflow absent", "run `cogpin install` to scaffold .github/workflows/cogpin.yml")

    default_branch = cfg.repo.default_branch if cfg else _detect_default_branch(cwd)
    base = _resolve_base(cwd, default_branch)
    if base:
        add("ok", f"base ref reachable ({base})")
    else:
        add("warn", "base ref unreachable", "shallow clone? set `fetch-depth: 0` — base-pinning degrades")

    if base and cfg and cfg.meta.base_pinned:
        bc = _git(cwd, ["show", f"{base}:cogpin.toml"])
        add("ok" if bc else "warn",
            "base-pinned config readable" if bc else "base-pinned config not yet in the base ref (first commit?)")
    else:
        add("skip", "base-pinning off or no base ref")

    if cfg:
        covered = _protects_gate_files(cfg)
        add("ok" if covered else "warn",
            "gate files covered by protected_path/self_protect" if covered else "gate files not self-protected",
            "" if covered else "add a protected_path covering .cogpin/** + cogpin.toml + .github/workflows/** "
                               "(the action's rev-pinned engine already covers GitHub CI)")

    if os.environ.get("CLAUDE_PLUGIN_ROOT"):
        add("ok", "agent layer: CLAUDE_PLUGIN_ROOT set (plugin active in-session)")
    else:
        add("skip", "agent layer: run /cogpin-doctor inside Claude Code to verify the plugin")

    if as_json:
        print(json.dumps([{"status": s, "label": lbl, "fix": fx} for s, lbl, fx in rows], indent=2))
    else:
        glyph = {"ok": "✓", "warn": "~", "fail": "✗", "skip": "·"}
        print("  legend: ✓ ok   ~ advisory (non-blocking)   ✗ must fix   · skipped")
        for s, lbl, fx in rows:
            print(f"  {glyph[s]} {lbl}")
            if fx and s in ("warn", "fail"):
                print(f"      → {fx}")
        print()
        if hard_fail:
            print("cogpin doctor: change layer NOT ready (fix the ✗ above)", file=sys.stderr)
        else:
            print("cogpin doctor: change layer ready")
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
        prog="cogpin",
        description="Ungameable diff-fact enforcement of the closing-discipline.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("gate", help="agent layer: PreToolUse hook (deny forbidden / un-DoD'd git ops)")
    st = sub.add_parser("stop", help="agent layer: Stop hook (block turn-end on unmet DoD)")
    st.add_argument("--cwd", default=".")
    c = sub.add_parser("check", help="change layer: gate the committed range (authoritative)",
                        epilog="exit codes: 0 = ok (or --report-only) · 1 = a blocking finding or a config/infra error · 2 = could not evaluate (an unreadable --*-file input)")
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
    c.add_argument("--default-branch", help="trusted base branch name (CI passes the repo's real default; overrides cogpin.toml so the base can't be redirected from the PR head)")
    c.add_argument("--allow-bypass", action="store_true", help="honour the agent-layer bypass (pre-push only)")
    c.add_argument("--report-only", action="store_true", help="print findings + a summary but always exit 0 (global rollout switch; infra/config errors still fail)")
    c.add_argument("--diff-file", help="evaluate a crafted unified-diff FIXTURE instead of the git range (config-as-code testing; uses the working cogpin.toml, never `run`)")
    c.add_argument("--expect-block", help="comma-separated check ids that MUST block on the fixture — exit 1 if any doesn't (requires --diff-file)")
    c.add_argument("--expect-clean", help="comma-separated check ids that MUST NOT fire on the fixture — exit 1 if any does (requires --diff-file)")
    c.add_argument("--commit-msg", help="synthetic commit message for the fixture (makes commit_footer / commit-scoped message checks evaluable; a diff carries none)")
    bt = sub.add_parser("backtest", help="replay the policy over merged history: which past commits would block? (calibration)")
    bt.add_argument("--cwd", default=".")
    bt.add_argument("--range", required=True, dest="rng", metavar="REV-RANGE", help="git rev-range, e.g. main~50..main")
    bt.add_argument("--config", default=None, help="config to backtest (default: the working cogpin.toml; e.g. cogpin.toml.draft)")
    bt.add_argument("--fail-on-block", action="store_true", help="exit 1 if any commit would block (default: pure report, exit 0)")
    j = sub.add_parser("judge", help="emit the advisory LLM-judge prompt(s) to stdout (CI)")
    j.add_argument("--cwd", default=".")
    v = sub.add_parser("validate", help="parse + validate cogpin.toml (the block-requires-fact invariant)")
    v.add_argument("--config", default="cogpin.toml")
    i = sub.add_parser("init", help="write a starter cogpin.toml")
    i.add_argument("--config", default="cogpin.toml")
    sg = sub.add_parser("suggest", help="extract repo facts → a ranked draft policy (for /cogpin-init; never writes)")
    sg.add_argument("--cwd", default=".")
    sg.add_argument("--format", choices=["json", "toml"], default="json")
    dl = sub.add_parser("draft-lint", help="strict-validate a drafted policy (superset of validate; gates on TODO markers)")
    dl.add_argument("--cwd", default=".")
    dl.add_argument("--config", default="cogpin.toml.draft")
    dl.add_argument("--simulate", action="store_true", help="also flag any block that would fire on existing HEAD code")
    gp = sub.add_parser("gaps", help="advisory: which CLAUDE.md house-rules are NOT bound by a cogpin check")
    gp.add_argument("--cwd", default=".")
    gp.add_argument("--format", choices=["text", "json"], default="text")
    ins = sub.add_parser("install", help="wire the change layer: vendor engine + scaffold config/hook/CI (idempotent)")
    ins.add_argument("--cwd", default=".")
    ins.add_argument("--no-vendor", action="store_true", help="skip vendoring .cogpin/cogpin.py")
    ins.add_argument("--no-config", action="store_true", help="skip writing a starter cogpin.toml")
    ins.add_argument("--no-hook", action="store_true", help="skip wiring the pre-push hook")
    ins.add_argument("--no-ci", action="store_true", help="skip scaffolding the CI workflow")
    ins.add_argument("--no-gitignore", action="store_true", help="skip the .gitignore entry")
    un = sub.add_parser("uninstall", help="strip the local pre-push managed block (never removes committed source)")
    un.add_argument("--cwd", default=".")
    up = sub.add_parser("update", help="re-vendor the active engine → .cogpin/cogpin.py (fix a stale-engine skew)")
    up.add_argument("--cwd", default=".")
    dr = sub.add_parser("doctor", help="diagnose both layers (read-only; exit 1 only on a hard change-layer failure)")
    dr.add_argument("--cwd", default=".")
    dr.add_argument("--json", action="store_true", help="emit the per-check status array")
    cap = sub.add_parser("capability", help="compile the declared [capability] floor to the harness (declare → emit; the OS enforces)")
    capsub = cap.add_subparsers(dest="capcmd", required=True)
    cape = capsub.add_parser("emit", help="render [capability] to the harness's native enforcement (.claude/settings.json)")
    cape.add_argument("--cwd", default=".")
    cape.add_argument("--backend", default=None, help="override [capability].backend (default: claude-code)")
    cape.add_argument("--dry-run", action="store_true", help="print the merged settings.json without writing")
    sub.add_parser("selftest", help="run the in-process self-test")

    args = p.parse_args(argv)
    if args.cmd == "gate":
        return cmd_gate()
    if args.cmd == "stop":
        return cmd_stop(args.cwd)
    if args.cmd == "check":
        if args.diff_file or args.expect_block or args.expect_clean:
            # fixture mode (#18): a crafted diff + per-check expectations, NOT the git range.
            return cmd_fixture(
                args.cwd,
                args.diff_file,
                expect_block=args.expect_block,
                expect_clean=args.expect_clean,
                pr_body_file=args.pr_body_file,
                approvals=args.approvals,
                reviews_file=args.reviews_file,
                head_sha=args.head_sha,
                pr_author=args.pr_author,
                checks_file=args.checks_file,
                commit_msg=args.commit_msg,
            )
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
            report_only=args.report_only,
        )
    if args.cmd == "backtest":
        return cmd_backtest(args.cwd, args.rng, config=args.config, fail_on_block=args.fail_on_block)
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
    if args.cmd == "update":
        return cmd_update(args.cwd)
    if args.cmd == "doctor":
        return cmd_doctor(args.cwd, as_json=args.json)
    if args.cmd == "capability":
        return cmd_capability_emit(args.cwd, backend=args.backend, dry_run=args.dry_run)
    if args.cmd == "selftest":
        print("cogpin selftest: ok (run `python3 -m pytest` / `tests/test_cogpin.py` for the full suite)")
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
