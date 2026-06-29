#!/usr/bin/env python3
"""Generate the primitive-library tables from the canonical registry.

The single source of truth is the ```toml block in ``docs/primitives.md``. This script
renders two views of it — README's verbose table (param signatures + full ``long`` prose)
and the tutorial site's condensed table (bare name + ``short`` prose) — into the
marker-delimited regions in each file, and substitutes the derived primitive count into the
count tokens. The two surfaces therefore can never disagree on the count, the membership, or
a primitive's kind.

    python3 scripts/gen_primitives.py            # write the generated regions
    python3 scripts/gen_primitives.py --check    # verify they are current (CI drift-guard)

Stdlib only (tomllib, 3.11+): cogpin ships on bare Python — the plugin hook, the vendored
pre-push engine, and the Pyodide playground all run without a pip step — so its tooling
takes no dependency either.
"""

from __future__ import annotations

import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REGISTRY = ROOT / "docs" / "primitives.md"

_TOML_FENCE = re.compile(r"```toml\n(.*?)\n```", re.DOTALL)


@dataclass(frozen=True)
class Target:
    path: Path
    params: bool  # render `id{a,b}` (verbose) or bare `id` (condensed)
    desc: str  # registry field for the "decides over" cell: "long" | "short"
    table_start: str
    table_end: str
    count_open: str
    count_close: str


_HTML = dict(
    table_start=(
        "<!-- gen:primitives:table — generated from docs/primitives.md "
        "(run scripts/gen_primitives.py); edit the registry, not here -->"
    ),
    table_end="<!-- /gen:primitives:table -->",
    count_open="<!-- gen:count -->",
    count_close="<!-- /gen:count -->",
)
_MDX = dict(
    table_start=(
        "{/* gen:primitives:table — generated from docs/primitives.md "
        "(run scripts/gen_primitives.py); edit the registry, not here */}"
    ),
    table_end="{/* /gen:primitives:table */}",
    count_open="{/* gen:count */}",
    count_close="{/* /gen:count */}",
)

TARGETS = [
    Target(ROOT / "README.md", params=True, desc="long", **_HTML),
    Target(
        ROOT / "site" / "src" / "content" / "docs" / "what-it-catches.mdx",
        params=False,
        desc="short",
        **_MDX,
    ),
]


def load_registry(path: Path = REGISTRY) -> list[dict]:
    text = path.read_text(encoding="utf-8")
    # pick the ```toml block that holds the registry, not the first one — so a future
    # TOML *example* added above it can't silently shadow the data.
    prims: list[dict] = []
    for block in _TOML_FENCE.findall(text):
        try:
            parsed = tomllib.loads(block)
        except tomllib.TOMLDecodeError:
            continue
        if parsed.get("primitive"):
            prims = parsed["primitive"]
            break
    if not prims:
        raise SystemExit(f"gen_primitives: no ```toml block with [[primitive]] entries in {path}")
    ids = [p["id"] for p in prims]
    if len(ids) != len(set(ids)):
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        raise SystemExit(f"gen_primitives: duplicate id(s) in registry: {dupes}")
    return prims


def _name_cell(p: dict, *, params: bool) -> str:
    if params:
        return f"`{p['id']}{{{','.join(p.get('params', []))}}}`"
    return f"`{p['id']}`"


def render_table(prims: list[dict], *, params: bool, desc: str) -> str:
    lines = ["| primitive | kind | decides over |", "|---|---|---|"]
    for p in prims:
        lines.append(f"| {_name_cell(p, params=params)} | {p['kind']} | {p[desc]} |")
    return "\n".join(lines)


def _sub_region(text: str, start: str, end: str, body: str, path: Path) -> str:
    pat = re.compile(re.escape(start) + r".*?" + re.escape(end), re.DOTALL)
    if not pat.search(text):
        raise SystemExit(f"gen_primitives: marker {start!r} not found in {path}")
    # function replacement → the body's backslashes/backticks stay literal (no group refs)
    return pat.sub(lambda _: f"{start}\n\n{body}\n\n{end}", text)


def _sub_count(text: str, open_tok: str, close_tok: str, count: int) -> str:
    pat = re.compile(re.escape(open_tok) + r"\d+" + re.escape(close_tok))
    return pat.sub(f"{open_tok}{count}{close_tok}", text)


def render_target(text: str, tgt: Target, prims: list[dict]) -> str:
    body = render_table(prims, params=tgt.params, desc=tgt.desc)
    text = _sub_region(text, tgt.table_start, tgt.table_end, body, tgt.path)
    return _sub_count(text, tgt.count_open, tgt.count_close, len(prims))


def main(argv: list[str]) -> int:
    check = "--check" in argv
    prims = load_registry()
    stale: list[Path] = []
    for tgt in TARGETS:
        current = tgt.path.read_text(encoding="utf-8")
        updated = render_target(current, tgt, prims)
        if updated == current:
            continue
        if check:
            stale.append(tgt.path)
        else:
            tgt.path.write_text(updated, encoding="utf-8")
            print(f"gen_primitives: wrote {tgt.path.relative_to(ROOT)}")
    if check:
        if stale:
            print("gen_primitives: OUT OF DATE — run `python3 scripts/gen_primitives.py`:")
            for p in stale:
                print(f"  - {p.relative_to(ROOT)}")
            return 1
        print(f"gen_primitives: OK — {len(prims)} primitives, all generated regions current")
    else:
        print(f"gen_primitives: {len(prims)} primitives rendered into {len(TARGETS)} target(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
