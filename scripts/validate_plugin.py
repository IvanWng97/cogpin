#!/usr/bin/env python3
"""Validate the Claude Code plugin packaging — the structure `/plugin install` reads.

Stdlib only (same ethos as the engine). Checks the three JSON manifests parse and carry
their required keys, that referenced files exist, that the skill/command frontmatter is
well-formed, and that the version is consistent across plugin.json ↔ marketplace.json.
Exit 1 on the first class of problems, with every finding printed."""

from __future__ import annotations

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load(rel: str) -> tuple[dict | None, list[str]]:
    path = os.path.join(ROOT, rel)
    if not os.path.exists(path):
        return None, [f"{rel}: missing"]
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh), []
    except (OSError, json.JSONDecodeError) as e:
        return None, [f"{rel}: invalid JSON — {e}"]


def _frontmatter(rel: str) -> tuple[dict, list[str]]:
    """Parse the leading `--- … ---` YAML-ish block as flat `key: value` pairs (no
    external YAML dep — the frontmatter we ship is intentionally flat)."""
    path = os.path.join(ROOT, rel)
    if not os.path.exists(path):
        return {}, [f"{rel}: missing"]
    with open(path, encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    if not lines or lines[0].strip() != "---":
        return {}, [f"{rel}: no `---` frontmatter block"]
    out: dict[str, str] = {}
    for line in lines[1:]:
        if line.strip() == "---":
            return out, []
        if ":" in line:
            k, _, v = line.partition(":")
            out[k.strip()] = v.strip()
    return out, [f"{rel}: frontmatter block not closed with `---`"]


def main() -> int:
    errors: list[str] = []

    plugin, e = _load(".claude-plugin/plugin.json")
    errors += e
    market, e = _load(".claude-plugin/marketplace.json")
    errors += e
    hooks, e = _load("hooks/hooks.json")
    errors += e

    if plugin is not None:
        for key in ("name", "version", "description", "hooks"):
            if not plugin.get(key):
                errors.append(f"plugin.json: missing `{key}`")
        ref = (plugin.get("hooks") or "").lstrip("./")
        if ref and not os.path.exists(os.path.join(ROOT, ref)):
            errors.append(f"plugin.json: hooks `{plugin['hooks']}` does not resolve")

    if market is not None:
        if not market.get("name"):
            errors.append("marketplace.json: missing `name`")
        plugins = market.get("plugins")
        if not isinstance(plugins, list) or not plugins:
            errors.append("marketplace.json: `plugins` must be a non-empty list")

    # version must agree across the two manifests (a drift ships a wrong store version)
    if plugin and market:
        pv = plugin.get("version")
        mv = (market.get("metadata") or {}).get("version")
        if pv and mv and pv != mv:
            errors.append(f"version drift: plugin.json {pv} != marketplace.json {mv}")

    if hooks is not None:
        h = hooks.get("hooks")
        if not isinstance(h, dict) or not h:
            errors.append("hooks.json: missing `hooks` object")
        else:
            blob = json.dumps(h)
            if "ratchet.py" not in blob:
                errors.append("hooks.json: no hook invokes ratchet.py")

    # the skill + commands carry name/description frontmatter the loader needs
    fm, e = _frontmatter("skills/ratchet/SKILL.md")
    errors += e
    for key in ("name", "description"):
        if not fm.get(key):
            errors.append(f"SKILL.md: frontmatter missing `{key}`")

    cmd_dir = os.path.join(ROOT, "commands")
    if os.path.isdir(cmd_dir):
        for fn in sorted(os.listdir(cmd_dir)):
            if not fn.endswith(".md"):
                continue
            cfm, ce = _frontmatter(f"commands/{fn}")
            errors += ce
            if not cfm.get("description"):
                errors.append(f"commands/{fn}: frontmatter missing `description`")

    # the composite action is the change-layer distribution surface (`uses: owner/repo@v0`);
    # actionlint validates the YAML in CI — here we only assert it exists, is composite, and
    # runs the engine (stdlib has no YAML parser, so this is a deliberate text-level check).
    action_path = os.path.join(ROOT, "action.yml")
    if not os.path.exists(action_path):
        errors.append("action.yml: missing (the composite action consumers `uses:`)")
    else:
        with open(action_path, encoding="utf-8") as fh:
            blob = fh.read()
        if "using: composite" not in blob:
            errors.append("action.yml: not a composite action (`using: composite`)")
        if "ratchet.py" not in blob:
            errors.append("action.yml: never invokes ratchet.py")

    if errors:
        print("plugin validation FAILED:")
        for err in errors:
            print(f"  ✗ {err}")
        return 1
    print("plugin validation: ok (manifests, hooks ref, version parity, skill/command frontmatter, action.yml)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
