"""Anti-drift tests for the primitive registry and its generated tables.

These tie the docs to the engine and to the registry so a stale surface fails the suite
(the suite is the authoritative gate; the `--check` CLI mode mirrors this for CI ergonomics).
"""

import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
sys.path.insert(0, os.path.join(_ROOT, "scripts"))

import gen_primitives as G  # noqa: E402

import cogpin  # noqa: E402


class TestPrimitiveRegistry(unittest.TestCase):
    def setUp(self):
        self.prims = G.load_registry()
        self.ids = [p["id"] for p in self.prims]

    def test_registry_ids_equal_engine_primitives(self):
        # the load-bearing lock: docs cannot claim a primitive the engine doesn't ship,
        # nor omit one it does — this is the "23 vs 26" drift class, made impossible.
        self.assertEqual(set(self.ids), set(cogpin.PRIMITIVES))

    def test_registry_ids_unique(self):
        self.assertEqual(len(self.ids), len(set(self.ids)))

    def test_every_entry_has_required_prose(self):
        for p in self.prims:
            for field in ("id", "kind", "short", "long"):
                self.assertIn(field, p, f"{p.get('id')!r} missing {field}")
                self.assertTrue(str(p[field]).strip(), f"{p.get('id')!r} has empty {field}")
            self.assertIsInstance(p.get("params", []), list)

    def test_generated_regions_are_current(self):
        # the committed README + site tables must equal a fresh render of the registry
        stale = []
        for tgt in G.TARGETS:
            current = tgt.path.read_text(encoding="utf-8")
            if G.render_target(current, tgt, self.prims) != current:
                stale.append(str(tgt.path.relative_to(G.ROOT)))
        self.assertEqual(stale, [], f"stale — run `python3 scripts/gen_primitives.py`: {stale}")

    def test_count_tokens_match_primitive_count(self):
        n = len(self.prims)
        for tgt in G.TARGETS:
            text = tgt.path.read_text(encoding="utf-8")
            pat = re.escape(tgt.count_open) + r"(\d+)" + re.escape(tgt.count_close)
            found = [int(m) for m in re.findall(pat, text)]
            self.assertTrue(found, f"no count token in {tgt.path.name}")
            for got in found:
                self.assertEqual(got, n, f"stale count token in {tgt.path.name}: {got} != {n}")


_ONE = '```toml\n[[primitive]]\nid = "a"\nkind = "fact"\nshort = "x"\nlong = "x"\n```\n'


class TestGeneratorGuards(unittest.TestCase):
    """The drift-guard's own fail-loud branches must actually fire (not just degrade)."""

    def _registry(self, body: str) -> Path:
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        p = Path(d.name) / "primitives.md"
        p.write_text(body, encoding="utf-8")
        return p

    def test_missing_toml_block_errors(self):
        with self.assertRaises(SystemExit):
            G.load_registry(self._registry("# just prose, no fenced toml\n"))

    def test_duplicate_ids_error(self):
        dupe = _ONE.replace("```\n", "[[primitive]]\nid = \"a\"\nkind = \"fact\"\nshort = \"y\"\nlong = \"y\"\n```\n")
        with self.assertRaises(SystemExit):
            G.load_registry(self._registry(dupe))

    def test_multiple_primitive_blocks_are_ambiguous(self):
        # a second [[primitive]] block must fail loudly, not be silently shadowed
        with self.assertRaises(SystemExit):
            G.load_registry(self._registry(_ONE + "\nan example below:\n\n" + _ONE))

    def test_non_data_toml_example_is_skipped(self):
        # a TOML *config* example (no [[primitive]]) is ignored, the real registry wins
        example = '```toml\n[meta]\nbypass_env = "X"\n```\n\nthen the registry:\n\n'
        prims = G.load_registry(self._registry(example + _ONE))
        self.assertEqual([p["id"] for p in prims], ["a"])

    def test_render_target_requires_marker(self):
        with self.assertRaises(SystemExit):
            G.render_target("no markers here at all", G.TARGETS[0], [{"id": "a", "kind": "fact",
                            "short": "x", "long": "x", "params": []}])

    def test_blanked_count_token_refills(self):
        # regression for the \\d* fix: an emptied token must re-substitute (not slip past)
        o, c = G._HTML["count_open"], G._HTML["count_close"]
        self.assertIn(f"{o}26{c}", G._sub_count(f"the {o}{c} primitives", o, c, 26))


if __name__ == "__main__":
    unittest.main()
