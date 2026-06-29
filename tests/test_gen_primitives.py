"""Anti-drift tests for the primitive registry and its generated tables.

These tie the docs to the engine and to the registry so a stale surface fails the suite
(the suite is the authoritative gate; the `--check` CLI mode mirrors this for CI ergonomics).
"""

import os
import re
import sys
import unittest

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


if __name__ == "__main__":
    unittest.main()
