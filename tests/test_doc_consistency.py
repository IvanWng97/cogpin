"""Cross-surface fact-consistency drift-guards.

The root `.md` docs and the site `.mdx` re-state the same facts in deliberately different
prose (a tutorial voice vs. a reference voice). PR 1 unified the one *structured* surface — the
primitive table — via a generated registry. The remaining overlaps are paraphrase, not
copy-paste, so generating them would flatten each voice. Instead, these tests assert the
underlying *facts* agree, killing numeric/factual drift without touching the prose.

Scope is deliberate: only facts that (a) are duplicated across surfaces and (b) can be checked
robustly (low false-positive on rewording). The empirical-sweep figures qualify — they are
distinctive numbers with a clear canonical home (`docs/coverage-map.md`). The two-layer
definition and the exit-code taxonomy are intentionally *not* guarded here: they are expressed
in stable technical terms that don't drift casually, and a keyword-presence test over them would
fire on innocent rewording — more maintenance friction than drift protection.
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _doc(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


class TestCoverageFigures(unittest.TestCase):
    """The empirical-pass figures (canonical in docs/coverage-map.md) must agree on every
    surface that cites them — the marketing-credibility numbers can't silently diverge."""

    # 30-agent sweep · nine corpora · 95 findings · 19 candidate gaps · six verified
    CANON = frozenset({30, 9, 95, 19, 6})
    WORDS = {"thirty": 30, "nine": 9, "nineteen": 19, "six": 6}
    SURFACES = (
        "docs/coverage-map.md",
        "site/src/content/docs/concepts.mdx",
        "site/src/content/docs/what-it-catches.mdx",
    )

    def _figures(self, text: str) -> set[int]:
        # the figures live in the single paragraph that names the "corpora"
        para = next((p for p in re.split(r"\n\s*\n", text) if "corpora" in p.lower()), "")
        self.assertTrue(para, "expected a paragraph mentioning 'corpora'")
        nums = {int(n) for n in re.findall(r"\d+", para)}
        for word, val in self.WORDS.items():
            if re.search(rf"\b{word}\b", para, re.IGNORECASE):
                nums.add(val)
        return nums

    def test_canonical_figures_present_in_coverage_map(self):
        # the canonical source itself must carry the full set (a self-check on CANON)
        self.assertLessEqual(self.CANON, self._figures(_doc("docs/coverage-map.md")))

    def test_figures_agree_across_surfaces(self):
        for surface in self.SURFACES:
            nums = self._figures(_doc(surface))
            missing = self.CANON - nums
            self.assertFalse(
                missing,
                f"{surface}: coverage-map figures drifted — missing {sorted(missing)} "
                f"(have {sorted(nums)}); canonical source is docs/coverage-map.md",
            )


if __name__ == "__main__":
    unittest.main()
