#!/usr/bin/env python3
"""Generate the README diagrams as self-contained SVGs (light card → reads on
GitHub light AND dark). Stdlib only. `python3 assets/gen_assets.py`.

Layout is computed by flow()/stack() so content never runs off the right edge;
canvas is 900 wide with ~36px margins."""
from __future__ import annotations
import html
import os

INK, MUT, LINE, CARD = "#1f2328", "#57606a", "#d0d7de", "#ffffff"
BLUE, BLUE_BG = "#2563eb", "#eaf1fd"
RED, RED_BG = "#cf222e", "#fdecea"
GRN, GRN_BG = "#1a7f37", "#e8f6ec"
FONT = "ui-sans-serif, -apple-system, 'Segoe UI', Helvetica, Arial, sans-serif"
MONO = "ui-monospace, 'SF Mono', Menlo, Consolas, monospace"
W = 900


def esc(s):
    return html.escape(s, quote=False)


def text(x, y, s, size=13, fill=INK, weight=400, anchor="middle", font=FONT):
    return (f'<text x="{x}" y="{y}" font-family="{font}" font-size="{size}" fill="{fill}" '
            f'font-weight="{weight}" text-anchor="{anchor}">{esc(s)}</text>')


def box(x, y, w, h, lines, fill="#f6f8fa", stroke=LINE, tcolor=INK, size=12, weight=400, mono=False):
    lh = 15.5
    cx, n = x + w / 2, len(lines)
    ty = y + h / 2 - (n - 1) * lh / 2 + 4
    font = MONO if mono else FONT
    out = [f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="10" fill="{fill}" stroke="{stroke}" stroke-width="1.5"/>',
           f'<text x="{cx}" y="{ty}" font-family="{font}" font-size="{size}" fill="{tcolor}" font-weight="{weight}" text-anchor="middle">']
    for i, ln in enumerate(lines):
        out.append(f'<tspan x="{cx}" dy="{0 if i == 0 else lh}">{esc(ln)}</tspan>')
    out.append("</text>")
    return "".join(out)


def arrow(x1, y, x2, color=MUT, label=None, lcolor=None):
    s = [f'<line x1="{x1}" y1="{y}" x2="{x2 - 7}" y2="{y}" stroke="{color}" stroke-width="2" marker-end="url(#a{color[1:]})"/>']
    if label:
        s.append(text((x1 + x2) / 2, y - 7, label, size=10, fill=lcolor or color, weight=600))
    return "".join(s)


def flow(y, h, start, items):
    """items: ('box', w, dict-of-box-kwargs) | ('arrow', gap, dict). Returns (svg, end_x)."""
    x, parts = start, []
    for it in items:
        if it[0] == "arrow":
            gap, kw = it[1], (it[2] if len(it) > 2 else {})
            parts.append(arrow(x, y + h / 2, x + gap, **kw))
            x += gap
        else:
            w, kw = it[1], it[2]
            parts.append(box(x, y, w, h, **kw))
            x += w
    return "".join(parts), x


def marker(c):
    return (f'<marker id="a{c[1:]}" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">'
            f'<path d="M0,0 L7,3 L0,6 Z" fill="{c}"/></marker>')


def svg(h, body):
    defs = "<defs>" + "".join(marker(c) for c in (MUT, RED, GRN, BLUE)) + "</defs>"
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {h}" width="{W}" height="{h}">'
            f'{defs}<rect x="1" y="1" width="{W - 2}" height="{h - 2}" rx="16" fill="{CARD}" stroke="{LINE}" stroke-width="1.5"/>{body}</svg>')


def write(name, content):
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), name)
    open(p, "w", encoding="utf-8").write(content)
    print("wrote", p)


def diagram_problem():
    H = 360
    b = [text(W / 2, 44, "Prose asks. ratchet enforces.", size=25, weight=700),
         text(W / 2, 69, "A rule in CLAUDE.md or a skill is a suggestion the agent can skip. A ratchet hook is not.", size=12.5, fill=MUT)]
    # WITHOUT
    b += [text(36, 112, "WITHOUT ratchet", size=12, fill=RED, weight=700, anchor="start")]
    f, _ = flow(124, 58, 36, [
        ("box", 168, dict(lines=["CLAUDE.md / a skill", "“run tests, no --no-verify,", "update docs”"], size=11)),
        ("arrow", 30, dict(color=RED, label="skips it", lcolor=RED)),
        ("box", 78, dict(lines=["AI", "agent"])),
        ("arrow", 30, dict(color=RED)),
        ("box", 196, dict(lines=["git push --no-verify", "tests skipped · docs stale"], size=11)),
        ("arrow", 28, dict(color=RED)),
        ("box", 270, dict(lines=["✗  MERGED", "broken and unreviewed"], fill=RED_BG, stroke=RED, tcolor=RED, weight=600)),
    ])
    b.append(f)
    # WITH
    b += [text(36, 250, "WITH ratchet", size=12, fill=GRN, weight=700, anchor="start")]
    f2, _ = flow(262, 58, 36, [
        ("box", 168, dict(lines=["the same rule, now", "declared in ratchet.toml"], size=11)),
        ("arrow", 30, dict(color=BLUE, label="tries to", lcolor=BLUE)),
        ("box", 78, dict(lines=["AI", "agent"])),
        ("arrow", 30, dict(color=BLUE)),
        ("box", 196, dict(lines=["ratchet hook", "PreToolUse · Stop"], fill=BLUE_BG, stroke=BLUE, tcolor=BLUE, weight=600)),
        ("arrow", 28, dict(color=GRN)),
        ("box", 270, dict(lines=["✓  BLOCKED until", "tests pass + docs updated"], fill=GRN_BG, stroke=GRN, tcolor=GRN, weight=600)),
    ])
    b.append(f2)
    write("concept.svg", svg(H, "".join(b)))


def diagram_layers():
    H = 410
    b = [text(W / 2, 44, "Two layers, one config — the same rules enforced twice", size=21, weight=700)]
    # agent band
    b += [f'<rect x="36" y="74" width="396" height="232" rx="12" fill="{BLUE_BG}" stroke="{BLUE}" stroke-width="1.5"/>']
    b += [text(54, 100, "AGENT LAYER · real-time", size=12.5, fill=BLUE, weight=700, anchor="start")]
    b += [box(52, 116, 175, 66, ["PreToolUse hook", "deny --no-verify and", "un-DoD'd push / merge"], fill=CARD, stroke=BLUE, size=11)]
    b += [box(241, 116, 175, 66, ["Stop hook", "block turn-end on", "unticked attestation"], fill=CARD, stroke=BLUE, size=11)]
    b += [text(234, 214, "bypassable (and logged) — friction, not the final word", size=11, fill=MUT)]
    b += [box(52, 232, 364, 30, ["mirrors what CI enforces, so you fix it before you push"], fill=CARD, stroke=BLUE, size=11)]
    # arrow
    b += [arrow(432, 190, 468, color=MUT, label="push / PR")]
    # change band
    b += [f'<rect x="468" y="74" width="396" height="232" rx="12" fill="{GRN_BG}" stroke="{GRN}" stroke-width="1.5"/>']
    b += [text(486, 100, "CHANGE LAYER · pre-push + CI", size=12.5, fill=GRN, weight=700, anchor="start")]
    b += [box(486, 116, 360, 50, ["authoritative · base-pinned · ignores the bypass"], fill=CARD, stroke=GRN, size=11.5, weight=600)]
    b += [box(486, 176, 360, 50, ["can't be relaxed by the same diff it gates"], fill=CARD, stroke=GRN, size=11.5)]
    b += [box(486, 236, 360, 50, ["a red CI check no env var can turn green"], fill=CARD, stroke=GRN, size=11.5)]
    # invariant footer
    b += [text(W / 2, 344, "block  =  only ungameable FACTS  (diff lines · the command · PR / commit metadata)", size=12.5, fill=INK, weight=700)]
    b += [text(W / 2, 368, "anything needing judgment (an LLM-judge, a self-checkbox) stays advisory — it warns, never blocks", size=11.5, fill=MUT)]
    write("layers.svg", svg(H, "".join(b)))


def diagram_bypass():
    H = 360
    b = [text(W / 2, 44, "The gate the diff can't loosen", size=23, weight=700),
         text(W / 2, 69, "One PR that leaks a secret AND edits ratchet.toml to disarm the check.", size=12.5, fill=MUT)]
    # PR card
    b += [f'<rect x="36" y="100" width="300" height="170" rx="10" fill="#f6f8fa" stroke="{LINE}" stroke-width="1.5"/>']
    b += [text(186, 128, "PR #42 — the agent's diff", size=12.5, weight=700)]
    b += [box(54, 146, 264, 42, ["+ leak.py:  AWS_KEY = \"AKIA…\""], fill=RED_BG, stroke=RED, tcolor=RED, size=11, mono=True)]
    b += [box(54, 200, 264, 52, ["~ ratchet.toml", "secret-scan:  block → warn"], fill=RED_BG, stroke=RED, tcolor=RED, size=11, mono=True)]
    # naive
    b += [arrow(336, 150, 374, color=MUT)]
    b += [box(374, 116, 462, 36, ["a naive gate reads config from the PR HEAD"], fill=CARD, stroke=LINE, size=12, weight=600)]
    b += [box(374, 158, 462, 36, ["✗  0 blocks left → it merges the leak"], fill=RED_BG, stroke=RED, tcolor=RED, size=12, weight=600)]
    # ratchet
    b += [arrow(336, 226, 374, color=GRN)]
    b += [box(374, 208, 462, 36, ["ratchet reads config from the BASE ref"], fill=CARD, stroke=GRN, tcolor=GRN, size=12, weight=700)]
    b += [box(374, 250, 462, 36, ["✓  secret still blocks → DENIED"], fill=GRN_BG, stroke=GRN, tcolor=GRN, size=12, weight=600)]
    b += [text(W / 2, 326, "base-pinning: every commit is judged against the policy that existed BEFORE it.", size=12.5, fill=INK, weight=600)]
    write("bypass.svg", svg(H, "".join(b)))


def diagram_catches():
    """Corner-cut → the fact that catches it. The value map; the three NEW fact-surface
    primitives are badged."""
    rows = [
        ("git commit --no-verify", "forbid_command", "the command string", False),
        ("commit straight to main", "forbid_commit_on_branch", "the current branch", True),
        ("delete the failing test", "forbid_delete", "file D-status", True),
        ("strip an assert / await / ?", "forbid_removal", "the removed line", True),
        ("leak a key into the diff", "secret_scan", "the added line", False),
        ("ship code, skip the docs", "path_requires", "name-status pairing", False),
        ("rubber-stamp its own gate edit", "protected_path", "an independent approval", False),
    ]
    rh, top = 39, 110
    H = top + len(rows) * rh + 40
    b = [text(W / 2, 44, "Every shortcut to look “done” — caught by a fact", size=22, weight=700),
         text(W / 2, 69, "The agent authors none of the evidence on the right, so it can’t fake a pass.", size=12.5, fill=MUT),
         text(36, 96, "THE CORNER-CUT", size=10.5, fill=RED, weight=700, anchor="start"),
         text(462, 96, "THE RULE  ·  and the fact it reads", size=10.5, fill=GRN, weight=700, anchor="start")]
    for i, (cut, prim, basis, new) in enumerate(rows):
        y = top + i * rh
        b.append(box(36, y, 372, rh - 9, [cut], fill=RED_BG, stroke=RED, tcolor=RED, size=12.5, weight=600))
        b.append(arrow(408, y + (rh - 9) / 2, 446, color=GRN))
        b.append(f'<rect x="446" y="{y}" width="418" height="{rh - 9}" rx="10" fill="{GRN_BG}" stroke="{GRN}" stroke-width="1.5"/>')
        b.append(text(462, y + (rh - 9) / 2 - 2, prim, size=12.5, fill=GRN, weight=700, anchor="start", font=MONO))
        b.append(text(462, y + (rh - 9) / 2 + 13, basis, size=10.5, fill=MUT, anchor="start"))
        if new:
            b.append(f'<rect x="810" y="{y + 6}" width="42" height="17" rx="8" fill="{BLUE}"/>')
            b.append(text(831, y + 18, "NEW", size=9.5, fill="#ffffff", weight=700))
    write("catches.svg", svg(H, "".join(b)))


if __name__ == "__main__":
    diagram_problem()
    diagram_layers()
    diagram_bypass()
    diagram_catches()
