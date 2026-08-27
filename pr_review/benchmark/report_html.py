"""The comparison scorecard, as one HTML page (`plan/benchmark.md` §4, item A).

WHAT THIS IS, AND WHAT IT DELIBERATELY IS NOT

Four plan documents ask for an HTML *dashboard of findings for one PR*. This is
not that, and the substitution is a decision rather than a shortfall
(`PIVOT_PLAN.md` §3): the thing worth making visible at the end of this project
is the **arm comparison** — four arms when this was written, five since
2026-08-26 — because that is the measurement, and
`report.py` already renders a per-corpus card in markdown that this can be a
second renderer over. The per-PR dashboard stays unbuilt and is recorded as
unbuilt in `BENCHMARK_STATUS.md` §1.

IT RENDERS UNTRUSTED TEXT, SO IT ESCAPES EVERYTHING

Every string on this page comes from somewhere a third party controls: repo
paths, CWE ids, advisory notes, detector error messages, the selection criteria
copied out of a pinned corpus. `report/markdown.py` shipped exactly this hole
once (`M1_STATUS.md` §5.2) -- a finding's evidence snippet closed the code fence
it was inside and the rest of the document was the snippet's to write. HTML is a
worse place to lose that argument, because the payload is not a broken fence but
a `<script>`. So `_e()` wraps every interpolation without exception, including
ones that "cannot" contain markup, and a test builds a case whose paths and
notes are markup.

THE THREE HONESTY CARRIES FROM `report.py`, KEPT

1. **n next to every rate.** `metrics.Rate.render()` already refuses to print a
   ratio without its denominator; this page never reformats around it.
2. **The recall ceiling, above the recall column.** 27 of 36 ground-truth rows
   are outside the taxonomy, so a perfect pipeline scores 0.250 (§14.45 --
   §14.42 published 0.364 off the advisory tags, and deriving the number here
   instead of quoting it is what caught that). A recall bar drawn against a
   full-width 1.0 would be a lie told by a layout choice, so the ceiling is
   drawn on the bar.
3. **Cost with the transport named.** `render_cost` in `report.py` is the one
   source for that prose; this page reuses the same split and the same
   "Derived, not measured here" hedge (§14.44).
"""
from __future__ import annotations

import html
import json
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from pr_review.benchmark.metrics import (
    LabelledMetrics,
    NegativeMetrics,
    PairMetrics,
    Rate,
    labelled_metrics,
    negative_metrics,
    pair_metrics,
)
from pr_review.benchmark.report import _tokens
from pr_review.benchmark.runner import CorpusRun
from pr_review.models.claude_cli import TRANSPORT_FLOOR_TOKENS, floor_for


def _e(value: object) -> str:
    """Escape anything before it reaches the page. No exceptions -- see the
    module docstring. `quote=True` because interpolations land in attributes
    as well as in text."""
    return html.escape("" if value is None else str(value), quote=True)


@dataclass
class Arm:
    """One column of the comparison."""

    label: str
    run: CorpusRun
    note: str = ""
    source: str = ""                      # display name: the results dir
    dump_path: str = ""                   # the run.json itself, for §24's ledger
    scored: bool = True                   # False = cost-only, see §14.40
    headline: bool = True                 # False = keep it off the first panel

    labelled: LabelledMetrics | None = field(default=None, repr=False)
    negative: NegativeMetrics | None = field(default=None, repr=False)
    pairs: PairMetrics | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        lab = [s for s in self.run.scores if s.labelled]
        neg = [s for s in self.run.scores if not s.labelled]
        if lab:
            self.labelled = labelled_metrics(lab)
            pair_of = {r.case.id: r.case.pair_id
                       for r in self.run.runs if r.case.pair_id}
            if pair_of:
                labelled_of = {r.case.id: r.case.labelled for r in self.run.runs}
                self.pairs = pair_metrics(self.run.scores, pair_of, labelled_of)
        if neg:
            self.negative = negative_metrics(neg)

    # -- delta scoping ------------------------------------------------------

    @property
    def scoping(self) -> tuple[int, int]:
        """`(raw findings, dropped as pre-existing)` across this arm's WHOLE run.

        Summed over every score rather than off one stratum. The first version
        of this read `self.negative or self.labelled`, which on the labelled
        corpus means the *control half* -- so a table built from it put 87
        findings over 50 negative-corpus PRs in the same column as 36 over 26
        control PRs, and invited exactly the cross-population comparison
        §14.42, §14.43 and §14.45 were all about. One arm is one run over one
        corpus, so the run is the right unit and the corpus is named in the row.
        """
        scored = sum(s.scored_findings for s in self.run.scores)
        dropped = sum(s.skipped_pre_existing for s in self.run.scores)
        return scored + dropped, dropped

    @property
    def suppression(self) -> Rate | None:
        """`None` means the arm has no baseline pass at all -- true of the LLM
        arms, and a fact about the arm rather than a zero. Rendering it as 0.000
        would put "removed nothing" in the same column as "cannot remove
        anything", and those are different claims."""
        raw, dropped = self.scoping
        if not self.scopes_against_a_baseline or not raw:
            return None
        return Rate(dropped, raw)

    @property
    def scopes_against_a_baseline(self) -> bool:
        """True when this arm ran the pipeline, which is the only producer here
        that sees the base tree. Read off the arm string rather than inferred
        from a zero count."""
        return not self.run.arm.startswith("llm")

    # -- cost ---------------------------------------------------------------

    @property
    def accounting(self) -> dict:
        return getattr(self.run, "model_accounting", None) or {}

    @property
    def calls(self) -> int:
        return int(self.accounting.get("calls") or 0)

    @property
    def cost_usd(self) -> float:
        return float(self.accounting.get("cost_usd") or 0.0)

    @property
    def cost_per_case(self) -> float | None:
        done = sum(1 for r in self.run.runs if r.ok)
        return self.cost_usd / done if self.calls and done else None

    @property
    def tokens(self) -> tuple[int, int]:
        return _tokens(self.accounting) if self.calls else (0, 0)

    @property
    def floor(self) -> int:
        """The floor this arm is priced with -- measured for its own CLI when
        the run recorded one, else the constant (§21)."""
        return floor_for(self.accounting)

    @property
    def our_tokens(self) -> int:
        """Total minus the calibrated harness floor. Derived, not measured --
        the subtraction comes off the *total* because taking it off the cached
        bucket alone reported zero for arm 2b (§14.44)."""
        uncached, cached = self.tokens
        harness = min(cached, self.calls * self.floor)
        return max(0, uncached + cached - harness)


def recall_ceiling(arms: list[Arm]) -> Rate | None:
    """How much of the ground truth the *pipeline's vocabulary* can reach.

    Drawn on the recall bars because a bar against a full-width 1.0 asserts a
    reachable maximum that does not exist here (§14.42). Derived from whichever
    arm scored the labelled corpus -- `in_scope_rows` is computed by
    `benchmark/scope.py` from the detectors' own dispatch tables, so it moves
    when the tool does and cannot be edited upward on its own.
    """
    for arm in arms:
        if arm.labelled and arm.labelled.gt_rows:
            m = arm.labelled
            return Rate(m.in_scope_rows, m.gt_rows)
    return None


# -- rendering ---------------------------------------------------------------

_FONTS = (
    '<link rel="preconnect" href="https://fonts.googleapis.com">'
    '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>'
    '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?'
    "family=Newsreader:ital,opsz,wght@0,6..72,400;0,6..72,600;1,6..72,400&"
    "family=IBM+Plex+Sans:wght@400;500;600&"
    'family=IBM+Plex+Mono:wght@400;500&display=swap">'
)

# A measurement record, so it is set like one: a text serif for the argument, a
# technical sans for the prose, and a mono with tabular figures for every number
# -- IBM Plex was drawn for engineering documentation, which is what this is.
# The neutral carries a slate bias toward the indigo accent rather than being a
# default grey, and the ceiling mark is brick rather than red: it is a limit of
# the measurement, not an alarm.
_CSS = """
:root {
  --paper: #fbfcfd; --raise: #f2f5f8; --ink: #131820; --muted: #5a6675;
  --rule: #dde3ea; --accent: #3a4fb8; --limit: #a8443f;
  --caution: #7d5800; --caution-bg: #fcf5e4; --caution-rule: #d8b45e;
  --track: #dbe3f2; --fill: #3a4fb8;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --paper: #0f1216; --raise: #171c23; --ink: #dfe4ea; --muted: #97a2b0;
    --rule: #262d36; --accent: #8b9cf0; --limit: #e07a72;
    --caution: #e0b666; --caution-bg: #211a0d; --caution-rule: #6b5320;
    --track: #232c3b; --fill: #8b9cf0;
  }
}
:root[data-theme="dark"] {
  --paper: #0f1216; --raise: #171c23; --ink: #dfe4ea; --muted: #97a2b0;
  --rule: #262d36; --accent: #8b9cf0; --limit: #e07a72;
  --caution: #e0b666; --caution-bg: #211a0d; --caution-rule: #6b5320;
  --track: #232c3b; --fill: #8b9cf0;
}

* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body {
  margin: 0; padding: clamp(2rem, 5vw, 4rem) 1.25rem 6rem;
  background: var(--paper); color: var(--ink);
  font: 400 16px/1.65 "IBM Plex Sans", ui-sans-serif, system-ui, sans-serif;
  font-feature-settings: "kern";
}
main { max-width: 60rem; margin: 0 auto; display: flex; flex-direction: column;
       gap: 0; }

h1 {
  font: 400 clamp(2rem, 4.5vw, 2.9rem)/1.1 "Newsreader", Georgia, serif;
  letter-spacing: -0.015em; text-wrap: balance; margin: 0 0 .5rem;
}
h2 {
  font: 600 1.25rem/1.3 "Newsreader", Georgia, serif;
  letter-spacing: -0.005em; text-wrap: balance;
  margin: 3.5rem 0 1rem; padding-bottom: .45rem;
  border-bottom: 1px solid var(--rule);
}
h3 {
  font: 600 .82rem/1.4 "IBM Plex Sans", system-ui, sans-serif;
  text-transform: uppercase; letter-spacing: .07em; color: var(--muted);
  margin: 2.25rem 0 .6rem;
}
p { margin: 0 0 1rem; max-width: 66ch; }
p:last-child { margin-bottom: 0; }
ol { max-width: 68ch; padding-left: 1.2rem; margin: 0; }
ol li { margin-bottom: .85rem; }
ol li::marker { color: var(--muted); font-variant-numeric: tabular-nums; }

.sub {
  color: var(--muted); font-size: .84rem; letter-spacing: .04em;
  text-transform: uppercase; margin: 0 0 2.25rem;
}
.note { color: var(--muted); font-size: .88rem; }
p.note { margin-top: .85rem; }

code, .mono {
  font-family: "IBM Plex Mono", ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: .84em;
}
code { color: var(--accent); }

.panel {
  background: var(--raise); border: 1px solid var(--rule); border-radius: 3px;
  padding: 1.15rem 1.35rem; margin: 1.25rem 0;
}
.callout {
  background: var(--caution-bg); border: 1px solid var(--caution-rule);
  border-left-width: 3px; border-radius: 2px;
  padding: 1rem 1.25rem; margin: 1.5rem 0; font-size: .92rem;
  max-width: 68ch;
}
.callout strong:first-child { color: var(--caution); }

.scroll { overflow-x: auto; margin: 1rem 0; }
table { border-collapse: collapse; width: 100%; font-size: .88rem; }
caption { caption-side: bottom; text-align: left; padding-top: .6rem;
          color: var(--muted); font-size: .82rem; }
th, td {
  text-align: left; padding: .62rem .8rem; vertical-align: top;
  border-bottom: 1px solid var(--rule); white-space: nowrap;
}
thead th {
  font: 500 .68rem/1.35 "IBM Plex Sans", system-ui, sans-serif;
  text-transform: uppercase; letter-spacing: .075em; color: var(--muted);
  border-bottom: 1px solid var(--ink); white-space: normal; min-width: 5.5rem;
}
thead th .note { font-size: .68rem; letter-spacing: .02em;
                 text-transform: none; }
tbody tr:last-child td { border-bottom: none; }
td.num, th.num { text-align: right; }
td.num {
  font-family: "IBM Plex Mono", ui-monospace, Menlo, monospace;
  font-variant-numeric: tabular-nums; font-size: .82rem;
}
td.name { white-space: normal; min-width: 12rem; }
td.name strong { font-weight: 600; }
td.name .note { display: block; margin-top: .15rem; font-size: .78rem;
                white-space: normal; }
.dim { color: var(--muted); }
.mid { text-align: center; font-style: italic; }

/* The one visual device on the page. The track is the full 0..1 range, the
   fill is the measured rate, and the brick rule is the ceiling -- drawn
   because a bar against an unmarked full width asserts a reachable 1.0. */
.bar { position: relative; height: 5px; background: var(--track);
       border-radius: 1px; min-width: 5.5rem; margin-top: .4rem; }
.bar > i { position: absolute; inset: 0 auto 0 0; display: block;
           background: var(--fill); border-radius: 1px; }
.bar > b { position: absolute; top: -3px; bottom: -3px; width: 2px;
           background: var(--limit); }

footer {
  margin-top: 4rem; padding-top: 1.25rem; border-top: 1px solid var(--rule);
  color: var(--muted); font-size: .82rem; max-width: 68ch;
}
@media (prefers-reduced-motion: reduce) {
  * { animation: none !important; transition: none !important; }
}
"""


def _bar(value: float | None, ceiling: float | None = None) -> str:
    if value is None:
        return ""
    pct = max(0.0, min(1.0, value)) * 100
    mark = ""
    if ceiling is not None and 0 < ceiling <= 1:
        mark = f'<b style="left:{ceiling * 100:.1f}%" title="ceiling"></b>'
    return f'<div class="bar"><i style="width:{pct:.1f}%"></i>{mark}</div>'


def _rate_cell(rate: Rate | None, ceiling: float | None = None,
               places: int = 3) -> str:
    if rate is None or rate.den == 0:
        return '<td class="num dim">n/a</td>'
    return (f'<td class="num">{_e(rate.render(places))}'
            f'{_bar(rate.value, ceiling)}</td>')


def _headline_table(arms: list[Arm], ceiling: Rate | None) -> list[str]:
    cap = ceiling.value if ceiling else None
    out = ['<div class="scroll"><table>', "<thead><tr>",
           "<th>Arm</th>",
           # The corpus, for the same reason the scoping table carries it: these
           # arms are not all on one, and "FP per clean PR" over 50 negative
           # PRs is a different population from the same phrase over 26 control
           # halves. The denominators are printed too; this is the second guard.
           "<th>Corpus</th>",
           '<th class="num">Recall<br><span class="note">all ground truth</span></th>',
           '<th class="num">Recall<br><span class="note">reachable stratum</span></th>',
           '<th class="num">Precision</th>',
           '<th class="num">Pairs discriminated</th>',
           '<th class="num">FP per clean PR<br>'
           '<span class="note">upper bound</span></th>',
           '<th class="num">Cost</th>',
           "</tr></thead><tbody>"]
    for arm in (a for a in arms if a.headline):
        # An unscored arm's note is a paragraph of explanation, and it gets its
        # own panel below. Repeating it inside a table cell makes the row
        # unreadable and the number it is explaining harder to find, not easier.
        inline = arm.note if (arm.scored and arm.note) else ""
        cells = [f'<td class="name"><strong>{_e(arm.label)}</strong>'
                 + (f'<span class="note">{_e(inline)}</span>' if inline else "")
                 + "</td>",
                 f'<td class="mono">{_e(arm.run.corpus_name)}</td>']
        if not arm.scored:
            # §14.40: arm 2b's findings ARE the deterministic arm's findings, so
            # printing them again would double-count one measurement. This is a
            # statement about the arm, not about its corpus.
            cells.append('<td class="dim mid" colspan="5">not a findings '
                         'measurement &mdash; see below</td>')
        elif arm.labelled is None:
            # A negative-corpus arm. It IS a findings measurement -- arm 2c's
            # false-alarm rate is the whole point of it -- there is simply no
            # ground truth to score recall against. Collapsing this into the
            # branch above would hide a real number behind someone else's
            # caveat, which is the §14.42 population error wearing a layout.
            cells += ['<td class="num dim">no ground truth</td>'] * 4
            cells.append(_rate_cell(arm.negative.fp_per_pr if arm.negative else None,
                                    places=2))
        else:
            m = arm.labelled
            cells.append(_rate_cell(m.recall, cap))
            cells.append(_rate_cell(m.in_scope_recall))
            cells.append(_rate_cell(m.precision))
            cells.append(_rate_cell(arm.pairs.discriminated if arm.pairs else None,
                                    places=2))
            cells.append(_rate_cell(arm.negative.fp_per_pr if arm.negative else None,
                                    places=2))
        cells.append(f'<td class="num">{_e(_cost_short(arm))}</td>')
        out.append("<tr>" + "".join(cells) + "</tr>")
    out.append("</tbody></table></div>")
    return out


def _cost_short(arm: Arm) -> str:
    if not arm.calls:
        return "$0"
    per = arm.cost_per_case
    return f"${arm.cost_usd:.4f}" + (f" ({per:.4f}/case)" if per else "")


def _cost_section(arms: list[Arm]) -> list[str]:
    spenders = [a for a in arms if a.calls]
    if not spenders:
        return []
    # A floor column ONLY when the arms disagree. `ours` is derived from the
    # floor, so two arms priced by different floors are not directly comparable
    # in that column and the page has to say so. When every arm shares one floor
    # -- the case for everything measured so far -- the column would be a
    # constant repeated per row, and the callout below already names it.
    floors = {arm.floor for arm in spenders}
    mixed = len(floors) > 1
    out = ["<h2>Cost</h2>",
           '<div class="scroll"><table>', "<thead><tr><th>Arm</th>",
           '<th class="num">Calls</th><th class="num">Total</th>',
           '<th class="num">Per case</th><th class="num">Cached</th>',
           '<th class="num">Uncached</th>'
           + ('<th class="num">Floor</th>' if mixed else "")
           + '<th class="num">Ours (derived)</th>',
           "</tr></thead><tbody>"]
    for arm in spenders:
        uncached, cached = arm.tokens
        per = arm.cost_per_case
        out.append(
            "<tr>"
            f'<td class="name">{_e(arm.label)}</td>'
            f'<td class="num">{arm.calls}</td>'
            f'<td class="num">${arm.cost_usd:.4f}</td>'
            f'<td class="num">{f"${per:.4f}" if per else "&mdash;"}</td>'
            f'<td class="num">{cached:,}</td>'
            f'<td class="num">{uncached:,}</td>'
            + (f'<td class="num">{arm.floor:,}</td>' if mixed else "")
            + f'<td class="num">~{arm.our_tokens:,}</td>'
            "</tr>")
    out.append("</tbody></table></div>")
    return out


def _variance_section(arms: list[Arm]) -> list[str]:
    """Repeated passes of one arm, reported as a spread rather than a mean.

    `plan/benchmark.md` treats run-to-run variance as a first-class result, and
    it is: the pipeline produced byte-identical scorecards twice, so a baseline
    that does not is a product difference and averaging it away would hide the
    finding rather than summarize it.
    """
    passes = [a for a in arms if a.scored and a.labelled and a.run.arm.startswith("llm")]
    if len(passes) < 2:
        return []
    rows = [
        ("Recall (all)", [a.labelled.recall for a in passes]),
        ("Recall (reachable)", [a.labelled.in_scope_recall for a in passes]),
        ("Precision", [a.labelled.precision for a in passes]),
        ("Pairs discriminated",
         [a.pairs.discriminated if a.pairs else None for a in passes]),
        ("False positives on controls",
         [a.negative.fp_per_pr if a.negative else None for a in passes]),
    ]
    out = ["<h2>Run-to-run variance</h2>",
           '<div class="scroll"><table><thead><tr><th>Metric</th>']
    out += [f'<th class="num">{_e(a.label)}</th>' for a in passes]
    out.append('<th class="num">Spread</th></tr></thead><tbody>')
    for name, rates in rows:
        cells = [f'<td class="name">{_e(name)}</td>']
        values = [r.value for r in rates if r is not None and r.value is not None]
        for r in rates:
            cells.append('<td class="num dim">n/a</td>' if r is None
                         else f'<td class="num">{_e(r.render(3))}</td>')
        spread = (f"{max(values) - min(values):.3f}" if len(values) > 1 else "&mdash;")
        cells.append(f'<td class="num">{spread}</td>')
        out.append("<tr>" + "".join(cells) + "</tr>")
    out.append("</tbody></table></div>")
    out.append('<p class="note">Same prompt, same corpus, same model, same '
               "effort, three passes. Reported as a spread and never as a mean: "
               "the deterministic arms produce identical scorecards on a re-run, "
               "so a range here is a difference in kind, not noise to smooth "
               "over.</p>")
    return out


_LIMITS = (
    ("The pipeline's numerator is one finding.",
     "Its entire recall on this corpus is a single <code>taint-path</code> "
     "detection. Nothing here has the resolution to rank two tools that both "
     "score near zero, and a ratio between arms is not a ratio between "
     "capabilities at n=1."),
    ("A labelled case is a fixing commit run backwards.",
     "The vulnerable lines are therefore essentially the whole diff &mdash; the "
     "easiest possible presentation of the defect, and one that favours an arm "
     "that reads diffs. The paired control is what keeps this from being "
     "worthless, and it is why <em>pairs discriminated</em> sits next to recall "
     "rather than under it."),
    ("The pipeline was measured at the scope it has, not the one it was designed for.",
     "Phase-3b agentic families and the Phase-3c verifier are designed and not "
     "built. The design's own answer to this comparison is exactly the part "
     "that does not exist, so this prices what the agent layer would have to "
     "earn &mdash; it does not show that it cannot."),
    ("Cost is measured through a harness that taxes it.",
     "Roughly 380k tokens of CLI system prompt ride along with 250k tokens of "
     "content on the LLM arm. An API caller pays neither the same tokens nor "
     "the same price."),
)


def _scoping_section(arms: list[Arm]) -> list[str]:
    """The axis the pipeline wins on, which no scorecard reported until now.

    Deliberately placed directly under the headline. Every metric in this
    harness was aimed at recall -- the axis this tool is worst at -- so its
    largest measured effect had no number anywhere for the whole project
    (§14.46). A reader who stops after the headline table should still see it.
    """
    # Only arms that actually have a baseline pass. The LLM arms have none, so
    # their rows said "no baseline pass" and nothing else -- three words of
    # absence per row, in a table about what the pass removes.
    rows = [a for a in arms if a.suppression is not None]
    if not rows:
        return []

    out = ["<h2>Delta scoping — what the baseline pass removes</h2>",
           "<p>Every arm that runs the pipeline scans the <em>base</em> commit "
           "with the same detectors and drops whatever was already there. It is "
           "the single largest effect any stage here has on the reported "
           "numbers, and it is the capability a diff-only reviewer cannot have: "
           "a tool that never sees the base tree cannot tell a defect the PR "
           "<em>introduced</em> from one it merely walked past.</p>",
           '<div class="scroll"><table><thead><tr><th>Arm</th>',
           "<th>Corpus</th>"
           '<th class="num">Raw findings</th>'
           '<th class="num">Dropped as pre-existing</th>'
           '<th class="num">Reported</th></tr></thead><tbody>']
    for arm in rows:
        raw, dropped = arm.scoping
        # The corpus is in the row because the arms here are not all on one:
        # a rate over 50 negative-corpus PRs and one over 26 control PRs are
        # different populations and must not be read down a column.
        head = (f'<tr><td class="name">{_e(arm.label)}</td>'
                f'<td class="mono">{_e(arm.run.corpus_name)}</td>')
        out.append(
            head
            + f'<td class="num">{raw}</td>'
            + f'<td class="num">{_e(arm.suppression.render(3))}'
              f'{_bar(arm.suppression.value)}</td>'
            + f'<td class="num">{raw - dropped}</td></tr>')
    out.append("</tbody></table></div>")
    return out


def _limits_section(arms: list[Arm]) -> list[str]:
    """The four things this comparison does not say.

    Placed above the cost tables rather than in a footnote, because a reader who
    stops after the headline should have already passed it. Every incentive in a
    benchmark points at a bigger number, and the only defense is putting the
    caveats where they cannot be skipped without choosing to.
    """
    out = ["<h2>What this does not say</h2>", "<ol>"]
    for head, body in _LIMITS:
        out.append(f"<li><strong>{head}</strong> {body}</li>")
    out.append("</ol>")
    return out


def _provenance_section(arms: list[Arm]) -> list[str]:
    out = ["<h2>Provenance</h2>",
           "<p class=\"note\">Every number above re-derives from a stored "
           "<code>run.json</code> by <code>python -m pr_review.benchmark "
           "rescore</code>. Cases are pinned by repo, PR number and both shas.</p>",
           '<div class="scroll"><table><thead><tr>',
           "<th>Arm</th><th>Corpus</th><th>Cases</th><th>Code</th>"
           "<th>Wall</th><th>Run</th></tr></thead><tbody>"]
    for arm in arms:
        out.append(
            "<tr>"
            f'<td class="name">{_e(arm.label)}</td>'
            f'<td class="mono">{_e(arm.run.corpus_name)}</td>'
            f'<td class="num">{arm.run.completed}/{len(arm.run.runs)}</td>'
            f'<td class="mono">{_e(arm.run.code_sha or "?")}</td>'
            f'<td class="num">{arm.run.wall_s:.0f}s</td>'
            f'<td class="mono">{_e(arm.source or "&mdash;")}</td>'
            "</tr>")
    out.append("</tbody></table></div>")
    criteria = next((a.run.selection_criteria for a in arms
                     if a.run.selection_criteria), "")
    if criteria:
        out += ['<h3>Selection criteria, verbatim from the pinned corpus</h3>',
                f'<div class="panel note">{_e(criteria)}</div>',
                '<p class="note">A corpus chosen to flatter the tool is the '
                "classic benchmark failure, and printing how it was picked is "
                "the only defense a reader has.</p>"]
    return out


def render_comparison(arms: list[Arm], *, title: str = "Comparison scorecard",
                      generated: str | None = None) -> str:
    if not arms:
        raise ValueError("a comparison needs at least one arm")
    ceiling = recall_ceiling(arms)
    when = generated or date.today().isoformat()

    out = [f"<title>{_e(title)}</title>", _FONTS, f"<style>{_CSS}</style>",
           "<main>",
           f"<h1>{_e(title)}</h1>",
           f'<p class="sub">Generated {_e(when)} from stored runs &middot; '
           f"{len(arms)} arm(s), same corpus, same scorer.</p>"]

    out += ['<div class="panel">',
            "<p><strong>What this compares.</strong> Every arm below is scored "
            "by the same <code>score_case</code> on the same pinned corpus. "
            "The arms differ only in what produced the findings: a single "
            "detector, the deterministic pipeline, or a model reading the diff "
            "and nothing else. No model judges any output &mdash; matching is "
            "CWE-family plus line overlap, and it is deterministic.</p>",
            "<p><strong>The corpus is a post-cutoff temporal holdout.</strong> "
            "Every advisory in it was published after the model's training "
            "cutoff, which is what <code>plan/benchmark.md</code> &sect;3 asks "
            "for and is the usual fatal objection to a comparison like this "
            "one. It holds here by accident: the corpus was built from the most "
            "recently published advisories for unrelated reasons.</p>",
            "</div>"]

    if ceiling and ceiling.value is not None:
        out.append(
            '<div class="callout"><strong>Read every recall figure against its '
            f"ceiling.</strong> Only {ceiling.num} of {ceiling.den} ground-truth "
            "rows name a weakness any detector in this milestone can express, so "
            f"a <em>perfect</em> pipeline scores <strong>"
            f"{ceiling.value:.3f}</strong> on the first recall column &mdash; "
            "not 1.000. The red mark on each bar is that ceiling. The second "
            "column restricts to the rows both kinds of arm can compete on, and "
            "it is the honest place to compare them. The stratum is derived from "
            "the detectors' own dispatch tables, never hand-listed. Errata "
            "&sect;14.42.</div>")

    out += ["<h2>Headline</h2>"]
    out += _headline_table(arms, ceiling)
    for arm in arms:
        if not arm.scored and arm.headline:
            out += [f"<h3>{_e(arm.label)}</h3>",
                    f'<div class="panel note">{_e(arm.note)}</div>']

    out += _scoping_section(arms)
    out += _cost_section(arms)
    out += _variance_section(arms)

    out += ["<footer>Render of stored corpus runs by "
            "<code>pr_review.benchmark.report_html</code>.</footer>",
            "</main>"]
    return "\n".join(out)


# -- loading -----------------------------------------------------------------

def load_arm(path: str | Path, label: str, *, note: str = "",
             scored: bool = True, headline: bool = True) -> Arm:
    """Load and rescore one stored run.

    Rescoring rather than trusting stored scores is the point: two arms compared
    on a page must have been judged by the same rules, and these runs were
    produced days apart across three scoring fixes (§14.42–§14.44).
    """
    from pr_review.benchmark.runner import rescore

    p = Path(path)
    dump = p / "run.json" if p.is_dir() else p
    run = rescore(json.loads(dump.read_text()))
    return Arm(label=label, run=run, note=note, source=str(dump.parent.name),
               dump_path=str(dump), scored=scored, headline=headline)


def write_comparison(arms: list[Arm], out_path: str | Path, **kw) -> Path:
    path = Path(out_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_comparison(arms, **kw))
    return path
