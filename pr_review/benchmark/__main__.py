"""CLI for the benchmark harness: build a corpus, then run it.

Deliberately separate from `pr_review/cli.py`. That CLI is the product — the
thing a user runs on their PR — and its surface is a contract. This is an
internal measuring instrument whose commands exist to be re-run by whoever is
auditing a number, so it lives behind `python -m pr_review.benchmark` and stays
out of the product's `--help`.

    python -m pr_review.benchmark build --repos pallets/flask,psf/requests \\
        --per-repo 5 --criteria "..." --out benchmark/corpus/negative.json
    python -m pr_review.benchmark run --corpus benchmark/corpus/negative.json
    python -m pr_review.benchmark rescore --run benchmark/results/<dir>/run.json
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

from pr_review.benchmark import corpus as corpus_mod
from pr_review.benchmark import gate as gate_mod
from pr_review.benchmark import ghsa as ghsa_mod
from pr_review.benchmark.report import (
    render_scorecard,
    write_scorecard,
    precheck_scorecard,
)
from pr_review.benchmark.runner import rescore, run_corpus
from pr_review.config import Config


def _build(args: argparse.Namespace) -> int:
    repos = [r.strip() for r in args.repos.split(",") if r.strip()]
    if not repos:
        print("no repos given", file=sys.stderr)
        return 2
    built = corpus_mod.build_negative_corpus(
        repos, per_repo=args.per_repo, name=args.name,
        selection_criteria=args.criteria, language=args.language,
        cache_root=args.cache_root,
    )
    if not built.cases:
        print("no cases were built — nothing pinned", file=sys.stderr)
        return 1
    path = corpus_mod.save(built, args.out)
    print(f"\npinned {len(built.cases)} case(s) -> {path}")
    return 0


def _build_labelled(args: argparse.Namespace) -> int:
    exclude = ghsa_mod.load_exclusions(args.exclude) if args.exclude else {}
    built, candidates = ghsa_mod.build_labelled_corpus(
        ecosystem=args.ecosystem, advisories=args.advisories,
        per_repo=args.per_repo, name=args.name,
        selection_criteria=args.criteria, cache_root=args.cache_root,
        max_diff_bytes=args.max_diff_bytes, controls=not args.no_controls,
        exclude=exclude,
    )
    if not built.cases:
        print("no cases were built — nothing pinned", file=sys.stderr)
        return 1
    path = corpus_mod.save(built, args.out)
    # The log is written next to the corpus, not printed: it is the record of
    # what was rejected, and a corpus whose rejections live only in a terminal
    # scrollback is a corpus nobody can audit.
    log = Path(args.out).with_suffix(".md")
    log.write_text(ghsa_mod.curation_log(candidates, built))
    kept = sum(1 for c in candidates if not c.rejected)
    print(f"\npinned {len(built.cases)} case(s) from {kept}/{len(candidates)} "
          f"advisories -> {path}")
    print(f"curation log -> {log}")
    print("The spans are CANDIDATES. Hand-verify each case and record the "
          "outcome in the log before quoting any number from this corpus.")
    return 0


def _build_triage_provider(name: str):
    """Arm 2b's provider, or None for the deterministic arm.

    Deliberately constructed here rather than inside `run_corpus`: which model
    a run paid for is a property of the *run*, and burying it in the harness is
    how a scorecard ends up unable to say what produced it.
    """
    if not name or name == "none":
        return None
    if name != "claude-cli":
        raise SystemExit(f"unknown triage provider {name!r} (none | claude-cli)")
    from pr_review.models.claude_cli import ClaudeCliProvider, cli_available
    if not cli_available():
        raise SystemExit(
            "`claude` is not on PATH, so --triage-provider claude-cli cannot "
            "run. Without it tier 3 keeps every ambiguous hunk, which is a "
            "different arm — so this refuses rather than quietly measuring one.")
    # A neutral cwd. The corpus checkouts are real repositories and a provider
    # rooted inside one could read source it was never given (`PIVOT_PLAN` §1.4).
    return ClaudeCliProvider(tempfile.mkdtemp(prefix="triage-cwd-"))


def _run(args: argparse.Namespace) -> int:
    loaded = corpus_mod.load(args.corpus)
    if args.rehydrate:
        loaded = corpus_mod.rehydrate(loaded, cache_root=args.cache_root)
    config = Config.load(args.config)

    # Before the run, not after it (§4). The post-write refusal stays -- it is
    # what actually protects the file -- but discovering a naming collision
    # should not cost the 844 seconds it cost on 2026-08-08.
    if not args.stdout and not args.overwrite:
        try:
            precheck_scorecard(loaded.name, args.results_root, label=args.label)
        except FileExistsError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    # Set by the LLM arms; checked only AFTER the run's artifacts are on disk.
    tool_check = None
    if args.arm == "llm-diff":
        # Arm 3 never touches the pipeline: no checkouts, no detectors, no
        # filter. A neutral cwd AND no tools, because `claude -p` rooted inside
        # a corpus checkout could read the source and quietly become arm 4.
        from pr_review.benchmark.llm_arm import run_llm_arm
        from pr_review.models.claude_cli import ClaudeCliProvider, cli_available
        if not cli_available():
            raise SystemExit("`claude` is not on PATH; arm 3 cannot run")
        provider = ClaudeCliProvider(tempfile.mkdtemp(prefix="llm-arm-cwd-"),
                                     default_model=args.arm_model)
        result = run_llm_arm(loaded, provider, limit=args.limit,
                             effort=args.arm_effort,
                             prompt_path=args.arm_prompt)
        tool_check = provider
    elif args.arm == "llm-context":
        # Arm 3c needs BOTH halves and takes the pipeline half from a committed
        # capture, so like arm 3 it builds no checkout and runs no detector --
        # and like arm 3 it gets a neutral cwd and no tools, because `claude -p`
        # rooted in a corpus checkout could read the source and quietly become
        # the repo-access arm that was cut.
        from pr_review.benchmark.context_arm import (CAPTURE_PATH,
                                                     run_context_arm)
        from pr_review.benchmark.context_capture import load as load_capture
        from pr_review.models.claude_cli import ClaudeCliProvider, cli_available
        if not cli_available():
            raise SystemExit("`claude` is not on PATH; arm 3c cannot run")
        capture = load_capture(args.arm_capture or CAPTURE_PATH)
        provider = ClaudeCliProvider(tempfile.mkdtemp(prefix="context-arm-cwd-"),
                                     default_model=args.arm_model)
        result = run_context_arm(loaded, provider, capture, limit=args.limit,
                                 effort=args.arm_effort,
                                 prompt_path=args.arm_prompt)
        tool_check = provider
    else:
        provider = _build_triage_provider(args.triage_provider)
        result = run_corpus(loaded, config=config, out_root=args.keep_runs,
                            limit=args.limit, cold_profiles=args.cold_profiles,
                            triage_provider=provider,
                            arm=("triage-live" if provider else "deterministic"))
    if args.stdout:
        print(render_scorecard(result))
        # Same rule as the on-disk path below: the scorecard is out, so the check
        # can no longer destroy it.
        if tool_check is not None:
            tool_check.assert_no_tool_use()
        return 0
    try:
        path = write_scorecard(result, root=args.results_root,
                               label=args.label, overwrite=args.overwrite)
    except FileExistsError as exc:
        # The corpus run itself already cost ~20 minutes. Print the scorecard
        # rather than lose it to a naming collision.
        print(f"\n{exc}\n", file=sys.stderr)
        print(render_scorecard(result))
        if tool_check is not None:
            tool_check.assert_no_tool_use()
        return 1
    print(f"\nscorecard -> {path}")
    if tool_check is not None:
        # AFTER `write_scorecard`, deliberately. This raised *before* it until
        # 2026-08-26 and cost five paid corpus passes: a guard that deletes the
        # evidence it exists to protect converts a recoverable anomaly into an
        # unrecoverable one, and the money is spent either way (errata §14.60).
        # The run is on disk now; if the check fails, the operator has both the
        # scorecard and the reason it is not to be trusted.
        tool_check.assert_no_tool_use()
    print(f"completed {result.completed}/{len(result.runs)} case(s) "
          f"in {result.wall_s:.0f}s")
    acct = result.model_accounting
    if acct:
        from pr_review.benchmark.report import _tokens
        uncached, cached = _tokens(acct)
        # Named for what the CLI reports. `cached` contains our prompt as well
        # as the harness's system prompt -- see §14.44.
        print(f"model: {acct['calls']} call(s), ${acct['cost_usd']:.4f}, "
              f"{cached} cached + {uncached} uncached tokens")
    if result.errors:
        print(f"{len(result.errors)} case(s) failed; see the scorecard")
    return 0


def _rescore(args: argparse.Namespace) -> int:
    """Re-derive a scorecard from a stored run — no pipeline, no checkouts."""
    try:
        data = json.loads(Path(args.run).read_text())
    except (OSError, ValueError) as exc:
        print(f"cannot read {args.run}: {exc}", file=sys.stderr)
        return 2
    try:
        result = rescore(data)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.stdout:
        print(render_scorecard(result))
        return 0
    try:
        # `dump=False`: the source run.json is already pinned where it is, and
        # writing a second copy under a new date would suggest a second
        # measurement had happened when nothing was re-executed.
        path = write_scorecard(result, root=args.results_root, label=args.label,
                               overwrite=args.overwrite, dump=False)
    except FileExistsError as exc:
        print(f"\n{exc}\n", file=sys.stderr)
        return 1
    print(f"\nrescored {result.completed}/{len(result.runs)} case(s) "
          f"from {args.run}")
    print(f"scorecard -> {path}")
    return 0


def comparison_sources(arms: list) -> list[str]:
    """Every file the scorecard page is built from, for the drift ledger.

    Named and returned rather than inlined at the `record` call, because the
    thing worth asserting in a test is the *declaration* -- which files this
    page admits to depending on -- and an argument built inline at one call site
    cannot be asserted on without running the whole command.

    Three kinds of source. Every arm's stored run, which holds the numbers. The
    script that hardcodes the arm descriptions, since a claim edited in a
    `--arm-run` note changes the page with no run.json moving. And the renderer
    itself, for exactly the same reason.

    THE RENDERER WAS MISSING UNTIL 2026-08-24, and the omission cost what this
    ledger was built to prevent (errata §14.52). Half this page's prose is
    literal strings in `report_html.py`: the callouts, the limits list, the
    ceiling note. One of them kept asserting a claim §14.51 had retired, the
    ledger reported "none" over it, and the published page contradicted its own
    table for a day. `render_report.py` records `__file__` and always did; this
    generator did not.

    WHERE THIS STILL DOES NOT REACH. The numbers are re-derived at render time
    from `scoring` and `metrics`, so a change there moves the page with no
    tracked source moving. That hole is real and is recorded in `OPEN_ITEMS.md`
    §24 rather than papered over. The fix for it is not a longer source list --
    the transitive import graph is most of the package, and a ledger that names
    everything reports drift on every commit, which is the same as reporting
    none. It is this repository's own rule from `REPORT.md` §5.7: a figure a
    reader will compare against another should be computed at render time from
    the object that produces the other one.
    """
    from pr_review.benchmark import report_html, rendered
    return ([a.dump_path for a in arms]
            + ["benchmark/results/comparison.sh",
               rendered.repo_relative(report_html.__file__)])


def _capture_context(args: argparse.Namespace) -> int:
    """Run the pipeline once and pin what it would hand a Phase-3b consumer.

    Zero model calls: the pipeline half of the context arm is deterministic, and
    this is that half, executed once so the passes that follow vary only in the
    model. See `context_capture`'s docstring for why replay beats rebuilding.
    """
    from pr_review.benchmark import context_capture

    loaded = corpus_mod.load(args.corpus)
    data = context_capture.capture(loaded, config=Config.load(args.config),
                                   limit=args.limit)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(context_capture.dumps(data))

    ok = [c for c in data["cases"].values() if "error" not in c]
    failed = [k for k, c in data["cases"].items() if "error" in c]
    bundles = sum(c["stats"]["bundles"] for c in ok)
    chars = sum(c["stats"]["slice_chars"] for c in ok)
    print(f"\nwrote {out} ({out.stat().st_size:,} bytes)")
    print(f"  {len(ok)} cases, {bundles} bundles, {chars:,} slice chars, "
          f"analyzer v{data['analyzer_version']} at {data['code_sha']}")
    if failed:
        print(f"  {len(failed)} case(s) captured no context: {', '.join(failed)}")
    return 0


def _compare(args: argparse.Namespace) -> int:
    """Render the arm comparison as one HTML page.

    Deliberately not "the four-arm comparison", which this docstring said until
    2026-08-26. The arms are whatever `--arm-run` is given -- five of them today,
    over two corpora -- and a count baked into a docstring is a claim that goes
    stale the next time one is added. §14.52 is the entry about exactly this: a
    documentation sweep that searched only `*.md` while the stale claim sat in a
    string literal.

    Every arm is **rescored** on load rather than trusted, because these runs
    were produced across three scoring fixes (§14.42–§14.44) and two arms judged
    by different rules on one page is exactly the comparison this is meant to
    prevent.
    """
    from pr_review.benchmark.report_html import load_arm, write_comparison
    from pr_review.benchmark import rendered

    arms = []
    for spec in args.arm_spec:
        label, sep, rest = spec.partition("=")
        if not sep:
            print(f"error: --arm-run wants LABEL=PATH, got {spec!r}",
                  file=sys.stderr)
            return 2
        path, _, note = rest.partition("::")
        try:
            note = note.strip()
            # Two independent markers, because they answer different questions.
            # `!` = cost-only, no findings column (§14.40). `-` = keep it out of
            # the headline panel, while it still counts everywhere else it has
            # something to say -- delta scoping, cost, variance.
            scored = not note.lstrip("-").startswith("!")
            headline = not note.lstrip("!").startswith("-")
            arms.append(load_arm(path, label.strip(),
                                 note=note.lstrip("!-").strip(),
                                 scored=scored, headline=headline))
        except (OSError, ValueError) as exc:
            print(f"cannot load {path}: {exc}", file=sys.stderr)
            return 2
    if not arms:
        print("error: no arms given", file=sys.stderr)
        return 2

    # Before rendering, not after: the drift being reported is what the page
    # looked like a moment ago, and saying it afterwards would read as though
    # the fresh page were stale.
    warning = rendered.check(args.out)

    path = write_comparison(arms, args.out, title=args.title)
    rendered.record(args.out, comparison_sources(arms))
    print(f"comparison -> {path}")
    if warning:
        print(warning)
    return 0


def _gate(args: argparse.Namespace) -> int:
    """Exit 0 pass / 1 regressed / 2 could not compare.

    The split matters: 2 means the gate did not run (unreadable file, stale dump,
    mismatched corpora) and must not be read as "no regression found".
    """
    try:
        result = gate_mod.gate_files(args.baseline, args.run, args.max_new_findings)
    except gate_mod.GateError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(json.dumps(gate_mod.as_dict(result), indent=2) if args.json
          else gate_mod.render(result))
    return 0 if result.passed else 1


def build_parser() -> argparse.ArgumentParser:
    """The CLI surface, separated from running it.

    Split out on 2026-08-26 so `--arm llm-context` could be tested (Plan 3
    Step 4). `run` carries fourteen flags and until then not one of them had a
    test that it parsed -- the arms, the effort, the prompt and now the capture
    all decide *what a stored run measured*, and a typo in any of them is a
    scorecard that says something other than what was asked for.
    """
    parser = argparse.ArgumentParser(prog="python -m pr_review.benchmark")
    sub = parser.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("build", help="pin a negative corpus from real merged PRs")
    b.add_argument("--repos", required=True, help="comma-separated owner/name list")
    b.add_argument("--per-repo", type=int, default=5)
    b.add_argument("--name", default="negative")
    b.add_argument("--language", default="python",
                   help="corpus metadata only — the pipeline reads config.languages, "
                        "not the case. Set it so the scorecard does not claim a "
                        "corpus is Python when it is Terraform.")
    b.add_argument("--criteria", required=True,
                   help="how these repos and PRs were chosen; printed in every "
                        "scorecard")
    b.add_argument("--out", default="benchmark/corpus/negative.json")
    b.add_argument("--cache-root", default=".pr_review/cache")
    b.set_defaults(func=_build)

    lb = sub.add_parser("build-labelled",
                        help="pin a labelled corpus from GitHub Security "
                             "Advisories (reverted fixes + post-fix controls)")
    lb.add_argument("--ecosystem", default="pip")
    lb.add_argument("--advisories", type=int, default=40,
                    help="how many advisories to examine, newest first")
    lb.add_argument("--per-repo", type=int, default=2,
                    help="cap per source repository; recent pip advisories are "
                         "heavily concentrated (one repo was 32 of 100)")
    lb.add_argument("--name", default="labelled")
    lb.add_argument("--criteria", required=True,
                    help="how these advisories were chosen; printed in every "
                         "scorecard")
    lb.add_argument("--out", default="benchmark/corpus/labelled.json")
    lb.add_argument("--cache-root", default=".pr_review/cache")
    lb.add_argument("--max-diff-bytes", type=int, default=400_000,
                    help="reject fixes too large to hand-verify")
    lb.add_argument("--exclude", default=None,
                    help="file of `GHSA-id  # reason` lines rejected by hand "
                         "curation; keeps the build reproducible instead of "
                         "editing the pinned corpus")
    lb.add_argument("--no-controls", action="store_true",
                    help="skip the post-fix control case (halves the run cost, "
                         "and gives up the only evidence that a detection is "
                         "about the vulnerability rather than the file)")
    lb.set_defaults(func=_build_labelled)

    r = sub.add_parser("run", help="run a pinned corpus and write a scorecard")
    r.add_argument("--corpus", required=True)
    r.add_argument("--config", default=None)
    r.add_argument("--limit", type=int, default=None)
    r.add_argument("--keep-runs", default=None,
                   help="keep the per-case run directories here for auditing")
    r.add_argument("--results-root", default="benchmark/results")
    r.add_argument("--label", default=None,
                   help="suffix the results directory (`--label after-fix` -> "
                        "benchmark/results/<date>-after-fix/), so re-measuring "
                        "the same corpus the same day keeps both runs")
    r.add_argument("--overwrite", action="store_true",
                   help="replace an existing scorecard instead of refusing")
    r.add_argument("--rehydrate", action="store_true",
                   help="re-extract checkouts from the pinned shas first")
    r.add_argument("--arm", default="pipeline",
                   choices=("pipeline", "llm-diff", "llm-context"),
                   help="`llm-diff` runs the raw single-prompt LLM baseline "
                        "instead of the pipeline: diff in, findings out, no "
                        "checkouts and no detectors. `llm-context` runs the "
                        "same model over the same diff PLUS the pipeline's own "
                        "context bundles, replayed from a committed capture — "
                        "arm 3's input is a strict subset of it, which is what "
                        "makes the pair interpretable. Scored by the same "
                        "score_case, which is the only thing the arms share.")
    r.add_argument("--arm-model", default="sonnet",
                   help="model for --arm llm-diff and --arm llm-context "
                        "(default sonnet). The two arms MUST use the same "
                        "model and effort or the pair measures both.")
    r.add_argument("--arm-effort", default="low",
                   choices=("low", "medium", "high", "xhigh", "max"),
                   help="thinking effort for the two LLM arms. Defaults to `low` "
                        "because that is plan/benchmark.md §3's 'raw "
                        "single-prompt LLM': measured, low spends 0 thinking "
                        "tokens where the CLI default spends 9,033 on one call, "
                        "at 15x the wall clock. An arm that does not state its "
                        "effort has not described what it measured.")
    r.add_argument("--arm-prompt", default=None,
                   help="prompt file for the LLM arms. Defaults to "
                        "`benchmark/prompts/llm-diff-baseline.md`. "
                        "CHANGING THE PROMPT CHANGES THE ARM: "
                        "`llm-diff-introduced-only.md` asks for introduced "
                        "vulnerabilities only, which is a different experiment "
                        "and needs its own --label. The file's stem is recorded "
                        "in `CorpusRun.arm`, so a stored run says which prompt "
                        "produced it.")
    r.add_argument("--arm-capture", default=None,
                   help="pinned context for --arm llm-context. Defaults to "
                        "`benchmark/context/labelled.json`. THE CAPTURE IS PART "
                        "OF THE ARM: two runs against different context are "
                        "different experiments, so its `code_sha` is recorded "
                        "in `CorpusRun.arm`. Refused before any model call if "
                        "it does not cover the corpus or was built at another "
                        "ANALYZER_VERSION.")
    r.add_argument("--triage-provider", default="none",
                   choices=("none", "claude-cli"),
                   help="arm 2b: run tier-3 triage against a real model. This "
                        "CHANGES WHAT IS MEASURED — tier 3 starts dropping "
                        "hunks it used to keep — so give it its own --label "
                        "rather than overwriting a deterministic run.")
    r.add_argument("--cold-profiles", action="store_true",
                   help="give every case its own profile cache. Required for a "
                        "paired corpus: without it the second case in a repo "
                        "patches the first one's profile, so the two halves of "
                        "a pair are computed by different code paths. Costs one "
                        "cold profile build per case.")
    r.add_argument("--stdout", action="store_true",
                   help="print the scorecard instead of writing it")
    r.set_defaults(func=_run)

    cc = sub.add_parser("capture-context",
                        help="pin the pipeline's context bundles for a corpus")
    cc.add_argument("--corpus", required=True)
    cc.add_argument("--config", default=None)
    cc.add_argument("--limit", type=int, default=None)
    cc.add_argument("--out", required=True,
                    help="where to write the capture; committed, because the "
                         "arm that replays it has to be reproducible without "
                         "the checkouts")
    cc.set_defaults(func=_capture_context)

    s = sub.add_parser("rescore",
                       help="re-derive a scorecard from a stored run.json, "
                            "without re-running the pipeline")
    s.add_argument("--run", required=True,
                   help="path to a run.json written beside a scorecard")
    s.add_argument("--results-root", default="benchmark/results")
    s.add_argument("--label", default=None,
                   help="suffix the results directory, as for `run`")
    s.add_argument("--overwrite", action="store_true")
    s.add_argument("--stdout", action="store_true",
                   help="print the scorecard instead of writing it")
    s.set_defaults(func=_rescore)

    c = sub.add_parser("compare",
                       help="render stored runs side by side as one HTML page")
    c.add_argument("--arm-run", dest="arm_spec", action="append", default=[],
                   metavar="LABEL=PATH[::NOTE]",
                   help="one arm per flag, repeatable, in the order they should "
                        "appear. PATH is a results directory or a run.json. A "
                        "NOTE beginning with `!` marks the arm as NOT a findings "
                        "measurement -- arm 2b is the case that needs it, since "
                        "its findings are the deterministic arm's findings "
                        "(errata 14.40) and printing them again would "
                        "double-count.")
    c.add_argument("--out", default="benchmark/results/comparison.html")
    c.add_argument("--title", default="Comparison scorecard")
    c.set_defaults(func=_compare)

    g = sub.add_parser("gate",
                       help="fail if a run regresses against a pinned baseline "
                            "run.json (counts, not rates — see gate.py)")
    g.add_argument("--run", required=True, help="the run.json being judged")
    g.add_argument("--baseline", required=True,
                   help="a pinned run.json from a known-good commit")
    g.add_argument("--max-new-findings", type=int,
                   default=gate_mod.DEFAULT_MAX_NEW_FINDINGS,
                   help="how many additional false positives the negative corpus "
                        "may gain before failing. One by default: a real "
                        "improvement can surface one more true finding in code "
                        "nobody flagged, and zero would fail on the tool getting "
                        "better")
    g.add_argument("--json", action="store_true",
                   help="emit the verdict as JSON instead of text")
    g.set_defaults(func=_gate)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except corpus_mod.CorpusError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
