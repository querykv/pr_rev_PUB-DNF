"""ARM 3c — the context-fed LLM arm (`PLAN-3-CONTEXT-ARM.md`, variant A).

WHAT IT MEASURES, AND WHAT IT DELIBERATELY DOES NOT

Arm 3 sends `pr_task.diff_text` and nothing else. This arm sends that same diff,
byte for byte, and then the context bundles Phase 2 assembles for the same PR.
Arm 3's input is a strict subset of this one's, so a difference in findings is
attributable to the added context and to nothing else. That is the whole design:
one variable, held against an arm whose runs are already stored.

It is NOT M3. It prices what M3 would buy. The moment this acquires tools or a
second turn it has become an agent and has stopped being a measurement.

WHY THE CONTEXT COMES FROM A COMMITTED CAPTURE AND NOT A LIVE PIPELINE RUN

`context_capture.py` explains the reasoning in full: the arm has two halves and
only the model half is meant to vary, so the pipeline half is pinned at a known
value. The consequence here is that this module never builds a checkout, never
runs a detector, and can be replayed by someone with neither.

WHAT BUILDING THE CONSUMER REVEALED ABOUT THE BUNDLE — measured on the pinned
capture (175 bundles, 52 cases), not inferred:

  * **A bundle does not carry the path of its own hunks.** `Hunk.id` is
    `<file_id>:h<n>` and `file_id` is a hash; `group.files` is on `ChangeGroup`,
    which `ContextBundle` does not embed. The path is recoverable only from
    `enclosing_symbols[].file`, and 141 of 175 bundles have exactly one such
    file. For the other 34 this renderer says so rather than guessing. A
    Phase-3b agent would have hit the same wall (`OPEN_ITEMS.md` §26).
  * Every bundle's hunks lie in exactly one file — 0 of 175 span two file ids —
    so "the group's file" is a well-formed question even where the bundle
    cannot answer it.
  * **34 of 175 bundles carry no source at all**: no enclosing symbol and no
    neighbour, 32 of them with hunks and 2 with none. For those groups this arm
    degenerates to arm 3 plus a profile slice. No case degenerates completely —
    all 52 have at least one bundle with source — but 18 have a mix, and the
    write-up must say so rather than describe the arm as uniformly context-fed.
  * `auth_summary` is a project-level fact repeated on every group's slice. It
    agrees across every bundle in all 52 cases, so it is emitted once per case;
    if a future capture ever disagrees, `_auth_summary` falls back to per-group
    emission instead of silently picking one.

THE TWO DECISIONS THAT ARE NOT THIS MODULE'S TO MAKE QUIETLY

Both are written into `benchmark/prompts/llm-context-bundles.md`'s header, which
is the artifact a reader audits, and repeated here because code and prompt drift:

  * **The diff is raw, the slices are wrapped.** `build_user_message` guarantees
    the message *begins* with the exact bytes arm 3 would have sent — that is
    what `test_the_message_opens_with_the_bytes_arm_3_would_have_sent` pins —
    and slice `content` goes through `safety/wrap.py:wrap_many`, because it is
    marked UNTRUSTED at `change/schema.py:92` and arm 3 never receives it.
  * **The escalation tier is not honoured; its reason is passed through.**
    Honouring `full_file` means whole files, which the capture does not hold and
    which would move the cost figures this arm is priced against. So the result
    is a LOWER BOUND on a tier-honouring implementation. The reason string is
    still sent: the `multi_hop` reasons name the concrete taint path, which is
    the most specific thing in the bundle and costs nothing.

ORDERING

Nothing here sorts. Every list is emitted in capture order, which the pinned
artifact freezes byte for byte (§14.57 is the entry about three orderings that
were not deterministic). Sorting in the renderer would *hide* a future capture
regression rather than surface it, and the requirement §14.57 actually imposes
is that the prompt not shuffle between passes — a spread that measures the
prompt is not a spread that measures the model.
"""
from __future__ import annotations

from pathlib import Path

from pr_review.benchmark.context_capture import bundles_for
from pr_review.benchmark.llm_arm import PROMPTS_DIR, oversized, to_findings
from pr_review.benchmark.schema import BenchCase
from pr_review.change.schema import CodeSlice, ContextBundle
from pr_review.safety.wrap import wrap_many

PROMPT_PATH = PROMPTS_DIR / "llm-context-bundles.md"

# The pinned context for the labelled corpus. A path rather than a loaded
# module-level constant: 1.7 MB of JSON should not be read by importing.
CAPTURE_PATH = (Path(__file__).resolve().parent.parent.parent
                / "benchmark" / "context" / "labelled.json")

TOOL = "llm-context-bundles"

CONTEXT_HEADING = "=== PIPELINE CONTEXT ==="
SOURCE_HEADING = "=== SOURCE FOR THE GROUPS ABOVE ==="

# `kind=` on every fence, so a reader of the trace can tell slice content from
# any other untrusted payload a future arm might wrap.
SLICE_KIND = "pipeline-slice"


def load_prompt(path: str | Path | None = None) -> str:
    """Read the committed prompt. Absent is fatal, never defaulted.

    Same rule as arm 3's loader and for the same reason: an arm that silently
    ran a prompt the repository does not record is unauditable, which is the one
    thing a baseline comparison cannot be.
    """
    p = Path(path) if path else PROMPT_PATH
    if not p.exists():
        raise FileNotFoundError(
            f"the arm-3c prompt is missing at {p}. It is a committed artifact — "
            f"the claim that this arm is reproducible rests on it.")
    return p.read_text()


def _q(value: object) -> str:
    """Quote an identifier that will sit OUTSIDE the untrusted fence.

    Paths, symbol names and group ids are all attacker-controllable, and this
    renderer places them in the instruction region. `repr` is what `wrap()`
    already applies to `origin` for the same reason: it escapes newlines, so a
    symbol named `"x\\n=== PIPELINE CONTEXT ==="` cannot forge a section.
    """
    return repr(str(value))


def _hunk_range(hunk) -> str:
    """Post-change line span of one hunk, in the numbering the prompt asks for."""
    if hunk.new_range:
        return hunk.new_range
    if hunk.added_lines:
        return f"{min(hunk.added_lines)}-{max(hunk.added_lines)}"
    return "unknown"


def _group_file(bundle: ContextBundle) -> str | None:
    """The one file this group's hunks are in, or None if the bundle cannot say.

    See the module docstring: the bundle carries no path for its hunks, so this
    reads it off the enclosing symbols. Returns None rather than a guess when
    there is not exactly one candidate — 34 of 175 bundles in the pinned
    capture, where the honest answer is that the diff is the only place the
    path appears.
    """
    files = {s.file for s in bundle.enclosing_symbols}
    return files.pop() if len(files) == 1 else None


def _node_line(node: dict) -> str:
    """One profile-slice node. Loose dicts by design (`change/schema.py`)."""
    where = f"{node.get('file', '?')}:{node.get('line', '?')}"
    bits = [f"{_q(node.get('name', '?'))} at {_q(where)}"]
    if node.get("sink_class"):
        bits.append(f"class={_q(node['sink_class'])}")
    if node.get("group"):
        bits.append(f"group={_q(node['group'])}")
    return "  - " + ", ".join(bits)


def _access_line(row: dict) -> str:
    where = f"{row.get('file', '?')}:{row.get('line', '?')}"
    return (f"  - {_q(row.get('http_method', '?'))} {_q(row.get('endpoint', '?'))}"
            f" -> {_q(row.get('controller', '?'))},"
            f" auth={_q(row.get('auth_pattern', 'unknown'))},"
            f" enforcement={_q(row.get('enforcement', 'unknown'))}"
            f" at {_q(where)}")


def _sensitive_line(row: dict) -> str:
    return (f"  - {_q(row.get('name', '?'))} "
            f"({_q(row.get('classification', 'unclassified'))})")


def _auth_summary(bundles: list[ContextBundle]) -> str | None:
    """The project-level auth summary, if every group agrees on it.

    Emitted once per case instead of once per group because it is a fact about
    the project, not the group, and repeating it 8 times on an 8-group case buys
    the model nothing. Returns None when the groups disagree, in which case the
    caller falls back to per-group emission — a silent pick of one would be a
    quiet lie about what the pipeline said.
    """
    summaries = {b.profile_slice.auth_summary for b in bundles
                 if b.profile_slice.auth_summary}
    return summaries.pop() if len(summaries) == 1 else None


def _slice_origin(index: int, role: str, sl: CodeSlice) -> str:
    """The fence label that ties a payload back to its group.

    The outline and the fenced source are separate sections — one banner per
    case rather than one per group — so the origin has to carry the group
    ordinal, the role and the location, or the reader cannot rejoin them.
    """
    symbol = sl.symbol or "(no symbol)"
    return f"group {index} · {role} · {symbol} · {sl.file}:{sl.start_line}-{sl.end_line}"


def render_group(bundle: ContextBundle, index: int, total: int,
                 skip_auth: bool, seen_profiles: dict[str, int] | None = None
                 ) -> str:
    """The trusted outline for one bundle. Source text is NOT in here.

    `seen_profiles` maps a profile slice's serialization to the group ordinal
    that first printed it. `_profile_slice` selects rows by `group.files`, so
    two groups in the same file legitimately get identical rows — on the pinned
    capture that is common, and re-printing a dozen taint nodes per group pads
    the payload this arm is being priced on. The back-reference is exact and
    lossless: identical means byte-identical, never "close enough".
    """
    out = [f"--- group {index} of {total} (pipeline id {_q(bundle.group_id)}) ---"]

    path = _group_file(bundle)
    if path:
        out.append(f"file: {_q(path)}")
    elif bundle.hunks:
        out.append("file: not carried in the bundle — match the ranges below "
                   "against the diff")

    if bundle.hunks:
        spans = ", ".join(
            f"{_hunk_range(h)} (+{len(h.added_lines)}/-{len(h.removed_lines)})"
            for h in bundle.hunks)
        out.append(f"changed regions, post-change lines: {spans}")
        # Deduped, first occurrence first. Eight hunks inside one class all
        # carry the same `class Foo:` header, and eight copies of it tell the
        # model nothing the first copy did not.
        headers = list(dict.fromkeys(
            h.header for h in bundle.hunks if h.header.strip()))
        if headers:
            out.append("diff section headers: "
                       + ", ".join(_q(h) for h in headers))
    else:
        out.append("changed regions: none recorded for this group")

    # Passed through as prose, never acted on -- see the module docstring's
    # second decision. Labelled as routing so the model does not read
    # `full_file` as a severity signal; 113 of 175 bundles say it.
    out.append(f"pipeline routing note ({bundle.escalation}), not a verdict about "
               f"risk: {bundle.escalation_reason}")

    for role, slices in (("enclosing symbol", bundle.enclosing_symbols),
                         ("1-hop neighbour", bundle.neighbors)):
        for sl in slices:
            out.append(f"{role}: {_q(sl.symbol or '(no symbol)')} at "
                       f"{_q(f'{sl.file}:{sl.start_line}-{sl.end_line}')} "
                       f"— source below")
    if not bundle.enclosing_symbols and not bundle.neighbors:
        out.append("source slices: none — the pipeline resolved no enclosing "
                   "symbol or neighbour for this group")

    ps = bundle.profile_slice
    if not skip_auth and ps.auth_summary:
        out.append(f"project authentication: {ps.auth_summary}")

    row_sets = (("access-control rows in scope", ps.access_control_rows),
                ("sensitive fields in scope", ps.sensitive_fields),
                ("taint sources in scope", ps.source_nodes),
                ("taint sinks in scope", ps.sink_nodes),
                ("sanitizers in scope", ps.sanitizer_nodes))

    # Only a slice that PRINTS something may be back-referenced. Registering an
    # empty one would let a later empty group say "identical to group 1" when
    # group 1 printed no profile block at all -- a dangling reference in the
    # prompt, which is worse than the duplication it saves.
    repeat_of = None
    if seen_profiles is not None and any(rows for _label, rows in row_sets):
        key = ps.model_dump_json()
        repeat_of = seen_profiles.get(key)
        if repeat_of is None:
            seen_profiles[key] = index

    if repeat_of is not None:
        out.append(f"profile rows in scope: identical to group {repeat_of}")
    else:
        for label, rows in row_sets:
            if not rows:
                continue
            out.append(f"{label}:")
            if label.startswith("access-control"):
                out.extend(_access_line(r) for r in rows)
            elif label.startswith("sensitive"):
                out.extend(_sensitive_line(r) for r in rows)
            else:
                out.extend(_node_line(r) for r in rows)

    if bundle.reachability_hints:
        out.append("reachability hints (pipeline's own flow trace):")
        out.extend(
            f"  - {_q(h.role)} at {_q(f'{h.file}:{h.line}')}"
            + (f" — {h.note}" if h.note else "")
            for h in bundle.reachability_hints)

    return "\n".join(out)


def build_user_message(case: BenchCase,
                       bundles: list[ContextBundle]) -> tuple[str, dict]:
    """The diff, then the context. Returns the message and what it cost.

    The stats are returned rather than logged because Step 4 records diff chars
    and context chars per case on the `CorpusRun`: this arm is more expensive
    than arm 3 by construction (§4.1), so any finding it claims has to be
    priced, and a ratio re-derived by hand afterwards is a ratio nobody can
    check.
    """
    diff = case.pr_task.diff_text

    # The diff leads and is untouched. Everything below is appended, so the
    # message begins with exactly the bytes arm 3 would have sent.
    parts = [diff]

    if not bundles:
        parts.append(
            f"\n\n{CONTEXT_HEADING}\n\n"
            "The pipeline produced no context for this pull request. Judge from "
            "the diff alone.\n")
    else:
        auth = _auth_summary(bundles)
        head = [f"\n\n{CONTEXT_HEADING}\n",
                f"The pipeline grouped this pull request's changes into "
                f"{len(bundles)} group(s). Groups, hunks and slices appear in "
                f"the order the pipeline produced them; nothing here is sorted.",
                ""]
        if auth:
            head.append(f"project authentication (same for every group): {auth}")
            head.append("")
        parts.append("\n".join(head))

        payloads: list[tuple[str, str]] = []
        seen_profiles: dict[str, int] = {}
        for i, bundle in enumerate(bundles, start=1):
            parts.append(render_group(bundle, i, len(bundles),
                                      skip_auth=auth is not None,
                                      seen_profiles=seen_profiles))
            parts.append("")
            for role, slices in (("enclosing-symbol", bundle.enclosing_symbols),
                                 ("neighbour", bundle.neighbors)):
                payloads.extend((_slice_origin(i, role, sl), sl.content)
                                for sl in slices)

        if payloads:
            parts.append(f"{SOURCE_HEADING}\n")
            parts.append(wrap_many(payloads, kind=SLICE_KIND))

    message = "\n".join(parts)
    slice_chars = sum(len(s.content)
                      for b in bundles
                      for s in (*b.enclosing_symbols, *b.neighbors))
    stats = {
        "diff_chars": len(diff),
        "context_chars": len(message) - len(diff),
        "message_chars": len(message),
        "bundles": len(bundles),
        "slices": sum(len(b.enclosing_symbols) + len(b.neighbors)
                      for b in bundles),
        "slice_chars": slice_chars,
        # Named because the write-up must not describe the arm as uniformly
        # context-fed: 34 of 175 bundles in the pinned capture have neither.
        "groups_without_source": sum(
            1 for b in bundles if not b.enclosing_symbols and not b.neighbors),
    }
    return message, stats


def review_case(case: BenchCase, provider, bundles: list[ContextBundle],
                model_id: str | None = None, effort: str = "low",
                prompt_path: str | Path | None = None
                ) -> tuple[list, list[str], dict]:
    """One case, one call, blind. The provider decides which model."""
    if not case.pr_task.diff_text.strip():
        return [], ["case carried no diff text"], {}
    message, stats = build_user_message(case, bundles)
    # The same ceiling arm 3 applies, to the same corpus, so the two arms
    # partition it identically. This arm's message is larger than arm 3's by
    # construction, so it can be refused where arm 3 is not -- which is itself
    # a cost of context and belongs in the result rather than in a caveat.
    too_big = oversized(len(message))
    if too_big:
        return [], [too_big], stats
    reply = provider.complete(
        [{"role": "system", "content": load_prompt(prompt_path)},
         {"role": "user", "content": message}],
        model_id=model_id,
        effort=effort,
    )
    # Arm 3's parser, with this arm's tool name. Sharing it is deliberate: two
    # arms that parsed replies differently would differ by more than context,
    # and `ScoredFinding.detector` reads `provenance.tool`, so the scorecard has
    # to be able to tell them apart.
    findings, notes = to_findings(reply, case, tool=TOOL)
    if stats["bundles"] == 0:
        notes.append("no context bundles for this case — arm 3 with a longer prompt")
    return findings, notes, stats


def preflight(corpus, capture: dict) -> None:
    """Refuse a run the capture cannot serve, BEFORE any model call.

    `precheck_scorecard` established the pattern for a different failure: a
    naming collision discovered after the run cost 844 seconds on 2026-08-08.
    The equivalent here costs money, not seconds -- Step 6 is three passes at
    $10-20 -- and the two ways to waste it are both cheap to rule out first.

    * **Coverage.** A capture missing cases would produce a shorter experiment
      that still writes a scorecard, and a recall denominator quietly reduced to
      the cases that happened to be captured is the failure §14.45 is about.
    * **Analyzer version.** A bump invalidates every profile, and the profile
      decides the CPG the bundles are cut from. A capture from another version
      is a different measurement wearing the same filename, so running against
      one would price context that this build no longer produces.

    Not checked: `code_sha`. It is provenance and it legitimately differs from
    HEAD after any commit that does not touch the pipeline.
    """
    from pr_review.profile.cache import ANALYZER_VERSION

    captured = capture.get("cases") or {}
    missing = [c.id for c in corpus.cases if c.id not in captured]
    if missing:
        shown = ", ".join(missing[:5]) + ("..." if len(missing) > 5 else "")
        raise SystemExit(
            f"the capture covers {len(captured)} cases but corpus "
            f"{corpus.name!r} has {len(corpus.cases)}; {len(missing)} are "
            f"missing ({shown}). Re-capture against this corpus rather than "
            f"running a shorter experiment that still writes a scorecard.")

    got = capture.get("analyzer_version")
    if got != ANALYZER_VERSION:
        raise SystemExit(
            f"the capture was built at ANALYZER_VERSION {got!r} and this build "
            f"is {ANALYZER_VERSION}. The profile decides the CPG the bundles "
            f"are cut from, so this context is not what this build produces. "
            f"Re-capture before spending a pass on it.")

    failed = [cid for cid, entry in captured.items() if "error" in entry]
    if failed:
        print(f"note: {len(failed)} case(s) failed at capture time and will run "
              f"with no context: {', '.join(sorted(failed)[:5])}", flush=True)


def run_context_arm(corpus, provider, capture: dict, limit: int | None = None,
                    model_id: str | None = None, progress: bool = True,
                    effort: str = "low",
                    prompt_path: str | Path | None = None):
    """Run arm 3c over a corpus and return a `CorpusRun` the normal machinery reads.

    Structurally this is the first arm that needs both halves. Arm 2 bypasses
    the model; arm 3 bypasses the pipeline entirely. This one wants the
    pipeline's context *and* a model -- and gets the pipeline half from a
    committed capture rather than a live run, so it still builds no checkout and
    runs no detector. What it shares with every other arm is `_score_all`, which
    is the only thing that has to be identical for the comparison to mean
    anything.
    """
    import time

    from pr_review.benchmark.runner import CaseRun, CorpusRun, _score_all, head_sha

    preflight(corpus, capture)

    cases = corpus.cases[:limit] if limit else corpus.cases
    stem = Path(prompt_path or PROMPT_PATH).stem
    result = CorpusRun(
        corpus_name=corpus.name,
        selection_criteria=corpus.selection_criteria,
        started_at=time.strftime("%Y-%m-%dT%H:%M:%S"),
        code_sha=head_sha(),
        # The capture is part of this arm's identity in exactly the way the
        # prompt file is: two runs of "arm 3c" against different context are
        # different experiments, and a scorecard has to say which.
        arm=f"llm-context:{effort}:{stem}:capture@{capture.get('code_sha', '?')}")
    started = time.monotonic()
    try:
        for i, case in enumerate(cases, start=1):
            if progress:
                print(f"[{i}/{len(cases)}] {case.id}", flush=True)
            mark = len(getattr(provider, "calls", ()) or ())
            case_started = time.monotonic()
            run = CaseRun(case=case)
            try:
                try:
                    bundles = bundles_for(capture, case.id)
                except ValueError as exc:
                    # The case failed at capture time. Running it with no
                    # context is arm 3 wearing this arm's label, so it is a
                    # case error rather than a silent degradation.
                    raise RuntimeError(f"no captured context: {exc}") from None
                findings, notes, stats = review_case(
                    case, provider, bundles, model_id=model_id, effort=effort,
                    prompt_path=prompt_path)
                run.findings = findings
                run.payload = stats
                # Same as arm 3: everything the model says is about this PR,
                # because it never saw a baseline to attribute anything to.
                run.pre_existing = 0
                if notes and progress:
                    for n in notes[:3]:
                        print(f"    note: {n}", flush=True)
            except Exception as exc:                 # noqa: BLE001
                run.error = f"{type(exc).__name__}: {exc}"
                if progress:
                    print(f"    ERROR {run.error}", flush=True)
                result.errors.append((case.id, run.error))
            run.wall_s = time.monotonic() - case_started
            try:
                run.model_cost = provider.accounting(since=mark)
            except (AttributeError, TypeError):
                run.model_cost = {}
            result.runs.append(run)
            if progress and run.ok:
                print(f"    {len(run.findings)} finding(s) · "
                      f"{run.payload.get('bundles', 0)} bundle(s) · "
                      f"{run.wall_s:.1f}s", flush=True)
    finally:
        result.wall_s = time.monotonic() - started
        try:
            result.model_accounting = provider.accounting()
        except (AttributeError, TypeError):
            result.model_accounting = {}
    _score_all(result)
    return result
