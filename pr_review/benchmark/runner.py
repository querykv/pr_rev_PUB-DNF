"""Run the pipeline over a corpus (`plan/benchmark.md` §4, `runner.py`).

IT DRIVES `pipeline.run_review()`, AND THAT IS THE WHOLE DESIGN

The tempting shortcut is to call `detect_stage()` directly: it is faster, it
needs no run directory, and it returns findings without a report to parse. It
would also measure something we do not ship. Errata §14.18 records the general
form of this mistake — "a fixture validates a parser; only the binary validates
an adapter" — and a harness that reimplements the pipeline is the same error one
level up: it would validate the harness author's model of the pipeline.

So each case runs the real entry point with the real config, and the harness
reads back the artifacts the real run wrote:

    03d_findings.normalized.json   what the reviewer would have seen
    02_changeset.json              the filter's drop records (the ablation)
    telemetry.json                 per-detector status, phase timings, notes

Reading `telemetry["detect"]` matters as much as reading the findings. A detector
whose binary is missing returns an empty list, and so does a detector that found
nothing — `AdapterRun.status` is the only thing that separates them, and a
scorecard built without it would quietly report a perfect false-positive rate for
a scanner that never ran.

COST IS NOT MEASURED HERE. No model is called anywhere in this package, so there
are no tokens to count. The scorecard prints UNMEASURED rather than 0, per
`M1_STATUS.md` §4 — a zero in a token-economy report reads as "cheap" when it
means "we did not look".

A RUN IS SERIALIZABLE, AND SCORING IS NOT PART OF IT

`CorpusRun.to_dict()` persists what the *pipeline* produced; `_score_all()`
derives everything else from it. Splitting the two is the whole point: a run
costs hours and a scoring rule is an opinion that changes. Without the split,
adjusting `scoring._CWE_GROUPS` or the TP/near-miss boundary means paying for
the pipeline again, and — worse — any result older than the code that scored it
can never be regenerated at all.

So `run_corpus()` executes and then calls `_score_all()`; `rescore()` loads a
dump and calls the same function. The live path and the replay path share one
scoring implementation by construction rather than by discipline.

THE DUMP IS A SLICE, AND NAMES WHICH ONE. It keeps the case, the findings, the
filter's drop records and the per-detector telemetry — precisely what
`score_case`, `ablate_filter`, `_case_context` and `_tally_detectors` read
today. It does **not** keep the whole changeset or the whole telemetry file, and
it clears `pr_task.diff_text` (7 MB on the negative corpus, and re-derivable
from the pinned corpus). Teaching scoring to read something new therefore means
widening `_DUMP_VERSION` and paying for one more full run — which is the honest
cost, and cheaper than the alternative of storing artifacts nothing reads.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from pr_review.benchmark.schema import BenchCase, Corpus
from pr_review.benchmark.scoring import CaseScore, FilterAblation, ablate_filter, score_case
from pr_review.config import Config
from pr_review.pipeline import run_review
from pr_review.schema import Finding

# Bumped when the dump stops carrying what scoring needs. A dump from an older
# version is refused rather than silently rescored against fields it lacks —
# the same reasoning as `profile/cache.py:ANALYZER_VERSION`, which exists
# because a cache keyed only on its input cannot see a change to the code that
# reads it (errata §14.25).
_DUMP_VERSION = 2


@dataclass
class CaseRun:
    """One case, executed. `error` set means the case did not produce a verdict."""
    case: BenchCase
    findings: list[Finding] = field(default_factory=list)
    changeset: dict = field(default_factory=dict)
    telemetry: dict = field(default_factory=dict)
    verdict: str = ""
    wall_s: float = 0.0
    error: str = ""
    # Read off the changeset at run time rather than re-derived from it later,
    # so the dump does not have to carry every change group to preserve a count.
    changed_files: int = 0
    # Set only on the replay path — see `to_dict`. `None` means "the findings
    # list carries them, count it yourself", which is the live path.
    pre_existing: int | None = None
    # What this case spent on model calls. `{}` means no provider was
    # configured, which is a different statement from `{"cost_usd": 0}`.
    model_cost: dict = field(default_factory=dict)
    # What this case SENT, in characters, broken down by where it came from.
    # Arm 3c is more expensive than arm 3 by construction (`PLAN-3` §4.1), so
    # every finding it claims has to be priced against a cost it definitely
    # increases -- and a ratio re-derived by hand after the fact is a ratio
    # nobody can check. `{}` means the arm did not measure its payload.
    #
    # Like `model_cost`, deliberately NOT guarded by `_DUMP_VERSION`: scoring
    # does not read it, so an old dump still rescores to the same numbers.
    payload: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not self.error

    def to_dict(self) -> dict:
        """Everything on a labelled case; introduced-only on a negative one.

        ON A NEGATIVE CASE a pre-existing finding is read by nothing.
        `score_case` excludes it and `metrics.py` reports only how many were
        excluded, because `introduced_by_pr` is decided by `findings/delta.py`
        during the run and scoring never revisits it. The objects buy no replay
        fidelity, and they are not free: one pre-existing `SEC-PASSWORD` hit on
        a minified sourcemap in the netbox corpus carries a 1.25 MB evidence
        snippet, which alone made a three-case dump 1.3 MB.

        ON A LABELLED CASE THEY ANSWER A RECALL QUESTION, so they are kept.
        A ground-truth row the detector *found* and `delta.py` then attributed
        to the baseline is a different failure from one it never saw at all —
        different cause, different fix — and `scoring.baseline_attribution()`
        can only tell them apart if the findings survive. Measured on the first
        labelled run: 93 findings landed in a ground-truth file this way, which
        is most of what that corpus has to say.
        """
        case = self.case.model_dump(mode="json")
        # The diff is the one large field and the pinned corpus already has it.
        case["pr_task"]["diff_text"] = ""
        kept = (self.findings if self.case.labelled
                else [f for f in self.findings if f.introduced_by_pr])
        introduced = sum(1 for f in self.findings if f.introduced_by_pr)
        return {
            "case": case,
            "findings": [f.model_dump(mode="json") for f in kept],
            "pre_existing": (self.pre_existing if self.pre_existing is not None
                             else len(self.findings) - introduced),
            "verdict": self.verdict,
            "wall_s": self.wall_s,
            "error": self.error,
            "changed_files": self.changed_files,
            "dropped": self.changeset.get("dropped") or [],
            "detect": (self.telemetry.get("meta") or {}).get("detect") or {},
            "model_cost": self.model_cost,
            "payload": self.payload,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "CaseRun":
        return cls(
            case=BenchCase.model_validate(data["case"]),
            findings=[Finding.model_validate(f) for f in data.get("findings") or []],
            pre_existing=int(data.get("pre_existing", 0) or 0),
            # Rebuilt in the shape its one reader queries. `ablate_filter` reads
            # `dropped` and nothing else; `detect_telemetry` reads meta.detect
            # and nothing else. Storing the rest would be storing it for nobody.
            changeset={"dropped": data.get("dropped") or []},
            telemetry={"meta": {"detect": data.get("detect") or {}}},
            verdict=data.get("verdict", ""),
            wall_s=float(data.get("wall_s", 0.0)),
            error=data.get("error", ""),
            changed_files=int(data.get("changed_files", 0) or 0),
            # Absent from every dump written before 2026-08-21, and absent is
            # correct for those: no model ran. Deliberately NOT guarded by
            # `_DUMP_VERSION`, which exists for fields *scoring* reads — cost is
            # not one, so an old dump still rescores to the same numbers, and
            # bumping would have stranded eighteen runs the comparison needs.
            model_cost=data.get("model_cost") or {},
            # Absent from every dump written before 2026-08-26, and absent is
            # correct for those: only the context arm measures its payload.
            payload=data.get("payload") or {},
        )


@dataclass
class CorpusRun:
    corpus_name: str
    selection_criteria: str
    runs: list[CaseRun] = field(default_factory=list)
    scores: list[CaseScore] = field(default_factory=list)
    ablations: list[FilterAblation] = field(default_factory=list)
    detector_status: dict[str, dict[str, int]] = field(default_factory=dict)
    errors: list[tuple[str, str]] = field(default_factory=list)
    started_at: str = ""
    wall_s: float = 0.0
    # Captured when the pipeline ran, not when the document is rendered. A
    # rescore happens on a later commit, and a scorecard that named *that* one
    # would credit the wrong code with the numbers.
    code_sha: str = ""
    rescored_at: str = ""
    # Whether each case got its own profile cache. Recorded because it changes
    # what was measured, not just how fast — see `_isolated`.
    cold_profiles: bool = False
    # Corpus-wide model spend, and which arm produced it.
    model_accounting: dict = field(default_factory=dict)
    arm: str = ""

    @property
    def completed(self) -> int:
        return sum(1 for r in self.runs if r.ok)

    def to_dict(self) -> dict:
        return {
            "dump_version": _DUMP_VERSION,
            "corpus_name": self.corpus_name,
            "selection_criteria": self.selection_criteria,
            "started_at": self.started_at,
            "wall_s": self.wall_s,
            "code_sha": self.code_sha,
            "cold_profiles": self.cold_profiles,
            "arm": self.arm,
            "model_accounting": self.model_accounting,
            "detector_status": self.detector_status,
            "errors": [list(e) for e in self.errors],
            "cases": [r.to_dict() for r in self.runs],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "CorpusRun":
        version = data.get("dump_version")
        if version != _DUMP_VERSION:
            raise ValueError(
                f"run dump is version {version!r}, this build reads "
                f"{_DUMP_VERSION}. It was written before the dump carried what "
                f"scoring now reads, so rescoring it would silently measure "
                f"missing fields. Re-run the corpus."
            )
        run = cls(
            corpus_name=data.get("corpus_name", ""),
            selection_criteria=data.get("selection_criteria", ""),
            started_at=data.get("started_at", ""),
            wall_s=float(data.get("wall_s", 0.0)),
            code_sha=data.get("code_sha", ""),
            cold_profiles=bool(data.get("cold_profiles", False)),
            arm=data.get("arm", ""),
            model_accounting=data.get("model_accounting") or {},
            errors=[tuple(e) for e in data.get("errors") or []],
        )
        # `detector_status` is deliberately not restored from the dump:
        # `_score_all` rebuilds it from each case's detect telemetry, so the
        # replay path derives it the same way the live path did.
        run.runs = [CaseRun.from_dict(c) for c in data.get("cases") or []]
        return run


def head_sha() -> str:
    """The working tree's commit, or an honest label when there isn't one.

    A dirty tree is reported as dirty rather than as its last commit: a
    scorecard that names a sha which does not contain the code that produced it
    is worse than one that admits it cannot say.

    Lives here rather than in `report.py` because it describes the *run*, not
    the render — which is exactly the distinction a rescore makes visible.
    """
    try:
        proc = subprocess.run(["git", "rev-parse", "--short", "HEAD"],
                              capture_output=True, text=True, timeout=10)
        if proc.returncode != 0:
            return "unknown (not a git checkout)"
        sha = proc.stdout.strip()
        dirty = subprocess.run(["git", "status", "--porcelain"],
                               capture_output=True, text=True, timeout=10)
        return f"{sha}-dirty" if dirty.stdout.strip() else sha
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def _read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return {}


def _provider_accounting(provider, since: int = 0) -> dict:
    """Per-case model spend, if the provider reports any. Duck-typed so the
    benchmark does not depend on which concrete provider is wired in."""
    if provider is None or not hasattr(provider, "accounting"):
        return {}
    try:
        return provider.accounting(since=since)
    except TypeError:                            # a provider without `since`
        return provider.accounting()


def _provider_calls(provider) -> int:
    return len(getattr(provider, "calls", ()) or ())


def _case_slug(case_id: str) -> str:
    """A directory of its own per case, because a run directory is not unique
    per case.

    `pipeline._run_dir` names a run `<repo>/<pr_number>-<head_sha[:12]>`. That is
    unique for a real pull request, which is what it was written for, and it is
    not unique for a corpus: the labelled corpus pairs advisories against
    reverse-applied fixes, and **three of its 52 cases share a head commit with
    another case at a different base** — `GHSA-fwg2-594c-jp42:vuln` with
    `GHSA-fp3f-mc75-235c:control`, `GHSA-wvpp-8hx9-p66j:vuln` with
    `GHSA-jm78-9fvv-mhgr:control`, and the two onionshare advisories with each
    other. Both cases wrote one directory and the second silently replaced the
    first.

    No scored number was ever wrong: each case reads its artifacts back
    immediately after writing them, before the next case runs. What was lost is
    what `--keep-runs` exists for — after the run, three cases' artifacts on
    disk belonged to a different case, and an audit reading them would attribute
    one case's context to another. Plan 3's bundle census did exactly that, and
    reported three ground-truth rows as unreachable when the filter had never
    touched them. Errata §14.55.
    """
    return case_id.replace("/", "__").replace(":", "__")


def case_run_dir(out_root: str | Path, case: BenchCase) -> Path:
    """Where `run_case` leaves one case's artifacts under `out_root`.

    The supported way to find them. `pipeline._run_dir` composes the inner path
    and creates it as a side effect of running, so it is not a lookup; this is,
    and `test_case_run_dir_agrees_with_the_pipelines_own_naming` fails if the two
    ever stop agreeing.
    """
    slug = case.ref.head_sha[:12] if case.ref.head_sha else "LOCAL"
    return (Path(out_root) / _case_slug(case.id)
            / case.ref.repo.replace("/", "__")
            / f"{case.pr_task.pr_number}-{slug}")


def run_case(case: BenchCase, config: Config, out_root: Path,
             triage_provider=None) -> CaseRun:
    """Execute one case through the shipping pipeline and read its artifacts."""
    out_root = Path(out_root) / _case_slug(case.id)
    result = CaseRun(case=case)
    calls_before = _provider_calls(triage_provider)
    task = case.pr_task
    started = time.monotonic()

    base_dir = task.base_dir or None
    head_dir = task.head_dir or None
    # `pipeline._source_reader` refuses the same path for both sides — it would
    # make every file AST-equal to itself and drop the entire PR. A corpus that
    # somehow pinned one directory twice would silently score zero findings on
    # every case, so it is caught here rather than diagnosed from a flat result.
    if base_dir and head_dir and Path(base_dir).resolve() == Path(head_dir).resolve():
        result.error = "base_dir and head_dir are the same tree"
        return result
    for label, path in (("base_dir", base_dir), ("head_dir", head_dir)):
        if path and not Path(path).is_dir():
            result.error = f"{label} does not exist: {path}"
            return result

    try:
        run = run_review(
            repo=task.repo,
            pr_number=task.pr_number,
            diff_text=task.diff_text,
            config=config,
            out_root=str(out_root),
            base_dir=base_dir,
            head_dir=head_dir,
            title=task.title,
            body=task.body,
            base_sha=case.ref.base_sha,
            head_sha=case.ref.head_sha,
            triage_provider=triage_provider,
        )
    except Exception as exc:                     # noqa: BLE001
        # One case failing must not end the run. A corpus of 50 real repositories
        # will contain a diff our parser mishandles, and losing the other 49 to
        # it would be the worse outcome. Errors are counted and named in the
        # scorecard so the denominator stays honest.
        result.error = f"{type(exc).__name__}: {exc}"
        result.wall_s = time.monotonic() - started
        result.model_cost = _provider_accounting(triage_provider, calls_before)
        return result

    result.wall_s = time.monotonic() - started
    result.verdict = run.verdict
    fset = _read_json(run.out_dir / "03d_findings.normalized.json")
    result.findings = [Finding.model_validate(f) for f in fset.get("findings", [])]
    result.changeset = _read_json(run.out_dir / "02_changeset.json")
    result.telemetry = _read_json(run.out_dir / "telemetry.json")
    result.changed_files = len(result.changeset.get("groups") or [])
    result.model_cost = _provider_accounting(triage_provider, calls_before)
    return result


def detect_telemetry(run: CaseRun) -> dict:
    """Per-detector `AdapterRun` entries, wherever `Telemetry` filed them."""
    return (run.telemetry.get("meta") or {}).get("detect") or {}


def _isolated(config: Config, root: Path, case: BenchCase) -> Config:
    """A config whose profile and baseline caches are this case's alone.

    THE CACHE IS STATEFUL ACROSS CASES, AND THAT DECIDES WHAT GETS MEASURED

    `ProfileCache` and `BaselineCache` are both keyed per repository under
    `config.profile.cache_root`, and `drift.decide()` reads the *latest*
    fingerprint for a repo rather than one matching this case. So on a corpus
    with two cases in one repository, the first builds a profile cold and the
    second finds a cached fingerprint at a different sha, computes a small churn
    and takes the `incremental` branch — patching the first case's profile
    instead of building its own.

    The patched profile is not wrong (`incremental.partial_cache()` re-parses
    the changed files from the right tree). But on a **paired** corpus the two
    halves of a pair differ by exactly one commit, so this fires every time and
    fires asymmetrically: whichever case runs first gets a full build and the
    other gets a patch. A pair table whose two sides were computed by different
    code paths cannot support the claim the pair table exists to make.

    Isolation costs one cold profile build per case, which is most of a run's
    time. It is off by default because the negative corpus's numbers were
    produced with a shared cache and have to stay comparable to it.
    """
    isolated = config.model_copy(deep=True)
    isolated.profile.cache_root = str(root / "_profiles" / case.id.replace("/", "__"))
    return isolated


def run_corpus(corpus: Corpus, config: Config | None = None,
               out_root: str | Path | None = None,
               limit: int | None = None,
               cold_profiles: bool = False,
               progress: bool = True,
               triage_provider=None,
               arm: str = "") -> CorpusRun:
    """Run every case, score it, and collect the ablation.

    `out_root` defaults to a temporary directory that is removed afterwards: a
    50-case run writes 50 run directories with full reports, and none of them is
    the artifact anyone wants — the scorecard is. Pass a path to keep them when
    a number needs auditing back to its run.

    `cold_profiles` gives every case its own profile cache — see `_isolated`.
    """
    config = config or Config.load()
    scratch = out_root is None
    root = Path(out_root) if out_root else Path(tempfile.mkdtemp(prefix="bench-runs-"))
    cases = corpus.cases[:limit] if limit else corpus.cases

    result = CorpusRun(corpus_name=corpus.name,
                       selection_criteria=corpus.selection_criteria,
                       started_at=time.strftime("%Y-%m-%dT%H:%M:%S"),
                       code_sha=head_sha(), cold_profiles=cold_profiles,
                       arm=arm)
    started = time.monotonic()
    try:
        for i, case in enumerate(cases, start=1):
            if progress:
                print(f"[{i}/{len(cases)}] {case.id}", flush=True)
            case_config = _isolated(config, root, case) if cold_profiles else config
            run = run_case(case, case_config, root, triage_provider=triage_provider)
            result.runs.append(run)
            if not run.ok:
                result.errors.append((case.id, run.error))
                if progress:
                    print(f"    ERROR {run.error}", flush=True)
                continue
            if progress:
                introduced = sum(1 for f in run.findings if f.introduced_by_pr)
                print(f"    {introduced} introduced finding(s) · "
                      f"{run.wall_s:.1f}s", flush=True)
    finally:
        result.wall_s = time.monotonic() - started
        # In the `finally` so a run interrupted part way still reports what it
        # already spent. Money does not come back when the loop does not finish.
        result.model_accounting = _provider_accounting(triage_provider)
        if scratch:
            shutil.rmtree(root, ignore_errors=True)
    _score_all(result)
    return result


def _score_all(result: CorpusRun) -> None:
    """Derive every scored quantity from `result.runs`.

    The one place scoring happens, so `run_corpus` and `rescore` cannot drift
    apart. Idempotent: it clears what it fills, because a rescore runs it over a
    `CorpusRun` that may already carry scores from a previous pass.
    """
    result.scores = []
    result.ablations = []
    result.detector_status = {}
    for run in result.runs:
        if not run.ok:
            continue
        score = score_case(run.case, run.findings, pre_existing=run.pre_existing)
        score.context = _case_context(run)
        result.scores.append(score)
        if run.case.labelled:
            result.ablations.append(ablate_filter(run.case, run.changeset))
        _tally_detectors(result, run)


def rescore(data: dict) -> CorpusRun:
    """Re-derive every number in a scorecard from a serialized run.

    Blind spot #9's answer. The pipeline is not re-executed and no checkout is
    touched — this replays `_score_all` over what the pipeline already produced,
    which is what makes changing a scoring rule cost seconds instead of hours.
    """
    result = CorpusRun.from_dict(data)
    result.errors = [(r.case.id, r.error) for r in result.runs if not r.ok]
    _score_all(result)
    result.rescored_at = time.strftime("%Y-%m-%dT%H:%M:%S")
    return result


def _case_context(run: CaseRun) -> dict:
    """What this case gave the detectors the chance to find.

    A rule cannot produce a false positive in a PR containing nothing it looks
    at, so an FP rate averaged over PRs that touch no endpoint prices
    `BAC-MISSING-AUTHZ` at zero without measuring it. The structural detector
    already reports how many endpoints it saw; recording it per case is what
    lets `metrics.py` report that rule against the right denominator.
    """
    detect = detect_telemetry(run)
    structural = detect.get("structural") or {}
    semgrep = detect.get("semgrep") or {}
    return {
        "endpoints": structural.get("endpoints", 0),
        "taint_paths": structural.get("taint_paths", 0),
        "semgrep_files": semgrep.get("files", 0),
        "changed_files": run.changed_files,
    }


def _tally_detectors(result: CorpusRun, run: CaseRun) -> None:
    """Count each detector's `AdapterRun.status` across the corpus.

    The scorecard needs this to state which detectors were actually exercised.
    A false-positive rate computed over a corpus where `semgrep` reported
    `missing_tool` on every case is a false-positive rate for a tool that did not
    run, and nothing else in the output would reveal that.
    """
    # `Telemetry.set()` files everything under `meta`; `phase()` writes the
    # sibling `phases`. Reading the top level would silently find nothing and
    # report an empty status table, which looks like "no detectors" rather than
    # like a bug.
    detect = (run.telemetry.get("meta") or {}).get("detect") or {}
    for name, entry in detect.items():
        # `detect_stage` files the baseline under the same dict, keyed `source`
        # rather than `status`. It is a cache record, not a detector, and
        # counting it here would invent a detector called "baseline" that is
        # permanently in state "unknown".
        if name == "baseline" or not isinstance(entry, dict) or "status" not in entry:
            continue
        status = str(entry["status"])
        result.detector_status.setdefault(name, {})
        result.detector_status[name][status] = (
            result.detector_status[name].get(status, 0) + 1)
