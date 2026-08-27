# Session Continuation — PR Review Tool

**State:** **M0 ✅ · M1 ✅ · M2 ✅** — deterministic detectors, baseline/delta scoping, five
adapters of which three drive a real external binary, and **all five have now executed on real
input**. CAP engine verified working.

**Measured, on three pinned corpora** (43 stored runs in `benchmark/results/`, every number in
`BENCHMARK_STATUS.md`):

| | negative — 50 merged PRs | labelled — 26 GHSA advisories | IaC — 20 PRs |
|---|---|---|---|
| false positives per PR | 0.24 (12/50) | 0.04 (1/26) | *coverage corpus, not a rate* |
| recall · in scope | — | 0.028 · 0.111 | — |
| head run | `2026-08-08-decisions/` | `2026-08-09-labelled-receivers/` | `2026-08-19-iac-secretsfix/` |

**Recall has a ceiling of 0.250 on that corpus** — 27 of 36 ground-truth rows name weaknesses no
detector here can express (errata §14.42, corrected in §14.45). Never quote 0.028 without it. The
in-scope column is the honest reading and is unaffected by the correction. **The single finding both
figures rest on was audited 2026-08-24 and is genuine** — right line, right CWE, and selected out of
four same-family hits in that file by delta scoping (§4o).

**And recall is the axis this tool is worst at.** The stage that matters most for the numbers above
is delta scoping: it drops **75 of 87 raw findings** on the negative corpus and **70 of 72** on the
labelled one, taking false alarms from 1.74/PR to 0.24. Nothing reported that until 2026-08-22
(§14.46) because every metric here scores what the tool *reported* and this stage's whole effect is
on what it did not. See `BENCHMARK_STATUS.md` §4j.

> ### ⚠️ The project pivoted on 2026-08-21. Read this before anything below.
>
> **The AWS credentials are not coming, and the project stopped waiting for them.** M3 (agentic
> families), M4's verifier and M5's RLM are **out of scope permanently on this branch** — not
> deferred, not next. `PIVOT_PLAN.md` is the descoping record and `README.md` §Scope is the
> one-page version.
>
> What was built instead, on the credential-free surface: `models/claude_cli.py` (the
> `ModelProvider` seam, filled over the `claude` CLI), `GitCheckout` wired into `cli.review`, and
> **the five-arm comparison** — semgrep-alone, this pipeline, pipeline + live triage, a raw
> diff-only LLM, and (from 2026-08-26) the same LLM fed the pipeline's own context bundles — on a
> post-cutoff temporal holdout (`BENCHMARK_STATUS.md` §4i, §4x).
>
> **The headline result is not flattering and is the most useful thing here.** On the ground truth
> this pipeline can express, a diff-only LLM at `--effort low` finds **eighteen times** as much
> (18/36 against 1/36), for $0.014 a case. That prices what the unbuilt agent layer would have to
> earn. *(It read "five times" until 2026-08-26, when a scoring defect that had understated every
> LLM arm by a third was found and fixed — errata §14.59. No run changed; the scorer did.)*
>
> **And on 2026-08-26 that budget was tested rather than only priced.** `ContextBundle` — the exact
> payload a Phase-3b agent was specified to receive — was captured and handed to the same model
> alongside the same diff. **It did not review any better**: recall 15–20 of 36 against arm 3's
> 17–18, precision 0.50 against 0.51, over three passes each. The context is not inert — it makes the
> model report missing authorization where it otherwise reports nothing — but it did not make it
> better. `BENCHMARK_STATUS.md` §4x; `REPORT.md` §5.3 for the four measured reasons that is a floor
> rather than a verdict.
>
> **Then 2026-08-22 measured the pipeline's own best axis, and moderated it.** Delta scoping is a
> 7.25× reduction in false alarms and had never been reported. But arm 3b — the same LLM baseline
> with **one instruction changed**, asking for introduced-only findings — reported **0 · 0 · 1
> false alarms on 26 control PRs across three passes**, against the baseline prompt's 3 · 5 · 4:
> **at or below** this pipeline's 1. So the suppression is real and it is *not* a capability only a
> base-tree scan can buy (§14.47, replicated and narrowed to that range in §14.51 — this banner read
> "0 … below this pipeline's 1" until 2026-08-24, from the single pass §14.47 had).
> Three more defects came out of that day:
> §14.48 (the degraded `--no-checkout` path scores better by losing a true HIGH) and §14.49 (the
> baseline cache had no version key, and a taxonomy remap silently tripled reported findings).
>
> Sections below dated before 2026-08-21 still describe M3 as "next". They are kept as the record
> of what was believed then; this banner overrides them.

**Start the next session at `OPEN_ITEMS.md`, then `README.md`, then `REPORT.md`.**

> ### 🔎 If the next session is a review rather than a build
>
> **All three of the claims previously listed here were attacked on 2026-08-24. Two held, one did
> not, and none of them is the place to start now.**
>
> 1. **The recall ceiling (0.250).** ✅ Re-derived from source by two independent paths —
>    `llm_arm.reachable_ground_truth` through the registry union widened by `_CWE_GROUPS`, and
>    `scope.is_in_scope` through the detector tables. Both return **9 of 36**. The figure holds; what
>    did not was three *docstrings* still quoting the pre-correction 0.364, in modules the 2026-08-22
>    documentation sweep never searched (§14.50).
> 2. **The suppression figures (86% / 97%).** ✅ Unchanged and re-verified — but arm 3b is no longer
>    n=1, and settling it **cost this claim its consolation**. Three passes: the suppression
>    replicates (control-half 0 · 0 · 1 against 3 · 5 · 4) while the recall cost §14.47 reported does
>    not exist. The prompt change is closer to free than the report allowed (§14.51).
> 3. **Every stored false-positive rate.** ✅ Measured at **nil**. All 17 baseline caches deleted,
>    both corpora re-run cold, identical on finding identity (12/12, 37/37). §14.49's mechanism is
>    real and did not reach these corpora (`BENCHMARK_STATUS.md` §4l.1, `OPEN_ITEMS.md` §23 closed).
>
> **Second rotation, 2026-08-24 (later the same day).** The three this block nominated next — §10,
> §17, §21 — were all worked in the same session and are no longer the place to start either. §10's
> five named patterns were censused and **all five are correct** (§4m); §17's reader was built and
> measured, and found that **nothing consumes the flag for IaC findings** (§4n); §21's trigger was
> made mechanical and **fired immediately** — the CLI had already moved to 2.1.241, floor 7,777
> (§4l.3, §4l.4).
>
> **Third rotation, 2026-08-25.** Plan 3's Steps 0, 1 and 1b landed and moved two things off this
> list before spending a dollar. The filter-recall bound the arm was supposed to be limited by is
> **measured and does not bind** — 36/36 ground-truth rows land inside a bundle the model would
> receive (§4p) — and the cost half of the pipeline's premise is measured on both corpora (§4p.1,
> §4p.2). **What replaced them is sharper than either**: §14.56 caught a correct number promoted to
> a law about diffs one paragraph after it was taken, which is the fourth instance of that move in
> the errata (§14.20, §14.34, §14.42). **The nomination is therefore the class, not an item** — sweep
> the published figures and ask of each one which set it was measured over, because the set is
> almost never in the sentence. Start with `REPORT.md` §3 and the scorecard's headline table.
>
> **Fourth rotation, 2026-08-26.** Plan 3 completed, and the two things it found were both in the
> **apparatus**, not the tool. The scorer was counting a child CWE as a false positive, worth a third
> of every LLM arm's recall and **nothing at all to the pipeline's** — a bias against one kind of arm
> that looked perfectly neutral (§14.59). And a guard raised before the scorecard was written,
> destroying five paid corpus passes and $4–22 that cannot be derived from disk (§14.60).
>
> **The nomination is again the class rather than an item, and it is sharper than the third
> rotation's.** Every arm here is run three times, pre-registered, and re-derived from a stored
> artifact. **The scorer that judges them and the harness that runs them get none of that**, and both
> broke on the same day. Ask of any measurement apparatus: what would tell me it is wrong, and does
> anything currently check it? `recall_ignoring_cwe` exists because the answer for the scorer was
> "nothing" — it is a second, independent way of asking the same question, which is the only reason
> §14.59 was findable at all.
>
> **The three worth attacking now**, in order of how much weight they carry against how little
> measurement is under them. (Item 1 below is kept struck through rather than deleted: it was the
> block's top nomination for a day, and what discharged it is the template for items 2 and 4.)
>
> 1. ~~**Recall's entire numerator is one finding.**~~ ✅ **Audited 2026-08-24 and it holds**
>    (`BENCHMARK_STATUS.md` §4o). `tar.extractall(local_download_folder)` at `penelope.py:3418` is
>    the exact call **CVE-2026-50558** names and the exact line the fix replaced with
>    `safe_tar_extractall`; line 3418 sits inside ground-truth span `[3415,3421]` and `CWE-22`
>    matches `CWE-22`. The reverse-fix coincidence objection does not hold either: ground truth is
>    14 lines of a 5,911-line file, and the same detector fired **four times in that file** while
>    delta scoping dropped the three pre-existing ones and kept the rewritten one. Recall 0.028 and
>    0.111 are now verified rather than asserted. n=1 is still n=1.
> 2. **The IaC corpus's whole yield is 32 findings from 3 PRs in 2 repositories**, every one a
>    checkov check on a `docker-library` Dockerfile — and it has now been **decided** those are
>    true findings with the wrong address (§17). So "`iac.py` runs on real input" is carried by an
>    extremely narrow base, and the base is one the project has agreed is mis-targeted.
> 3. **§11 — `open` is 2,828 receivers and is both a source and a sink.** Since §4m cleared the five
>    patterns around it, this is now the **largest unmeasured pattern in the catalog**, and the one
>    the taint engine leans on hardest.
> 4. **The other headline number has never had the audit §4o just gave recall.** `0.24 FP/PR` is
>    **12 findings across 50 merged PRs**, and not one of them has been read. `REPORT.md` §5.6 limit 4
>    already concedes why this matters: a merged PR from a healthy repository can still contain a
>    real vulnerability, and any such finding is counted against the tool — so 0.24 is an **upper
>    bound**, and nobody knows how loose. This is the exact question §4o asked of the 1, asked of the
>    12, and it can only move the number in the tool's favour. Twelve findings is an afternoon.
>
> **Newest live behaviour, least battle-tested:** `classify.is_generated` reads header markers as of
> 2026-08-24. It was calibrated over 305,861 files and verified not to move any scored finding, but
> it is one day old and it suppresses. If something goes quiet that should not have, look there
> first (`BENCHMARK_STATUS.md` §4n).

> ⚠️ **The work is on a branch, not on `main`.** `m2-detector-suite` is several commits ahead of
> `main`, which still stops at M1. Merge with
> `git checkout main && git merge --ff-only m2-detector-suite`, or keep working on the branch —
> but do not start from `main` expecting `detect/runner.py` to exist.

> This file is *where we are and how to run things*. Design intent is in `PR_Rev_0620.md` (locked
> outline) and `plan/` (9 docs). Build records: **`M1_STATUS.md`** (phases 1–2, CAP defects,
> `safety/`), **`M2_STATUS.md`** (detector suite, delta scoping, what is unvalidated and why) and
> **`BENCHMARK_STATUS.md`** (the measurement harness, all three corpora, all 43 stored runs, and every defect with
> what actually landed for each). **`OPEN_ITEMS.md`** is the short list of things found and *not*
> fixed — read it before picking up anything else.
> **The working plans in `~/.claude/plans/` are retired scratch, not a record** (§9). They are
> outside version control, one per session, and the least reliable copy of anything — this
> session's own contained a part that was later argued against and removed. Everything still true
> has been folded into these docs.

---

## 1. How to resume (environment — ephemeral, not in the design docs)

- **Working dir:** `/Users/davidsy/PR Review 2026` · git repo, **currently on branch
  `m2-detector-suite`** (first commit 2026-08-05 at the end of M1; `main` stops at M1 and the two
  M2 commits are ahead of it — see the banner above). No remote. `cap_engine/` is a *separate*
  repo nested inside it.
- **`cap_engine/` is gitignored, and that is a licence control, not tidiness.** §13.3 commits this
  tool to being open-sourceable; errata §14.1 records that CAP's licence contradicts that, and
  CAP-lite is the deferred resolution. Keeping the restricted tree out of version control is what
  stops the contradiction from becoming a distribution. It is installed separately. Also ignored:
  `.venv/`, `.pr_review/` (run artifacts + profile cache), `.state/` (CAP's CGP session DB),
  `.claude/`, and the usual build/cache dirs.
- **Python 3.13.7**, venv at `.venv/` (gitignored). Editable installs: `pr-review` **and**
  `cap-engine` (`pip install -e cap_engine/'[tree-sitter]'` → rustworkx 0.18, tree-sitter 0.26 +
  python/java/js grammars).
- **Installed 2026-08-05:** `semgrep` 1.172.0, `osv-scanner` 2.4.0, `checkov` 3.3.0 — all three
  adapters are now validated against the real tools (`M2_STATUS.md` §5). Still missing: `gh`,
  `gitleaks`, `codeql`. **No AWS/Bedrock access** — the agent layer still runs on a fake provider.
- **Run the tool:**
  ```bash
  # offline, full thread including Phase 1 + 2 (--base-dir enables profiling)
  .venv/bin/pr-review review --repo o/r --pr 7 --diff-file tests/fixtures/phase2_pr.diff \
      --base-dir tests/fixtures/sample_app
  # M2 thread: both checkouts, so the structural detector and the baseline both run
  .venv/bin/pr-review review --repo o/r --pr 9 --diff-file tests/fixtures/m2_pr.diff \
      --base-dir tests/fixtures/m2_base --head-dir tests/fixtures/m2_head   # FLAGGED, exit 1
  .venv/bin/pr-review review https://github.com/owner/repo/pull/1     # needs gh
  .venv/bin/pr-review extract --repo o/r --pr 1 --diff-file tests/fixtures/sample.diff
  .venv/bin/pr-review profile tests/fixtures/sample_app --repo o/r --sha <sha> [--rebuild]
  ```
  `--base-dir` is the checkout at `base_sha` (profiling + the "before" side of the AST compare);
  `--head-dir` is the checkout at `head_sha` (code slices + the "after" side). **Passing the same
  path to both is refused** — it would make every file AST-equal to itself and drop the whole PR.
  Without `--base-dir` the run still completes, with Phase 1 skipped *loudly* in `telemetry.json`.
- **Run the benchmark** (`pr_review/benchmark/`, no model, no credentials):
  ```bash
  # re-run the pinned 50-PR negative corpus -> benchmark/results/<date>/negative.md
  # ~20 min warm; a bumped ANALYZER_VERSION makes every case a cold profile build, so budget an hour
  .venv/bin/python -m pr_review.benchmark run --corpus benchmark/corpus/negative.json
  # the labelled GHSA corpus (52 cases, ~15 min). --cold-profiles is REQUIRED here:
  # without it the second case in a repo patches the first one's profile, so the two
  # halves of a pair are built by different code paths (`runner._isolated`).
  .venv/bin/python -m pr_review.benchmark run --corpus benchmark/corpus/labelled.json \
      --cold-profiles --label labelled
  # re-measuring the SAME day: label it, or the write refuses rather than overwrite
  .venv/bin/python -m pr_review.benchmark run --corpus benchmark/corpus/negative.json \
      --label after-fix
  # re-derive a scorecard from a stored run — seconds, no pipeline, no checkouts
  .venv/bin/python -m pr_review.benchmark rescore \
      --run benchmark/results/2026-08-07-labelled/run.json --label retaxonomy
  # regression gate: integer ratchets against a pinned baseline. 0 pass / 1 regressed /
  # 2 could not compare (different corpus, different case set, stale dump). See gate.py.
  .venv/bin/python -m pr_review.benchmark gate \
      --baseline benchmark/results/<pinned>/run.json \
      --run benchmark/results/<new>/run.json
  # on a machine without the checkouts, re-extract them from the pinned shas first
  .venv/bin/python -m pr_review.benchmark run --corpus benchmark/corpus/negative.json --rehydrate
  # build a new corpus (GH_TOKEN optional; unauthenticated is 60 API req/hr)
  .venv/bin/python -m pr_review.benchmark build --repos o/r,o2/r2 --per-repo 5 \
      --criteria "how these were chosen — printed verbatim in every scorecard" \
      --out benchmark/corpus/negative.json
  # rebuild the labelled corpus from the advisory feed (same command + same
  # exclusions = same corpus). Its spans are CANDIDATES — read
  # benchmark/corpus/labelled-verification.md before quoting a number from it.
  .venv/bin/python -m pr_review.benchmark build-labelled --advisories 80 --per-repo 2 \
      --exclude benchmark/corpus/labelled-excluded.txt --criteria "..." \
      --out benchmark/corpus/labelled.json
  ```
  `--keep-runs DIR` retains the per-case run directories so a number can be audited back to the
  run that produced it. Corpus and results are **committed**; the checkouts live in the gitignored
  `.pr_review/cache/` (**6.9 GB** for both corpora — two extracted trees per case, plus mirrors).

  ⚠️ **Changing how a profile is built? Bump `profile/cache.py:ANALYZER_VERSION`.** Cached profiles
  are keyed on the repo sha and the artifact layout — neither moves when you fix an extraction rule
  in `promote.py`, `cpg.py` or `patterns/*.yaml`. Without the bump a re-run loads profiles built by
  the old code and reports that your fix did nothing, silently (errata §14.25). Bumping forces a
  full profile rebuild per repository, which is most of a re-run's cost.
- **Run tests:** `.venv/bin/python -m pytest tests/ -q` → **616 pass** (~100s; the scanner
  integration tests run real binaries and skip when one is absent).
  CAP's own: `cd cap_engine && ../.venv/bin/python -m pytest tests/ -q` → **4 pass**.
- **Exit codes:** 1 = flagged, 0 = approved, 2 = tool/usage error. Run artifacts land in
  `.pr_review/runs/<repo>/<pr>-<sha|LOCAL>/` — `00_manifest.json`, `01_profile.ref`,
  `02_changeset.json`, `02_context_bundles.json`, `03a_candidates.json`,
  `03d_findings.normalized.json`, `telemetry.json`, `report.*`. Caches in
  `.pr_review/cache/<repo>/` — `profile/` and `baseline/`.

## 2. CAP engine — resolved and working

`cap_engine/` holds `querykv/cap-mapt` (~10.6K LOC, 62 modules), a **transcription from
photographs** of the original CAP source. Separate git repo, **restricted licence**.

**Verified working 2026-08-04** — it had never been executed before this session. `build_cache`
parses cleanly, `CAPFramework` constructs, the 7-step workflow completes end to end.
**`cap_engine/`'s working tree is clean: zero edits.** Two defects found and handled; three
ParseCache gaps worked around. All of it is in `M1_STATUS.md` §3.

**The static audit behind "faithful reconstruction"**, run independently of CAP's own
`ARCHITECTURE.md` rather than taken from it — folded in here 2026-08-09 from a working plan, so it
stops living only outside version control:

| Check | Result |
|---|---|
| All modules parse (AST) | **62/62, 0 syntax errors** |
| Internal `from cap_engine.X import Y` resolution | **0 unresolved** |
| Risky `UNCERTAIN` attribute/method targets (9 sampled) | **9/9 resolve** |
| Stub bodies (`NotImplementedError` / `TODO` / `pass`-only) | **0** |
| Leftover transcription artifacts (`## IMAGE ##`, `--- image N ---`) | **0** |

Of the 60 `UNCERTAIN` markers in code, roughly a third are cosmetic (truncation limits, prompt
phrasing, pricing) and a third are name or signature guesses that verify against their definitions.
The residual risk was concentrated in three external contracts, two of which are now M1 blind spots
§4.2 and §4.3. **What separated "plausible" from "working" was one runtime smoke test that had
never been run** — CAP's own §8.4 said so outright, and running it is what found the two defects.

**Three rules that will bite you if forgotten:**

- **Import CAP by fully-qualified submodule path.** `from cap_engine import CAPFramework` fails
  from the repo root (namespace-package shadow) and succeeds everywhere else — so it fails only in
  the CLI. Use `from cap_engine.config.framework import CAPFramework`.
- **Call `cap_compat.apply()` before running a multi-step workflow.** Without it, two steps
  starting in the same second abort the run with `CGPError [-32012] Session already exists`.
  `security_profile.py` does this for you.
- **Never commit `cap_engine/` into this repo, and never edit it.** Workarounds go in
  `pr_review/cap_compat.py`; the `.gitignore` entry is the licence control described in §1. CAP
  imports stay confined to `profile/promote.py`, `profile/cpg.py`, `profile/security_profile.py`,
  `profile/incremental.py`, `models/framework.py` and `cap_compat.py`, which bounds the eventual
  CAP-lite retrofit. **Nothing in `change/` imports CAP** — Phase 2 uses tree-sitter directly.
- **Do not reach for `ParseCache.refresh()`.** It looks like the incremental hook and is not one:
  it re-parses by mtime over files it *already knows*, so it never sees a file a PR adds, and it
  updates neither the call graph nor the type hierarchy — taint would silently vanish.
  `profile/incremental.partial_cache()` is the supported path.

**Decisions taken 2026-08-04:** CAP-lite **deferred** (import `cap_engine` directly; keep the
imports confined so the later retrofit is bounded) · CAP's config assets **authored from scratch**
into `pr_review/prompts/`, not the restricted tree · M1 built against a **fake provider**.

## 3. What exists on disk

| Path | What |
|---|---|
| `PR_Rev_0620.md` | **Locked outline** (decisions §13, implementation errata §14). Design intent. **The errata log stops at §14.33 (2026-08-08) and is three sessions behind** — **Caught up 2026-08-09 with §14.34–14.39**, which is now the single home for a reusable lesson. |
| `plan/00-overview.md` | Architecture, stack, layout, data contracts, **milestones M0–M6**. |
| `plan/cross-cutting.md` | Finding schema, taxonomy, severity/confidence, trust, config, gating. |
| `plan/phase-0..4-*.md` | Per-phase plans. `plan/benchmark.md`, `plan/tooling.md` — eval harness; 31-component inventory. |
| **`M1_STATUS.md`** | **M1 build record: what was built, the reasoning, CAP defects, blind spots, next step.** |
| **`M2_STATUS.md`** | **M2 build record: detector suite, delta scoping, and §5 — what first contact with the real scanners broke.** |
| `context_assembly_writeup.md` | CAP paper. §9 = the only surviving workflow YAML example; §7 = the `structured`-dict CSV trick the matrix depends on. |
| `cap_engine/` | The dropped-in CAP package. Separate git repo, restricted licence, **unmodified**. |
| `pr_review/` | M0–M2 code. Nothing in `change/` imports CAP. |
| `pr_review/prompts/` | Authored CAP assets: 3 personas, `security-profile.yaml`, 7 tasks, 8 templates. |
| `pr_review/safety/` | All three code mechanisms of cross-cutting §9: `wrap.py` (placement), `sentinel.py` (detection, runs **before** the filter), `permissions.py` (persona tool binding). |
| `pr_review/detect/` | 3a: `normalize.py` (rule→taxonomy + SARIF), `structural.py` (our CPG), `sast_semgrep.py`, `sca.py`, `iac.py`, `secrets.py`, `runner.py`. |
| `pr_review/findings/` | 3d: `validate.py`, `dedup.py`, `delta.py` (baseline + scoping), `normalize.py`. `merge/severity/calibrate/suppress` are M3–M4 and absent. |
| `pr_review/benchmark/` | The measurement harness (`plan/benchmark.md`, narrow 3a scope): `schema.py` (BenchCase/GTVuln/PRTask/AdvisoryRef), `corpus.py` (negative set), `ghsa.py` (labelled set), `runner.py` (drives the real `run_review`; serializes a run), `scoring.py`, `scope.py` (what 3a can express), `metrics.py`, `report.py`. No model, no credentials. |
| `benchmark/corpus/negative.json` | **Committed, pinned** 50-PR negative corpus (repo + PR + both shas + diff). 7 MB — one netbox PR carries a 4.3 MB diff, kept because dropping an outlier after seeing it would break the selection criteria. |
| `benchmark/corpus/labelled.json` | **Committed, pinned** 26-advisory / 52-case GHSA corpus (each advisory = a reverted fix + the fix itself as its control). Siblings: `labelled.md` **generated** by the builder and rewritten every build; `labelled-verification.md` **hand-written**, the curation record; `labelled-excluded.txt` the hand rejections, applied with `--exclude` so the corpus stays rebuildable. |
| `benchmark/results/<date>[-label]/` | `<corpus>.md` — generated scorecard. `run.json` — the serialized run, which `rescore` re-derives every number from. `analysis.md` — the hand verification, which is where the defects are written up. A same-day re-run **refuses to overwrite**; pass `--label` for a sibling directory. `2026-08-07/` is the pass-1 baseline, `-after-fixes/` and `-defect2/` the re-measurements, `-labelled/` is pass 2, `-selfpair/` and `-labelled-selfpair/` are the state after the taint fix, `2026-08-08-lockfiles/` + `-labelled-lockfiles/` are the lockfile measurement, and
`2026-08-08-decisions/` + `-labelled-decisions/` were the head until 2026-08-09. **Current head of
each of the three corpora: `2026-08-08-decisions/` (negative, still at `ANALYZER_VERSION` 6 —
§4), `2026-08-09-labelled-receivers/` (labelled) and `2026-08-19-iac-secretsfix/` (IaC).** **Give
each corpus a different label**: the markdown is named per corpus but `run.json` is one per
directory, so a shared label loses the second run's dump *after* it has run (`OPEN_ITEMS.md` §4). |
| `benchmark/corpus/iac.json` | **Committed, pinned** 20-case IaC corpus, added 2026-08-09 — two Terraform-module and two Docker-image repos, the first thing to run `detect/iac.py` on real input (`BENCHMARK_STATUS.md` §4h). Repositories were screened for IaC content; **pull requests were not**, which keeps the negative corpus's rule. |
| `tests/` | 34 files, 894 tests (`test_ghsa.py` builds a local git repo with a vulnerable commit and its fix, `test_cpg_selfloop.py` pins the dual-role source/sink guards — neither needs the network). `fixtures/sample_app/` is the hand-labelled profiling target; `fixtures/phase2_pr.diff` is the 10-file PR that exercises every filter tier; `fixtures/injection_pr.diff` carries four injection payloads; `fixtures/m2_{base,head}/` + `m2_pr.diff` are the detector fixture's two checkouts; `semgrep.sarif` / `checkov.sarif` / `osv.json` are recorded from real tool output; `iac_sample/` is what Checkov scans. |
| `~/.claude/plans/*.md` | Six working plans, one per build session, outside the repo. They are **scratch, not a record** — anything from them that still matters has been folded into the status docs, and nothing here should be the only place a decision lives. `melodic-bubbling-raccoon.md` (M1 assessment + CAP audit) is the one with content the status docs never fully absorbed. |

## 4. Milestones

`plan/00-overview.md` §6: **M0 ✅** → **M1 ✅** → **M2 ✅** → M3 agentic families → M4
verifier+pipeline → M5 orchestration+registries → M6 benchmark+ship.

### 4.0 Scope statement — designed vs built, stated once

**Everything below this line that predates 2026-08-21 assumes M3 is next. It is not.** This is the
authoritative statement of what exists; `README.md` carries the reader-facing version and
`PIVOT_PLAN.md` the reasoning.

| | milestone | state |
|---|---|---|
| Phase 0 extraction | M0 | ✅ built, exercised on real PRs |
| Phase 1 profiling + CPG | M1 | ✅ built, incremental (50–144×) |
| Phase 2 change analysis | M1 | ✅ built; tier 3 triage now runs against a real model |
| Phase 3a deterministic detectors | M2 | ✅ five detectors, all on real input |
| Phase 4 findings + report + gate | M0–M2 | ✅ markdown, SARIF, JSON, delta scoping |
| **Phase 3b agentic families** | **M3** | ❌ **not built, permanently out of scope here — but its designed *input* has now been measured, see below** |
| **Phase 3c adversarial verifier** | **M4** | ❌ not built |
| Phase 5 orchestration, RLM, registries | M5 | ❌ not built |
| GitHub write path (comments, SARIF upload) | M5 | ❌ not built, and **cut deliberately** |
| Per-PR HTML dashboard | M5 | ❌ not built, and **cut deliberately** (`PIVOT_PLAN.md` §3) |
| Benchmark harness | M6 | ✅ ~65% — harness, three corpora, gate, scorecards, comparison |
| Calibration / ECE / threshold tuning | M6 | ❌ needs a model |
| CodeQL baseline column | M6 | ❌ `detect/codeql.py` never built |

> **Phase 3b is still not built, and as of 2026-08-26 something is known about what it would have
> bought.** `change/context.py` assembles a `ContextBundle` on every run — its docstring reads *"the
> exact context a Phase-3b agent receives for one group"* — and that payload was captured and handed
> to a model alongside the diff, three passes on each of two corpora. **The model reviewed no better
> than from the diff alone.** That does not build 3b or retire it; it means the premise that
> assembled context makes a reviewer better now has a measurement against it rather than only a
> design document for it. `BENCHMARK_STATUS.md` §4x, and `REPORT.md` §5.3 for the four measured
> reasons the result is a floor.

**One dependency explains every ❌ except the two marked "cut".** M3, M4's verifier and M5's RLM
all need a model provider, and the AWS Bedrock credentials this was built against never arrived.
`models/bedrock.py` was deliberately not written blind (`M1_STATUS.md` §5.3): a provider that has
never spoken to its service is a guess with tests attached.

`models/claude_cli.py` fills the same **`ModelProvider`** seam over the `claude` CLI and proved the
seam is real — it runs tier-3 triage live and produced the LLM baseline. It does **not** discharge
§5.3, and it deliberately does not implement CAP's **`InferenceProvider`**: flattening that
interface's `system_prompt_parts` destroys the prompt-cache breakpoints Phase 1 exists to buy, so a
shimmed CAP run could demonstrate the thread end to end and could not validate the efficiency claim
(`PIVOT_PLAN.md` §1.0). If it is ever revisited it is a **labelled demonstration only**, never an
efficiency measurement.

**The seams M3 attaches to, so resuming is a build and not a rewrite:**

| seam | file |
|---|---|
| `DetectorKind.AGENT` | `pr_review/schema.py` |
| `ModelProvider` | `pr_review/models/provider.py` |
| `PRFramework` / `build_framework` | `pr_review/models/framework.py` |
| authored CAP assets | `pr_review/prompts/{personas,tasks,workflows,templates}` |
| the input agents consume | `change/classify.py` → `candidate_families`, `coverage_plan` |
| tool permissions | `pr_review/safety/permissions.py` |

`analyze/` is absent because building it *is* M3.

> **Read the three known input defects below before wiring the BAC agent to any of these seams**
> ("The only blocker is credentials", two paragraphs down). They are not seam problems — every seam
> here is sound — they are defects in what the seams *carry*, and one of them
> (`OPEN_ITEMS.md` §9, any `Depends()` counting as a guard) is a deliberate trade whose reasoning
> **expires the moment an agent is deciding this rather than a lookup**. That is the condition M3
> creates, so the trade wants re-reading at the start of M3 rather than after it.



**What resuming would cost, and what it would have to beat.** M3 was estimated at 4–8 sessions and
the provider was never the bulk of it — BAC family logic (role discovery, endpoint mapping, matrix,
diff overlay) is model-agnostic. The bar it has to clear is now measured rather than assumed: a raw
diff-only LLM at `--effort low` scores **0.556–0.667** on the reachable stratum against this
pipeline's **0.111**, at $0.014 per case. An agent layer that costs more than that and finds less
is not worth building, and until 2026-08-21 there was no way to know which side of that line it
would fall on.

**M3 readiness, checked 2026-08-09.** Everything M3 dispatches on exists: `DetectorKind.AGENT`
(`schema.py`), the `ModelProvider` seam (`models/provider.py`, `fake.py` behind it), `PRFramework`
+ `build_framework` (`models/framework.py`), the authored assets in `pr_review/prompts/`, and —
the input that matters — `candidate_families` and `coverage_plan`, populated per group by
`change/classify.py`. `analyze/` is absent because building it *is* M3.

**The only blocker is credentials.** But three known defects sit in the BAC agent's flagship input,
all already assigned to M3, and they should be read before it is built rather than discovered by it:
defect 4 (authz enforced imperatively in a callee — 9 of the negative corpus's 11 `missing-authz`),
`OPEN_ITEMS.md` §9 (**any** `Depends()` counts as a guard, so the matrix can report
`auth_pattern: dependency:get_db`), and Django route resolution (4 of 11 fixture matrix rows still
read `(unresolved:ViewName)`, `M1_STATUS.md` §5.3).

**M1 acceptance is met on the fixture, both phases.** Phase 1 (phase-1 §11): cold profile →
11/11 correct access-control rows; CPG with endpoints/sources/sinks + 2 taint paths; warm re-run
end to end (0.099s → 0.0013s); dep-manifest change rebuilds; docstring change stays incremental.
Phase 2 (phase-2 §8): 6 coherent change groups with correct `touches`, sensible family routing,
minimal bundles (3 `none` / 2 `full_file` / 1 `multi_hop`), every drop audited, and **100% recall
on the labelled vuln-bearing set**. Evidence tables in `M1_STATUS.md` §1.

**Incremental profiling landed 2026-08-05** (`profile/incremental.py`), closing M1's largest
debt. `drift.decide()`'s third outcome now patches instead of rebuilding: **50× cheaper on a
54-file repo, 144× on 304 files**, with a matrix identical to the full build in both cases. Cost is
priced by the change, not the repo, so the ratio grows with repo size — the shape Principle #4
needs. Reasoning and measurements in `M1_STATUS.md` §5.1.

**`pr_review/safety/` completed 2026-08-05** (`M1_STATUS.md` §5.2), closing M1's second debt.
All three of cross-cutting §9's code mechanisms exist: `wrap.py` (placement), `sentinel.py`
(detection — 5 rules, 3 of which can fail the gate, running against the manifest **before** the
noise filter), `permissions.py` (persona tool binding, planner source-free). Two things it turned
up: the **PR body was never captured** anywhere despite phase-0 §4 (errata §14.13), and
`report/markdown.py` let crafted evidence break out of its code fence.

**M2 landed 2026-08-05** (`M2_STATUS.md`). `detect/` gained the structural CPG detector plus the
semgrep/sca/iac adapters and a shared normalization spine; `findings/` gained validate, dedup and
**baseline/delta scoping**, which closes the M0 simplification where `secrets.py` hardcoded
`introduced_by_pr=True` and the gate could not tell introduced from pre-existing. Accepted on
`m2_{base,head}`: 6 findings, 4 introduced / 2 pre-existing, 1 gate trigger. Three errata came out
of it — §14.15 (structural needs a head-side graph), §14.16 (dedup had no provenance field),
§14.17 (the baseline is not a whole-repo run, and fingerprints only match if both sides read
source the same way).

**The three external scanners were then installed and every adapter was found broken** — errata
§14.18, with the defect table in `M2_STATUS.md` §5. Nothing was wrong with the parsers; the wrong
things were the CLI contracts the fixtures encoded (semgrep's exit 2 on an unresolvable
`--baseline-commit`, checkov writing SARIF to a file it names itself, osv-scanner's absolute paths
and alias groups) and a mapping table in which five of six semgrep rule ids did not exist. With
all scanners on, the fixture thread produces **7 findings, 5 introduced / 2 pre-existing, 1 gate
trigger**.

### ⏭ Next

1. ~~Install the three scanners and run each once.~~ **Done 2026-08-05** — every adapter was
   broken in a way its fixture could not show (errata §14.18); all fixed and re-tested,
   `M2_STATUS.md` §5 has the table.
2. ~~Get every adapter onto real input.~~ **Done 2026-08-09** — the IaC corpus was the last one
   (`BENCHMARK_STATUS.md` §4h), and first contact broke it in three more places.
3. **`models/bedrock.py`** — M1's last debt (`M1_STATUS.md` §5.3), still **blocked**: no AWS
   credentials, no `boto3`, no `strands-agents` here, and §5.3's reasoning for not writing it
   blind stands. **M2 proceeded without it as predicted; M3 cannot** — against a fake provider
   the agent lift is scripted JSON, tier-3 triage exercises labels but not judgement, and every
   cost number is a zero meaning "unmeasured". **This is the only thing blocking M3**; §4 above
   lists what is already in place and the three known input defects to read first.
4. **M3 agentic families** (BAC flagship), then `findings/merge.py` to weigh the agreement signal
   `provenance.also_detected_by` now records. Smaller credential-free items: `M2_STATUS.md` §4.8,
   and the open items in `OPEN_ITEMS.md` — §3 (two catalog gaps) and §11 (`open`, 2,828 receivers,
   both a source and a sink) are the ones with measurements attached. §10 stood here until
   2026-08-24, when its five named patterns were censused over 946 nodes and **all five came back
   correct** (`BENCHMARK_STATUS.md` §4m); §11 is what the census left as the largest unmeasured
   pattern in the catalog.

### ✅ The 2026-08-07 agenda — done, and what it turned into

The recommendation was "fix the safe defects and re-measure before building anything new." That
ran to completion: **four of the five defects are fixed and re-measured, 1.96 → 0.22 FP/PR.**
Defect #4 stays deferred to M3 by design. Detail in `BENCHMARK_STATUS.md` §3 and §4.

Two lessons from doing it, both worth more than the number:

- **The scorecard is a bad severity proxy.** Defect #2 was rated "1 false positive, recall risk,
  defer" — reading the cached profiles instead showed **46% of the access-control matrix was
  `@patch(...)` mock targets**, 99.8% for Saleor. A defect is only counted by the benchmark when it
  lands inside a diff, so profile-wide corruption prices at ~nothing. Defect #5 was similar: its
  failure was per-invocation, not per-file. **Check the artifact, not just the metric.**
- **Two of the three "proposed fixes" in the status doc were wrong**, and cheaply so — they were
  written from the symptom without checking what else the rule touched. Both are recorded in §4
  next to what actually landed, because the reasoning is the reusable part.

### ✅ Pass 2 — done 2026-08-07

Built and run: `pr_review/benchmark/ghsa.py` (advisories → reverted fixes + post-fix controls), a pinned
26-advisory / 52-case corpus over 18 repositories, `CorpusRun` serialization with a `rescore`
subcommand, `--cold-profiles`, the in-scope stratum, the pair table, and baseline attribution.
**Recall 0.028 (1/36), 0.111 in scope, 0.04 of pairs discriminated, 0.00 gate-relevant false
positives, filter ablation 36/36.** Zero case errors, run twice with identical numbers.
Full record in `BENCHMARK_STATUS.md` §3b; hand analysis in
`benchmark/results/2026-08-07-labelled/analysis.md`.

Three things it turned up that the negative corpus structurally could not:

- **The detectors are mis-aimed, not blind.** 4 of 9 in-scope misses had a taxonomy-matching
  finding in the right file at the wrong lines — a taint detector reports at the sink, and a fixing
  commit's ground truth sits where the missing validation went. **Delta scoping, the obvious
  suspect, cost exactly zero recall.**
- ~~**A whole false-positive class**: 10 of 11 FPs are in the security regression tests the fixes
  ship with.~~ **That reading was wrong, and the correction is the more useful finding.** Reading
  the flows showed `source` and `sink` were the *same node*: `open`, `requests.get` and `httpx.get`
  are each both a source and a sink in `python.yaml`, so every `open(x)` tainted itself. Test files
  were a symptom — test code just calls `open()` more, and 42 of the same shape were sitting in
  non-test code. Fixed in two guards, **0.42 → 0.04 FP/PR with every signal number unchanged**
  (errata §14.31).
- **A corpus of fixes is not a corpus of PRs.** Every property above follows from that, and none of
  it was visible on 50 ordinary merged PRs.

### ⏭ The recommended agenda, from here

**Everything deterministic on this list is now done** — pass 2 acted on (§4b, §4c), five lockfile
formats read (§4d), the last three agenda items closed 2026-08-08 (§4e), and every adapter is
on real input as of 2026-08-09 (§4h). What remains is M3 work, one credential block, and the open
items — **two** detector gaps from the catalog audit (`OPEN_ITEMS.md` §3), not the three it
started with.

Where the numbers actually stand, after all of it:

| | negative (50 merged PRs) | labelled (26 advisories, 52 cases) | IaC (20 PRs) |
|---|---|---|---|
| **False positives per PR** | 0.24 (12/50) | **0.04 (1/26)** | not a precision corpus — see below |
| Gate-relevant per PR | 0.02 (1/50) | **0.00** | 0.00 (was 1 before the `$(...)` fix) |
| Recall · in-scope · pairs | — | 0.028 · 0.111 · 0.038 | — |
| missing-authz per endpoint | 0.149 (11/74) | 0.000 (0/16) | — |
| Findings generated → introduced | — | — | **204 → 32** (delta scoping demoted 84%) |

**The IaC column is coverage, not precision, and must not be quoted as a rate.** Four repositories
across two organisations answers "does the adapter work on real input" — it does — and cannot
support a false-positive number. Its 32 findings are checkov policy defaults on generated
Dockerfiles (`BENCHMARK_STATUS.md` §4h).

The negative corpus's 0.24 and 0.02 are **not** a regression from pass 2's 0.22 / 0.00: the five
lockfile formats gave SCA a dependency delta to read for the first time, and the one HIGH is a
correct finding on a real under-upgrade (§4d). Do not tune it back down.

**The two columns are not at the same analyzer version, and the difference is two bumps, not one.**

| column | run | built at | current |
|---|---|---|---|
| negative | `2026-08-08-decisions/` | **`ANALYZER_VERSION` 6** | 8 — **two bumps behind** |
| labelled | `2026-08-09-labelled-receivers/` | **8** | 8 — current |

The **labelled column was re-measured at 8 and every scored number is identical** (gate PASS), even
though the reported finding count under it fell 59%.

The **negative column has not been re-run since 6**, deliberately, and each skip was argued from a
named mechanism at the time — errata §14.34 for 6→7 (only `fastapi__fastapi` matrix rows moved,
and wagtail's 11 `missing-authz` are django-ninja), §14.35 for 7→8 (that corpus emits **zero** scored taint findings:
29 paths → 9 findings → none surviving delta scoping, and its 12 scored are 11 `missing-authz` plus
1 SCA). Both times the artifact-level check was done instead, which is where the 180 changed matrix
rows and the −1,483 nodes were measured.

Each skip was sound on its own. **Two of them stacked is a different claim**, and nothing said so
until an audit on 2026-08-09 — so if that corpus is re-run, treat it as testing the *conjunction*,
not as a formality. Cost: ~50-60 min, fully cold.

Worth naming the near-miss: two of those rows **do** read taint paths, and saying otherwise would
have been exactly the error this file keeps recording. The labelled FP is `taint-http_outbound` on
`requests.post`; the entire recall numerator is `taint-path` on `tar.extractall`. They held because
`requests.post`, `open` and `extractall` are patterns the narrowing **did not touch** — and
`extractall` now carries a must-not-regress test for it.

| # | Item | Effort | Risk | Blocked by |
|---|---|---|---|---|
| 1 | Defect **4** (imperative authz) | M | **design decision**, not a patch | defer to M3 with the BAC agent |
| 2 | `M2_STATUS.md` §4.8 — suppress.py + allowlist, taxonomy YAML, SARIF suppressions | M | — | — |
| 3 | ~~Three~~ **two** real detector gaps from the catalog audit (`OPEN_ITEMS.md` §3) | M | **neither can move a scored number** — errata §14.35 | `router_kwarg` **done — errata §14.34**; `param_annotations` and the argument-reading pair remain, and `BENCHMARK_STATUS.md` §4g measured what each is actually worth before either is started |
| 3b | Receiver collisions in the rest of the catalog (`OPEN_ITEMS.md` §10) | S | needs a corpus read, not a code read | four patterns **done — errata §14.36**; `from_string`, `mark_safe`, `format_html`, `extractall`, `urlopen` unchecked |
| 4 | `models/bedrock.py` → M3 | L | — | **AWS credentials** — the only thing blocking M3 |
| 5 | `classify.is_generated` cannot see header markers (`OPEN_ITEMS.md` §17) | M | **interface change**; it suppresses 3 detectors, so a false positive loses coverage silently | phase-0 §3 specifies it; 12 IaC findings are on files that say DO NOT EDIT |
| 6 | `CKV_DOCKER_3`'s family, and the fingerprint that blocks fixing it (`OPEN_ITEMS.md` §18) | M | correcting it **deleted 16 findings**; pinned by a test now | needs a taxonomy decision, not a mapping edit |
| 7 | `classify.is_iac` misses `charts/*/templates/*.yaml` (`OPEN_ITEMS.md` §16) | S | fixing on path alone catches every dir named `templates` | wants a chart repo in a corpus first |
| 8 | HTML dashboard · any write path to GitHub (`OPEN_ITEMS.md` §14) | L | — | **M5**; required by four plan docs, tracked nowhere until 2026-08-09 |
| ✅ | ~~`iac.py` has never run on real input~~ → 20-case corpus, ran on 16, 3 defects found | | | **done — `BENCHMARK_STATUS.md` §4h** |
| ✅ | ~~`extract/tickets.py` · `extract/blame.py`~~ → **descoped**, with both dead hooks named | | | **decided — `OPEN_ITEMS.md` §15** |
| ✅ | ~~`python.yaml`'s dead `endpoints` block~~ → read or deleted, provably inert | | | **done — `BENCHMARK_STATUS.md` §4e** |
| ✅ | ~~SCA and the lockfile self-entry~~ → skipped, counted, stated | | | **decided — errata §14.33** |
| ✅ | ~~`pr_review/benchmark/gate.py`~~ → built on counts rather than rates | | | **done — `BENCHMARK_STATUS.md` §4e** |
| ✅ | ~~`extract/deps.py` lockfiles~~ → all five landed, both corpora re-measured | | | **done — `BENCHMARK_STATUS.md` §4d** |
| ✅ | ~~Localization~~ → accepted as M3 work, errata §14.30 | | | **decided — errata §14.30** |
| ✅ | ~~Test-file FP class~~ → was a dual-role source/sink defect, errata §14.31 | | | **fixed — errata §14.31** |
| ✅ | ~~Endpoint hand count~~ · ~~`is_generated` (sourcemaps/`dist/`)~~ · ~~secrets `MAX_SNIPPET_CHARS`~~ | | | **done — `BENCHMARK_STATUS.md` §4b**. Note `is_generated` has a *different* gap still open, item 5 above — the 2026-08-07 fix was path-based and the missing half is header markers. |

**Do not** fix defect 4 by adding decorator names; it is a partial guard model, not a missing
entry, and `BENCHMARK_STATUS.md` §4 explains why. **Do not** widen `scoring._CWE_GROUPS` to improve
a number — that table is where a benchmark cheats, `relation_table_share` exists to make widening
visible, and pass 2 added a second reason: `pr_review/benchmark/scope.py` decides the in-scope stratum through
the same table, so widening it moves recall in *both* directions at once. **Do not** read the
negative corpus's 0.24 FP/PR as a quality claim (in-sample, upper bound, all 11 FPs one file in one
repo), **do not** read 0.028 recall as one either — it rests on 26 advisories and a single true
positive — and **do not** quote the IaC corpus as a rate at all; it is coverage, four repos, and it
says only that the adapter works.

## 5. Blind spots to state out loud

Four things **cannot be validated without Bedrock** (full detail `M1_STATUS.md` §4). The one that
matters most:

> `token_tracker.py:116` **guesses** the Strands usage key `cacheWriteInputTokens`. If wrong it
> reports **0** silently — and the whole token-economy claim rides on that number. The fake emits
> the same guessed keys, so it looks healthy either way. **When reporting M1 results, say cost
> telemetry is _unmeasured_, not _low_.**

Also: the agent *lift* is unexercised (`agent_rows_merged == 0` with a fake), CAP's default
`model_id` is past its retirement date, and `temperature` is rejected by current Claude models
(use `RoleModel.effort`).

**Phase-2 equivalents, stated the same way:** tier-3 triage has never been run against a real
model (the fake returns scripted JSON, so the prompt's *labels* are exercised but its *judgement*
is not). The noise filter's recall ablation **has now been run** — pass 2, **36/36 ground-truth
files survived**, the first time `benchmark/scoring.py:ablate_filter` had labelled cases to read.
Read it with errata §14.19 attached: at M2 the filter does **not** gate what the detectors see, so
this is a baseline taken *before* the stage becomes load-bearing at M3, not a live leak check.
**Superseded in strength 2026-08-25 by `BENCHMARK_STATUS.md` §4p**, which asks the question one level
finer: `ablate_filter` reads drop records and answers *"was a ground-truth file dropped"*; the census
opens `02_context_bundles.json` and answers *"does the vulnerable span land inside a payload a model
would receive"* — **36/36 rows, 112/112 spans**. The two agree at file level, which is a cross-check.
The finer number is the one a Phase-3b arm is actually bounded by.

**M2's, stated the same way:** the **three** adapters that drive an external binary run against
real ones, but against **one version each**, and two of the three had version-sensitive behaviour,
so an upgrade is a plausible breakage. (The other two adapters have no binary to pin: `secrets` is
the builtin regex scanner still standing in for gitleaks, and `structural` is our own CPG. And
`iac` has never fired on real input — `M2_STATUS.md` blind spot 8.) `map_rule()` leaves 17% of `p/python`'s security rules unmapped
by design. And M2 raises **recall, not gating power**: everything new emits `status=candidate`
while `policy.gate()` triggers only on `validated`, so the gate still fires on secrets alone
until the verifier lands at M4.

**Detector precision is no longer unmeasured** (2026-08-07): **1.96 → 0.22 false positives per
PR** across three runs of the same pinned corpus, **0.00 gate-relevant** throughout, 96% of PRs
silent. The number is an **upper bound**, since a merged PR can still carry an undiscovered
vulnerability, and it is **in-sample** — the fixes were derived from this corpus. Five defects came
out of the run, four now fixed — see §9.

**Recall is no longer unmeasured either** (2026-08-07, §10): **0.028 flat / 0.111 in scope / 0.04
of pairs discriminated** on the labelled GHSA corpus. It is an upper bound in the *opposite*
direction — a reverted fix is the easiest possible presentation of a defect — and it rests on 26
advisories with a **single** true positive, so treat it as a first measurement rather than a
baseline. **IaC remains unmeasured** — `not_applicable` on all 102 cases across both corpora.
**SCA is now thinly measured** (2026-08-08, §11): five more lockfile formats took it from 1
invocation in 102 cases to **13**, producing the first **2** SCA findings on real input. One is a
genuine HIGH the negative corpus scores as a false positive (fastapi bumped gitpython to 3.1.57;
3.1.58 is the fix), and one is an artifact of a lockfile's editable self-entry (errata §14.32).
13 invocations is first contact, not a rate.

~~**The endpoint set has never been checked against a hand count on real code.**~~ **Closed
2026-08-07** (`BENCHMARK_STATUS.md` §4b): four real Prefect FastAPI routers hand-read and matched
**13/13** on count, verb and route path, plus a regression test that profiles a `@patch`-heavy
module and asserts the count does not move. **That test was inert on its first draft** — it passed
identically with the fix neutralized, because `extract_frameworks` skips files with no framework
import. One `from fastapi.testclient import TestClient` made it bite: 11 endpoints with the fix, 16
without. Neutralize the fix and watch the test fail, or the guard is decorative.

**The sentinel's, stated the same way:** it scans **added diff lines**, so a pre-existing
injection in a file that a `full_file` bundle later ships to an agent is invisible to it —
`scan_text()` exists for Phase 3 to close that at the bundle, and until it does the gap is real.
Its rules are English phrases matched per line, so a payload split across two lines, written in
another language, or spelled with homoglyphs passes. Its precision **is** now measured — 85 false
positives on 50 real PRs, all one platform convention, now exempted (errata §14.21) — but its
**recall is not**, and `tooling.md`'s "prompt-injection corpus" trust test is still the real
measurement. One known open case, deliberately unfixed: **ZWJ is required in emoji sequences and
Indic scripts** and would still be reported; it did not occur once in the corpus, so fixing it now
would be writing an unmeasured rule against a hypothetical.

## 6. Locked v1 decisions (full text in `PR_Rev_0620.md` §13)

GitHub-first (modular) · **Python-first** · Bedrock default (provider-pluggable, OSS-able —
**but see §14 errata: CAP's licence blocks this**) · **all detectors in v1** · **single** verifier ·
configurable budget (~300–500K tokens/PR default) · benchmark ≈ Gemini **~P90/R93** on a real-CVE
**post-cutoff** holdout (not directly comparable — measure honestly).

## 7. External facts already grounded (don't re-research)

- **OWASP Top 10:2025** (Jan 2026): A01 Broken Access Control (absorbs SSRF) · A02 Misconfig ·
  **A03 Supply Chain (new)** · A04 Crypto · A05 Injection · A06 Insecure Design · A07 Auth ·
  A08 Integrity · A09 Logging/Alerting · **A10 Exceptional Conditions (new)**.
- **Gemini CLI Security Extension** vuln classes (our families model these; reports ~P90/R93):
  Hardcoded Secrets · Broken Access Control · Insecure Data Handling · Injection · Auth ·
  LLM Safety · Privacy/PII. Its "Final Review Filter" → our verifier checklist (phase-3 §3c).
- **Benchmark datasets:** CVEfixes, PrimeVul (ICSE'25, temporal split), CVE-GENIE, OWASP
  Benchmark, Juliet/SARD. Methodology in `plan/benchmark.md`.

## 8. M0 notes still worth keeping

**Bug found & fixed at M0:** the secrets regex used `\b(password)`, which **missed `DB_PASSWORD` /
`AWS_ACCESS_KEY_ID`** — underscore is a word char, so no boundary. Fixed to match keywords
embedded in identifiers, plus specific-rule-suppresses-generic dedup. Regression test retained.

**Deliberate M0 simplifications, still open:** secrets findings are hardcoded
`status=validated` + `introduced_by_pr=True` (no verifier until M4, no baseline until M2 — so the
gate currently cannot distinguish introduced from pre-existing); the builtin regex scanner stands
in for gitleaks; the canonical AWS `...EXAMPLE` key is not filtered; `report/sarif.py`
`informationUri` is a placeholder.

**M0 was never run against a real GitHub PR** — both run dirs are `*-LOCAL` offline `--diff-file`
runs. Phase-0 acceptance items (tickets, dep deltas, real base/head SHAs, blame) are unverified.

> ⚠️ **Superseded 2026-08-07.** The benchmark run did exactly this, 50 times: real repos, real
> merged PRs, real base/head shas from GitHub, two real checkouts per case. Phase 0 works against
> live GitHub data. Tickets and blame are still unbuilt (`extract/tickets.py`, `extract/blame.py`),
> and the tool has still never *posted* anything to a PR.

## 9. Session log — what happened when, and where it is recorded

**These seven sections used to be 517 lines of narrative here**, duplicating the measurement record
in `BENCHMARK_STATUS.md` and burying the reusable lessons where nothing indexed them. That
duplication is how `M2_STATUS.md`'s headline stayed wrong for two days in four places (errata
§14.39). Each fact now has one home:

| kind of fact | home |
|---|---|
| a reusable lesson | **`PR_Rev_0620.md` §14** — numbered, stated once, referenced by number |
| a measurement | **`BENCHMARK_STATUS.md`** — every corpus number, pre-registration and result |
| a decision not yet made | **`OPEN_ITEMS.md`** |
| where we are, what is next | **here**, §1–§8 |

| # | Session | What changed | Measurement | Lessons |
|---|---|---|---|---|
| 1 | 2026-08-05 | M2 built; all three scanners installed and every adapter found broken | `M2_STATUS.md` §5 | §14.18 |
| 2 | 2026-08-07 | **Precision measured** on 50 merged PRs, 5 defects found, 4 fixed → 1.96 → 0.22 FP/PR | `BENCHMARK_STATUS.md` §3, §4 | §14.24 (mock targets), §14.25 (`ANALYZER_VERSION`) |
| 3 | 2026-08-07 | **Recall measured** — labelled GHSA corpus, 0.028 flat / 0.111 in scope | §3b | §14.26 (a corpus of fixes is not a corpus of PRs), §14.27 |
| 4 | 2026-08-07/08 | Acting on pass 2: the dual-role source/sink defect, 0.42 → 0.04 FP/PR | §4b, §4c | §14.28, §14.29 (a passing test is not a live assertion), §14.31 |
| 5 | 2026-08-08 | Five lockfile formats → SCA's first real findings | §4d | §14.32 |
| 6 | 2026-08-08 | Two design decisions and the regression gate, on counts not rates | §4e | §14.33 |
| 7 | 2026-08-08 | Both same-file FastAPI `dependencies=` forms — **and the agenda's stated reason was false** | §4f | **§14.34** |
| 8 | 2026-08-09 | Four catalog patterns matching the wrong receivers; reported findings 76 → 31 | §4g | **§14.35, §14.36, §14.37** |
| 9 | 2026-08-09 | Plan-vs-tree audit; the IaC corpus, and `iac.py` on real input for the first time | §4h | **§14.38, §14.39** |
| 10 | 2026-08-21 | **The pivot.** Four-arm comparison built and run; the pipeline priced against a raw LLM | §4i | §14.40 (a stage that runs is not a stage that gates), §14.42 |
| 11 | 2026-08-22 | Delta scoping measured — the stage carrying most of the numbers, reported by nothing until then | §4j, §4k | §14.46, §14.47, §14.48 |
| 12 | 2026-08-24 | Plan 2: the three review nominations worked; arm 3b to n=3; the publication audit | §4l–§4o | §14.49–§14.53 |
| 13 | 2026-08-25 | Plan 3 Steps 0/1/1b/2: report title derived from its document; the bundle census; the context priced on both corpora; the context pinned and its three orderings fixed | §4p–§4q | **§14.54–§14.57** |
| 14 | 2026-08-26 | Plan 3 Steps 3–6 complete. **The result is a null: the pipeline's context did not make the model a better reviewer** (§4x). Along the way: the scorer was calling a child CWE a false positive, worth a third of both LLM arms' recall; and a guard raising before the scorecard was written destroyed five of nine paid passes | §4r–§4x.5 | **§14.58, §14.59, §14.60**, `OPEN_ITEMS.md` §26, §27 |

The design reasoning from session 7 that used to sit here lives where it belongs instead — at the
code. `promote._router_guards`'s docstring carries why the walker is deliberately name-agnostic
about the constructor, why `include_router` is deferred, and both narrowings that measurement
forced; `python.yaml`'s `exact_calls` block carries the receiver counts behind session 8.
