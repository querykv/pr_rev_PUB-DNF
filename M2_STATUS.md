# M2 — Build Status & Handoff

**Last updated:** 2026-08-09 · **Milestone:** M2 (Deterministic detector suite + delta scoping)
**State:** **M2 built and accepted on a fixture**, and the acceptance is pinned by tests rather
than by this paragraph — `tests/test_detect_m2.py` asserts `introduced == 4`, `pre_existing == 2`,
`triggers == 1` on `m2_{base,head}`, and it still passes at `ANALYZER_VERSION` 8.
**Five adapters** — `secrets`, `structural`, `semgrep`, `sca`, `iac` — of which **three run an
external binary** (semgrep 1.172.0, osv-scanner 2.4.0, checkov 3.3.0); `secrets` is the builtin
regex scanner standing in for gitleaks (an M0 simplification, still open) and `structural` is our
own CPG. **Precision measured on 50 real merged PRs, then fixed and re-measured** (§3.2):
**1.96 → 0.22 false positives per PR**, since 0.24 on the same corpus once SCA had lockfiles to
read (`BENCHMARK_STATUS.md` §4d).

> **This header was wrong until 2026-08-09** in three ways, and the corrections are the useful
> part. It said "all six adapters" (there are five) "run against their real binaries" (three do),
> and that **recall** was unmeasured. Recall was measured 2026-08-07 on the labelled GHSA corpus —
> **0.028 flat, 0.111 in scope** — and **SCA has since run 13 times** across the two corpora and
> produced 2 findings. IaC was the last one still true, and is now closed too: a 20-case IaC corpus
> ran it on real PRs for the first time on 2026-08-09 (§3.8, `BENCHMARK_STATUS.md` §4h). **All five
> adapters have now executed against real input.**

> Detail record for the M2 build, in the same role `M1_STATUS.md` plays for M1.
> `CONTINUATION.md` is the short "where are we". Design intent: `plan/phase-3-security-analysis.md`
> §3a and §3d, `plan/cross-cutting.md` §2/§5/§6.

> 🧊 **FROZEN — the record for M2, not current state.** M2 is complete and its acceptance is
> pinned by `tests/test_detect_m2.py`. Corrections are **appended** rather than rewritten: the
> header block above is a worked example, and errata §14.39 records what it cost to leave it
> unchecked for two days. Measurements live in `BENCHMARK_STATUS.md`, lessons in
> `PR_Rev_0620.md` §14, open decisions in `OPEN_ITEMS.md`, current state in `CONTINUATION.md`.

---

## 1. Where M2 stands

**669 tests pass** (416 at the end of M1, +38 for M2 — four of which run the real scanners and skip
without them — then +212 across the benchmark harness, both corpora and every defect and catalog
fix they found; the breakdown is `BENCHMARK_STATUS.md` §1), plus CAP's own 4.
**`cap_engine/`'s working tree is clean — zero edits.** Nothing in `detect/` or `findings/`
imports `cap_engine` directly; `detect/structural.py` reaches it only through
`profile/incremental.partial_cache()`, so the six-file confinement in CONTINUATION §2 still holds.

| plan | Deliverable | Status |
|---|---|---|
| 3a | `detect/normalize.py` — rule→taxonomy mapping, SARIF reader, finding factory | ✅ |
| 3a | `detect/structural.py` — CPG taint-lite + access-control delta | ✅ verified on fixture |
| 3a | `detect/sast_semgrep.py` | ✅ run against semgrep 1.172.0 |
| 3a | `detect/sca.py` — osv-scanner over the dep delta | ✅ run against osv-scanner 2.4.0 |
| 3a | `detect/iac.py` — checkov on `is_iac` files | ✅ run against checkov 3.3.0 |
| 3a | `detect/runner.py` — detector registry + per-detector telemetry | ✅ |
| 3d | `findings/validate.py` | ✅ |
| 3d | `findings/dedup.py` — cross-source collapse on fingerprint | ✅ |
| 3d | `findings/delta.py` — baseline build/cache + scoping | ✅ verified both directions |
| 3d | `findings/{merge,severity,calibrate,suppress}.py` | ❌ M3/M4 — absent, not stubbed |
| — | `detect/codeql.py` | ❌ off by default in the plan; not built |

### M2 acceptance — met on `tests/fixtures/m2_{base,head}`

Overview §6 asks for "all candidate findings normalized, deduped, delta-scoped on a sample PR".
The fixture is a base/head checkout pair plus the diff between them, deliberately separate from
`sample_app/` (whose exact counts the profiling tests assert). One run, six findings:

| Finding | Introduced | Why it is the case it is |
|---|---|---|
| `INJ-SQLI` critical, `taint-sql` | ✅ | new `/search` taints `cursor.execute`; **unguarded**, so the graph raises HIGH→CRITICAL |
| `SEC-TOKEN` high, `github-pat` | ✅ | new secret. `validated` → **the only gate trigger** |
| `SEC-TOKEN` high, `github-pat` | ❌ | *the same secret moved down the file.* The diff shows it as an added line; only the baseline knows it is not new |
| `BAC-MISSING-AUTHZ`, `guard-removed` | ✅ | `/items` lost `Depends(get_current_user)`. Needs **both** graphs |
| `BAC-MISSING-AUTHZ`, `missing-authz` | ✅ | the new endpoint has no check |
| `BAC-MISSING-AUTHZ`, `missing-authz` | ❌ | `/legacy/{iid}` was unguarded before this PR |

`Verdict: FLAGGED · findings 6 · gate triggers 1 · exit 1`, `delta.method = "baseline"`,
`introduced 4 / pre_existing 2`. The two pre-existing rows are the point of the milestone: before
`findings/delta.py`, `secrets.py` hardcoded `introduced_by_pr=True` and both of them would have
been blamed on this PR — one of them at gating severity.

**The M1 thread is unchanged.** `phase2_pr.diff` still produces 6 groups, 4 filtered, APPROVED,
exit 0, and now additionally reports `structural: not_applicable` because that run passes no
`--head-dir`.

---

## 2. What was built, and the reasoning that isn't obvious from the code

### The rule table is three-stage, and the third stage is the honest one

External rulesets are large and moving; `p/python` alone is hundreds of rules. `map_rule()` tries
an exact table (rules someone has read), then token heuristics over the rule id, then
`TOOL-UNMAPPED`. The heuristic tier costs one confidence point, because a substring of an id is
weaker evidence than a rule someone read.

The unmapped tier is where the design decision is. Dropping the finding costs recall, which is
the only thing 3a provides; guessing a family puts an unread rule into an agent's routing table
and into the coverage denominator, where it reads as *analyzed*. So an unmapped rule reports,
under a family (`Unmapped`) deliberately absent from `FAMILIES` so no Phase-3b runner can claim
it, capped at MEDIUM and left `candidate` so it cannot reach the gate, with its rule id in
telemetry so the exact table grows from evidence rather than from a ruleset dump.

Checkov gets a per-tool fallback to `CFG-IAC` and Semgrep does not. Every Checkov check is a
misconfiguration by construction, so that is a fact about the tool; Semgrep's rules span the
entire taxonomy, so there is nothing true to say about an unread one.

### `structural.py` — and why it insists on a head checkout

Recorded as errata §14.15. Short version: Phase 1's CPG is at `base_sha`, so running structural
rules against it reports the repository's existing shape as though the PR caused it. The detector
builds a transient head-side subgraph instead (one parse per changed file, never cached, never
merged into the profile) and **disables itself without `--head-dir`** rather than substituting the
base graph.

Holding both graphs is what makes `guard-removed` expressible, and that finding — "this endpoint
was guarded at base and is not now" — is §2.5's first significant-change example and cannot be
stated from either side alone.

Two sink classes are deliberately not reported. A path from untrusted input to a `log` or
`response` sink is log forging and reflection; the interesting question for those sinks runs the
other way — whether a *sensitive value* reaches them — which is a query over the sensitive-field
overlay and belongs to Privacy/PII in Phase 3b. Emitting them would fill every report with
`logging.info(request.args[...])`.

Reachability is real but bounded: `cpg._resolve_callee` is local-file-first, so no call edge
crosses a file. Every reachability claim is within-file, which understates and never overstates.
Guarded and reachable are kept apart — a sink behind `login_required` is still reachable by
anyone who can register, so it stays `attacker_reachable=True` with the guard names recorded, and
only the unauthenticated route earns the severity raise.

### `delta.py` — the baseline, and the bug that proves it works

Errata §14.17 has the full story. Two methods, and the weaker one announces itself: with a base
checkout, the same detectors run over base-side file content and every fingerprint they produce
is a defect that already existed; without one, scoping falls back to hunk overlap and the run
records that the introduced set is an over-estimate.

Hunk **ranges**, not added-line numbers. A finding caused by a *deletion* — an authorization
decorator taken off an endpoint — has no added line anywhere near it, and the hunk's new-side
range is what covers the context around a removal.

Findings on `pr:body` / `pr:title` / `ticket:*` are introduced by definition. They exist in no
checkout, so neither method applies, and getting this wrong would have silently un-gated the
planted-instruction case `safety/sentinel.py` exists for.

The bug worth remembering: the base pass initially ran without a source reader, so its structural
findings carried synthesized snippets while the head pass carried real source lines. Fingerprints
include the snippet, so nothing ever matched, and the failure was silent and noisy-direction —
every pre-existing finding looked introduced.

### Absence is a state, not an empty list

`ExternalTool` + `AdapterRun.status` exist because a detector that found nothing and a detector
whose binary is missing produce the same empty list and mean opposite things. Every adapter
reports `ran | missing_tool | not_applicable | error | disabled` into `telemetry["detect"]`, and
`build_baseline()` refuses to record a detector as a baseline contributor unless its status is
`ran` — the first version of that code listed `semgrep` among the tools that built a baseline on a
machine with no semgrep installed.

### The report separates the two sets

`report/markdown.py` now renders "Findings introduced by this PR" and "Pre-existing findings"
as separate sections with separate counts. Interleaving them makes the repository's backlog read
as this author's fault, which is how a security tool loses its reader.

---

## 3. Known blind spots — state these, do not let them read as clean

1. ~~Three of the six adapters have never executed.~~ **Closed 2026-08-05** — see §5. All three
   binaries are installed and all three adapters run. What replaced this blind spot is smaller and
   specific: the adapters are validated against *one version each*, and two of the three had
   version-sensitive behaviour (checkov's output filename, osv-scanner's v1/v2 CLI), so an upgrade
   is a plausible breakage. The integration tests in `tests/test_detect_m2.py` skip rather than
   fail when a binary is absent, which keeps a bare machine honest but also means CI without the
   scanners tests the parsers only.

   **Narrowed again 2026-08-07.** §5 validated that each adapter *parses* its tool correctly. It
   did not validate which **inputs** each tool accepts, and that turned out to be a separate axis:
   `osv-scanner --lockfile` rejects dependency manifests and rejects them for the whole invocation,
   so one `pyproject.toml` discarded the results already extracted from a valid lockfile
   (errata §14.23). `sca._OSV_LOCKFILES` now pins the accepted set, probed file by file. The same
   question — *what will this tool refuse to be given?* — has **not** been asked of semgrep or
   checkov.
2. ~~**Precision is unmeasured.**~~ **Measured 2026-08-07** on 50 real merged PRs from 10 Python
   repositories, then **fixed and re-measured on the same pinned corpus**:
   **1.96 → 0.22 false positives per PR (−88%)**, **0.00 gate-relevant** in both runs (nothing
   could have failed a build), and **94% of PRs now produce no findings at all** (was 86%). Delta
   Three runs of the same pinned corpus:
   `benchmark/results/2026-08-07/` (baseline), `-after-fixes/` (defects 1, 3, 5) and `-defect2/`;
   each has a generated `negative.md` and a hand-verified `analysis.md`.

   **Defect 2's effect is not in the false-positive column.** It removed one FP and **halved the
   endpoint denominator** (142 → 74 endpoints; 10 → 5 PRs that touch any), so `missing-authz` per
   endpoint *rose* 0.085 → 0.149 — the only number a fix made worse, and the one most worth
   trusting. Pre-existing findings fell 158 → 91: the baseline pass had been generating ~67
   spurious findings per corpus that `delta.py` excluded and no scorecard ever showed.

   The prediction in this bullet was half right. `missing-authz` does fire on every unguarded
   endpoint in a changed router file — 11 hits on one Wagtail file (touched by two PRs), some
   deliberately public and some enforcing authorization imperatively where the guard model cannot
   see it. But it was not the main noise source: **87% of the baseline's false positives were
   `INTEG-HIDDEN-TEXT` from the sentinel**, firing on GitHub's own `@<ZWSP>` convention in
   auto-generated release-note PR bodies. Five defects came out of the run; four are fixed and one
   (imperative authorization) is deferred to M3 by design. `BENCHMARK_STATUS.md` §4 has each with
   its mechanism, the fix that landed, and — for two of them — why the fix differs from what was
   first proposed.

   **The run's largest finding was not in the scorecard.** Defect 2 was rated "1 false positive
   plus unknown denominator inflation"; reading the cached profiles directly showed **46% of the
   access-control matrix was `@patch(...)` mock targets rather than endpoints** (99.8% for
   Saleor). A defect is only counted by the scorecard when it lands inside a diff, so profile-wide
   corruption is nearly invisible to it — errata §14.24.

   ~~What is still unmeasured: **recall**, and **SCA and IaC**, which this corpus never
   exercised.~~ **Two of those three closed; see §3.8 for the one that did not.** Recall was
   measured 2026-08-07 (0.028 flat, 0.111 in scope) and SCA started running once `extract/deps.py`
   read five more lockfile formats (§4d) — 13 invocations, 2 findings, across the two corpora.

   The number is still an **upper bound**: a merged PR can carry an undiscovered vulnerability,
   and this counts any such finding as a false alarm. And it is **in-sample** — the fixes were
   derived from this corpus and measured on it.
3. **M2 raises recall, not gating power.** Per phase-3 §3a everything new emits
   `status=candidate`, and `policy.gate()` triggers only on `validated`. So the gate still fires
   on secrets alone until the verifier lands at M4. This is by design and worth saying out loud
   before someone reads "detector suite shipped" as "the build now blocks on injection".
4. **Cross-file taint is still absent**, bounded by the resolver (§2). A source in one file
   reaching a sink in another is invisible to `structural.py`, and the CPG's splice invariant
   depends on that staying true.
5. **The endpoint set has never been checked against a hand count on real code.** It was 46% wrong
   for the entire life of the profile (blind spot 2) and all 31 `promote.py` tests passed, because
   the only fixture they assert against has six endpoints and structurally cannot contain the
   defect. The fix is pinned by tests now; the *denominator* still is not.
6. **`profile/cache.py:ANALYZER_VERSION` is hand-maintained.** Cached profiles are keyed on the
   repo sha and the artifact layout, so a change to `promote.py`, `cpg.py` or `patterns/*.yaml`
   does **not** invalidate them on its own. Forgetting the bump makes a re-run silently measure the
   old analyzer (errata §14.25). A source hash would be automatic and would discard every cached
   profile on a comment edit, which is why it is a constant — the cost is that it needs discipline.
7. **All four M1 Bedrock blind spots survive verbatim.** Nothing in M2 called a model. Token and
   cost telemetry remains **unmeasured, not low**.
8. ~~**`iac.py` has never executed on real input.**~~ **Closed 2026-08-09 — `BENCHMARK_STATUS.md`
   §4h.** A 20-case corpus of Terraform-module and Docker-image repositories was pinned and run:
   `iac` reported `ran` on **16 of 20** (the other 4 touch no IaC file, which is the `AdapterRun`
   contract, not a miss), generated **204** findings, and `delta.py` demoted **84%** of them as
   pre-existing — the first test of delta scoping against this detector and this file type.

   What replaces this blind spot is narrower. **The corpus is coverage, not precision**: four
   repositories across two organisations answers "does it work" and cannot support a false-positive
   rate. And first contact found **three defects an adapter that passed every unit test still
   had** — a false secret that *failed a gate* (`NSS_WRAPPER_PASSWD="$(mktemp)"`, fixed), a
   taxonomy mis-mapping whose obvious correction silently deleted 16 findings (`OPEN_ITEMS.md`
   §18, reverted), and `is_generated`'s missing header-marker half (§17). The fourth time first
   contact with real input has broken an adapter that looked finished (errata §14.18).
9. **Severity finalization is split across two layers, and the plan says it should not be.**
   `plan/phase-3 §3d` puts reachability adjustment in `findings/severity.py`, which is correctly
   listed as absent (M3/M4). But the unguarded HIGH→CRITICAL upgrade is **already implemented**,
   inside `detect/structural.py:_taint_findings`. So part of an unbuilt module's job is done in a
   detector. Nothing was wrong with doing it there — the graph is the only thing that knows
   reachability — but whoever writes `severity.py` will duplicate it unless this says so, and the
   CVSS-v4 vector half of that step is genuinely unbuilt (`Finding.cvss_vector` is populated only
   by `sca.py`, as passthrough).

---

## 4. Next step

**`models/bedrock.py` is still M1's open debt (`M1_STATUS.md` §5.3) and is still blocked**: no
AWS credentials, no `boto3`, no `strands-agents` in this environment. §5.3's reasoning for not
writing it blind stands — blind spot #2 is a private-Strands-attribute override whose mitigation
is "pin `strands-agents` when access lands", and code written against an unpinned Strands would
be wrong at exactly the seam no mock can test.

M2 proceeded without it, as §5.3 said it could. **M3 cannot.**

Ordered by what unblocks the most:

1. ~~Install the three scanners and run them once.~~ **Done — §5.**
2. ~~Measure detector precision.~~ **Done 2026-08-07 — see §3.2.** 1.96 FP/PR over 50 real merged
   PRs, 0.00 gate-relevant. Build record and defect list: **`BENCHMARK_STATUS.md`**.
3. ~~Fix the three safe defects the measurement found, then re-run the pinned corpus.~~
   **Done 2026-08-07 — four of five fixed** (1, 3, 5, then 2), re-measured on the same pinned
   corpus: **1.96 → 0.22 FP/PR**. Defect #4 (imperative authorization) is deferred to M3 by design.
   Mechanisms, what actually landed and why two fixes differ from what was first proposed:
   `BENCHMARK_STATUS.md` §4.
4. **Benchmark pass 2 — the labelled GHSA corpus.** Promoted from item 7: it is now the only thing
   that can measure **recall**, which four fixes in a row have just made more load-bearing. Three
   of them narrow what the tool reports, and a negative set cannot tell narrowing-correctly from
   breaking. Credential-free; the long pole is corpus curation, not code.
5. **`models/bedrock.py` + one real run** — settles all four M1 blind spots at once and is the
   precondition for M3. Blocked on AWS access; pin `strands-agents` at the same time (§4.2 of
   `M1_STATUS.md`).
6. **M3 agentic families**, BAC flagship (phase-3 §3b). The 3a candidates and the CPG context
   this milestone produces are its inputs. Defect #4 — authorization enforced imperatively in a
   callee the local-file-first resolver cannot follow — belongs here, not in a detector patch.
   Note that its input got materially cleaner on 2026-08-07: the access-control matrix it reads
   was 46% mock targets until defect #2 was fixed.
7. **`findings/merge.py`** — 3a candidate + 3b confirmation into one finding with the agreement
   signal weighted once. `provenance.also_detected_by` (errata §14.16) is already populated for
   it.
8. Smaller, and independent of credentials: `findings/suppress.py` + `.pr_review/allowlist.yaml`
   (cross-cutting §6), `taxonomy/*.yaml` as data rather than a code table (§2 says data), and
   SARIF `suppressions` for pre-existing findings. ~~Plus two the benchmark work surfaced:
   `extract/deps.py` does not recognize `uv.lock`/`pdm.lock`/`Cargo.lock`, and
   `patterns/python.yaml`'s `endpoints.decorators` block is never read.~~ **Both done** — the five
   lockfile formats landed 2026-08-08 (§4d) and the endpoint block is now read or deleted, with a
   test that fails on any future inert catalog key (errata §14.33). Note for whoever writes
   `suppress.py`: it is wanted for its own reasons and **not** for the test-file false-positive
   cluster, which turned out to be a detector defect and is already fixed (§14.31).

   **Two warnings for whoever picks this up**, both from 2026-08-09 (`BENCHMARK_STATUS.md` §4g).
   First, that inert-key test proves **readership and nothing else**: `sinks.sql.calls` contained
   `text`, passed the test, and was matching `request.text` as an SQL sink. A pattern is only
   checkable against a corpus, not against the code. Second, **the scorecard cannot see the taint
   engine** — 457 taint findings reach 1 scored — so none of the remaining detector items can be
   justified or refuted by FP/PR, and pricing one that way wastes the measurement.

---

## 5. First contact with the real scanners — 2026-08-05

Installed semgrep 1.172.0, osv-scanner 2.4.0 and checkov 3.3.0 and ran each adapter. **Every one
of them was broken in a way its recorded fixture could not show**, which is now errata §14.18.

| What broke | How it presented | Fix |
|---|---|---|
| Semgrep `--baseline-commit` with an unresolvable sha | exit **2**, so `status=error`; every offline `--diff-file` run silently lost SAST | `_usable_baseline()` asks git first, drops the flag and notes it |
| Checkov writes SARIF to a **file**, prints a banner to stdout | `JSONDecodeError` on the ASCII art | collect from a temp dir, glob `*.sarif`; `read_sarif` also skips leading noise |
| `--output-file-path console` | created a stray `console/` **inside the scanned checkout** | temp dir, removed on exit; a test asserts the checkout is unchanged |
| osv-scanner v2 `source.path` is absolute | findings landed on absolute paths, so delta scoping could never join them to the manifest | resolve `head_dir` before stripping |
| PYSEC advisories carry no `summary` or `database_specific.severity` | everything rated MEDIUM-by-default | fall through to the group's `max_severity`; `details` used for the headline |
| One defect, several ids (`PYSEC-2021-142` = `GHSA-8q59-q68h-6hv4`) | duplicate findings for one upgrade | one finding **per package**, all ids kept in evidence |
| **5 of 6 Semgrep rule ids in `_EXACT` do not exist** in `p/python` | dead table rows that read as coverage | table rebuilt from ids the installed ruleset actually loads |

**The mapping table measured, for the first time.** Against `p/python`'s 138 security rules,
`map_rule()` left **72 unmapped (52%)**. Adding token clusters the real ids revealed — cipher and
key-size, TLS/cert validation, `system-call`/`spawn-process`, `code-run`/`subinterp`,
`sql-string`, `raw-html`, `jwt` — brought that to **24 (17%)**. The remaining 24 are rules our
taxonomy genuinely has no id for (open redirect, CSV injection, NaN injection, XXE, CSRF,
file permissions, bind-all-interfaces). They stay `TOOL-UNMAPPED` rather than getting invented
ids, which is the design working rather than failing.

**Delta scoping, demonstrated on real advisory data.** osv-scanner reported 24 advisories against
the fixture's three dependencies; 22 belong to `requests`, which the PR does not touch. One
finding survived: `pyyaml 5.3.1`, CVSS 9.8, fixed in 5.4.

`tests/fixtures/{semgrep.sarif,checkov.sarif,osv.json}` are now recorded from real output rather
than written by hand, and `tests/fixtures/iac_sample/main.tf` exists so the Checkov adapter has
something to scan. The full thread with every scanner enabled produces **7 findings, 5 introduced
/ 2 pre-existing, 1 gate trigger**.
