# Pivot plan — approved 2026-08-21

> **Status: APPROVED and in progress.** This is the descoping decision for the project, not
> scratch. It was drafted in `~/.claude/plans/` and moved here on approval, because that directory
> is retired scratch outside version control (`CONTINUATION.md` §9) and this document is the
> record of *what was cut and why*.
>
> Budget ~5 sessions. Bedrock credentials are never arriving, so M3 / M4-verifier / M5-RLM are
> permanently out. Progress is tracked against §3's item numbers.

---


## Context

Budget is **~5 sessions** (3–4 nominal, overage accepted); **Bedrock credentials are never
arriving**, so M3 (and M4's verifier, M5's RLM) are permanently out. v1 as designed needs ~12–18
sessions, ~9–13 of them blocked. This plan spends the budget on the credential-free surface and on
**one experiment that turns the unbuilt agent layer from a gap into a measured question.**

Prior decisions still standing: build **D** (wire checkouts) and **C** (Semgrep-alone baseline);
**B** (`suppress.py`) is cut — no audience, no slack.

---

## 0. Four findings from research, before any plan

**① The labelled corpus is a clean temporal holdout — by accident.** Every advisory in it was
published **2026-07-24 → 2026-08-07**; the model's cutoff is **May 2026**. `plan/benchmark.md` §3
demands exactly this ("prefer a temporal holdout: CVEs published after the model's cutoff") and
treats it as the hard part of evaluating an LLM honestly. It already exists, because the corpus was
built from "the 80 most recently published advisories." **This is what makes the comparison worth
running at all** — the usual fatal objection to LLM-vs-tool benchmarks does not apply here.
Also load-bearing: `AdvisoryRef.summary` is deliberately withheld from `PRTask`, so the task cannot
leak its own answer.

**② The comparison needs a producer, not a harness.** `score_case(case, findings, pre_existing=)`
takes a plain `list[Finding]` (`scoring.py:197`), and `_score_all` (`runner.py:382`) is what turns
a `CaseRun` into scores. So any arm that emits `Finding`-shaped JSON is scored, serialized,
`rescore`-able and reported by **existing, unmodified machinery**. That is a ~40-line producer plus
a prompt, not a second benchmark.

**③ `claude` CLI 2.1.235 is installed** at `/Users/davidsy/.local/bin/claude`, with `-p/--print`,
`--output-format json` and `--json-schema`. A blind, reproducible, per-case LLM run is scriptable
today. **No `ANTHROPIC_API_KEY` and no Bedrock is needed.** It serves two roles: the external
baseline (arm 3) and — per §1.0 — a concrete `ModelProvider` behind the pipeline's own tier-3
triage seam (arm 2b). It bills to the Claude Code account, same as an interactive session.

**④ There is no README.** For "primed for continuation" this is the single real gap. The docs are
otherwise unusually thorough; someone landing on the repo has an excellent session-resume doc and
no answer to *what is this*.

---

## 1. The LLM comparison — feasible, and the most valuable thing left

### 1.0 The provider shim — the pipeline is not structurally zero-token

**Correction to an earlier framing in this plan.** "The pipeline spends zero model tokens" is true
of the current state but is **an empty provider slot, not a property of the design**. Both seams
are one-method ABCs and both are shimmable to `claude -p`, with no Bedrock, no `boto3`, no
`strands-agents`:

| seam | shape | today | shimmable? |
|---|---|---|---|
| `ModelProvider.complete(messages, tools, **cfg)` | one-shot, messages in / answer out | **live code, gets `None`** | **yes, cleanly** |
| CAP `InferenceProvider.invoke(system_prompt_parts, user_prompt, tools, agent_id, …)` | agent loop w/ callables | `FakeInferenceProvider` | yes, but **lossy** |

**The `ModelProvider` half is already wired end to end.** `pipeline.py:257` takes
`triage_provider`, passes it at `:295`, and `change/filter.py:_triage` calls
`provider.complete(...)` at `:230`. It receives `None`, so tier 3 degrades to "all ambiguous
kept." A ~30-line `ClaudeCliProvider` lights up existing code.

**Why this is more than a workaround.** Phase 2's thesis is *do not send everything to the model* —
tier 3 triages only the ambiguous remainder. So the shim produces the comparison this project was
built to make:

> Pipeline: **N tokens/PR**, spent only on ambiguous hunks.
> Raw LLM: **M tokens/PR**, spent on the whole diff.
> Same corpus, same scorer, both measured.

That is **Principle #4 measured rather than asserted**, and it is strictly better than the "0 vs N"
framing below, which was true but uninteresting. It also discharges a caveat standing since the
start — token cost here has always been **unmeasured, not low** (guessed Strands usage keys failing
silently to zero). `claude -p --output-format json` reports usage from its own accounting.

**The CAP-side shim was considered and CUT** — the reasoning is kept because it is the argument for
never doing it casually later. Flattening `system_prompt_parts` destroys the **prompt-cache
breakpoints** that are "the token economy Phase 1 exists to buy", so a shimmed CAP run could
*demonstrate* the thread end to end but **could not validate Principle #4** — it would break the
exact mechanism the efficiency claim rests on. `tools` are Python callables `claude -p` cannot
invoke; granting it filesystem tools instead bypasses `safety/permissions.py`, the enforcement
point for "planners never read source". And nesting CAP's planner→worker→synthesizer loop inside
`claude -p`'s own loop puts the inner tool calls outside CAP's `budget_gate`. If it is ever
revisited, it is a **labelled demonstration only** and never an efficiency measurement.

**It does not make M3 cheap.** BAC family logic — role discovery, endpoint mapping, matrix, diff
overlay — is model-agnostic and stays 4–8 sessions. The provider was never the bulk of that work.

**~~Consequence to plan for:~~ THIS PREDICTION WAS WRONG — corrected 2026-08-21.** The plan said
tier 3 going live would change every scored number on both corpora. Measured on four labelled cases,
deterministic vs live: the scorecards are **identical except for wall clock** (17s -> 92s).

`pipeline.py` builds the detect stage from the manifest and every parsed file, **not** from the
filter's kept set, so a dropped hunk is still scanned and its findings still reach the report. The
filter's drops route **Phase-3b agents**, and Phase 3b is M3, which does not exist. The stage runs;
it gates nothing. Errata **§14.40**; the refutation was printed under every scorecard this project
has ever generated.

**What arm 2b actually is, therefore:** a **cost** measurement of the pipeline's only live model
seam, and never a quality one. Measured on 6 labelled cases / 5 triage calls: **$0.0933, 10,139
content tokens vs 36,725 tokens of CLI transport overhead, 5.7x wall clock** — for an identical
scorecard. It still earns its place, because pricing that seam is what the efficiency axis needs.
Any table that puts it in a findings column is lying.

### 1.1 The framing trap, and the reframe that makes it a contribution

Even with the shim, the flattering comparison must be refused. "We are cheaper than an LLM" would
be the error the errata log keeps recording — a number that names a population rather than a
cause — because the *designed* pipeline (M3 agents) would spend far more than triage does.

The honest question, and the one the project needs:

> The pipeline costs **N tokens** (triage only) and finds **X**. A raw LLM costs **M** and finds
> **Y**. The gap `Y − X` at price `M − N` is **the budget the agent layer would have to earn** —
> and M3 was never built, so this is the only way to price it.

### 1.2 Why it is a good experiment: every outcome is informative

| If the LLM… | The finding is |
|---|---|
| beats the pipeline substantially | the value is in the agent layer; detectors are a floor. Validates the architecture's premise and indicts its current state. |
| does comparably badly | the corpus's ground truth is the hard part — already suspected, since 4 of 9 in-scope misses were right-file-wrong-lines. Validates the measurement critique. |
| finds more but with many false alarms | the classic result, and the strongest possible justification for the unbuilt 3c verifier. |
| **varies run to run** | a first-class result. The pipeline produced *identical numbers twice*; if the LLM does not, that is a product difference, not noise to average away. |

Pre-register the prediction before running — established practice here, and it has caught wrong
predictions before.

### 1.3 The arms

| arm | what it is | status |
|---|---|---|
| 1 | **Semgrep-alone** | item C — config only, `--config` + `detectors.*.enabled` already exist |
| 2 | **Pipeline, deterministic** | already measured, 18 runs |
| 2b | **Pipeline + live tier-3 triage** | §1.0 — the `ClaudeCliProvider`; the pipeline's own token number |
| 3 | **Raw LLM, diff only, Sonnet, 3 passes** | `plan/benchmark.md` §3's "raw single-prompt LLM" |
| ~~4~~ | ~~LLM with repo read access~~ | **cut** — ~$8/pass and +0.75 session; revisit only if 1–3 land early |

**2b is what makes the efficiency axis real**, since it is the only arm where the pipeline spends
tokens and can therefore be compared on cost rather than only on findings.

The `claude -p` plumbing (subprocess, JSON parse, usage extraction, retry) is **shared** between 2b
and 3. Build it once for 2b; arm 3 is then a prompt over the same transport.

**Rough cost** (from diff bytes: 229 KB across 26 vuln cases, ~8.6 KB median):
arm 3 ≈ 150k in / 50k out per pass → **~$1/pass on Sonnet, ~$3 for three**. Arm 2b's triage calls
are smaller still (ambiguous hunks only). Estimates from diff size, not measured — **the first
1-case smoke run replaces them, and a zero-usage reading there is a bug, not a result.**

### 1.4 Design rules that keep it fair

- **Blind.** The producer sees `pr_task.diff_text` and nothing else: no ground truth, no advisory
  summary, no pipeline output, no context from this conversation.
- **`claude -p` subprocesses, not this session's Agent tool** — for both 2b and 3. A subprocess
  with a pinned prompt file is re-runnable by a third party and reports usage per call via
  `--output-format json`; an agent spawned from this session inherits its framing and cannot be
  reproduced. The prompt file is a committed artifact.
- **Arm 3 must run tool-free, and outside the checkout.** `claude -p` has tools by default: with
  cwd inside a corpus repo it can simply read the source, at which point **arm 3 silently becomes
  arm 4** — the arm we cut — and its token numbers describe a different experiment. Pass
  `--disallowedTools` (flags confirmed present in 2.1.235) *and* run from a neutral cwd, then
  **assert in the smoke run that no tool calls appear in the JSON**. Belt and braces, because the
  failure is invisible in the output: this is the same shape as errata §14.36, where a proxy
  disagreed with the pipeline and nothing surfaced it.
- **Deterministic scoring only.** Reuse `score_case`. Never an LLM judge — that is a model grading
  its own family, and the CWE-family + line-overlap rule is already written and already ratcheted
  by `gate.py`.
- **Do not implement it as a `Detector`.** Slotting into `build_detectors` would inherit delta
  scoping and the noise filter, at which point it is not a baseline. Separate arm, same scorer.
- **Same corpora, unmodified.** Labelled (recall, 26+26) and negative (false alarms, 50).
- **`--label` every run distinctly** — `run.json` is one per directory (`OPEN_ITEMS.md` §4).
- **Do not widen `scoring._CWE_GROUPS`** to make an arm look better. It is where a benchmark
  cheats, and `scope.py` reads the same table.

### 1.5 Metrics — all of them already exist

Recall · in-scope recall · pair discrimination (`labelled_metrics`, `pair_metrics`) · FP per PR
(`negative_metrics`) · localization / right-file-wrong-lines (`CaseScore` tracks near-miss).
**New, and only for the LLM arms:** tokens in/out per case, wall-clock, $ at published rates, and
**run-to-run variance across 3 passes** (identical-output rate, and the spread on every headline
number).

---

## 2. Continuation-readiness — the intent is right, the mechanism is not

### 2.1 v1/v2 branching: keep the distinction, drop the branches

The instinct is sound — *vision* / *what shipped* / *lessons* are three different things with three
different audiences. **Git branches are the wrong tool for it**, for four reasons:

1. **There is no code difference.** v2 is v1 plus commits. A branch buys nothing and costs a merge.
2. **Two doc sets reintroduce the failure just fixed.** `M2_STATUS.md`'s headline was wrong in
   three places for two days — one error, three copies, found by audit rather than by reading.
   A v1/v2 doc split *guarantees* that class of bug.
3. **Step 4 is a hand merge scheduled last**, when budget is gone — the highest-risk, lowest-value
   step in the sequence.
4. **The repo already has this separation, by document kind:** `plan/*.md` + `PR_Rev_0620.md` =
   the vision; `CONTINUATION.md` + status docs = what shipped; **§14 errata = lessons learned.**

So **step 4 already exists as a mechanism.** "Update the v1 docs with v2's lessons" is *writing
errata* — established practice, its own numbered home, and roughly free.

**Instead:** one branch, and a **git tag** at the pivot point (`v0.2-deterministic`). Tags mark
history without diverging, which is the whole requirement.

### 2.2 What is actually missing (short list — the docs are in good shape)

- **`README.md`** — what this is, what it does today, what it does not, how to run it, where to
  start reading. The entry point that does not exist.
- **The scope statement** (already planned) — designed-vs-built and why, stated once.
- **An architecture diagram** — mermaid, phases 0→4 with what is built vs. designed. Cheap, and it
  is the fastest way for a newcomer to orient.
- Everything else is already done. I am not inventing restructuring work: the 2026-08-19 pass
  collapsed `CONTINUATION.md` 1,016 → 542 lines and established one home per kind of fact.

---

## 3. Sequencing and time estimates

Rates are the project's own measured ones: deterministic work against existing contracts ≈ 1
session per slice; **anything meeting external reality has cost +1 session, every time, without
exception.**

| # | Work | Estimate | Notes |
|---|---|---|---|
| **1** | **`ClaudeCliProvider` + arm 2b (live tier-3 triage)** | **0.75** | **DONE 2026-08-21.** 348 lines, not ~30 — the guards are the module. First contact found a real defect: the triage prompt never defined what a "change id" was, so the model keyed its answers by the origin marker and zero labels parsed. Arm 2b then falsified this plan's own central prediction — tier 3 going live changed **no** scored number (§14.40). Cost measured at last: **$0.019/PR**. |
| **2** | **D — wire `GitCheckout` into `cli.review`** | **0.75** | **DONE 2026-08-21.** Verified on `pallets/flask#5812` — front door reproduced the benchmark's stored `pre_existing=20, APPROVED` exactly, two independent paths agreeing. The predicted fork break **did not occur** (§14.41): GitHub shares an object network across forks, so the existing single-sha fetch reaches an open fork head in a fresh mirror in 1.2s. `fetch_pull_ref` is kept as a fallback for remotes that refuse arbitrary shas, unexercised against GitHub. |
| **3** | **The comparison: arms 1 + 3** | **1.5** | **DONE 2026-08-21.** Four of five predictions held; the two that moved both moved against the tool. Three errata (§14.42–§14.44), two of them defects in numbers already published. Total spend **$5.46**. `BENCHMARK_STATUS.md` §4i. |
| **4** | **Comparison scorecard, HTML** | **0.75** | **DONE 2026-08-22.** `benchmark/report_html.py` + a `compare` subcommand + `comparison.sh`. Building the second renderer found an error in the first one's inputs: it derives the recall ceiling instead of quoting it, and printed 0.250 against four documents saying 0.364 (§14.45). Escaping tested structurally, not by blocklist. |
| **5** | **README + architecture diagram + scope statement + tag** | **0.75** | **DONE 2026-08-22.** `README.md` (mermaid diagram, solid = built / dashed = designed), `CONTINUATION.md` §4.0 as the authoritative designed-vs-built table plus a pivot banner over the pre-2026-08-21 sections, version 0.0.1 → 0.2.0, tag **`v0.2-deterministic`**. |
| **6** | **The writeup** | **0.5** | **DONE 2026-08-22.** `REPORT.md`. Half of it is §5, on the four times the measurement itself broke — which is the part that generalises beyond this repository. |
| | **Total** | **5.0** | **all six delivered.** Nothing on this table was cut. |

**The reshape that saves the plan:** build the HTML page as the **comparison scorecard**, not the
per-PR finding dashboard. `benchmark/report.py` already renders the markdown scorecard, so this is
a second renderer over an existing model, and it serves *both* goals at once — "make it visible"
and "show the measurement." The per-PR dashboard that four plan docs ask for stays unbuilt and
gets recorded as such.

**Budget: ~5 sessions, accepted.** Nothing is cut. Two sequencing rules protect the value if the
5th runs short:

- **The writeup is written as runs land**, not saved for the end — it is where the value is
  concentrated and it must not be what gets squeezed.
- **Item 1 goes first** because it is the shared transport: it de-risks `claude -p` for arm 3, and
  if it fails outright the whole comparison collapses to arm 1 while there is still budget to
  re-plan.

---

## 4. Verification

```bash
cd "/Users/davidsy/PR Review 2026"
.venv/bin/python -m pytest tests/ -q          # 669 + new, unaffected by arms

# SMOKE FIRST — one case each, cents, before any full pass. This is a GATE, not a formality:
#   assert (a) output parses into Finding, (b) score_case runs, (c) usage tokens are NON-ZERO,
#   (d) arm 3's JSON contains NO tool calls (else it has quietly become arm 4).
#   A zero in (c) is the guessed-usage-key failure repeating — a bug, not a result.
.venv/bin/python -m pr_review.benchmark run --corpus benchmark/corpus/labelled.json \
    --arm llm-diff --limit 1 --label smoke-llm
.venv/bin/python -m pr_review.benchmark run --corpus benchmark/corpus/labelled.json \
    --triage-provider claude-cli --limit 1 --label smoke-triage

# Arm 2b — pipeline with tier-3 triage live. New arm, own label: tier 3 now DROPS
# hunks it used to keep, so every scored number moves. The filter ablation
# ("recall after filter") becomes meaningful here for the first time.
.venv/bin/python -m pr_review.benchmark run --corpus benchmark/corpus/labelled.json \
    --cold-profiles --triage-provider claude-cli --label triage-live-labelled

# Arm 1 — config only, no new code
.venv/bin/python -m pr_review.benchmark run --corpus benchmark/corpus/labelled.json \
    --config benchmark/configs/semgrep-only.yaml --label semgrep-only-labelled

# Arm 3 variance — same arm, same corpus, 3 passes, distinct labels; report the spread
```

**Success:** a scorecard with four columns (semgrep-alone · pipeline · pipeline+triage · LLM-diff)
on a **post-cutoff** holdout, carrying real measured token counts on both sides and a run-to-run
variance figure; a README and scope statement that make the unbuilt three-quarters legible as a
decision; and a tag marking the pivot.

**Cut and recorded as cut:** `suppress.py` (B) · the M5 GitHub write path · the per-PR HTML
dashboard · arm 4 (LLM + repo access) · the CAP `InferenceProvider` shim · all of M3 — and the
v1/v2 *branch* structure, replaced by a tag.

---

## ADDENDUM — 2026-08-26, after Plan 3

**Nothing above is edited.** This document is the record of what was cut and why, and a record that
gets rewritten when the situation changes is not a record. Three things in it are now amended.

### A1. §1.4's "and nothing else" has one deliberate exception, and it is a different arm

§1.4 reads: *"The producer sees `pr_task.diff_text` and nothing else: no ground truth, no advisory
summary, **no pipeline output**, no context from this conversation."*

That rule is unchanged and still governs arm 3, whose stored passes were all produced under it.
**Arm 3c breaks exactly one clause of it on purpose** — "no pipeline output" — and nothing else:

- **still forbidden**, unchanged: ground truth, `AdvisoryRef.summary`, the advisory's CWE or GHSA id,
  `PRTask.title`, `PRTask.body`, the repository, tools, any conversation.
- **newly allowed**, and only this: what the pipeline produces for an *unseen* PR through the same
  code path, replayed from a committed capture. Never hand-curated per case.
- **`diff_text` is retained.** The clause broken is *"and nothing else"*, not *"sees `diff_text`"*.
  Arm 3's input is a strict **subset** of arm 3c's — asserted by a test, not intended — which is the
  only reason the two are comparable.

**Everything else in §1.4 held.** Tool-free, neutral cwd, committed prompt file, `claude -p`
subprocess, deterministic `score_case`, not a `Detector`.

### A2. The tool-free assertion in §1.4 was right, and the way it was implemented was not

§1.4 says: *"assert in the smoke run that no tool calls appear in the JSON"*, and calls it belt and
braces because *"the failure is invisible in the output"*. Both correct.

The implementation asserted something narrower and stated it as something broader. It raised on any
call taking **more than one turn** and reported that as *"which means tools ran"*. Tool *use* is what
`--disallowedTools` blocks, so an attempted tool is refused into `permission_denials` and the refusal
then forces a second turn — a denial implies multi-turn, **multi-turn does not imply a denial**.

On 2026-08-26 that cost **five paid corpus passes**, because the check also ran before the scorecard
was written and so deleted the evidence it existed to protect. Errata **§14.60**. The rule §1.4 asks
for is now implemented as §1.4 describes it: a denial is fatal, a bare multi-turn call is recorded.

### A3. Arm 4 stays cut — and the case for it is stronger than when it was cut

*"Arm 4 (LLM + repo access)"* remains cut and is not being revisited. But Plan 3 produced two
measurements that bear on it, and both should be on the page for whoever revisits it:

1. **Bounded context did not help.** Arm 3c gave a model the pipeline's assembled context — enclosing
   symbols, one-hop neighbours, profile slice — and it reviewed no better than from the diff alone
   (`BENCHMARK_STATUS.md` §4x). Arm 4 is the unbounded version of the same idea. **This is evidence
   against it**, though not decisive: §4x lists four reasons the null is a floor.
2. **A single-prompt arm has a maximum pull-request size and the pipeline does not.** Two of the
   negative corpus's fifty PRs exceed any context window — one is 4.37 MB — and both LLM arms refuse
   them while the pipeline reviews both, because it works file by file (§4v). **Arm 4 would inherit
   that ceiling.** An arm with repo access still has to fit what it reads into one context.

**The success criterion in §3 said "a scorecard with four columns".** It has five, on two corpora,
and the fifth is the one that tested this document's own premise. `benchmark/results/comparison.html`.
