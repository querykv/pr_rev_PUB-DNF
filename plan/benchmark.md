# Plan — Benchmarking & Evaluation

> A first-class harness, not an afterthought. It (a) proves the tool detects real vulns, (b)
> measures the false-positive rate that decides adoption, (c) calibrates confidence, (d) tunes
> the pipeline's thresholds, and (e) runs as a **regression gate** on every change to the tool.
> Package: `pr_review/benchmark/`. Built in M6 but stubbed earlier so each milestone can measure
> itself.

> **Two notes from the build, added 2026-08-09.** Bare paths below like `scoring.py` are relative
> to that package; **`benchmark/` at the repo root is a different thing** — the *data* directory
> holding `corpus/` and `results/`, and it contains no Python. And this landed far earlier than
> "built in M6": the harness existed by 2026-08-07 and has run three corpora since, because M2's
> defects were only findable by measuring. `BENCHMARK_STATUS.md` is its build record.

## 1. Metrics

| Metric | Definition | Why |
|---|---|---|
| **Precision** | TP / (TP+FP) at finding level | trust / noise |
| **Recall** | TP / (TP+FN) vs ground-truth vulns | coverage |
| **F1** | harmonic mean | single headline |
| **Per-taxonomy P/R** | broken out by CWE / OWASP-2025 family | find weak families |
| **False-positive rate** | FP per clean PR (negative set) | **weighted heavily** — FP fatigue kills SAST adoption |
| **Localization accuracy** | finding file + overlapping lines vs fixing-commit lines | is it actionable? |
| **Severity calibration** | predicted vs reference severity (MAE / confusion) | gate correctness |
| **Confidence calibration** | reliability diagram + **ECE** | does "9" ≈ 90% correct? |
| **Cost / latency** | tokens, $, wall-clock per PR; warm vs cold | Principle #4 (must trend down) |

## 2. Ground-truth datasets

### 2a. Real CVE fixing-commits (primary signal — "against CVEs")

From a vulnerability's **fixing commit**: the **pre-fix state is vulnerable ground truth**; the
**post-fix state is the clean control**. We synthesize a **PR-shaped task** by treating the
pre-fix→(reintroduce) or the vuln-introducing diff as the PR under review, with the fixing
commit's changed lines as the ground-truth location.

| Dataset | Shape | Use |
|---|---|---|
| **CVEfixes** | patch-diff, ~1.7k samples, 180 projects, 30 CWEs, real-world | primary Python-filtered set |
| **PrimeVul** (ICSE'25) | 224k functions / 6k vulnerable; merges BigVul·CrossVul·CVEfixes·DiverseVul; **deduped + temporal split** | scale + contamination-resistant eval |
| **CVE-GENIE** | CVEs Jun-2024→May-2025 w/ verifiable exploits | recent, reachability-relevant |
| **GHSA-linked PRs** | advisories → fixing PRs | most PR-realistic; build a small curated Python set |

Scope to **Python** (v1) by language filter. Each sample stored as a `BenchCase` (§4).

### 2b. Synthetic / curated (breadth + scoring)

| Dataset | Notes |
|---|---|
| **OWASP Benchmark** | has an official scorecard; *but synthetic + Java* → use for taxonomy-coverage sanity, not headline numbers |
| **Juliet / NIST SARD** | CWE-labeled; Python subset where available |
| **SecuriBench** | classic taint cases |
| **Intentionally-vulnerable apps** (e.g., a deliberately-insecure Django/Flask target) | end-to-end PR realism for the BAC flagship |

### 2c. Negative set (essential — measures FP rate)

Random **merged PRs from healthy Python repos** + the **post-fix** versions of the CVE pairs
(known clean). Any finding here counts against precision/FP rate.

## 3. Methodology

- **Two granularities:**
  - **PR-level (binary):** does the tool *flag* a PR that contains the planted vuln? (detection)
  - **Finding-level (the real bar):** a TP requires **compatible taxonomy (same CWE family)**
    **AND location overlap** with the fixing commit's changed lines. Defined in
    `benchmark/scoring.py`; near-miss (right file, wrong lines) tracked separately.
- **Contamination control (must-do):** models may have memorized public CVEs. So:
  - Prefer a **temporal holdout: CVEs published after the model's Jan-2026 cutoff**; **report
    results split pre/post-cutoff** so memorization is visible.
  - Use PrimeVul's **dedup**; avoid samples whose fix text leaks the answer.
- **Baselines for lift:** run **Semgrep-alone**, **CodeQL-alone**, and a **raw single-prompt LLM**
  over the same cases → prove the full pipeline (and specifically 3b + 3c) adds value.

  > **Note added 2026-08-26. Two of these three ran, and a fourth was built that this line does not
  > ask for.** Semgrep-alone is arm 1; the raw single-prompt LLM is arm 3, at Sonnet `--effort low`,
  > three passes. **CodeQL-alone was never run.**
  >
  > The addition is **arm 3c**: the same single prompt, given the diff *and* the `ContextBundle`
  > payload Phase 2 assembles — which is what this file's own §3b agents were specified to receive.
  > That exceeds "raw single-prompt" deliberately, because the bullet's stated purpose is to *prove
  > the full pipeline adds value*, and a raw baseline can only price the gap. It cannot say whether
  > the pipeline's own output is what closes it. Arm 3c asks that directly.
  >
  > **It answered no**, on the corpus built for it: recall 15–20 of 36 against arm 3's 17–18,
  > precision 0.50 against 0.51. `BENCHMARK_STATUS.md` §4x, and §7.1 of `REPORT.md` for the four
  > measured reasons that is a floor rather than a verdict.
  >
  > **The ablation this bullet asks for is therefore only half-done.** "Prove the pipeline adds
  > value" has an answer for Phase 3a (it is quiet and free and finds 1 of 36) and now a first answer
  > for what 3b's *input* buys. The verifier ablation two bullets down — "precision before vs after
  > the verifier (3c)" — still has no 3c to ablate, and that naming collision is worth flagging:
  > **this file's "3c" is the adversarial verifier; the benchmark arm called 3c is the context-fed
  > LLM.** They are unrelated. The arm was named for its position after 3b, before anyone checked.
- **Per-stage ablations:**
  - **Recall after the Phase-2 noise filter** (leak check — did the filter drop a vuln file?).
  - **Precision before vs after the verifier (3c)** + **recall cost** (did it refute any TP?).
  - **Detector contribution:** marginal P/R of SCA, IaC, secrets, structural, each agent family.
  - **Warm vs cold cost** (registry/amortization effectiveness).

## 4. Harness design

`benchmark/`:

```python
class BenchCase(BaseModel):
    id: str; source: str                    # "cvefixes" | "ghsa" | "owasp" | "negative"
    repo_snapshot: str                      # path/ref to pre-fix tree
    pr_task: PRTask                          # synthesized diff to review
    ground_truth: list[GTVuln]              # [] for negatives
    cwe: list[str]; published: date | None  # for temporal split
    language: str                           # "python"

class GTVuln(BaseModel):
    cwe: str; file: str; lines: str         # fixing-commit changed lines
```

- `loaders/` adapt each dataset → `BenchCase` (one module per dataset; cached locally).
- `runner.py` runs the **full pipeline** (or an ablation variant) on each case → `Finding[]`.
- `scoring.py` matches findings ↔ `GTVuln` (taxonomy+overlap) → per-case TP/FP/FN.
- `metrics.py` aggregates → P/R/F1, FP rate, calibration (ECE/reliability), cost; splits by
  taxonomy and pre/post-cutoff.
- `report.py` → a markdown + HTML scorecard with diagrams; stored under `benchmark/results/<date>/`.

## 5. Threshold tuning (closes the loop)

The benchmark **tunes**, not just measures:
- Phase-1 **drift thresholds** (`drift_file_pct`, `drift_edge_pct`) via incremental-vs-rebuild
  agreement vs cost.
- Phase-2 **noise-filter** aggressiveness vs recall-after-filter.
- Phase-3c **verifier strictness** (`refute_strictness`) on the precision/recall frontier.
- Phase-4 **gate floors** (`severity_floor`, `confidence_floor`) on the FP/coverage trade-off.
- **CalibrationRegistry** is fit here (raw confidence → empirical P(correct)).

## 6. Regression gate (CI)

`benchmark/gate.py` runs a fast **smoke subset** (a few dozen cases) on every PR to the tool and
fails if P/R/FP regress beyond tolerances; the **full suite** runs nightly. This is the
"regression-eval hook" from Phase 4. Results tracked over time to show improvement.

## 7. Target & honesty

- **v1 target:** detection ≈ the Gemini extension's reported **~P90/R93** ballpark — measured on
  our **real-CVE, post-cutoff holdout** with FP rate reported on the negative set.
- **Caveat (carried from outline §13.7):** Gemini's number is self-reported on *its own* set;
  ours is a harder, **not-directly-comparable** bar. We report our methodology transparently and
  never quote a single number without its FP rate and its pre/post-cutoff split.
- **Cautions baked into reporting:** synthetic benchmarks (OWASP/Juliet) overstate real
  performance; CVE labels are noisy (a "fix" commit may change unrelated lines); always pair
  detection with FP rate.

## 8. Components & acceptance (M6)

| File | Responsibility |
|---|---|
| `benchmark/loaders/*.py` | dataset → `BenchCase` |
| `benchmark/runner.py` | run pipeline/ablations over cases |
| `benchmark/scoring.py` | finding↔ground-truth matching |
| `benchmark/metrics.py` | P/R/F1, FP, calibration/ECE, cost; splits |
| `benchmark/report.py` | scorecard (md/html + diagrams) |
| `benchmark/gate.py` | CI regression gate (smoke + nightly) |

**Acceptance:** produce a scorecard on a real-CVE Python holdout showing P/R/F1 + FP rate +
calibration + cost, with baseline (Semgrep/CodeQL/raw-LLM) and ablation columns, and a green
regression gate wired into CI.
