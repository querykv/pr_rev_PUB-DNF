# Detector scorecard — negative

**Run:** 2026-08-26T13:36:20 · **cases attempted:** 50 · **completed:** 50 · **wall clock:** 221s

**Code under measurement:** `7536361`

**Scope: one model call per case, and no pipeline.** These numbers come from a single-prompt LLM arm: **no detector ran**, and neither did the noise filter, delta scoping or the injection sentinel. Everything reported is `introduced_by_pr` by construction, because the model never saw a baseline to attribute anything to. Scored by the same `score_case` as every other arm, which is the only thing the arms share.

**Cost / tokens: MEASURED.** 48 model call(s) via the `claude` CLI (`sonnet`, effort `low`): **$1.4922** total, **$0.0298** per completed case.

Tokens, as the CLI reports them: **1,099,839** cached (`cache_creation + cache_read`) plus **6,367** uncached (`input + output`), **1,106,206** in all. Those two buckets are **not** our-content and their-overhead. Claude Code caches its own system prompt and, when our prompt clears the model's minimum cacheable length, our prompt with it — so which bucket our tokens land in varies by prompt size and model, and neither bucket alone names a party (§14.44).

**Derived, not measured here:** at a calibrated floor of 7,300 tokens per call for the CLI's own system prompt, ~**350,400** of the total is harness and ~**755,806** is ours. The subtraction is taken from the *total* rather than from the cached bucket, because doing the latter reported 0 tokens of our own content for a run that had plainly sent some. It rests on a calibration against one CLI build, not on this run. Neither figure is an API price.

**Floor provenance: RECORDED, never calibrated.** This run used `claude` **2.1.246**, which has never been measured, so the split above falls back to the **7,300** calibrated against **2.1.235**. That makes it an extrapolation: whatever this build's system prompt actually costs, the difference is being attributed to our content. The fallback is deliberate — an interpolated floor would be a number with no measurement behind it and no way to tell the two apart. Measure this build per `OPEN_ITEMS.md` §21 before quoting the split; the totals and the cost are unaffected.

---

## Corpus

**Selection criteria, verbatim from the pinned corpus:**

> Ten actively-maintained Python repositories, fixed before any results were seen, chosen to span the surfaces the deterministic detectors read: four server applications with real endpoints and authorization (netbox, saleor, wagtail, prefect) so BAC-MISSING-AUTHZ has somewhere to fire; three web frameworks/libraries (flask, fastapi, django-rest-framework); and three general-purpose libraries (requests, pydantic, poetry) as a noise baseline. Within each repo the most recently updated MERGED pull requests were taken in listing order with no filtering on size, content, files touched, or outcome. The only exclusions are mechanical: PRs whose head commit is no longer fetchable (deleted fork branches) and PRs with an empty diff. No repository or PR was added or removed after seeing what the tool reported on it.

A corpus chosen to flatter the tool is the classic benchmark failure, and printing how it was picked is the only defense a reader has. Cases are pinned by repo, PR number and both shas, so every number below can be re-derived.

## Delta scoping — what the baseline pass removes

- **Raw findings the detectors produced:** 4
- **Attributed to the base tree and dropped:** 0.000 (0/4)
- **False positives per PR, as shipped:** 0.08 (4/50)
- **...if every raw finding were reported:** 0.08 (4/50)

> `findings/delta.py` runs the same detectors over the base commit and drops anything that was already there. This is the single largest effect any stage in this pipeline has on the reported numbers, and it is the capability a diff-only reviewer cannot have: **a tool that never sees the base tree cannot tell an introduced defect from one the PR merely walked past.**

### Three tiers, and only two of them are measured

| tier | what it is | this run |
|---|---|---|
| no scoping | every raw finding reported | 0.08 (4/50) · **derived** |
| hunk-based | no base checkout; a finding counts as introduced when it sits in an edited region | *measured 2026-08-22: 0.32/PR on the negative corpus — and it lost the one gate-relevant finding, §14.48* |
| baseline | the base tree scanned and subtracted | 0.08 (4/50) · measured |

> **The top row is arithmetic, not a run.** It is what this run's own counts imply if nothing were dropped. A genuinely unscoped run would also lose Semgrep's `--baseline-commit` scoping, so the real figure is that one or worse. The middle row *was* run, and it is the tool's real behaviour whenever checkouts are unavailable — `--no-checkout`, an offline `--diff-file`, the whole M0 thread.

> **The middle tier is not the bottom tier with less noise.** It over-reports inside edited hunks and under-reports outside them. On the negative corpus it gained five medium alarms and lost one HIGH — the only gate-relevant finding there, and a correct one. Its gate-relevant rate is therefore *better* than the full pipeline's while its gating is worse. **When a false-alarm rate improves, diff the finding sets before believing it**: an aggregate cannot tell you whether noise or evidence was removed. §14.48.

> **A raw-LLM arm's zero here is the prompt's doing, not the model's.** `llm-diff-baseline.md` asks for vulnerabilities the diff *"introduces or leaves present in the code shown"* — it was told to include pre-existing ones and then scored as wrong for each. **Asked the other way it does the job**: `llm-diff-introduced-only.md` changes that one instruction and took control-PR false alarms to **0 · 0 · 1 of 26 across three passes**, against the baseline prompt's 3 · 5 · 4 — at or below this pipeline's 1 of 26 — while leaving vulnerable-half output inside its own run-to-run range. So the suppression figures above are a real property of this pipeline and **not** a capability only it can have. §14.47, replicated and narrowed to this range in §14.51.

## False positives on known-clean PRs

- **False positives per PR:** 0.08 (4/50)
- **Gate-relevant (high/critical) per PR:** 0.00 (0/50)
- **PRs with no findings at all:** 0.94 (47/50)
- Pre-existing findings excluded from scoring: 0

> Every finding attributed to the PR on known-clean code is counted against the tool. **This is an upper bound on the false-positive rate**, not a point estimate: a merged PR from a healthy repository can still contain a real vulnerability that nobody has found, and any such finding is counted here as a false alarm. It also says nothing about recall — a detector that reports nothing scores perfectly on this set.

### The endpoint stratum

- PRs where the structural detector saw at least one endpoint: **0** of 50
- Endpoints seen across those PRs: **0**
- **False positives per endpoint-touching PR:** n/a (0 cases)
- **`BAC-MISSING-AUTHZ` alarms per endpoint seen:** n/a (0 cases)

> `M2_STATUS.md` §3.2's named worry is that `BAC-MISSING-AUTHZ` fires on every unguarded endpoint in a changed file, including deliberately public ones. Most merged PRs touch no endpoint at all, so that rule cannot fire in them and the corpus-wide average prices it at near-zero — arithmetically true, and an answer to a different question. This stratum is the one that addresses it. The split is derived from what the detector actually saw, not from how the corpus was picked, so neither number is biased by the other's needs.

### Which rules produce the noise

The aggregate above is not actionable on its own; this table is the output that is.

| Taxonomy id | False positives |
|---|---|
| TOOL-UNMAPPED | 4 (100%) |

### By detector

| Detector | False positives |
|---|---|
| llm-diff-baseline | 4 (100%) |

### By severity

| Severity | False positives |
|---|---|
| low | 3 (75%) |
| medium | 1 (25%) |

### Noisiest cases

| Case | False positives |
|---|---|
| wagtail__wagtail#14452 | 2 |
| saleor__saleor#19614 | 1 |
| wagtail__wagtail#14453 | 1 |
| netbox-community__netbox#22764 | 0 |
| netbox-community__netbox#22830 | 0 |

---

<sub>Generated by `pr_review.benchmark`. Deterministic render of a corpus run — no model involved in producing these numbers or this document.</sub>