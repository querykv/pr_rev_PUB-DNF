# Detector scorecard — iac

**Run:** 2026-08-19T16:18:43 · **cases attempted:** 20 · **completed:** 20 · **wall clock:** 176s

**Code under measurement:** `7440b0b-dirty`
**Rescored:** 2026-08-26T12:41:34 by `b34cef5-dirty`, replaying the stored run above. The pipeline was not re-executed — every finding below is the one `7440b0b-dirty` produced, re-judged by this commit's scoring rules. If two scorecards disagree, this line says which of the two things moved.


**Scope: 3a only.** These numbers cover the deterministic detectors (secrets, structural CPG, semgrep, sca, iac) plus the injection sentinel. Phase 3b agentic families and the 3c verifier are not built and are not measured here, so this is **not** the `PR_Rev_0620.md` §13.7 / `benchmark.md` §7 headline (~P90/R93 on a post-cutoff CVE holdout), and it is not comparable to the Gemini extension's self-reported figure — §7 already records that ours is a harder, not-directly-comparable bar.

**Cost / tokens: UNMEASURED.** No model is invoked anywhere in this harness, so there is nothing to count. This is not a claim that the tool is cheap; per `M1_STATUS.md` §4 the token accounting itself is still unverified against a real provider.

---

## Corpus

**Selection criteria, verbatim from the pinned corpus:**

> Four infrastructure-as-code repositories, fixed before any results were seen, chosen so that iac.py has real input for the first time: it reports not_applicable on all 102 cases of the negative and labelled corpora, both of which are Python-only by construction (M2_STATUS.md blind spot 8). Two Terraform module repositories (terraform-aws-modules/terraform-aws-vpc, terraform-aws-modules/terraform-aws-eks) exercise checkov's HCL checks, and two Docker image repositories (docker-library/postgres, docker-library/python) exercise its Dockerfile checks, which are a different code path. Repository selection was screened: recent merged PRs in each candidate were sampled and the fraction touching a classify.is_iac file was counted, because a Terraform module repo's PR stream is substantially GitHub Actions and pre-commit churn that iac.py correctly ignores. terraform-aws-modules/terraform-aws-security-group was rejected on that screen at 1 of 4. THE SCREEN WAS APPLIED TO REPOSITORIES, NEVER TO PULL REQUESTS: within each repo the most recently updated MERGED pull requests were taken in listing order with no filtering on size, content, files touched, or outcome, the same rule as the negative corpus. Cases whose PRs touch no IaC file are kept deliberately — a detector that reports not_applicable when there is nothing to scan is the contract being tested (AdapterRun status, M2_STATUS.md section 2), not a wasted case. Helm and Kubernetes chart repositories were deliberately excluded: classify.is_iac matches yaml only on a literal /k8s/ or /helm/ path segment, so the charts/<name>/templates/*.yaml layout those repos actually use would not classify, and such a corpus would measure the classifier rather than the adapter (OPEN_ITEMS.md). This is a COVERAGE corpus, not a precision claim: four repositories across two organisations is enough to answer whether the adapter works on real input and is not enough to support a false-positive rate. No repository or PR was added or removed after seeing what the tool reported on it.

A corpus chosen to flatter the tool is the classic benchmark failure, and printing how it was picked is the only defense a reader has. Cases are pinned by repo, PR number and both shas, so every number below can be re-derived.

## Detectors actually exercised

A detector that found nothing and a detector whose binary is absent produce the same empty list. These are the `AdapterRun.status` counts across the corpus; anything not mostly `ran` means the numbers below do not cover that detector.

| Detector | Status counts |
|---|---|
| iac | not_applicable: 4 · ran: 16 |
| sca | not_applicable: 20 |
| secrets | ran: 20 |
| semgrep | ran: 20 |
| structural | not_applicable: 20 |

## Delta scoping — what the baseline pass removes

- **Raw findings the detectors produced:** 206
- **Attributed to the base tree and dropped:** 0.825 (170/206)
- **False positives per PR, as shipped:** 1.80 (36/20)
- **...if every raw finding were reported:** 10.30 (206/20)

> `findings/delta.py` runs the same detectors over the base commit and drops anything that was already there. This is the single largest effect any stage in this pipeline has on the reported numbers, and it is the capability a diff-only reviewer cannot have: **a tool that never sees the base tree cannot tell an introduced defect from one the PR merely walked past.**

### Three tiers, and only two of them are measured

| tier | what it is | this run |
|---|---|---|
| no scoping | every raw finding reported | 10.30 (206/20) · **derived** |
| hunk-based | no base checkout; a finding counts as introduced when it sits in an edited region | *measured 2026-08-22: 0.32/PR on the negative corpus — and it lost the one gate-relevant finding, §14.48* |
| baseline | the base tree scanned and subtracted | 1.80 (36/20) · measured |

> **The top row is arithmetic, not a run.** It is what this run's own counts imply if nothing were dropped. A genuinely unscoped run would also lose Semgrep's `--baseline-commit` scoping, so the real figure is that one or worse. The middle row *was* run, and it is the tool's real behaviour whenever checkouts are unavailable — `--no-checkout`, an offline `--diff-file`, the whole M0 thread.

> **The middle tier is not the bottom tier with less noise.** It over-reports inside edited hunks and under-reports outside them. On the negative corpus it gained five medium alarms and lost one HIGH — the only gate-relevant finding there, and a correct one. Its gate-relevant rate is therefore *better* than the full pipeline's while its gating is worse. **When a false-alarm rate improves, diff the finding sets before believing it**: an aggregate cannot tell you whether noise or evidence was removed. §14.48.

> **A raw-LLM arm's zero here is the prompt's doing, not the model's.** `llm-diff-baseline.md` asks for vulnerabilities the diff *"introduces or leaves present in the code shown"* — it was told to include pre-existing ones and then scored as wrong for each. **Asked the other way it does the job**: `llm-diff-introduced-only.md` changes that one instruction and took control-PR false alarms to **0 · 0 · 1 of 26 across three passes**, against the baseline prompt's 3 · 5 · 4 — at or below this pipeline's 1 of 26 — while leaving vulnerable-half output inside its own run-to-run range. So the suppression figures above are a real property of this pipeline and **not** a capability only it can have. §14.47, replicated and narrowed to this range in §14.51.

## False positives on known-clean PRs

- **False positives per PR:** 1.80 (36/20)
- **Gate-relevant (high/critical) per PR:** 1.00 (20/20)
- **PRs with no findings at all:** 0.85 (17/20)
- Pre-existing findings excluded from scoring: 170

> Every finding attributed to the PR on known-clean code is counted against the tool. **This is an upper bound on the false-positive rate**, not a point estimate: a merged PR from a healthy repository can still contain a real vulnerability that nobody has found, and any such finding is counted here as a false alarm. It also says nothing about recall — a detector that reports nothing scores perfectly on this set.

### The endpoint stratum

- PRs where the structural detector saw at least one endpoint: **0** of 20
- Endpoints seen across those PRs: **0**
- **False positives per endpoint-touching PR:** n/a (0 cases)
- **`BAC-MISSING-AUTHZ` alarms per endpoint seen:** n/a (0 cases)

> `M2_STATUS.md` §3.2's named worry is that `BAC-MISSING-AUTHZ` fires on every unguarded endpoint in a changed file, including deliberately public ones. Most merged PRs touch no endpoint at all, so that rule cannot fire in them and the corpus-wide average prices it at near-zero — arithmetically true, and an answer to a different question. This stratum is the one that addresses it. The split is derived from what the detector actually saw, not from how the corpus was picked, so neither number is biased by the other's needs.

### Which rules produce the noise

The aggregate above is not actionable on its own; this table is the output that is.

| Taxonomy id | False positives |
|---|---|
| CFG-IAC | 16 (44%) |
| CFG-DEFAULT-CREDS | 16 (44%) |
| SEC-PASSWORD | 4 (11%) |

### By detector

| Detector | False positives |
|---|---|
| checkov | 32 (89%) |
| builtin-secrets | 4 (11%) |

### By severity

| Severity | False positives |
|---|---|
| high | 20 (56%) |
| medium | 16 (44%) |

### Noisiest cases

| Case | False positives |
|---|---|
| docker-library__postgres#1416 | 12 |
| docker-library__postgres#1415 | 12 |
| docker-library__python#1123 | 12 |
| terraform-aws-modules__terraform-aws-vpc#1302 | 0 |
| terraform-aws-modules__terraform-aws-vpc#926 | 0 |

---

<sub>Generated by `pr_review.benchmark`. Deterministic render of a corpus run — no model involved in producing these numbers or this document.</sub>
