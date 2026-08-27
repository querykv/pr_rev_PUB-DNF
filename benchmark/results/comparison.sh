#!/bin/sh
# The five-arm comparison page, from the stored runs. Re-runs in seconds and
# re-scores every arm by the current rules, so the page cannot silently mix
# numbers judged by two different scorers.
set -e
cd "$(dirname "$0")/../.."
.venv/bin/python -m pr_review.benchmark compare \
  --title "Five-Arm Comparison Scorecard" \
  --out benchmark/results/comparison.html \
  --arm-run "1 · semgrep alone=benchmark/results/2026-08-21-arm1-semgrep-only::every other detector disabled" \
  --arm-run "2 · pipeline=benchmark/results/2026-08-09-labelled-receivers::deterministic, Phase 3a. Re-run 2026-08-24 from deleted baseline caches and identical on finding identity, 37/37 — OPEN_ITEMS §23 closed." \
  --arm-run "2c · pipeline, hunk scoping=benchmark/results/2026-08-22-arm2c-hunk-scoping::-No base-tree scan (baseline.enabled: false) — what the tool does on --no-checkout and offline. 0.32 FP/PR against 0.24, and it LOST the corpus's one gate-relevant finding, a correct HIGH. Errata §14.48." \
  --arm-run "2b · pipeline + live triage=benchmark/results/2026-08-21-triage-live-negative::!-Cost only. Tier-3 triage ran on 33 of 50 negative-corpus PRs and changed no scored number: pipeline.py builds the detect stage from the manifest, not from the filter's kept set, so what tier 3 decides routes Phase-3b agents and Phase 3b does not exist. Confirmed at n=50. Errata §14.40." \
  --arm-run "3 · raw LLM, pass 1=benchmark/results/2026-08-21-arm3-llm-p1::sonnet, --effort low, diff only, no tools" \
  --arm-run "3 · raw LLM, pass 2=benchmark/results/2026-08-21-arm3-llm-p2::same prompt, same corpus" \
  --arm-run "3 · raw LLM, pass 3=benchmark/results/2026-08-21-arm3-llm-p3::same prompt, same corpus" \
  --arm-run "3b · raw LLM, introduced-only, pass 1=benchmark/results/2026-08-22-arm3b-introduced-only::one instruction changed: report only what the diff INTRODUCES. Three passes now run — control-half output 0 · 0 · 1 against the baseline prompt 3 · 5 · 4, non-overlapping. Errata §14.51." \
  --arm-run "3b · raw LLM, introduced-only, pass 2=benchmark/results/2026-08-24-arm3b-introduced-only-p2::same prompt, same corpus" \
  --arm-run "3b · raw LLM, introduced-only, pass 3=benchmark/results/2026-08-24-arm3b-introduced-only-p3::same prompt, same corpus. The pass that falsified the recall-cost claim in §14.47: recall 0.444 beats every baseline pass, and it produced the arm's only control-half finding." \
  --arm-run "3c · pipeline-fed LLM, pass 1=benchmark/results/2026-08-26-arm3c-labelled-p1::THE ARM PLAN 3 EXISTS TO MEASURE. Same model, same effort, same corpus, same scorer as arm 3 — and arm 3's input is a strict SUBSET of this one's, asserted rather than intended, so a difference is attributable to the added context and nothing else. It receives the diff plus the ContextBundle list Phase 2 builds for the same PR, replayed from a committed capture. Result: no improvement. BENCHMARK_STATUS §4x." \
  --arm-run "3c · pipeline-fed LLM, pass 2=benchmark/results/2026-08-26-arm3c-labelled-p2::same prompt, same corpus, same capture. The arm's best pass — recall 20/36, above every arm-3 pass — and its existence is why one pass could not have been published." \
  --arm-run "3c · pipeline-fed LLM, pass 3=benchmark/results/2026-08-26-arm3c-labelled-p3::same prompt, same corpus, same capture. The arm's worst pass — recall 15/36, below every arm-3 pass. Best and worst straddle arm 3 entirely: mean 16.7 against 17.7, spread 15-20 against 17-18." \
  --arm-run "3 · raw LLM on ordinary PRs, pass 1=benchmark/results/2026-08-26-arm3-negative-p1::!Negative corpus, 50 merged PRs from healthy repositories — every finding counts against the tool. Arm 3 had never been run here before 2026-08-26, so the context arm below had no baseline to be compared with. 3 false alarms, and ZERO gate-relevant findings across all three passes." \
  --arm-run "3c · pipeline-fed LLM on ordinary PRs, pass 1=benchmark/results/2026-08-26-arm3c-negative-p1::!Negative corpus. False alarms ROSE, 3.3 to 5.0 mean — but this arm emits five BAC-MISSING-AUTHZ findings across three passes where arm 3 emits none, naming the pipeline's own vocabulary. That is ProfileSlice.access_control_rows reaching the model's output: the context works, in the sense that it redirects attention exactly as designed. On clean PRs that produces false alarms."
