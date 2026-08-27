"""Benchmark harness (`plan/benchmark.md`).

Built narrow and early rather than whole and late. benchmark.md's own preamble
sanctions this — "built in M6 but stubbed earlier so each milestone can measure
itself" — and M2 has a measurement it cannot make without it: detector precision
on real code (`M2_STATUS.md` §3.2).

WHAT THIS PACKAGE IS SCOPED TO, AND WHAT IT IS NOT

It measures the **deterministic** path only: the 3a detectors plus the injection
sentinel. Every number it produces is a 3a-only number and is labelled as one.
It is *not* the §7 headline (~P90/R93 on a post-cutoff CVE holdout), which is a
whole-pipeline figure that needs Phase 3b and 3c, and therefore Bedrock.

Deliberately absent, all M6: `gate.py` (CI regression gate), the HTML scorecard,
the Semgrep-alone / CodeQL-alone / raw-LLM baseline columns, calibration and ECE,
and the threshold tuning of §5. Three of those are blocked on something that does
not exist here — `detect/codeql.py` was never built, and the raw-LLM baseline and
calibration both need a model.
"""
