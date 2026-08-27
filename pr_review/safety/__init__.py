"""Trust boundaries and prompt-injection defense (cross-cutting §9).

Three of §9's four mechanisms live here, and they are three different answers to
the same fact — everything read from a repository is untrusted:

- `wrap.py` (§9.1) controls **placement**: untrusted text is fenced, labelled
  with its provenance, and never put where a model reads instructions.
- `sentinel.py` (§9.3) controls **detection**: an instruction aimed at the
  agents is reported as an `LLM-PROMPT-INJ` finding and flags the file it came
  from. It runs against the manifest, *before* the noise filter, because a
  comment-only hunk is both where an injection lives and what tier 1 drops.
- `permissions.py` (§9.2) controls **capability**: personas are bound only the
  tools their role permits, so the planner cannot read source no matter what the
  source it never reads tells it to do.

§9.4 (determinism for audit) is not a module: it is the verifier's `effort`
pinning at M4, plus tool-call logging that CAP already does.
"""
