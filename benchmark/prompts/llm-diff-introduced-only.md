<!-- ARM 3b — the raw LLM baseline, asked for INTRODUCED vulnerabilities only.

WHAT DIFFERS FROM `llm-diff-baseline.md`, AND WHY

Exactly one instruction. The baseline prompt says:

    Report only vulnerabilities that this diff introduces
    OR LEAVES PRESENT IN THE CODE SHOWN.

That sentence was written to keep the arm from missing a real defect on a
context line. It also means arm 3 was *told* to report pre-existing
vulnerabilities -- and then every one it produced on a post-fix control PR was
scored as a false alarm. So arm 3's `pre_existing = 0` says what the prompt
said, not what a model can do (§14.46).

The pipeline's answer to that question is `findings/delta.py`: scan the base
commit with the same detectors and subtract. It removes 86-97% of raw findings
and is the axis the pipeline most clearly wins on. This arm asks whether a model
can reach the same judgement from a diff alone, with no base tree and no second
scan.

Changing a prompt changes the arm. This file is committed, and any re-run gets
its own --label. Everything else -- model, effort, corpus, producer, scorer --
is identical to arm 3. -->

You are a security reviewer examining a single pull request diff.

Report only vulnerabilities that **this diff introduces**. A vulnerability that
is visible in the surrounding context but was not created by this change is out
of scope: it was already in the code before this pull request, and reporting it
here is a false alarm. Judge from the diff alone. Do not speculate about code
you cannot see, and do not report style, performance, or maintainability issues.

A line with no `+` or `-` marker is context: it was there before this change.
A defect on such a line counts as introduced only if this diff is what makes it
reachable or exploitable — for example, a change that starts passing untrusted
input to an existing unsafe call. Say which changed line does that in your
`why`.

For each vulnerability, give:

- `file` — the path exactly as it appears in the diff
- `start_line` / `end_line` — line numbers in the **post-change** file, i.e. the
  numbering the `+` side of the hunk header describes
- `cwe` — the CWE identifier, e.g. `CWE-89`
- `severity` — one of `critical`, `high`, `medium`, `low`
- `title` — one short line
- `why` — one or two sentences of concrete evidence from the diff

Reply with a single JSON object and no other text:

```json
{"findings": [{"file": "app/db.py", "start_line": 42, "end_line": 42,
               "cwe": "CWE-89", "severity": "high",
               "title": "SQL query built by string interpolation",
               "why": "the diff adds this line, interpolating user_id into the query text"}]}
```

If the diff introduces no vulnerability, reply `{"findings": []}`. An empty
answer is a real answer here and costs you nothing; inventing a finding to look
thorough is the failure mode this is measuring.
