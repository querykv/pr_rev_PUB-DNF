# Labelled corpus — hand verification

**Date:** 2026-08-07 · **Corpus:** `benchmark/corpus/labelled.json` · **26 advisories, 52 cases,
18 repositories, 36 ground-truth files, 112 spans.**

> `labelled.md` beside this file is **generated** and is rewritten by every build. This one is
> written by hand and is not. Same split `benchmark/results/<date>/` uses between the generated
> `negative.md` and the hand-written `analysis.md`.
>
> Cases dropped on inspection go in `labelled-excluded.txt`, applied with `--exclude`, so the
> corpus stays rebuildable from one command rather than becoming a hand-edited artifact nobody
> can regenerate.

## What was checked

Every accepted advisory, against three questions: does the CWE describe what the diff actually
fixes; is the fixing commit the whole fix; do the spans cover the vulnerable lines and nothing
else. The third is where the work was, and it is the one an automated rule cannot answer.

## What the first pass found, and what it changed

The builder's first output was checked span-by-span against the vulnerable tree. Three classes of
defect came out of it, and **two were fixed in code rather than by editing the corpus**, because a
defect a rule can state will otherwise return on the next build.

### 1. A fix's scaffolding was being labelled as the vulnerability — fixed in code

Seven of the first 28 advisories offered as ground truth a line that no detector could ever flag:

| Advisory | Span | Line |
|---|---|---|
| `GHSA-fp3f-mc75-235c` | `pypdf/_cmap.py:3` | `from math import ceil` |
| `GHSA-fwg2-594c-jp42` | `pypdf/_font.py:24` | `from .errors import PdfReadError` |
| `GHSA-gm37-52c6-37mw` | `pymdownx/__meta__.py:196` | `__version_info__ = Version(11, 0, 0, "final")` |
| `GHSA-f42x-p2mx-hm8r` | `penelope.py:19` | `__version__ = "0.19.2"` |
| `GHSA-c5px-58j2-7fqp` | `src/__init__.py:5` | `__version__ = "1.3.0"` |
| `GHSA-29w2-fq35-v728` | `.../__init__.py:17` | `__version__ = '1.3.47'` |
| `GHSA-9xq3-3fqg-4vg7` | `.../tar_extract.py:40-46` | a six-line comment block |

A fix ships with the import it needs, the version bump that releases it and a comment explaining
it. None of those is the defect, and scoring against one is a **guaranteed miss recorded against
the detector** — the benchmark marking itself wrong.

Fixed with `ghsa._SUPPORTING`: a span is dropped when *every* line in it is an import, a version
assignment, a comment or blank. Narrow on purpose — a span mixing an import with real code
survives intact, and the claim ("an import declares availability; the vulnerability is in the
use") holds for every CWE in this corpus. Two `pymdownx` and one `gemini-bridge` ground-truth
*file* disappeared entirely as a result, which is correct: they contained nothing else.

### 2. One commit was entering the corpus twice — fixed in code

`GHSA-c9hr-64h3-gxpc` and `GHSA-pgwh-4jj4-qm8v` resolve to the same `flytohub/flyto-core` commit.
Both were accepted, pinning the same trees, the same diff and the same 16 ground-truth files under
two ids — double-weighting one commit in the recall numerator **and** its denominator. 28
advisories had resolved to 27 commits. Now deduplicated on `(repo, fix_sha)`.

### 3. Two "fixes" were bulk refactors — excluded by hand

`flytohub/flyto-core@0a0a5285` (16 modules) and `@d5f89d71` (18 modules) thread a shared SSRF
guard and a secret-redaction change through every HTTP-family module. The extracted spans are the
import blocks at the top of each touched module and whatever code sat beside them: they mark where
the **remediation was plumbed**, not where the defect was. Together they would have put 34 of ~70
ground-truth files into one repository's two commits.

Excluded, and **the exclusion is keyed on the commit, not the advisory id** — the first attempt
keyed on the id and leaked. Rejecting `c9hr` freed a per-repo slot that `pgwh`, pointing at the
same commit, walked straight into; the two commits came back under four GHSA ids between them.
`load_exclusions` now accepts `owner/repo@sha`.

## Spot checks against source

Verified line-by-line against the vulnerable tree:

- **`GHSA-wvpp-8hx9-p66j`** (CWE-88, GitPython) — `git/cmd.py:1047-1048` is
  `options.append(f"-{key}" if len(key) == 1 else f"--{dashify(key)}")` and the `if len(key) == 1
  and split_single_char_options:` beneath it, which the fix restructures into a guarded branch.
  Exactly the argument-injection site. **Correct and precisely localized.**
- **`GHSA-gm37-52c6-37mw`** (CWE-1333, pymdown-extensions) — the four surviving spans are the four
  backtracking regexes (`STAR_EM2`, `SUB2`, `SUP2`, the magiclink URL pattern). Correct.
- **`GHSA-jm78-9fvv-mhgr`** (CWE-74, GitPython) — an added-only fix; spans are the insertion points
  where `UNSAFE_CONFIG_CHARS_RE` and `_assure_config_name_safe` went. This is the "absence of a
  guard" shape, and the span marks where the guard belonged. Correct by the rule's own definition,
  and worth remembering when reading its recall: a detector must flag the *absence* of something.
- **`GHSA-cj54-hpcc-gj6h`** (CWE-22, thumbor) — `file_loader.py:19-25` is the `join` + `abspath`
  path construction the traversal exploits. Correct.

## Residual noise, accepted and recorded

Two spans of 112 are still scaffolding, and neither is worth a rule:

- **`GHSA-c5px-58j2-7fqp`** — `src/mcp_server.py:4` is `Version 1.3.0`, free text inside the module
  docstring. Not a comment, not an assignment; the per-line rule cannot see it.
- **`GHSA-29w2-fq35-v728`** — `server.py:37,39` are `READ_ONLY_KEY,` and `REQUIRE_MUTATION_CONSENT,`,
  continuation lines of a multi-line `from … import (…)`. Catching these needs parenthesis
  tracking across the hunk, which is more machinery than two instances justify.

**Direction matters and is the reason these are tolerable.** An unmatchable span adds to false
negatives, so it *understates* recall. The corpus is therefore conservative in the same direction
the negative corpus is: pass 1's false-positive rate is an upper bound, and this corpus's recall is
biased low by roughly 2%. If it were biased the other way it would need fixing before use.

## Known properties of this corpus, to state with any number taken from it

1. **Recall measured here is an upper bound.** In a reverted fix the vulnerable lines are
   essentially the whole diff. A real vulnerability-introducing PR buries them in unrelated change,
   so this is the easiest possible presentation of the defect. The paired control is what keeps the
   number meaningful — it holds the file constant and removes only the vulnerability.
2. **Roughly half the corpus is out of 3a's reach by design.** CWE-400, CWE-1333, CWE-834, CWE-455,
   CWE-200, CWE-59, CWE-61 have no deterministic detector in this milestone. They were **not**
   filtered out — that would be the corpus-flattering failure `selection_criteria` exists to
   prevent, and errata §14.20 already ruled on the same question from the other side. They are
   reported as a stratum instead. A miss there is a milestone boundary, not a detector defect.
3. **n = 26, and two repositories contribute two advisories each.** This is a first measurement,
   not a stable baseline — the same caveat pass 1 carries at n = 50.
4. **Concentration in the source population is severe.** 37 of 54 rejections were the per-repo cap;
   `open-webui` alone accounted for 13. Without the cap this would be a corpus about three
   repositories.
5. **Repo quality is uneven.** Several sources are small, recently-published packages rather than
   established libraries. That is what the recent `pip` advisory feed contains, and filtering on
   perceived repo quality would be selection by another name.
