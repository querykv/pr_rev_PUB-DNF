# Open items — found and not fixed

Things this branch turned up that were **deliberately left alone**, with enough context to decide
each without re-deriving it. Nothing here is a regression: every item is either a design question,
a documented gap, or a consistency wrinkle that currently behaves correctly by accident.

Resolved items stay, struck through with what was decided and why, because the reasoning is the
part that gets re-derived otherwise.

Ordered by what it costs to leave them. **9 of 27 closed, and §27 partly** (§1, §4, §5, §12, §18, §20, §22, §23,
§24); §10, §13 and §17 measured but open; **§21's trigger made mechanical, and it fired** — twice,
the second time on 2026-08-26 against an uncalibrated CLI build.
**§27 is the one to read first.** It is the only open item that changes a *published* number, it was
found by reading findings the metrics had already dismissed, and it is under a standing constraint,
so it needs a decision rather than an afternoon.
§25 and §26 both came out of Plan 3 and both are **deliberately deferred until the arm has run**:
each would change the context the arm receives, and changing the input mid-experiment is the
confound Step 2's pinned capture exists to prevent.

**What is left is Group B of `.claude/handoff/PLAN-2-CONTINUATION.md` — §8, §3, §16, §11 — and all
four are safe to leave.** Each costs *capability*, not correctness: none can silently corrupt a
published number, and none gets worse with time. That is the distinction this file is ordered by,
and 2026-08-24 is the day it earned its keep — §21 was filed as "cost of leaving: today, zero" and
had **already expired** when a mechanical check was finally built for it.
Last updated **2026-08-26** — §27 filed from Plan 3 Step 5's smoke; §26 from Step 3. Before that, §25 (2026-08-25); §19 re-derived and confirmed
at 0.250 (errata §14.50); §22 and §23 measured. Items 10 to 13 came from the receiver-collision work
(`BENCHMARK_STATUS.md` §4g) and item 14 from a plan-against-tree audit, both 2026-08-09; items 19 to
23 from the four-arm comparison, 2026-08-21/22, and **item 24 from reviewing the continuation plan**
on 2026-08-24 (§21's trigger was made mechanical the same day and fired immediately — §4l.3) — the only entry here not found by a corpus run or an audit of the tree. Item 3's
remaining two entries are unchanged and still open; §4g explains why they were not done first.

**This header has been wrong before.** It read "Last updated 2026-08-09" until 2026-08-24, on a file
that by then carried five items and two closures dated 2026-08-22. A date that is maintained by hand
decays exactly like the figures §14.50 is about; if it disagrees with the newest entry below, trust
the entry.

---

## ✅ 1. Should SCA skip a lockfile's editable self-entry? — **decided 2026-08-08: yes**

Resolved. `detect/sca.py:_first_party` drops packages the lockfile marks as this repository's own
source, counts them in `detail["first_party_skipped"]` and states the drop in the adapter's notes.
Errata **§14.33**; the mechanism it closes is §14.32.

Decided on the mechanism rather than the number, which is why 10 dependency-changing PRs was enough:
osv-scanner is asked *"is this **dependency** vulnerable"*, and the first-party entry is the subject
of that question rather than an answer to it. The remediation the adapter generates — "Upgrade
`<name>` to `<version>` or later" — is addressed to the people who publish `<name>`, who are the
people reading the review. The real case the counter-argument wanted kept is kept by the note; it
wants different words and a different severity than an upgrade instruction.

The filter went in `parse()` and not `changed_packages()` for a reason the offline data supplied:
filtering the delta would have emptied saleor's, flipped `applicable()` to `False` and dropped `sca`
from `ran: 10` to `ran: 8` — reducing measured coverage to remove a finding that was never emitted.

## 2. `composer.lock` and `Gemfile.lock` first-party entries are not detected — **documented gap**

`_first_party` covers the `[[package]]` formats: uv, pdm and poetry mark a local package in
`source`, and Cargo marks one by the **absence** of `source`. Neither of the other two is handled:
composer.lock has no root entry to confuse, so it needs nothing; Bundler's equivalent is the `PATH`
section's `specs:`, and that one is a real gap.

Left alone because no case in either corpus reaches it, and a parser nothing exercises is a parser
nobody knows is wrong — the same reasoning as item 4 below, and the opposite of inventing a fixture
to make an untested branch look pinned. Revisit when a Ruby case enters a corpus.

## 3. Eight more inert catalog keys — **two closed, and one stated reason was wrong**

`tests/test_m1_schemas.py:_DECLARED_NOT_READ` lists every key `python.yaml` declares that no module
reads, with a reason each, and the test fails on any new one. Of the nine it found, three were real
gaps rather than decoration:

- ~~**`auth.router_kwarg`** — FastAPI's router-level `dependencies=[...]`.~~ **Read, 2026-08-08** by
  `promote._router_guards`, same-file only. **Its stated justification was wrong and that is the
  more useful finding** — see the correction below. A sibling key it turned out the catalog had
  never declared, `auth.route_decorator_kwarg`, went in beside it.
- **`sources.param_annotations`** — FastAPI `Body`/`Query`/`Form` annotations mark a parameter as
  request-derived; `cpg.py` seeds taint from attribute chains and calls, so these are unseeded
  sources. Still open.
- **`sinks.*.danger_kwarg` / `conditional_calls`** — `shell=True`, `yaml.load(Loader=...)`. Both
  need call-*argument* extraction, the same ParseCache gap that defers Django route tables. One fix
  would close both. Still open — and note `_kwarg_region` / `_dep_names` in `promote.py` are now a
  worked example of reading an argument off the cached tree, if not directly reusable in `cpg.py`.

Two things the guard reader deliberately refuses, both stated in `promote._router_guards` and pinned
by tests: a router bound **inside a conditional**, and a name **rebound at module level**. Both are
real bindings at runtime and both are dropped, because over-attributing a guard *suppresses* a
`missing-authz` finding while under-attributing one only adds noise. That is recall the reader does
not have; it is a deliberate trade, not an oversight.

**The correction.** This item claimed `router_kwarg` inflated `missing-authz` (0.149, 11/74) and was
therefore the one to do first because it corrupted a published number. It does not, and it never
did. All 11 of those findings are in **one file** — `wagtail/api/v3/routers/pages.py`, PRs #14452
and #14453 — which is **django-ninja**, not FastAPI, and contains no `dependencies=` anywhere. Nine
are endpoints that enforce authz **imperatively in the body**
(`page.permissions_for_user(request.user).can_publish()`), which is **defect 4**, deferred to M3
with the BAC agent. The other two, `list_pages` and `find_page`, are deliberately-public reads over
a tier-filtered queryset — §3.2's named worry, arriving for real.

Third time for the same mistake: **a counter was predicted to move because the input reached it,
rather than because the event it counts happened** (after `first_party_skipped` and "pre-existing
falls"). The cost of checking was twenty minutes; the cost of not checking would have been a
measurement that came back flat with nothing anywhere saying why. Full record in
`BENCHMARK_STATUS.md` §4f.

What the two keys are actually worth: matrix hygiene, in the same class as §14.24's 8,297 phantom
mock-target rows, and **not** a metric. Their whole measurable population on the negative corpus is
inside `fastapi__fastapi`'s own test suite. The production usage is elsewhere — flyto-core's 20
route-decorator sites in the labelled corpus, and Prefect's 9, which are item 8.

## ✅ 4. Two corpora sharing a `--label` silently lose one's `run.json` — **CLOSED 2026-08-24**

`report.write_scorecard` names the markdown per corpus (`negative.md`, `labelled.md`) but writes
`run.json` at a **fixed path per directory**. Run both corpora with the same `--label` and the
second refuses rather than clobber — correct, and it does it *after* the run, so 844 seconds of work
produces a scorecard on stdout and no dump. Hit on 2026-08-08.

Prior sessions avoided it by convention (`-lockfiles` / `-labelled-lockfiles`), which is not a
mechanism. Either name the dump per corpus (`<corpus_name>.run.json`, matching the markdown) or
check the target before running rather than after. The second is the better fix: nothing about this
needs a whole run to discover.

**Closed 2026-08-24 with the second fix.** `report.precheck_scorecard()` runs in
`benchmark run` before the corpus does, and `report.scorecard_target()` is the shared path
derivation so the pre-flight and the real write cannot drift apart. Renaming the dump was **not**
done: `<corpus_name>.run.json` would break every `--run .../run.json` path in the docs, the
`comparison.sh` arms and `report_html.load_arm`, to fix a collision the pre-flight already catches.

Verified against the real scenario rather than a unit fixture: two corpora, one `--label`, where
`labelled.md` is free and only `run.json` collides. It now fails in under a second instead of after
the run. `test_two_corpora_under_one_label_collide_on_the_dump_not_the_scorecard` pins exactly that
asymmetry, because a pre-flight that checked only the markdown would have passed this case — which
is the case that actually happened.

**A limit, stated because a pre-flight invites the wrong assumption.** It is not a lock. The results
directory is keyed on *today's* date, so a run beginning 23:58 and ending 00:03 writes somewhere the
check never looked, and a concurrent run can take the name in between. The post-write refusal stays
and is what actually protects the file; this only makes the common case cheap to find.

## ✅ 5. Two sources of truth for "is this a lockfile" — **CLOSED 2026-08-24**

`extract/classify.py:_LOCKFILES` lists five names; `extract/deps.py:_FORMATS` now lists eleven.
They do not disagree today only because `classify.is_lockfile` also accepts any `.lock` suffix,
which happens to cover `uv.lock`, `pdm.lock`, `Cargo.lock`, `composer.lock` and `Gemfile.lock`.

`composer.lock` is the one to watch: it is caught by the suffix rule, but a future format ending in
`.json` (as `package-lock.json` already does) would be recognized by `deps.py` and **not** by
`classify.py`, so `filter.py:_lockfile_captured` would never fire for it — a `DepDelta` with no
drop, silently. The two lists want to be one derived from the other.

Not fixed because it is behaviour-neutral today and the fix touches the filter's drop path, which
should not move in the same commit as a measurement.

**Closed 2026-08-24, and it is still behaviour-neutral — which was the point of doing it now.** No
measurement moved in this commit, so the objection above is discharged rather than ignored.

`deps.py` gained `lockfile_names()` and `manifest_names()`, derived from `_FORMATS` by partitioning
on `LOCKFILE_FORMATS`, and `classify._LOCKFILES` / `_DEP_MANIFESTS` are now *those calls* instead of
two hand-kept sets. `deps.py` is the right owner because it is the module that actually parses these
files. The `.endswith(".lock")` rule stays as a superset safety net: dropping it would narrow
behaviour, and narrowing `is_lockfile` removes a *drop*, which is the direction that adds noise.

**Neutrality was proved, not asserted.** Both old predicates were reimplemented and compared against
the new ones over 27 names — every name either side could plausibly see, plus the five §5 names to
watch: **zero differences.** `_DEP_MANIFESTS` turned out to equal `manifest_names()` exactly, so the
same accident was running in the manifest half and is now gone too.

The predicted failure has a test: `test_a_new_json_suffixed_lockfile_is_recognised_without_a_second_edit`
appends a `bun-lock.json` format to `_FORMATS` and asserts `classify` sees it. Falsified by restoring
the hardcoded five — the test goes red on exactly that name. So the expiry §5 named is now the thing
the suite checks, rather than a paragraph hoping someone remembers.

## 6. Rust, PHP and Ruby have lockfiles but no manifests — **documented gap, deliberate**

No `Cargo.toml`, `composer.json` or `Gemfile` in `deps.py:_FORMATS`. Recorded in that module's
docstring with the reasoning: SCA is the only consumer, osv-scanner rejects manifests because a
declared *range* is not a version an advisory can be checked against, and a manifest this module
does not recognize is simply reviewed as an ordinary file — the safe direction.

Revisit only when something reads declared ranges. Adding them now buys nothing and widens the set
of files the filter is entitled to reason about.

## 7. `_GEMFILE_SPEC_RE`'s four-space floor has no test that can fail — **known, stated in place**

`_parse_gemfile_lock` requires indent ≥ 4 **and** a version starting with a digit. On Bundler's
real output the digit test alone is sufficient: every `DEPENDENCIES` and nested-requirement line
carries an operator, and Bundler never emits a bare version at less than four spaces. So the indent
floor rejects nothing the other test does not already reject, and no honest fixture falsifies it.

It is kept because it is the structure of the file, and the docstring says plainly that it is not
load-bearing — per errata §14.29, a guard no test can falsify must not be left *looking* tested.
Either fixture-hunt for a real case or drop the clause; do not add a synthetic test that Bundler
would never produce, which would only make the guard look pinned.

## 8. `include_router(r, dependencies=[...])` is cross-file — **deferred, with a mechanism**

The third way FastAPI declares a router-level guard, and the one item 3 did not close. Nine real
production sites in Prefect (`src/prefect/server/api/server.py:486`), 200 more in fastapi's tests.

Deferred because it is **cross-file**, and two constraints make reaching for it wrong rather than
merely hard:

- `CPG.splice_violations()` treats any edge whose ends are in different files as a violation, and
  `incremental.py` raises `NotSpliceable` on it — so a `guards` edge from the module that assembles
  the app to the module that defines the endpoint forces a full rebuild on **every** incremental run.
- `incremental.py` re-derives from a `partial_cache` holding only the changed files, so the lookup
  would silently find nothing on the incremental path while succeeding on the full one.
  `extract_frameworks`'s docstring is explicit that these two must never disagree about what an
  endpoint is.

Pinned by `test_include_router_dependencies_are_deliberately_not_read`, so the deferral stays a
decision. Revisit only with a design that reads the same on both paths — most likely a repo-wide
pre-pass that resolves inclusions into a name→guards table *before* extraction, rather than an edge.

## 9. Any `Depends(...)` counts as an authorization guard — **pre-existing, now visible**

`promote._extract_function_endpoints` treats every dependency as a guard, without checking the name
against `auth.dependency_names`. So `def endpoint(db=Depends(get_db), user=Security(get_user, ...))`
is `enforced`, and the matrix can report `auth_pattern: dependency:get_db` — a database session
named as the endpoint's authorization mechanism.

Not introduced by the `dependencies=` work; that only made it legible, because ordering `guards` by
source position put `get_db` first in 10 rows where the previous set-iteration order happened to
put `get_user` first (`BENCHMARK_STATUS.md` §4f). The rows were never stable, so this is not a
regression — it is a pre-existing looseness that a determinism fix exposed.

Left alone deliberately, in both directions. Restricting guards to `dependency_names` would make the
catalog's starter list load-bearing for whether an endpoint is enforced at all — a short list of
eight names against which every real project's own guard function would fail, turning a precision
wrinkle into recall loss on Broken Access Control. And it is the *same* looseness the router and
route-decorator forms inherit by design, so changing it is one decision about three guards, needing
its own measurement. Revisit with defect 4 and the BAC agent, which is where "is this dependency an
authorization check?" is a judgement rather than a lookup.

**The trigger is now on the path, 2026-08-24.** "Revisit with the BAC agent" is a reminder, and this
file's own standard (§15) is that a trigger should be mechanical. `CONTINUATION.md` §4.0 already
named this among the three input defects to read before M3; it now also carries a pointer **at the
seams table**, which is what a session actually scans when wiring an agent up. Stated plainly, since
it is the part that expires: **the deferral above is safe exactly as long as M3 stays unbuilt.** The
moment a model is judging whether a dependency authorizes, a documented precision trade becomes a
live Broken Access Control correctness bug — on the flagship family.

## 10. Catalog patterns are audited for *readership*, never for *correctness* — **class, narrowed 2026-08-24**

`tests/test_m1_schemas.py` requires every key in `python.yaml` to name the module that reads it.
That is the whole audit. `sinks.sql.calls` contained `text`, was read by `cpg._call_patterns`, and
passed — while matching `request.text`, `part.text` and `clipboard.text` as SQL sinks.

Four patterns were checked against the corpora and narrowed on 2026-08-09 (`BENCHMARK_STATUS.md`
§4g): `text`, `exec`/`eval`, `escape`, `poll`/`consume`. **The rest of the file has not been checked
the same way.** What was checked and cleared, with its evidence, is in the catalog comments;
everything else is unmeasured rather than known-good.

### The five named next targets were censused 2026-08-24 — all five are correct

~~The ones most worth doing next are the patterns whose sink class is actually reported and whose
receiver could be anything — `from_string`, `mark_safe`, `format_html`, `extractall`, `urlopen`.~~
**Measured.** Receiver census over the cached CPGs, the same method and the same population §4g
used. Full record and per-receiver tables: `BENCHMARK_STATUS.md` §4m.

| pattern | nodes | distinct receivers | collisions | verdict |
|---|---|---|---|---|
| `extractall` | 53 | 4 | **0** | correct — leave it |
| `from_string` | 123 | 9 | **0** | correct — every receiver is a template environment |
| `mark_safe` | 546 | 1 | **0** | correct — always bare, Django imports it directly |
| `format_html` | 194 | 1 | **0** | correct — same |
| `urlopen` (source) | 30 | 4 | **0** | correct — includes urllib3's `conn.urlopen`, a real network read |

**Nothing was changed, so nothing needs re-running.** No `ANALYZER_VERSION` bump, no corpus re-run,
no published number moves. A census that clears a pattern is a *measurement*, and its cost is the
paragraph you are reading.

**`extractall` is the one that mattered, and the answer is the opposite of "narrow it".** It is the
sink behind the pipeline's **only scored true positive** — `tar.extractall(local_download_folder)`
at `penelope.py:3418`, CWE-22, flowing from `tarfile.open` two lines earlier. Every real receiver in
the census is a **local variable** — `tar`, `zf`, `z`, `archive` — plus poetry's own module-level
`extractall()` wrapper around `zipfile`/`tarfile`. There is no dotted form to narrow *to*: the
method name is the entire signal, because `extractall` exists on `TarFile` and `ZipFile` and
essentially nowhere else in Python. **Any narrowing that required a dotted receiver would delete the
project's single true positive.** `tests/test_cpg.py:283` already pins it; that test is the guard,
and it should be read before anyone touches this line of the catalog.

This is §4g's own warning, vindicated on the first pattern it was applied to: *do not assume a
single-segment pattern is wrong because it is single-segment.* `text` collided 45 times in 1,632
nodes; these five collided **0 times in 946**.

**What stays open.** The census covers the patterns whose receiver could plausibly vary and whose
sink class is reported. The rest of `python.yaml` is still unmeasured, and §11's `open` — 2,828
receivers, the largest ambiguous pattern — is deliberately untouched for the reasons in that entry.
The class is narrower than it was, not closed.

Note what makes this class invisible to the audit that found the inert keys: an inert key is
detectable by *reading the code*, and a wrong pattern is only detectable by *reading the corpus*.
The same distinction cost §4f a whole premise. **A key that is read is not a key that is right.**

## 11. `open` has 2,828 receivers and is still both a source and a sink — **deliberately left**

The largest remaining ambiguous pattern: `prefect_file.open` 762, `path.open` 242,
`locker.lock.open` 210, `Image.open` 146, `client.open` 122. Unlike `exec` or `poll`, **most of these
are real file opens** — `pathlib.Path.open`, PIL's `Image.open`, `gzip.open` — so exact-matching it
would cut genuine coverage, and it is also the corpus's single largest source *and* sink population.

Left alone because it is a different question from item 10's: not "is this pattern matching the
wrong thing" but "is a file read untrusted input, and when." `_self_pairing` (§14.31) already
narrowed the worst of it. Revisit with its own measurement, not as part of a receiver sweep.

## ✅ 12. A duplicate key in `python.yaml` silently discards the earlier list — **CLOSED 2026-08-22**

PyYAML's `safe_load` keeps the **last** of two identical keys and says nothing. A block written
with a stray second `calls:` therefore loses every pattern in the first one, with no error, no
warning, and no test failure unless something asserts that exact pattern.

Found while falsifying item 10's fix: the mutation added a second `calls:` key intending to loosen a
pattern, and instead deleted it — the pinning test passed, and a live guard reported as **INERT**.
The catalog is data read by one loader, so this is cheap to close: load with a duplicate-rejecting
loader, or have the coverage test parse the file twice and compare key counts. `_call_patterns` now
raises on the related case (a pattern in both `calls` and `exact_calls`), but that guard cannot see
duplicate keys — by the time it runs, PyYAML has already thrown one away.

**Closed 2026-08-22 with the first of the two options.** `profile/patterns/__init__.py` now loads
through a `_StrictLoader` — a `SafeLoader` subclass whose mapping constructor checks the key nodes
*before* the dict exists, because a dict cannot represent the problem it is being asked to detect.
A repeat raises `CatalogError` naming the key, the line and the column: a catalog is 300+ lines, and
"duplicate key" without a location is a search rather than a diagnosis.

The second option — a coverage test that parses the file twice and compares key counts — was **not**
taken. It would catch duplicates only in the files that test knows about, while the loader is what
every caller goes through, including `parse_catalog` for a catalog that is not on disk here.

**No `ANALYZER_VERSION` bump.** The loader rejects bad input; it does not change what a valid
catalog produces, and a test pins exactly that. Falsified three ways: neutralize the key scan, swap
the loader back to `safe_load` (which fails only the *nested* test — the failure that originally bit
us was three levels deep), and drop the location from the message.

## 13. `redis.eval` is real code execution and is not read — **censused 2026-08-24, still deferred**

3 nodes in the cached profiles. `redis.eval` runs a Lua script server-side and is a genuine
`code_exec` sink; it stopped matching when `eval` became exact, because it was only ever matching by
accident, through the same suffix rule that was giving `c.eval` 199 false ones.

Not added in the same commit, because adding coverage inside a precision fix makes the census
un-readable — the node count would move for two reasons at once and neither could be attributed.
Add it with its own before/after, or as part of a deliberate pass over Redis/Lua sinks.

### Censused 2026-08-24 — the 3 nodes are confirmed, and the proposed pattern catches 3 of 5

Every dotted `.eval(` call site in the corpus checkouts, deduplicated to distinct `(repo, file,
line)` rather than counted per checkout — 34 source trees, 138,858 Python files:

| receiver | sites | repos | genuine code execution? |
|---|---|---|---|
| `c.eval` | 51 | netbox | **no** |
| `cs.eval` | 25 | netbox | **no** |
| `self.eval` | 4 | keras | **no** — a model mode switch |
| `self.redis.eval` | **3** | open-webui 2, prefect 1 | **yes** — Lua, server-side |
| `model.eval` | 2 | keras | **no** |
| `d.eval` | 2 | netbox | **no** |
| `self.redis_client.eval` | **1** | prefect | **yes** |
| `builtins.eval` | **1** | flytohub | **yes** |
| `export_model.eval` | 1 | keras | **no** |

**5 genuine sites against 85 false ones.** This is the 94% false rate that made `eval` exact in the
first place (§4g), measured directly rather than inferred — and the 3 this entry named are exactly
the `self.redis.eval` ones, so the original count was right.

**What the census changes about the proposal.** `redis.eval` under the suffix rule catches the 3 and
**zero false positives** — nothing else in 138,858 files ends in `.redis.eval`. It is a clean gain.
But it also misses **`self.redis_client.eval`**, because that suffix is `redis_client.eval`. So the
proposal is a *variable-name* match that happens to fit the idiomatic spelling, not an API match:
there is no stable dotted form, since the receiver is a variable holding a client. `r.eval`,
`client.eval` or `cache.eval` in another codebase would all be missed, and none of them can be added
without re-admitting the collisions.

**`builtins.eval` is the clean part** and is unrelated to Redis: it is a stable dotted spelling of
the builtin, currently invisible because `eval` is in `exact_calls`. One site here, and it will
never be a false positive.

**Still deferred, and now for a stated price rather than a vague one.** Any of this is a semantic
change to `patterns/python.yaml`, which means bumping `profile/cache.py:ANALYZER_VERSION` and a
**full cold profile rebuild across the corpus (~50 min)** to produce the after-census this entry
asks for. Five sinks, in three repos, none of which is currently reached by a taint path that
reports — and per the standing trap, a taint-precision change moves FP/PR by zero. The measurement
above is the part that was missing; the change itself is cheap to make and expensive to *verify*,
and verifying it is not optional.

## 14. Two plan deliverables that no status doc tracks — **found by audit 2026-08-09**

Everything else in this file was found by building. These two were found by reading the plan
against the tree, which had not been done since M0, and the gap is that **nothing anywhere said
they were missing** — not `M1_STATUS.md`, not `M2_STATUS.md`, not `CONTINUATION.md`, not this file.

- **The self-contained HTML dashboard.** Required by `plan/00-overview.md` §1,
  `plan/phase-3-security-analysis.md` §3d ("the visualizer is a deterministic render of this set,
  not a separate analysis"), `plan/phase-4-orchestration.md` §8 acceptance, and `PR_Rev_0620.md`
  §3.6. `report/` contains `markdown.py` and `sarif.py` and nothing else.
- **Any write path to GitHub at all.** `vcs/github.py` reads — `get_pr`, `get_diff`, checkouts.
  There is no code that posts an inline comment, and phase-4 §8 makes "inline PR comments only for
  introduced+validated findings" an acceptance criterion.

Both are **M5** by the plan, so neither makes an earlier milestone incomplete, and neither is
urgent. They are recorded because a deliverable that is late is a schedule item, while a deliverable
nobody has written down is a surprise — and this one survived three milestones and two benchmark
passes without being noticed.

> **Premise closed 2026-08-24 — the gap this item names is no longer open.** The finding was that
> *nothing anywhere said they were missing*. `CONTINUATION.md` §4.0 now names both explicitly, as
> **"GitHub write path (comments, SARIF upload) · M5 · ❌ not built, and cut deliberately"** and
> **"Per-PR HTML dashboard · M5 · ❌ not built, and cut deliberately (`PIVOT_PLAN.md` §3)"**. They
> are tracked, and the reason is on the record.
>
> The entry stays open rather than closed because the **deliverables** are still unbuilt — only the
> *invisibility* was fixed. Note also that §4.0's HTML-dashboard row is the **per-PR** dashboard;
> `pr_review/benchmark/report_html.py` renders the *benchmark comparison* page, which is a different
> artifact answering a different question. The literal claim above still holds: `pr_review/report/`
> contains `markdown.py` and `sarif.py` and nothing else.
>
> Worth keeping for the method rather than the outcome: this was found by reading `plan/*.md`
> against the tree, and it is the only item here that no amount of building would have surfaced.

The audit that found them is worth repeating rather than trusting: read `plan/*.md`'s component
tables against `find pr_review -name '*.py'`, milestone by milestone. It took about ten minutes and
also turned up the two `M2_STATUS.md` blind spots now numbered 8 and 9 there.

**Still-open M0 items live in `M1_STATUS.md` §5.3, not here**, and are easy to miss because M0 reads
as long finished: `extract/tickets.py` and `extract/blame.py` are phase-0 §4 and §7 deliverables and
were never built. Those are the only things on this list that make an already-declared milestone
incomplete.

## 15. `extract/tickets.py` and `extract/blame.py` — **decided 2026-08-09: deferred, not late**

The only two things that make an already-declared milestone incomplete. Both are **M0** —
`plan/phase-0-extraction.md` §4 (ticket extraction) and §7 (the blame map) — and neither was ever
built, while `CONTINUATION.md` reads **M0 ✅**. That is now said out loud here instead of sitting in
an `M1_STATUS.md` §5.3 bullet that reads as backlog.

**Deferred rather than built, because neither has a consumer.** The revisit trigger is mechanical,
not a reminder — each has exactly one dead hook, and the day something reads it, the module is
worth writing:

- `DeltaManifest.tickets` (`extract/schema.py`) is populated by nothing and read by nothing.
  Its consumer is **M3**, which will want ticket text as prompt context; it is already
  untrusted-tagged and `safety/wrap.py` exists to wrap it.
- `Finding.provenance.contributor_id` (`schema.py:106`) is **never assigned anywhere**. Its
  consumer is **M5** feedback and registries.

Building them now would contradict this file twice: §2's "a parser nothing exercises is a parser
nobody knows is wrong", and §12's principle that a declared-but-unread key is worse than none.

**What it costs, stated plainly:** phase-0's acceptance is not met as written, and M0's own
acceptance line — "run on a real GitHub PR" — was only ever met by proxy. The benchmark did the
real-GitHub half 102 times over (real repos, real shas, two checkouts per case); the tool has still
never *posted* anything to a PR, which is item 14.

Two things an audit **cleared**, recorded so they are not re-raised: `extract/guard.py` is not
missing — the large-diff guard is implemented at `extract/manifest.py:85`. And `vcs/base.py`
already declares `get_linked_issues`, `post_comments` and `upload_sarif`, marked "M1+ surface (not
needed by the M0 skeleton)" and raising `NotImplementedError`; the write path is deferred in code,
honestly, rather than silently absent.

## 16. `classify.is_iac` misses the layout Helm charts actually use — **real, unexercised**

`is_iac` matches yaml only on a literal `/k8s/` or `/helm/` path segment. Real chart repositories
lay out as `charts/<name>/templates/*.yaml`, which contains neither, so **none of it classifies as
IaC** and `iac.py` never sees it. `plan/phase-0-extraction.md` §3 says "`*.yaml` under k8s/helm",
which those files are.

Found while choosing the IaC corpus (§4h), and it is why that corpus is Terraform and Dockerfile
only: including a chart repo would have measured this classifier rather than the adapter, which is
a different experiment and wants doing on purpose.

Not fixed blind. `is_generated`'s docstring states the trade this sits on — a false *positive* in
these classifiers is silent lost coverage — and matching `charts/*/templates/` on path alone would
also catch every non-k8s directory called `templates`. The honest fix reads the file for
`apiVersion:`/`kind:`, which needs content plumbed into a function that currently takes a path
(see item 17). Revisit with a chart repo in a corpus, so the fix has something to be wrong about.

## 17. `classify.is_generated` cannot see header markers — **reader built 2026-08-24; the gating half is open**

`plan/phase-0-extraction.md` §3 specifies `is_generated` as "**header markers**, `*_pb2.py`,
`migrations/`, vendored dirs". Only the path-based half exists: the function's signature is
`is_generated(path: str)`, so it structurally cannot read a header.

The IaC corpus made this concrete. 12 of its reported findings are checkov checks on
`docker-library` Dockerfiles whose first lines read *"NOTE: THIS DOCKERFILE IS GENERATED VIA
apply-templates.sh / PLEASE DO NOT EDIT IT"* — machine-written files, reported as though someone
had chosen their contents.

Deliberately not fixed in the same pass as the two one-line defects §4h did fix. This one changes an
**interface**: every caller of `classify.is_generated` passes a path and content is not plumbed to
it, so it is a real refactor rather than a regex. And it points the dangerous way — `is_generated`
suppresses `secrets.py`, `sast_semgrep.py` and `change/filter.py`, so a false positive here is
silent lost coverage on three detectors at once. Wants its own measurement.

### Half done 2026-08-24: the reader is built and measured; the 12 findings did not move

**Built.** `is_generated(path, head=None)` — path rules unchanged and authoritative, content
strictly additive. Content comes from the checkout when there is one and from the diff's first hunk
(padded so line numbers stay true) when there is not, because `--no-checkout` is **arm 2c**, a
measured configuration rather than a degraded one; requiring a checkout would have quietly changed
what that arm measures.

**Measured before it shipped, because of the warning above.** Over 305,861 files in the corpus
trees, counting only *new* suppressions: the single-marker shape this entry sketched would suppress
**11,073 files (3.6%)** — including `apply-templates.sh` and `generate-stackbrew-library.sh`, the
hand-written scripts that DO the generating. Requiring **two** signals ("generated" AND "do not
edit", in the first 10 comment lines) suppresses **803 (0.26%)**, 640 of them Dockerfiles. Full
tables in `BENCHMARK_STATUS.md` §4n.

**And the findings did not move: 32 before, 32 after, identical case for case.** The prediction was
that all 32 would disappear, pre-registered before the run. It was wrong for a structural reason:
the reader works — 6 of 6 Dockerfiles flagged on `python#1123` with a checkout — but **nothing
consumes the flag for these findings**. `is_generated` gates `secrets.py:118`,
`sast_semgrep.py:57` and `filter.py:147`; **`detect/iac.py` is not among them and never asks**, and
all 32 are checkov checks. This entry's own evidence implied a fix that was only ever half of one.
Errata §14.40's shape again: the stage that decides is not the stage that gates.

**DECIDED 2026-08-24: `iac.py` will NOT be made to respect the flag.** The recommendation below was
put to the project owner and accepted, so this is a closed decision rather than an open one — if it
is ever reopened, reopen it with an argument against the reasoning here, not by noticing the
one-line fix again.

Making `iac.py` respect the flag is one line and takes the IaC corpus **from 32 findings to 0** — every
finding it has is a checkov check on a generated Dockerfile. That corpus exists to prove `iac.py`
runs on real input (§4h); with no findings it proves nothing, and §18 is already the entry about an
obvious fix that deletes findings. "Container runs as root" on a generated Dockerfile is a **true**
finding with the **wrong address**: the fix belongs in `apply-templates.sh`, not in its output. What
it needs is to be *annotated* with the generator so the reader is sent to the template — a different
and larger change than suppression, and one that should not be made by reflex.

So what remains open under §17 is **annotation**, not suppression: attaching the generating script
to a finding on a generated file. That has no owner and no trigger yet, and it is the honest name
for the remaining work. The header reader that landed today is what such an annotation would be
built on, so it is not wasted by this decision — it is the half of it that was worth doing.

## ✅ 18. `CKV_DOCKER_3` is filed under the wrong family, and the obvious fix deletes findings — **CLOSED 2026-08-22**

Two defects that cannot be separated, found by the IaC corpus (`BENCHMARK_STATUS.md` §4h).

**The label is wrong.** `detect/normalize.py` maps checkov's `CKV_DOCKER_3` to
`CFG-DEFAULT-CREDS`, while the finding's own title reads *"Container runs as root"*. Running as
root is a privilege misconfiguration, not a default credential. The corpus produced **16** of them,
every one carrying a family that would route it to the wrong M3 agent.

**And correcting it in place makes things worse.** Retargeting to `CFG-IAC` was tried and reverted:
the fingerprint is `(path, internal, symbol, snippet)` — `rule_id` is only a fallback for findings
with no snippet — and `CKV_DOCKER_2` (no HEALTHCHECK) reports on the **same Dockerfile at the same
line**. Unifying the taxonomy id collapsed the pair in dedup and **silently deleted 16 findings**;
the run showed 36 → 16 reported where 32 was correct. A visible wrong label beats an invisible lost
finding, so the wrong label stays, stated at the mapping and pinned by
`test_two_rules_on_one_line_collapse_if_they_share_a_taxonomy_id`.

Three ways out, none of them a one-liner, which is why this is an item and not a fix:

- **Add `rule_id` to the fingerprint.** Looks obvious and is not: the fingerprint is the
  *cross-source* join key (cross-cutting §6), so this would also stop a semgrep finding and a
  structural finding for one defect from deduping — the behaviour M2's acceptance test asserts.
- **Give the taxonomy a container-privilege id.** Probably right, and the reason it was not done
  here: it touches `taxonomy/registry.py`, and any new id has to be checked against
  `scoring._CWE_GROUPS` and `pr_review/benchmark/scope.py`, which read the same table and must not be widened
  casually.
- **Leave it.** Defensible until M3 actually routes on family.

**Closed 2026-08-22 with the second route, once its blocker became checkable.** The objection was
*"any new id has to be checked against `scoring._CWE_GROUPS` and `benchmark/scope.py`, which read the
same table and must not be widened casually"* — an argument, with no way to settle it. §14.42's work
turned it into a measurement: the labelled corpus has 36 ground-truth rows over 17 CWEs, 9 of them
in scope, and that is a number a test can hold.

`CFG-CONTAINER-PRIVILEGE` carries **CWE-250/269**, chosen because neither appears in the corpus's
17, neither is in any `_CWE_GROUPS` group, and neither was in `in_scope_cwes()`. They now enter that
set — correctly, a detector can emit them — while the corpus's in-scope row count stays **9/36**.
`test_the_new_id_does_not_move_the_benchmark_recall_ceiling` asserts it, and the falsification pass
confirms the guard bites: adding `CWE-668` (which *is* in the corpus) to the same id turns it red.

**That distinction is the whole point.** Widening the vocabulary because a detector grew is correct;
widening it to improve a number is the cheating move §19 names. The difference is not intent, it is
whether the corpus's reachable count moves — and that is now testable rather than promised.

The first route (`rule_id` in the fingerprint) stays rejected: it is the *cross-source* join key, so
it would also stop a semgrep finding and a structural finding for one defect from deduping, which is
what the fingerprint exists to do. A **new** id cannot collide with `CFG-IAC` by construction, so
the 36 → 16 collapse cannot recur; `test_two_rules_on_one_line_collapse_if_they_share_a_taxonomy_id`
still pins the mechanism that made the first attempt fail.

---

## Standing traps — not items, but do not walk into them

- **Bump `profile/cache.py:ANALYZER_VERSION`** when changing `promote.py`, `cpg.py` or
  `patterns/*.yaml`. Currently **8**. Without it a re-run loads profiles built by the old code and
  reports that your fix did nothing (§14.25).
- **A published number names a population, not a cause.** Before fixing the thing a metric is
  *attributed* to, read the findings and confirm the mechanism is the one you think it is. Item 3
  above is the third time that check changed the answer, and the first time it would have sent a
  whole session at the wrong file.
- **The scorecard cannot see the taint engine.** 2,938 taint paths become 457 findings become 76
  reported become **1 scored**, because the labelled corpus's reverse-fix construction marks
  almost everything `pre_existing`. Do not price a taint-precision change by what it does to
  FP/PR — the answer is always zero. Price it against the reported set, and say which you measured.
- **A key that is read is not a key that is right.** The catalog coverage test proves readership
  and nothing else; a pattern matching the wrong receivers passes it every time. Item 10.
- **Do not** silently widen a pattern inside a precision fix (item 13), and do not assume a
  single-segment pattern is wrong because it is single-segment — `urlparse`, `bindparam` and
  `from_string` are all correct in their dotted forms. Which patterns need narrowing is a
  measurement, and `rg` over source is not that measurement: it read `text` as a disaster when the
  cached CPGs said 1,557 of its 1,632 nodes were right (§4g).
- **Falsify every guard before trusting it** (§14.29) — and when scripting that loop, `rm -rf` the
  `__pycache__` and let a second pass between writes. A mutated source written inside the same
  second as the cached `.pyc` can be imported **stale**, which reports a live test as INERT. That
  happened this session and cost a wrong conclusion until it was checked by hand.
- **Do not** widen `scoring._CWE_GROUPS` to improve a number: `pr_review/benchmark/scope.py` reads the same
  table, so widening moves recall in both directions at once.
- **Do not** tune the new gate-relevant 0.02 back to 0.00. It is a correct HIGH finding on a real
  under-upgrade (gitpython 3.1.57, fixed in 3.1.58) that the negative corpus scores as a false
  positive by construction — blind spot 2, arriving for real.
- **Token and cost telemetry through CAP/Strands is UNMEASURED, not low.** The zeros come from
  guessed Strands usage keys that fail silently to zero. **Scoped 2026-08-24:** this trap used to end
  "no model runs anywhere in this harness yet", which stopped being true on 2026-08-21.
  `models/claude_cli.py` runs real calls, and cost through *that* path is measured — arm 2b put
  tier-3 triage live over 50 negative-corpus PRs at **$0.9537 total, $0.019/PR** (`REPORT.md` §4).
  The Strands half of the caveat still stands, and so does the rule behind it: **a zero in a token
  report means we did not look.** But do not quote this bullet as evidence that nothing has been
  measured — see §21 for what the measured numbers still rest on.
- **A cost figure without its cache state is not a measurement.** Added 2026-08-24 from §4l.2: arm
  3b's two replication passes cost **$1.7963** cold and **$0.4665** warm for the *same prompt over
  the same 52 cases* — 3.85×. So per-pass costs are not comparable across passes, and a total summed
  over passes taken at different cache states is an accounting rather than an estimate. `REPORT.md`
  §4's total is exactly that, and now says so. **It also read $7.72 until 2026-08-24, when it should
  have read $9.58** — $5.46 was correct on 08-21, $1.86 of 08-22 spend was never folded in, and the
  08-24 update added $2.26 to the stale base (§14.53). **A running total goes stale every time the
  set it sums grows, and unlike other figures it cannot be corrected by editing it — only by
  recomputing.** It is now derived from the stored runs. The per-PR figures above are the least exposed
  kind, being within-run averages that amortise one cold start.
- **`cap_engine/` is a separate repo under a restricted licence.** Never edit it, never commit it.
  Workarounds go in `pr_review/cap_compat.py`.

## 19. The labelled corpus's recall ceiling is 0.250, not 1.0 — **found 2026-08-21, corrected 2026-08-22**

27 of 36 ground-truth rows name weaknesses no detector can express: the pipeline's emittable CWE set
is the union of `taxonomy/registry.py`'s lists widened by `scoring._CWE_GROUPS`, and
`CWE-400/88/200/1333/444/834/74/20/59/668/61/455` are outside it. Errata **§14.42**.

> **This section said 0.364 (21 of 33) until 2026-08-22.** That counted `BenchCase.cwe` advisory
> tags; `recall` divides by `ground_truth` rows. Errata **§14.45** — the correction, and why the
> entry naming this error class committed it. The ceiling is *lower* than was published, so nothing
> below softens; it hardens.

**Not fixed, and deliberately.** The available moves are all wrong or expensive:

- **Widening `_CWE_GROUPS`** is the cheating move. `benchmark/scope.py` reads the same table, so it
  moves recall in both directions at once — the reason that warning already existed.
- **Adding taxonomy ids** without detectors behind them makes the ceiling rise while nothing detects
  more; the number would improve and the tool would not.
- **Building detectors** for resource exhaustion, request smuggling and information exposure is real
  work and belongs with M3's families, not with a benchmark fix.

**What to do instead, and it is cheap:** report the reachable stratum next to the headline, always.
`benchmark/llm_arm.reachable_ground_truth()` is the predicate. A recall figure from this corpus that
does not name its ceiling is misleading, and it has been quoted in four documents without one.

## ✅ 20. `test_the_second_run_is_warm` is a wall-clock assertion, and it flaked — **CLOSED 2026-08-24**

`tests/test_pipeline_phase2.py:96` asserts `warm["phases"]["profile"] < cold["phases"]["profile"]`.
It failed once during a full-suite run while three benchmark jobs were saturating the machine, and
passed in isolation and on an immediate re-run. 721/721 either side of it.

**The assertion is measuring the right thing the wrong way.** What incremental profiling promises is
that the warm path does *less work*, and the run already records that categorically —
`profile_action` is `cold` vs `warm`, asserted on line 95 — so the timing line adds nothing except a
dependency on machine load. Under contention a cold build that gets a full core can beat a warm one
that does not, and the test then reports a false regression on the project's headline efficiency
claim, which is the worst thing for a flake to be about.

**Not fixed here** because it is orthogonal to the comparison work and the fix wants a moment's
thought about what should replace it — a cache-hit assertion, or a work-proxy such as files parsed,
rather than seconds. Recorded so the next person who sees it red knows it is a known flake and does
not go looking for a performance regression that is not there.

The 50x/144x incremental-profiling measurements in `M1_STATUS.md` §5.1 are unaffected: those were
taken deliberately on a quiet machine and are not what this test checks.

**Closed 2026-08-24 — and the replacement is stronger than what it replaced, which was not the
expected outcome.** The timing line is now:

```python
assert _files_parsed(cold) >= 1
assert _files_parsed(warm) < _files_parsed(cold)
```

`_files_parsed` collapses the three shapes the profile phase can report into one comparable number:
a full build records `files_parsed`, an incremental splice records `files_reparsed`, and a straight
cache hit records no profile telemetry at all, meaning it parsed nothing. Parsed files are what the
stopwatch was a proxy *for* — the warm run is faster **because** it re-parses nothing — so the test
now asserts the cause rather than the symptom.

**What the falsification found.** Neutralizing the cache reuse (`entry = None` on the warm branch,
so every "warm" run silently rebuilds) turns the new assertion red at `4 < 4`. The **old** assertion
would have passed: the rebuilt warm run still clocked **0.0345s against the cold run's 0.0853s**,
because by then the OS file cache was warm even though the profile cache was doing nothing. So the
wall-clock line was not merely flaky — **it would have accepted a completely broken profile cache**,
which is the exact regression it existed to catch. A flake was the visible symptom of a test that
was measuring the wrong thing; the invisible half was worse.

---

## 21. The transport floor is a calibration constant, and it will go stale — **2026-08-22**

`models/claude_cli.py:TRANSPORT_FLOOR_TOKENS = 7_300` is the only thing separating our tokens from
the CLI's in every cost figure this project reports. It is a **single measurement against `claude`
2.1.235** with `--system-prompt` + `--exclude-dynamic-system-prompt-sections` (7,263 cached cold,
7,445 read warm), and the CLI does not report the split itself — §14.44 is the entry on why the
split cannot be derived from `usage` alone.

**The failure mode is silent and directional.** If a CLI upgrade grows the system prompt, the stale
floor under-counts the harness and re-attributes the difference to *our* content, making the
pipeline and the LLM arm both look more expensive in content terms than they are. Nothing in the
suite would notice: the constant has no test that could fail, because there is no second source to
disagree with it.

**Not fixed here.** The cheap fix is a one-call calibration at the start of a run — send an empty
prompt, read `cache_creation + cache_read`, use that instead of the constant — which costs ~$0.01
and makes the number a property of the run rather than of this file. It was not done because it
adds a network call to every benchmark invocation including the offline ones, and that trade wants
a decision rather than a default. Until then the scorecard marks the split **"Derived, not measured
here"** and names the constant, which is the honest interim.

### Trigger made mechanical 2026-08-24 — and it fired immediately

The reminder above ("re-measure when the CLI version changes") was the thing this file's own §15
standard says a trigger must not be. It is now a mechanism, and the mechanism found the failure on
its **first execution**: the machine was already running `claude` **2.1.241**, whose floor measures
**7,777** against the constant's 7,300. Nobody had noticed, in the way nothing without a second
source is ever noticed. Measurement record: `BENCHMARK_STATUS.md` §4l.3.

**What changed.** `ClaudeCliProvider.accounting()` records the live `claude --version` — probed once
per provider and only if a call was actually made, so offline runs never shell out — and
`report.floor_provenance()` compares it against the calibrated build. Four states, deliberately
distinct: matching (silent), mismatched against a build that **has** been measured (quantifies the
gap: *"understates harness by ~477 tokens per call — ~24,804 across this run"*), mismatched against
one that has not (says the split is an extrapolation), and **unrecorded** — every run stored before
2026-08-24, where silence must not read as agreement.

**What did NOT change, deliberately: the constant.** `TRANSPORT_FLOOR_TOKENS` still reads 7,300.
Moving it re-derives the harness/ours split of every stored run, including those the older CLI
produced, for which 7,300 is correct — and that split is published (`REPORT.md` §4). It is a
published number with a landing cost, not a knob. `claude_cli._FLOOR_BY_VERSION` holds every
measurement taken so the choice stays open and informed.

**DECIDED 2026-08-24: the constant stays at 7,300.** Not as a deferral — as the correct answer, once
the runs were attributed. `BENCHMARK_STATUS.md` §4l.4 recovers which CLI produced every stored run
from the install times in `~/.local/share/claude/versions/` and each run's `started_at`. **Every
published floor-derived figure — `REPORT.md` §4's ~380k/~250k and the scorecard's 249,665 — comes
from arm 3, which ran on 2.1.235, the build 7,300 was calibrated against.** Moving the constant to
7,777 would make correct published numbers wrong by ~10% in order to fix arm 3b p2/p3, whose splits
are published nowhere. The newer measurement is not more accurate; it is accurate about a *different
build*, which is precisely why the number is keyed by version rather than replaced.

**Version-aware at read time — done 2026-08-24.** `claude_cli.floor_for(accounting)` returns the
floor measured for the run's own CLI, falling back to `TRANSPORT_FLOOR_TOKENS` when the version is
unknown or was never calibrated; `report.py` and `report_html.Arm.our_tokens` both price through it.

**It moved nothing, and that was checked rather than asserted.** No `run.json` written before
2026-08-24 carries `cli_version`, so every stored run takes the fallback and prices exactly as
before. The acceptance test was a byte-for-byte comparison of the regenerated scorecard — which
**failed the first time**, catching a blank line an empty list element had injected into the table
header. No number had moved; the published markup would have, silently. Second run: identical.

Three consequences worth carrying:

- **The provenance message had to be rewritten in the same change.** It said *"understates harness by
  ~477 tokens per call"*, which was true only while the arithmetic ignored the version. With
  `floor_for` selecting the measured floor there is no gap to report, and leaving that sentence would
  have been this project's commonest defect exactly (Plan 2 §L5). Four states now: calibrated build
  (silent), **measured** build (names the floor used), **recorded but never calibrated** (says the
  split is an extrapolation), **unrecorded** (unchanged).
- **A build nobody measured falls back rather than interpolating.** 2.1.239 and 2.1.240 get the
  constant and a warning. An interpolated floor would be a number with no measurement behind it and
  no way to tell it from one that has.
- **Arms on one page can now be priced by different floors**, so the scorecard grows a `Floor`
  column and a "not directly comparable across arms" note — **only when the floors actually
  differ.** With one floor it would be a constant repeated per row, and adding it would have changed
  a published page for no information.

**Still open:** the per-run auto-calibration this entry sketches above, which would make the floor a
property of the run rather than of this file and render all of the above redundant. The auto-calibration is strictly
better and would make the version check redundant; the version check was built because it costs no
network call on offline runs. Expected effect of either, stated so it cannot be quietly restated
later: arm 3's harness figure rises ~477/call and its content figure falls by the same. Cost,
recall and precision do not move.

**Re-measure it when the `claude` CLI version changes**, and record the new number with its version.

---

## ✅ 22. Arm 3b is n=1 against the baseline prompt's n=3 — **CLOSED 2026-08-24**

`2026-08-22-arm3b-introduced-only` reported **0 false alarms on 26 control PRs**, and that number
now appears in the scorecard, the comparison page, `REPORT.md` and errata §14.47 as the thing that
falsified §14.46's "cannot".

**It is one pass.** The baseline prompt was run three times precisely because arm 3 varies run to
run — its control-half counts came out 3, 4 and 5, and its reachable-stratum recall 0.556, 0.667 and
0.556. A single draw from an arm known to be non-deterministic is the weakest evidence this project
accepts anywhere else, and it is currently carrying a correction to a headline claim.

The reasoning for believing it anyway, stated so it can be disagreed with: 0 is outside the
baseline's observed 3–5 spread, the vulnerable half stayed inside its range (40 against 41–51) so
the drop is selective rather than uniform, and under uniform thinning at the observed rate the
expected control count would be 2–3 rather than 0.

**Not fixed because it costs money, not thought.** Two more passes at `--effort low` are ~$0.75 each
and ~5 minutes; the commands are in `BENCHMARK_STATUS.md` §4j. Until they run, every quotation of
0/26 should carry "one pass" beside it, and the reachable-recall drop (0.333 against 0.556–0.667) is
the figure most likely to move, because it has the smallest denominator on the page.

**Closed 2026-08-24. Both passes ran, and the prediction in the last sentence above was right.**

| pass | vuln-half | control | recall | reachable |
|---|---|---|---|---|
| p1 (08-22) | 40 | **0** | 0.444 | 0.333 (3/9) |
| p2 (08-24) | 40 | **0** | 0.444 | 0.667 (6/9) |
| p3 (08-24) | 46 | **1** | 0.556 | 0.556 (5/9) |

> Recall figures corrected 2026-08-26 — the scorer changed, the runs did not (errata §14.59). They
> read 0.306 · 0.333 · 0.444 before. The control column, which is what this item turned on, is
> untouched.

- **The suppression replicated.** Control-half output is 3–5 under the baseline prompt against 0–1
  under introduced-only — non-overlapping at n=3 each. This was the finding and it holds.
- **"Below the pipeline's 1" became "at or below".** p3 produced one.
- **"It was not free" did not hold at all.** Headline recall spans 0.444–0.556 against the baseline's
  0.472–0.500, so arm 3b's best pass beats every baseline pass; reachable spans 0.333–0.667 against
  0.556–0.667, overlapping with the same maximum. The halving was one draw read as a point.

Cost **$2.26**, not the ~$1.50 estimated here — p2 ran cold at $1.7963, p3 warm at $0.4665. Errata
**§14.51**; measurement record `BENCHMARK_STATUS.md` §4l.2.

---

## ✅ 23. Stored false-positive rates may be inflated by stale baselines — **CLOSED 2026-08-24: they were not**

§14.49 fixed `BaselineCache`, which had no version key: a baseline built before a change to detector
output kept fingerprints nothing could match, so pre-existing findings were reported as
**introduced**. Measured magnitude on the IaC corpus at the moment it was found: **32 reported
became 112**, a 3.5× inflation from the cache alone.

**The question this leaves open is retroactive.** Every stored run in `benchmark/results/` that
executed against a warm baseline cache *after* a change to a mapping table, a rule mapping or a
snippet-producing detector carries some amount of the same inflation. The pass-1 → pass-2 → receiver
work between 2026-08-07 and 2026-08-09 changed detector output repeatedly, and those runs share a
cache root.

**The direction is safe and that is why this is an item rather than an emergency.** Staleness only
ever moves findings from *pre-existing* to *introduced*, so it inflates false-positive counts. No
stored number was flattered by it; several may be worse than the tool deserves. The headline
improvements (1.96 → 0.22 → 0.24 FP/PR) were *reductions*, so they cannot be artifacts of inflation
in the direction that would explain them away.

**What it would cost to settle:** delete `.pr_review/cache/*/baseline/` and re-run the negative and
labelled corpora — about 20 and 50 minutes, no model spend. The comparison against the stored runs
is then a direct measurement of how much each was inflated. Worth doing before any of these numbers
is quoted outside this repository; not worth blocking on inside it, because the direction is known.

Note the `--cold-profiles` flag isolates the *profile* cache per case and does **not** touch the
baseline cache, so the labelled corpus's paired runs are not protected by it either.

**Closed 2026-08-24 — measured, and the exposure on these two corpora is nil.** All 17
`.pr_review/cache/*/baseline/` directories were archived and deleted; both corpora re-ran from cold
baselines (`--label negative-freshbaseline` / `labelled-freshbaseline`, distinct per §4). Ten
baseline directories rebuilt afterwards, every mtime checked against the deletion time — because a
re-run that quietly found the cache it was supposed to have lost would report "no change" for the
wrong reason.

Both corpora came back **identical on finding identity** — `(case, path, line, taxonomy id, rule
id)`, not merely on counts, since two runs can agree on a total and disagree about its contents.
12/12 negative and 37/37 labelled. Every rate unchanged: negative 0.24 FP/PR (12/50) and 0.02
gate-relevant; labelled recall 0.028 (1/36), reachable 0.111 (1/9), pairs 0.04 (1/26).

**Do not read this as retiring the trap.** §14.49 measured the mechanism at 32 → 112 on the IaC
corpus and that measurement stands. It did not reach these two because the IaC inflation came from a
**taxonomy-id remap**, and the id is part of the fingerprint; the negative and labelled baselines
were built against detector output whose fingerprints have not moved since. The next remap will do
it again — which is why `BASELINE_VERSION` and `normalize.mapping_digest()` are the fix and this
measurement is not.

What the item did buy: the direction argument — staleness only ever moves a finding from
pre-existing to introduced, so no stored number was ever flattered — is now **measured rather than
reasoned**. `BENCHMARK_STATUS.md` §4l.1, errata §14.49's answer banner.

---

## ✅ 24. A source doc can change and its published page not be regenerated — **CLOSED 2026-08-24, same day**

Two committed generators render a source in this repo into a page published outside it:
`benchmark/results/comparison.sh` → the scorecard, and `render_report.py` → the report page, from
`REPORT.md`. **Nothing connects a change in a source to a re-run of its generator.** Edit
`REPORT.md`, commit, and the published page is quietly a previous version of the argument. All 799
tests stay green, because no test knows the page exists.

**It has already happened twice here, in both directions.** The 2026-08-22 renderer was written to a
session scratchpad, lost when that session ended, and rebuilt on 2026-08-24 — which is why it is now
committed (`c879d8e`). And the ceiling correction of 2026-08-22 reached seven documents and **none
of the source**, because the sweep searched `*.md`: three docstrings still said 0.364 two days
later, including `report_html.py`'s, the module errata §14.45 credits with catching that very error
(§14.50).

**Cost of leaving.** No benchmark number moves. What moves is **what a reader is shown**, and the
published page is the most-read and least-checked artifact this project produces. The artifact URLs
live in assistant memory rather than in any file — deliberately, because a URL in a source file goes
stale silently — so there is not even an mtime a reader could compare.

**Why it is deferred anyway.** The failure is loud the moment anyone opens the page beside the doc,
and the blast radius is one stale page rather than a wrong number. That makes it cheaper to catch
than to prevent, for now.

**Revisit trigger, and it is close.** The next time the report is **sent** to someone rather than
shown to them. A page you are demoing gets regenerated because you are looking at it; a page someone
opens next week does not.

**The fix, ~30 min.** Record each generator's source hash beside its output — a
`benchmark/results/.rendered.json` of `{source path: sha256 at last render}`, written by both
generators — and have the generators report on startup when a source's current hash differs from its
recorded one. A **report, not a test failure**: rendering is a deliberate act, and a red suite on an
unpublished edit trains people to ignore it. Do not try to check the live page over the network —
the artifact is private by default and the CSP forbids it; the point is to catch drift locally,
before publishing.

**Where the real fix lives, if anyone wants it.** Claims worth pinning should live in one place and
be *cited* elsewhere rather than restated. The docstring case is the proof: the number was right in
the docs and wrong in the code because the code kept its own copy.

**First item on this list found by reviewing a plan rather than by measurement** — worth recording,
because every other entry here came from a corpus run or an audit of the tree.

**Closed 2026-08-24.** `pr_review/benchmark/rendered.py` keeps
`benchmark/results/.rendered.json`, a `{page: {source: sha256}}` ledger written by both generators
after they render. Each reports drift **before** rendering, since the drift being described is what
the published page looked like a moment ago. The report names the page, the source and what to do;
it never fails a build, for the reason given above.

The report page is keyed by its **artifact URL** rather than by an output path, because the local
path is a scratch file that varies per invocation while the published page is the thing that goes
stale. Its sources are `REPORT.md` **and `render_report.py`** — a change to either alters what a
reader sees. The scorecard's sources are every arm's `run.json` plus `comparison.sh` itself, which
hardcodes the arm descriptions.

**It shipped with the bug it exists to prevent, which is the part worth keeping.** The first version
was handed `Arm.source` — a *display name*, not a path — so every digest came back `None`. `None`
then compared equal to `None` on every later check, and the ledger reported "no drift" forever while
watching nothing. It was caught within minutes only because the ledger was inspected rather than
trusted. `record()` now raises on an unreadable source, and `test_recording_an_unreadable_source_raises_rather_than_storing_none`
pins it: **a mechanism that cannot fail loudly is worse than no mechanism, because it is believed.**
Six tests, three guards falsified.

**A known limit, stated rather than papered over.** The two pages are keyed differently. The report
page is keyed by its **artifact URL**, because its local output path is a scratch file. The scorecard
is keyed by its **committed local path** (`benchmark/results/comparison.html`), because
`benchmark compare` is a general command that takes `--out` and does not know where any particular
page is published. So for the scorecard the ledger catches *source → page* drift but not *page →
artifact* drift: a regenerated and committed `comparison.html` that nobody republished still reads
as clean. Git catches the first half of that chain, which is why this is a limit and not a hole —
but it is not the same guarantee the report page gets. Closing it means giving `comparison.sh` the
artifact URL, which puts a second URL in source; that trade was not taken here, and
`render_report.py` already carries one, so it is a small step if anyone wants it.

**Corrected 2026-08-24, later the same day — it shipped with a second, larger blind spot, and that
one cost something.** The scorecard's sources were "every arm's `run.json` plus `comparison.sh`". The
renderer itself, `report_html.py`, was **not** on the list — and roughly half the page's prose is
literal strings in that module: the callouts, the limits list, the ceiling note. `render_report.py`
recorded `__file__` from its first version. This generator never did, and no test compared them.

The cost was immediate and is written up as errata **§14.52**: §14.51 retired the claim that arm 3b
scored "below this pipeline's 1", every document was corrected, `report_html.py` was not, and the
published scorecard spent a day asserting the retired wording in a callout three rows under its own
table printing `0.04 (1/26)`. **`check()` was run that morning and returned "none".**

> **A ledger of inputs is a claim about what can change the output**, and it is falsifiable exactly
> the way a guard is: name a file that changes the page and ask whether the ledger holds it. That
> question was never put to this one — it was verified by watching it pass, which is the failure mode
> §14.29 exists to prevent for guards and had not been extended to the thing doing the watching.

The list now lives in `comparison_sources()` rather than inline at the `record()` call, and is
asserted directly by `test_the_scorecard_declares_the_renderer_that_writes_its_prose`: what was wrong
was the *declaration*, not the rendering, so the declaration is what a test should be able to see.
A second test checks every declared source is readable, so a rename cannot quietly reintroduce the
`None`-compares-equal-to-`None` bug through the front door.

**What remains open, and it is the interesting part.** The page's *numbers* are re-derived at render
time from `scoring` and `metrics`. A change there moves the page with **no tracked source moving**,
and no reasonable source list fixes that: the transitive import graph is most of the package, and a
ledger that names everything reports drift on every commit, which is indistinguishable from
reporting none. The real answer is the rule this project already wrote down in errata §14.42 and
proved in §14.45 — *a figure a reader will compare against another should be computed at render time
from the object that produces the other one* — which is why the ceiling is derived on the scorecard
and why that derivation caught §14.42. **Prose is the part that cannot be derived**, and prose is now
tracked. Numbers are covered by being computed rather than quoted, wherever that has actually been
done; where a number is still quoted in a string, this ledger is the only thing watching it.

**Narrowed 2026-08-25, on the report page's half of the problem.** The ledger is a detector: it says
a page is behind its sources, and it can only ever say that. The stronger move is to leave the
generator nothing worth tracking. `render_report.py` carried three strings a reader sees — the tab
title, the eyebrow and the `<h1>` — and the `<h1>` was a *copy* of `REPORT.md`'s own first line, so
the page was free to disagree with the document it was rendered from and the ledger would have
reported clean, because neither file had moved. All three now come from `REPORT.md`: the first two
from a `---` front-matter block, the third from the heading itself.

`tests/test_render_report.py` pins the direction of that dependency, and its last test is the one
that matters: it reads today's title, eyebrow and heading out of `REPORT.md` and asserts none of
them appears as a literal in the generator. That is a guard against the *class*, not against the
three strings that happened to be there.

**`report_html.py` is the half still open**, and it is the larger half — the callouts, the limits
list and the ceiling note are prose with no document behind them to derive from. The scorecard has
no `REPORT.md`. Closing it the same way means giving the scorecard a source document, which is a
real change and not a tidy-up; until then the ledger is what watches that module, which is why
§14.52's fix was to declare it rather than to remove it.

---

## 25. Which six neighbours a bundle keeps is decided by source order, and nobody has measured whether that is the right six — **2026-08-25**

`change/context.py:_neighbors` collects the 1-hop callers and callees of a hunk's enclosing symbols
and returns `out[:MAX_NEIGHBORS]`, with `MAX_NEIGHBORS = 6`. Until 2026-08-25 the six that survived
were whichever six the graph's edge iteration happened to yield first, and that order was not stable
across processes (§14.57). It is now `(file, line, name)` — **source order, chosen because it is
stable and reads naturally in a prompt, not because it selects well.**

**The cap binds, and how often is measured rather than guessed.** Instrumenting `_neighbors` to count
before the slice, over the labelled corpus's 175 bundles: **10 were truncated (5.7%) and 32
neighbours were discarded**; another 8 sat at exactly six with nothing lost. The tail is long for its
size — one bundle each at 10, 11, 12 and 13 neighbours, so the worst case throws away more than it
keeps. Where the cap binds, this rule is choosing what a model gets to see.

**Three orderings are defensible and they disagree:**

| rule | argument |
|---|---|
| source order *(current)* | stable, cheap, and a prompt laid out in file order is one a human could check |
| callers before callees | the reachability question is usually *"can untrusted input get here"*, and that is answered upstream |
| by CPG distance or taint participation | the graph already knows which neighbours sit on a source→sink path; `reachability_hints` is built from exactly that |

The third is the one worth measuring, because the pipeline already computes it: `_taint_paths_through`
runs for every bundle, so preferring neighbours that appear on a taint path costs nothing new.

**Why this is an open item and not a fix.** Changing which neighbours survive changes what the
context arm receives, and the arm has not run yet. Doing it now would mean the arm's first result is
measured against a selection rule that was itself never measured — the shape §14.34 warns about.
**Run the arm on source order, then ablate the selection rule against it.** That way the ablation
has a baseline, which is the only thing that makes it readable.

**Do not raise `MAX_NEIGHBORS` instead.** The bundle is where Phase 1's token economy is spent or
thrown away (`change/context.py`'s module docstring), and §4p.1/§4p.2 measured what that economy is
worth — raising the cap trades a measured cost for an unmeasured benefit in the wrong direction.

> **The baseline this item was waiting for now exists — 2026-08-26, and the answer is: not yet.**
>
> This item said *"run the arm on source order, then ablate the selection rule against it"*, and the
> arm has run (`BENCHMARK_STATUS.md` §4x). But the baseline it produced is **a null**: context made
> no measurable difference to findings. **Ablating a selection rule inside a component that showed no
> effect measures nothing** — any movement would be indistinguishable from the run-to-run spread the
> arm already exhibits, which at 15–20 of 36 is wider than any neighbour-selection change is likely
> to produce.
>
> **The ablation becomes worth running when, and only when, some configuration of the context arm
> first shows an effect to attribute.** Three candidates, in the order their evidence supports:
>
> 1. **Honour the escalation tier.** 113 of 175 bundles asked for `full_file` and got slices. This is
>    the pipeline's own judgment that slices are insufficient, overruled by an implementation detail
>    of the capture. Of everything unmeasured, this is the one the pipeline itself predicts matters.
> 2. **Bundles instead of the diff** — the 0.50× rung. Not because it should score better, but
>    because it is the only configuration that is *cheaper*, and because it has no context-window
>    ceiling: it would review the 4.37 MB pull request neither current LLM arm can open (§4v).
> 3. **A corpus that is not `reverse_fix`.** §7.1 of `REPORT.md`: reverting a fix makes the
>    vulnerable lines *be* the diff, so this corpus structurally cannot contain the case where
>    context matters most. **No amount of tuning inside the bundle fixes that**, and it is the
>    largest single limit on everything Plan 3 measured.
>
> **Cost of leaving it: still zero, and now better understood.** The reason to leave it is no longer
> "the arm has not run" but "the arm ran and there is nothing to ablate against".


## 26. A `ContextBundle` cannot name the file its own hunks are in — **2026-08-26**

Found by building the first consumer of a bundle (Plan 3 Step 3, `BENCHMARK_STATUS.md` §4r.1).

`ContextBundle.hunks` are `Hunk` objects, and `Hunk.id` is `"<file_id>:h<n>"` where `file_id` is a
hash from the delta manifest. The path lives on `ChangeGroup.files`, and the bundle does not embed
the group. So the payload whose docstring says it is *"the exact context a Phase-3b agent receives
for one group"* does not tell that agent which file the changed lines are in.

**Measured on the pinned capture**, 175 bundles:

| | count |
|---|---|
| bundles whose hunks span more than one file | **0 of 175** — a group is single-file, so the question is well formed |
| path recoverable from `enclosing_symbols[].file` | 141 of 175 |
| **path not recoverable at all** | **34 of 175** |

The renderer says *"file: not carried in the bundle — match the ranges below against the diff"* for
those 34, which is honest and works only because **this** arm also carries the diff. A Phase-3b agent
would not have that fallback: it receives the bundle and nothing else, so for 19% of groups it would
have line numbers with no file to apply them to.

**The fix is one field and it is deliberately not being made now.** Adding `files: list[str]` to
`ContextBundle` changes the capture's shape, which means `CAPTURE_VERSION` 2, a re-capture of the
whole labelled corpus (~10–14 min), and a new pinned artifact — during a plan whose entire point is
that the pipeline half stays fixed while the model half varies. Changing the input mid-experiment is
the confound Step 2 exists to prevent.

**Do it at the top of the next plan, not at the end of this one**, and re-capture in the same commit
that bumps the version — `load()` already refuses a mismatch, so the failure mode is loud.

**What this is evidence for, beyond itself.** The bundle was specified in phase-2 §5, built in M2,
serialized on every run since, and censused in §4p — and the gap only appeared when something finally
had to *read* one. That is the argument for pricing Phase 3b with a consumer before building the
agent, and it belongs in the write-up as a finding rather than as a footnote about a missing field.


## 27. `_CWE_GROUPS` is a hand-list, and the hierarchy it is missing costs the LLM arms a third of their recall — **2026-08-26, PARTLY CLOSED THE SAME DAY**

Found by reading three smoke findings the metrics had already dismissed (`BENCHMARK_STATUS.md` §4u).
Re-derive with `.claude/handoff/cwe-relation-probe.py` rather than quoting the numbers below.

`scoring.cwe_match` relates two CWEs only if a **hand-written** group in `_CWE_GROUPS` says so. Five
parent/child families are listed. **CWE-59 → CWE-61 is the same relationship and is absent**, and it
is the corpus's most common class.

Across the six stored LLM passes, **124 findings land in the right file on overlapping lines and are
scored false positive on the CWE id alone** — 44 of them on the CWE-59/61 pair, in both directions.

| group added | arm 2's ceiling | arm 3 rows matched, p1/p2/p3 |
|---|---|---|
| none (today) | 9/36 | 13 / 13 / 12 |
| **{CWE-59, CWE-61}** | **9/36 — unchanged** | **18 / 18 / 17** |
| {CWE-77, 78, 88} | **11/36 — moves** | 14 / 14 / 13 |
| {CWE-287, CWE-306} | 9/36 — unchanged | 14 / 13 / 13 |

> **This table was measured on 2026-08-26 *before* `{CWE-59, CWE-61}` was added**, which is why its
> first row reads 13/13/12. It is the evidence the decision was taken on and is left as it stood.
> Re-running `.claude/handoff/cwe-relation-probe.py` today reports the current table as the baseline
> and 18/18/17, because the pair is now in it.

**This is under a standing constraint and is therefore the owner's call, not a fix to make.** The
rule is *do not widen `_CWE_GROUPS` to flatter an arm*, and its mechanism is that `benchmark/scope.py`
reads the same table so widening moves recall both ways. §4u.2 is the measurement that rule asks for:

- **{CWE-59, CWE-61} does not move arm 2's ceiling** — neither id is emittable by any detector, so
  `reachable_ground_truth` cannot change. It raises the **LLM** arms from 0.35 to ~0.49 while the
  pipeline stays at 1/36, i.e. it makes this project's own tool look worse. Not self-flattery in any
  direction.
- **{CWE-77, 78, 88} does move it**, 9 to 11, because CWE-78 is emittable. The constraint is right to
  forbid this one, and it separates the two cases rather than banning both.

**The deeper problem, which no single group fixes.** A hand-list cannot keep up with a taxonomy of
~940 ids. Every advisory that labels a defect one level up or down from where a model would is a
silent false positive. The options, none free:

| option | cost | what it buys |
|---|---|---|
| add the one measured pair | minutes | the largest single source of error, and nothing else |
| add a real CWE parent/child table (MITRE publishes one) | a data file and its provenance | the class of error, permanently |
| report a *CWE-agnostic* recall alongside the current one | a metric | separates "found the defect" from "labelled it our way" — arguably the number a reader wants |

**The third is the one worth doing regardless of the first two**, because it makes the question
visible rather than resolving it by decree: a reader can then see how much of the gap between arms is
detection and how much is vocabulary.

**Cost of leaving it: rising.** Every paid pass stored while this is open is a pass whose absolute
numbers are understated by roughly a third, and `rescore` makes re-deriving them free only for as
long as the runs are still on disk.

> **PARTLY CLOSED 2026-08-26** (§4u.4, errata §14.59). The owner took options 1 and 3: the measured
> pair was added, and `recall_ignoring_cwe` now reports beside `recall` everywhere. All 36 stored
> scorecards were re-scored; no pipeline number moved.
>
> **What remains open is option 2 — a real parent/child table** — and it is deliberately still open.
> The probe still finds `{CWE-77, 78, 88}` (rejected: moves arm 2's ceiling 9 → 11),
> `{CWE-287, CWE-306}` and `{CWE-834, CWE-770}` as further candidates. **Do not add them one at a
> time as they turn up in results.** That is how a relation table becomes a record of which arms were
> measured rather than of how CWEs relate — the exact failure the standing constraint exists to
> prevent. Either import MITRE's published hierarchy wholesale, with its provenance recorded, or add
> nothing further and let `recall_ignoring_cwe` carry the question.
