"""Change groups, CPG-driven `touches`, family routing (phase-2 §4).

Turns surviving hunks into an `AnnotatedChangeSet`: what changed, what security
surface it touches, which Phase-3b families should look at it, and how sure we
are of that routing. Everything here is deterministic — the CPG and the profile
answer the questions, and the triage model only contributes labels the filter
already collected.

WHY `SecurityIndex` LIVES HERE
phase-2 §7 assigns "CPG-driven `touches`" to this module, and the noise filter's
allow-by-default guardrail asks the *same* question ("does this file touch
security-relevant structure?") with a different consequence. Rather than answer
it twice and let the two answers drift, `filter.py` imports this index. The
guardrail and the routing are then provably the same query: a file the filter
refused to drop is a file this module can explain.

THREE SIGNAL SOURCES, AND WHY EACH IS NEEDED

  CPG nodes     endpoints, sources, sinks, sanitizers, sensitive fields, with
                lines — the precise layer.
  Profile rows  access-control rows and permission checks, which carry the agent
                lift (`declared_not_enforced`) that the CPG has no node for.
  Path + flags  `permissions.py`, `settings.py`, a lockfile, a Terraform file.
                Structure-free but decisive: a new `middleware.py` has no CPG
                node yet and must never be filtered out.

THE PROFILE IS AT `base_sha`, THE DIFF IS NOT
The CPG describes the repo *before* this PR. So a guard the PR **removes** is
still in the graph and a guard it **adds** is absent from it. Neither is a bug —
it is why `_guard_edits()` reads the hunk text against the framework catalog.
That textual pass is what makes "someone deleted `@login_required`" visible at
all, and it is the single highest-signal one-line change in a Python PR.

GROUPING IS PER FILE, ON PURPOSE
Groups key on `(file, touch signature)`. Cross-file merging is deliberately not
done: the similarity notion it needs is untuned, and over-merging produces one
enormous context bundle — precisely the failure the tiered context design exists
to prevent (§5). Cross-file relationships are not lost; `context.py` carries them
as 1-hop `neighbors` from the call graph.
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from fnmatch import fnmatch
from posixpath import basename
from typing import get_args

from pr_review.change.schema import AnnotatedChangeSet, ChangeGroup, TouchKind
from pr_review.config import Config
from pr_review.extract.diff import ParsedFile
from pr_review.extract.schema import DeltaManifest, FileChange, Hunk
from pr_review.profile.patterns import load_catalog
from pr_review.profile.schema import ProjectProfile
from pr_review.schema import Severity
from pr_review.taxonomy import registry

# Derived from the schema's Literal rather than restated, so the two cannot
# drift — a routing key that is not a `TouchKind` would never reach Phase 3.
TOUCH_KINDS: frozenset[str] = frozenset(get_args(TouchKind))

# What the tier-2 guardrail protects: the security surface named in phase-2 §3,
# plus the two node kinds that are surface without being a routing key. Narrower
# than TOUCH_KINDS on purpose — see `SecurityIndex.security_relevant`.
GUARDRAIL_KINDS: frozenset[str] = frozenset(
    {"endpoint", "auth", "authz", "source", "sink",
     "sensitive_field", "sanitizer", "permission"}
)

# CPG node kind -> touch kind. `sanitizer` and `permission` are deliberately
# absent: they make a file security-relevant for the guardrail but are not
# themselves a routing key (a sanitizer routes via the sink it protects).
_NODE_TO_TOUCH = {
    "endpoint": "endpoint",
    "source": "source",
    "sink": "sink",
    "sensitive_field": "sensitive_field",
}

# Names that indicate *authentication* rather than authorization. Everything
# else that guards an endpoint is treated as authz, which is the larger family
# and the one with the flagship agent.
_AUTHN_HINTS = (
    "login", "authenticate", "authentication", "jwt", "session", "token",
    "current_user", "oauth", "basic", "bearer", "api_key", "apikey", "mfa",
    "otp", "signin", "sign_in",
)

# Path shape -> what changing it touches, for files with no CPG presence.
_PATH_SIGNALS: tuple[tuple[str, str], ...] = (
    ("**/settings.py", "config"),
    ("**/settings/*.py", "config"),
    ("**/config.py", "config"),
    ("**/urls.py", "endpoint"),
    ("**/routes.py", "endpoint"),
    ("**/middleware.py", "authz"),
    ("**/permissions.py", "authz"),
    ("**/auth.py", "auth"),
    ("**/authentication.py", "auth"),
    ("**/security.py", "authz"),
)

# Assertion vocabulary, for spotting a security test that a PR weakens.
_AUTHZ_TEST_TERMS = ("403", "forbidden", "permission", "unauthorized_access",
                     "is_admin", "role", "authz", "access_denied", "no_access")
_AUTHN_TEST_TERMS = ("401", "unauthorized", "login", "logged_in", "authenticate",
                     "token", "session", "credential")


@dataclass
class Signal:
    """One reason a path is security-relevant."""
    kind: str                    # a TouchKind, or "sanitizer"/"permission"
    line: int = 0
    detail: str = ""
    confidence: int = 8
    source: str = "cpg"          # cpg | profile | path | text

    @property
    def is_touch(self) -> bool:
        return self.kind in TOUCH_KINDS


# ---------------------------------------------------------------------------
# The shared read-model
# ---------------------------------------------------------------------------

class SecurityIndex:
    """Per-file security signals, assembled once and queried by line range.

    Constructed with whatever is available. With no CPG and no profile it still
    answers from paths and manifest flags — degraded, never absent, because the
    consumer that matters most (the guardrail) fails dangerously when it gets an
    empty answer for the wrong reason.
    """

    def __init__(self, cpg=None, profile: ProjectProfile | None = None,
                 manifest: DeltaManifest | None = None,
                 config: Config | None = None, language: str = "python") -> None:
        self.config = config or Config()
        self.language = language
        self.has_cpg = cpg is not None
        self.has_profile = profile is not None
        self._signals: dict[str, list[Signal]] = defaultdict(list)

        if cpg is not None:
            self._from_cpg(cpg)
        if profile is not None:
            self._from_profile(profile)
        if manifest is not None:
            self._from_manifest(manifest)

    # -- construction ------------------------------------------------------

    def _from_cpg(self, cpg) -> None:
        for node in cpg.graph.nodes():
            if not node.file:
                continue
            touch = _NODE_TO_TOUCH.get(node.kind)
            if touch:
                self._signals[node.file].append(
                    Signal(touch, node.line, node.name, 8, "cpg"))
            elif node.kind == "sanitizer":
                self._signals[node.file].append(
                    Signal("sanitizer", node.line, node.name, 8, "cpg"))
            if node.kind == "endpoint":
                for guard in node.attrs.get("guards", []) or []:
                    self._signals[node.file].append(
                        Signal(_authn_or_authz(guard), node.line, guard, 8, "cpg"))
                if node.attrs.get("opens_access"):
                    self._signals[node.file].append(
                        Signal("authz", node.line, "opens_access", 9, "cpg"))

    def _from_profile(self, profile: ProjectProfile) -> None:
        for row in profile.access_control_matrix:
            if not row.file:
                continue
            self._signals[row.file].append(
                Signal("endpoint", row.line or 0, row.endpoint, 9, "profile"))
            # An unenforced row is the A01 candidate set — mark it either way, so
            # a change *near* it always routes to Broken Access Control.
            self._signals[row.file].append(
                Signal(_authn_or_authz(row.auth_pattern), row.line or 0,
                       f"enforcement={row.enforcement}", 9, "profile"))
        for check in profile.permission_checks:
            if check.file:
                self._signals[check.file].append(
                    Signal(_authn_or_authz(check.name), check.line or 0,
                           check.name, 9, "profile"))
        for field_ in profile.sensitive_fields:
            for loc in field_.locations:
                path = loc.split(":", 1)[0]
                if path:
                    self._signals[path].append(
                        Signal("sensitive_field", 0, field_.name, 9, "profile"))

    def _from_manifest(self, manifest: DeltaManifest) -> None:
        for fc in manifest.files:
            for signal in self.path_signals(fc):
                self._signals[fc.path].append(signal)

    def path_signals(self, fc: FileChange) -> list[Signal]:
        """Signals derivable from the path and the Phase-0 flags alone.

        These carry confidence 9 because they are facts, not inferences: a
        lockfile *is* a dependency change. They also cover the case the CPG
        structurally cannot — a file added by this PR has no node in a graph
        built from `base_sha`.
        """
        out: list[Signal] = []
        if fc.is_lockfile or fc.is_dep_manifest:
            out.append(Signal("dependency", 0, basename(fc.path), 9, "path"))
        if fc.is_iac:
            out.append(Signal("config", 0, basename(fc.path), 9, "path"))
        for pattern, kind in _PATH_SIGNALS:
            if fnmatch(fc.path, pattern) or fnmatch("/" + fc.path, "*/" + pattern.lstrip("*/")):
                out.append(Signal(kind, 0, basename(fc.path), 8, "path"))
        return out

    # -- queries -----------------------------------------------------------

    def signals(self, path: str) -> list[Signal]:
        return list(self._signals.get(path, ()))

    def signals_in(self, path: str, span: tuple[int, int] | None) -> list[Signal]:
        """Signals inside a hunk's line span, plus every line-less signal.

        A `span` of None (a deleted file, or a pure-deletion hunk) falls back to
        the whole file. Line-0 signals — path flags, profile rows with no line —
        always apply: they describe the file, not a region of it.
        """
        found = self.signals(path)
        if span is None:
            return found
        lo, hi = span
        return [s for s in found if s.line == 0 or lo <= s.line <= hi]

    def touches(self, path: str, span: tuple[int, int] | None = None) -> set[str]:
        return {s.kind for s in self.signals_in(path, span) if s.is_touch}

    def security_relevant(self, path: str) -> bool:
        """The tier-2 guardrail question (phase-2 §3).

        Scoped to `GUARDRAIL_KINDS` — the security *surface*. `sanitizer` counts
        even though it is not a touch kind: a file whose only security presence
        is `shlex.quote` is a file where deleting one line turns a safe call into
        command injection.

        `config` and `dependency` are deliberately excluded. They are not a
        security surface, and including them would make the guardrail veto the
        very tier-1 rules that exist to act on them — a lockfile is `dependency`
        by definition, so the `lockfile_captured` drop could never fire.
        """
        return any(s.kind in GUARDRAIL_KINDS for s in self._signals.get(path, ()))

    def why(self, path: str, spans: list[tuple[int, int]] | None = None) -> str:
        """A human-readable account of the signals, optionally limited to spans.

        Unscoped for the guardrail (the drop is about the whole file); scoped to
        the hunks for a change group's rationale, so it explains *this* change
        rather than everything the file happens to contain.
        """
        seen: dict[str, str] = {}
        for span in (spans or [None]):
            for s in self.signals_in(path, span):
                seen.setdefault(s.kind, s.detail)
        return ", ".join(f"{k}({v})" if v else k for k, v in sorted(seen.items()))


def _authn_or_authz(name: str) -> str:
    lowered = (name or "").lower()
    return "auth" if any(h in lowered for h in _AUTHN_HINTS) else "authz"


# ---------------------------------------------------------------------------
# Guard edits — the signal the base-sha CPG cannot carry
# ---------------------------------------------------------------------------

@dataclass
class GuardEdit:
    kind: str            # guard_removed | guard_added | access_opened
    name: str
    line: int
    path: str


def _catalog_guard_names(language: str) -> tuple[set[str], set[str]]:
    """(enforcing guard names, access-opening names) across every framework."""
    try:
        catalog = load_catalog(language)
    except Exception:                                # noqa: BLE001
        return set(), set()
    guards: set[str] = set()
    opening: set[str] = set()
    for fw in (catalog.get("frameworks") or {}).values():
        auth = fw.get("auth") or {}
        for key in ("decorators", "mixins", "dependency_names"):
            guards |= set(auth.get(key) or [])
        perms = auth.get("permission_classes") or {}
        guards |= set(perms.get("enforcing") or [])
        opening |= set(auth.get("opt_out_decorators") or [])
        opening |= set(perms.get("opening") or [])
    return {g.rsplit(".", 1)[-1] for g in guards}, {o.rsplit(".", 1)[-1] for o in opening}


def guard_edits(parsed: ParsedFile, language: str = "python") -> list[GuardEdit]:
    """Guards this diff adds or removes, read from the hunk text.

    Word-boundary matching against the framework catalog. This is a text pass
    because the graph cannot answer it: the CPG is built at `base_sha`, so it
    contains exactly the guards the PR has not touched.
    """
    guards, opening = _catalog_guard_names(language)
    if not guards and not opening:
        return []
    edits: list[GuardEdit] = []
    for hunk in parsed.hunks:
        for line in hunk.removed:
            for name in _names_in(line.text, guards):
                edits.append(GuardEdit("guard_removed", name, line.lineno, parsed.path))
        for line in hunk.added:
            for name in _names_in(line.text, guards):
                edits.append(GuardEdit("guard_added", name, line.lineno, parsed.path))
            for name in _names_in(line.text, opening):
                edits.append(GuardEdit("access_opened", name, line.lineno, parsed.path))
    return edits


def _names_in(text: str, names: set[str]) -> list[str]:
    if not text.strip():
        return []
    return sorted(n for n in names if re.search(rf"\b{re.escape(n)}\b", text))


def weakened_security_test(parsed: ParsedFile) -> tuple[bool, list[str]]:
    """Whether a test file drops a security assertion, and which families it covered.

    phase-2 §3: a deleted or weakened security test is itself a signal, so tests
    are never silently dropped. Removed lines only — adding an assertion is fine.
    """
    removed = " ".join(l.text.lower() for h in parsed.hunks for l in h.removed)
    if not removed.strip():
        return False, []
    assertive = "assert" in removed or "status_code" in removed or "raises" in removed
    if not assertive:
        return False, []
    fams: list[str] = []
    if any(t in removed for t in _AUTHZ_TEST_TERMS):
        fams.append("Broken Access Control")
    if any(t in removed for t in _AUTHN_TEST_TERMS):
        fams.append("Authentication Failures")
    return bool(fams), fams


# ---------------------------------------------------------------------------
# Family routing (phase-2 §4)
# ---------------------------------------------------------------------------

def route_families(touches: set[str], sink_classes: set[str] | None = None,
                   tainted: bool = False) -> list[str]:
    """`touches` -> the Phase-3b families that should analyze this group.

    Recall-biased: a lone sink routes to Injection even with no source found,
    because taint-lite only *seeds* candidates and Phase 3c is the stage that
    refutes them cheaply. Validated against the registry so a typo cannot
    produce a group no runner claims.
    """
    sink_classes = sink_classes or set()
    fams: list[str] = []

    if "endpoint" in touches or "authz" in touches:
        fams.append("Broken Access Control")
    if "auth" in touches:
        fams.append("Authentication Failures")
    if "sink" in touches or "source" in touches:
        fams.append("Injection")
    if "deserialize" in sink_classes:
        fams.append("Software/Data Integrity")
    if "sensitive_field" in touches:
        fams.append("Privacy / PII")
        if "log" in sink_classes or "sink" in touches:
            fams.append("Logging & Alerting")
    if "config" in touches:
        fams.append("Security Misconfiguration")
    if "dependency" in touches:
        # No agent — Phase 3a's SCA owns this. Routed anyway so the coverage
        # denominator counts it as handled rather than skipped (§6).
        fams.append("Software Supply Chain")
    if tainted and "Injection" not in fams:
        fams.append("Injection")

    return registry.validate_families(sorted(dict.fromkeys(fams)))


# ---------------------------------------------------------------------------
# Grouping
# ---------------------------------------------------------------------------

def _span(hunk: Hunk) -> tuple[int, int] | None:
    if not hunk.new_range:
        return None
    lo, _, hi = hunk.new_range.partition("-")
    try:
        return int(lo), int(hi or lo)
    except ValueError:
        return None


def _kind_of(touches: set[str], fc: FileChange, weakened: bool) -> str:
    security = {"endpoint", "auth", "authz", "source", "sink", "sensitive_field"}
    if touches & security or weakened:
        return "security"
    if touches & {"config", "dependency"}:
        return "architecture"
    if fc.is_test:
        return "quality"
    return "convention"


def _severity(touches: set[str], edits: list[GuardEdit], tainted: bool,
              unguarded_endpoint: bool) -> Severity:
    """A cheap prior, refined in 3d after reachability and verification (§3)."""
    if tainted or unguarded_endpoint:
        return Severity.HIGH
    if any(e.kind in ("guard_removed", "access_opened") for e in edits):
        return Severity.HIGH
    if touches & {"sink", "endpoint", "auth", "authz"}:
        return Severity.MEDIUM
    if touches & {"sensitive_field", "config", "dependency", "source"}:
        return Severity.MEDIUM
    return Severity.LOW


def _significant(touches: set[str], edits: list[GuardEdit],
                 weakened: bool, fc: FileChange) -> tuple[bool, list[str]]:
    """The significant-changes checklist (phase-2 §4), with the item that hit."""
    hits: list[str] = []
    if touches & {"auth", "authz"} or edits:
        hits.append("auth/authz logic")
    if "endpoint" in touches:
        hits.append("new or modified API endpoint")
    if "sensitive_field" in touches:
        hits.append("sensitive-data handling")
    if "source" in touches or "sink" in touches:
        hits.append("new I/O channel")
    if touches & {"config", "dependency"} or fc.is_iac:
        hits.append("architecture/config change")
    if weakened:
        hits.append("weakened security test")
    return bool(hits), hits


def classify_changes(
    manifest: DeltaManifest,
    kept: dict[str, list[str]],
    parsed: list[ParsedFile] | None = None,
    cpg=None,
    profile: ProjectProfile | None = None,
    config: Config | None = None,
    index: SecurityIndex | None = None,
    dropped=None,
    triage_labels: dict[str, str] | None = None,
) -> AnnotatedChangeSet:
    """Build the `AnnotatedChangeSet` from the hunks the filter kept."""
    config = config or Config()
    language = config.languages[0] if config.languages else "python"
    index = index or SecurityIndex(cpg, profile, manifest, config, language)
    by_path = {pf.path: pf for pf in (parsed or [])}
    triage_labels = triage_labels or {}

    taint_lines = _taint_lines(cpg)
    sink_class_by_line = _sink_classes(cpg)
    unguarded = _unguarded_lines(cpg, profile)

    groups: list[ChangeGroup] = []
    for fc in sorted(manifest.files, key=lambda f: f.path):
        hunk_ids = kept.get(fc.path)
        if hunk_ids is None:
            continue
        pf = by_path.get(fc.path)
        edits = guard_edits(pf, language) if pf else []
        weakened, test_families = weakened_security_test(pf) if (pf and fc.is_test) \
            else (False, [])

        # Bucket the file's surviving hunks by their touch signature. A file
        # with no hunks at all — a rename, a mode change, a binary the guardrail
        # rescued — still gets one file-level group, because "nothing to show
        # you" is not the same as "nothing changed".
        surviving = set(hunk_ids)
        hunks: list[Hunk | None] = [h for h in fc.hunks if h.id in surviving]
        if not hunks and not fc.hunks:
            hunks = [None]

        buckets: dict[frozenset[str], list[Hunk]] = defaultdict(list)
        for hunk in hunks:
            span = _span(hunk) if hunk is not None else None
            touches = index.touches(fc.path, span)
            if edits and _edits_in_span(edits, span):
                touches |= {"authz"}
            if weakened:
                touches |= {"authz"} if "Broken Access Control" in test_families else set()
            buckets[frozenset(touches)].append(hunk)

        for n, (signature, bucket) in enumerate(
                sorted(buckets.items(), key=lambda kv: sorted(kv[0]))):
            groups.append(_make_group(
                index=index, fc=fc, n=n, touches=set(signature), hunks=bucket,
                edits=edits, weakened=weakened, test_families=test_families,
                taint_lines=taint_lines, sink_class_by_line=sink_class_by_line,
                unguarded=unguarded, triage_labels=triage_labels,
            ))

    changeset = AnnotatedChangeSet(
        repo=manifest.repo,
        pr_number=manifest.pr_number,
        base_sha=manifest.base_sha,
        head_sha=manifest.head_sha,
        profile_version=profile.profile_version if profile else "",
        groups=groups,
        dropped=list(dropped or []),
        coverage_plan={g.id: g.candidate_families for g in groups},
    )
    return changeset


def _make_group(*, index, fc, n, touches, hunks, edits, weakened, test_families,
                taint_lines, sink_class_by_line, unguarded, triage_labels
                ) -> ChangeGroup:
    spans = [_span(h) for h in hunks if h is not None]
    lines = {ln for span in spans if span for ln in range(span[0], span[1] + 1)}

    tainted = bool(lines & taint_lines.get(fc.path, set()))
    # An empty `lines` means a file-level group (no hunk spans), so the whole
    # file's sinks are in scope — the alternative is routing it nowhere.
    sink_classes = {cls for ln, cls in sink_class_by_line.get(fc.path, ())
                    if not lines or ln in lines}
    unguarded_endpoint = bool(lines & unguarded.get(fc.path, set())) or (
        not lines and bool(unguarded.get(fc.path)))

    families = route_families(touches, sink_classes, tainted)
    for fam in test_families:
        if fam not in families:
            families.append(fam)
    families = registry.validate_families(sorted(dict.fromkeys(families)))

    significant, checklist = _significant(touches, edits, weakened, fc)
    hunk_ids = [h.id for h in hunks if h is not None]
    labels = {triage_labels.get(hid) for hid in hunk_ids} - {None}

    confidence = max(
        [s.confidence for s in index.signals(fc.path) if s.kind in touches] or [5]
    )
    if edits or weakened:
        confidence = max(confidence, 7)
    if labels == {"maybe"}:
        confidence = min(confidence, 4)

    return ChangeGroup(
        id=f"{fc.file_id[:8]}-{n}",
        kind=_kind_of(touches, fc, weakened),
        files=[fc.path],
        hunk_ids=hunk_ids,
        touches=sorted(touches),
        candidate_families=families,
        projected_severity=_severity(touches, edits, tainted, unguarded_endpoint),
        confidence=confidence,
        significant=significant,
        rationale=_rationale(index, fc, touches, edits, checklist, tainted,
                             weakened, spans),
    )


def _rationale(index, fc, touches, edits, checklist, tainted, weakened,
               spans) -> str:
    bits: list[str] = []
    if touches:
        bits.append(
            f"touches {', '.join(sorted(touches))} ({index.why(fc.path, spans) or 'path'})")
    else:
        bits.append("no security surface found in the CPG or profile for this file")
    if edits:
        bits.append("; ".join(sorted({f"{e.kind}:{e.name}" for e in edits})))
    if tainted:
        bits.append("a taint-lite path passes through the changed lines")
    if weakened:
        bits.append("a security assertion was removed from a test")
    if checklist:
        bits.append("significant: " + "; ".join(checklist))
    return ". ".join(bits)


def _edits_in_span(edits: list[GuardEdit], span: tuple[int, int] | None) -> bool:
    if span is None:
        return bool(edits)
    lo, hi = span
    # Removed-line numbers index the OLD file, so a strict span test would miss
    # every deletion. Widened to the hunk window, which is where they landed.
    return any(lo - 3 <= e.line <= hi + 3 for e in edits)


# ---------------------------------------------------------------------------
# CPG projections
# ---------------------------------------------------------------------------

def _taint_lines(cpg) -> dict[str, set[int]]:
    """file -> lines that lie on a taint-lite path (source or sink endpoint)."""
    out: dict[str, set[int]] = defaultdict(set)
    for path in getattr(cpg, "taint_paths", ()) or ():
        out[path.source.file].add(path.source.line)
        out[path.sink.file].add(path.sink.line)
    return out


def _sink_classes(cpg) -> dict[str, list[tuple[int, str]]]:
    out: dict[str, list[tuple[int, str]]] = defaultdict(list)
    if cpg is None:
        return out
    for node in cpg.nodes_of_kind("sink"):
        out[node.file].append((node.line, node.attrs.get("sink_class", "")))
    return out


def _unguarded_lines(cpg, profile) -> dict[str, set[int]]:
    """file -> lines of endpoints with no effective enforcement."""
    out: dict[str, set[int]] = defaultdict(set)
    if cpg is not None:
        for node in cpg.unguarded_endpoints():
            out[node.file].add(node.line)
    if profile is not None:
        for row in profile.unguarded_endpoints():
            if row.file:
                out[row.file].add(row.line or 0)
    return out
