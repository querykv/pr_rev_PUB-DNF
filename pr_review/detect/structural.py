"""Structural detector over our own CPG (phase-3 §3a, "our CPG — no subprocess").

The only 3a adapter with no external tool behind it, and the only one that can
express a rule about *this* application: Semgrep knows what `subprocess.run`
means, it does not know that `/items/{iid}` lost its authorization dependency
in this PR.

IT NEEDS THE HEAD, AND THAT IS THE WHOLE DESIGN PROBLEM

Phase 1's profile and CPG describe the checkout at **base_sha** — `phase-1 §6`
is emphatic about it, and `profile/incremental.py` refuses to patch a base
profile from head content for a good reason: a graph that is base for most
files and head for a few is neither commit, and nothing downstream could tell.

But a detector asking "what did this PR introduce" has to see the code the PR
produced. So this module builds a **transient head-side subgraph** — one parse
per changed file, out of `head_dir`, thrown away at the end of the run. It is
never cached, never merged into the profile, and never written to
`.pr_review/cache/`. The cached artifact stays a clean base-commit artifact;
this is a detector's scratch space that happens to use the same builder.

The consequence is a hard dependency: **without `--head-dir` this detector is
disabled**, and says so in telemetry rather than falling back to the base graph.
Reporting base-side structure during a PR review would attribute the
repository's existing shape to the author of the diff.

WHAT IT EMITS

- **Taint.** An unsanitized source -> sink path whose sink sits in a file the PR
  changed. Severity comes from the sink class; a path reachable from an
  unguarded endpoint is raised, because that is the difference between a
  dangerous function and an attacker-reachable one.
- **Access control.** An unguarded endpoint in a changed file. When the base
  graph shows the same endpoint *guarded*, that is a removed guard, which is a
  far stronger claim than "this endpoint has no check" and is reported as such.

WHAT IT DELIBERATELY DOES NOT EMIT

The CPG's `log` and `response` sink classes. A path from untrusted input to a
log call is log forging (CWE-117); a path to a response is reflection. Both are
low-value on their own, and the *interesting* question for those two sinks runs
the other way — does a **sensitive value** reach them — which is a query over
the sensitive-field overlay, not the untrusted-source overlay, and belongs to
the Privacy/PII family in Phase 3b. Emitting them here would fill the report
with `logging.info(request.args[...])` at the cost of the findings that matter.

BOUNDED BY THE RESOLVER: `cpg._resolve_callee` is local-file-first, so no call
edge and no taint path crosses a file boundary. Every claim below is therefore
within-file, which understates real reachability and never overstates it.
"""
from __future__ import annotations

from collections import deque
from pathlib import Path

from pr_review.detect.base import AdapterRun, Detector, ScanTarget
from pr_review.detect.normalize import make_finding
from pr_review.extract.schema import DeltaManifest
from pr_review.schema import DetectorKind, Finding, Reachability, Severity

TOOL = "cpg-structural"

# sink_class -> (internal id, base severity, title)
_SINKS: dict[str, tuple[str, Severity, str]] = {
    "sql": ("INJ-SQLI", Severity.HIGH, "Untrusted input reaches an SQL sink"),
    "command": ("INJ-CMD", Severity.HIGH, "Untrusted input reaches a command sink"),
    "code_exec": ("INJ-CODE-EXEC", Severity.HIGH, "Untrusted input reaches a code-execution sink"),
    "deserialize": ("INJ-DESERIALIZE", Severity.HIGH, "Untrusted input is deserialized"),
    "template": ("INJ-SSTI", Severity.MEDIUM, "Untrusted input reaches a template sink"),
    "path": ("BAC-PATH-TRAVERSAL", Severity.MEDIUM, "Untrusted input reaches a filesystem path"),
    "http_outbound": ("BAC-SSRF", Severity.MEDIUM, "Untrusted input controls an outbound request"),
}

# See the module docstring — these two are a different question, not an omission.
_SKIPPED_SINKS = ("log", "response")


# ---------------------------------------------------------------------------
# The transient head-side subgraph
# ---------------------------------------------------------------------------

def head_subgraph(head_dir: str | Path, manifest: DeltaManifest, language: str = "python"):
    """Parse the PR's changed files out of `head_dir` into a throwaway CPG.

    Costs one tree-sitter parse per changed file — the same unit of work
    `profile/incremental.py` does, which is what makes running it per PR
    affordable at all.

    CAP is reached through `profile/incremental.partial_cache()` rather than
    imported here, which keeps `cap_engine` imports confined to the six files
    CONTINUATION §2 lists.
    """
    from pr_review.profile.cpg import build_cpg
    from pr_review.profile.incremental import partial_cache
    from pr_review.profile.promote import extract_frameworks

    head_dir = Path(head_dir)
    paths = [f.path for f in manifest.files
             if not f.is_binary and f.change != "deleted"]
    if not paths:
        return None
    cache = partial_cache(head_dir, paths)
    if not cache.structural_index:
        return None
    promotion = extract_frameworks(cache, head_dir, language)
    return build_cpg(promotion, language=language)


def _reachable_from_endpoints(cpg) -> dict[str, list]:
    """qualified symbol -> the endpoint nodes that can reach it.

    Endpoints link to their handler with `implements`; handlers link onward with
    `calls`. A breadth-first walk over those two relations is the whole of our
    reachability story, and it stops at file boundaries because the resolver
    does (module docstring).
    """
    calls: dict[str, set[str]] = {}
    for src, dst, rel in cpg.edges("calls"):
        calls.setdefault(src.name, set()).add(dst.name)

    reach: dict[str, list] = {}
    for endpoint in cpg.nodes_of_kind("endpoint"):
        seen: set[str] = set()
        queue = deque(dst.name for src, dst, _rel in cpg.edges("implements")
                      if src.id == endpoint.id)
        while queue:
            sym = queue.popleft()
            if sym in seen:
                continue
            seen.add(sym)
            queue.extend(calls.get(sym, ()))
        for sym in seen:
            reach.setdefault(sym, []).append(endpoint)
    return reach


# ---------------------------------------------------------------------------
# The detector
# ---------------------------------------------------------------------------

class StructuralDetector(Detector):
    """CPG taint-lite + access-control deltas.

    Unlike the other adapters this one needs more than the diff, so its context
    arrives through the constructor and `run()`'s `targets` supply only the
    per-path test/generated flags.
    """

    kind = DetectorKind.STRUCTURAL
    name = "structural"

    def __init__(self, head_cpg=None, base_cpg=None, changed_paths: set[str] | None = None,
                 sources=None) -> None:
        self.head_cpg = head_cpg
        self.base_cpg = base_cpg
        self.changed = changed_paths or set()
        self.sources = sources          # (path, side) -> text, for evidence snippets
        self.notes: list[str] = []

    def applicable(self, targets: list[ScanTarget]) -> bool:
        return self.head_cpg is not None

    def run(self, targets: list[ScanTarget]) -> list[Finding]:
        return self.scan(targets).findings

    def scan(self, targets: list[ScanTarget]) -> AdapterRun:
        result = AdapterRun("ran")
        if self.head_cpg is None:
            result.status = "not_applicable"
            result.notes.append(
                "STRUCTURAL DETECTOR SKIPPED: no head checkout, so the graph of "
                "the code this PR produced does not exist. The base-side CPG was "
                "not substituted — it describes the repository before the change "
                "and would attribute existing structure to this PR."
            )
            return result

        is_test = {t.path: t.is_test for t in targets}
        reach = _reachable_from_endpoints(self.head_cpg)

        taint = self._taint_findings(is_test, reach, result)
        bac = self._access_findings(is_test, result)
        result.findings = taint + bac
        result.detail = {
            "taint_paths": len(self.head_cpg.taint_paths),
            "taint_findings": len(taint),
            "endpoints": len(self.head_cpg.nodes_of_kind("endpoint")),
            "access_findings": len(bac),
            "base_graph": self.base_cpg is not None,
        }
        return result

    # -- taint -------------------------------------------------------------

    def _taint_findings(self, is_test: dict[str, bool], reach: dict[str, list],
                        result: AdapterRun) -> list[Finding]:
        out: list[Finding] = []
        skipped = 0
        for path in self.head_cpg.taint_paths:
            if path.sanitized_by:
                continue                        # the catalog says this class is neutralized
            sink_class = path.sink_class
            if sink_class in _SKIPPED_SINKS:
                skipped += 1
                continue
            spec = _SINKS.get(sink_class)
            if spec is None:
                continue
            if path.sink.file not in self.changed:
                continue                        # pre-existing structure, not this PR's
            internal, severity, title = spec

            entry, guards, reachable, unguarded = self._entry_for(path, reach)
            confidence = 7 if reachable else 6
            if unguarded:
                # A dangerous call and an unauthenticated-reachable dangerous
                # call are different findings (cross-cutting §3: severity is
                # impact x exploitability), and the graph is the only thing
                # that knows which this is.
                if severity is Severity.HIGH:
                    severity = Severity.CRITICAL

            out.append(make_finding(
                internal=internal,
                title=title,
                severity=severity,
                confidence=confidence,
                detector=DetectorKind.STRUCTURAL,
                tool=TOOL,
                rule_id=f"taint-{sink_class}",
                path=path.sink.file,
                start_line=path.sink.line,
                symbol=path.symbols[-1] if path.symbols else None,
                snippet=self._line(path.sink.file, path.sink.line)
                        or f"{path.sink.name}(...)",
                why=(f"{path.source.name} is untrusted input and reaches "
                     f"{path.sink.name} with no {sink_class} sanitizer on the path"
                     + (f"; reachable from {entry}" if entry else "")
                     + (f", which is guarded by {', '.join(guards)}" if guards else "")
                     + "."),
                is_test=is_test.get(path.sink.file, False),
                data_flow=path.to_flow(),
                reachability=Reachability(entry=entry,
                                          attacker_reachable=reachable,
                                          guards=guards),
            ))
        if skipped:
            result.notes.append(
                f"{skipped} taint path(s) to log/response sinks were not reported "
                "(see detect/structural.py: those sinks are a sensitive-value "
                "question, not an untrusted-input one)."
            )
        return out

    def _entry_for(self, path, reach: dict[str, list]
                   ) -> tuple[str | None, list[str], bool | None, bool]:
        """`(entry, guards, reachable, unguarded)` for this path's symbols.

        `reachable` and `unguarded` are kept apart on purpose. A sink behind
        `login_required` is still reachable by any attacker who can register an
        account, so it does not become unreachable — it becomes *guarded*, and
        the guard names go on the finding for the verifier to weigh. Only the
        genuinely unauthenticated route earns the severity raise.
        """
        endpoints = []
        for sym in path.symbols:
            endpoints.extend(reach.get(sym, ()))
        if not endpoints:
            return None, [], False, False
        # An unguarded route is the one worth naming when there is one.
        unguarded = [e for e in endpoints if not e.attrs.get("guarded")]
        chosen = (unguarded or endpoints)[0]
        methods = chosen.attrs.get("http_methods") or []
        route = chosen.attrs.get("route") or chosen.name
        entry = f"{'/'.join(m.upper() for m in methods) or 'HTTP'} {route}"
        guards = list(chosen.attrs.get("guards") or [])
        return entry, guards, True, bool(unguarded)

    # -- access control ----------------------------------------------------

    def _access_findings(self, is_test: dict[str, bool],
                         result: AdapterRun) -> list[Finding]:
        out: list[Finding] = []
        base_by_id = {}
        if self.base_cpg is not None:
            base_by_id = {n.id: n for n in self.base_cpg.nodes_of_kind("endpoint")}
        else:
            result.notes.append(
                "no base-side CPG, so a removed authorization check cannot be "
                "distinguished from an endpoint that never had one; unguarded "
                "endpoints in changed files are reported at candidate strength.")

        for node in self.head_cpg.nodes_of_kind("endpoint"):
            if node.attrs.get("guarded"):
                continue
            if node.file not in self.changed:
                continue
            if node.attrs.get("opens_access"):
                # An explicit `AllowAny` / `permission_classes = []` is a
                # decision on the record, not an omission. It may still be
                # wrong, but judging *that* needs to know what the endpoint
                # returns, which is a Phase-3b question about sensitivity.
                continue

            was = base_by_id.get(node.id)
            removed = was is not None and bool(was.attrs.get("guarded"))
            route = node.attrs.get("route") or node.name
            methods = "/".join(m.upper() for m in (node.attrs.get("http_methods") or [])) or "HTTP"

            if removed:
                title = "Authorization check removed from an endpoint"
                why = (f"{methods} {route} was guarded by "
                       f"{', '.join(was.attrs.get('guards') or ['a check'])} at the base "
                       f"commit and has no guard after this change.")
                severity, confidence, rule = Severity.HIGH, 7, "guard-removed"
            else:
                title = "Endpoint has no authorization check"
                why = (f"{methods} {route} is handled by {node.name} and no "
                       f"authorization guard was found on it; this PR changed the "
                       f"file it lives in.")
                severity, confidence, rule = Severity.MEDIUM, 5, "missing-authz"

            out.append(make_finding(
                internal="BAC-MISSING-AUTHZ",
                title=title,
                severity=severity,
                confidence=confidence,
                detector=DetectorKind.STRUCTURAL,
                tool=TOOL,
                rule_id=rule,
                path=node.file,
                start_line=node.line,
                symbol=node.name,
                snippet=self._line(node.file, node.line) or f"{methods} {route}",
                why=why,
                is_test=is_test.get(node.file, False),
                reachability=Reachability(entry=f"{methods} {route}",
                                          attacker_reachable=True, guards=[]),
            ))
        return out

    # -- evidence ----------------------------------------------------------

    def _line(self, path: str, lineno: int) -> str:
        """The head-side source line, for verbatim evidence."""
        if self.sources is None or lineno <= 0:
            return ""
        text = self.sources(path, "after")
        if not text:
            return ""
        lines = text.splitlines()
        if lineno > len(lines):
            return ""
        return lines[lineno - 1].strip()
