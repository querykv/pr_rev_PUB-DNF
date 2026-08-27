"""CLI entry point (typer). Commands: `review` (full M0 thread) and `extract`
(Phase 0 only). Supports an offline `--diff-file` path for environments without
`gh`. Exit code: 1 = flagged, 0 = approved, 2 = tool/usage error.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer

from pr_review import __version__
from pr_review import pipeline
from pr_review.config import Config
from pr_review.vcs.checkout import CheckoutError, GitCheckout
from pr_review.vcs.github import GhNotAvailable, GitHubAdapter

app = typer.Typer(add_completion=False,
                  help="Security-focused PR review. Deterministic detectors "
                       "(Phase 3a); the agentic families and the verifier are "
                       "designed and not built — see README.md.")


def _resolve(pr: Optional[str], diff_file: Optional[str], repo: Optional[str],
             pr_number: Optional[int], cfg: Config):
    """Resolve (repo, number, diff_text, metadata) from CLI inputs.

    Online: use `gh` for metadata + diff. Offline: --diff-file + --repo/--pr.
    """
    adapter = GitHubAdapter(cfg.vcs.token_env)
    if repo and pr_number:
        r, n = repo, pr_number
    elif pr:
        r, n = adapter.parse_url(pr)
    else:
        raise typer.BadParameter("provide a PR URL/owner-repo#N, or --repo and --pr")

    if diff_file:
        diff_text = Path(diff_file).read_text()
        return r, n, diff_text, {}  # offline: no PR metadata

    pr_ref = adapter.get_pr(r, n)
    diff_text = adapter.get_diff(r, n)
    meta = dict(
        title=pr_ref.title, body=pr_ref.body, author=pr_ref.author, base_sha=pr_ref.base_sha,
        head_sha=pr_ref.head_sha, base_ref=pr_ref.base_ref, head_ref=pr_ref.head_ref,
        from_fork=pr_ref.from_fork, labels=pr_ref.labels,
    )
    return r, n, diff_text, meta


def _materialize(repo: str, number: int, meta: dict, cache_root: str):
    """Build both checkouts for an online run, from shas we already fetched.

    THE GAP THIS CLOSES. `vcs/checkout.py` was imported by `benchmark/ghsa.py`
    and by nothing else: the CLI fetched `base_sha` and `head_sha`, passed them
    through as metadata, and left `--base-dir`/`--head-dir` as options a human
    filled in by hand. So the tool's own front door produced an M0-grade run --
    Phase 1 skipped, structural `not_applicable`, delta scoping degraded --
    while `GitCheckout` sat proven across 122 benchmark cases, unwired.

    Returns `(base_dir, head_dir, info)`; `info["skipped"]` explains a refusal
    rather than letting the run silently fall back to the degraded thread.
    """
    base_sha, head_sha = meta.get("base_sha"), meta.get("head_sha")
    if not base_sha or not head_sha:
        return None, None, {"skipped": "PR metadata carried no base/head sha"}
    if base_sha == head_sha:
        # `pipeline._source_reader` refuses one path for both sides, and it is
        # right to: every file would be AST-equal to itself and the whole PR
        # would drop. Say so here rather than fail three phases later.
        return None, None, {"skipped": "base and head are the same commit"}

    co = GitCheckout(cache_root)
    base = co.ensure(repo, base_sha)
    try:
        head = co.ensure(repo, head_sha)
    except CheckoutError:
        # A fork PR's head lives in the contributor's repository, so neither
        # fetch strategy in `_fetch` can reach it. Recovering on failure rather
        # than branching on `PRRef.from_fork` means this also covers a head that
        # is missing for some other reason, and does not trust one API field.
        co.fetch_pull_ref(repo, number)
        head = co.ensure(repo, head_sha)

    return str(base.path), str(head.path), {
        "auto": True,
        "base": {"sha": base_sha[:12], "warm": base.warm},
        "head": {"sha": head_sha[:12], "warm": head.warm},
    }


@app.command()
def review(
    pr: Optional[str] = typer.Argument(None, help="GitHub PR URL or owner/repo#N"),
    diff_file: Optional[str] = typer.Option(None, "--diff-file", help="Offline: read diff from file"),
    repo: Optional[str] = typer.Option(None, "--repo", help="owner/repo (with --diff-file)"),
    pr_number: Optional[int] = typer.Option(None, "--pr", help="PR number (with --repo)"),
    config_path: Optional[str] = typer.Option(None, "--config", help="pr_review.yaml path"),
    out: str = typer.Option(".pr_review/runs", "--out", help="run output root"),
    base_dir: Optional[str] = typer.Option(
        None, "--base-dir",
        help="checkout at base_sha — enables Phase 1 profiling and the CPG"),
    head_dir: Optional[str] = typer.Option(
        None, "--head-dir",
        help="checkout at head_sha — enables AST formatting-only detection and code slices"),
    no_checkout: bool = typer.Option(
        False, "--no-checkout",
        help="online mode: do NOT materialize the two trees. Keeps the M0 thread "
             "reachable — Phase 1 skipped, structural not_applicable."),
):
    """Review a PR: extract -> profile -> change -> detect -> report -> gate."""
    cfg = Config.load(config_path)
    try:
        r, n, diff_text, meta = _resolve(pr, diff_file, repo, pr_number, cfg)
    except GhNotAvailable as e:
        typer.secho(str(e), fg=typer.colors.RED)
        raise typer.Exit(2)

    checkout_info: dict = {}
    if not diff_file and not no_checkout and base_dir is None and head_dir is None:
        try:
            base_dir, head_dir, checkout_info = _materialize(
                r, n, meta, cfg.profile.cache_root)
        except CheckoutError as e:
            # Degrade loudly to the M0 thread. A review that silently reviewed
            # less than it could is the failure this project keeps recording.
            checkout_info = {"skipped": str(e)}
        if checkout_info.get("skipped"):
            typer.secho(f"checkouts unavailable ({checkout_info['skipped']}); "
                        f"Phase 1 will be skipped", fg=typer.colors.YELLOW, err=True)
        else:
            typer.secho(
                f"checkouts ready · base {checkout_info['base']['sha']} "
                f"({'warm' if checkout_info['base']['warm'] else 'cold'}) · "
                f"head {checkout_info['head']['sha']} "
                f"({'warm' if checkout_info['head']['warm'] else 'cold'})",
                fg=typer.colors.BLUE, err=True)

    result = pipeline.run_review(repo=r, pr_number=n, diff_text=diff_text, config=cfg,
                                 out_root=out, base_dir=base_dir, head_dir=head_dir,
                                 checkout_info=checkout_info, **meta)
    color = typer.colors.RED if result.verdict == "flagged" else typer.colors.GREEN
    typer.secho(
        f"Verdict: {result.verdict.upper()}  |  findings: {result.findings}  |  gate triggers: {result.triggers}",
        fg=color,
    )
    typer.echo(f"Changes: {result.groups} group(s), {result.dropped} file(s) filtered out"
               + (f"  |  profile {result.profile_version[:12]}" if result.profile_version
                  else "  |  no profile (run with --base-dir)"))
    typer.echo(f"Report:  {result.out_dir / 'report.md'}")
    typer.echo(f"SARIF:   {result.out_dir / 'report.sarif'}")
    raise typer.Exit(1 if result.verdict == "flagged" else 0)


@app.command()
def profile(
    base_dir: str = typer.Argument(..., help="repo checkout to profile"),
    repo: str = typer.Option(..., "--repo", help="owner/repo — the cache key"),
    base_sha: str = typer.Option("", "--sha", help="commit the checkout is at"),
    rebuild: bool = typer.Option(False, "--rebuild", help="discard any cached profile first"),
    config_path: Optional[str] = typer.Option(None, "--config"),
):
    """Build (or rebuild) the cached ProjectProfile for a repo (phase-1 §8)."""
    from pr_review.profile.cache import ProfileCache
    from pr_review.profile.drift import fingerprint_repo
    from pr_review.profile.security_profile import build_profile

    cfg = Config.load(config_path)
    cache = ProfileCache(repo, cfg.profile.cache_root)
    if rebuild:
        dropped = cache.invalidate()
        typer.echo(f"Invalidated {len(dropped)} cached profile(s).")

    build = build_profile(base_dir, repo=repo, base_sha=base_sha, config=cfg)
    path = cache.save(build.profile,
                      fingerprint_repo(build.promotion, base_sha=base_sha), build.cpg)
    typer.echo(f"Profile: {path}")
    typer.echo(f"  {len(build.profile.access_control_matrix)} access-control rows, "
               f"{len(build.profile.sensitive_fields)} sensitive fields, "
               f"{build.cpg.stats()['taint_paths']} taint path(s)")
    for note in build.profile.notes:
        typer.echo(f"  - {note}")


@app.command()
def extract(
    pr: Optional[str] = typer.Argument(None, help="GitHub PR URL or owner/repo#N"),
    diff_file: Optional[str] = typer.Option(None, "--diff-file"),
    repo: Optional[str] = typer.Option(None, "--repo"),
    pr_number: Optional[int] = typer.Option(None, "--pr"),
    out: str = typer.Option(".pr_review/runs", "--out"),
):
    """Phase 0 only: write the DeltaManifest for a PR."""
    cfg = Config.load(None)
    try:
        r, n, diff_text, meta = _resolve(pr, diff_file, repo, pr_number, cfg)
    except GhNotAvailable as e:
        typer.secho(str(e), fg=typer.colors.RED)
        raise typer.Exit(2)
    manifest, path = pipeline.run_extract(repo=r, pr_number=n, diff_text=diff_text, out_root=out, **meta)
    s = manifest.stats
    typer.echo(f"Manifest: {path}")
    typer.echo(f"  {s.get('files', 0)} files, +{s.get('additions', 0)}/-{s.get('deletions', 0)}, "
               f"{s.get('hunks', 0)} hunks" + ("  (oversize)" if manifest.oversize else ""))


@app.command()
def version():
    """Print version."""
    typer.echo(f"pr-review {__version__}")


if __name__ == "__main__":
    app()
