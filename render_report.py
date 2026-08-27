"""`REPORT.md` -> the published report page.

    .venv/bin/python render_report.py REPORT.md /tmp/report.html

The companion of `benchmark/results/comparison.sh`: that regenerates the
scorecard artifact from the stored runs, this regenerates the report artifact
from `REPORT.md`. Both pages are published privately and updated **in place** —
publishing without the existing URL creates a second artifact rather than
updating the first, so the URLs are the load-bearing part and they live in the
project memory, not here, because a URL in a source file goes stale silently.

WHY THIS FILE IS IN VERSION CONTROL. It was not, once. The report page was
published on 2026-08-22 from a renderer in a session scratchpad, that directory
did not outlive the session, and regenerating the page on 2026-08-24 meant
writing this again from the live artifact. A build step for a published artifact
is not scratch work; `comparison.sh` had been treated that way from the start and
this had not.

Deliberately a small hand-rolled converter rather than a dependency: the document
uses a known subset of markdown -- headings, tables, fences, blockquotes, lists
and four inline forms -- and a dependency added to render one file outlives the
file. If `REPORT.md` grows a construct this does not handle, the failure is
visible in the output rather than silent; check the render before publishing.

Two behaviours that are decisions rather than details:

- **Repo-relative links are stripped to plain text** (`relink`). `README.md` and
  the rest are files in the repository, and the artifact sandbox cannot resolve
  them; a dead `<a>` promises navigation the page cannot deliver. The one
  exception is the scorecard, which *is* published, so it becomes a real link.
- **The two blockquotes render as pull-quotes**, because that is what they are --
  the report's aphorisms, not asides.
- **Nothing a reader sees is written here.** The tab title, the eyebrow and the
  <h1> come from `REPORT.md` -- the first two from its front-matter block, the
  third from its own first heading. They were literals in this file until
  2026-08-25, which is a stale-claim defect waiting to happen: the published
  page could contradict the document it was rendered from, and did not have to
  say so. Editing the report's title is now an edit to the report.
"""
import html as H
import re
import sys

INLINE_CODE = re.compile(r'`([^`]+)`')
BOLD = re.compile(r'\*\*([^*]+)\*\*')
ITAL = re.compile(r'(?<![*\w])\*([^*\n]+)\*(?!\*)')
LINK = re.compile(r'\[([^\]]+)\]\(([^)]+)\)')


def inline(t: str) -> str:
    out, spans = [], []
    def stash(m):
        spans.append(f'<code>{H.escape(m.group(1))}</code>')
        return f'\x00{len(spans)-1}\x00'
    t = INLINE_CODE.sub(stash, t)
    t = H.escape(t)
    t = BOLD.sub(r'<strong>\1</strong>', t)
    t = ITAL.sub(r'<em>\1</em>', t)
    t = LINK.sub(lambda m: f'<a href="{H.escape(m.group(2), quote=True)}">{m.group(1)}</a>', t)
    t = t.replace('&amp;mdash;', '&mdash;').replace('&amp;times;', '&times;')
    return re.sub(r'\x00(\d+)\x00', lambda m: spans[int(m.group(1))], t)


def render(md: str) -> str:
    lines = md.split('\n')
    out, i = [], 0
    while i < len(lines):
        ln = lines[i]

        if ln.startswith('```'):
            lang = ln[3:].strip()
            body, i = [], i + 1
            while i < len(lines) and not lines[i].startswith('```'):
                body.append(lines[i]); i += 1
            i += 1
            src = '\n'.join(body)
            if lang == 'mermaid':
                out.append(f'<div class="fig"><pre class="mermaid">{H.escape(src)}</pre></div>')
            else:
                out.append(f'<div class="scroll"><pre><code>{H.escape(src)}</code></pre></div>')
            continue

        if re.match(r'^\|.*\|\s*$', ln) and i + 1 < len(lines) and re.match(r'^\|[\s:|-]+\|\s*$', lines[i+1]):
            def cells(r): return [c.strip() for c in r.strip().strip('|').split('|')]
            head = cells(ln); i += 2
            rows = []
            while i < len(lines) and re.match(r'^\|.*\|\s*$', lines[i]):
                rows.append(cells(lines[i])); i += 1
            t = ['<div class="scroll"><table><thead><tr>']
            t += [f'<th>{inline(c)}</th>' for c in head]
            t.append('</tr></thead><tbody>')
            for r in rows:
                t.append('<tr>' + ''.join(
                    f'<td>{inline(c)}</td>' for c in r) + '</tr>')
            t.append('</tbody></table></div>')
            out.append(''.join(t)); continue

        if ln.startswith('> '):
            body = []
            while i < len(lines) and (lines[i].startswith('> ') or lines[i] == '>'):
                body.append(lines[i][2:] if lines[i].startswith('> ') else ''); i += 1
            inner = render('\n'.join(body))
            # A dated correction is the document's spine; give it its own voice.
            cls = 'note correction' if re.search(
                r'corrected|superseded|did not survive|until 2026|no longer|answered',
                ' '.join(body), re.I) else 'note'
            out.append(f'<blockquote class="{cls}">{inner}</blockquote>'); continue

        m = re.match(r'^(#{1,4}) (.*)$', ln)
        if m:
            lvl, txt = len(m.group(1)), m.group(2)
            num = re.match(r'^(\d+(?:\.\d+)*)\.?\s+(.*)$', txt)
            if num and lvl in (2, 3, 4):
                out.append(f'<h{lvl}><span class="secno">{num.group(1)}</span>'
                           f'{inline(num.group(2))}</h{lvl}>')
            else:
                out.append(f'<h{lvl}>{inline(txt)}</h{lvl}>')
            i += 1; continue

        if re.match(r'^---+\s*$', ln):
            out.append('<hr>'); i += 1; continue

        m = re.match(r'^(\s*)([-*]|\d+\.) +(.*)$', ln)
        if m:
            ordered = not m.group(2) in ('-', '*')
            tag = 'ol' if ordered else 'ul'
            items, cur = [], None
            while i < len(lines):
                mm = re.match(r'^(\s*)([-*]|\d+\.) +(.*)$', lines[i])
                if mm and len(mm.group(1)) == 0:
                    if cur is not None: items.append(cur)
                    cur = [mm.group(3)]; i += 1
                elif cur is not None and lines[i].strip() and lines[i].startswith((' ', '\t')):
                    cur.append(lines[i].strip()); i += 1
                elif cur is not None and lines[i].strip() == '' and i + 1 < len(lines) \
                        and re.match(r'^(\s*)([-*]|\d+\.) +', lines[i+1]):
                    i += 1
                else:
                    break
            if cur is not None: items.append(cur)
            out.append(f'<{tag}>' + ''.join(
                f'<li>{inline(" ".join(it))}</li>' for it in items) + f'</{tag}>')
            continue

        if ln.strip() == '':
            i += 1; continue

        para = []
        while i < len(lines) and lines[i].strip() and not re.match(
                r'^(#{1,4} |> |```|\||---+\s*$|\s*([-*]|\d+\.) )', lines[i]):
            para.append(lines[i]); i += 1
        if para:
            out.append(f'<p>{inline(" ".join(para))}</p>')
    return '\n'.join(out)


CSS = """
:root{
  --paper:#fbfcfd; --raise:#f2f5f8; --ink:#131820; --muted:#5a6675;
  --rule:#dde3ea; --rule-firm:#c3ccd8; --accent:#3a4fb8;
  
}
@media (prefers-color-scheme:dark){
  :root:not([data-theme="light"]){
    --paper:#0f1216; --raise:#171c23; --ink:#dfe4ea; --muted:#97a2b0;
    --rule:#262d36; --rule-firm:#3a4552; --accent:#8b9cf0;
    
  }
}
:root[data-theme="dark"]{
  --paper:#0f1216; --raise:#171c23; --ink:#dfe4ea; --muted:#97a2b0;
  --rule:#262d36; --rule-firm:#3a4552; --accent:#8b9cf0;
  
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{
  margin:0; padding:clamp(2.5rem,6vw,5rem) 1.25rem 7rem;
  background:var(--paper); color:var(--ink);
  font:400 18px/1.68 "Newsreader",Georgia,"Times New Roman",serif;
  font-feature-settings:"kern";
}
main{max-width:42rem;margin:0 auto;display:flex;flex-direction:column;gap:0}
h1{font:400 clamp(2.1rem,5vw,3.1rem)/1.1 "Newsreader",Georgia,serif;
   letter-spacing:-.018em;text-wrap:balance;margin:0 0 .75rem}
h2{font:600 1.5rem/1.28 "Newsreader",Georgia,serif;letter-spacing:-.008em;
   text-wrap:balance;margin:3.75rem 0 1.1rem;padding-bottom:.5rem;
   border-bottom:1px solid var(--rule-firm);display:flex;gap:.7rem;align-items:baseline}
h3{font:600 1.14rem/1.35 "Newsreader",Georgia,serif;text-wrap:balance;
   margin:2.5rem 0 .7rem;display:flex;gap:.6rem;align-items:baseline}
h4{font:600 .78rem/1.4 "IBM Plex Sans",system-ui,sans-serif;text-transform:uppercase;
   letter-spacing:.08em;color:var(--muted);margin:2rem 0 .5rem}
.secno{font:500 .72em/1 "IBM Plex Mono",ui-monospace,Menlo,monospace;
       color:var(--accent);font-variant-numeric:tabular-nums;flex:none}
p{margin:0 0 1.15rem;max-width:66ch}
p:last-child{margin-bottom:0}
ul,ol{max-width:66ch;padding-left:1.35rem;margin:0 0 1.15rem;
      display:flex;flex-direction:column;gap:.6rem}
li::marker{color:var(--muted)}
ol li::marker{font:500 .85em "IBM Plex Mono",ui-monospace,monospace;
              font-variant-numeric:tabular-nums}
strong{font-weight:600}
em{font-style:italic}
a{color:var(--accent);text-decoration:none;border-bottom:1px solid transparent;
  transition:border-color .12s}
a:hover{border-bottom-color:var(--accent)}
a:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:2px}
code{font:500 .82em/1.5 "IBM Plex Mono",ui-monospace,SFMono-Regular,Menlo,monospace;
     color:var(--accent);font-variant-numeric:tabular-nums;
     background:var(--raise);padding:.08em .32em;border-radius:3px}
pre{margin:0;background:var(--raise);border:1px solid var(--rule);border-radius:4px;
    padding:1rem 1.15rem;overflow-x:auto}
pre code{background:none;padding:0;color:var(--ink);font-size:.8rem;line-height:1.6}
.scroll{overflow-x:auto;margin:1.4rem 0;max-width:100%}
.fig{margin:1.75rem 0;padding:1.25rem;background:var(--raise);
     border:1px solid var(--rule);border-radius:4px;overflow-x:auto}
.fig .mermaid{background:none;border:0;padding:0}
table{border-collapse:collapse;width:100%;font:400 .84rem/1.45 "IBM Plex Sans",system-ui,sans-serif;
      font-variant-numeric:tabular-nums}
th,td{text-align:left;padding:.6rem .75rem;vertical-align:top;
      border-bottom:1px solid var(--rule)}
thead th{font:600 .67rem/1.35 "IBM Plex Sans",system-ui,sans-serif;text-transform:uppercase;
         letter-spacing:.075em;color:var(--muted);border-bottom:1px solid var(--rule-firm);
         white-space:nowrap}
tbody tr:last-child td{border-bottom:0}
td code{font-size:.88em;background:none;padding:0}
blockquote{margin:2.25rem 0;padding:0 0 0 1.35rem;max-width:60ch;
           border-left:2px solid var(--accent);color:var(--ink);
           font:400 1.14rem/1.5 "Newsreader",Georgia,serif;font-style:italic}
blockquote p{margin-bottom:.6rem}
blockquote p:last-child{margin-bottom:0}
blockquote strong{font-weight:600;font-style:normal}
blockquote code{font-style:normal}
hr{border:0;border-top:1px solid var(--rule);margin:3rem 0 0}
.eyebrow{font:500 .74rem/1.4 "IBM Plex Sans",system-ui,sans-serif;text-transform:uppercase;
         letter-spacing:.11em;color:var(--muted);margin:0 0 1rem}
.standfirst{font-size:1.06rem;color:var(--muted);max-width:64ch;margin:0 0 2.5rem}
.standfirst strong{color:var(--ink);font-weight:600}
@media (prefers-reduced-motion:reduce){*{transition:none!important;animation:none!important}}
@media (max-width:34rem){body{font-size:17px}}
"""


SCORECARD = "https://claude.ai/code/artifact/8a3ac770-7b75-408e-aa66-7da088681fce"
# This page's own published location -- the ledger key, because the local
# output path is scratch and the published page is what goes stale.
PUBLISHED = "https://claude.ai/code/artifact/5a173399-6cfc-4605-950e-4de9ba15b46d"


def relink(page: str) -> str:
    """Repo-relative links do not resolve inside an artifact.

    The companion scorecard IS published, so that one becomes a real link to it.
    The rest are files in the repository: rendering them as dead <a> tags would
    promise navigation the page cannot deliver, so they become plain code spans.
    """
    page = page.replace(f'<a href="benchmark/results/comparison.html">',
                        f'<a href="{SCORECARD}">')
    return re.sub(r'<a href="(?!https?:)[^"]*">(.*?)</a>', r'\1', page, flags=re.S)


def front_matter(lines: list[str]) -> tuple[dict[str, str], int]:
    """Parse the `---` block `REPORT.md` opens with; return it and where the
    document proper starts.

    Deliberately not YAML, and deliberately not optional.

    Not YAML because two flat string fields do not justify a dependency, and a
    parser that accepts only `key: value` cannot quietly mis-read something more
    elaborate that someone assumed would work.

    Not optional because the obvious fallback -- keep the old hardcoded title
    when the block is absent -- reproduces the defect this replaces. The page
    would still render, it would render with a title nobody chose, and nothing
    would say so. Missing front matter is a build failure.
    """
    if not lines or lines[0].strip() != '---':
        raise SystemExit("REPORT.md must open with a '---' front-matter block "
                         "carrying title: and eyebrow:.")
    end = next((i for i, l in enumerate(lines[1:], 1) if l.strip() == '---'), None)
    if end is None:
        raise SystemExit("REPORT.md's front-matter block has no closing '---'.")
    fields: dict[str, str] = {}
    for line in lines[1:end]:
        if not line.strip():
            continue
        key, sep, value = line.partition(':')
        if not sep or not key.strip() or not value.strip():
            raise SystemExit(f"front matter is one 'key: value' per line, not: {line!r}")
        fields[key.strip()] = value.strip()
    missing = {'title', 'eyebrow'} - set(fields)
    if missing:
        raise SystemExit(f"REPORT.md front matter is missing: {', '.join(sorted(missing))}")
    return fields, end + 1


def main(src: str, dst: str) -> None:
    md = open(src).read()
    lines = md.split('\n')
    fields, start = front_matter(lines)
    # The page's <h1> is the document's own first heading, not a copy of it.
    # It was a literal in this file until 2026-08-25, which meant the report's
    # title lived in two places and the published page was free to disagree
    # with the document it was built from.
    heading = next(i for i, l in enumerate(lines[start:], start) if l.startswith('# '))
    body_start = next(i for i, l in enumerate(lines[heading + 1:], heading + 1)
                      if l.startswith('---'))
    standfirst = relink(render('\n'.join(lines[heading + 1:body_start])))
    body = relink(render('\n'.join(lines[body_start + 1:])))
    page = f"""<title>{H.escape(fields['title'])}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Newsreader:ital,opsz,wght@0,6..72,400;0,6..72,600;1,6..72,400;1,6..72,600&family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500&display=swap">
<style>{CSS}</style>
<main>
<p class="eyebrow">{inline(fields['eyebrow'])}</p>
<h1>{inline(lines[heading][2:].strip())}</h1>
<div class="standfirst">{standfirst}</div>
{body}
</main>
"""
    # Before writing: the drift being reported is what the published page looked
    # like a moment ago, not what this render produces.
    from pr_review.benchmark import rendered
    warning = rendered.check(PUBLISHED)

    data = page.encode('utf-8')
    open(dst, 'wb').write(data)
    print(f"wrote {dst} ({len(data):,} bytes)")

    # Recorded against the artifact URL rather than `dst`: the output path is a
    # scratch file that varies per invocation, while the thing that can go stale
    # is the published page. Sources are the document and this renderer -- a
    # change to either one changes what a reader sees (OPEN_ITEMS.md §24).
    rendered.record(PUBLISHED, [src, rendered.repo_relative(__file__)])
    if warning:
        print(warning)


if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
