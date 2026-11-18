"""Per-repository audit report: the security documentation an auditor would read.

Rendered in the terminal (rich) or exported as SVG / Markdown. The analyzer service builds AuditData from
a scan (app/services/report/audit_data.py); the benchmark builds it for one snapshot with the known
vulnerability overlaid (bench/audit.py). Rendering never calls an API.
"""

from __future__ import annotations

import io as _io
import textwrap
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from rich import box
from rich.console import Console, Group
from rich.padding import Padding
from rich.panel import Panel
from rich.rule import Rule
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

CONFIG_PREFERENCE = ["S+T+D", "S+T", "S+D", "L"]
CONFIG_LABEL = {
    "S": "SAST only (tool agreement → severity)",
    "S+T": "SAST + LLM triage",
    "S+D": "SAST ∪ LLM discovery (rank fusion)",
    "S+T+D": "full pipeline: triaged SAST ∪ hybrid LLM discovery",
    "L": "LLM discovery only",
}
SEV_STYLE = {"critical": "bold white on red", "high": "bold red", "medium": "yellow", "low": "cyan", None: "dim"}
CWE_NAMES = {
    "CWE-22": "Path traversal", "CWE-78": "OS command injection", "CWE-79": "Cross-site scripting",
    "CWE-89": "SQL injection", "CWE-94": "Code injection", "CWE-95": "Eval injection",
    "CWE-502": "Unsafe deserialization", "CWE-611": "XXE", "CWE-918": "SSRF", "CWE-352": "CSRF",
    "CWE-287": "Improper authentication", "CWE-862": "Missing authorization", "CWE-863": "Incorrect authorization",
    "CWE-1321": "Prototype pollution", "CWE-1333": "ReDoS", "CWE-601": "Open redirect", "CWE-20": "Input validation",
    "CWE-915": "Mass assignment", "CWE-400": "Resource exhaustion", "CWE-1007": "Homoglyphs",
}


@dataclass
class AuditData:
    """Everything the renderers need. `item` holds at least name/id, language and loc; benchmark items also
    carry repo_url, cve/ghsa, cwe and fix_commit (used only when the ground truth is revealed)."""

    item: dict
    side: str
    model: str | None
    config: str
    ranked: list[dict]
    root: Path
    commit: str | None = None
    removed: list[dict] = field(default_factory=list)
    context: dict = field(default_factory=dict)
    entry_kinds: Counter = field(default_factory=Counter)
    sink_cwes: Counter = field(default_factory=Counter)
    sast: dict = field(default_factory=dict)
    idx: Any = None                                   # app.context.index.SnapshotIndex, if built
    # benchmark mode only
    gt_ranks: dict = field(default_factory=dict)
    gt_locations: list = field(default_factory=list)
    gt_hit: Callable[[dict], bool] | None = None

    @property
    def repo_name(self) -> str:
        url = self.item.get("repo_url") or ""
        return url.split("github.com/")[-1] if url else (self.item.get("name") or self.item.get("id") or "repository")


def _is_gt_hit(data: AuditData, e: dict) -> bool:
    return bool(data.gt_hit and data.gt_hit(e))


def _source(e: dict) -> str:
    tools = e.get("tools") or []
    parts = list(tools)
    if e.get("llm") or "llm" in e.get("origin", ""):
        parts.append("LLM")
    return ", ".join(parts) or e.get("origin", "")


def _title(e: dict) -> str:
    if e.get("llm") and e["llm"].get("title"):
        return e["llm"]["title"]
    cwe = (e.get("cwe") or [None])[0]
    msg = (e.get("message") or "").strip().split("\n")[0]
    return msg[:110] if msg else CWE_NAMES.get(cwe, cwe or "finding")


def _explanation(e: dict) -> tuple[str | None, list[str], list[str], str | None]:
    """(explanation, source→sink chain, sanitizers, preconditions)."""
    if e.get("triage"):
        t = e["triage"]
        chain = [x for x in (t.get("source"), t.get("sink")) if x]
        return t.get("explanation"), chain, t.get("sanitizers") or [], t.get("preconditions")
    if e.get("llm"):
        ll = e["llm"]
        return ll.get("explanation"), ll.get("source_to_sink") or [], [], ll.get("exploit_sketch")
    return None, [], [], None


def _confidence(e: dict) -> float | None:
    if e.get("triage"):
        return e["triage"].get("confidence")
    if e.get("llm"):
        return e["llm"].get("confidence")
    return None


def _function(data: AuditData, e: dict) -> str | None:
    if e.get("llm") and e["llm"].get("function"):
        return e["llm"]["function"]
    fn = data.idx.function_at(e["file"], e["start_line"]) if data.idx is not None else None
    return fn.name if fn else None


# ----------------------------------------------------------------------------- rich rendering


def _verdict_text(e: dict) -> Text:
    v = e.get("verdict") or (e.get("triage") or {}).get("verdict")
    conf = _confidence(e)
    c = f" {conf:.2f}" if conf is not None else ""
    if v == "true_positive":
        return Text(f"✔ real{c}", style="bold green")
    if v == "uncertain":
        return Text(f"? unsure{c}", style="yellow")
    if e.get("llm"):
        return Text(f"◆ LLM{c}", style="magenta")
    return Text("· unreviewed", style="dim")


def _bar(value: float, width: int = 10) -> Text:
    n = max(0, min(width, round(value * width)))
    return Text("█" * n + "░" * (width - n), style="red" if value >= 0.75 else "yellow" if value >= 0.5 else "cyan")


def _header(data: AuditData, width: int = 120) -> Panel:
    it = data.item
    repo = data.repo_name
    tools = "  ".join(f"[green]✓[/] {t} [dim]{v.get('findings', 0)}[/]" if v["ok"] else f"[red]✗[/] {t}"
                      for t, v in sorted(data.sast.items()))
    cfg_base = data.config.split("@")[0]
    rows = [("Repository", f"[bold]{repo}[/]"), ("Language", it["language"]),
            ("Snapshot", f"{data.side} @ {data.commit[:10]}" if data.commit else data.side),
            ("Size", f"{it.get('loc') or 0:,} LOC"),
            ("Code index", f"{data.context.get('files', '?')} files · {data.context.get('functions', '?')} functions"),
            ("Attack surface", f"{data.context.get('entrypoints', '?')} entry points · {data.context.get('sinks', '?')} sinks"),
            ("SAST", tools or "–"), ("LLM", data.model or "[dim]none[/]")]
    g = Table.grid(padding=(0, 2))
    if width >= 110:
        for _ in range(2):
            g.add_column(style="bold cyan", justify="right")
            g.add_column()
        for i in range(0, len(rows), 2):
            g.add_row(*rows[i], *rows[i + 1])
        g.add_row("Ranking", f"{cfg_base} — {CONFIG_LABEL.get(cfg_base, '')}", "", "")
    else:
        g.add_column(style="bold cyan", justify="right")
        g.add_column()
        for r in rows + [("Ranking", f"{cfg_base} — {CONFIG_LABEL.get(cfg_base, '')}")]:
            g.add_row(*r)
    return Panel(g, title=f"[bold white]Security audit · {repo}[/]", subtitle="repo-analyzer · secaudit",
                 border_style="bright_blue", box=box.ROUNDED, padding=(1, 2))


def _surface(data: AuditData) -> Table:
    t = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold", expand=True, title="Attack surface",
              title_style="bold", title_justify="left")
    t.add_column("Entry points", ratio=1)
    t.add_column("Dangerous sinks (by CWE)", ratio=2)
    eps = "\n".join(f"{k} · {v}" for k, v in data.entry_kinds.most_common(6)) or "–"
    sinks = "\n".join(f"{c:<9} {CWE_NAMES.get(c, ''):<26} {n:>4}" for c, n in data.sink_cwes.most_common(6)) or "–"
    t.add_row(eps, sinks)
    return t


def _findings_table(data: AuditData, top: int, reveal: bool, width: int = 120) -> Table:
    narrow = width < 110
    t = Table(box=box.ROUNDED, header_style="bold white on grey23", expand=True, title=f"Top {top} findings",
              title_style="bold", title_justify="left", row_styles=["", "on grey11"])
    t.add_column("#", justify="right", width=3)
    t.add_column("CWE", width=9, no_wrap=True)
    t.add_column("Location", ratio=3, min_width=16, overflow="fold")
    t.add_column("Finding", ratio=4, overflow="ellipsis", no_wrap=True)
    if not narrow:
        t.add_column("Source", ratio=2, overflow="fold")
    t.add_column("Verdict", width=13, no_wrap=True)
    if reveal:
        t.add_column("GT", width=3, justify="center")
    for i, e in enumerate(data.ranked[:top], start=1):
        cwe = (e.get("cwe") or ["?"])[0]
        sev = e.get("severity")
        row = [str(i), Text(cwe, style=SEV_STYLE.get(sev, "bold") if sev else "bold"),
               f"[bold]{e['file']}[/]:{e['start_line']}", _title(e)]
        if not narrow:
            row.append(_source(e))
        row.append(_verdict_text(e))
        if reveal:
            row.append(Text("★", style="bold yellow") if _is_gt_hit(data, e) else Text(""))
        t.add_row(*row)
    return t


def _snippet(data: AuditData, e: dict, context: int = 4) -> Syntax | None:
    path = data.root / e["file"]
    if not path.exists():
        return None
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    # long ranges (LLM often reports a whole function): highlight the first line, show a window
    hl_end = e["end_line"] if e["end_line"] - e["start_line"] <= 6 else e["start_line"]
    start = max(1, e["start_line"] - context)
    end = min(len(lines), hl_end + context + (6 if hl_end != e["end_line"] else 0))
    code = "\n".join(lines[start - 1:end])
    lexer = "python" if e["file"].endswith(".py") else ("typescript" if e["file"].endswith((".ts", ".tsx")) else "javascript")
    return Syntax(code, lexer, line_numbers=True, start_line=start, theme="monokai", word_wrap=True,
                  highlight_lines=set(range(e["start_line"], hl_end + 1)))


def _detail(data: AuditData, rank: int, e: dict, reveal: bool) -> Panel:
    expl, chain, sanitizers, pre = _explanation(e)
    parts = []
    meta = Text()
    cwe = (e.get("cwe") or ["?"])[0]
    meta.append(f"{cwe} {CWE_NAMES.get(cwe, '')}", style="bold")
    meta.append(f"   {e['file']}:{e['start_line']}", style="cyan")
    fn = _function(data, e)
    if fn:
        meta.append(f"  in {fn}()", style="dim")
    meta.append(f"   via {_source(e)}", style="dim")
    conf = _confidence(e)
    if conf is not None:
        meta.append("   confidence ")
        meta.append_text(_bar(conf))
    parts.append(meta)
    if expl:
        parts.append(Padding(Text(expl.strip()), (1, 0, 0, 0)))
    if chain:
        parts.append(Text("Flow: ", style="bold").append(" → ".join(c.strip() for c in chain), style="italic"))
    if sanitizers:
        parts.append(Text("Checks on the path: ", style="bold").append("; ".join(sanitizers)[:300]))
    if pre:
        parts.append(Text("Attacker needs / exploit idea: ", style="bold").append(pre[:300]))
    if not expl and e.get("rule_ids"):
        parts.append(Text("Rules: " + ", ".join(e["rule_ids"][:4]), style="dim"))
    snip = _snippet(data, e)
    if snip is not None:
        parts.append(Padding(snip, (1, 0, 0, 0)))
    star = "  [bold yellow]★ matches the known vulnerability[/]" if reveal and _is_gt_hit(data, e) else ""
    return Panel(Group(*parts), title=f"[bold]#{rank} · {_title(e)[:90]}[/]{star}", title_align="left",
                 border_style="red" if (e.get("verdict") == "true_positive" or (conf or 0) >= 0.75) else "yellow",
                 box=box.ROUNDED, padding=(0, 1))


def _removed_table(data: AuditData, n: int = 6) -> Table | None:
    if not data.removed:
        return None
    t = Table(box=box.SIMPLE, expand=True, title=f"Filtered out by LLM triage ({len(data.removed)} false positives)",
              title_style="bold", title_justify="left", header_style="dim")
    t.add_column("Location", ratio=2, overflow="fold")
    t.add_column("Tool", ratio=1)
    t.add_column("Why it is not exploitable", ratio=5)
    for r in data.removed[:n]:
        reason = (r["result"].get("explanation") or "").split(". ")[0]
        t.add_row(f"{r['file']}:{r['start_line']}", ", ".join(r["tools"]), Text(reason[:180], style="dim"))
    return t


def _gt_panel(data: AuditData) -> Panel:
    it = data.item
    g = Table.grid(padding=(0, 2))
    g.add_column(style="bold")
    g.add_column()
    g.add_row("Known vulnerability", f"{it.get('cve') or it.get('ghsa') or '-'} · {', '.join(it['cwe'][:3])}")
    locs = [f"{x.file}:{x.start}-{x.end} ({x.kind})" for x in data.gt_locations[:4]]
    g.add_row("Fixed at", "\n".join(locs) or "-")
    ranks = Table(box=box.MINIMAL, show_header=True, header_style="bold")
    ranks.add_column("Configuration")
    ranks.add_column("First hit (rank)", justify="right")
    for key in sorted(data.gt_ranks, key=lambda k: (k != "S", k)):
        r = data.gt_ranks[key]
        ranks.add_row(f"{key.split('@')[0]:<6} {CONFIG_LABEL.get(key.split('@')[0], '')}",
                      Text(str(r), style="bold green" if r and r <= 5 else "yellow") if r else Text("miss", style="red"))
    return Panel(Group(g, Padding(ranks, (1, 0, 0, 0))), title="[bold yellow]Ground truth (benchmark mode)[/]",
                 border_style="yellow", box=box.ROUNDED)


def render(data: AuditData, console: Console, top: int = 10, details: int = 3, reveal: bool = False) -> None:
    console.print(_header(data, console.width))
    if data.context:
        console.print(_surface(data))
    if not data.ranked:
        console.print(Panel("No findings.", border_style="green"))
    else:
        console.print(_findings_table(data, top, reveal, console.width))
        console.print(Rule("[bold]Details[/]", style="grey50"))
        for i, e in enumerate(data.ranked[:details], start=1):
            console.print(_detail(data, i, e, reveal))
    rem = _removed_table(data)
    if rem is not None:
        console.print(rem)
    if reveal:
        console.print(_gt_panel(data))


def render_to_svg(data: AuditData, path: Path, width: int = 120, **kw) -> None:
    console = Console(record=True, width=width, file=_io.StringIO(), force_terminal=True, color_system="truecolor")
    render(data, console, **kw)
    path.parent.mkdir(parents=True, exist_ok=True)
    console.save_svg(str(path), title=f"audit · {data.repo_name}")


# ----------------------------------------------------------------------------- markdown


def cwe_link(cwe: str | None) -> str:
    if not cwe or not cwe.startswith("CWE-") or not cwe[4:].isdigit():
        return cwe or "?"
    return f"[{cwe}](https://cwe.mitre.org/data/definitions/{cwe[4:]}.html)"


def advisory_link(item: dict) -> str:
    if item.get("cve"):
        return f"[{item['cve']}](https://nvd.nist.gov/vuln/detail/{item['cve']})"
    if item.get("ghsa"):
        return f"[{item['ghsa']}](https://github.com/advisories/{item['ghsa']})"
    return "-"


def render_markdown(data: AuditData, top: int = 10, details: int = 5, reveal: bool = False) -> str:
    it = data.item
    repo_url = it.get("repo_url")
    repo = data.repo_name
    linked = bool(repo_url and data.commit)
    blob = f"{repo_url}/blob/{data.commit}" if linked else ""

    def loc(file: str, line: int, end: int | None = None) -> str:
        if not linked:
            return f"`{file}:{line}`"
        anchor = f"#L{line}" + (f"-L{end}" if end and end != line else "")
        return f"[`{file}:{line}`]({blob}/{file}{anchor})"

    cfg_base = data.config.split("@")[0]
    sast = ", ".join(f"{t} ({v.get('findings', 0)})" for t, v in sorted(data.sast.items()) if v["ok"])
    snapshot = (f"`{data.side}` @ [`{data.commit[:10]}`]({repo_url}/tree/{data.commit})" if linked
                else f"`{data.side}`" + (f" @ `{data.commit[:10]}`" if data.commit else ""))
    L = [f"# Security audit: [{repo}]({repo_url})" if repo_url else f"# Security audit: {repo}", "",
         f"> Generated by repo-analyzer (secaudit) from {cfg_base} ({CONFIG_LABEL.get(cfg_base, '')}). "
         "Findings are ranked; verdicts and explanations come from the LLM, locations from SAST and the LLM. "
         + ("Locations link to the analyzed commit." if linked else ""), "",
         "| | |", "|---|---|",
         f"| Snapshot | {snapshot} |",
         f"| Language / size | {it['language']} / {it.get('loc') or 0:,} LOC |",
         f"| Code index | {data.context.get('files', '?')} files, {data.context.get('functions', '?')} functions |",
         f"| Attack surface | {data.context.get('entrypoints', '?')} entry points, {data.context.get('sinks', '?')} dangerous sinks |",
         f"| SAST | {sast} |",
         f"| LLM | {data.model or '–'} |", ""]
    L += ["## Findings", "", "| # | CWE | Location | Finding | Source | Verdict |" + (" GT |" if reveal else ""),
          "|---|---|---|---|---|---|" + ("---|" if reveal else "")]
    for i, e in enumerate(data.ranked[:top], start=1):
        v = e.get("verdict") or ""
        conf = _confidence(e)
        verdict = {"true_positive": "✔ real", "uncertain": "? unsure"}.get(v, "◆ LLM" if e.get("llm") else "· unreviewed")
        if conf is not None:
            verdict += f" ({conf:.2f})"
        L.append(f"| {i} | {cwe_link((e.get('cwe') or ['?'])[0])} | {loc(e['file'], e['start_line'])} | "
                 f"{_title(e).replace('|', '/')[:90]} | {_source(e)} | {verdict} |"
                 + (f" {'★' if _is_gt_hit(data, e) else ''} |" if reveal else ""))
    L.append("")
    for i, e in enumerate(data.ranked[:details], start=1):
        expl, chain, sanitizers, pre = _explanation(e)
        cwe = (e.get("cwe") or ["?"])[0]
        L += [f"### {i}. {_title(e)}", "",
              f"**{cwe_link(cwe)} {CWE_NAMES.get(cwe, '')}** · {loc(e['file'], e['start_line'], e['end_line'])} "
              f"· via {_source(e)}", ""]
        if expl:
            L += [textwrap.fill(expl.strip(), 110), ""]
        if chain:
            L += ["**Flow:** " + " → ".join(chain), ""]
        if sanitizers:
            L += ["**Checks on the path:** " + "; ".join(sanitizers), ""]
        if pre:
            L += ["**Attacker needs / exploit idea:** " + pre, ""]
        path = data.root / e["file"]
        if path.exists():
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            s, t = max(1, e["start_line"] - 3), min(len(lines), min(e["end_line"], e["start_line"] + 8) + 3)
            lang = "python" if e["file"].endswith(".py") else "js"
            body = "\n".join(f"{'>' if e['start_line'] <= n <= e['end_line'] else ' '}{n:4d}  {lines[n - 1]}"
                             for n in range(s, t + 1))
            L += [f"```{lang}", body, "```", ""]
    if data.removed:
        L += [f"## Filtered out by triage ({len(data.removed)})", "", "| Location | Tool | Reason |", "|---|---|---|"]
        for r in data.removed[:10]:
            reason = (r["result"].get("explanation") or "").split(". ")[0].replace("|", "/")
            L.append(f"| {loc(r['file'], r['start_line'])} | {', '.join(r['tools'])} | {reason[:200]} |")
        L.append("")
    if reveal:
        fix = f"{repo_url}/commit/{it['fix_commit']}"
        L += ["## Ground truth (benchmark mode)", "",
              f"Known vulnerability: **{advisory_link(it)}** ({', '.join(cwe_link(c) for c in it['cwe'][:3])}), "
              f"fixed in [`{it['fix_commit'][:10]}`]({fix}).", "",
              "| Configuration | First hit rank |", "|---|---|"]
        for key in sorted(data.gt_ranks, key=lambda k: (k != "S", k)):
            L.append(f"| {key.split('@')[0]} | {data.gt_ranks[key] or 'miss'} |")
        L.append("")
    return "\n".join(L)
