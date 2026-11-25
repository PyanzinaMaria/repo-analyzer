"""Visualizations of LLM-flow results: rich terminal views (+ SVG via rich's recorder) and Mermaid export.

Both read the same `Flow` / `CallSite` objects, so the terminal and the docs show the same paths.
"""

from __future__ import annotations

import io as _io
import re
from pathlib import Path

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from app.llmflow.models import CallSite, Flow, Hop
from app.llmflow.pipeline import Result

ROLE_ICON = {"source": "🌐", "prompt": "💬", "llm": "🤖", "wrapper": "↩", "call": "⇢", "tool": "🛠", "sink": "💥"}
ROLE_STYLE = {"source": "bold cyan", "prompt": "cyan", "llm": "bold magenta", "wrapper": "magenta",
              "call": "white", "tool": "bold yellow", "sink": "bold red"}
SINK_ICON = {"shell": "🐚", "code_eval": "🧨", "sql": "🗄", "deserialize": "📦", "file_write": "📁",
             "http": "🌍", "html": "🖼", "text": "📝"}


def _prio_style(p: float, gated: bool) -> str:
    if gated:
        return "green"
    return "bold red" if p >= 0.45 else "dark_orange" if p >= 0.25 else "yellow" if p >= 0.1 else "green"


def bar(value: float, width: int = 10, style: str = "white") -> Text:
    full = round(max(0.0, min(1.0, value)) * width)
    t = Text("█" * full, style=style)
    t.append("░" * (width - full), style="grey30")
    return t


def _loc(h: Hop) -> str:
    return f"{h.file}:{h.line}"


# --------------------------------------------------------------------------- terminal


def summary_panel(res: Result) -> Panel:
    s = res.summary()
    g = Table.grid(padding=(0, 3))
    for _ in range(4):
        g.add_column()
    ungated = s["flows"] - s["gated"]
    g.add_row(Text.assemble(("🔌 call sites  ", "dim"), (str(s["callsites"]), "bold")),
              Text.assemble(("🤖 models  ", "dim"), (", ".join(s["models"]) or "—", "bold magenta")),
              Text.assemble(("🛠 tools  ", "dim"), (str(s["tools"]), "bold yellow")),
              Text.assemble(("🌐 exposed prompts  ", "dim"), (str(s["exposed_callsites"]), "bold cyan")))
    by = "  ".join(f"{SINK_ICON.get(k, '•')} {k} {v}" for k, v in sorted(s["flows_by_sink"].items(),
                                                                          key=lambda kv: -kv[1])) or "—"
    g.add_row(Text.assemble(("💥 flows  ", "dim"), (str(s["flows"]), "bold red")),
              Text.assemble(("ungated ", "dim"), (str(ungated), "bold red"), ("  gated ", "dim"),
                            (str(s["gated"]), "bold green")),
              Text(by),
              Text.assemble(("🧹 hygiene  ", "dim"), (str(s["hygiene"]), "bold")))
    passes = " → ".join(f"p{p['n']}:{p['matches']}" for p in s["passes"])
    foot = Text(f"{s['files']} files · {s['functions']} functions · semgrep passes {passes} · "
                f"wrappers {len(s['wrappers'])} · {s['seconds']}s", style="dim")
    return Panel(Group(g, foot), title=f"[bold]LLM attack surface[/] · {res.repo_name}", border_style="magenta",
                 box=box.ROUNDED, padding=(0, 1))


def inventory_tree(callsites: list[CallSite]) -> Tree:
    root = Tree("[bold]🔌 LLM call sites[/]", guide_style="grey50")
    if not callsites:
        root.add("[dim]no call sites of openai / anthropic / ollama found[/]")
    for c in callsites:
        node = root.add(Text.assemble((f"{c.sdk}", "bold magenta"), ("  ", ""), (f"{c.file}:{c.line}", "cyan"),
                                      ("  in ", "dim"), (c.func_name or "<module>", "white"),
                                      (f"  [{c.channel}]", "dim")))
        m = c.model
        how = f"{m.how}" + (f" · {m.detail}" if m.detail else "")
        node.add(Text.assemble(("🤖 ", ""), (m.name or "unknown model", "bold" if m.name else "dim italic"),
                               (f"  ({how})", "dim"),
                               (f"  KB: {m.kb_id}" if m.kb_id else "  KB: —", "green" if m.kb_id else "dim")))
        if c.tools:
            tn = node.add("🛠 [yellow]tools[/]")
            for t in c.tools:
                tn.add(Text.assemble((t.name, "bold yellow"), ("  → ", "dim"),
                                     (f"{t.func_name}({', '.join(t.params)})" if t.func_name else "unbound",
                                      "white" if t.func_name else "dim italic")))
        if c.exposure:
            en = node.add("🌐 [cyan]reached by untrusted input[/]")
            for e in sorted(c.exposure, key=lambda e: -e["E"])[:4]:
                en.add(Text.assemble((e["title"], "cyan"), (f"  E={e['E']}", "bold"), (f"  from {e['source']}",
                                                                                        "dim")))
    return root


def findings_table(flows: list[Flow], top: int) -> Table:
    t = Table(box=box.SIMPLE_HEAVY, header_style="bold", title="[bold]Ranked LLM flows[/]  priority = S·E·R",
              title_justify="left", expand=False)
    t.add_column("#", justify="right", style="dim")
    t.add_column("priority", no_wrap=True)
    t.add_column("S", justify="right")
    t.add_column("E", justify="right")
    t.add_column("R", justify="right")
    t.add_column("source → sink", overflow="fold")
    t.add_column("gate", overflow="fold")
    t.add_column("hops", justify="right", style="dim")
    for f in flows[:top]:
        style = _prio_style(f.priority, f.gated)
        pr = bar(f.priority, 8, style)
        pr.append(f" {f.priority:.2f}", style=style)
        first = f.hops[0]
        src = f.source_title if f.source_kind != "unknown" else "LLM output (provenance unknown)"
        via = f" +{len(f.alt_callsites)} call sites" if f.alt_callsites else ""
        path = Text.assemble((f"{src}", "cyan"), (" → ", "dim"), (f"🤖 {f.model or '?'}{via}", "magenta"),
                             (" → ", "dim"), (f"{SINK_ICON.get(f.sink_class, '')} {f.sink_class}", "bold red"),
                             (f"\n{_loc(first)} → {_loc(f.sink)}", "dim"))
        gate = Text(", ".join(sorted({g.gate for g in f.gates})), style="green") if f.gates else Text("none",
                                                                                                       "red")
        t.add_row(str(f.rank), pr, f"{f.S:.1f}", f"{f.E:.2f}", f"{f.R:.1f}", path, gate,
                  str(len(f.hops)) + (" ≈" if f.approx else ""))
    if len(flows) > top:
        t.caption = f"… {len(flows) - top} more in findings.json"
    return t


def path_panel(f: Flow) -> Panel:
    grid = Table.grid(padding=(0, 1))
    grid.add_column(width=2, no_wrap=True)
    grid.add_column(overflow="fold")
    llm_i = next((i for i, h in enumerate(f.hops) if h.role in ("llm", "tool")), -1)
    shown_gates: set[str] = set()
    if llm_i > 0:
        grid.add_row("", Text("── untrusted input → prompt", style="grey50"))
    for i, h in enumerate(f.hops):
        style = ROLE_STYLE.get(h.role, "white")
        if h.approx:
            style += " dim"
        head = Text.assemble((f"{h.role:<7}", style), (f" {_loc(h)}", "cyan"),
                             (f"  {h.func_name or '<module>'}", "white"), ("  ", ""),
                             (h.label + ("  ≈ approximate (name-based)" if h.approx else ""), style))
        grid.add_row(ROLE_ICON.get(h.role, "•"), head)
        if h.code:
            grid.add_row("", Text(f"  {h.code[:120]}", style="grey62 italic"))
        for g in f.gates:
            key = f"{g.file}:{g.line}"
            if key not in shown_gates and g.func and g.func == h.func and g.line <= h.line \
                    and h.role in ("sink", "call"):
                shown_gates.add(key)
                grid.add_row("🛡", Text.assemble(("gate    ", "bold green"), (f"{g.file}:{g.line}  ", "cyan"),
                                                 (f"{g.title} ({g.kind}, ×{g.factor})", "green")))
        if i == llm_i and i < len(f.hops) - 1:
            grid.add_row("", Text("── LLM output → sink", style="grey50"))
        elif i < len(f.hops) - 1:
            grid.add_row(Text("│", style="grey42"), "")
    style = _prio_style(f.priority, f.gated)
    scores = Text.assemble(("S ", "dim"), bar(f.S, 6, "red"), (f" {f.S:.2f}  ", ""),
                           ("E ", "dim"), bar(f.E, 6, "cyan"), (f" {f.E:.2f}", ""),
                           (f" (base {f.E_base:.2f})  " if f.gated else "  ", "dim"),
                           ("R ", "dim"), bar(f.R, 6, "magenta"), (f" {f.R:.2f}", ""))
    title = Text.assemble((f" {f.id} ", f"reverse {style}"), (f"  {SINK_ICON.get(f.sink_class, '')} "
                                                               f"{f.sink_title} · {f.cwe}", "bold"),
                          (f"  priority {f.priority:.3f}", style),
                          ("  🛡 gated" if f.gated else "  ⚠ no gate", "green" if f.gated else "red"))
    parts = [scores]
    if f.alt_callsites:
        alts = ", ".join(f.alt_callsites[:4]) + (" …" if len(f.alt_callsites) > 4 else "")
        parts.append(Text(f"also via {len(f.alt_callsites)} other LLM call site(s): {alts}", style="magenta dim"))
    return Panel(Group(*parts, Text(""), grid), title=title, title_align="left", border_style=style,
                 box=box.ROUNDED, padding=(0, 1))


def hygiene_table(rows: list[dict], top: int = 12) -> Table:
    t = Table(box=box.SIMPLE, header_style="bold", title="[bold]🧹 LLM hygiene[/]", title_justify="left")
    t.add_column("rule", style="yellow")
    t.add_column("where", style="cyan")
    t.add_column("code", style="grey62", overflow="fold")
    for h in rows[:top]:
        t.add_row(h["rule"], f"{h['file']}:{h['line']}", h["code"][:80])
    if len(rows) > top:
        t.caption = f"… {len(rows) - top} more in hygiene.json"
    return t


def render(res: Result, console: Console, top: int = 15, details: int = 3, hygiene: bool = True) -> None:
    console.print(summary_panel(res))
    console.print(inventory_tree(res.callsites))
    console.print()
    if res.flows:
        console.print(findings_table(res.flows, top))
        for f in res.flows[:details]:
            console.print(path_panel(f))
        gated = [f for f in res.flows[details:] if f.gated]
        if gated and details:
            console.print(Text("first gated flow:", style="dim"))
            console.print(path_panel(gated[0]))
    else:
        console.print("[green]No flow from an LLM call into a dangerous sink was found.[/]")
    if hygiene and res.hygiene:
        console.print(hygiene_table(res.hygiene))
    for e in res.errors[:5]:
        console.print(f"[dim]semgrep: {e}[/]")


def render_to_svg(res: Result, path: Path, width: int = 140, **kw) -> None:
    console = Console(record=True, width=width, file=_io.StringIO(), force_terminal=True, color_system="truecolor")
    render(res, console, **kw)
    path.parent.mkdir(parents=True, exist_ok=True)
    console.save_svg(str(path), title=f"llmflow · {res.repo_name}")


# --------------------------------------------------------------------------- mermaid


def _m(text: str, n: int = 60) -> str:
    """Mermaid-safe label text."""
    text = (text or "").replace("\n", " ").strip()
    if len(text) > n:
        text = text[: n - 1] + "…"
    return (text.replace("&", "#amp;").replace('"', "#quot;").replace("<", "#lt;").replace(">", "#gt;")
            .replace("|", "#124;").replace("`", "'").replace("[", "#91;").replace("]", "#93;")
            .replace("{", "#123;").replace("}", "#125;"))


SHAPES = {"source": ('(["', '"])'), "prompt": ('[/"', '"/]'), "llm": ('{{"', '"}}'), "tool": ('[["', '"]]'),
          "sink": ('[\\"', '"/]'), "wrapper": ('("', '")'), "call": ('["', '"]')}
CLASSDEFS = """    classDef source fill:#083344,stroke:#22d3ee,color:#e0f2fe
    classDef prompt fill:#0c4a6e,stroke:#38bdf8,color:#e0f2fe
    classDef llm fill:#4a044e,stroke:#e879f9,color:#fdf4ff
    classDef wrapper fill:#3b0764,stroke:#c084fc,color:#faf5ff
    classDef call fill:#1f2937,stroke:#9ca3af,color:#f9fafb
    classDef tool fill:#422006,stroke:#facc15,color:#fefce8
    classDef sink fill:#450a0a,stroke:#f87171,color:#fef2f2
    classDef gate fill:#052e16,stroke:#4ade80,color:#f0fdf4"""


def flow_mermaid(f: Flow) -> str:
    lines = ["flowchart LR"]
    ids = []
    for i, h in enumerate(f.hops):
        nid = f"h{i}"
        ids.append(nid)
        o, c = SHAPES.get(h.role, ('["', '"]'))
        icon = ROLE_ICON.get(h.role, "")
        label = f"{icon} {_m(h.label, 48)}<br/><small>{_m(h.func_name or '<module>', 30)} · {_m(_loc(h), 40)}</small>"
        lines.append(f"    {nid}{o}{label}{c}:::{h.role}")
    for i in range(len(ids) - 1):
        arrow = "-.->" if f.hops[i + 1].approx else "-->"
        lines.append(f"    {ids[i]} {arrow} {ids[i + 1]}")
    for j, g in enumerate(f.gates):
        gid = f"g{j}"
        lines.append(f'    {gid}{{{{"🛡 {_m(g.title, 40)}<br/><small>{g.kind} ×{g.factor} · {_m(g.file)}:{g.line}'
                     f'</small>"}}}}:::gate')
        target = next((ids[i] for i, h in reversed(list(enumerate(f.hops))) if h.func == g.func), ids[-1])
        lines.append(f"    {gid} -. guards .-> {target}")
    lines.append(CLASSDEFS)
    return "\n".join(lines)


def surface_mermaid(res: Result, top: int = 25) -> str:
    """Untrusted sources → LLM call sites → sinks; edge labels carry the best priority."""
    lines = ["flowchart LR"]
    cs_ids = {c.id: f"cs{i}" for i, c in enumerate(res.callsites)}
    src_nodes: dict[str, str] = {}
    sink_nodes: dict[str, str] = {}
    edges_in: set[tuple[str, str]] = set()
    edges_out: dict[tuple[str, str, bool], float] = {}
    for f in res.flows[:top]:
        if f.callsite not in cs_ids:
            continue
        sk = f"{f.sink.file}:{f.sink.line}"
        if sk not in sink_nodes:
            sink_nodes[sk] = f"sk{len(sink_nodes)}"
        key = (cs_ids[f.callsite], sink_nodes[sk], f.gated)
        edges_out[key] = max(edges_out.get(key, 0.0), f.priority)
    used_cs = {k[0] for k in edges_out}
    for c in res.callsites:
        for e in c.exposure:
            key = f"{e['kind']}@{e['source']}"
            if key not in src_nodes:
                src_nodes[key] = f"src{len(src_nodes)}"
            edges_in.add((src_nodes[key], cs_ids[c.id]))
            used_cs.add(cs_ids[c.id])
    lines.append('    subgraph S["🌐 untrusted input"]')
    for key, nid in src_nodes.items():
        kind, loc = key.split("@", 1)
        lines.append(f'        {nid}(["{_m(kind)}<br/><small>{_m(loc)}</small>"]):::source')
    lines.append("    end")
    lines.append('    subgraph L["🤖 LLM call sites"]')
    for c in res.callsites:
        if cs_ids[c.id] not in used_cs:
            continue
        tools = f" · 🛠 {len(c.tools)}" if c.tools else ""
        lines.append(f'        {cs_ids[c.id]}{{{{"{_m(c.sdk)} · {_m(c.model.name or "model?")}{tools}<br/>'
                     f'<small>{_m(c.id)}</small>"}}}}:::llm')
    lines.append("    end")
    lines.append('    subgraph K["💥 dangerous sinks"]')
    sink_class = {f"{f.sink.file}:{f.sink.line}": f.sink_class for f in res.flows[:top]}
    for sk, nid in sink_nodes.items():
        lines.append(f'        {nid}[\\"{SINK_ICON.get(sink_class[sk], "")} {_m(sink_class[sk])}<br/>'
                     f'<small>{_m(sk)}</small>"/]:::sink')
    lines.append("    end")
    for a, b in sorted(edges_in):
        lines.append(f"    {a} --> {b}")
    for (a, b, gated), p in sorted(edges_out.items(), key=lambda kv: -kv[1]):
        if gated:
            lines.append(f'    {a} -. "{p:.2f} 🛡" .-> {b}')
        elif p >= 0.4:
            lines.append(f'    {a} == "{p:.2f}" ==> {b}')
        else:
            lines.append(f'    {a} -- "{p:.2f}" --> {b}')
    lines.append(CLASSDEFS)
    return "\n".join(lines)


def mermaid_markdown(res: Result, top: int = 5) -> str:
    out = [f"# LLM flows · {res.repo_name}", "",
           f"{len(res.callsites)} LLM call sites, {len(res.flows)} flows "
           f"({sum(1 for f in res.flows if f.gated)} gated). Generated by `python -m app llmflow scan`.", "",
           "## Attack surface", "", "```mermaid", surface_mermaid(res), "```", ""]
    for f in res.flows[:top]:
        gates = ", ".join(sorted({g.title for g in f.gates})) or "none"
        out += [f"## {f.id} · {f.sink_title} ({f.cwe}) · priority {f.priority:.3f}", "",
                f"S={f.S:.2f} · E={f.E:.2f} (base {f.E_base:.2f}) · R={f.R:.2f} · source: {f.source_title} · "
                f"model: `{f.model or '?'}` · gates: {gates}", "",
                "```mermaid", flow_mermaid(f), "```", "",
                "| # | role | where | function | detail |", "|---|---|---|---|---|"]
        for i, h in enumerate(f.hops, 1):
            detail = re.sub(r"\|", "\\|", h.label)
            out.append(f"| {i} | {ROLE_ICON.get(h.role, '')} {h.role} | `{_loc(h)}` | `{h.func_name or '<module>'}` "
                       f"| {detail}{' (≈)' if h.approx else ''} |")
        out.append("")
    return "\n".join(out)
