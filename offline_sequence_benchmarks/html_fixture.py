"""Offline HTML workflow exploration. No networking or external targets.

Run: python -m offline_sequence_benchmarks.html_fixture
"""

import argparse
import csv
import hashlib
import json
from collections import Counter, deque
from dataclasses import dataclass, replace
from html import escape
from html.parser import HTMLParser
from math import sqrt
from pathlib import Path
from random import Random
from statistics import mean

from .synthetic import HORIZON, METHODS, START, genetic_search, online_search


PROOFS = ("text-proof", "screen-proof", "print-proof")


@dataclass(frozen=True)
class Action:
    method: str
    path: str
    fields: tuple = ()
    label: str = ""

    def describe(self):
        args = ", ".join(f"{k}={v}" for k, v in self.fields)
        return f"{self.label} [{self.method} {self.path}{' ' + args if args else ''}]"


@dataclass(frozen=True)
class Booklet:
    page: str = "/"
    text: str = "empty"
    palette: str = "plain"
    cover: bool = False


def render(book):
    def link(path, label):
        return f'<a href="{path}" aria-label="{label}">{label}</a>'

    def form(field, value, label):
        return (f'<form method="post" action="{book.page}" aria-label="{label}">'
                f'<input type="hidden" name="{field}" value="{value}">'
                f'<button type="submit">{label}</button></form>')

    home = link("/", "Home")
    body = []
    match book.page:
        case "/":
            body = [link("/text", "Text"), link("/palette", "Palette"),
                    link("/cover", "Cover"), link("/preview", "Preview")]
        case "/text":
            body = [form("text", value, f"Set text: {value}")
                    for value in ("empty", "draft", "final")] + [home]
        case "/palette":
            body = [form("palette", value, f"Set palette: {value}")
                    for value in ("plain", "blue", "green")] + [home]
        case "/cover":
            body = [form("cover", "off" if book.cover else "on",
                         "Remove cover" if book.cover else "Add cover"), home]
        case "/preview":
            body = [home]
            if book.text == "draft" and book.palette == "green" and not book.cover:
                body += [link("/text-proof", "Open text proof")]
            if book.text == "final" and book.cover:
                if book.palette == "blue":
                    body += [link("/screen-proof", "Open screen proof")]
                if book.palette == "green":
                    body += [link("/print-proof", "Open print proof")]
        case _:
            # Proof pages end an episode; there is no active action to extract.
            body = ["<p>Preview generated.</p>"]
    status = f"text={book.text}; palette={book.palette}; cover={'on' if book.cover else 'off'}"
    return (f"<html><body><h1>{escape(book.page)}</h1><p>{status}</p>"
            f"{''.join(body)}</body></html>")


class FixtureParser(HTMLParser):
    """Parse the subset emitted by render(): links and simple submit forms."""

    def __init__(self):
        super().__init__()
        self.actions = []
        self.form = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a" and "href" in attrs:
            self.actions.append(Action("GET", attrs["href"], label=attrs["aria-label"]))
        elif tag == "form":
            self.form = (attrs, [], [])
        elif self.form is not None and tag == "input" and attrs.get("type") == "hidden":
            self.form[1].append((attrs["name"], attrs["value"]))
        elif self.form is not None and tag == "button" and attrs.get("type") == "submit":
            self.form[2].append(True)

    def handle_endtag(self, tag):
        if tag == "form" and self.form is not None:
            attrs, fields, submits = self.form
            if submits:
                self.actions.append(Action(attrs["method"].upper(), attrs["action"],
                                           tuple(fields), attrs["aria-label"]))
            self.form = None


def actions_in(html):
    parser = FixtureParser()
    parser.feed(html)
    parser.close()
    return tuple(parser.actions)


def follow(book, action):
    """In-memory execution of actions emitted by the fixed booklet fixture."""
    if action.method == "GET":
        return replace(book, page=action.path)
    ((field, value),) = action.fields
    return replace(book, **{field: (value == "on") if field == "cover" else value})


class HTMLTrial:
    """Adapter for the two original policies. No full graph is provided to them."""

    def __init__(self, budget, horizon=HORIZON):
        if horizon < 1:
            raise ValueError("horizon must be positive")
        self.budget = budget
        self.horizon = horizon
        self.steps = 0
        self.counts = Counter()
        self.nodes = {}
        self.edges = {}
        self.examples = {}
        self.checkpoints = []
        self.checkpoint_steps = {i * budget // 4 for i in range(1, 5)}
        initial = self.observe(Booklet())
        assert initial == START
        self.counts[START] = 1
        self.snapshot()

    def observe(self, book):
        html = render(book)
        identity = START if book == Booklet() else hashlib.sha256(html.encode()).hexdigest()[:16]
        if identity not in self.nodes:
            actions = actions_in(html)
            self.nodes[identity] = (book, actions, self.steps)
        return identity

    def actions(self, state):
        return range(len(self.nodes[state][1]))

    def step(self, state, action, path):
        assert self.steps < self.budget
        book, actions, _ = self.nodes[state]
        self.steps += 1
        nxt = self.observe(follow(book, actions[action]))
        self.edges.setdefault((state, action, nxt), self.steps)
        self.counts[nxt] += 1
        if nxt != START:
            self.examples.setdefault(nxt, (*path, action))
        if self.steps in self.checkpoint_steps:
            self.snapshot()
        return nxt, 1.0 / sqrt(self.counts[nxt])

    def snapshot(self):
        self.checkpoints.append(dict(
            step=self.steps, states=len(self.nodes),
            discovered_actions=sum(len(actions) for _, actions, _ in self.nodes.values()),
            transitions=len(self.edges),
        ))

    def replay(self, path):
        book, labels = Booklet(), []
        for action_id in path:
            action = actions_in(render(book))[action_id]
            labels.append(action.describe())
            book = follow(book, action)
        return book, labels

    def export(self):
        return dict(
            checkpoints=self.checkpoints,
            nodes=[dict(id=node, path=book.page, text=book.text, palette=book.palette,
                        cover=book.cover, discovered_at=seen_at,
                        actions=[dict(index=i, name=action.describe())
                                 for i, action in enumerate(actions)])
                   for node, (book, actions, seen_at) in self.nodes.items()],
            edges=[dict(source=source, action=index, target=target, first_used_at=step)
                   for (source, index, target), step in self.edges.items()],
        )


def evaluate(seed, method, budget, horizon=HORIZON):
    trial, rng = HTMLTrial(budget, horizon), Random(seed)
    if method == "Genetic":
        genetic_search(trial, rng)
    else:
        online_search(trial, rng, learning=method == "Q-learning")
    assert trial.steps == budget
    rows = sorted((seen_at, node, book) for node, (book, _, seen_at) in trial.nodes.items()
                  if book.page.lstrip("/") in PROOFS)
    assert len(rows) == len({book.page for _, _, book in rows})
    examples = {}
    for seen_at, node, book in rows:
        result, path = trial.replay(trial.examples[node])
        assert book == result
        examples[book.page] = dict(step=seen_at, path=path)
    first = next(iter(examples), "")
    metrics = dict(seed=seed, method=method, **trial.checkpoints[-1], proofs=len(rows),
                   first_proof_step=examples[first]["step"] if first else "",
                   first_proof=first,
                   first_sequence=json.dumps(examples[first]["path"]) if first else "")
    return metrics, trial, examples


def fixture_reference():
    """Enumerate reachable fixture states for reporting only, after all runs."""
    start = Booklet()
    queue, distances, edges = deque([start]), {start: 0}, 0
    while queue:
        book = queue.popleft()
        for action in actions_in(render(book)):
            edges += 1
            nxt = follow(book, action)
            if nxt not in distances:
                distances[nxt] = distances[book] + 1
                queue.append(nxt)
    return dict(states=len(distances), transitions=edges,
                proof_min_steps={book.page: steps for book, steps in distances.items()
                                 if book.page.lstrip("/") in PROOFS})


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seeds", type=int, default=10)
    parser.add_argument("--budget", type=int, default=600)
    parser.add_argument("--horizon", type=int, default=HORIZON,
                        help="Maximum actions per episode (default: %(default)s)")
    parser.add_argument("--csv", type=Path)
    parser.add_argument("--graph-json", type=Path, help="Graphs for one seed, one per method")
    parser.add_argument("--graph-seed", type=int, default=0)
    args = parser.parse_args(argv)
    if min(args.seeds, args.budget, args.horizon) < 1:
        parser.error("--seeds, --budget and --horizon must be positive")
    if args.graph_json and not 0 <= args.graph_seed < args.seeds:
        parser.error("--graph-seed must be in [0, --seeds)")
    rows, graphs = [], {}
    for seed in range(args.seeds):
        for method in METHODS:
            row, trial, examples = evaluate(seed, method, args.budget, args.horizon)
            rows.append(row)
            if seed == args.graph_seed and args.graph_json:
                graphs[method] = dict(**trial.export(), proof_sequences=examples)
    reference = fixture_reference()
    print(f"Fixture reference: {reference}")
    print(f"Paired seeds: {args.seeds}; budget: {args.budget} UI actions per run; "
          f"episode limit: {args.horizon}.")
    for method in METHODS:
        group = [row for row in rows if row["method"] == method]
        hits = sum(row["proofs"] > 0 for row in group)
        metrics = "; ".join(f"{key}: {mean(row[key] for row in group):.2f}"
                            for key in ("states", "discovered_actions", "transitions", "proofs"))
        print(f"{method:12} {metrics}; runs with a proof: {hits}/{len(group)}")
    if args.csv:
        with args.csv.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=rows[0])
            writer.writeheader()
            writer.writerows(rows)
    if args.graph_json:
        with args.graph_json.open("w", encoding="utf-8") as f:
            json.dump(dict(seed=args.graph_seed, fixture_reference=reference, methods=graphs),
                      f, indent=2, ensure_ascii=False)
            f.write("\n")


if __name__ == "__main__":
    main()
