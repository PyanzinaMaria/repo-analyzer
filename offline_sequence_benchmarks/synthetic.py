"""Offline benchmark of sequence exploration on a synthetic state machine.

Standard library only. Run: python -m offline_sequence_benchmarks.synthetic
"""

import argparse
import csv
from collections import Counter, deque
from dataclasses import dataclass, field
from math import sqrt
from pathlib import Path
from random import Random
from statistics import mean, stdev

from .genome import decode_action, mutate, random_genome


START = "hub"
HORIZON = 64
METHODS = ("Random", "Q-learning", "Genetic")


def build_graph(seed):
    """Materialize the directed action graph before running any method."""
    rng = Random(seed)
    graph = {START: tuple(f"route-{i}:1" for i in range(4))}
    rare = set()
    for route, depth in enumerate((6, 7, 8, 9)):
        for level in range(1, depth):
            state = f"route-{route}:{level}"
            advance = f"route-{route}:{level + 1}"
            # Other actions redirect to the hub or drop part of the progress.
            targets = [advance, START, f"route-{(route + 1) % 4}:1",
                       f"route-{route}:{max(1, level - 2)}"]
            rng.shuffle(targets)
            graph[state] = tuple(targets)
        terminal = f"route-{route}:{depth}"
        graph[terminal] = ()
        rare.add(terminal)
    return graph, frozenset(rare)


def shortest_distances(graph):
    distance = {START: 0}
    queue = deque([START])
    while queue:
        state = queue.popleft()
        for nxt in graph[state]:
            if nxt not in distance:
                distance[nxt] = distance[state] + 1
                queue.append(nxt)
    return distance


@dataclass
class Trial:
    graph: dict
    budget: int
    horizon: int = HORIZON
    counts: Counter = field(default_factory=lambda: Counter({START: 1}))
    edges: set = field(default_factory=set)
    first_visits: dict = field(default_factory=dict)
    examples: dict = field(default_factory=dict)
    steps: int = 0

    def __post_init__(self):
        if self.horizon < 1:
            raise ValueError("horizon must be positive")

    def actions(self, state):
        # The learners see only locally available action IDs, not destinations.
        return range(len(self.graph[state]))

    def step(self, state, action, path):
        assert self.steps < self.budget
        nxt = self.graph[state][action]
        self.steps += 1
        self.edges.add((state, action))
        self.counts[nxt] += 1
        if nxt != START and nxt not in self.first_visits:
            self.first_visits[nxt] = self.steps
            self.examples[nxt] = tuple(path) + (action,)
        return nxt, 1.0 / sqrt(self.counts[nxt])


def online_search(trial, rng, learning):
    q = {}
    while trial.steps < trial.budget:
        state, path = START, []
        for t in range(trial.horizon):
            values = q.setdefault((state, t), [0.0] * len(trial.actions(state)))
            if not learning or rng.random() < 0.25:
                action = rng.choice(trial.actions(state))
            else:
                action = rng.choice([a for a, v in enumerate(values) if v == max(values)])
            nxt, reward = trial.step(state, action, path)
            path.append(action)
            done = not trial.actions(nxt) or t + 1 == trial.horizon
            if learning:
                continuation = 0.0 if done else max(
                    q.get((nxt, t + 1), [0.0] * len(trial.actions(nxt)))
                )
                values[action] += 0.35 * (reward + 0.95 * continuation - values[action])
            state = nxt
            if done or trial.steps == trial.budget:
                break


def genetic_search(trial, rng, size=16):
    horizon = trial.horizon

    def evaluate(genome):
        states, state, used = [START], START, []
        for gene in genome:
            actions = trial.actions(state)
            if not actions:
                break
            action = decode_action(gene, actions)
            state, _ = trial.step(state, action, used)
            used.append(action)
            states.append(state)
            if not trial.actions(state) or trial.steps == trial.budget:
                break
        return genome, tuple(states)

    def fitness(item):
        _, states = item
        # Credit each destination once per scenario; loops cannot farm novelty.
        return sum(1 / sqrt(trial.counts[s]) for s in dict.fromkeys(states) if s != START)

    def breed(pool):
        def parent():
            return max(rng.sample(pool, k=min(3, len(pool))), key=fitness)

        left, ltrace = parent()
        right, rtrace = parent()
        # Splice only at a common nonterminal state observed in both traces.
        joins = [(i, j) for i, a in enumerate(ltrace[:-1])
                 for j, b in enumerate(rtrace[:-1]) if a == b and (i or j)]
        if joins:
            i, j = rng.choice(joins)
            child = list((left[:i] + right[j:])[:horizon])
        else:
            child = list(left)
        child.extend(random_genome(rng, horizon - len(child)))
        return mutate(child, rng, 0.07)

    genomes = [random_genome(rng, horizon) for _ in range(size)]
    while trial.steps < trial.budget:
        population = []
        for genome in genomes:
            population.append(evaluate(genome))
            if trial.steps == trial.budget:
                return
        elite = sorted(population, key=fitness, reverse=True)[:2]
        genomes = ([item[0] for item in elite]
                   + [breed(population) for _ in range(size - 4)]
                   + [random_genome(rng, horizon) for _ in range(2)])


def run(seed, method, budget, horizon=HORIZON):
    graph, rare = build_graph(seed)
    trial = Trial(graph, budget, horizon=horizon)
    rng = Random(seed + 10_000)
    if method == "Genetic":
        genetic_search(trial, rng)
    else:
        online_search(trial, rng, learning=method == "Q-learning")
    assert trial.steps == budget
    hits = rare & trial.first_visits.keys()
    first = min(hits, key=trial.first_visits.__getitem__) if hits else None
    path = trial.examples[first] if first else ()
    replay = START
    for action in path:
        replay = graph[replay][action]
    assert first is None or replay == first
    return dict(seed=seed, method=method, steps=trial.steps,
                states=len(trial.counts), edges=len(trial.edges),
                rare_found=len(hits),
                first_rare=trial.first_visits[first] if first else "",
                first_target=first or "", first_path=" ".join(map(str, path)))


def summary(rows):
    def spread(values):
        return f"{mean(values):.2f} ± {(stdev(values) if len(values) > 1 else 0):.2f}"

    print("\nMeans ± sample SD. First hit is conditional on successful runs.")
    for method in METHODS:
        group = [row for row in rows if row["method"] == method]
        hits = [row["first_rare"] for row in group if row["first_rare"] != ""]
        first = f"{mean(hits):.1f}" if hits else "n/a"
        print(f"{method:12} states {spread([r['states'] for r in group])}; "
              f"edges {spread([r['edges'] for r in group])}; "
              f"rare {spread([r['rare_found'] for r in group])}; "
              f"hit {len(hits)}/{len(group)}; first {first}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seeds", type=int, default=10)
    parser.add_argument("--budget", type=int, default=1200)
    parser.add_argument("--horizon", type=int, default=HORIZON,
                        help="Maximum actions per episode (default: %(default)s)")
    parser.add_argument("--csv", type=Path)
    args = parser.parse_args(argv)
    if min(args.seeds, args.budget, args.horizon) < 1:
        parser.error("--seeds, --budget and --horizon must be positive")
    graph, rare = build_graph(0)
    distances = shortest_distances(graph)
    assert len(distances) == len(graph)
    print(f"Graph: {len(graph)} states, {sum(map(len, graph.values()))} state-action edges, "
          f"{len(rare)} designated terminals; shortest distances "
          f"{sorted(distances[node] for node in rare)}.")
    print(f"Paired seeds: {args.seeds}; transition budget per run: {args.budget}; "
          f"episode limit: {args.horizon}.")
    rows = [run(seed, method, args.budget, args.horizon)
            for seed in range(args.seeds) for method in METHODS]
    summary(rows)
    if args.csv:
        with args.csv.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=rows[0])
            writer.writeheader()
            writer.writerows(rows)


if __name__ == "__main__":
    main()
