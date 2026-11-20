"""Parameter search on the fixed, offline booklet HTML fixture.

Use: python -m offline_sequence_benchmarks.tuning --hybrids --output-dir output
No packages or network access are required.
"""

import argparse
import csv
import json
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from itertools import product
from math import sqrt
from pathlib import Path
from random import Random
from statistics import mean

from .html_fixture import HTMLTrial, PROOFS
from .synthetic import HORIZON, START, genetic_search, online_search


@dataclass(frozen=True)
class QConfig:
    alpha: float
    gamma: float
    epsilon: float
    bonus: float
    power: float
    use_time: bool


@dataclass(frozen=True)
class GAConfig:
    population: int
    mutation: float
    immigrants: float
    tournament: int
    scoring: str
    power: float


def run_q(trial, rng, cfg, *, limit=None, random_warmup=0):
    values = defaultdict(float)
    action_counts = Counter()
    stop = trial.budget if limit is None else limit

    def key(state, time, action):
        return state, time if cfg.use_time else 0, action

    while trial.steps < stop:
        state, path = START, []
        for t in range(HORIZON):
            actions = trial.actions(state)
            if trial.steps < random_warmup or rng.random() < cfg.epsilon:
                action = rng.choice(actions)
            else:
                scores = [
                    values[key(state, t, a)]
                    + cfg.bonus / sqrt(1 + action_counts[state, a])
                    for a in actions
                ]
                top = max(scores)
                action = rng.choice([a for a in actions if scores[a] == top])
            nxt, _ = trial.step(state, action, path)
            path.append(action)
            action_counts[state, action] += 1
            reward = trial.counts[nxt] ** (-cfg.power)
            terminal = not trial.actions(nxt) or t + 1 == HORIZON
            future = 0.0 if terminal else max(values[key(nxt, t + 1, a)]
                                              for a in trial.actions(nxt))
            qkey = key(state, t, action)
            values[qkey] += cfg.alpha * (reward + cfg.gamma * future - values[qkey])
            state = nxt
            if terminal or trial.steps == stop:
                break


def run_random_prefix(trial, rng, limit):
    while trial.steps < limit:
        state, path = START, []
        for _ in range(HORIZON):
            action = rng.choice(trial.actions(state))
            state, _ = trial.step(state, action, path)
            path.append(action)
            if trial.steps == limit or not trial.actions(state):
                break


def run_ga(trial, rng, cfg, *, warm_start=False):
    def genome():
        return tuple(rng.randrange(4) for _ in range(HORIZON))

    def evaluate(genes):
        state, trace, path = START, [START], []
        for gene in genes:
            action = gene % len(trial.actions(state))
            state, _ = trial.step(state, action, path)
            path.append(action)
            trace.append(state)
            if trial.steps == trial.budget or not trial.actions(state):
                break
        return genes, trace

    def score(trace):
        rarity = [trial.counts[s] ** (-cfg.power)
                  for s in dict.fromkeys(trace) if s != START]
        if not rarity:
            return 0.0
        if cfg.scoring == "peak3":
            return sum(sorted(rarity, reverse=True)[:3]) / 3
        if cfg.scoring == "scaled-sum":
            return sum(rarity) / sqrt(len(rarity))
        return sum(rarity)

    def child(pool):
        def select():
            return max(rng.sample(pool, cfg.tournament), key=lambda entry: entry[0])[1]

        (a, ta), (b, tb) = select(), select()
        joins = [(i, j) for i, left in enumerate(ta[:-1])
                 for j, right in enumerate(tb[:-1]) if left == right and (i or j)]
        if joins:
            i, j = rng.choice(joins)
            genes = list((a[:i] + b[j:])[:HORIZON])
        else:
            genes = list(a)
        genes.extend(rng.randrange(4) for _ in range(HORIZON - len(genes)))
        for i in range(HORIZON):
            if rng.random() < cfg.mutation:
                genes[i] = (genes[i] + rng.randrange(1, 4)) % 4
        return tuple(genes)

    genomes = [genome() for _ in range(cfg.population)]
    if warm_start:
        paths = [path for state, path in trial.examples.items() if trial.actions(state)]
        weights = [len(path) for path in paths]
        for i in range(cfg.population // 2 if paths else 0):
            prefix = rng.choices(paths, weights, k=1)[0][:HORIZON - 4]
            genomes[i] = prefix + genomes[i][len(prefix):]
    while trial.steps < trial.budget:
        population = []
        for genes in genomes:
            population.append(evaluate(genes))
            if trial.steps == trial.budget:
                return
        ranked = sorted(((score(item[1]), item) for item in population),
                        key=lambda entry: entry[0], reverse=True)
        immigrants = round(cfg.population * cfg.immigrants)
        genomes = ([ranked[0][1][0]]
                   + [child(ranked) for _ in range(cfg.population - 1 - immigrants)]
                   + [genome() for _ in range(immigrants)])


def trial_row(seed, budget, method, cfg=None, *, q=None, ga=None):
    rng, trial = Random(seed), HTMLTrial(budget)
    if method == "Q-tuned":
        run_q(trial, rng, cfg)
    elif method == "GA-tuned":
        run_ga(trial, rng, cfg)
    elif method == "Random+Q":
        run_q(trial, rng, q, random_warmup=budget // 2)
    elif method in ("Random+GA", "Q+GA"):
        if method == "Random+GA":
            run_random_prefix(trial, rng, budget // 2)
        else:
            run_q(trial, rng, q, limit=budget // 2)
        run_ga(trial, rng, ga, warm_start=True)
    elif method == "GA-original":
        genetic_search(trial, rng)
    else:
        online_search(trial, rng, learning=method == "Q-original")
    assert trial.steps == budget
    hits = [(step, node, book) for node, (book, _, step) in trial.nodes.items()
            if book.page[1:] in PROOFS]
    for _, node, book in hits:
        replay, _ = trial.replay(trial.examples[node])
        assert replay == book
    return dict(seed=seed, method=method, **trial.checkpoints[-1], proofs=len(hits),
                found=int(bool(hits)), first=min((h[0] for h in hits), default=None))


def grid(candidates):
    rng = Random(897)
    qs = [QConfig(*x) for x in product((0.2, 0.55, 0.85), (0.4, 0.8, 0.95),
                                      (0.04, 0.18, 0.45), (0.0, 0.7, 2.0, 5.0),
                                      (0.5, 1.0), (False, True))]
    gs = [GAConfig(*x) for x in product((6, 10, 16), (0.04, 0.10, 0.18, 0.28),
                                       (0.0, 0.20, 0.36), (2, 4),
                                       ("sum", "scaled-sum", "peak3"), (0.5, 1.0))]
    return {"Q-tuned": rng.sample(qs, candidates), "GA-tuned": rng.sample(gs, candidates)}


def scores(rows):
    return {k: mean(r[k] for r in rows)
            for k in ("proofs", "found", "states", "transitions", "discovered_actions")}


def paired_interval(method, baseline, key, repetitions=4000):
    assert [r["seed"] for r in method] == [r["seed"] for r in baseline]
    diffs = [a[key] - b[key] for a, b in zip(method, baseline)]
    rng = Random(118)
    draws = sorted(mean(rng.choices(diffs, k=len(diffs))) for _ in range(repetitions))
    return dict(delta=mean(diffs), low=draws[int(0.025 * repetitions)],
                high=draws[int(0.975 * repetitions) - 1])


def csv_write(path, rows):
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0])
        writer.writeheader()
        writer.writerows(rows)


def summarize(test_rows):
    baseline = test_rows["Random"]
    summary = {}
    for method, rows in test_rows.items():
        summary[method] = dict(**scores(rows), hits=sum(r["found"] for r in rows))
        if method != "Random":
            summary[method]["vs_random"] = {
                metric: paired_interval(rows, baseline, metric)
                for metric in ("proofs", "found", "transitions")
            }
        print(f"{method}: {summary[method]}")
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--budget", type=int, default=600)
    parser.add_argument("--candidates", type=int, default=40, help="Per method")
    parser.add_argument("--dev", type=int, default=20, help="Training seed count, starting at 0")
    parser.add_argument("--test", type=int, default=50, help="Held-out seed count, starting at 100")
    parser.add_argument("--hybrids", action="store_true",
                        help="Also compare three hybrids on an independent set of seeds")
    parser.add_argument("--output-dir", type=Path, default=Path("."))
    args = parser.parse_args(argv)
    if not (args.budget >= 1 and 1 <= args.candidates <= 432 and
            1 <= args.dev <= 100 and args.test >= 1):
        parser.error("budget/test must be positive; dev in 1..100, candidates in 1..432")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    dev_seeds, test_seeds = range(args.dev), range(100, 100 + args.test)
    dev_rows, test_rows, chosen = [], {}, {}
    base = scores([trial_row(seed, args.budget, "Random") for seed in dev_seeds])
    for method, configs in grid(args.candidates).items():
        ranked = []
        for cfg in configs:
            result = scores([trial_row(seed, args.budget, method, cfg) for seed in dev_seeds])
            record = dict(method=method, config=json.dumps(asdict(cfg), sort_keys=True), **result)
            dev_rows.append(record)
            ranked.append(((result["proofs"], result["transitions"]), cfg, result))
        _, cfg, result = max(ranked, key=lambda item: item[0])
        chosen[method] = (cfg, result)
        print(f"{method} chosen on dev: {cfg}; {result}", flush=True)
    print(f"Random on dev: {base}", flush=True)
    for method in ("Random", "Q-original", "GA-original", *chosen):
        cfg = chosen.get(method, (None, None))[0]
        test_rows[method] = [trial_row(seed, args.budget, method, cfg) for seed in test_seeds]
    summary = summarize(test_rows)
    csv_write(args.output_dir / "html_tuning_dev.csv", dev_rows)
    csv_write(args.output_dir / "html_tuning_test.csv", [r for rows in test_rows.values() for r in rows])
    output = dict(budget=args.budget, candidates=args.candidates,
                  dev_seeds=list(dev_seeds), test_seeds=list(test_seeds),
                  random_dev=base,
                  chosen={m: dict(config=asdict(cfg), dev=result) for m, (cfg, result) in chosen.items()},
                  test=summary)
    if args.hybrids:
        start = max(200, 100 + args.test)
        seeds = list(range(start, start + args.test))
        q, ga = chosen["Q-tuned"][0], chosen["GA-tuned"][0]
        params = {"Q-tuned": q, "GA-tuned": ga}
        methods = ("Random", "Q-tuned", "GA-tuned", "Random+Q", "Random+GA", "Q+GA")
        rows = {m: [trial_row(s, args.budget, m, params.get(m), q=q, ga=ga) for s in seeds]
                for m in methods}
        print(f"\nHybrid comparison on new seeds {seeds[0]}..{seeds[-1]}")
        output["hybrid_seeds"] = seeds
        output["hybrids"] = summarize(rows)
        output["hybrids_vs_q"] = {
            m: {metric: paired_interval(rows[m], rows["Q-tuned"], metric)
                for metric in ("proofs", "transitions")}
            for m in ("Random+Q", "Random+GA", "Q+GA")
        }
        csv_write(args.output_dir / "html_tuning_hybrids.csv", [r for group in rows.values() for r in group])
    (args.output_dir / "html_tuning_summary.json").write_text(
        json.dumps(output, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
