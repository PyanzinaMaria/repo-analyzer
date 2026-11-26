"""Q-learning and genetic search over a live (or offline) interaction trial."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from math import sqrt
from pathlib import Path
from random import Random

from offline_sequence_benchmarks.genome import decode_action, mutate, random_genome

from .graph_trial import START, LiveTrial

METHODS = ("Random", "Q-learning", "Genetic", "Q+GA")
HYPERPARAMS_PATH = Path(__file__).resolve().parent / "hyperparams.json"


@dataclass(frozen=True)
class QConfig:
    alpha: float = 0.55
    gamma: float = 0.95
    epsilon: float = 0.18
    bonus: float = 2.0
    power: float = 0.5
    use_time: bool = False


@dataclass(frozen=True)
class GAConfig:
    population: int = 16
    mutation: float = 0.10
    immigrants: float = 0.20
    tournament: int = 3
    scoring: str = "sum"
    power: float = 0.5


def _start_episode(trial) -> str:
    if hasattr(trial, "begin_episode"):
        return trial.begin_episode()
    return START


def load_hyperparams(path: Path | None = None) -> tuple[QConfig, GAConfig]:
    target = path or HYPERPARAMS_PATH
    if not target.is_file():
        return QConfig(), GAConfig()
    data = json.loads(target.read_text(encoding="utf-8"))
    q = QConfig(**{k: data["q"][k] for k in QConfig.__dataclass_fields__})
    ga = GAConfig(**{k: data["ga"][k] for k in GAConfig.__dataclass_fields__})
    return q, ga


def save_hyperparams(q: QConfig, ga: GAConfig, path: Path | None = None, *, meta: dict | None = None) -> Path:
    target = path or HYPERPARAMS_PATH
    payload = {"q": asdict(q), "ga": asdict(ga)}
    if meta:
        payload["meta"] = meta
    target.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return target


DEFAULT_Q, DEFAULT_GA = load_hyperparams()


def run_random(trial, rng: Random) -> None:
    while trial.steps < trial.budget:
        state, path = _start_episode(trial), []
        for _ in range(trial.horizon):
            actions = list(trial.actions(state))
            if not actions:
                break
            action = rng.choice(actions)
            state, _ = trial.step(state, action, path)
            path.append(action)
            if trial.steps == trial.budget or not list(trial.actions(state)):
                break


def run_q(trial, rng: Random, cfg: QConfig | None = None, *, limit=None, random_warmup: int = 0) -> None:
    cfg = cfg or DEFAULT_Q
    values = defaultdict(float)
    action_counts = Counter()
    stop = trial.budget if limit is None else limit

    def key(state, time, action):
        return state, time if cfg.use_time else 0, action

    while trial.steps < stop:
        state, path = _start_episode(trial), []
        for t in range(trial.horizon):
            actions = list(trial.actions(state))
            if not actions:
                break
            if trial.steps < random_warmup or rng.random() < cfg.epsilon:
                action = rng.choice(actions)
            else:
                scores = [
                    values[key(state, t, a)]
                    + cfg.bonus / sqrt(1 + action_counts[state, a])
                    for a in actions
                ]
                top = max(scores)
                action = rng.choice(
                    [a for i, a in enumerate(actions) if scores[i] == top]
                )
            nxt, _ = trial.step(state, action, path)
            path.append(action)
            action_counts[state, action] += 1
            reward = trial.counts[nxt] ** (-cfg.power)
            nxt_actions = list(trial.actions(nxt))
            terminal = not nxt_actions or t + 1 == trial.horizon
            future = 0.0 if terminal else max(values[key(nxt, t + 1, a)] for a in nxt_actions)
            qkey = key(state, t, action)
            values[qkey] += cfg.alpha * (reward + cfg.gamma * future - values[qkey])
            state = nxt
            if terminal or trial.steps == stop:
                break


def run_ga(trial, rng: Random, cfg: GAConfig | None = None) -> None:
    cfg = cfg or DEFAULT_GA
    horizon = trial.horizon

    def evaluate(genes):
        state, trace, path = _start_episode(trial), [START], []
        for gene in genes:
            actions = list(trial.actions(state))
            if not actions:
                break
            action = decode_action(gene, actions)
            state, _ = trial.step(state, action, path)
            path.append(action)
            trace.append(state)
            if trial.steps == trial.budget or not list(trial.actions(state)):
                break
        return genes, trace

    def score(trace):
        rarity = [
            trial.counts[s] ** (-cfg.power)
            for s in dict.fromkeys(trace)
            if s != START
        ]
        if not rarity:
            return 0.0
        if cfg.scoring == "peak3":
            return sum(sorted(rarity, reverse=True)[:3]) / 3
        if cfg.scoring == "scaled-sum":
            return sum(rarity) / sqrt(len(rarity))
        return sum(rarity)

    def child(pool):
        def select():
            k = min(cfg.tournament, len(pool))
            return max(rng.sample(pool, k), key=lambda entry: entry[0])[1]

        (a, ta), (b, tb) = select(), select()
        joins = [
            (i, j)
            for i, left in enumerate(ta[:-1])
            for j, right in enumerate(tb[:-1])
            if left == right and (i or j)
        ]
        if joins:
            i, j = rng.choice(joins)
            genes = list((a[:i] + b[j:])[:horizon])
        else:
            genes = list(a)
        genes.extend(random_genome(rng, horizon - len(genes)))
        return mutate(genes, rng, cfg.mutation)

    population_size = max(4, cfg.population)
    genomes = [random_genome(rng, horizon) for _ in range(population_size)]
    while trial.steps < trial.budget:
        population = []
        for genes in genomes:
            population.append(evaluate(genes))
            if trial.steps == trial.budget:
                return
        ranked = sorted(
            ((score(item[1]), item) for item in population),
            key=lambda entry: entry[0],
            reverse=True,
        )
        immigrants = min(population_size - 1, round(population_size * cfg.immigrants))
        genomes = (
            [ranked[0][1][0]]
            + [child(ranked) for _ in range(population_size - 1 - immigrants)]
            + [random_genome(rng, horizon) for _ in range(immigrants)]
        )


def hybrid_q_ga(trial, rng: Random, q: QConfig | None = None, ga: GAConfig | None = None) -> None:
    half = max(1, trial.budget // 2)
    original = trial.budget
    trial.budget = half
    run_q(trial, rng, q)
    trial.budget = original
    run_ga(trial, rng, ga)


def online_search(trial, rng: Random, *, learning: bool, cfg: QConfig | None = None) -> None:
    """Compatibility wrapper used by pipeline leftover-budget fill."""
    if learning:
        run_q(trial, rng, cfg)
    else:
        run_random(trial, rng)


def genetic_search(trial, rng: Random, size: int = 16, cfg: GAConfig | None = None) -> None:
    """Compatibility wrapper; size overrides population when cfg is None."""
    if cfg is None:
        cfg = GAConfig(**{**asdict(DEFAULT_GA), "population": size})
    run_ga(trial, rng, cfg)


def run_method(
    trial: LiveTrial,
    method: str,
    rng: Random,
    *,
    q: QConfig | None = None,
    ga: GAConfig | None = None,
) -> None:
    q = q or DEFAULT_Q
    ga = ga or DEFAULT_GA
    if method == "Genetic":
        run_ga(trial, rng, ga)
    elif method == "Q+GA":
        hybrid_q_ga(trial, rng, q, ga)
    elif method == "Q-learning":
        run_q(trial, rng, q)
    else:
        run_random(trial, rng)
