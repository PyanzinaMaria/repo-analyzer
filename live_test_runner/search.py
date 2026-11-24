"""Q-learning and genetic search over a live interaction trial."""

from __future__ import annotations

from random import Random

from offline_sequence_benchmarks.genome import decode_action, mutate, random_genome

from .graph_trial import START, LiveTrial

METHODS = ("Random", "Q-learning", "Genetic", "Q+GA")


def online_search(trial: LiveTrial, rng: Random, *, learning: bool) -> None:
    """Random walk or tabular Q-learning (same structure as offline synthetic)."""
    q: dict = {}
    while trial.steps < trial.budget:
        state, path = trial.begin_episode(), []
        for t in range(trial.horizon):
            available = list(trial.actions(state))
            if not available:
                break
            values = q.setdefault((state, t), [0.0] * len(available))
            # Grow Q-vector if the action set expanded for this state.
            if len(values) < len(available):
                values.extend([0.0] * (len(available) - len(values)))
            if not learning or rng.random() < 0.25:
                action = rng.choice(available)
            else:
                top = max(values[a] for a in available)
                action = rng.choice([a for a in available if values[a] == top])
            nxt, reward = trial.step(state, action, path)
            path.append(action)
            done = not list(trial.actions(nxt)) or t + 1 == trial.horizon
            if learning:
                continuation = 0.0
                if not done:
                    nxt_actions = list(trial.actions(nxt))
                    future = q.get((nxt, t + 1), [0.0] * max(1, len(nxt_actions)))
                    if nxt_actions:
                        continuation = max(future[a] if a < len(future) else 0.0
                                           for a in nxt_actions)
                values[action] += 0.35 * (reward + 0.95 * continuation - values[action])
            state = nxt
            if done or trial.steps == trial.budget:
                break


def genetic_search(trial: LiveTrial, rng: Random, size: int = 16) -> None:
    horizon = trial.horizon

    def evaluate(genome):
        states, state, used = [START], trial.begin_episode(), []
        for gene in genome:
            available = list(trial.actions(state))
            if not available:
                break
            action = decode_action(gene, available)
            state, _ = trial.step(state, action, used)
            used.append(action)
            states.append(state)
            if not list(trial.actions(state)) or trial.steps == trial.budget:
                break
        return genome, tuple(states)

    def fitness(item):
        _, states = item
        return sum(
            1 / (trial.counts[s] ** 0.5)
            for s in dict.fromkeys(states)
            if s != START
        )

    def breed(pool):
        def parent():
            return max(rng.sample(pool, k=min(3, len(pool))), key=fitness)

        left, ltrace = parent()
        right, rtrace = parent()
        joins = [
            (i, j)
            for i, a in enumerate(ltrace[:-1])
            for j, b in enumerate(rtrace[:-1])
            if a == b and (i or j)
        ]
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
        genomes = (
            [item[0] for item in elite]
            + [breed(population) for _ in range(size - 4)]
            + [random_genome(rng, horizon) for _ in range(2)]
        )


def hybrid_q_ga(trial: LiveTrial, rng: Random) -> None:
    """Half budget Q-learning, then genetic search with remaining budget."""
    half = trial.budget // 2
    original_budget = trial.budget
    # Run Q until half the steps are consumed by temporarily lowering budget.
    trial.budget = half
    online_search(trial, rng, learning=True)
    trial.budget = original_budget
    genetic_search(trial, rng)


def run_method(trial: LiveTrial, method: str, rng: Random) -> None:
    if method == "Genetic":
        genetic_search(trial, rng)
    elif method == "Q+GA":
        hybrid_q_ga(trial, rng)
    else:
        online_search(trial, rng, learning=method == "Q-learning")
