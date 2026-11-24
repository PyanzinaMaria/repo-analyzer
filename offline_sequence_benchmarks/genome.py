"""Relative action genes for deterministic replay with variable branching."""


def random_genome(rng, length):
    return tuple(rng.random() for _ in range(length))


def decode_action(gene, actions):
    """Choose by rank in the ordered, nonempty list of current actions."""
    size = len(actions)
    # Clamp in case multiplication rounds up to size.
    return actions[min(int(gene * size), size - 1)]


def encode_rank(index, size):
    """Place a known action rank in the middle of its interval."""
    if not 0 <= index < size:
        raise ValueError(f"Action rank {index} outside list of size {size}")
    return (index + 0.5) / size


def mutate(genes, rng, probability):
    return tuple(rng.random() if rng.random() < probability else gene for gene in genes)
