"""One adapter per dataset; each exposes `fetch(raw_dir, cfg, force)` and `load(raw_dir, cfg) -> list[RawItem]`."""

from bench.sources import osv, patcheval, pyvul, secbenchjs

# Priority order: earlier sources have better labels and win when merging duplicates.
ADAPTERS = {"patcheval": patcheval, "secbenchjs": secbenchjs, "pyvul": pyvul, "osv": osv}
