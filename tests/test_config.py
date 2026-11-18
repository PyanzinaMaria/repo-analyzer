
from app.core.yaml_configs import load_models_config, load_sast_config
from bench.config import load_benchmark_config, load_eval_config


def test_all_configs_load():
    b = load_benchmark_config()
    assert "CWE-22" in b.cwe_whitelist and "CWE-1321" in b.cwe_whitelist
    assert b.loc_bounds["python"][0] == 2000
    assert b.tangled.max_files == 10
    s = load_sast_config()
    assert set(s.tools) == {"semgrep", "bandit", "eslint", "codeql"}
    assert s.tools["codeql"].args["typescript"]
    m = load_models_config()
    assert m.budget_usd == 0
    e = load_eval_config()
    assert e.ks == [1, 5, 10, 20]
