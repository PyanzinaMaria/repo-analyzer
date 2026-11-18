from app.sast.runners import bandit, codeql, eslint, semgrep

RUNNERS = {"semgrep": semgrep, "bandit": bandit, "eslint": eslint, "codeql": codeql}
