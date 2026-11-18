"""Tool-agnostic SARIF 2.1.0 reader producing flat raw findings."""

from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlparse

from pydantic import BaseModel

from app.sast.cwe_map import BANDIT_CWE, BANDIT_EXTRA_CWE, ESLINT_SECURITY_CWE, cwes_from_strings


class FlowStep(BaseModel):
    file: str
    line: int
    snippet: str | None = None


class RawFinding(BaseModel):
    tool: str
    rule_id: str
    cwe: list[str]
    severity: str | None
    file: str
    start_line: int
    end_line: int
    message: str
    dataflow: list[FlowStep] | None = None


def _tool_key(driver_name: str) -> str:
    n = driver_name.lower()
    if "semgrep" in n:
        return "semgrep"
    if "bandit" in n:
        return "bandit"
    if "eslint" in n:
        return "eslint"
    if "codeql" in n:
        return "codeql"
    return n.replace(" ", "_")


def rel_path(uri: str, root: Path | None, base_ids: dict[str, str] | None = None,
             base_id: str | None = None) -> str:
    """Turn a SARIF artifact URI into a repo-relative POSIX path."""
    if uri.startswith("file:"):
        parsed = urlparse(uri)
        path = unquote(parsed.path)
        # file:///C:/x on Windows -> /C:/x
        if len(path) > 2 and path[0] == "/" and path[2] == ":":
            path = path[1:]
    else:
        path = unquote(uri)
        if base_id and base_ids and base_id in base_ids:
            base = base_ids[base_id]
            if base.startswith("file:"):
                base = unquote(urlparse(base).path)
            path = str(PurePosixPath(base) / path)
    path = path.replace("\\", "/")
    if root is not None:
        root_s = str(root).replace("\\", "/").rstrip("/") + "/"
        candidates = [root_s]
        try:
            candidates.append(str(Path(root).resolve()).replace("\\", "/").rstrip("/") + "/")
        except OSError:
            pass
        for r in candidates:
            if path.startswith(r):
                path = path[len(r):]
                break
    while path.startswith("./"):
        path = path[2:]
    return path


_LEVEL_TO_SEV = {"error": "high", "warning": "medium", "note": "low", "none": "low"}


def _severity(result: dict, rule: dict) -> str | None:
    props = result.get("properties") or {}
    # bandit puts its own severity on the result
    sev = props.get("issue_severity")
    if isinstance(sev, str):
        return sev.lower()
    rprops = rule.get("properties") or {}
    sec = rprops.get("security-severity")
    if sec is not None:
        try:
            s = float(sec)
            return "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low"
        except (TypeError, ValueError):
            pass
    level = result.get("level") or (rule.get("defaultConfiguration") or {}).get("level")
    return _LEVEL_TO_SEV.get(level) if level else None


def _rule_cwes(tool: str, rule_id: str, rule: dict, result: dict) -> list[str]:
    props = rule.get("properties") or {}
    cwes = cwes_from_strings(props.get("tags") or [])
    cwes += [c for c in cwes_from_strings(props.get("cwe") or []) if c not in cwes]
    rprops = result.get("properties") or {}
    issue_cwe = rprops.get("issue_cwe")
    if isinstance(issue_cwe, dict):
        issue_cwe = issue_cwe.get("id")
    cwes += [c for c in cwes_from_strings([issue_cwe] if issue_cwe else []) if c not in cwes]
    if tool == "bandit":
        test_id = rule_id.split(":")[0]
        for c in [BANDIT_CWE.get(test_id)] + BANDIT_EXTRA_CWE.get(test_id, []):
            if c and c not in cwes:
                cwes.append(c)
    if tool == "eslint":
        for c in ESLINT_SECURITY_CWE.get(rule_id, []):
            if c not in cwes:
                cwes.append(c)
    return cwes


def _location(loc: dict, root: Path | None, base_ids: dict) -> tuple[str, int, int, str | None] | None:
    phys = loc.get("physicalLocation") or {}
    art = phys.get("artifactLocation") or {}
    uri = art.get("uri")
    if not uri:
        return None
    region = phys.get("region") or {}
    start = int(region.get("startLine") or 1)
    end = int(region.get("endLine") or start)
    snippet = (region.get("snippet") or {}).get("text")
    return rel_path(uri, root, base_ids, art.get("uriBaseId")), start, max(start, end), snippet


def parse_sarif(path_or_obj, root: Path | None = None) -> list[RawFinding]:
    """Parse a SARIF file (or already-loaded dict). `root` strips absolute prefixes."""
    if isinstance(path_or_obj, (str, Path)):
        with open(path_or_obj, encoding="utf-8") as fh:
            sarif = json.load(fh)
    else:
        sarif = path_or_obj
    out: list[RawFinding] = []
    for run in sarif.get("runs") or []:
        driver = (run.get("tool") or {}).get("driver") or {}
        tool = _tool_key(driver.get("name", "unknown"))
        rules = driver.get("rules") or []
        rules_by_id = {r.get("id"): r for r in rules}
        # CodeQL puts rules in extensions (packs)
        for ext in (run.get("tool") or {}).get("extensions") or []:
            for r in ext.get("rules") or []:
                rules_by_id.setdefault(r.get("id"), r)
        base_ids = {k: (v or {}).get("uri", "") for k, v in (run.get("originalUriBaseIds") or {}).items()}
        for res in run.get("results") or []:
            rule_id = res.get("ruleId") or (res.get("rule") or {}).get("id") or "unknown"
            rule = rules_by_id.get(rule_id)
            if rule is None and isinstance(res.get("ruleIndex"), int) and res["ruleIndex"] < len(rules):
                rule = rules[res["ruleIndex"]]
            rule = rule or {}
            locs = res.get("locations") or []
            if not locs:
                continue
            first = _location(locs[0], root, base_ids)
            if first is None:
                continue
            file, start, end, _ = first
            flow = None
            for cf in res.get("codeFlows") or []:
                for tf in cf.get("threadFlows") or []:
                    steps = []
                    for st in tf.get("locations") or []:
                        loc = _location(st.get("location") or {}, root, base_ids)
                        if loc:
                            steps.append(FlowStep(file=loc[0], line=loc[1], snippet=loc[3]))
                    if steps:
                        flow = steps
                        break
                if flow:
                    break
            message = (res.get("message") or {}).get("text") or ""
            out.append(RawFinding(
                tool=tool, rule_id=rule_id, cwe=_rule_cwes(tool, rule_id, rule, res),
                severity=_severity(res, rule), file=file, start_line=start, end_line=end,
                message=message.strip(), dataflow=flow,
            ))
    return out
