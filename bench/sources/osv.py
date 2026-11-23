"""OSV.dev bulk dumps (PyPI, npm). Mirrors GitHub Security Advisories (with CWE ids) and PYSEC.

Fix commits come from GIT `fixed` range events and from FIX/WEB references that are GitHub commit
URLs. Records that alias each other (GHSA/PYSEC/CVE) are merged by (repo, fix commit).
Also used as an enrichment index (CVE, GHSA, published, CWE) for other sources.
"""

from __future__ import annotations

import json
import zipfile
from datetime import date
from pathlib import Path

from bench.schemas import RawItem, norm_repo_url, parse_commit_url, repo_key
from bench.sources._fetch import download
from bench.config import BenchmarkConfig
from app.sast.cwe_map import cwes_from_strings

NAME = "osv"
LICENSE = "CC-BY-4.0 (OSV data); GHSA content CC-BY-4.0"


def fetch(raw_dir: Path, cfg: BenchmarkConfig, force: bool = False) -> dict:
    osv = cfg.sources.osv
    for eco in osv.ecosystems:
        download(osv.url_template.format(ecosystem=eco), raw_dir / "osv" / f"{eco}.zip", force)
    return {"name": NAME, "url": osv.url_template, "version": "downloaded dump (see file mtime)",
            "license": LICENSE}


def _published(rec: dict) -> date | None:
    p = rec.get("published")
    try:
        return date.fromisoformat(p[:10]) if p else None
    except ValueError:
        return None


def _fix_commits(rec: dict) -> list[tuple[str, str]]:
    """All (repo_url, sha) fix commits named by a record, de-duplicated, in order."""
    out: list[tuple[str, str]] = []

    def add(repo: str | None, sha: str | None):
        if repo and sha and len(sha) >= 7 and all(c in "0123456789abcdef" for c in sha.lower()):
            k = (repo, sha.lower())
            if not any(repo_key(r) == repo_key(k[0]) and (s.startswith(k[1]) or k[1].startswith(s))
                       for r, s in out):
                out.append(k)

    for aff in rec.get("affected") or []:
        for rng in aff.get("ranges") or []:
            if rng.get("type") != "GIT":
                continue
            repo = norm_repo_url(rng.get("repo", ""))
            for ev in rng.get("events") or []:
                add(repo, ev.get("fixed"))
    for ref in rec.get("references") or []:
        if ref.get("type") in ("FIX", "WEB", "PACKAGE", "ADVISORY"):
            parsed = parse_commit_url(ref.get("url", ""))
            if parsed:
                add(*parsed)
    return out


def iter_records(raw_dir: Path, cfg: BenchmarkConfig):
    for eco in cfg.sources.osv.ecosystems:
        path = raw_dir / "osv" / f"{eco}.zip"
        if not path.exists():
            continue
        with zipfile.ZipFile(path) as zf:
            for name in zf.namelist():
                if not name.endswith(".json"):
                    continue
                try:
                    rec = json.loads(zf.read(name))
                except json.JSONDecodeError:
                    continue
                if rec.get("withdrawn"):
                    continue
                yield eco, rec


def _ids(rec: dict) -> tuple[str | None, str | None]:
    ids = [rec.get("id", "")] + list(rec.get("aliases") or [])
    cve = next((i for i in ids if i.startswith("CVE-")), None)
    ghsa = next((i for i in ids if i.startswith("GHSA-")), None)
    return cve, ghsa


def load(raw_dir: Path, cfg: BenchmarkConfig) -> list[RawItem]:
    """One RawItem per (repo, fix commit). Records naming several commits in one repo -> multi_commit."""
    min_pub = cfg.sources.osv.min_published
    merged: dict[tuple[str, str], RawItem] = {}
    for eco, rec in iter_records(raw_dir, cfg):
        pub = _published(rec)
        if pub and pub < min_pub:
            continue
        commits = _fix_commits(rec)
        if not commits:
            continue
        per_repo: dict[str, int] = {}
        for repo, _ in commits:
            per_repo[repo_key(repo)] = per_repo.get(repo_key(repo), 0) + 1
        cve, ghsa = _ids(rec)
        cwes = cwes_from_strings((rec.get("database_specific") or {}).get("cwe_ids") or [])
        for repo, sha in commits:
            item = RawItem(source=NAME, cve=cve, ghsa=ghsa, repo_url=repo, fix_commit=sha, cwe=cwes,
                           language=cfg.sources.osv.languages[eco], published=pub,
                           multi_commit=per_repo[repo_key(repo)] > 1,
                           extra={"osv_ids": [rec.get("id")], "summary": (rec.get("summary") or "")[:200]})
            k = item.key
            if k in merged:
                m = merged[k]
                m.cve = m.cve or cve
                m.ghsa = m.ghsa or ghsa
                m.cwe += [c for c in cwes if c not in m.cwe]
                if pub and (m.published is None or pub < m.published):
                    m.published = pub
                m.multi_commit = m.multi_commit and item.multi_commit
                m.extra["osv_ids"].append(rec.get("id"))
            else:
                merged[k] = item
    return list(merged.values())


def enrichment_index(items: list[RawItem]) -> dict[tuple[str, str], RawItem]:
    """(repo_key, sha) -> OSV item; also indexed by 12-char sha prefix for short-sha sources."""
    idx: dict[tuple[str, str], RawItem] = {}
    for it in items:
        r, s = it.key
        idx[(r, s)] = it
        idx[(r, s[:12])] = it
    return idx
