"""LLM-generated final documents: FSTEC research protocol and code docs kit.

System prompts live in ``system_prompts/`` and are mapped to document ids by
``worker.yaml`` (``ai_documents:``). The user payload is the analyzer's raw
``ScanResult`` JSON — the combined output of every analyzer and the AI review
step; the code documentation prompt additionally receives project source
files selected by ``app.ai.selector`` from the scan workspace.

Multi-file answers follow the «ФАЙЛ: <relative path>» + fenced code block
convention: ``split_files`` turns them into real files under
``data/reports/{scan_id}/docs/``, and ``build_combined_markdown`` assembles
the single serveable Markdown artifact with per-file separators.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from worker.config import ROOT_DIR, WorkerConfig

logger = logging.getLogger(__name__)

# «ФАЙЛ: docs/README.md» on its own line introduces one attached file.
FILE_MARKER = re.compile(r"^ФАЙЛ:\s*(.+?)\s*$")
FENCE = "```"
INLINE_EXTENSIONS = {".md", ".markdown", ".txt"}

# Long LLM answers (a full FSTEC protocol) need a slack limit; anything above
# it is treated as a broken answer rather than a document.
MAX_ANSWER_BYTES = 2 * 1024 * 1024

# Free-tier models choke on ~120k-char payloads (finish_reason=length). Keep
# the user prompt under this ceiling; findings first, then ranked source files.
MAX_USER_PROMPT_CHARS = 80_000
DEFAULT_DOC_MAX_FINDINGS = 50

_SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "unknown": 5,
}


class AiDocError(RuntimeError):
    """A document generation attempt produced no usable document."""


@dataclass(frozen=True)
class DocFile:
    rel_path: str
    content: str


def load_prompt(path: Path | str) -> str:
    """Read a system prompt; relative paths resolve against the repo root."""
    resolved = Path(path)
    if not resolved.is_absolute():
        resolved = ROOT_DIR / resolved
    if not resolved.is_file():
        raise AiDocError(f"system prompt not found: {resolved}")
    return resolved.read_text(encoding="utf-8")


def split_files(markdown: str) -> tuple[str, list[DocFile]]:
    """Split an LLM answer into (main markdown, attached files).

    A file is a «ФАЙЛ: <path>» line followed by one fenced code block;
    everything outside such pairs is the main document (the protocol body
    or, when the model emits no markers, the whole answer).
    """
    main_lines: list[str] = []
    files: list[DocFile] = []
    lines = markdown.splitlines()
    i = 0
    while i < len(lines):
        marker = FILE_MARKER.match(lines[i])
        opener = _find_fence(lines, i + 1)
        if marker is None or opener is None:
            main_lines.append(lines[i])
            i += 1
            continue
        closer = _find_fence(lines, opener + 1)
        if closer is None:
            main_lines.append(lines[i])
            i += 1
            continue
        rel_path = marker.group(1).strip().strip("`")
        content = "\n".join(lines[opener + 1 : closer])
        files.append(DocFile(rel_path=rel_path, content=content))
        i = closer + 1
    return "\n".join(main_lines).strip(), files


def _find_fence(lines: list[str], start: int) -> int | None:
    for j in range(start, len(lines)):
        if lines[j].lstrip().startswith(FENCE):
            return j
    return None


def safe_rel_path(rel_path: str) -> Path | None:
    """Normalize an LLM-provided relative path, rejecting escape attempts."""
    parts = [
        part
        for part in rel_path.replace("\\", "/").split("/")
        if part not in ("", ".", "..") and not part.endswith(":")
    ]
    if not parts:
        return None
    return Path(*parts)


def write_files(files: list[DocFile], docs_dir: Path) -> list[Path]:
    """Write attached files under ``docs_dir``; returns the written paths.

    The docs kit's own leading ``docs/`` segment is stripped (the target
    directory already is the docs dir); paths that would escape ``docs_dir``
    are skipped with a warning."""
    written: list[Path] = []
    for doc_file in files:
        rel = safe_rel_path(doc_file.rel_path)
        if rel is None:
            logger.warning("Skipping attached file with unsafe path %r", doc_file.rel_path)
            continue
        if rel.parts and rel.parts[0] == "docs":
            rel = Path(*rel.parts[1:]) if len(rel.parts) > 1 else Path("README.md")
        target = docs_dir / rel
        if docs_dir not in target.parents and target.parent != docs_dir:
            logger.warning("Skipping attached file escaping docs dir: %r", doc_file.rel_path)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(doc_file.content, encoding="utf-8")
        written.append(target)
    return written


def build_combined_markdown(main: str, files: list[DocFile]) -> str:
    """Assemble the serveable Markdown artifact: the main document followed
    by every attached file under a path heading. Markdown files are inlined,
    everything else (JSON SBOM, registries) is fenced as code."""
    parts = [main.strip()] if main.strip() else []
    for doc_file in files:
        suffix = Path(doc_file.rel_path).suffix.lower()
        heading = f"## Файл: `{doc_file.rel_path}`"
        if suffix in INLINE_EXTENSIONS:
            parts.append(f"{heading}\n\n{doc_file.content.strip()}")
        else:
            parts.append(f"{heading}\n\n```{suffix.lstrip('.')}\n{doc_file.content.strip()}\n```")
    combined = "\n\n".join(parts).strip()
    if not combined:
        raise AiDocError("LLM returned an empty document")
    return combined


def _rank_findings(findings: list[Any]) -> list[Any]:
    """Highest severity first so truncation keeps the most important hits."""

    def _key(item: Any) -> tuple[int, str]:
        if isinstance(item, dict):
            sev = str(item.get("severity") or "unknown").lower()
            fid = str(item.get("id") or "")
        else:
            sev = str(getattr(item, "severity", "unknown")).lower()
            # Enum → value
            if hasattr(getattr(item, "severity", None), "value"):
                sev = str(item.severity.value).lower()
            fid = str(getattr(item, "id", "") or "")
        return (_SEVERITY_RANK.get(sev, 9), fid)

    return sorted(findings, key=_key)


def build_user_prompt(
    doc_id: str,
    result: Any,
    *,
    max_findings: int = 0,
    selected_files: list[Any] | None = None,
    max_chars: int = MAX_USER_PROMPT_CHARS,
) -> str:
    """Serialize the raw analyzer output the way the system prompts expect:
    ScanResult JSON, plus `<file path="...">` blocks for code documentation.

    Findings are severity-ranked and truncated; source files are appended
    until ``max_chars`` is reached so free LLM tiers stay within context.
    """
    data = result.model_dump(mode="json") if hasattr(result, "model_dump") else dict(result)
    findings = list(data.get("findings") or [])
    ranked = _rank_findings(findings)
    limit = int(max_findings) if max_findings else 0
    if limit and len(ranked) > limit:
        data["findings"] = ranked[:limit]
        data.setdefault("meta", {})["findings_truncated"] = {
            "shown": limit,
            "total": len(findings),
        }
    else:
        data["findings"] = ranked

    # Drop bulky blobs that rarely help FSTEC/codedocs and blow the budget.
    meta = data.get("meta")
    if isinstance(meta, dict):
        meta = dict(meta)
        meta.pop("security_hypotheses", None)
        data["meta"] = meta

    base = json.dumps(data, ensure_ascii=False, indent=2)
    if max_chars > 0 and len(base) > max_chars:
        # Extreme case: even truncated findings overflow — hard-cut JSON.
        data.setdefault("meta", {})["prompt_truncated"] = {
            "reason": "findings_json_too_large",
            "max_chars": max_chars,
        }
        base = json.dumps(data, ensure_ascii=False, indent=2)[:max_chars]

    parts = [base]
    included = 0
    skipped = 0
    for item in selected_files or []:
        block = f'<file path="{item.rel_path}">\n{item.content}\n</file>'
        candidate = "\n\n".join(parts + [block])
        if max_chars > 0 and len(candidate) > max_chars:
            skipped += 1
            continue
        parts.append(block)
        included += 1
    if skipped:
        # Tiny trailer so the model knows context was capped.
        note = (
            f"\n\n<!-- prompt_truncated: included_files={included} "
            f"skipped_files={skipped} max_chars={max_chars} -->"
        )
        if max_chars <= 0 or len("\n\n".join(parts)) + len(note) <= max_chars:
            parts.append(note.strip())
        data_meta = data.setdefault("meta", {})
        if isinstance(data_meta, dict):
            # Re-serialize is expensive; the HTML comment above is enough for the model.
            pass
    return "\n\n".join(parts)


def generate_document(
    doc_id: str,
    result: Any,
    cfg: WorkerConfig,
    *,
    workspace_root: Path | None = None,
    client: Any | None = None,
    ai_settings: Any | None = None,
) -> tuple[str, list[DocFile]]:
    """Generate one LLM document. Returns (combined markdown, attached files).

    ``client`` and ``ai_settings`` are injection points for tests; by default
    the OpenAI-compatible client is built from the analyzer AI settings with
    the per-document timeout applied.
    """
    spec = cfg.ai_documents.get(doc_id)
    if not spec:
        raise AiDocError(f"no ai_documents spec for document {doc_id!r}")

    from app.ai.client import OpenAICompatibleClient
    from app.ai.config import AiSettings, load_ai_settings

    if ai_settings is None:
        ai_settings = load_ai_settings()
    timeout = int(spec.get("timeout_seconds") or ai_settings.timeout_seconds)
    # Per-document overrides from worker.yaml `ai_documents.<id>`.
    max_files = int(spec.get("max_files") or ai_settings.max_files or 25)
    max_file_bytes = int(spec.get("max_file_bytes") or ai_settings.max_file_bytes or 40_000)
    max_findings = int(
        spec.get("max_findings")
        or ai_settings.max_findings
        or DEFAULT_DOC_MAX_FINDINGS
    )
    max_chars = int(spec.get("max_prompt_chars") or MAX_USER_PROMPT_CHARS)
    ai_settings = replace(
        ai_settings,
        timeout_seconds=timeout,
        max_files=max_files,
        max_file_bytes=max_file_bytes,
        max_findings=max_findings,
    )
    if client is None:
        client = OpenAICompatibleClient(ai_settings)

    system_prompt = load_prompt(spec.get("prompt") or "")
    user_prompt = _user_prompt_for(
        doc_id,
        result,
        ai_settings,
        workspace_root,
        max_chars=max_chars,
    )
    logger.info(
        "Generating %s document (model=%s, timeout=%ds, prompt=%d chars, "
        "max_files=%d, max_findings=%d)",
        doc_id,
        ai_settings.model,
        timeout,
        len(user_prompt),
        max_files,
        max_findings,
    )
    answer = client.chat(system_prompt, user_prompt)
    if len(answer.encode("utf-8")) > MAX_ANSWER_BYTES:
        raise AiDocError(f"{doc_id}: LLM answer exceeds {MAX_ANSWER_BYTES} bytes")

    main, files = split_files(answer)
    return build_combined_markdown(main, files), files


def _user_prompt_for(
    doc_id: str,
    result: Any,
    ai_settings: Any,
    workspace_root: Path | None,
    *,
    max_chars: int = MAX_USER_PROMPT_CHARS,
) -> str:
    max_findings = int(ai_settings.max_findings or DEFAULT_DOC_MAX_FINDINGS)
    selected: list[Any] = []
    if workspace_root is not None:
        from app.ai.selector import select_files

        # Ranked + capped selection — never dump the whole repo (collect_all_files
        # previously blew free-tier context to ~120k chars).
        selected = select_files(
            Path(workspace_root),
            list(result.inventories),
            ai_settings,
        )
        logger.info(
            "Selected %d/%s project files for %s payload (max_files=%s)",
            len(selected),
            ai_settings.max_files,
            doc_id,
            ai_settings.max_files,
        )
    return build_user_prompt(
        doc_id,
        result,
        max_findings=max_findings,
        selected_files=selected,
        max_chars=max_chars,
    )
