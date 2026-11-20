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


def build_user_prompt(
    doc_id: str,
    result: Any,
    *,
    max_findings: int = 0,
    selected_files: list[Any] | None = None,
) -> str:
    """Serialize the raw analyzer output the way the system prompts expect:
    ScanResult JSON, plus `<file path="...">` blocks for code documentation."""
    data = result.model_dump(mode="json") if hasattr(result, "model_dump") else dict(result)
    findings = data.get("findings") or []
    if max_findings and len(findings) > max_findings:
        data["findings"] = findings[:max_findings]
        data.setdefault("meta", {})["findings_truncated"] = {
            "shown": max_findings,
            "total": len(findings),
        }
    parts = [json.dumps(data, ensure_ascii=False, indent=2)]
    for item in selected_files or []:
        parts.append(f'<file path="{item.rel_path}">\n{item.content}\n</file>')
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
    ai_settings = replace(ai_settings, timeout_seconds=timeout)
    if client is None:
        client = OpenAICompatibleClient(ai_settings)

    system_prompt = load_prompt(spec.get("prompt") or "")
    user_prompt = _user_prompt_for(doc_id, result, ai_settings, workspace_root)
    logger.info(
        "Generating %s document (model=%s, timeout=%ds, prompt=%d chars)",
        doc_id, ai_settings.model, timeout, len(user_prompt),
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
) -> str:
    max_findings = int(ai_settings.max_findings or 0)
    if workspace_root is not None:
        from app.ai.selector import collect_all_files

        all_files = collect_all_files(
            Path(workspace_root),
            list(result.inventories),
            max_file_bytes=ai_settings.max_file_bytes,
        )
        logger.info("Collected %d project files for %s payload", len(all_files), doc_id)
        return build_user_prompt(doc_id, result, max_findings=max_findings, selected_files=all_files)
    return build_user_prompt(doc_id, result, max_findings=max_findings)
