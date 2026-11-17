from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from app.ai.config import AiSettings
from app.core.config import get_settings, load_yaml_settings
from app.models.finding import CodeInventory

PRIORITY_TOKENS = (
    "auth",
    "login",
    "crypto",
    "payment",
    "admin",
    "upload",
    "exec",
    "shell",
    "sql",
    "db",
    "config",
    "security",
    "password",
    "token",
    "session",
    "secret",
    "jwt",
    "oauth",
    "hash",
    "cipher",
)

DEFAULT_EXTENSIONS = (".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go")


@dataclass(frozen=True)
class SelectedFile:
    rel_path: str
    content: str
    score: int


def _exclude_dirs() -> set[str]:
    settings = get_settings()
    cfg = load_yaml_settings(settings.settings_path)
    return set(cfg.get("scan", {}).get("exclude_dirs", []))


def _score_path(rel: str) -> int:
    lowered = rel.lower().replace("\\", "/")
    score = 0
    for token in PRIORITY_TOKENS:
        if token in lowered:
            score += 10
    depth = lowered.count("/")
    score += max(0, 5 - depth)
    if lowered.endswith(("app.py", "main.py", "server.py", "wsgi.py", "asgi.py")):
        score += 8
    return score


def language_for_path(rel: str) -> str:
    suffix = Path(rel).suffix.lower()
    mapping = {
        ".py": "python",
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "javascript",
        ".tsx": "javascript",
        ".java": "java",
        ".go": "go",
    }
    return mapping.get(suffix, "unknown")


def collect_candidate_paths(
    root: Path,
    inventories: list[CodeInventory],
    extensions: tuple[str, ...] = DEFAULT_EXTENSIONS,
) -> list[Path]:
    excluded = _exclude_dirs()
    seen: set[Path] = set()
    out: list[Path] = []

    for inv in inventories:
        for mod in inv.modules:
            path = root / mod
            if path.is_file() and path not in seen:
                seen.add(path)
                out.append(path)

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in extensions:
            continue
        if any(part in excluded for part in path.parts):
            continue
        if path not in seen:
            seen.add(path)
            out.append(path)
    return out


def select_files(
    root: Path,
    inventories: list[CodeInventory],
    ai_cfg: AiSettings,
    extensions: tuple[str, ...] | None = None,
) -> list[SelectedFile]:
    exts = extensions or DEFAULT_EXTENSIONS
    candidates = collect_candidate_paths(root, inventories, exts)
    ranked: list[tuple[int, Path]] = []
    for path in candidates:
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size <= 0 or size > ai_cfg.max_file_bytes:
            continue
        rel = path.relative_to(root).as_posix()
        ranked.append((_score_path(rel), path))

    ranked.sort(key=lambda item: (-item[0], item[1].as_posix()))

    selected: list[SelectedFile] = []
    for score, path in ranked:
        if len(selected) >= ai_cfg.max_files:
            break
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        if b"\x00" in raw[:1024]:
            continue
        try:
            content = raw.decode("utf-8")
        except UnicodeDecodeError:
            content = raw.decode("utf-8", errors="ignore")
        if not content.strip():
            continue
        encoded = content.encode("utf-8")
        if len(encoded) > ai_cfg.max_file_bytes:
            content = encoded[: ai_cfg.max_file_bytes].decode("utf-8", errors="ignore")
        selected.append(
            SelectedFile(
                rel_path=path.relative_to(root).as_posix(),
                content=content,
                score=score,
            )
        )
    return selected
