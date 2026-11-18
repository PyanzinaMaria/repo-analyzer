"""Ground-truth extraction from fix diffs (spec §3.3), with fixed-side locations."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from app.core.yaml_configs import compile_excludes, in_scope  # noqa: F401  (re-exported)
from bench.schemas import GTLocation
from app.context.parse import FunctionSpan, enclosing_function, find_by_name, functions_for_file

_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


@dataclass
class Hunk:
    old_start: int
    old_count: int
    new_start: int
    new_count: int

    @property
    def pure_addition(self) -> bool:
        return self.old_count == 0

    @property
    def pure_deletion(self) -> bool:
        return self.new_count == 0

    def old_range(self) -> tuple[int, int]:
        """Vulnerable-side lines. Pure additions are anchored on the line before the insertion."""
        if self.old_count == 0:
            a = max(self.old_start, 1)
            return a, a
        return self.old_start, self.old_start + self.old_count - 1

    def new_range(self) -> tuple[int, int]:
        if self.new_count == 0:
            a = max(self.new_start, 1)
            return a, a
        return self.new_start, self.new_start + self.new_count - 1


@dataclass
class FileDiff:
    old_path: str | None
    new_path: str | None
    hunks: list[Hunk] = field(default_factory=list)

    @property
    def path(self) -> str:
        return self.old_path or self.new_path or ""

    @property
    def changed_lines(self) -> int:
        return sum(h.old_count + h.new_count for h in self.hunks)


def _unquote(p: str) -> str:
    p = p.strip()
    if p.startswith('"') and p.endswith('"'):
        p = p[1:-1].encode("latin-1", "backslashreplace").decode("unicode_escape").encode("latin-1").decode(
            "utf-8", "replace")
    return p


def _strip_prefix(p: str) -> str | None:
    p = _unquote(p)
    if p == "/dev/null":
        return None
    return p[2:] if p[:2] in ("a/", "b/") else p


def parse_diff(text: str) -> list[FileDiff]:
    """Parse `git diff -U0` output."""
    files: list[FileDiff] = []
    cur: FileDiff | None = None
    for line in text.splitlines():
        if line.startswith("diff --git "):
            cur = FileDiff(None, None)
            files.append(cur)
            m = re.match(r'diff --git ("?a/.+?"?) ("?b/.+"?)$', line)
            if m:
                cur.old_path, cur.new_path = _strip_prefix(m.group(1)), _strip_prefix(m.group(2))
        elif cur is None:
            continue
        elif line.startswith("--- "):
            cur.old_path = _strip_prefix(line[4:])
        elif line.startswith("+++ "):
            cur.new_path = _strip_prefix(line[4:])
        elif line.startswith("rename from "):
            cur.old_path = _unquote(line[len("rename from "):])
        elif line.startswith("rename to "):
            cur.new_path = _unquote(line[len("rename to "):])
        elif line.startswith("new file mode"):
            cur.old_path = None
        elif line.startswith("deleted file mode"):
            cur.new_path = None
        elif line.startswith("@@"):
            m = _HUNK_RE.match(line)
            if m:
                a, b, c, d = m.groups()
                cur.hunks.append(Hunk(int(a), int(b) if b is not None else 1,
                                      int(c), int(d) if d is not None else 1))
    return files


def map_old_line(line: int, hunks: list[Hunk]) -> int:
    """Map an unchanged vulnerable-side line to the fixed side; lines inside a hunk map to its start."""
    offset = 0
    for h in sorted(hunks, key=lambda h: h.old_start):
        o_start, o_end = h.old_range()
        if h.old_count and o_start <= line <= o_end:
            return h.new_range()[0]
        if (h.old_count and o_end < line) or (h.old_count == 0 and h.old_start < line):
            offset += h.new_count - h.old_count
        else:
            break
    return max(1, line + offset)


@dataclass
class GTResult:
    locations: list[GTLocation]
    files_changed: int
    lines_changed: int
    tangled: bool
    notes: list[str]


class FileReader:
    """Reads file contents at a commit and caches parsed function spans."""

    def __init__(self, read):  # read(sha, path) -> bytes | None
        self._read = read
        self._cache: dict[tuple[str, str], list[FunctionSpan] | None] = {}

    def functions(self, sha: str, path: str) -> list[FunctionSpan] | None:
        k = (sha, path)
        if k not in self._cache:
            src = self._read(sha, path)
            self._cache[k] = None if src is None else functions_for_file(path, src)
        return self._cache[k]

    def exists(self, sha: str, path: str) -> bool:
        return self.functions(sha, path) is not None or self._read(sha, path) is not None


def _fn_fields(fn: FunctionSpan | None, prefix: str = "") -> dict:
    return {f"{prefix}function": fn.name if fn else None,
            f"{prefix}function_start": fn.start if fn else None,
            f"{prefix}function_end": fn.end if fn else None}


def extract_gt(diff_text: str, vuln: str, fix: str, reader: FileReader, extensions: list[str],
               excludes: list[re.Pattern], max_files: int, max_lines: int,
               sink: dict | None = None, vul_funcs: list[dict] | None = None,
               vuln_tree: list[str] | None = None) -> GTResult:
    files = [f for f in parse_diff(diff_text) if in_scope(f.path, extensions, excludes)]
    notes: list[str] = []
    locations: list[GTLocation] = []
    hunks_by_old_path: dict[str, list[Hunk]] = {}
    for fd in files:
        if fd.old_path is None:      # file added by the fix: nothing to point at on the vuln side
            notes.append(f"added file ignored for GT: {fd.new_path}")
            continue
        hunks_by_old_path[fd.old_path] = fd.hunks
        v_funcs = reader.functions(vuln, fd.old_path) or []
        f_funcs = (reader.functions(fix, fd.new_path) or []) if fd.new_path else []
        for h in fd.hunks:
            vs, ve = h.old_range()
            vfn = enclosing_function(v_funcs, vs, ve)
            ffn = None
            if fd.new_path:
                fs, fe = h.new_range()
                ffn = find_by_name(f_funcs, vfn.name) if vfn else None
                ffn = ffn or enclosing_function(f_funcs, fs, fe)
                # Lines appended at the end of a function anchor just outside it on the vuln side:
                # recover the vulnerable function by the fixed-side function's name.
                if vfn is None and ffn is not None:
                    vfn = find_by_name(v_funcs, ffn.name)
            loc = GTLocation(file=fd.old_path, kind="fix_hunk", start_line=vs, end_line=ve,
                             pure_addition=h.pure_addition, **_fn_fields(vfn))
            if fd.new_path:
                loc.fixed_file, loc.fixed_start_line, loc.fixed_end_line = fd.new_path, fs, fe
                for k, v in _fn_fields(ffn, "fixed_").items():
                    setattr(loc, k, v)
            locations.append(loc)

    lines_changed = sum(f.changed_lines for f in files)
    tangled = len(files) > max_files or lines_changed > max_lines

    def extra_location(kind: str, path: str, start: int, end: int):
        v_funcs = reader.functions(vuln, path)
        if v_funcs is None:
            notes.append(f"{kind} file not found at vuln commit: {path}")
            return
        vfn = enclosing_function(v_funcs, start, end)
        loc = GTLocation(file=path, kind=kind, start_line=start, end_line=end, **_fn_fields(vfn))
        hunks = hunks_by_old_path.get(path, [])
        new_path = next((f.new_path for f in files if f.old_path == path), path)
        f_funcs = reader.functions(fix, new_path) if new_path else None
        if f_funcs is not None:
            fs, fe = map_old_line(start, hunks), map_old_line(end, hunks)
            ffn = find_by_name(f_funcs, vfn.name) if vfn else None
            ffn = ffn or enclosing_function(f_funcs, fs, fe)
            loc.fixed_file, loc.fixed_start_line, loc.fixed_end_line = new_path, fs, max(fs, fe)
            for k, v in _fn_fields(ffn, "fixed_").items():
                setattr(loc, k, v)
        locations.append(loc)

    if sink:
        path = resolve_path(sink["file"], vuln_tree) if vuln_tree is not None else sink["file"]
        if path:
            extra_location("sink", path, sink["line"], sink["line"])
        else:
            notes.append(f"sink path not in repo: {sink['file']}")
    for vf in vul_funcs or []:
        if vf.get("commit") and not (vuln.startswith(vf["commit"]) or vf["commit"].startswith(vuln[:7])):
            notes.append(f"vul_func commit {vf['commit']} != vuln commit; skipped")
            continue
        if vf.get("start_line") and vf.get("end_line"):
            extra_location("vuln_function", vf["file"], int(vf["start_line"]), int(vf["end_line"]))

    return GTResult(locations=locations, files_changed=len(files), lines_changed=lines_changed,
                    tangled=tangled, notes=notes)


def resolve_path(path: str, tree: list[str]) -> str | None:
    """Exact match, else a unique path ending with '/<path>' (npm package paths vs repo layout)."""
    path = path.lstrip("./")
    if path in tree:
        return path
    cands = [p for p in tree if p.endswith("/" + path)]
    if len(cands) == 1:
        return cands[0]
    base = Path(path).name
    cands = [p for p in tree if Path(p).name == base and not p.startswith(("test", "node_modules"))]
    return cands[0] if len(cands) == 1 else None
