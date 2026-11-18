from bench.diff_gt import (
    FileReader,
    compile_excludes,
    extract_gt,
    in_scope,
    map_old_line,
    parse_diff,
    resolve_path,
)
from bench.config import load_benchmark_config

DIFF = """diff --git a/app/views.py b/app/views.py
index 111..222 100644
--- a/app/views.py
+++ b/app/views.py
@@ -5 +5,2 @@ def download(name):
-    return open(os.path.join(BASE, name)).read()
+    path = safe_join(BASE, name)
+    return open(path).read()
@@ -9,0 +11,2 @@ def upload(name):
+    if ".." in name:
+        abort(400)
diff --git a/tests/test_views.py b/tests/test_views.py
--- a/tests/test_views.py
+++ b/tests/test_views.py
@@ -1,0 +2,3 @@
+def test_x():
+    pass
+
diff --git a/app/new_helper.py b/app/new_helper.py
new file mode 100644
--- /dev/null
+++ b/app/new_helper.py
@@ -0,0 +1,2 @@
+def safe(x):
+    return x
diff --git a/CHANGELOG.md b/CHANGELOG.md
--- a/CHANGELOG.md
+++ b/CHANGELOG.md
@@ -1 +1,2 @@
-old
+new
+line
"""

VULN_SRC = b"""import os
BASE = "/srv"


def download(name):
    return open(os.path.join(BASE, name)).read()


def upload(name):
    save(name)
"""

FIXED_SRC = b"""import os
BASE = "/srv"


def download(name):
    path = safe_join(BASE, name)
    return open(path).read()


def upload(name):
    if ".." in name:
        abort(400)
    save(name)
"""


def _cfg():
    cfg = load_benchmark_config()
    return cfg, compile_excludes(cfg.path_excludes)


def test_parse_diff_counts_and_paths():
    files = parse_diff(DIFF)
    assert [f.path for f in files] == ["app/views.py", "tests/test_views.py", "app/new_helper.py", "CHANGELOG.md"]
    h1, h2 = files[0].hunks
    assert (h1.old_start, h1.old_count, h1.new_start, h1.new_count) == (5, 1, 5, 2)
    assert h2.pure_addition and h2.old_range() == (9, 9) and h2.new_range() == (11, 12)
    assert files[2].old_path is None and files[2].new_path == "app/new_helper.py"


def test_path_filters():
    cfg, ex = _cfg()
    py = cfg.source_extensions["python"]
    js = cfg.source_extensions["javascript"] + cfg.source_extensions["typescript"]
    assert in_scope("app/views.py", py, ex)
    assert not in_scope("tests/test_views.py", py, ex)
    assert not in_scope("pkg/test_utils.py", py, ex)
    assert not in_scope("setup.py", py, ex)
    assert not in_scope("docs/conf.py", py, ex)
    assert not in_scope("CHANGELOG.md", py, ex)
    assert in_scope("lib/index.js", js, ex)
    assert in_scope("src/a.ts", js, ex)
    assert not in_scope("dist/a.min.js", js, ex)
    assert not in_scope("lib/a.test.js", js, ex)
    assert not in_scope("node_modules/x/index.js", js, ex)
    assert not in_scope("types/index.d.ts", js, ex)
    assert not in_scope("__tests__/a.js", js, ex)


def test_map_old_line():
    hunks = parse_diff(DIFF)[0].hunks
    assert map_old_line(2, hunks) == 2      # before any hunk
    assert map_old_line(5, hunks) == 5      # inside modified hunk -> its new start
    assert map_old_line(8, hunks) == 9      # after +1 net line
    assert map_old_line(9, hunks) == 10     # insertion happens after line 9
    assert map_old_line(10, hunks) == 13    # after the 2 inserted lines


def test_extract_gt_both_sides():
    cfg, ex = _cfg()
    srcs = {("v", "app/views.py"): VULN_SRC, ("f", "app/views.py"): FIXED_SRC}
    reader = FileReader(lambda sha, path: srcs.get((sha, path)))
    gt = extract_gt(DIFF, "v", "f", reader, cfg.source_extensions["python"], ex, 10, 300)
    hunks = [loc for loc in gt.locations if loc.kind == "fix_hunk"]
    assert len(hunks) == 2                      # test file, new file and changelog excluded
    a, b = hunks
    assert (a.file, a.start_line, a.end_line, a.function) == ("app/views.py", 5, 5, "download")
    assert (a.function_start, a.function_end) == (5, 6)
    assert (a.fixed_start_line, a.fixed_end_line, a.fixed_function) == (5, 6, "download")
    assert b.pure_addition and b.start_line == 9 and b.function == "upload"
    assert b.fixed_function == "upload" and (b.fixed_function_start, b.fixed_function_end) == (10, 13)
    assert gt.files_changed == 2                # views.py + new_helper.py (in scope)
    assert gt.lines_changed == 3 + 2 + 2
    assert not gt.tangled
    assert any("added file" in n for n in gt.notes)


def test_tangled_flag():
    cfg, ex = _cfg()
    reader = FileReader(lambda sha, path: None)
    gt = extract_gt(DIFF, "v", "f", reader, cfg.source_extensions["python"], ex, max_files=1, max_lines=300)
    assert gt.tangled
    gt = extract_gt(DIFF, "v", "f", reader, cfg.source_extensions["python"], ex, max_files=10, max_lines=5)
    assert gt.tangled


def test_sink_and_vul_func_locations():
    cfg, ex = _cfg()
    srcs = {("v", "app/views.py"): VULN_SRC, ("f", "app/views.py"): FIXED_SRC}
    reader = FileReader(lambda sha, path: srcs.get((sha, path)))
    gt = extract_gt(DIFF, "v", "f", reader, cfg.source_extensions["python"], ex, 10, 300,
                    sink={"file": "views.py", "line": 10},
                    vul_funcs=[{"file": "app/views.py", "start_line": 5, "end_line": 6, "commit": "v"},
                               {"file": "app/views.py", "start_line": 9, "end_line": 10, "commit": "zzz"}],
                    vuln_tree=["app/views.py", "app/__init__.py"])
    sink = next(loc for loc in gt.locations if loc.kind == "sink")
    assert sink.file == "app/views.py" and sink.function == "upload"
    assert sink.fixed_start_line == 13 and sink.fixed_function == "upload"
    vfs = [loc for loc in gt.locations if loc.kind == "vuln_function"]
    assert len(vfs) == 1 and vfs[0].function == "download"
    assert any("vul_func commit" in n for n in gt.notes)


def test_resolve_path():
    tree = ["lib/a.js", "src/lib/b.js", "x/index.js", "y/index.js"]
    assert resolve_path("lib/a.js", tree) == "lib/a.js"
    assert resolve_path("./lib/b.js", tree) == "src/lib/b.js"
    assert resolve_path("index.js", tree) is None   # ambiguous
    assert resolve_path("nope.js", tree) is None


def test_append_at_function_end_recovers_function_by_name():
    cfg, ex = _cfg()
    diff = """diff --git a/v.py b/v.py
--- a/v.py
+++ b/v.py
@@ -3,0 +4,2 @@ def check(data):
+    if b"<script" in data:
+        raise ValueError
"""
    vuln = b"def check(data):\n    x = 1\n    y = 2\n\n\ndef other():\n    pass\n"
    fixed = b"def check(data):\n    x = 1\n    y = 2\n    if b'<script' in data:\n        raise ValueError\n\n\ndef other():\n    pass\n"
    srcs = {("v", "v.py"): vuln, ("f", "v.py"): fixed}
    reader = FileReader(lambda sha, path: srcs.get((sha, path)))
    gt = extract_gt(diff, "v", "f", reader, cfg.source_extensions["python"], ex, 10, 300)
    [loc] = gt.locations
    assert loc.pure_addition and loc.start_line == 3
    assert loc.function == "check" and loc.fixed_function == "check"


def test_anchor_after_function_end_uses_fixed_name():
    cfg, ex = _cfg()
    # insertion after the blank line that follows the function body (anchor outside the function)
    diff = """diff --git a/v.py b/v.py
--- a/v.py
+++ b/v.py
@@ -4,0 +5,1 @@
+    validate(data)
"""
    vuln = b"def check(data):\n    x = 1\n    y = 2\n\n"
    fixed = b"def check(data):\n    x = 1\n    y = 2\n\n    validate(data)\n"
    srcs = {("v", "v.py"): vuln, ("f", "v.py"): fixed}
    reader = FileReader(lambda sha, path: srcs.get((sha, path)))
    [loc] = extract_gt(diff, "v", "f", reader, cfg.source_extensions["python"], ex, 10, 300).locations
    assert loc.start_line == 4 and loc.function == "check"
