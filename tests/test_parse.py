from app.context.parse import enclosing_function, find_by_name, functions_for_file

PY = b'''import os

class Store:
    @staticmethod
    def load(path):
        with open(path) as fh:
            return fh.read()

    def save(self, path, data):
        def inner():
            return data
        return inner()


def top(x):
    return x + 1
'''

JS = b'''const express = require("express");
const app = express();

function merge(a, b) {
  for (const k in b) {
    a[k] = b[k];
  }
}

const helper = (x) => {
  return x * 2;
};

app.get("/ping", (req, res) => {
  res.send("ok");
});

class Svc {
  run(cmd) {
    return cmd;
  }
}
module.exports = { merge };
'''

TS = b'''export function parse(input: string): number {
  return parseInt(input, 10);
}
export class A {
  private m(x: number): number { return x; }
}
'''


def names(funcs):
    return {f.name: (f.start, f.end) for f in funcs}


def test_python_functions_with_decorators_and_nesting():
    fs = functions_for_file("a.py", PY)
    n = names(fs)
    assert n["Store.load"] == (4, 7)          # decorator line included
    assert n["Store.save"] == (9, 12)
    assert n["Store.save.inner"] == (10, 11)
    assert n["top"] == (15, 16)
    assert enclosing_function(fs, 11).name == "Store.save.inner"
    assert enclosing_function(fs, 12).name == "Store.save"
    assert enclosing_function(fs, 1) is None


def test_js_function_naming():
    fs = functions_for_file("server.js", JS)
    n = names(fs)
    assert n["merge"] == (4, 8)
    assert n["helper"] == (10, 12)
    assert "app.get(\"/ping\")" in n
    assert n["Svc.run"] == (19, 21)
    assert enclosing_function(fs, 6).name == "merge"
    # keyword tokens must not create bogus one-line "functions"
    assert not [f for f in fs if "<anonymous" in f.name]
    assert enclosing_function(fs, 4).name == "merge"


def test_typescript_and_lookup():
    fs = functions_for_file("x.ts", TS)
    n = names(fs)
    assert n["parse"] == (1, 3)
    assert n["A.m"] == (5, 5)
    assert find_by_name(fs, "A.m").start == 5
    assert find_by_name(fs, "missing") is None


def test_unknown_extension_and_garbage():
    assert functions_for_file("README.md", b"# hi") == []
    assert isinstance(functions_for_file("broken.py", b"def (:\n  ??"), list)
