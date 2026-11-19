"""CWE extraction from rule metadata plus manual mapping tables for tools that lack it."""

from __future__ import annotations

import re

_CWE_RE = re.compile(r"cwe[-_/ ]?0*(\d+)", re.IGNORECASE)


def norm_cwe(value: str | int | None) -> str | None:
    """'CWE-078', 'external/cwe/cwe-78', 78, 'CWE-78: ...' -> 'CWE-78'."""
    if value is None:
        return None
    if isinstance(value, int):
        return f"CWE-{value}"
    s = str(value).strip()
    if s.isdigit():
        return f"CWE-{int(s)}"
    m = _CWE_RE.search(s)
    return f"CWE-{int(m.group(1))}" if m else None


def cwes_from_strings(values) -> list[str]:
    out: list[str] = []
    for v in values or []:
        if isinstance(v, (list, tuple)):
            out.extend(cwes_from_strings(v))
            continue
        c = norm_cwe(v)
        if c and c not in out:
            out.append(c)
    return out


# Bandit test IDs -> CWE (from bandit docs; bandit's own `issue_cwe` is used when present).
BANDIT_CWE = {
    "B102": "CWE-78", "B103": "CWE-732", "B104": "CWE-605", "B105": "CWE-259", "B106": "CWE-259",
    "B107": "CWE-259", "B108": "CWE-377", "B110": "CWE-703", "B112": "CWE-703", "B113": "CWE-400",
    "B201": "CWE-94", "B202": "CWE-22", "B301": "CWE-502", "B302": "CWE-502", "B303": "CWE-327",
    "B304": "CWE-327", "B305": "CWE-327", "B306": "CWE-377", "B307": "CWE-78", "B308": "CWE-79",
    "B310": "CWE-22", "B311": "CWE-330", "B312": "CWE-319", "B313": "CWE-20", "B314": "CWE-20",
    "B315": "CWE-20", "B316": "CWE-20", "B317": "CWE-20", "B318": "CWE-20", "B319": "CWE-20",
    "B320": "CWE-20", "B321": "CWE-319", "B323": "CWE-295", "B324": "CWE-327", "B401": "CWE-319",
    "B402": "CWE-319", "B403": "CWE-502", "B404": "CWE-78", "B405": "CWE-20", "B406": "CWE-20",
    "B407": "CWE-20", "B408": "CWE-20", "B409": "CWE-20", "B410": "CWE-20", "B411": "CWE-20",
    "B412": "CWE-319", "B413": "CWE-327", "B415": "CWE-327", "B501": "CWE-295", "B502": "CWE-327",
    "B503": "CWE-327", "B504": "CWE-327", "B505": "CWE-326", "B506": "CWE-20", "B507": "CWE-295",
    "B508": "CWE-319", "B509": "CWE-319", "B601": "CWE-78", "B602": "CWE-78", "B603": "CWE-78",
    "B604": "CWE-78", "B605": "CWE-78", "B606": "CWE-78", "B607": "CWE-78", "B608": "CWE-89",
    "B609": "CWE-78", "B610": "CWE-89", "B611": "CWE-89", "B612": "CWE-94", "B613": "CWE-838",
    "B614": "CWE-502", "B615": "CWE-494", "B701": "CWE-94", "B702": "CWE-80", "B703": "CWE-80",
    "B704": "CWE-79",
}

# Bandit's own CWE for some XML/yaml tests is generic (CWE-20); add the specific class too.
BANDIT_EXTRA_CWE = {
    "B506": ["CWE-502"],
    **{k: ["CWE-611"] for k in ("B313", "B314", "B315", "B316", "B317", "B318", "B319", "B320",
                               "B405", "B406", "B407", "B408", "B409", "B410")},
}

ESLINT_SECURITY_CWE = {
    "security/detect-bidi-characters": ["CWE-1007"],
    "security/detect-buffer-noassert": ["CWE-119"],
    "security/detect-child-process": ["CWE-78"],
    "security/detect-disable-mustache-escape": ["CWE-79"],
    "security/detect-eval-with-expression": ["CWE-95", "CWE-94"],
    "security/detect-new-buffer": ["CWE-119"],
    "security/detect-no-csrf-before-method-override": ["CWE-352"],
    "security/detect-non-literal-fs-filename": ["CWE-22"],
    "security/detect-non-literal-regexp": ["CWE-1333"],
    "security/detect-non-literal-require": ["CWE-94"],
    "security/detect-object-injection": ["CWE-1321", "CWE-915"],
    "security/detect-possible-timing-attacks": ["CWE-208"],
    "security/detect-pseudoRandomBytes": ["CWE-338"],
    "security/detect-unsafe-regex": ["CWE-1333"],
}

# CWE "families" so that related classes still merge/match (e.g. eval vs code injection).
CWE_FAMILIES: list[set[str]] = [
    {"CWE-94", "CWE-95", "CWE-96"},
    {"CWE-78", "CWE-77", "CWE-88"},
    {"CWE-22", "CWE-23", "CWE-36", "CWE-73"},
    {"CWE-79", "CWE-80", "CWE-116"},
    {"CWE-89", "CWE-564"},
    {"CWE-1321", "CWE-915", "CWE-471"},
    {"CWE-1333", "CWE-400", "CWE-730"},
    {"CWE-862", "CWE-863", "CWE-285", "CWE-284"},
]


def expand_family(cwes) -> set[str]:
    out = set(cwes)
    for fam in CWE_FAMILIES:
        if out & fam:
            out |= fam
    return out


def cwe_overlap(a, b) -> bool:
    if not a or not b:
        return False
    return bool(expand_family(a) & expand_family(b))
