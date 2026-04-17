"""Refang defanged IOCs back to their live form.

Analysts share IOCs in a "defanged" form so they can't be accidentally clicked
or resolved (e.g. `evil[.]com`, `hxxps://bad.example[.]com/path`,
`user[at]evil(.)com`). We accept either form everywhere an IOC is entered —
the frontend also refangs on input, and the backend refangs defensively on
every seed-accepting endpoint.
"""
import re

_LITERAL_SUBS = [
    ("[.]", "."), ("(.)", "."), ("{.}", "."),
    ("[:]", ":"), ("[/]", "/"),
    ("[@]", "@"),
]

_RE_DOT_WORD = re.compile(r"\[\s*dot\s*\]|\(\s*dot\s*\)|\{\s*dot\s*\}", re.I)
_RE_AT_WORD = re.compile(r"\[\s*at\s*\]|\(\s*at\s*\)", re.I)
_RE_HXXPS = re.compile(r"\bhxxps\b", re.I)
_RE_HXXP = re.compile(r"\bhxxp\b", re.I)
_RE_FXP = re.compile(r"\bfxp\b", re.I)


def refang(s: str) -> str:
    """Return a refanged copy of `s`. Safe to call on already-live IOCs."""
    if not s:
        return s
    s = s.strip()
    # Strip common wrappers: angle brackets, leading/trailing quotes/parens.
    while s and s[0] in "<" and s[-1] in ">":
        s = s[1:-1].strip()
    for old, new in _LITERAL_SUBS:
        s = s.replace(old, new)
    s = _RE_DOT_WORD.sub(".", s)
    s = _RE_AT_WORD.sub("@", s)
    s = _RE_HXXPS.sub("https", s)
    s = _RE_HXXP.sub("http", s)
    s = _RE_FXP.sub("ftp", s)
    return s.strip()
