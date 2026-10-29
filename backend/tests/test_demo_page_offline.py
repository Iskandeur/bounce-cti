"""The static demo is read where a reader opens it, and that is often from disk.

A double-clicked ``frontend/dist-demo/index.html`` is a ``file://`` page. The
browser refuses its module script there (and ``fetch`` of the snapshot too), so
before this test the page stayed blank, with no word of what to do. Promises:

* The page says how to open it: a hint in ``#root``, hidden by default, shown by
  an inline classic script (the only kind that still runs on ``file://``) only
  when the protocol is ``file:``. Served over HTTP, React replaces ``#root`` and
  the hint never shows.
* The command it names needs nothing but Python, and listens on the loopback
  only, like every other server of this repository.
* With JavaScript off, a ``<noscript>`` says so instead of a blank page.

Plain text parsing, no browser and no Node needed. It reads the source page; the
build keeping the inline script as written was checked on ``dist-demo/`` in
headless Chrome when this was written (blank before, the hint after on
``file://``, the graph over HTTP), and the CI builds the demo on every PR.
"""
import re
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PAGE = (ROOT / "frontend" / "demo" / "index.html").read_text(encoding="utf-8")


class _Root(HTMLParser):
    """Collects what sits inside <div id="root">, following div nesting: the
    hint's attributes and text, and the text of a <noscript> there."""

    def __init__(self):
        super().__init__()
        self.depth = 0  # div depth inside #root; 0 = outside
        self.hint_depth = 0  # div depth at which the hint opened; 0 = outside it
        self.in_noscript = False
        self.hint_attrs = None
        self.hint_text = []
        self.noscript_text = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if self.depth == 0 and tag == "div" and a.get("id") == "root":
            self.depth = 1
        elif self.depth and tag == "div":
            self.depth += 1
            if a.get("id") == "file-hint":
                self.hint_attrs = a
                self.hint_depth = self.depth
        elif self.depth and tag == "noscript":
            self.in_noscript = True

    def handle_endtag(self, tag):
        if self.depth and tag == "div":
            if self.depth == self.hint_depth:
                self.hint_depth = 0
            self.depth -= 1
        elif tag == "noscript":
            self.in_noscript = False

    def handle_data(self, data):
        if self.hint_depth:
            self.hint_text.append(data)
        elif self.depth and self.in_noscript:
            self.noscript_text.append(data)


def _root():
    p = _Root()
    p.feed(PAGE)
    return p


def _inline_classic_scripts() -> list[str]:
    out = []
    for attrs, body in re.findall(r"<script([^>]*)>(.*?)</script>", PAGE, re.S):
        if "src=" not in attrs and 'type="module"' not in attrs:
            out.append(body)
    return out


def test_the_hint_lives_in_root_hidden_by_default():
    root = _root()
    assert root.hint_attrs is not None, "the file:// hint must sit inside #root, so React replaces it over HTTP"
    assert "hidden" in root.hint_attrs, "the hint must be hidden unless the page is a file:// one"


def test_the_hint_names_a_python_only_server_on_loopback():
    text = re.sub(r"\s+", " ", "".join(_root().hint_text))
    m = re.search(r"python3 -m http\.server( \d+)?(?: --bind ([^\s,;]+))?", text)
    assert m, "the hint must name a server that needs nothing but Python (no npm install for a reader)"
    assert m.group(2) == "127.0.0.1", "http.server without --bind 127.0.0.1 listens on every interface"
    port = (m.group(1) or " 8000").strip()
    assert f"http://127.0.0.1:{port}/" in text, "the address to open must match the port the command listens on"


def test_an_inline_classic_script_shows_the_hint_on_file_only():
    shown = [s for s in _inline_classic_scripts() if "file-hint" in s]
    assert shown, "only an inline classic script runs on file://; a module or src script never would"
    assert any(re.search(r"location\.protocol\s*===\s*['\"]file:['\"]", s) for s in shown)
    page_order = PAGE.index('id="file-hint"') < PAGE.index("location.protocol")
    assert page_order, "the script must come after the hint it unhides"


def test_without_javascript_the_page_says_so():
    assert "JavaScript" in "".join(_root().noscript_text), "a <noscript> inside #root, instead of a blank page"
