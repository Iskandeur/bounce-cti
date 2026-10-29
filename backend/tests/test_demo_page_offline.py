"""The static demo is read where a reader opens it, and that is often from disk.

A double-clicked ``frontend/dist-demo/index.html`` is a ``file://`` page. The
browser refuses its module script there (and ``fetch`` of the snapshot too), so
before this test the page stayed blank, with no word of what to do. Two promises:

* The page says how to open it: a hint in ``#root``, hidden by default, shown by
  an inline classic script (the only kind that still runs on ``file://``) only
  when the protocol is ``file:``. Served over HTTP, React replaces ``#root`` and
  the hint never shows.
* The way it names exists: ``npm run preview:demo`` serves the demo build, on the
  loopback only, like every other server of this repository.

Plain text parsing, no browser and no Node needed. The rendering itself (blank
before, hint after on ``file://``, the graph over HTTP) was checked in headless
Chrome when this was written.
"""
import json
import re
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PAGE = (ROOT / "frontend" / "demo" / "index.html").read_text(encoding="utf-8")
SCRIPTS = json.loads((ROOT / "frontend" / "package.json").read_text(encoding="utf-8"))["scripts"]


class _Root(HTMLParser):
    """Collects what sits inside <div id="root">, following div nesting."""

    def __init__(self):
        super().__init__()
        self.depth = 0  # div depth inside #root; 0 = outside
        self.hint_attrs = None
        self.text = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if self.depth == 0 and tag == "div" and a.get("id") == "root":
            self.depth = 1
        elif self.depth and tag == "div":
            self.depth += 1
            if a.get("id") == "file-hint":
                self.hint_attrs = a

    def handle_endtag(self, tag):
        if self.depth and tag == "div":
            self.depth -= 1

    def handle_data(self, data):
        if self.depth:
            self.text.append(data)


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


def test_the_hint_names_the_command_that_exists():
    assert "npm run preview:demo" in "".join(_root().text)
    assert "preview:demo" in SCRIPTS


def test_an_inline_classic_script_shows_the_hint_on_file_only():
    shown = [s for s in _inline_classic_scripts() if "file-hint" in s]
    assert shown, "only an inline classic script runs on file://; a module or src script never would"
    assert any(re.search(r"location\.protocol\s*===\s*['\"]file:['\"]", s) for s in shown)
    page_order = PAGE.index('id="file-hint"') < PAGE.index("location.protocol")
    assert page_order, "the script must come after the hint it unhides"


def test_preview_demo_serves_the_demo_build_on_loopback():
    cmd = SCRIPTS["preview:demo"]
    assert "vite preview" in cmd
    assert "--config vite.demo.config.js" in cmd, "without it, preview serves the app build (dist/), not the demo"
    m = re.search(r"--host(?:\s+|=)(\S+)", cmd)
    assert m and m.group(1) == "127.0.0.1", "a bare --host listens on every interface"
