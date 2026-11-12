"""The canvas calls "defused" the nodes the backend defuses.

``frontend/src/lib/constants.js`` DEFUSE_TAGS drives the toolbar's "Defused"
toggle (hide CDN / parking / sinkhole… nodes) and its count. The backend has
two lists and no single one:

* the tags ``defuse_check`` puts on a node (``backend/defuse_lists.py``);
* ``_DEFUSED_TAGS`` in ``backend/action_exports.py``: what the Actions tab
  leaves out of a blocklist unless "Include defused indicators" is ticked.

The canvas list is their union, so the word means the same nodes in both
places. A tag added on one side only would leave a defused node on a canvas
that claims to hide them, or hide a node the exports treat as actionable.

The Python files are read as text / ``ast``, so the check runs without the
backend's dependencies.
"""
import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _canvas_tags() -> list[str]:
    src = (ROOT / "frontend" / "src" / "lib" / "constants.js").read_text(encoding="utf-8")
    block = re.search(r"export const DEFUSE_TAGS = \[(.*?)\]", src, re.S)
    assert block, "DEFUSE_TAGS not found in lib/constants.js"
    return re.findall(r"'([a-z_]+)'", block.group(1))


def _export_tags() -> set[str]:
    tree = ast.parse((ROOT / "backend" / "action_exports.py").read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "_DEFUSED_TAGS" for t in node.targets
        ):
            return set(ast.literal_eval(node.value))
    raise AssertionError("_DEFUSED_TAGS not found in action_exports.py")


def _emitted_tags() -> set[str]:
    src = (ROOT / "backend" / "defuse_lists.py").read_text(encoding="utf-8")
    return set(re.findall(r'tags\.append\("([a-z_]+)"\)', src))


def test_the_backend_lists_are_still_readable():
    assert {"cdn", "sinkhole", "tor_exit"} <= _emitted_tags()
    assert {"cdn", "shared_hosting"} <= _export_tags()


def test_canvas_defuse_tags_are_the_union_of_the_backend_lists():
    assert set(_canvas_tags()) == _emitted_tags() | _export_tags()


def test_canvas_defuse_tags_have_no_duplicate():
    tags = _canvas_tags()
    assert len(tags) == len(set(tags))
