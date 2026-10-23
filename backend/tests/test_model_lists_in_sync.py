"""The model and effort choices live in five places that must agree.

* ``backend/main.py`` ALLOWED_MODELS / ALLOWED_EFFORTS: what the API accepts;
* ``backend/agent_runner.py`` _MODEL_ALIASES / _VALID_EFFORTS: what the spawn
  passes to ``claude -p``;
* ``frontend/src/App.jsx``: the new-investigation selectors;
* ``frontend/src/AdminPanel.jsx`` MODEL_LABELS: the per-user whitelist editor.

A model added to the API but not to the form can never be picked; one in the
form but not the API is offered and then refused with a 400; a pinned alias
(``opus-5``) missing from _MODEL_ALIASES reaches the CLI as a bare string it
does not know. Nothing failed loudly on any of these before this test.

The tier names (``sonnet``/``opus``/``haiku``) are pinned as well since
2026-10-23: left to the CLI's own aliasing they ran claude-sonnet-4-6,
claude-opus-4-7 and claude-haiku-4-5 in production (CLI 2.1.149) under a
"latest" label. Their labels now name the version they run, and a test below
fails when the table and the labels part ways.

The Python files are read with ``ast`` instead of imported, so the check runs
without the backend's dependencies.
"""
import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TIER_ALIASES = {"sonnet", "opus", "haiku"}  # "current" of each tier, pinned like the rest


def _literal(path: Path, name: str):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in tree.body:
        targets = []
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        for t in targets:
            if isinstance(t, ast.Name) and t.id == name:
                return ast.literal_eval(node.value)
    raise AssertionError(f"{name} not found in {path.name}")


def _app_options(pattern: str) -> list[str]:
    text = (ROOT / "frontend" / "src" / "App.jsx").read_text(encoding="utf-8")
    return re.findall(pattern, text)


ALLOWED_MODELS = _literal(ROOT / "backend" / "main.py", "ALLOWED_MODELS")
ALLOWED_EFFORTS = _literal(ROOT / "backend" / "main.py", "ALLOWED_EFFORTS")
MODEL_ALIASES = _literal(ROOT / "backend" / "agent_runner.py", "_MODEL_ALIASES")
VALID_EFFORTS = _literal(ROOT / "backend" / "agent_runner.py", "_VALID_EFFORTS")


def test_allowed_models_have_no_duplicates():
    assert len(ALLOWED_MODELS) == len(set(ALLOWED_MODELS))


def test_every_allowed_model_maps_to_a_cli_id():
    assert set(ALLOWED_MODELS) - set(MODEL_ALIASES) == set(), "alias reaches the CLI unmapped"
    assert set(MODEL_ALIASES) - set(ALLOWED_MODELS) == set(), "alias the API never accepts"
    for alias, model_id in MODEL_ALIASES.items():
        assert model_id.startswith("claude-"), (alias, model_id)


def _tier_and_version(model_id: str) -> tuple[str, tuple[int, ...]]:
    """claude-opus-4-7 → ("opus", (4, 7)); claude-sonnet-5-5 → ("sonnet", (5, 5))."""
    m = re.fullmatch(r"claude-([a-z]+)-(\d+(?:-\d+)*)", model_id)
    assert m, f"unexpected model id shape: {model_id}"
    return m.group(1), tuple(int(x) for x in m.group(2).split("-"))


def _version_label(model_id: str) -> str:
    return ".".join(str(x) for x in _tier_and_version(model_id)[1])


def test_a_tier_name_runs_the_newest_model_of_its_tier_on_offer():
    for tier in TIER_ALIASES:
        same_tier = [_tier_and_version(i)[1] for i in MODEL_ALIASES.values()
                     if _tier_and_version(i)[0] == tier]
        got_tier, got = _tier_and_version(MODEL_ALIASES[tier])
        assert got_tier == tier, (tier, MODEL_ALIASES[tier])
        assert got == max(same_tier), f"{tier} runs {got}, newer {max(same_tier)} is on offer"


def test_tier_labels_name_the_version_they_run():
    """The label is the analyst's only way to know which model "opus" is."""
    app = (ROOT / "frontend" / "src" / "App.jsx").read_text(encoding="utf-8")
    admin = (ROOT / "frontend" / "src" / "AdminPanel.jsx").read_text(encoding="utf-8")
    for tier in TIER_ALIASES:
        version = re.escape(_version_label(MODEL_ALIASES[tier]))
        option = re.search(rf'<option value="{tier}">([^<]+)</option>', app)
        assert option, tier
        assert re.search(rf"current: {version}(?![.\d])", option.group(1)), option.group(1)
        assert "latest" not in option.group(1).lower(), option.group(1)
        label = re.search(rf"^\s*{tier}: '([^']+)'", admin, re.M)
        assert label, tier
        assert re.search(rf"current: {version}(?![.\d])", label.group(1)), label.group(1)


def test_new_investigation_form_offers_exactly_the_allowed_models():
    offered = _app_options(r"allowedModels\.includes\('([^']+)'\)\) && <option value=\"\1\"")
    assert len(offered) == len(set(offered))
    assert set(offered) == set(ALLOWED_MODELS)


def test_admin_whitelist_labels_every_allowed_model():
    text = (ROOT / "frontend" / "src" / "AdminPanel.jsx").read_text(encoding="utf-8")
    block = re.search(r"const MODEL_LABELS = \{(.*?)\n\}", text, re.S)
    assert block, "MODEL_LABELS not found in AdminPanel.jsx"
    labelled = set(re.findall(r"^\s*'?([a-z0-9.\-]+)'?\s*:", block.group(1), re.M))
    assert labelled == set(ALLOWED_MODELS)


def test_effort_levels_agree_between_api_spawn_and_form():
    assert set(ALLOWED_EFFORTS) == set(VALID_EFFORTS)
    offered = _app_options(r"<option value=\"(low|medium|high|xhigh|max)\">")
    assert set(offered) == set(ALLOWED_EFFORTS)
