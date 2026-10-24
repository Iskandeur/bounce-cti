"""The CI workflows keep four promises that GitHub itself never checks.

* The checks the ``main`` ruleset requires keep their names. The ruleset asks for
  "Backend imports" and "Frontend builds" by name; a renamed job, or a matrix on it
  (GitHub appends the matrix values: "Backend imports (3.12)"), leaves the required
  check pending forever and every PR blocked, with no error anywhere.
* CI runs what production runs. Until 2026-10-24 the required gate imported the
  backend on Python 3.11 while production and the image run 3.12, and built the
  frontend on Node 20 while the image uses Node 22. The Dockerfile is the reference.
* Every action is pinned to a full commit SHA. ``deploy.yml`` hands the production
  SSH key to a third-party action: a movable tag would let whoever moves it read it.
* Dependabot never proposes a version ``requirements.txt`` caps on purpose.

Plain text parsing, no YAML library needed (same approach as test_docker_packaging).
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
CI = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
DOCKERFILE = (ROOT / "Dockerfile").read_text(encoding="utf-8")
DEPENDABOT = (ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8")
REQUIRED_CHECKS = {"backend-import": "Backend imports", "frontend-build": "Frontend builds"}


def _jobs(workflow: str) -> dict[str, str]:
    """Job id -> its block of text, for the two-space-indented keys under `jobs:`."""
    body = workflow.split("\njobs:\n", 1)[1]
    parts = re.split(r"(?m)^  ([A-Za-z0-9_-]+):\s*$", body)
    return dict(zip(parts[1::2], parts[2::2]))


def _image_python() -> str:
    froms = re.findall(r"(?mi)^FROM\s+python:(\d+\.\d+)", DOCKERFILE)
    assert froms, "the Dockerfile no longer starts from an official python image"
    return froms[-1]


def _image_node_major() -> str:
    froms = re.findall(r"(?mi)^FROM\s+node:(\d+)", DOCKERFILE)
    assert froms, "the Dockerfile no longer builds the frontend on an official node image"
    return froms[-1]


def test_the_checks_main_requires_keep_their_names():
    jobs = _jobs(CI)
    for job_id, check in REQUIRED_CHECKS.items():
        assert job_id in jobs, f"job {job_id} is gone: the ruleset still requires {check!r}"
        names = re.findall(r"(?m)^    name:\s*(.+?)\s*$", jobs[job_id])
        assert names == [check], f"{job_id} must stay named {check!r} (ruleset on main)"
        assert "matrix" not in jobs[job_id], f"a matrix renames the required check {check!r}"


def test_the_required_import_gate_runs_the_python_of_the_image():
    jobs = _jobs(CI)
    image = _image_python()
    gate = re.findall(r'python-version:\s*"?([\d.]+)"?', jobs["backend-import"])
    assert gate == [image], f"Backend imports runs {gate}, the image and production run {image}"
    matrix = re.search(r"(?m)^\s+python:\s*\[([^\]]*)\]", jobs["backend-tests"])
    assert matrix, "backend-tests lost its Python matrix"
    versions = re.findall(r'"([\d.]+)"', matrix.group(1))
    assert image in versions, f"the tests never run on {image}, the Python of production"


def test_ci_builds_the_frontend_with_the_node_of_the_image():
    image = _image_node_major()
    for path in sorted(WORKFLOWS.glob("*.yml")):
        for node in re.findall(r'node-version:\s*"?(\d+)', path.read_text(encoding="utf-8")):
            assert node == image, f"{path.name} builds on Node {node}, the image on Node {image}"


def test_every_action_is_pinned_to_a_commit():
    for path in sorted(WORKFLOWS.glob("*.yml")):
        for line in path.read_text(encoding="utf-8").splitlines():
            m = re.match(r"\s*(?:-\s*)?uses:\s*(\S+)(.*)$", line)
            if not m or m.group(1).startswith("./"):
                continue
            ref, rest = m.group(1), m.group(2)
            assert re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", ref), (
                f"{path.name}: {ref} is not pinned to a full commit SHA")
            assert re.match(r"\s*#\s*v\d", rest), f"{path.name}: say which release {ref} is"


def test_dependabot_never_proposes_what_requirements_cap():
    caps = {}
    for line in (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        m = re.match(r"([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?\s*(.*)", line)
        if m:
            cap = re.search(r"<\s*([\d.]+)", m.group(2))
            if cap:
                caps[m.group(1).lower()] = cap.group(1)
    assert caps.get("mcp") == "2.0", "the mcp cap moved: update this test and dependabot.yml"
    for name, version in caps.items():
        rule = re.search(
            rf"-\s*dependency-name:\s*{re.escape(name)}\s*\n\s*versions:\s*\[\s*\">=\s*{re.escape(version)}\"\s*\]",
            DEPENDABOT)
        assert rule, f"requirements.txt caps {name} below {version}, Dependabot would propose it"


def test_dependabot_watches_every_manifest_ci_installs_from():
    entries = re.findall(r"package-ecosystem:\s*(\S+)\s*\n\s*directory:\s*(\S+)", DEPENDABOT)
    assert set(entries) >= {("github-actions", "/"), ("npm", "/frontend"), ("pip", "/")}, entries
