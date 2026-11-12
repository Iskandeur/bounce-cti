"""The deploy script of `.github/workflows/deploy.yml`, run for real in a sandbox.

That script runs on the production server at every push to `main`, and nowhere
else before. This file takes it out of the workflow as it is written and runs
it on a throwaway clone, with `sudo`, `npm`, `pip` and `sleep` replaced by stubs
that log what they were asked. Each test pushes a commit to the sandbox's
`origin`, runs the script, and reads which steps ran.

What it pins:

* The steps follow what changed. A restart ends every investigation in flight,
  so it is kept for paths the running service loads; a path nobody classified
  restarts. The bundle is rebuilt for `frontend/` minus the browser suite. The
  list of paths that restart nothing (`INERT`) is checked against the files of
  this repository, so a new top-level file has to be classified.
* A failed build fails the deploy. `cd … && npm ci && npm run build` inside an
  `if` let a failed `npm ci` go on to the restart and to "Deploy OK": `set -e`
  does not stop on a failure inside an `&&` list.
* A deploy that stops before its restart puts the checkout back where it was.
  The service then runs code that is still on disk (the processes it spawns for
  each investigation read `backend/` from disk), and the next run decides its
  steps from the same starting point, whatever its own commit touches.
* Deploys run one at a time (`concurrency`). Until 2026-11-12 two pushes five
  seconds apart ran two scripts in the same directory, the second resetting
  the checkout while the first was building.

Plain text parsing of the workflow, like test_ci_workflows.py.
"""
import os
import re
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
DEPLOY = (ROOT / ".github" / "workflows" / "deploy.yml").read_text(encoding="utf-8")
APP_LINE = 'APP="/opt/bounce-cti"'
GIT = shutil.which("git")

pytestmark = pytest.mark.skipif(
    shutil.which("bash") is None or GIT is None,
    reason="the deploy script needs bash and git to run")


def _script() -> str:
    """The `script: |` block of the deploy step, dedented."""
    lines = DEPLOY.splitlines()
    starts = [i for i, line in enumerate(lines) if line.strip() == "script: |"]
    assert len(starts) == 1, "deploy.yml no longer has exactly one `script: |` block"
    key_indent = len(lines[starts[0]]) - len(lines[starts[0]].lstrip())
    body = []
    for line in lines[starts[0] + 1:]:
        if line.strip() and len(line) - len(line.lstrip()) <= key_indent:
            break
        body.append(line)
    script = textwrap.dedent("\n".join(body)) + "\n"
    assert APP_LINE in script, f"the script no longer sets {APP_LINE}: update this test"
    return script


def _inert_pattern() -> str:
    m = re.search(r"(?m)^INERT='(.+)'$", _script())
    assert m, "the script no longer sets INERT='…' on one line: update this test"
    return m.group(1)


# Files of the sandbox repository: one of each kind the script tells apart.
_TREE = [
    "README.md", "ARCHITECTURE.md", "requirements.txt", "requirements-dev.txt",
    "run_mcp.py", "mcp.json", "deploy.sh", "LICENSE", "Dockerfile",
    "docker-compose.yml", ".gitignore", ".dockerignore", ".env.example",
    "media/demo.gif",
    "backend/main.py", "backend/config.py", "backend/mcp_servers/graph_mcp.py",
    "backend/sources/rdap.py", "backend/tests/test_x.py",
    "frontend/package.json", "frontend/index.html", "frontend/vite.config.js",
    "frontend/src/App.jsx", "frontend/public/icon.svg", "frontend/README.md",
    "frontend/playwright.config.js", "frontend/e2e/a.spec.js", "frontend/e2e/README.md",
    "eval/tool.py", "runs/r1/scorecard.md", ".github/workflows/ci.yml",
]

_STUBS = {
    # `status` answers from the service_state file, `restart` brings the service
    # up unless a test asked it not to.
    "sudo": """\
        echo "sudo $*" >> "$SANDBOX/calls.log"
        case "$*" in
          *status*) [ "$(cat "$SANDBOX/service_state")" = up ] ; exit $? ;;
          *restart*) [ -f "$SANDBOX/restart_fails" ] || echo up > "$SANDBOX/service_state" ;;
        esac
        """,
    # A file named npm_<subcommand>_fails makes that npm command fail (ci, run).
    "npm": """\
        echo "npm $*" >> "$SANDBOX/calls.log"
        [ ! -f "$SANDBOX/npm_$1_fails" ]
        """,
    "sleep": "exit 0\n",
    # The real git, except `diff` when a test asks it to fail.
    "git": f"""\
        if [ -f "$SANDBOX/git_diff_fails" ]; then
          for arg in "$@"; do [ "$arg" = diff ] && exit 128; done
        fi
        exec "{GIT}" "$@"
        """,
}


class Sandbox:
    """An `origin`, a clone to commit from (`work`) and the server's clone
    (`app`), under `tmp`. Built with git once per session, then copied for each
    test: `template` is that first sandbox."""

    def __init__(self, tmp: Path, template: "Sandbox | None" = None):
        self.tmp = tmp
        self.origin, self.work, self.app = tmp / "origin.git", tmp / "work", tmp / "app"
        self.calls = tmp / "calls.log"
        self.pending = self.app / ".git" / "bounce-deploy-pending"
        bin_dir = tmp / "bin"
        self.env = {
            **os.environ, "SANDBOX": str(tmp), "HOME": str(tmp),
            "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
            "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
            "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid",
        }
        self.script = tmp / "deploy-script.sh"
        if template is not None:
            shutil.copytree(template.tmp, tmp, dirs_exist_ok=True, symlinks=True)
            # The two clones name their origin by its absolute path.
            for clone in (self.work, self.app):
                config = clone / ".git" / "config"
                config.write_text(config.read_text().replace(str(template.tmp), str(tmp)))
            self.script.write_text(self.script.read_text().replace(str(template.tmp), str(tmp)))
            return

        self.git(tmp, "init", "-q", "--bare", "-b", "main", str(self.origin))
        self.git(tmp, "clone", "-q", str(self.origin), str(self.work))
        self.git(self.work, "checkout", "-q", "-b", "main")
        self.push(_TREE)
        self.git(tmp, "clone", "-q", "-b", "main", str(self.origin), str(self.app))

        stubs = dict(_STUBS, pip='echo "pip $*" >> "$SANDBOX/calls.log"\n'
                                 '[ ! -f "$SANDBOX/pip_fails" ]\n')
        for name, body in stubs.items():
            # pip is called by its path in the app's virtualenv, the rest by name.
            path = (self.app / ".venv" / "bin" if name == "pip" else bin_dir) / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("#!/bin/sh\n" + textwrap.dedent(body), encoding="utf-8")
            path.chmod(0o755)
        (tmp / "service_state").write_text("up\n")
        self.script.write_text(_script().replace(APP_LINE, f'APP="{self.app}"'), encoding="utf-8")

    def git(self, cwd: Path, *args: str) -> str:
        return subprocess.run([GIT, *args], cwd=cwd, env=self.env, check=True,
                              capture_output=True, text=True).stdout.strip()

    def flag(self, name: str, on: bool = True) -> None:
        """Switch a failure the stubs look for (npm_ci_fails, restart_fails…)."""
        path = self.tmp / name
        if on:
            path.write_text("")
        else:
            path.unlink()

    def service(self, state: str) -> None:
        (self.tmp / "service_state").write_text(state + "\n")

    def push(self, paths: "list[str] | None" = None) -> str:
        """Push `work` to origin/main, after one commit that touches `paths`
        (an empty list = an empty commit; None = push what `work` already has)."""
        if paths is not None:
            for p in paths:
                f = self.work / p
                f.parent.mkdir(parents=True, exist_ok=True)
                with f.open("a", encoding="utf-8") as fh:
                    fh.write("x\n")
            self.git(self.work, "add", "-A")
            self.git(self.work, "commit", "-q", "--allow-empty", "-m", "change")
        self.git(self.work, "push", "-q", "origin", "main")
        return self.git(self.work, "rev-parse", "HEAD")

    def deploy(self):
        """Run the script. Returns (process, steps): the steps among pip / npm /
        restart that ran. `npm` means the install; the tests that care about
        the build read the log."""
        self.calls.write_text("")
        proc = subprocess.run(["bash", str(self.script)], env=self.env,
                              capture_output=True, text=True)
        log = self.calls.read_text()
        steps = set()
        if "pip install" in log:
            steps.add("pip")
        if "npm ci" in log:
            steps.add("npm")
        if "systemctl restart bounce-cti" in log:
            steps.add("restart")
        return proc, steps

    def head(self) -> str:
        return self.git(self.app, "rev-parse", "HEAD")


@pytest.fixture(scope="session")
def _template(tmp_path_factory):
    return Sandbox(tmp_path_factory.mktemp("deploy-template"))


@pytest.fixture
def sb(tmp_path, _template):
    return Sandbox(tmp_path, _template)


# ── The steps follow what changed ───────────────────────────────────────────

@pytest.mark.parametrize("paths, expected", [
    # Nothing the service loads, nothing the bundle is built from.
    (["README.md"], set()),
    (["ARCHITECTURE.md", "backend/tests/test_x.py", ".github/workflows/ci.yml",
      "eval/tool.py", "runs/r1/scorecard.md", "requirements-dev.txt"], set()),
    ([".gitignore", ".dockerignore", ".env.example", "Dockerfile", "docker-compose.yml",
      "LICENSE", "media/demo.gif"], set()),
    (["frontend/e2e/a.spec.js", "frontend/e2e/README.md", "frontend/README.md",
      "frontend/playwright.config.js"], set()),
    ([], set()),  # an empty commit
    # The bundle, which the service serves from disk: rebuilt, no restart.
    (["frontend/src/App.jsx"], {"npm"}),
    (["frontend/package.json"], {"npm"}),
    (["frontend/index.html"], {"npm"}),
    (["frontend/vite.config.js"], {"npm"}),
    (["frontend/public/icon.svg"], {"npm"}),
    (["frontend/e2e-notes/a.js"], {"npm"}),  # not the e2e/ directory
    (["frontend/src/café.jsx"], {"npm"}),    # git would quote this path by default
    (["frontend/e2e/a.spec.js", "frontend/src/App.jsx"], {"npm"}),
    # What the service loads.
    (["backend/main.py"], {"restart"}),
    (["backend/mcp_servers/graph_mcp.py"], {"restart"}),
    (["backend/sources/rdap.py"], {"restart"}),
    (["run_mcp.py"], {"restart"}),
    (["mcp.json"], {"restart"}),
    (["requirements.txt"], {"pip", "restart"}),
    (["README.md", "backend/config.py", "frontend/src/App.jsx"], {"npm", "restart"}),
    # Paths nobody classified count as code.
    (["a_new_tool.py"], {"restart"}),
    (["newdir/notes.md"], {"restart"}),
    (["README.md.py"], {"restart"}),
    (["deploy.sh"], {"restart"}),
])
def test_the_steps_follow_what_changed(sb, paths, expected):
    commit = sb.push(paths)
    proc, steps = sb.deploy()
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert steps == expected, proc.stdout
    assert ("npm run build" in sb.calls.read_text()) == ("npm" in expected)
    assert sb.head() == commit
    assert not sb.pending.exists()


@pytest.mark.parametrize("old, new, expected", [
    # Paired as a rename, git would list the new path only.
    ("backend/config.py", "eval/config.py", {"restart"}),
    ("frontend/src/App.jsx", "frontend/e2e/App.jsx", {"npm"}),
])
def test_a_file_moved_to_an_inert_place_still_counts_where_it_was(sb, old, new, expected):
    (sb.work / old).write_text("a file long enough for git to pair the two paths\n" * 20)
    sb.git(sb.work, "commit", "-q", "-am", "content")
    sb.push()
    assert sb.deploy()[0].returncode == 0
    (sb.work / new).parent.mkdir(parents=True, exist_ok=True)
    sb.git(sb.work, "mv", old, new)
    sb.git(sb.work, "commit", "-q", "-m", "move")
    sb.push()
    proc, steps = sb.deploy()
    assert proc.returncode == 0 and steps == expected, proc.stdout


def test_nothing_new_runs_nothing(sb):
    sb.push(["backend/main.py"])
    assert sb.deploy()[0].returncode == 0
    proc, steps = sb.deploy()
    assert proc.returncode == 0 and "No new commit" in proc.stdout
    assert steps == set()


def test_the_inert_list_matches_the_files_of_this_repository():
    """Every tracked file is classified. What restarts the service is `backend/`
    without its tests, plus the four files named here. A new top-level file
    fails this test until it is added to INERT in deploy.yml (the service never
    loads it) or to `code` below (it does)."""
    code = {"run_mcp.py", "mcp.json", "requirements.txt", "deploy.sh"}
    listing = subprocess.run([GIT, "ls-files"], cwd=ROOT, capture_output=True, text=True)
    if listing.returncode != 0:
        pytest.skip("not a git checkout")
    tracked = [p for p in listing.stdout.split("\n") if p]
    assert len(tracked) > 100, "git ls-files returned next to nothing"
    # The pattern as grep reads it, since grep is what the script runs.
    restarts = set(subprocess.run(
        ["grep", "-vE", _inert_pattern()], input="\n".join(tracked) + "\n",
        capture_output=True, text=True).stdout.split("\n")) - {""}

    backend = {p for p in tracked
               if p.startswith("backend/") and not p.startswith("backend/tests/")}
    assert backend, "no tracked file under backend/"
    assert backend <= restarts, sorted(backend - restarts)[:10]
    assert restarts - backend == code, sorted((restarts - backend) ^ code)


# ── A deploy that stops before the restart ──────────────────────────────────

@pytest.mark.parametrize("failure", ["npm_ci_fails", "npm_run_fails"])
def test_a_failed_build_fails_the_deploy_and_puts_the_checkout_back(sb, failure):
    before = sb.head()
    sb.push(["backend/main.py", "frontend/src/App.jsx"])
    sb.flag(failure)
    proc, steps = sb.deploy()
    assert proc.returncode != 0, "a failed build did not fail the deploy"
    assert "restart" not in steps and "Deploy OK" not in proc.stdout
    # The service was not restarted: it must find on disk the code it runs.
    assert sb.head() == before
    assert not sb.pending.exists()


def test_a_failed_pip_install_stops_before_the_build_and_the_restart(sb):
    before = sb.head()
    sb.push(["requirements.txt", "frontend/src/App.jsx"])
    sb.flag("pip_fails")
    proc, steps = sb.deploy()
    assert proc.returncode != 0 and steps == {"pip"}
    assert sb.head() == before


def test_a_failed_deploy_is_redone_by_the_next_push_whatever_it_touches(sb):
    sb.push(["requirements.txt", "backend/main.py", "frontend/src/App.jsx"])
    sb.flag("npm_ci_fails")
    assert sb.deploy()[0].returncode != 0

    sb.flag("npm_ci_fails", on=False)
    last = sb.push(["README.md"])
    proc, steps = sb.deploy()
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert steps == {"pip", "npm", "restart"}
    assert sb.head() == last


def test_a_failed_deploy_is_redone_by_running_the_job_again(sb):
    last = sb.push(["backend/main.py", "frontend/src/App.jsx"])
    sb.flag("npm_run_fails")
    assert sb.deploy()[0].returncode != 0
    sb.flag("npm_run_fails", on=False)
    proc, steps = sb.deploy()
    assert proc.returncode == 0 and steps == {"npm", "restart"}
    assert sb.head() == last


def test_a_diff_that_cannot_be_read_fails_the_deploy(sb):
    """An unreadable list of changes must never be read as "nothing to do"."""
    before = sb.head()
    sb.push(["backend/main.py"])
    sb.flag("git_diff_fails")
    proc, steps = sb.deploy()
    assert proc.returncode != 0 and steps == set()
    assert "Deploy OK" not in proc.stdout
    sb.flag("git_diff_fails", on=False)
    assert sb.head() == before


def test_a_claude_cli_that_is_gone_stops_the_deploy_before_the_checkout_moves(sb):
    before = sb.head()
    (sb.app / ".env").write_text("CLAUDE_BIN=/nonexistent/claude\n")
    sb.push(["backend/main.py"])
    proc, steps = sb.deploy()
    assert proc.returncode != 0 and steps == set()
    assert sb.head() == before and not sb.pending.exists()


def test_a_run_killed_outright_is_redone_by_the_next_one(sb):
    """Killed with no chance to clean up (the server rebooted mid-build): the
    checkout is on the new commit, nothing was built or restarted, and the
    file that names where that run started is still there."""
    before = sb.head()
    sb.push(["backend/main.py", "frontend/src/App.jsx"])
    sb.git(sb.app, "fetch", "-q", "origin", "main")
    sb.git(sb.app, "reset", "-q", "--hard", "origin/main")
    sb.pending.write_text(before + "\n")

    last = sb.push(["README.md"])
    proc, steps = sb.deploy()
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert steps == {"npm", "restart"}
    assert sb.head() == last and not sb.pending.exists()


def test_a_pending_file_that_names_no_commit_is_ignored(sb):
    sb.pending.write_text("not a commit\n")
    commit = sb.push(["backend/main.py"])
    proc, steps = sb.deploy()
    assert proc.returncode == 0 and steps == {"restart"}
    assert sb.head() == commit and not sb.pending.exists()


def test_a_checkout_reset_by_hand_is_caught_up(sb):
    """The rollback of ARCHITECTURE.md: `git reset --hard <good commit>` on the
    server, then a restart by hand. The service runs the old code, and the next
    deploy brings the newer backend back on disk: it must restart, even if its
    own commit only touches docs. A failed build in between changes nothing."""
    good = sb.push(["README.md"])
    assert sb.deploy()[0].returncode == 0
    sb.push(["backend/main.py"])
    assert sb.deploy()[1] == {"restart"}
    sb.git(sb.app, "reset", "-q", "--hard", good)

    sb.push(["README.md", "frontend/src/App.jsx"])
    sb.flag("npm_ci_fails")
    assert sb.deploy()[0].returncode != 0
    assert sb.head() == good

    sb.flag("npm_ci_fails", on=False)
    proc, steps = sb.deploy()
    assert proc.returncode == 0 and steps == {"npm", "restart"}


# ── The service ─────────────────────────────────────────────────────────────

def test_a_stopped_service_is_started_whatever_changed(sb):
    sb.service("down")
    sb.push(["README.md"])
    proc, steps = sb.deploy()
    assert proc.returncode == 0 and steps == {"restart"}, proc.stdout


def test_a_stopped_service_is_started_with_no_new_commit(sb):
    sb.service("down")
    proc, steps = sb.deploy()
    assert proc.returncode == 0 and steps == {"restart"}, proc.stdout


def test_a_service_that_does_not_come_back_fails_the_deploy(sb):
    """The new code is the one the service was restarted on: the checkout stays,
    and the next run starts everything again from where this one started."""
    before = sb.head()
    commit = sb.push(["backend/main.py", "frontend/src/App.jsx"])
    sb.flag("restart_fails")
    sb.service("down")
    proc, steps = sb.deploy()
    assert proc.returncode != 0 and "ERROR" in proc.stdout and "Deploy OK" not in proc.stdout
    assert sb.head() == commit
    assert sb.pending.read_text().strip() == before

    sb.flag("restart_fails", on=False)
    proc, steps = sb.deploy()
    assert proc.returncode == 0 and steps == {"npm", "restart"}
    assert not sb.pending.exists()


# ── The workflow around the script ──────────────────────────────────────────

def test_deploys_run_one_at_a_time():
    """A top-level concurrency group, and no cancelling of the run in flight:
    killing the SSH step halfway would leave the server between two states."""
    m = re.search(r"(?m)^concurrency:\n((?:  .*\n)+)", DEPLOY)
    assert m, "deploy.yml has no top-level `concurrency:` block"
    block = m.group(1)
    assert re.search(r"(?m)^  group: \S+$", block), block
    assert re.search(r"(?m)^  cancel-in-progress: false$", block), block
    assert "${{" not in block, "a group that varies per run queues nothing"
