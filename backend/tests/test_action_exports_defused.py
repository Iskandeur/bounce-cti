"""A defused node stays out of the actionable exports, whatever tag defused it.

`action_exports._DEFUSED_TAGS` is a hand-written list, and it had parted ways
with the tags the platform really writes: it named `parked_domain`, which
nothing emits, and lacked `parking`, the tag `defuse_lists.defuse_check`
returns for a parking nameserver and the agent prompt tells the agent to set on
a parked domain or its lander IP. A parked domain therefore went into
blocklists, detection rules and takedown bundles (found 2026-11-11).

The first half of this file ties the list to its two sources, the code of
`defuse_check` and the tag names the agent prompt quotes. The second half
checks the behaviour on each export.
"""
import ast
import inspect
import re

import pytest

from backend import action_exports as ax
from backend import agent_runner as ar
from backend import defuse_lists
from backend import graph_store as gs
from backend import pivot_mapping as pm

# Every tag `defuse_check` could return on 2026-11-11. The AST walk below finds
# them in the function's source; this set only proves the walk still sees
# something (a refactor away from `tags.append("…")` must fail here, loudly,
# instead of leaving the tie vacuous).
_KNOWN_DEFUSE_CHECK_TAGS = {"cdn", "blackhole", "sinkhole", "tor_exit", "dyndns", "parking"}


def _tags_defuse_check_can_emit() -> set[str]:
    """Every tag `defuse_check` can put in its result, read from its source.

    The function builds its result with `tags.append("<literal>")` and nothing
    else. Any other way of filling `tags` fails the test, so a new tag cannot
    enter unseen."""
    tree = ast.parse(inspect.getsource(defuse_lists.defuse_check))
    emitted: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and isinstance(node.func.value, ast.Name) and node.func.value.id == "tags":
            assert node.func.attr == "append", (
                f"defuse_check fills `tags` with .{node.func.attr}(): teach this test to read it")
            (arg,) = node.args
            assert isinstance(arg, ast.Constant) and isinstance(arg.value, str), (
                "defuse_check appends a tag that is not a string literal: "
                "teach this test to read it")
            emitted.add(arg.value)
        if isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for t in targets:
                if isinstance(t, ast.Name) and t.id == "tags":
                    value = node.value
                    assert isinstance(value, ast.List) and not value.elts, (
                        "defuse_check assigns `tags` something other than []: "
                        "teach this test to read it")
    return emitted


def test_the_walk_still_reads_defuse_check():
    assert _tags_defuse_check_can_emit() >= _KNOWN_DEFUSE_CHECK_TAGS


def test_every_tag_defuse_check_emits_is_defused_in_the_exports():
    missing = _tags_defuse_check_can_emit() - ax._DEFUSED_TAGS
    assert not missing, (
        f"defuse_check can emit {sorted(missing)}, which action_exports._DEFUSED_TAGS "
        "does not list: a node carrying it would ship in blocklists and takedown bundles")


@pytest.mark.parametrize("kind,value,tag", [
    ("ip", "104.16.0.1", "cdn"),
    ("ip", "0.0.0.0", "blackhole"),
    ("domain", "evil.duckdns.org", "dyndns"),
    ("ns", "ns1.sedoparking.com", "parking"),
])
def test_a_real_defuse_check_result_is_defused_in_the_exports(kind, value, tag):
    """The same tie, through the function itself on one real value per list."""
    tags = defuse_lists.defuse_check(kind, value)["tags"]
    assert tag in tags, f"{value} is no longer on the {tag} list: pick another example"
    assert ax._is_defused({"type": kind, "value": value, "tags": tags})


def test_the_noise_tags_of_the_other_modules_are_defused_in_the_exports():
    """`graph_store._NOISE_TAGS` (no malicious tag may land on them) and the
    tags `pivot_mapping.discriminating_marker` reads as defused name the same
    kind of node: real, and too shared to act on."""
    assert gs._NOISE_TAGS <= ax._DEFUSED_TAGS
    src = inspect.getsource(pm.discriminating_marker)
    m = re.search(r"bad_tags\s*=\s*\{([^}]*)\}", src)
    assert m, "discriminating_marker no longer has a bad_tags set literal"
    bad_tags = set(re.findall(r'"([a-z_0-9]+)"', m.group(1)))
    assert bad_tags, "bad_tags read as empty"
    assert bad_tags <= ax._DEFUSED_TAGS, sorted(bad_tags - ax._DEFUSED_TAGS)


def test_the_parking_tag_the_agent_prompt_asks_for_is_defused():
    """The system prompt tells the agent to tag a parked node "parking". If the
    prompt ever spells it another way, this fails until the exports follow.

    "parking_ns" is the one exception, on purpose: the prompt puts it on a seed
    whose nameservers are a parking provider's, which is one signal out of the
    two a parked verdict needs. A malicious domain can sit on such nameservers
    (eval case c12, see test_is_parked.py), and it must still be blockable."""
    quoted = set(re.findall(r'"(park[a-z_]*)"', ar.SYSTEM_PROMPT))
    assert "parking" in quoted, "the prompt no longer names the parking tag"
    assert quoted - {"parking_ns"} <= ax._DEFUSED_TAGS, sorted(quoted - ax._DEFUSED_TAGS)
    assert "parking_ns" not in ax._DEFUSED_TAGS


# ── Behaviour on each export ───────────────────────────────────────────────

_ABUSE = {"abuse_email": "abuse@host.example"}
_NODES = [
    {"id": "n1", "type": "domain", "value": "live-c2.example", "tags": ["c2"],
     "metadata": _ABUSE, "confidence": 0.8, "source": "crtsh", "created_at": 1.0},
    # A live IP too: the Cisco ACL format holds IPs only.
    {"id": "n0", "type": "ip", "value": "203.0.113.9", "tags": ["c2"],
     "metadata": {}, "confidence": 0.8, "source": "dns_resolve", "created_at": 1.5},
    # The seed the agent confirmed parked (prompt: 'Tag the seed node with "parking"').
    {"id": "n2", "type": "domain", "value": "parked-seed.example", "tags": ["parking"],
     "metadata": _ABUSE, "confidence": 0.8, "source": "rdap", "created_at": 2.0},
    # The parking lander it resolves to.
    {"id": "n3", "type": "ip", "value": "198.51.100.7", "tags": ["parking"],
     "metadata": _ABUSE, "confidence": 0.8, "source": "dns_resolve", "created_at": 3.0},
    {"id": "n4", "type": "url", "value": "http://parked-url.example/lander",
     "tags": ["parking"], "metadata": {}, "confidence": 0.8, "source": "urlscan",
     "created_at": 4.0},
    # The old spelling stays understood (see _DEFUSED_TAGS).
    {"id": "n5", "type": "domain", "value": "old-spelling.example",
     "tags": ["parked_domain"], "metadata": _ABUSE, "confidence": 0.8,
     "source": "rdap", "created_at": 5.0},
]
_PARKED = ("parked-seed.example", "198.51.100.7", "parked-url.example", "old-spelling.example")


@pytest.mark.parametrize("fmt", ["plain", "hosts", "unbound", "rpz", "palo_edl",
                                 "cisco_acl", "csv"])
def test_blocklist_leaves_parked_nodes_out(fmt):
    out = ax.render_blocklist(_NODES, fmt)
    assert "203.0.113.9" in out if fmt == "cisco_acl" else "live-c2.example" in out
    for value in _PARKED:
        assert value not in out, (fmt, value)


def test_blocklist_override_still_brings_parked_nodes_back():
    """A parked node is real-but-noisy: the analyst's checkbox keeps its meaning."""
    out = ax.render_blocklist(_NODES, "plain", include_defused=True)
    for value in _PARKED:
        assert value in out, value


@pytest.mark.parametrize("fmt", ["sigma", "snort", "yara"])
def test_detection_rules_leave_parked_nodes_out(fmt):
    out = ax.render_detection(_NODES, fmt)
    for value in _PARKED:
        assert value not in out, (fmt, value)


def test_takedown_bundle_has_no_parked_target():
    targets = {r["target"]["value"] for r in ax.render_takedown(_NODES, [], "inv")}
    assert targets == {"live-c2.example"}


def test_iter_actionable_is_what_the_eval_claims_read():
    """eval/prospective.py seals `_iter_actionable` as an arm's claims."""
    kept = {n["value"] for n in ax._iter_actionable(_NODES, ax._NETWORK_TYPES)}
    assert kept == {"live-c2.example", "203.0.113.9"}


def test_a_malicious_domain_on_parking_nameservers_still_ships():
    """Eval case c12: the nameservers are parking, the domain is a live C2."""
    nodes = [
        {"id": "s", "type": "domain", "value": "921hapudyqwdvy.com",
         "tags": ["seed", "c2", "malicious", "parking_ns"], "metadata": _ABUSE,
         "confidence": 0.9, "source": "seed", "created_at": 1.0},
        {"id": "ns", "type": "ns", "value": "ns1.renewyourname.net",
         "tags": ["parking"], "metadata": {}, "confidence": 0.8, "source": "rdap",
         "created_at": 2.0},
    ]
    assert "921hapudyqwdvy.com" in ax.render_blocklist(nodes, "plain")
    assert [r["target"]["value"] for r in ax.render_takedown(nodes, [], "inv")] \
        == ["921hapudyqwdvy.com"]
