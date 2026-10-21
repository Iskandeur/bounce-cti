"""eval/baseline.py — the same model without Bounce-CTI, scored by the same scorer.

These tests run offline: no CLI, no network. They pin the three promises a
reader of the baseline numbers relies on: the bare run really is bare, its
answer is scored by eval/scorer.py like an investigation graph, and it cannot
make its own attributions "traceable" by writing them itself.
"""
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("eval_baseline", ROOT / "eval" / "baseline.py")
bl = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = bl
_spec.loader.exec_module(bl)

CASE2 = next(c for c in bl.CASES if c["case_id"] == 2)


def _write(d: Path, graph: dict, transcript: dict) -> Path:
    d.mkdir(parents=True, exist_ok=True)
    (d / "graph.json").write_text(json.dumps(graph))
    (d / "transcript.json").write_text(json.dumps(transcript))
    return d


ANSWER_CASE2 = {
    "verdict": "malicious",
    "summary": "Stagecomp loader of MuddyWater beaconing to its C2.",
    "attribution": [{"name": "MuddyWater", "kind": "threat_actor", "confidence": 0.8,
                     "basis": "Rapid7 report"}],
    "indicators": [
        {"type": "domain", "value": "moonzonet[.]com", "relation": "contacts",
         "malicious": True, "basis": "C2", "source_url": "https://example.org/report"},
        {"type": "ipv4", "value": "172.86.126.208", "linked_to": "moonzonet.com",
         "relation": "resolves_to", "malicious": True},
    ],
}


def test_the_bare_run_gets_no_bounce_tool_and_no_mcp_server():
    mem = bl.build_cmd("claude", "memory", "claude-opus-5", "p")
    web = bl.build_cmd("claude", "web", "claude-opus-5", "p")
    assert mem[mem.index("--tools") + 1] == ""
    assert web[web.index("--tools") + 1] == "WebSearch,WebFetch"
    # Offered is not granted: in -p mode an offered tool that is not allowed is
    # refused on every call (the first web run of 2026-10-21 got nothing else).
    assert web[web.index("--allowedTools") + 1] == "WebSearch,WebFetch"
    assert "--allowedTools" not in mem
    for cmd in (mem, web):
        assert "--strict-mcp-config" in cmd
        assert json.loads(cmd[cmd.index("--mcp-config") + 1]) == {"mcpServers": {}}
        assert cmd[cmd.index("--model") + 1] == "claude-opus-5"
        assert "--no-session-persistence" in cmd and "--disable-slash-commands" in cmd


def test_unknown_arm_is_refused():
    try:
        bl.build_cmd("claude", "bounce", "m", "p")
    except ValueError:
        return
    raise AssertionError("an unknown arm must not run")


def test_the_child_env_keeps_the_cli_login_and_drops_what_changes_the_run():
    env = bl.child_env({"HOME": "/h", "PATH": "/p", "CLAUDE_CODE_OAUTH_TOKEN": "t",
                        "ANTHROPIC_API_KEY": "k", "CLAUDE_CODE_EFFORT_LEVEL": "max",
                        "CLAUDECODE": "1", "XDG_CONFIG_HOME": "/x", "SOME_SECRET": "s"})
    assert env == {"HOME": "/h", "PATH": "/p", "CLAUDE_CODE_OAUTH_TOKEN": "t",
                   "XDG_CONFIG_HOME": "/x"}


def test_the_prompt_is_the_same_brief_for_both_arms_except_the_tools_line():
    mem = bl.build_prompt(CASE2, "memory")
    web = bl.build_prompt(CASE2, "web")
    assert CASE2["seed_value"] in mem and CASE2["seed_value"] in web
    assert mem.replace(bl._TOOLS_LINE["memory"], "") == web.replace(bl._TOOLS_LINE["web"], "")
    # No ground truth leaks into the brief.
    for _, value in CASE2["gt_nodes"][1:]:
        assert value not in mem


def test_extract_answer_reads_a_fence_or_a_trailing_object_and_survives_braces_in_strings():
    obj = {"verdict": "benign", "summary": "a {weird} value", "indicators": [], "attribution": []}
    fenced = "Here is my answer.\n```json\n" + json.dumps(obj) + "\n```"
    trailing = "Prose with {a brace} first.\n\n" + json.dumps(obj)
    assert bl.extract_answer(fenced) == obj
    assert bl.extract_answer(trailing) == obj
    assert bl.extract_answer("no json at all") is None
    assert bl.extract_answer("") is None


def test_parse_stream_collects_model_tools_results_and_the_final_text():
    lines = [
        json.dumps({"type": "system", "subtype": "init", "model": "claude-opus-5",
                    "claude_code_version": "2.1.301", "tools": ["WebSearch", "WebFetch"]}),
        json.dumps({"type": "assistant", "message": {"content": [
            {"type": "tool_use", "id": "t1", "name": "WebFetch",
             "input": {"url": "https://www.rapid7.com/blog/x"}}]}}),
        json.dumps({"type": "user", "message": {"content": [
            {"type": "tool_result", "tool_use_id": "t1",
             "content": [{"type": "text", "text": "MuddyWater uses moonzonet.com"}]}]}}),
        "not json",
        json.dumps({"type": "result", "subtype": "success", "result": "final", "num_turns": 3,
                    "is_error": False}),
    ]
    p = bl.parse_stream(lines)
    assert p["model"] == "claude-opus-5" and p["tools"] == ["WebSearch", "WebFetch"]
    assert p["tool_results"][0]["text"] == "MuddyWater uses moonzonet.com"
    assert p["final"] == "final" and p["num_turns"] == 3
    assert bl.hosts_read(p) == ["www.rapid7.com"]


def test_a_refused_tool_call_is_counted_and_reads_no_page():
    p = {"tool_calls": [{"id": "a", "name": "WebFetch", "input": {"url": "https://www.virustotal.com/x"}},
                        {"id": "b", "name": "WebFetch", "input": {"url": "https://bazaar.abuse.ch/y"}}],
         "tool_results": [{"id": "a", "text": "Claude requested permissions to use WebFetch, but "
                                              "you haven't granted it yet."},
                          {"id": "b", "text": "sample page"}]}
    assert bl.permission_denials(p) == 1
    assert bl.hosts_read(p) == ["bazaar.abuse.ch"]


def test_a_page_about_permissions_is_a_page_read_not_a_refusal():
    p = {"tool_calls": [{"id": "a", "name": "WebFetch", "input": {"url": "https://blog.example/x"}}],
         "tool_results": [{"id": "a", "text": "The dropper exits with 'permission denied' when..."}]}
    assert bl.permission_denials(p) == 0
    assert bl.hosts_read(p) == ["blog.example"]


def test_search_results_count_as_seen_even_with_no_page_fetched():
    p = {"tool_calls": [{"id": "s", "name": "WebSearch", "input": {"query": "3df9dcc45d2a"}}],
         "tool_results": [{"id": "s", "text": 'Links: [{"title": "Muddying the Tracks", '
                                              '"url": "https://www.rapid7.com/blog/post/x"}]'}]}
    assert bl.hosts_read(p) == []
    assert bl.hosts_seen(p) == ["www.rapid7.com"]


def test_answer_key_is_the_ground_truth_source_not_any_page():
    # case 3's ground truth comes from The DFIR Report
    assert bl.answer_key(3, ["thedfirreport.com", "x.org"], []) == "fetched"
    assert bl.answer_key(3, ["x.org"], ["www.thedfirreport.com"]) == "in search results"
    assert bl.answer_key(3, ["virustotal.com"], ["notthedfirreport.com"]) == "not reached"
    assert bl.answer_key(999, ["thedfirreport.com"], []) is None
    # every positive case has its source declared
    assert all(c["case_id"] in bl.GT_SOURCE_HOSTS for c in bl.CASES)


def test_to_graph_has_the_seed_refangs_values_and_links_indicators():
    g = bl.to_graph(CASE2, ANSWER_CASE2)
    by_value = {n["value"]: n for n in g["nodes"]}
    assert CASE2["seed_value"] in by_value
    assert by_value["moonzonet.com"]["type"] == "domain"
    assert "malicious" in by_value["moonzonet.com"]["tags"]
    assert by_value["172.86.126.208"]["type"] == "ip"
    assert by_value["MuddyWater"]["type"] == "actor"
    ids = {n["value"]: n["id"] for n in g["nodes"]}
    pairs = {(e["src"], e["dst"]) for e in g["edges"]}
    assert (ids["moonzonet.com"], ids["172.86.126.208"]) in pairs      # linked_to honoured
    assert (ids[CASE2["seed_value"]], ids["moonzonet.com"]) in pairs   # default: from the seed
    report = next(n for n in g["nodes"] if n["value"] == "investigation_summary")
    assert "moonzonet.com" in report["metadata"]["indicators"]


def test_a_citation_the_model_wrote_is_not_provenance():
    g = bl.to_graph(CASE2, ANSWER_CASE2)
    for n in g["nodes"]:
        assert not bl.scorer._has_provenance(n), n


def test_the_baseline_is_scored_by_the_scorer_itself(tmp_path):
    d = _write(tmp_path / "web" / "c02", bl.to_graph(CASE2, ANSWER_CASE2), {"entries": []})
    r = bl.score_dir("2", d)
    # seed + moonzonet + 172.86.126.208 + muddywater = 4 of the 11 ground-truth nodes
    assert r["nr_hits"] == 4 and r["nr_total"] == len(CASE2["gt_nodes"])
    assert r["mk"] == 100 and r["actor_hit"] is True
    assert r["rec_ungated"] is not None and r["n_attribution"] == 1


def test_memory_attributions_are_untraceable_and_web_ones_traceable_only_from_what_was_read(tmp_path):
    graph = bl.to_graph(CASE2, ANSWER_CASE2)
    memory = bl.score_dir("2", _write(tmp_path / "m" / "c02", graph, {"entries": []}))
    assert memory["hallucinations"] == [["actor", "MuddyWater"]]
    # A search query that names the actor is the model citing itself: still untraceable.
    queried = bl.to_transcript({"tool_calls": [{"id": "t1", "name": "WebSearch",
                                                 "input": {"query": "MuddyWater moonzonet"}}],
                                "tool_results": [{"id": "t1", "text": "no relevant result"}]})
    r = bl.score_dir("2", _write(tmp_path / "q" / "c02", graph, queried))
    assert r["hallucinations"] == [["actor", "MuddyWater"]]
    read = bl.to_transcript({"tool_calls": [{"id": "t1", "name": "WebFetch", "input": {}}],
                             "tool_results": [{"id": "t1", "text": "Rapid7: MuddyWater C2"}]})
    r = bl.score_dir("2", _write(tmp_path / "w" / "c02", graph, read))
    assert r["hallucinations"] == []


def test_negative_cases_reuse_the_scorer_restraint_rule(tmp_path):
    neg, negative, dname = bl.case_for("N1")
    assert negative and dname == "n01"
    benign = {"verdict": "benign", "summary": "Cloudflare anycast", "attribution": [],
              "indicators": [{"type": "asn", "value": "AS13335", "malicious": False}]}
    r = bl.score_dir("N1", _write(tmp_path / "b" / dname, bl.to_graph(neg, benign), {"entries": []}))
    assert r["rst"] == 100
    accused = dict(benign, attribution=[{"name": "Lazarus", "kind": "actor"}])
    r = bl.score_dir("N1", _write(tmp_path / "a" / dname, bl.to_graph(neg, accused), {"entries": []}))
    assert r["rst"] == 0


def test_the_ground_truth_is_this_checkout_s_cases_module():
    assert bl.scorer.CASES is bl.CASES
    assert Path(sys.modules["cases"].__file__).resolve() == ROOT / "eval" / "cases.py"


def test_compare_renders_every_side_and_the_hosts_the_web_arm_read(tmp_path):
    out = tmp_path / "run"
    g = bl.to_graph(CASE2, ANSWER_CASE2)
    for side in ("memory", "web"):
        d = _write(out / side / "c02", g, {"entries": []})
        (d / "run.json").write_text(json.dumps({"tool_calls": ["WebFetch"],
                                                "hosts_read": ["www.rapid7.com"]}))
    bounce = tmp_path / "bounce"
    _write(bounce / "c02", g, {"entries": []})
    sides = bl.compare(out, bounce, ["2"])
    assert set(sides) == {"memory", "web", "bounce"}
    md = bl.render_md(sides, ["2"], "t", [])
    assert "Bounce-CTI" in md and "www.rapid7.com" in md
    slim = bl._slim(sides)
    json.dumps(slim)  # serialisable
    assert slim["web"]["2"]["run"]["hosts_read"] == ["www.rapid7.com"]
