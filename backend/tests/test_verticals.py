"""Tests for the vertical registry (backend/verticals.py).

Locks the iso-functional CTI default (roadmap invariant 4.4) and the Phase-2
OSINT lens registration.
"""
from backend import seeds, verticals
from backend import agent_runner as ar


def test_cti_and_osint_registered():
    assert set(verticals.KNOWN_VERTICALS) == {"cti", "osint"}
    assert verticals.DEFAULT_VERTICAL == "cti"


def test_cti_accepts_all_known_seed_types():
    cti = verticals.get_vertical("cti")
    assert cti.seed_types == seeds.KNOWN_SEED_TYPES
    assert cti.source_pool == "cti"
    assert cti.agent_name == "Bounce-CTI"
    assert cti.prompt_block == ""   # CTI stays byte-for-byte the {core} template


def test_unknown_vertical_falls_back_to_cti():
    for bad in [None, "", "dd", "nonsense", "OSINTT"]:
        assert verticals.normalise(bad) == "cti"
        assert verticals.get_vertical(bad).name == "cti"


def test_osint_vertical_is_a_lens_over_the_cti_pool():
    o = verticals.get_vertical("osint")
    assert o.name == "osint"
    assert o.agent_name == "Bounce-OSINT"
    # v1 reuses the CTI pool/namespace so allowedTools + call-counting stay valid
    assert o.source_pool == "cti"
    assert verticals.source_pool_module(o.source_pool) == "cti_mcp"
    assert o.prompt_block != ""          # the OSINT lens block
    assert "OSINT" in o.prompt_block
    assert set(o.seed_types) <= set(seeds.KNOWN_SEED_TYPES)


def test_is_known():
    assert verticals.is_known("cti") is True
    assert verticals.is_known("CTI") is True       # case-insensitive
    assert verticals.is_known("osint") is True
    assert verticals.is_known("OSINT") is True
    assert verticals.is_known("dd") is False
    assert verticals.is_known(None) is False


def test_source_pool_module_cti():
    assert verticals.source_pool_module("cti") == "cti_mcp"
    # Unknown pools fall back to the cti module so config generation never breaks.
    assert verticals.source_pool_module("nonexistent") == "cti_mcp"


def test_prompt_builder_applies_osint_lens():
    out = ar.build_system_prompt(ar.SYSTEM_PROMPT, verticals.OSINT)
    assert "Bounce-OSINT" in out
    assert "Bounce-CTI" not in out
    assert "OSINT LENS" in out
    # CTI build remains byte-for-byte the template (regression guard)
    assert ar.build_system_prompt(ar.SYSTEM_PROMPT, verticals.CTI) == ar.SYSTEM_PROMPT


def test_build_allowed_tools_is_namespace_aware():
    # cti pool → unchanged (iso-functional for CTI and OSINT-v1)
    assert ar.build_allowed_tools("cti") == ar._ALLOWED_TOOLS
    # a dedicated pool rewrites only the source prefix; graph tools untouched
    osint_tools = ar.build_allowed_tools("osint")
    assert "mcp__osint__crtsh_subdomains" in osint_tools
    assert "mcp__cti__" not in osint_tools
    assert "mcp__graph__add_node" in osint_tools   # graph namespace is pool-agnostic
    assert osint_tools.count(",") == ar._ALLOWED_TOOLS.count(",")  # same tool count


def test_allowed_seed_types_matches_registry():
    # The original CTI set plus the OSINT people seeds added in Phase 2.
    expected = {"domain", "ip", "hash", "url", "jarm", "asn", "command_line",
                "executable_name", "email", "wallet_address", "username", "phone"}
    assert set(seeds.KNOWN_SEED_TYPES) == expected
