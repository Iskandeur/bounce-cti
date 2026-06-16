"""Tests for the vertical registry (backend/verticals.py).

Locks the iso-functional CTI default (roadmap invariant 4.4): until OSINT/DD are
registered, only ``cti`` exists and any unknown input resolves to it.
"""
from backend import seeds, verticals


def test_only_cti_registered_for_now():
    assert verticals.KNOWN_VERTICALS == ("cti",)
    assert verticals.DEFAULT_VERTICAL == "cti"


def test_cti_accepts_all_known_seed_types():
    cti = verticals.get_vertical("cti")
    assert cti.seed_types == seeds.KNOWN_SEED_TYPES
    assert cti.source_pool == "cti"
    assert cti.agent_name == "Bounce-CTI"


def test_unknown_vertical_falls_back_to_cti():
    for bad in [None, "", "osint", "dd", "nonsense", "CTI"]:
        assert verticals.normalise(bad) == "cti"
        assert verticals.get_vertical(bad).name == "cti"


def test_is_known():
    assert verticals.is_known("cti") is True
    assert verticals.is_known("CTI") is True   # case-insensitive
    assert verticals.is_known("osint") is False
    assert verticals.is_known(None) is False


def test_source_pool_module_cti():
    # The cti pool mounts the cti_mcp server module under the mcp__cti__* namespace.
    assert verticals.source_pool_module("cti") == "cti_mcp"
    assert verticals.get_vertical("cti").source_pool == "cti"
    # Unknown pools fall back to the cti module so config generation never breaks.
    assert verticals.source_pool_module("nonexistent") == "cti_mcp"


def test_allowed_seed_types_matches_registry():
    # main.ALLOWED_SEED_TYPES is derived from the registry; the historical
    # hand-maintained set must stay equal to it.
    historical = {"domain", "ip", "hash", "url", "jarm", "asn", "command_line",
                  "executable_name", "email", "wallet_address", "username"}
    assert set(seeds.KNOWN_SEED_TYPES) == historical
