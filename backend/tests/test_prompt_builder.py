"""Tests for the {core}+{vertical} system-prompt builder
(agent_runner.build_system_prompt).

Locks the roadmap invariant 4.4 guarantee: for the CTI vertical the builder is
a byte-for-byte identity over every phase template, so the multi-vertical seam
cannot silently change the production CTI agent prompt.

Also locks the context-pool addendum (backend/context_pool.py): it must appear
exactly when the pool is mounted for the vertical and never otherwise — in
particular never for CTI under the default configuration, which is what keeps
the byte-for-byte invariant true in production.
"""
import pytest

from backend import agent_runner as ar
from backend import verticals


# Every phase system-prompt template the builder is applied to.
_CTI_TEMPLATES = [
    ar.SYSTEM_PROMPT,
    ar._FOLLOWUP_SYSTEM_PROMPT,
    ar._HYPOTHESIS_SYSTEM_PROMPT,
    ar._LESSONS_LEARNED_SYSTEM_PROMPT,
    ar._PIVOT_SYSTEM_PROMPT,
    ar._ADD_SEED_SYSTEM_PROMPT,
    ar._CUSTOM_PROMPT_SYSTEM_PROMPT,
    ar._CORROBORATE_SYSTEM_PROMPT,
]


@pytest.fixture
def ctx_off(monkeypatch):
    """Isolate the pure composition mechanics from the context-pool addendum."""
    monkeypatch.setenv("BOUNCE_CTX_ENABLED", "0")


def test_cti_is_byte_for_byte_identity():
    """No fixture on purpose: this must hold under the DEFAULT configuration,
    because that is what production runs."""
    for tmpl in _CTI_TEMPLATES:
        assert ar.build_system_prompt(tmpl, verticals.CTI) == tmpl


def test_non_cti_swaps_agent_name_and_appends_block(ctx_off):
    osint = verticals.Vertical(
        name="osint", label="OSINT", agent_name="Bounce-OSINT",
        seed_types=("username",), source_pool="osint",
        prompt_block="OSINT-SPECIFIC RULES.",
    )
    out = ar.build_system_prompt("You are Bounce-CTI, do CTI things.", osint)
    assert out.startswith("You are Bounce-OSINT, do CTI things.")
    assert out.endswith("OSINT-SPECIFIC RULES.")
    assert "Bounce-CTI" not in out


def test_empty_block_appends_nothing(ctx_off):
    osint = verticals.Vertical(
        name="osint", label="OSINT", agent_name="Bounce-OSINT",
        seed_types=("username",), source_pool="osint",
    )
    out = ar.build_system_prompt("You are Bounce-CTI.", osint)
    assert out == "You are Bounce-OSINT."


# ── Context-pool addendum ──────────────────────────────────────────────────

def test_context_block_appended_for_osint_and_dd_by_default(monkeypatch):
    monkeypatch.delenv("BOUNCE_CTX_ENABLED", raising=False)
    for v in (verticals.OSINT, verticals.DD):
        out = ar.build_system_prompt(ar.SYSTEM_PROMPT, v)
        assert "CONTEXT POOL" in out, v.name
        assert "corroborate_lead" in out, v.name
        # The vertical's own lens block must still come first.
        assert out.index(v.prompt_block[:40]) < out.index("CONTEXT POOL"), v.name


def test_context_block_absent_for_cti_by_default(monkeypatch):
    monkeypatch.delenv("BOUNCE_CTX_ENABLED", raising=False)
    out = ar.build_system_prompt(ar.SYSTEM_PROMPT, verticals.CTI)
    assert "CONTEXT POOL" not in out


def test_context_block_reaches_cti_when_explicitly_enabled(monkeypatch):
    monkeypatch.setenv("BOUNCE_CTX_ENABLED", "all")
    out = ar.build_system_prompt(ar.SYSTEM_PROMPT, verticals.CTI)
    assert "CONTEXT POOL" in out


def test_context_block_amends_rule_r3(monkeypatch):
    """R3 in the core prompt forbids searching the web. The addendum must
    explicitly amend it, or the agent gets contradictory instructions."""
    monkeypatch.setenv("BOUNCE_CTX_ENABLED", "all")
    out = ar.build_system_prompt(ar.SYSTEM_PROMPT, verticals.CTI)
    assert "AMENDS rule R3" in out
    # The native tools stay forbidden even so.
    assert "WebSearch" in verticals.CONTEXT_POOL_PROMPT_BLOCK


# ── Tool whitelist ─────────────────────────────────────────────────────────

def test_allowed_tools_gain_ctx_only_when_enabled(monkeypatch):
    monkeypatch.setenv("BOUNCE_CTX_ENABLED", "0")
    assert ar.build_allowed_tools_for(verticals.OSINT) == ar._ALLOWED_TOOLS

    monkeypatch.setenv("BOUNCE_CTX_ENABLED", "all")
    tools = ar.build_allowed_tools_for(verticals.OSINT)
    for t in ("mcp__ctx__recall_prior_knowledge", "mcp__ctx__web_search",
              "mcp__ctx__web_fetch", "mcp__graph__corroborate_lead",
              "mcp__graph__lead_status"):
        assert t in tools, t


def test_cti_tool_whitelist_unchanged_by_default(monkeypatch):
    """The historical CTI whitelist is a locked invariant (test_verticals);
    mounting the context pool must not touch it under the default config."""
    monkeypatch.delenv("BOUNCE_CTX_ENABLED", raising=False)
    assert ar.build_allowed_tools_for(verticals.CTI) == ar._ALLOWED_TOOLS
    assert "mcp__ctx__" not in ar.build_allowed_tools_for(verticals.CTI)


def test_ctx_tools_survive_the_source_namespace_rewrite(monkeypatch):
    """build_allowed_tools rewrites the source prefix (mcp__cti__ → mcp__dd__).
    The ctx entries are appended AFTER that rewrite, so they must keep their own
    namespace rather than being dragged into the source pool's."""
    monkeypatch.setenv("BOUNCE_CTX_ENABLED", "all")
    tools = ar.build_allowed_tools_for(verticals.DD)
    assert "mcp__dd__crtsh_subdomains" in tools     # source pool, rewritten
    assert "mcp__ctx__recall_prior_knowledge" in tools
    assert "mcp__ctx__" in tools
    assert "mcp__dd__recall_prior_knowledge" not in tools
    assert "mcp__cti__" not in tools


def test_native_web_tools_stay_disallowed():
    """Open-web access must go exclusively through the wrapped, cached,
    budgeted, SSRF-guarded mcp__ctx__ versions."""
    assert "WebSearch" in ar._DISALLOWED_TOOLS
    assert "WebFetch" in ar._DISALLOWED_TOOLS
