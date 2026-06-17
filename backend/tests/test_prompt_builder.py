"""Tests for the {core}+{vertical} system-prompt builder
(agent_runner.build_system_prompt).

Locks the roadmap invariant 4.4 guarantee: for the CTI vertical the builder is
a byte-for-byte identity over every phase template, so the multi-vertical seam
cannot silently change the production CTI agent prompt.
"""
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
]


def test_cti_is_byte_for_byte_identity():
    for tmpl in _CTI_TEMPLATES:
        assert ar.build_system_prompt(tmpl, verticals.CTI) == tmpl


def test_non_cti_swaps_agent_name_and_appends_block():
    osint = verticals.Vertical(
        name="osint", label="OSINT", agent_name="Bounce-OSINT",
        seed_types=("username",), source_pool="osint",
        prompt_block="OSINT-SPECIFIC RULES.",
    )
    out = ar.build_system_prompt("You are Bounce-CTI, do CTI things.", osint)
    assert out.startswith("You are Bounce-OSINT, do CTI things.")
    assert out.endswith("OSINT-SPECIFIC RULES.")
    assert "Bounce-CTI" not in out


def test_empty_block_appends_nothing():
    osint = verticals.Vertical(
        name="osint", label="OSINT", agent_name="Bounce-OSINT",
        seed_types=("username",), source_pool="osint",
    )
    out = ar.build_system_prompt("You are Bounce-CTI.", osint)
    assert out == "You are Bounce-OSINT."
