"""Golden regression tests for the seed registry (backend/seeds.py).

These lock the mandatory-tool spec to the exact strings the agent-runner ladders
produced before the registry extraction, so the refactor is provably
behaviour-preserving and future edits can't silently change the agent's
mandatory-tool prompts. CTI must stay iso-functional (roadmap invariant 4.4).
"""
import json
from pathlib import Path

from backend import seeds
from backend.agent_runner import _missing_mandatory_tools

# Representative seed values, one per type. Chosen to exercise interpolation
# (e.g. the AS-number stripping for asn).
SAMPLES = {
    "ip": "1.2.3.4",
    "domain": "evil.com",
    "url": "http://evil.com/x",
    "jarm": "a" * 62,
    "asn": "AS13335",
    "hash": "d41d8cd98f00b204e9800998ecf8427e",
    "executable_name": "dropper.exe",
    "email": "a@b.com",
    "wallet_address": "0xabc",
    "username": "h4ck3r",
    "command_line": "cmd",
}

# Golden output of seeds.mandatory_tools(seed_type, SAMPLES[seed_type]), frozen
# from the pre-refactor ladder in agent_runner._missing_mandatory_tools.
GOLDEN = {
    "ip": [
        ("rdap_ip", 'rdap_ip("1.2.3.4")'),
        ("reverse_dns", 'reverse_dns("1.2.3.4")'),
        ("virustotal_communicating_files", 'virustotal_communicating_files("ip", "1.2.3.4")'),
        ("threatfox_search", 'threatfox_search("1.2.3.4")'),
        ("virustotal_resolutions_ip", 'virustotal_resolutions_ip("1.2.3.4")'),
        ("shodan_host", 'shodan_host("1.2.3.4")'),
        ("onyphe_ip", 'onyphe_ip("1.2.3.4")'),
        ("urlscan_search", 'urlscan_search("ip:1.2.3.4")'),
        ("otx_ip", 'otx_ip("1.2.3.4")'),
    ],
    "domain": [
        ("rdap_domain", 'rdap_domain("evil.com")'),
        ("dns_resolve", 'dns_resolve("evil.com")'),
        ("virustotal_communicating_files", 'virustotal_communicating_files("domain", "evil.com")'),
        ("threatfox_search", 'threatfox_search("evil.com")'),
        ("virustotal_resolutions_domain", 'virustotal_resolutions_domain("evil.com")'),
        ("otx_domain", 'otx_domain("evil.com")'),
        ("crtsh_subdomains", 'crtsh_subdomains("evil.com")'),
        ("onyphe_domain", 'onyphe_domain("evil.com")'),
        ("urlscan_search", 'urlscan_search("domain:evil.com")'),
        ("wayback", 'wayback("evil.com")'),
    ],
    "url": [
        ("urlscan_search", 'urlscan_search("page.url:http://evil.com/x")'),
        ("threatfox_search", 'threatfox_search("http://evil.com/x")'),
    ],
    "jarm": [
        ("shodan_search", 'shodan_search("ssl.jarm:' + "a" * 62 + '")'),
        ("urlscan_search", 'urlscan_search("hash:' + "a" * 62 + '")'),
    ],
    "asn": [
        ("shodan_search", 'shodan_search("asn:AS13335")'),
    ],
    "hash": [
        ("virustotal_file", 'virustotal_file("d41d8cd98f00b204e9800998ecf8427e")'),
        ("malwarebazaar_hash", 'malwarebazaar_hash("d41d8cd98f00b204e9800998ecf8427e")'),
        ("threatfox_search", 'threatfox_search("d41d8cd98f00b204e9800998ecf8427e")'),
        ("otx_file", 'otx_file("d41d8cd98f00b204e9800998ecf8427e")'),
    ],
    "executable_name": [
        ("malwarebazaar_filename", 'malwarebazaar_filename("dropper.exe")'),
        ("threatfox_search", 'threatfox_search("dropper.exe")'),
    ],
    "email": [
        ("emailrep_check", 'emailrep_check("a@b.com")'),
        ("whoxy_reverse", 'whoxy_reverse(email="a@b.com")'),
        ("pulsedive_indicator", 'pulsedive_indicator("a@b.com")'),
        ("opencti_lookup_indicator", 'opencti_lookup_indicator("a@b.com")'),
        ("threatfox_search", 'threatfox_search("a@b.com")'),
    ],
    "wallet_address": [
        ("threatfox_search", 'threatfox_search("0xabc")'),
        ("pulsedive_indicator", 'pulsedive_indicator("0xabc")'),
        ("opencti_lookup_indicator", 'opencti_lookup_indicator("0xabc")'),
    ],
    "username": [
        ("threatfox_search", 'threatfox_search("h4ck3r")'),
        ("pulsedive_indicator", 'pulsedive_indicator("h4ck3r")'),
        ("opencti_lookup_indicator", 'opencti_lookup_indicator("h4ck3r")'),
    ],
    "command_line": [],
}


def test_mandatory_tools_byte_identical():
    for seed_type, value in SAMPLES.items():
        assert seeds.mandatory_tools(seed_type, value) == GOLDEN[seed_type], seed_type


def test_unknown_seed_type_has_no_mandatory_tools():
    assert seeds.mandatory_tools("totally_unknown", "x") == []


def test_asn_accepts_bare_number():
    # "13335" (no AS prefix) must produce the same canonical AS13335 query.
    assert seeds.mandatory_tools("asn", "13335") == [
        ("shodan_search", 'shodan_search("asn:AS13335")'),
    ]


def test_missing_mandatory_filters_called_tools():
    # Only the call examples for not-yet-called tools come back, in order.
    missing = _missing_mandatory_tools("url", "http://evil.com/x", {"urlscan_search"})
    assert missing == ['threatfox_search("http://evil.com/x")']
    # All called → nothing missing.
    assert _missing_mandatory_tools("url", "http://evil.com/x",
                                    {"urlscan_search", "threatfox_search"}) == []


def test_known_seed_types_registered():
    # Every known IOC seed type except command_line has mandatory tools.
    for st in seeds.KNOWN_SEED_TYPES:
        tools = seeds.mandatory_tools(st, "x")
        if st == "command_line":
            assert tools == []
        else:
            assert tools, st


# ── investigation_prompt golden snapshot ──────────────────────────────────
# The snapshot was captured from seeds.investigation_prompt() and verified
# byte-identical against the pre-refactor run_investigation inline ladder
# (git HEAD at extraction time) for every seed type, including domain / hash /
# unknown falling through to the generic branch. Regenerate intentionally only
# when the prompt text is meant to change (and re-run EVAL_PROTOCOL.md).
_GOLDEN_PROMPTS = json.loads(
    (Path(__file__).parent / "golden_investigation_prompts.json").read_text(encoding="utf-8")
)


def test_investigation_prompt_byte_identical():
    samples = _GOLDEN_PROMPTS["_samples"]
    expected = _GOLDEN_PROMPTS["prompts"]
    for seed_type, prompt in expected.items():
        assert seeds.investigation_prompt(seed_type, samples[seed_type]) == prompt, seed_type


_GOLDEN_BLOCKS = json.loads(
    (Path(__file__).parent / "golden_seed_blocks.json").read_text(encoding="utf-8")
)


def test_add_seed_block_byte_identical():
    samples = _GOLDEN_BLOCKS["_samples"]
    for seed_type, block in _GOLDEN_BLOCKS["add_seed"].items():
        assert seeds.add_seed_block(seed_type, samples[seed_type]) == block, seed_type


def test_pivot_block_byte_identical():
    samples = _GOLDEN_BLOCKS["_samples"]
    for seed_type, block in _GOLDEN_BLOCKS["pivot"].items():
        assert seeds.pivot_block(seed_type, samples[seed_type]) == block, seed_type


def test_add_seed_and_pivot_unknown_type_empty():
    # Unknown seed types append nothing, exactly as the original ladders did.
    assert seeds.add_seed_block("totally_unknown", "x") == ""
    assert seeds.pivot_block("totally_unknown", "x") == ""


def test_followup_extra_steps():
    # ip has three steps, domain one, everything else none.
    assert len(seeds.followup_extra_steps("ip")) == 3
    assert len(seeds.followup_extra_steps("domain")) == 1
    assert seeds.followup_extra_steps("url") == []
    assert seeds.followup_extra_steps("hash") == []
    # The ip malware-family step targets the seed IP; the domain one the seed.
    assert seeds.followup_extra_steps("ip")[1].endswith("to the seed IP.")
    assert seeds.followup_extra_steps("domain")[0].endswith("to the seed.")


def test_investigation_prompt_domain_and_hash_use_generic_branch():
    # domain / hash / unknown all fall through to the generic else branch, which
    # interpolates the type token but is otherwise identical text. Strip the
    # first line (the only type-dependent part) and the bodies must match.
    def body(t):
        return seeds.investigation_prompt(t, "X").split("\n", 1)[1]

    assert body("domain") == body("hash") == body("totally_unknown")
    # ...and it really is the generic domain-style workflow.
    generic = seeds.investigation_prompt("domain", "evil.com")
    assert "type=domain value=evil.com" in generic
    assert "onyphe_ctl(evil.com)" in generic


def test_phone_seed_registered():
    # The OSINT `phone` seed type is wired end to end in the registry.
    assert "phone" in seeds.KNOWN_SEED_TYPES
    tools = seeds.mandatory_tools("phone", "+16502530000")
    assert tools and tools[0][0] == "phone_lookup"
    assert "phone_lookup(\"+16502530000\")" in dict((t, c) for t, c in tools).values() \
        or any("phone_lookup" in c for _, c in tools)
    for fn in (seeds.investigation_prompt, seeds.add_seed_block, seeds.pivot_block):
        block = fn("phone", "+16502530000")
        assert block and "phone_lookup" in block
