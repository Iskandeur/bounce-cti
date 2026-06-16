"""Golden regression tests for the seed registry (backend/seeds.py).

These lock the mandatory-tool spec to the exact strings the agent-runner ladders
produced before the registry extraction, so the refactor is provably
behaviour-preserving and future edits can't silently change the agent's
mandatory-tool prompts. CTI must stay iso-functional (roadmap invariant 4.4).
"""
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
