"""Tests for the context pool — the second epistemic tier (backend/context_pool.py).

These lock the guarantees the whole design rests on. Each one corresponds to a
way the feature could quietly become dangerous:

  * the confidence cap and the forced `lead` type (hallucination → fake IOC)
  * the vertical claim deny-lists (DD adverse-media → GDPR art. 10)
  * export exclusion (unverified lead → firewall EDL / abuse mailbox / TIP)
  * the SSRF guard (web_fetch → internal network / cloud metadata)
  * corroboration accounting (the hallucination thermometer)
  * the CTI iso-functionality invariant (context pool must be off by default there)
"""
import pytest

from backend import context_pool as cp


# ── Tier boundary: confidence cap + provenance detection ───────────────────

def test_lead_sources_are_recognised():
    assert cp.is_lead_source("parametric_memory")
    assert cp.is_lead_source("PARAMETRIC_MEMORY")
    assert cp.is_lead_source("web:example.com")
    assert cp.is_lead_source("web:duckduckgo")
    # Real source tools are NOT lead sources.
    for src in ("crtsh", "virustotal", "gleif", "agent", "rdap", "", None):
        assert not cp.is_lead_source(src)


@pytest.mark.parametrize("given,expected", [
    (0.99, cp.LEAD_CONFIDENCE_CAP),
    (1.0, cp.LEAD_CONFIDENCE_CAP),
    (0.9, cp.LEAD_CONFIDENCE_CAP),
    (0.35, 0.35),
    (0.2, 0.2),
    (0.0, 0.0),
    (-5, 0.0),
    (None, cp.LEAD_CONFIDENCE_CAP),
    ("garbage", cp.LEAD_CONFIDENCE_CAP),
])
def test_confidence_is_capped(given, expected):
    assert cp.cap_lead_confidence(given) == expected


def test_cap_is_below_every_normal_confidence():
    # add_node's default is 0.8 and tag-promotion uses 0.7; a lead must never be
    # able to reach either, or it would read as an ordinary finding in the UI.
    assert cp.LEAD_CONFIDENCE_CAP < 0.5


def test_web_source_marker_carries_the_host():
    assert cp.web_source("https://evil.example.com/a/b?c=1") == "web:evil.example.com"
    assert cp.web_source("not a url").startswith("web:")


# ── Claim deny-lists (the mechanical legal guardrails) ─────────────────────

def test_dd_refuses_adverse_media_claims():
    """verticals._DD_PROMPT_BLOCK forbids adverse-media by prompt; this makes it
    an enforced refusal so it holds regardless of agent compliance."""
    for ct in ("adverse_media", "litigation", "allegation", "pep_status", "fraud"):
        assert cp.claim_type_denied(ct, "dd"), ct


def test_dd_allows_registry_routing():
    # The whole point of the pool in DD: route to the right registry.
    assert cp.claim_type_denied("registry_routing", "dd") is None
    assert cp.claim_type_denied("identity", "dd") is None


def test_osint_refuses_wrongdoing_claims_but_allows_identity():
    assert cp.claim_type_denied("adverse_media", "osint")
    assert cp.claim_type_denied("allegation", "osint")
    assert cp.claim_type_denied("identity", "osint") is None
    assert cp.claim_type_denied("affiliation", "osint") is None


def test_special_category_claims_are_refused_in_every_vertical():
    for vertical in ("cti", "osint", "dd", "unknown"):
        for ct in ("criminal_record", "health", "religion", "ethnicity",
                   "sexual_orientation", "biometric"):
            assert cp.claim_type_denied(ct, vertical), (vertical, ct)


def test_claim_type_normalisation():
    assert cp.normalise_claim_type("  Adverse Media ") == "adverse_media"
    assert cp.normalise_claim_type("adverse-media") == "adverse_media"
    # ...and the deny-list sees through the formatting variants.
    assert cp.claim_type_denied("Adverse-Media", "dd")


def test_cti_permits_reputation_but_not_criminal_inference():
    # CTI legitimately reasons about malicious infrastructure reputation.
    assert cp.claim_type_denied("reputation", "cti") is None
    assert cp.claim_type_denied("criminal_record", "cti")


# ── Corroboration: no circular ratification ────────────────────────────────

def test_context_tools_cannot_corroborate():
    assert not cp.is_primary_evidence_tool("mcp__ctx__web_search")
    assert not cp.is_primary_evidence_tool("mcp__ctx__recall_prior_knowledge")
    # Graph mutations observe nothing either.
    assert not cp.is_primary_evidence_tool("mcp__graph__add_node")
    assert not cp.is_primary_evidence_tool("")
    assert not cp.is_primary_evidence_tool(None)


def test_source_tools_can_corroborate():
    for t in ("mcp__cti__crtsh_subdomains", "mcp__dd__gleif_lookup",
              "crtsh_subdomains", "malwarebazaar_signature"):
        assert cp.is_primary_evidence_tool(t), t


# ── Corroboration telemetry ────────────────────────────────────────────────

def _lead(value, tags=(), claim_type="identity"):
    return {"type": "lead", "value": value, "tags": list(tags),
            "metadata": {"claim_type": claim_type}}


def test_corroboration_stats_counts_and_rate():
    nodes = [
        _lead("a", [cp.TAG_CORROBORATED]),
        _lead("b", [cp.TAG_CORROBORATED]),
        _lead("c", [cp.TAG_REFUTED]),
        _lead("d", [cp.TAG_UNVERIFIABLE]),
        _lead("e", [cp.TAG_UNVERIFIED]),
        {"type": "domain", "value": "evil.com", "tags": [], "metadata": {}},
    ]
    s = cp.corroboration_stats(nodes)
    assert s["total_leads"] == 5           # the domain is not a lead
    assert s["corroborated"] == 2
    assert s["refuted"] == 1
    assert s["unverifiable"] == 1
    assert s["unverified"] == 1
    assert s["corroboration_rate"] == 0.4


def test_corroboration_stats_empty_graph():
    s = cp.corroboration_stats([])
    assert s["total_leads"] == 0
    assert s["corroboration_rate"] is None


def test_corroboration_stats_untagged_lead_counts_as_unverified():
    s = cp.corroboration_stats([_lead("x")])
    assert s["unverified"] == 1
    assert s["corroboration_rate"] == 0.0


def test_corroboration_stats_breaks_down_by_claim_type():
    s = cp.corroboration_stats([
        _lead("a", [cp.TAG_CORROBORATED], claim_type="naming"),
        _lead("b", [cp.TAG_REFUTED], claim_type="naming"),
        _lead("c", [cp.TAG_CORROBORATED], claim_type="registry_routing"),
    ])
    assert s["by_claim_type"]["naming"] == {
        "total": 2, "corroborated": 1, "refuted": 1,
        "unverifiable": 0, "unverified": 0}
    assert s["by_claim_type"]["registry_routing"]["corroborated"] == 1


# ── Export exclusion (the non-negotiable guarantee) ────────────────────────

def test_leads_are_never_actionable():
    assert not cp.is_actionable({"type": "lead", "value": "x", "tags": []})
    assert not cp.is_actionable(
        {"type": "lead", "value": "x", "tags": [cp.TAG_CORROBORATED]})


def test_unverified_typed_nodes_are_not_actionable():
    for tag in (cp.TAG_UNVERIFIED, cp.TAG_REFUTED, cp.TAG_UNVERIFIABLE):
        assert not cp.is_actionable(
            {"type": "domain", "value": "evil.com", "tags": [tag]}), tag


def test_corroborated_typed_nodes_are_actionable():
    assert cp.is_actionable(
        {"type": "domain", "value": "evil.com", "tags": [cp.TAG_CORROBORATED]})
    assert cp.is_actionable({"type": "ip", "value": "1.2.3.4", "tags": []})


def test_split_leads_partitions():
    nodes = [{"type": "domain", "value": "a"}, _lead("b"), {"type": "ip", "value": "c"}]
    rest, leads = cp.split_leads(nodes)
    assert [n["value"] for n in rest] == ["a", "c"]
    assert [n["value"] for n in leads] == ["b"]


def test_leads_markdown_section_labels_and_is_empty_without_leads():
    assert cp.leads_markdown_section([]) == []
    md = "\n".join(cp.leads_markdown_section([
        _lead("claim one", [cp.TAG_CORROBORATED]),
        _lead("claim two", [cp.TAG_UNVERIFIED]),
    ]))
    assert "not established facts" in md
    assert "excluded from all" in md.lower()
    assert "Corroborated" in md and "Unverified" in md
    assert "claim one" in md and "claim two" in md


# ── SSRF guard ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("url", [
    "file:///etc/passwd",
    "ftp://example.com/x",
    "gopher://example.com",
    "http://127.0.0.1/admin",
    "http://localhost:8001/api/admin/users",
    "http://169.254.169.254/latest/meta-data/",       # AWS IMDS
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://10.0.0.5/internal",
    "http://192.168.1.1/",
    "http://172.16.0.1/",
    "http://[::1]/",
    "http://something.local/",
    "",
])
def test_unsafe_fetch_urls_are_refused(url):
    assert cp.check_fetch_url(url) is not None, url


@pytest.mark.parametrize("url", [
    "https://example.com/writeup",
    "http://blog.vendor.io/threat-report",
    "https://8.8.8.8/",
])
def test_public_urls_are_allowed(url):
    assert cp.check_fetch_url(url) is None, url


def test_resolved_address_check_catches_public_name_pointing_inward():
    # A public hostname resolving to link-local is the SSRF bypass the
    # post-DNS check exists for.
    assert cp.check_fetch_host_address("169.254.169.254") is not None
    assert cp.check_fetch_host_address("127.0.0.1") is not None
    assert cp.check_fetch_host_address("8.8.8.8") is None
    assert cp.check_fetch_host_address("not-an-ip") is None


# ── Enablement policy ──────────────────────────────────────────────────────

def test_default_is_on_for_osint_and_dd_off_for_cti(monkeypatch):
    """CTI carries the byte-for-byte prompt invariant and the EVAL §4.5 budget
    cliff, so it must not gain the context pool without an explicit opt-in."""
    monkeypatch.delenv("BOUNCE_CTX_ENABLED", raising=False)
    assert cp.context_pool_enabled("osint") is True
    assert cp.context_pool_enabled("dd") is True
    assert cp.context_pool_enabled("cti") is False


def test_kill_switch(monkeypatch):
    monkeypatch.setenv("BOUNCE_CTX_ENABLED", "0")
    for v in ("cti", "osint", "dd"):
        assert cp.context_pool_enabled(v) is False


def test_enable_everywhere(monkeypatch):
    monkeypatch.setenv("BOUNCE_CTX_ENABLED", "all")
    for v in ("cti", "osint", "dd"):
        assert cp.context_pool_enabled(v) is True


def test_explicit_vertical_list(monkeypatch):
    monkeypatch.setenv("BOUNCE_CTX_ENABLED", "dd")
    assert cp.context_pool_enabled("dd") is True
    assert cp.context_pool_enabled("osint") is False
    assert cp.context_pool_enabled("cti") is False


def test_web_tools_switch(monkeypatch):
    monkeypatch.delenv("BOUNCE_CTX_WEB", raising=False)
    assert cp.web_tools_enabled() is True
    monkeypatch.setenv("BOUNCE_CTX_WEB", "0")
    assert cp.web_tools_enabled() is False


def test_ctx_budget_default_and_override(monkeypatch):
    monkeypatch.delenv("BOUNCE_CTX_BUDGET", raising=False)
    assert cp.ctx_budget() == 12
    monkeypatch.setenv("BOUNCE_CTX_BUDGET", "3")
    assert cp.ctx_budget() == 3
    monkeypatch.setenv("BOUNCE_CTX_BUDGET", "nonsense")
    assert cp.ctx_budget() == 12
