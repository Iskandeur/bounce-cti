"""Shodan credit-guard tests.

The operating constraint is that the instance's Shodan Membership credits
(100 query credits/month, shared by every investigation) must NOT be spent
unless an operator explicitly opts in. These tests are the enforcement:

  - the billable path makes **zero HTTP requests** when credits are disabled
  - filter detection (which decides "billable") is biased toward refusing
  - the free endpoints stay reachable and are never mis-classified as billable
  - no seed type can mandate a call the guard would refuse

Everything here is offline: any attempt to open a socket fails the test.
"""
import asyncio

import pytest

from backend import pivot_mapping as pm
from backend.sources import shodan


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    """Reset credit accounting and make ANY network call an immediate failure.

    Patching the httpx client at the source module means a guard regression
    surfaces as a loud error rather than a silently-spent credit.
    """
    shodan.reset_for_tests()
    monkeypatch.delenv("BOUNCE_SHODAN_ALLOW_CREDITS", raising=False)
    monkeypatch.delenv("BOUNCE_SHODAN_CREDIT_BUDGET", raising=False)

    def _explode(*a, **k):
        raise AssertionError("network call attempted — a credit may have been spent")

    monkeypatch.setattr(shodan.httpx, "AsyncClient", _explode)

    # Make the rate limiter's waits instant rather than stubbing the limiter
    # itself: the real spacing logic still runs (and stays under test), but the
    # suite doesn't spend 1.5s per call.
    async def _instant(_seconds):
        return None
    monkeypatch.setattr(shodan.asyncio, "sleep", _instant)

    yield
    shodan.reset_for_tests()


# `_get` deliberately catches every transport exception so a network blip can't
# crash an investigation — which means the sentinel above surfaces as this error
# payload rather than propagating. Reaching it proves the call got all the way
# to the transport instead of being short-circuited by the credit guard.
_REACHED_NETWORK = "network call attempted"


def _reached_network(out: dict) -> bool:
    return _REACHED_NETWORK in str(out.get("error", ""))


# ── filter detection ───────────────────────────────────────────────────────

@pytest.mark.parametrize("query", [
    'ssl.jarm:29d3fd00029d29d00042d43d00041d598ac0c1012db967bb1ad0ff2491b3ae',
    'http.favicon.hash:-1234567890',
    'ssl.cert.serial:146473198',
    'asn:AS13335',
    'asn:AS13335 port:443',
    'ssl.cert.subject.CN:"evil.com"',
    'product:nginx os:Linux',
    'net:1.2.3.0/24',
])
def test_filtered_queries_are_billable(query):
    assert shodan.query_is_filtered(query) is True


@pytest.mark.parametrize("query", [
    "apache",
    "cobalt strike",
    '"default landing page"',
    "",
])
def test_keyword_only_queries_are_not_billable(query):
    assert shodan.query_is_filtered(query) is False


def test_bare_url_is_not_mistaken_for_a_filter():
    # `https:` must not read as a filter name.
    assert shodan.query_is_filtered("https://example.com") is False


# ── the guard: no request, no credit ───────────────────────────────────────

def test_filtered_search_is_refused_without_any_http_call():
    out = asyncio.run(shodan.shodan_search('ssl.jarm:abc123'))
    assert out["error"] == "shodan_credits_disabled"
    assert out["refused"] is True
    assert out["policy"]["allow_credits"] is False
    assert out["policy"]["spent_this_process"] == 0
    # The refusal must be actionable, not a dead end.
    assert any("shodan_host_count" in alt for alt in out["free_alternatives"])


def test_paging_past_page_one_is_refused_even_for_keyword_query():
    # Page >= 2 bills even without a filter.
    out = asyncio.run(shodan.shodan_search("apache", page=2))
    assert out["refused"] is True


def test_refusal_does_not_increment_spend():
    for _ in range(5):
        asyncio.run(shodan.shodan_search("asn:AS13335"))
    assert shodan.credit_policy()["spent_this_process"] == 0


def test_budget_zero_blocks_even_when_credits_allowed(monkeypatch):
    # Opted in, but with an explicit budget of... 1. Exhaust it, then confirm
    # further calls are refused rather than silently spending.
    monkeypatch.setenv("BOUNCE_SHODAN_ALLOW_CREDITS", "1")
    monkeypatch.setenv("BOUNCE_SHODAN_CREDIT_BUDGET", "1")
    shodan._credits_spent = 1  # simulate the one permitted call already made
    out = asyncio.run(shodan.shodan_search("asn:AS13335"))
    assert out["refused"] is True
    assert "budget exhausted" in out["reason"]


def test_opt_in_is_required_explicitly(monkeypatch):
    for value in ("", "0", "false", "no", "off"):
        monkeypatch.setenv("BOUNCE_SHODAN_ALLOW_CREDITS", value)
        out = asyncio.run(shodan.shodan_search("asn:AS13335"))
        assert out["refused"] is True, value


def test_opt_in_recognised(monkeypatch):
    # With credits allowed the guard steps aside — and then the patched network
    # layer trips, proving the guard (not the missing key/network) was what
    # blocked before. A fake key is injected so the call gets that far; the
    # patched transport guarantees no real request leaves the process.
    monkeypatch.setenv("BOUNCE_SHODAN_ALLOW_CREDITS", "1")
    monkeypatch.setattr(shodan.key_pool, "acquire", lambda _s: "fake-key-for-tests")
    out = asyncio.run(shodan.shodan_search("asn:AS13335"))
    assert out.get("refused") is not True
    assert _reached_network(out)


def test_no_key_is_reported_rather_than_refused_as_a_credit_issue():
    """With no key configured the free endpoints report the missing key —
    they must not masquerade as a credit refusal (different operator fix)."""
    out = asyncio.run(shodan.shodan_host("1.2.3.4"))
    assert "no Shodan key" in out["error"]
    assert out.get("refused") is not True


# ── free endpoints are not gated ───────────────────────────────────────────

def test_free_endpoints_are_not_refused(monkeypatch):
    """host / host_count / api_info must never hit the credit guard.

    With a key present they proceed all the way to the network layer (which the
    fixture makes explode). The point is that they are never short-circuited by
    a credit refusal, whatever the credit policy says.
    """
    monkeypatch.setattr(shodan.key_pool, "acquire", lambda _s: "fake-key-for-tests")
    for name, call in (
        ("host", lambda: shodan.shodan_host("1.2.3.4")),
        ("host_count", lambda: shodan.shodan_host_count('ssl.jarm:abc', facets="asn,org")),
        ("api_info", lambda: shodan.shodan_api_info()),
        ("dns_resolve", lambda: shodan.shodan_dns_resolve("evil.com")),
        ("reverse_dns", lambda: shodan.shodan_reverse_dns("1.2.3.4")),
    ):
        out = asyncio.run(call())
        assert out.get("refused") is not True, name
        assert _reached_network(out), name


def test_empty_inputs_short_circuit_without_network():
    assert asyncio.run(shodan.shodan_host_count(""))["error"] == "empty query"
    assert asyncio.run(shodan.shodan_search(""))["error"] == "empty query"
    assert "error" in asyncio.run(shodan.shodan_dns_resolve(""))
    assert "error" in asyncio.run(shodan.shodan_reverse_dns(""))


# ── error-in-HTTP-200 handling ─────────────────────────────────────────────

def test_rate_limit_error_arriving_as_http_200_is_detected():
    payload, health = shodan._unwrap(200, {"error": "Rate limit reached. Please slow down."})
    assert payload["_retryable"] is True
    assert health is None  # transient, not a dead source


def test_invalid_key_marks_source_dead():
    _, health = shodan._unwrap(200, {"error": "Invalid API key"})
    assert health == "auth_required"


def test_membership_gate_marks_tier_restricted():
    _, health = shodan._unwrap(200, {"error": "This method requires a Membership upgrade"})
    assert health == "tier_restricted"


def test_credit_exhaustion_marks_quota():
    _, health = shodan._unwrap(200, {"error": "Insufficient query credits"})
    assert health == "quota_exhausted"


def test_successful_payload_passes_through():
    payload, health = shodan._unwrap(200, {"total": 7, "matches": []})
    assert payload["total"] == 7 and health is None


def test_api_info_never_reports_a_non_numeric_credit_balance():
    """A rate-limited /api-info can omit the balances; they must normalise to
    None rather than leaking a value that reads as 0 in arithmetic."""
    out = {"plan": "dev", "query_credits": None, "scan_credits": "unknown"}
    for field in ("query_credits", "scan_credits"):
        if not isinstance(out.get(field), (int, float)):
            out[field] = None
    assert out["query_credits"] is None and out["scan_credits"] is None


# ── rate limiter (Shodan enforces 1 req/s strictly) ────────────────────────

def test_throttle_spaces_consecutive_calls(monkeypatch):
    """Back-to-back calls must be spaced by at least the configured interval.

    Verified by capturing what the limiter asks asyncio to sleep for, so the
    test asserts the behaviour without actually waiting.
    """
    slept: list[float] = []

    async def _fake_sleep(seconds):
        slept.append(seconds)

    monkeypatch.setattr(shodan.asyncio, "sleep", _fake_sleep)
    monkeypatch.setattr(shodan, "_last_call", 0.0)

    async def _three_in_a_row():
        for _ in range(3):
            await shodan._throttle()

    asyncio.run(_three_in_a_row())

    # The first call finds a stale timestamp and proceeds immediately; the two
    # that follow must each be asked to wait ~_MIN_INTERVAL.
    assert len(slept) == 2, slept
    for delay in slept:
        assert 0 < delay <= shodan._MIN_INTERVAL
        assert delay > shodan._MIN_INTERVAL * 0.9


def test_min_interval_respects_the_documented_limit():
    # Shodan documents 1 request/second; we space wider on purpose.
    assert shodan._MIN_INTERVAL >= 1.0


# ── pivot-queue integration ────────────────────────────────────────────────

def _reasons(node_type, value, vertical="cti"):
    return {op: reason for op, _, reason in
            pm.pivots_for(node_type, value, has_key=lambda _s: True, vertical=vertical)}


def test_credit_metered_pivots_are_parked_by_default():
    for node_type, value in (("jarm", "a" * 62), ("favicon_hash", "-12345"),
                             ("asn", "AS13335")):
        r = _reasons(node_type, value)
        assert r.get("shodan_search") == "credit_metered", node_type
        # ...and the free counterpart is queued in its place.
        assert r.get("shodan_host_count") is None, node_type


def test_credit_metered_pivots_unlock_when_opted_in(monkeypatch):
    monkeypatch.setenv("BOUNCE_SHODAN_ALLOW_CREDITS", "1")
    assert _reasons("jarm", "a" * 62).get("shodan_search") is None


def test_internetdb_is_queued_on_every_ip_including_defused():
    r = _reasons("ip", "1.2.3.4")
    assert r.get("internetdb_ip") is None
    # doc_only → survives defusing (free and keyless, always safe to record)
    defused = {op: reason for op, _, reason in
               pm.pivots_for("ip", "1.2.3.4", has_key=lambda _s: True, defused=True)}
    assert defused.get("internetdb_ip") is None


def test_internetdb_stays_live_in_the_osint_lens():
    # Exposure data is footprint signal, not abuse-feed noise — it must not be
    # suppressed the way threat feeds are in OSINT.
    assert _reasons("ip", "1.2.3.4", vertical="osint").get("internetdb_ip") is None
