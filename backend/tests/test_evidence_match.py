"""Evidence → Load keeps the cached answers about the node's exact value.

The lookup used to be `key LIKE '%<value>%'`: `a.example` also returned the
answers about `data.example.net`, `1.2.3.4` those about `11.2.3.45`, and `%` /
`_` in a value were SQL wildcards. The key shapes below are the ones the
sources write (http_client's defaults and the per-source keys).
"""
import pytest

import backend.graph_store as gs
from backend.evidence_match import MIN_VALUE_LEN, key_mentions, like_pattern


def _hits(value, keys):
    return [k for k in keys if key_mentions(k, value)]


# ── Hostnames ──────────────────────────────────────────────────────────────

def test_domain_is_found_in_every_key_shape_that_asks_about_it():
    keys = [
        "GET|https://rdap.org/domain/example.com|None",
        "GET|https://crt.sh/|{'q': '%.example.com', 'output': 'json'}",
        "GET|https://crt.sh/|{'q': 'example.com', 'exclude': 'expired', 'output': 'json'}",
        "GET|https://urlscan.io/api/v1/search/|{'q': 'domain:example.com', 'size': 50}",
        "POST|https://threatfox-api.abuse.ch/api/v1/|{'query': 'search_ioc', 'search_term': 'example.com'}",
        "whois|domain|example.com",
        "certspotter|issuances|example.com|True",
        "shodan|/dns/domain/example.com|[]",
        "dnstwist|example.com|reg=True|mx=False",
        "GET|https://api.example.org/v1/names|{'q': '*.example.com'}",
        "whois|domain|example.com.",                      # trailing dot of an FQDN
        "FORM|https://urlhaus-api.abuse.ch/v1/url/|{'url': 'http://example.com/login.php'}",
    ]
    assert _hits("example.com", keys) == keys


def test_domain_glued_to_more_hostname_is_another_indicator():
    keys = [
        "GET|https://rdap.org/domain/sub.example.com|None",
        "GET|https://rdap.org/domain/example.com.evil.net|None",
        "whois|domain|my-example.com",
        "whois|domain|example.com-cdn.net",
        "whois|domain|notexample.com",
        "whois|domain|example.community",
        "whois|domain|www_example.com",
        "emailrep|admin@example.com",
        "GET|https://crt.sh/|{'q': '%.www.example.com', 'output': 'json'}",
    ]
    assert _hits("example.com", keys) == []


def test_short_domain_no_longer_drags_in_unrelated_hosts():
    """The case of the bug report: `a.example` inside `data.example.net`."""
    keys = ["GET|https://rdap.org/domain/data.example.net|None",
            "GET|https://rdap.org/domain/a.example|None"]
    assert _hits("a.example", keys) == ["GET|https://rdap.org/domain/a.example|None"]


def test_domain_comparison_ignores_case():
    assert key_mentions("whois|domain|example.com", "Example.COM")
    assert key_mentions("GET|https://rdap.org/domain/EXAMPLE.com|None", "example.com")


def test_the_api_host_of_the_question_is_not_a_mention():
    assert not key_mentions("GET|https://rdap.org/domain/example.com|None", "rdap.org")
    assert not key_mentions("GET|https://crt.sh/|{'q': '%.example.com'}", "crt.sh")
    # … unless the question is about that host.
    assert key_mentions("GET|https://rdap.org/domain/rdap.org|None", "rdap.org")
    # The head of a per-source key names the source, it is not a value.
    assert not key_mentions("shodan|/dns/domain/example.com|[]", "shodan")
    assert key_mentions("uenum|github|shodan", "shodan")


# ── IP addresses ───────────────────────────────────────────────────────────

def test_ipv4_matches_itself_only():
    assert key_mentions("internetdb|1.2.3.4", "1.2.3.4")
    assert key_mentions("abuseipdb|check|1.2.3.4|90", "1.2.3.4")
    assert key_mentions("GET|https://rdap.org/ip/1.2.3.4|None", "1.2.3.4")
    assert key_mentions("netlas|search|host:1.2.3.4|20", "1.2.3.4")
    assert key_mentions("zoomeye|host|ip:1.2.3.4 port:443|1", "1.2.3.4")
    for other in ("11.2.3.45", "1.2.3.45", "11.2.3.4", "1.2.3.4.5", "0.1.2.3.4"):
        assert not key_mentions(f"internetdb|{other}", "1.2.3.4"), other


def test_ipv6_matches_itself_only():
    v = "2001:db8::1"
    assert key_mentions(f"internetdb|{v}", v)
    assert key_mentions(f"GET|https://rdap.org/ip/{v}|None", v)
    assert key_mentions("whois|ip|2001:DB8::1", v)
    assert key_mentions(f"netlas|search|ip:{v}|20", v)          # `ip:` is a field name
    assert key_mentions(f"zoomeye|host|[{v}]:443|1", v)
    for other in ("2001:db8::10", "2001:db8::1:2", "fe80:2001:db8::1", "12001:db8::1"):
        assert not key_mentions(f"internetdb|{other}", v), other


# ── Hashes ─────────────────────────────────────────────────────────────────

def test_hash_prefix_does_not_match_a_longer_hash():
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    sha256 = md5 + "0123456789abcdef0123456789abcdef"
    assert key_mentions(f"circl|hash|md5|{md5}", md5)
    assert key_mentions(f"GET|https://www.virustotal.com/api/v3/files/{md5}|None", md5)
    assert not key_mentions(f"circl|hash|sha256|{sha256}", md5)
    assert not key_mentions(f"circl|hash|sha256|{sha256}", sha256[8:])
    # Hex digests are case-insensitive.
    assert key_mentions(f"circl|hash|md5|{md5}", md5.upper())


# ── URLs, emails ───────────────────────────────────────────────────────────

def test_url_matches_where_the_keys_url_ends():
    url = "http://a.example/x"
    hits = [
        "FORM|https://urlhaus-api.abuse.ch/v1/url/|{'url': 'http://a.example/x'}",
        "phishtank|http://a.example/x",
        "CTXFETCH|http://a.example/x|6000",
        "website|http://a.example/x/",                                  # one trailing slash
        "GET|https://urlscan.io/api/v1/search/|{'q': 'page.url:\"http://a.example/x\"'}",
        "GET|https://archive.org/wayback/available|{'url': 'HTTP://A.example/x'}",
    ]
    misses = [
        "phishtank|http://a.example/xy",
        "phishtank|http://a.example/x/y",
        "phishtank|http://a.example/x?id=1",
        "phishtank|http://a.example/x.php",
        "phishtank|xhttp://a.example/x",
    ]
    assert _hits(url, hits + misses) == hits


def test_url_node_equal_to_the_asked_url_is_a_mention():
    assert key_mentions("TXT|https://a.example/x|None", "https://a.example/x")


def test_percent_encoded_occurrences_are_decoded():
    assert key_mentions("GET|https://api.example.org/email/user%40example.com|None",
                        "user@example.com")
    assert key_mentions("GET|https://api.example.org/scan?u=http%3A%2F%2Fa.example%2Fx|None",
                        "http://a.example/x")
    # Decoding also shows what a value is glued to.
    assert not key_mentions("GET|https://api.example.org/host/sub%2Eexample.com|None",
                            "example.com")
    # An escape is not the start of a value.
    assert not key_mentions("GET|https://api.example.org/q?d%3Dexample.com|None",
                            "3dexample.com")


def test_email_matches_itself_only():
    v = "user@example.com"
    assert key_mentions("emailrep|user@example.com", v)
    assert key_mentions("whoxy|email|User@Example.com|1|quick", v)
    assert not key_mentions("emailrep|other.user@example.com", v)
    assert not key_mentions("emailrep|user@example.com.au", v)
    # The local part alone is another indicator (a username) …
    assert not key_mentions("emailrep|user@example.com", "user")
    # … and a handle written with a leading @ is that username.
    assert key_mentions("TXT|https://social.example/@user|None", "user")


# ── Values that look like patterns ─────────────────────────────────────────

def test_regex_metacharacters_match_themselves_only():
    assert key_mentions("whoxy|name|acme (holdings) [uk] ltd.|1|quick", "ACME (Holdings) [UK] Ltd.")
    assert key_mentions("whoxy|kw|c++ dev|1|quick", "c++ dev")
    assert not key_mentions("whois|domain|evil.example", "e.il.example")
    assert not key_mentions("whoxy|kw|aaa|1|quick", "a+")
    assert not key_mentions("whoxy|kw|anything|1|quick", ".*")


@pytest.mark.parametrize("value", ["", " ", "a", "US", None])
def test_value_too_short_matches_nothing(value):
    assert like_pattern(value) is None
    assert not key_mentions("GET|https://rdap.org/domain/a.us|{'q': 'a', 'cc': 'US'}", value)


def test_min_value_len_is_three():
    assert MIN_VALUE_LEN == 3
    assert key_mentions("whoxy|kw|ovh|1|quick", "OVH")


def test_like_pattern_keeps_what_the_matcher_accepts():
    # The longest run percent-encoding leaves alone, SQL wildcards escaped.
    assert like_pattern("example.com") == "%example.com%"
    assert like_pattern("user@example.com") == "%example.com%"
    assert like_pattern("http://a.example/x_y") == "%a.example%"
    assert like_pattern("under_score.example") == "%under\\_score.example%"
    assert like_pattern("50%_off") == "%\\_off%"
    assert like_pattern("@@@") == "%%"   # nothing to prefilter on: the matcher decides alone


# ── Through the database ───────────────────────────────────────────────────

@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(gs, "DB_PATH", str(tmp_path / "t.db"))
    gs.init_db()
    return gs


def _keys(evidence):
    return sorted(e["cache_key"] for e in evidence)


def test_lookup_returns_exact_matches_only(db):
    db.cache_set("internetdb|1.2.3.4", {"ports": [22]})
    db.cache_set("internetdb|11.2.3.45", {"ports": [80]})
    db.cache_set("GET|https://rdap.org/domain/a.example|None", {"handle": "A"})
    db.cache_set("GET|https://rdap.org/domain/data.example.net|None", {"handle": "B"})

    assert _keys(db.get_evidence_for_value("1.2.3.4")) == ["internetdb|1.2.3.4"]
    assert _keys(db.get_evidence_for_value("a.example")) == [
        "GET|https://rdap.org/domain/a.example|None"]


def test_sql_wildcards_in_a_value_are_literal(db):
    db.cache_set("whois|domain|a_b.example", {"n": 1})
    db.cache_set("whois|domain|axb.example", {"n": 2})
    db.cache_set("whoxy|kw|100% legit|1|quick", {"n": 3})
    db.cache_set("whoxy|kw|100 percent legit|1|quick", {"n": 4})

    assert _keys(db.get_evidence_for_value("a_b.example")) == ["whois|domain|a_b.example"]
    assert _keys(db.get_evidence_for_value("100% legit")) == ["whoxy|kw|100% legit|1|quick"]
    # A value made of wildcards finds nothing instead of every row.
    assert db.get_evidence_for_value("%%%") == []
    assert db.get_evidence_for_value("___") == []


@pytest.mark.parametrize("value", ["", "a", "US", "%", "_"])
def test_short_value_never_dumps_the_cache(db, value):
    db.cache_set("GET|https://rdap.org/domain/a.us|None", {"handle": "X"})
    db.cache_set("whoxy|kw|a|1|quick", {"n": 1})
    assert db.get_evidence_for_value(value) == []


def test_bookkeeping_key_holding_the_value_is_not_evidence(db):
    db.cache_set("whois|domain|evil.example", {"registrar": "R"})
    db.cache_set("counter|inv1|evil.example", 3)
    db.cache_set("source_health|evil.example", {"status": "auth_required"})
    db.cache_set("pdf_source:evil.example", {"text": "…"})
    db.cache_set("sample_source:evil.example", {"text": "…"})

    assert _keys(db.get_evidence_for_value("evil.example")) == ["whois|domain|evil.example"]


def test_percent_encoded_key_is_found_through_the_prefilter(db):
    db.cache_set("GET|https://api.example.org/email/user%40example.com|None", {"n": 1})
    db.cache_set("GET|https://api.example.org/email/other%40example.com|None", {"n": 2})

    assert _keys(db.get_evidence_for_value("user@example.com")) == [
        "GET|https://api.example.org/email/user%40example.com|None"]


def test_answers_come_oldest_first_with_their_data(db):
    db.cache_set("whois|domain|evil.example", {"registrar": "R"})
    db.cache_set("GET|https://rdap.org/domain/evil.example|None", {"handle": "X1"})
    with db.conn() as c:   # cache_set stamps the wall clock: pin both rows
        c.execute("UPDATE cache SET created_at=100.0 WHERE key LIKE 'whois|%'")
        c.execute("UPDATE cache SET created_at=200.0 WHERE key LIKE 'GET|%'")

    evidence = db.get_evidence_for_value("evil.example")

    assert [(e["cache_key"], e["data"], e["cached_at"]) for e in evidence] == [
        ("whois|domain|evil.example", {"registrar": "R"}, 100.0),
        ("GET|https://rdap.org/domain/evil.example|None", {"handle": "X1"}, 200.0),
    ]
