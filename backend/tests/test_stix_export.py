"""STIX 2.1 conformance tests for the bundle builder (pure, no DB).

Locks the fixes for the non-conformities found in a real investigation export:
  - confidence/labels only on SDOs/SROs, never on cyber-observables (SCOs)
  - email-addr emitted only for RFC-valid addresses
  - a TLP marking-definition is present and referenced by every object
  - relationships restricted to spec-valid source/target pairs (resolves-to
    flipped when reversed; out-of-spec pairs degraded to related-to)
  - report carries report_types
  - malicious observables promoted to indicator SDOs with valid patterns
"""
from backend import stix_export as sx

_SCO_TYPES = sx._SCO_TYPES

_NODES = [
    {"id": "d1", "type": "domain", "value": "evil.com", "tags": ["malicious"],
     "confidence": 0.9, "metadata": {"sources_seen": ["virustotal", "otx"]}},
    {"id": "ip1", "type": "ip", "value": "199.247.3.191", "tags": ["suspicious"],
     "confidence": 0.8, "metadata": {}},
    {"id": "as1", "type": "asn", "value": "AS20473", "tags": [],
     "confidence": 0.8, "metadata": {"as_owner": "Vultr"}},
    {"id": "c1", "type": "cert", "value": "da71226e22295641172e5c8e64d64d9a9c748d78",
     "confidence": 0.8, "metadata": {"subject": "CN=*.wpmudev.host"}},
    {"id": "co1", "type": "country", "value": "DE", "tags": [], "metadata": {}},
    {"id": "em1", "type": "email", "value": "f651612a2f356ad3s@", "metadata": {}},
    {"id": "em2", "type": "email", "value": "abuse@evil.com", "metadata": {}},
    {"id": "rep", "type": "report", "value": "investigation_summary",
     "metadata": {"threat_assessment": "suspicious", "summary": "xHunt infra.",
                  "ioc_list": ["evil.com", "199.247.3.191"]}},
]

_EDGES = [
    # reversed resolves-to: ipv4 -> domain  (must be flipped to domain -> ipv4)
    {"src": "ip1", "dst": "d1", "relation": "resolves_to", "confidence": 0.8},
    # attributed-to domain -> email (out of spec -> related-to); but em1 invalid
    # so its node is dropped; use a valid edge domain -> asn instead below.
    {"src": "d1", "dst": "as1", "relation": "hosted_on_asn", "confidence": 0.7},
    {"src": "as1", "dst": "co1", "relation": "located_in", "confidence": 0.9},
]

_INV = {"id": "inv-test", "seed_type": "ip", "seed_value": "199.247.3.191",
        "created_at": 1700000000}


def _build():
    return sx.build_stix_bundle(_NODES, _EDGES, _INV, "inv-test", tlp="amber")


def _by_type(bundle, t):
    return [o for o in bundle["objects"] if o["type"] == t]


def test_no_forbidden_common_props_on_scos():
    b = _build()
    for o in b["objects"]:
        if o["type"] in _SCO_TYPES:
            for forbidden in ("confidence", "labels", "created", "modified",
                              "created_by_ref"):
                assert forbidden not in o, f"{forbidden} on SCO {o['type']}"


def test_invalid_email_dropped_valid_kept():
    b = _build()
    emails = [o["value"] for o in _by_type(b, "email-addr")]
    assert "abuse@evil.com" in emails
    assert "f651612a2f356ad3s@" not in emails
    # raw invalid value preserved on the report as an unmodelled observable
    rep = _by_type(b, "report")[0]
    assert any("f651612a2f356ad3s@" in u
               for u in rep.get("x_bounce_unmodelled_observables", []))


def test_tlp_marking_present_and_referenced():
    b = _build()
    markings = _by_type(b, "marking-definition")
    assert len(markings) == 1
    mid = markings[0]["id"]
    assert markings[0]["name"] == "TLP:AMBER"
    for o in b["objects"]:
        if o["type"] == "marking-definition":
            continue
        assert o.get("object_marking_refs") == [mid], f"{o['type']} unmarked"


def test_resolves_to_direction_corrected():
    b = _build()
    rels = _by_type(b, "relationship")
    types = {o["id"]: o["type"] for o in b["objects"]}
    rtr = [r for r in rels if r["relationship_type"] == "resolves-to"]
    assert len(rtr) == 1
    # source must be the domain, target the ipv4 (spec direction)
    assert types[rtr[0]["source_ref"]] == "domain-name"
    assert types[rtr[0]["target_ref"]] == "ipv4-addr"


def test_out_of_spec_pairs_downgraded():
    b = _build()
    types = {o["id"]: o["type"] for o in b["objects"]}
    for r in _by_type(b, "relationship"):
        rt = r["relationship_type"]
        st, tt = types[r["source_ref"]], types[r["target_ref"]]
        if rt == "related-to":
            continue
        rule = sx._REL_RULES.get(rt)
        assert rule, f"unexpected relationship_type {rt}"
        assert st in rule[0] and tt in rule[1], f"illegal pair {rt} {st}->{tt}"
    # located_in AS->location is not spec-valid → must have degraded
    located = [r for r in _by_type(b, "relationship")
               if r["relationship_type"] == "located-at"]
    assert located == []


def test_report_has_report_types():
    b = _build()
    rep = _by_type(b, "report")[0]
    assert rep.get("report_types") == ["threat-report"]


def test_malicious_observables_promoted_to_indicators():
    b = _build()
    inds = _by_type(b, "indicator")
    patterns = {i["pattern"] for i in inds}
    assert "[domain-name:value = 'evil.com']" in patterns
    assert "[ipv4-addr:value = '199.247.3.191']" in patterns
    for i in inds:
        assert i["pattern_type"] == "stix"
        assert i["indicator_types"]


def test_referential_integrity():
    b = _build()
    ids = {o["id"] for o in b["objects"]}
    for o in b["objects"]:
        for ref_key in ("source_ref", "target_ref", "created_by_ref"):
            if ref_key in o:
                assert o[ref_key] in ids, f"dangling {ref_key} on {o['type']}"
        for mref in o.get("object_marking_refs", []):
            assert mref in ids
        for oref in o.get("object_refs", []):
            assert oref in ids
