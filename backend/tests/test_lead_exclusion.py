"""Integration tests for the lead tier's reach into the rest of the platform.

test_context_pool.py locks the pure predicates; this file locks that they are
actually *wired* — that an unverified lead cannot reach a firewall blocklist, a
takedown email, a STIX bundle consumed by a client TIP, or a dossier body, and
that the pivot queue treats a lead as a verification task rather than as an
indicator to fan out from.
"""
from backend import action_exports, dd_export, osint_export, stix_export
from backend import context_pool as cp
from backend import pivot_mapping as pm


# A graph containing one real observed indicator, one unverified lead, and one
# typed node that came in through the context pool and is still unratified.
_NODES = [
    {"id": "n1", "type": "domain", "value": "real-observed.com", "tags": [],
     "metadata": {"abuse_email": "abuse@host.example"}, "confidence": 0.8,
     "source": "crtsh", "created_at": 1.0},
    {"id": "n2", "type": "lead", "value": "this domain is probably Tycoon 2FA",
     "tags": [cp.TAG_UNVERIFIED], "metadata": {"claim_type": "naming"},
     "confidence": 0.3, "source": "parametric_memory", "created_at": 2.0},
    {"id": "n3", "type": "domain", "value": "hallucinated.com",
     "tags": [cp.TAG_UNVERIFIED],
     "metadata": {"abuse_email": "abuse@host.example"},
     "confidence": 0.35, "source": "web:blog.example", "created_at": 3.0},
    {"id": "n4", "type": "ip", "value": "9.9.9.9", "tags": [cp.TAG_CORROBORATED],
     "metadata": {}, "confidence": 0.7, "source": "mcp__cti__dns_resolve",
     "created_at": 4.0},
]


# ── Blocklists ─────────────────────────────────────────────────────────────

def test_blocklist_excludes_unverified_but_keeps_observed_and_corroborated():
    out = action_exports.render_blocklist(_NODES, "plain")
    assert "real-observed.com" in out
    assert "9.9.9.9" in out                    # corroborated → actionable
    assert "hallucinated.com" not in out       # unverified → never actionable
    assert "Tycoon" not in out                 # the lead itself never appears


def test_include_defused_override_does_not_unlock_unverified():
    """`include_defused` is a deliberate analyst override for real-but-noisy
    nodes. It must NOT double as an override for 'we are not sure this exists'."""
    out = action_exports.render_blocklist(_NODES, "plain", include_defused=True)
    assert "hallucinated.com" not in out
    assert "real-observed.com" in out


def test_every_blocklist_format_excludes_unverified():
    for fmt in ("plain", "hosts", "unbound", "rpz", "palo_edl", "cisco_acl", "csv"):
        out = action_exports.render_blocklist(_NODES, fmt)
        assert "hallucinated.com" not in out, fmt


def test_detection_rules_exclude_unverified():
    for fmt in ("sigma", "snort", "yara"):
        out = action_exports.render_detection(_NODES, fmt)
        assert "hallucinated.com" not in out, fmt


def test_takedown_never_targets_an_unverified_lead():
    """The worst-case export: an abuse email sent to a real hoster, under the
    analyst's name, about a domain the model may have invented."""
    bundles = action_exports.render_takedown(_NODES, [])
    targets = {b["target"]["value"] for b in bundles}
    assert "hallucinated.com" not in targets
    assert "real-observed.com" in targets


# ── STIX ───────────────────────────────────────────────────────────────────

def test_stix_bundle_excludes_leads_and_unverified_nodes():
    bundle = stix_export.build_stix_bundle(
        _NODES, [], {"seed_value": "real-observed.com", "seed_type": "domain"},
        "inv-test")
    # No SCO / indicator may carry the unratified values. (They are still named
    # in the report's x_bounce_unverified_leads_excluded property — see the
    # transparency test below — so assert on the objects, not on the blob.)
    observables = [o for o in bundle["objects"] if o.get("type") != "report"]
    blob = str(observables)
    assert "real-observed.com" in blob
    assert "hallucinated.com" not in blob
    assert "Tycoon" not in blob


def test_stix_reports_what_it_withheld():
    """Transparency, not silent omission: a consumer must be able to tell that
    context-pool material existed and was held back."""
    bundle = stix_export.build_stix_bundle(
        _NODES, [], {"seed_value": "real-observed.com", "seed_type": "domain"},
        "inv-test")
    reports = [o for o in bundle["objects"] if o.get("type") == "report"]
    assert reports, "expected a report SDO"
    excluded = reports[0].get("x_bounce_unverified_leads_excluded") or []
    assert any("hallucinated.com" in e for e in excluded)


def test_stix_still_discloses_when_everything_was_excluded():
    """The case a consumer most needs told about: nothing survived the tier
    gate. The bundle must still say so rather than being silently empty."""
    only_leads = [n for n in _NODES if not cp.is_actionable(n)]
    bundle = stix_export.build_stix_bundle(
        only_leads, [], {"seed_value": "x", "seed_type": "domain"}, "inv-test")
    reports = [o for o in bundle["objects"] if o.get("type") == "report"]
    assert reports, "a report SDO must still be emitted to carry the disclosure"
    assert reports[0].get("x_bounce_unverified_leads_excluded")
    # STIX 2.1 requires object_refs to be non-empty.
    assert reports[0]["object_refs"]


# ── Dossiers ───────────────────────────────────────────────────────────────

def test_osint_dossier_separates_leads_from_the_body():
    md = osint_export.render_dossier(
        {"nodes": _NODES, "edges": []},
        {"id": "inv-test", "seed_value": "someone", "seed_type": "username"})
    assert "Leads (context pool" in md
    # The unverified domain must not appear in the Domains section...
    body = md.split("Leads (context pool")[0]
    assert "hallucinated.com" not in body
    assert "real-observed.com" in body


def test_kyb_dossier_separates_leads_from_registry_fact():
    md = dd_export.render_kyb_dossier(
        {"nodes": _NODES, "edges": []},
        {"id": "inv-test", "seed_value": "ACME SA", "seed_type": "company"})
    assert "Leads (context pool" in md
    body = md.split("Leads (context pool")[0]
    assert "hallucinated.com" not in body


def test_dossiers_omit_the_section_entirely_when_there_are_no_leads():
    clean = [n for n in _NODES if n["type"] != "lead" and not (
        set(n["tags"]) & cp.NON_ACTIONABLE_TAGS)]
    md = osint_export.render_dossier(
        {"nodes": clean, "edges": []},
        {"id": "inv-test", "seed_value": "someone", "seed_type": "username"})
    assert "Leads (context pool" not in md


# ── Pivot queue ────────────────────────────────────────────────────────────

def test_lead_has_exactly_one_pivot_and_it_is_verification():
    """A lead's value is free text, not an indicator — it must never fan out the
    CTI pivot set the way a domain node does."""
    rules = pm.pivots_for("lead", "some free-text claim",
                          has_key=lambda s: True, vertical="osint")
    assert [op for op, _, _ in rules] == [cp.VERIFY_LEAD_OP]


def test_verify_lead_needs_no_api_key():
    rules = pm.pivots_for("lead", "claim", has_key=lambda s: False, vertical="dd")
    assert rules == [(cp.VERIFY_LEAD_OP, 2, None)]


def test_lead_pivot_is_registered_in_every_vertical():
    for vertical in ("cti", "osint", "dd"):
        rules = pm.pivots_for("lead", "claim", has_key=lambda s: True,
                              vertical=vertical)
        assert rules, vertical
        assert all(reason is None for _, _, reason in rules), vertical
