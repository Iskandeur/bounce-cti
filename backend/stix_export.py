"""Export an investigation graph as a STIX 2.1 bundle (or as a STIX-flavoured
CSV ready for an OpenCTI workbench)."""
import csv
import io
import uuid
import hashlib
import re
from datetime import datetime, timezone
from . import graph_store as gs


# Deterministic STIX UUIDv5 namespace for Bounce-CTI
_NAMESPACE = uuid.UUID("b0c1e2d3-4f5a-6b7c-8d9e-0f1a2b3c4d5e")


def _stix_id(type_prefix: str, inv_id: str, node_type: str, value: str) -> str:
    """Generate a deterministic STIX id from investigation + node identity."""
    seed = f"{inv_id}|{node_type}|{value.lower()}"
    uid = uuid.uuid5(_NAMESPACE, seed)
    return f"{type_prefix}--{uid}"


def _ts(epoch: float | None) -> str:
    """Convert epoch seconds to STIX timestamp string."""
    if not epoch:
        epoch = 0.0
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _stix_relationship_type(relation: str) -> str:
    """Map a Bounce-CTI edge relation to the closest STIX relationship-type."""
    mapping = {
        "resolves_to": "resolves-to",
        "registered_by": "attributed-to",
        "has_cert": "related-to",
        "sibling_domain": "related-to",
        "same_ns": "related-to",
        "same_favicon": "related-to",
        "same_jarm": "related-to",
        "hosted_on_asn": "related-to",
        "communicates_with": "communicates-with",
        "historical_resolution": "resolves-to",
        "belongs_to": "related-to",
        "associated_with": "related-to",
        "uses": "uses",
        "attributed_to": "attributed-to",
        "indicates": "indicates",
        "located_in": "located-at",
    }
    return mapping.get(relation, "related-to")


# ── STIX 2.1 conformance helpers ─────────────────────────────────────────────

# Cyber-observable (SCO) types we emit. `confidence`, `created`, `modified`,
# `created_by_ref` and `labels` are SDO/SRO-only common properties and MUST NOT
# appear on these (stix2-validator rejects them).
_SCO_TYPES = {
    "domain-name", "ipv4-addr", "ipv6-addr", "url", "file", "email-addr",
    "autonomous-system", "x509-certificate",
}
# STIX Domain Objects we emit, which DO accept the common properties above.
_SDO_TYPES = {
    "identity", "location", "malware", "campaign", "threat-actor",
    "intrusion-set", "indicator", "report",
}

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _is_valid_email(value: str) -> bool:
    return bool(_EMAIL_RE.match((value or "").strip()))


# Standard STIX 2.1 TLP marking-definition objects (the canonical fixed
# representations from the spec — well-known IDs + the canonical
# created timestamp, so a strict validator / the stix2 lib accepts them
# verbatim). Default to TLP:AMBER for shareable-but-limited CTI.
_TLP_CREATED = "2017-01-20T00:00:00.000Z"
_TLP_MARKINGS = {
    "white": {
        "type": "marking-definition", "spec_version": "2.1",
        "id": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
        "created": _TLP_CREATED, "definition_type": "tlp",
        "name": "TLP:WHITE", "definition": {"tlp": "white"},
    },
    "green": {
        "type": "marking-definition", "spec_version": "2.1",
        "id": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
        "created": _TLP_CREATED, "definition_type": "tlp",
        "name": "TLP:GREEN", "definition": {"tlp": "green"},
    },
    "amber": {
        "type": "marking-definition", "spec_version": "2.1",
        "id": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
        "created": _TLP_CREATED, "definition_type": "tlp",
        "name": "TLP:AMBER", "definition": {"tlp": "amber"},
    },
    "red": {
        "type": "marking-definition", "spec_version": "2.1",
        "id": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
        "created": _TLP_CREATED, "definition_type": "tlp",
        "name": "TLP:RED", "definition": {"tlp": "red"},
    },
}


# STIX 2.1 relationship pair rules: relationship_type → (allowed source types,
# allowed target types). `related-to` is the universal fallback (any → any) and
# is intentionally absent. When a mapped relationship's endpoints don't fit the
# spec, we downgrade to related-to (preserving the intent in x_bounce_relation)
# rather than emit an illegal pairing. resolves-to additionally supports a
# direction flip (an ipv4-addr → domain-name edge becomes domain-name → ipv4).
_REL_RULES = {
    "resolves-to": ({"domain-name"},
                    {"ipv4-addr", "ipv6-addr", "domain-name"}),
    "communicates-with": ({"malware", "infrastructure"},
                          {"ipv4-addr", "ipv6-addr", "domain-name", "url"}),
    "attributed-to": ({"campaign", "intrusion-set", "threat-actor"},
                      {"threat-actor", "identity", "intrusion-set"}),
    "located-at": ({"threat-actor", "intrusion-set", "campaign", "malware",
                    "identity", "infrastructure"},
                   {"location"}),
    "indicates": ({"indicator"},
                  {"attack-pattern", "campaign", "infrastructure",
                   "intrusion-set", "malware", "threat-actor", "tool"}),
    "uses": ({"threat-actor", "intrusion-set", "campaign", "malware",
              "identity", "infrastructure", "tool"},
             {"malware", "tool", "infrastructure", "attack-pattern"}),
}


def _normalise_relationship(rel_type: str, src_type: str, dst_type: str):
    """Return (final_relationship_type, flip) so the emitted SRO is spec-valid.

    `flip` True means swap source/target. Out-of-spec pairings degrade to
    related-to instead of producing a relationship the spec forbids.
    """
    if rel_type == "related-to":
        return "related-to", False
    rule = _REL_RULES.get(rel_type)
    if not rule:
        return "related-to", False
    src_ok, dst_ok = rule
    if src_type in src_ok and dst_type in dst_ok:
        return rel_type, False
    # Reversed but otherwise valid (chiefly resolves-to ipv4 → domain).
    if src_type in dst_ok and dst_type in src_ok:
        return rel_type, True
    return "related-to", False


# Node tags that promote an observable to a deployable detection indicator.
_MALICIOUS_TAGS = {
    "malicious", "suspicious", "c2", "command_and_control", "phishing",
    "malware_hosting", "known_ioc", "known_bad", "ioc", "botnet_c2",
}

# observable STIX type → STIX pattern expression for its value.
_PATTERN_LHS = {
    "domain-name": "domain-name:value",
    "ipv4-addr": "ipv4-addr:value",
    "ipv6-addr": "ipv6-addr:value",
    "url": "url:value",
    "email-addr": "email-addr:value",
}


def _pattern_escape(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace("'", "\\'")


def _indicator_pattern(stix_type: str, node: dict) -> str | None:
    """Build a valid STIX 2.1 pattern for an observable node, or None."""
    value = node.get("value", "")
    if stix_type == "file":
        h_len = len(str(value))
        algo = {32: "MD5", 40: "SHA-1", 64: "SHA-256", 128: "SHA-512"}.get(h_len)
        if not algo:
            return None
        return f"[file:hashes.'{algo}' = '{_pattern_escape(value)}']"
    lhs = _PATTERN_LHS.get(stix_type)
    if not lhs:
        return None
    return f"[{lhs} = '{_pattern_escape(value)}']"


# ── Node type → STIX object builder ──────────────────────────────────────────

def _make_domain(stix_id: str, node: dict, created: str) -> dict:
    return {
        "type": "domain-name",
        "spec_version": "2.1",
        "id": stix_id,
        "value": node["value"],
    }


def _make_ip(stix_id: str, node: dict, created: str) -> dict:
    v = node["value"]
    stype = "ipv6-addr" if ":" in v else "ipv4-addr"
    return {
        "type": stype,
        "spec_version": "2.1",
        "id": stix_id.replace("ipv4-addr", stype).replace("ipv6-addr", stype),
        "value": v,
    }


def _make_url(stix_id: str, node: dict, created: str) -> dict:
    return {
        "type": "url",
        "spec_version": "2.1",
        "id": stix_id,
        "value": node["value"],
    }


def _make_hash(stix_id: str, node: dict, created: str) -> dict:
    v = node["value"]
    # Detect hash type by length
    h_len = len(v)
    if h_len == 32:
        algo = "MD5"
    elif h_len == 40:
        algo = "SHA-1"
    elif h_len == 64:
        algo = "SHA-256"
    elif h_len == 128:
        algo = "SHA-512"
    else:
        algo = "MD5"  # fallback
    return {
        "type": "file",
        "spec_version": "2.1",
        "id": stix_id,
        "hashes": {algo: v},
    }


def _make_email(stix_id: str, node: dict, created: str) -> dict | None:
    # STIX 2.1 requires email-addr.value to be a valid RFC 5322 address.
    # Bounce sometimes carries a privacy-hashed WHOIS token (e.g.
    # "f651612a2f356ad3s@") which is NOT a valid address — emitting it as an
    # email-addr SCO produces a non-conformant bundle. Skip the SCO in that
    # case (caller records the raw value as an unmodelled observable instead).
    if not _is_valid_email(node.get("value", "")):
        return None
    return {
        "type": "email-addr",
        "spec_version": "2.1",
        "id": stix_id,
        "value": node["value"],
    }


def _make_asn(stix_id: str, node: dict, created: str) -> dict:
    # Extract numeric ASN from values like "AS12345" or "12345"
    raw = node["value"]
    num_match = re.search(r"\d+", raw)
    number = int(num_match.group()) if num_match else 0
    md = node.get("metadata", {})
    obj = {
        "type": "autonomous-system",
        "spec_version": "2.1",
        "id": stix_id,
        "number": number,
    }
    name = md.get("as_owner") or md.get("name") or md.get("description")
    if name:
        obj["name"] = str(name)
    return obj


def _make_cert(stix_id: str, node: dict, created: str) -> dict:
    md = node.get("metadata", {})
    obj = {
        "type": "x509-certificate",
        "spec_version": "2.1",
        "id": stix_id,
    }
    if md.get("serial_number"):
        obj["serial_number"] = str(md["serial_number"])
    if md.get("subject"):
        obj["subject"] = str(md["subject"])
    if md.get("issuer"):
        obj["issuer"] = str(md["issuer"])
    # Use the value (usually a fingerprint) as serial if nothing else
    if "serial_number" not in obj:
        obj["serial_number"] = node["value"]
    return obj


def _make_country(stix_id: str, node: dict, created: str) -> dict:
    v = node["value"]
    return {
        "type": "location",
        "spec_version": "2.1",
        "id": stix_id,
        "country": v[:2].upper() if len(v) == 2 else v,
        "name": v,
        "created": created,
        "modified": created,
    }


def _make_registrar(stix_id: str, node: dict, created: str) -> dict:
    return {
        "type": "identity",
        "spec_version": "2.1",
        "id": stix_id,
        "name": node["value"],
        "identity_class": "organization",
        "created": created,
        "modified": created,
    }


def _make_ns(stix_id: str, node: dict, created: str) -> dict:
    # Nameservers are domains
    return {
        "type": "domain-name",
        "spec_version": "2.1",
        "id": stix_id,
        "value": node["value"],
    }


def _make_malware(stix_id: str, node: dict, created: str) -> dict:
    return {
        "type": "malware",
        "spec_version": "2.1",
        "id": stix_id,
        "name": node["value"],
        "is_family": True,
        "created": created,
        "modified": created,
    }


def _make_campaign(stix_id: str, node: dict, created: str) -> dict:
    return {
        "type": "campaign",
        "spec_version": "2.1",
        "id": stix_id,
        "name": node["value"],
        "created": created,
        "modified": created,
    }


def _make_threat_actor(stix_id: str, node: dict, created: str) -> dict:
    return {
        "type": "threat-actor",
        "spec_version": "2.1",
        "id": stix_id,
        "name": node["value"],
        "created": created,
        "modified": created,
    }


# Map bounce-cti node.type → (STIX type prefix for ID, builder function)
_BUILDERS = {
    "domain":    ("domain-name",        _make_domain),
    "ip":        ("ipv4-addr",          _make_ip),
    "url":       ("url",                _make_url),
    "hash":      ("file",               _make_hash),
    "email":     ("email-addr",         _make_email),
    "asn":       ("autonomous-system",  _make_asn),
    "cert":      ("x509-certificate",   _make_cert),
    "country":   ("location",           _make_country),
    "registrar": ("identity",           _make_registrar),
    "ns":        ("domain-name",        _make_ns),
    "malware":   ("malware",            _make_malware),
    "campaign":  ("campaign",           _make_campaign),
    "apt":       ("threat-actor",       _make_threat_actor),
}

# Types we intentionally skip (no standard STIX SCO/SDO equivalent)
_SKIP_TYPES = {"report", "jarm", "ja3", "ja3s", "favicon", "js_hash"}


def generate_stix_bundle(inv_id: str, tlp: str = "amber") -> dict:
    """Generate a STIX 2.1 bundle from the investigation graph (DB-backed)."""
    graph = gs.get_graph(inv_id)
    with gs.conn() as c:
        inv_row = c.execute("SELECT * FROM investigations WHERE id=?", (inv_id,)).fetchone()
    inv = dict(inv_row) if inv_row else {}
    return build_stix_bundle(
        graph.get("nodes", []), graph.get("edges", []), inv, inv_id, tlp=tlp,
    )


def build_stix_bundle(nodes, edges, inv, inv_id, tlp: str = "amber") -> dict:
    """Pure STIX 2.1 bundle builder (no DB access — unit-testable).

    Conformance contract enforced here:
      * Cyber-observables (SCOs) carry NO confidence/labels/created/
        created_by_ref (those are SDO/SRO-only common properties).
      * email-addr is only emitted for RFC-valid addresses; privacy-hashed
        WHOIS tokens are recorded as unmodelled observables on the report.
      * Every object is stamped with a TLP marking-definition (default AMBER).
      * Relationships are validated against the spec's source/target pairs;
        out-of-spec pairs degrade to related-to (resolves-to is flipped when
        reversed). The original Bounce relation is kept in x_bounce_relation.
      * The report carries report_types (SHOULD) alongside the legacy label.
    """
    created = _ts(inv.get("created_at"))

    # TLP marking applied to every object (SCOs MAY carry object_marking_refs
    # in 2.1, so this is uniform and spec-clean).
    marking = _TLP_MARKINGS.get((tlp or "amber").lower(), _TLP_MARKINGS["amber"])
    marking_id = marking["id"]

    # Bounce-CTI as the creator identity
    identity_id = f"identity--{uuid.uuid5(_NAMESPACE, 'bounce-cti')}"
    identity_obj = {
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "name": "Bounce-CTI",
        "identity_class": "system",
        "created": created,
        "modified": created,
        "object_marking_refs": [marking_id],
    }

    objects = [identity_obj]
    node_id_map = {}        # bounce node id → stix id
    stix_type_by_id = {}    # stix id → stix type (for relationship validation)
    indicator_seeds = []    # (node, stix_type) eligible for an indicator SDO
    unmodelled = []         # raw values we couldn't represent as a valid SCO
    skipped = set()

    # Convert nodes
    for n in nodes:
        ntype = n.get("type", "")
        nvalue = n.get("value", "")

        if ntype in _SKIP_TYPES:
            skipped.add(n.get("id"))
            continue

        builder_entry = _BUILDERS.get(ntype)
        if not builder_entry:
            skipped.add(n.get("id"))
            continue

        stix_prefix, builder_fn = builder_entry
        # For IP nodes, adjust the prefix for the actual type
        if ntype == "ip" and ":" in str(nvalue):
            stix_prefix = "ipv6-addr"
        stix_id = _stix_id(stix_prefix, inv_id, ntype, nvalue)

        ts_created = _ts(n.get("created_at"))
        obj = builder_fn(stix_id, n, ts_created)
        if obj is None:
            # Builder rejected the value (e.g. invalid email) — keep the raw
            # signal on the report instead of emitting a malformed SCO.
            skipped.add(n.get("id"))
            if nvalue:
                unmodelled.append(f"{ntype}:{nvalue}")
            continue

        node_id_map[n.get("id")] = stix_id
        stix_type_by_id[stix_id] = obj["type"]
        is_sdo = obj["type"] in _SDO_TYPES

        # created_by_ref / confidence / labels are SDO/SRO-only common props.
        if is_sdo:
            obj["created_by_ref"] = identity_id
            conf = n.get("confidence")
            if conf is not None:
                obj["confidence"] = max(0, min(100, int(conf * 100)))
            tags = n.get("tags", [])
            if tags:
                obj["labels"] = [str(t) for t in tags]

        # external references — custom prop, allowed on any object.
        md = n.get("metadata", {}) or {}
        sources_seen = md.get("sources_seen", [])
        if sources_seen:
            obj["x_bounce_sources"] = [str(s) for s in sources_seen]

        obj["object_marking_refs"] = [marking_id]
        objects.append(obj)

        # Track malicious observables for indicator promotion.
        if obj["type"] in _SCO_TYPES and _MALICIOUS_TAGS.intersection(
            str(t).lower() for t in (n.get("tags") or [])
        ):
            indicator_seeds.append((n, obj["type"]))

    # Promote malicious observables to deployable detection indicators (SDOs
    # with a real STIX pattern), addressing the "no indicators" gap.
    for n, stix_type in indicator_seeds:
        pattern = _indicator_pattern(stix_type, n)
        if not pattern:
            continue
        ind_id = _stix_id("indicator", inv_id, "indicator", n.get("value", ""))
        tags_l = {str(t).lower() for t in (n.get("tags") or [])}
        ind_types = (["malicious-activity"] if "malicious" in tags_l
                     else ["anomalous-activity"])
        ind = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": ind_id,
            "name": f"{n.get('type', 'ioc')}: {n.get('value', '')}",
            "indicator_types": ind_types,
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": _ts(n.get("created_at")),
            "created": _ts(n.get("created_at")),
            "modified": _ts(n.get("created_at")),
            "created_by_ref": identity_id,
            "labels": [str(t) for t in (n.get("tags") or [])],
            "object_marking_refs": [marking_id],
        }
        objects.append(ind)
        stix_type_by_id[ind_id] = "indicator"

    # Convert edges to STIX relationships
    for e in edges:
        src_stix = node_id_map.get(e.get("src"))
        dst_stix = node_id_map.get(e.get("dst"))
        if not src_stix or not dst_stix:
            continue  # one end was skipped

        mapped = _stix_relationship_type(e.get("relation", "related-to"))
        rel_type, flip = _normalise_relationship(
            mapped, stix_type_by_id[src_stix], stix_type_by_id[dst_stix],
        )
        s_ref, t_ref = (dst_stix, src_stix) if flip else (src_stix, dst_stix)

        rel_seed = f"{inv_id}|{e.get('src')}|{e.get('dst')}|{e.get('relation')}"
        rel_id = f"relationship--{uuid.uuid5(_NAMESPACE, rel_seed)}"

        rel_obj = {
            "type": "relationship",
            "spec_version": "2.1",
            "id": rel_id,
            "relationship_type": rel_type,
            "source_ref": s_ref,
            "target_ref": t_ref,
            "created": _ts(e.get("created_at")),
            "modified": _ts(e.get("created_at")),
            "created_by_ref": identity_id,
            "object_marking_refs": [marking_id],
        }

        # Preserve the original Bounce-CTI relation when it carries more
        # nuance than the emitted STIX type (incl. spec-downgraded pairs).
        orig_rel = e.get("relation", "")
        if orig_rel and orig_rel != rel_type:
            rel_obj["x_bounce_relation"] = orig_rel

        conf = e.get("confidence")
        if conf is not None:
            rel_obj["confidence"] = max(0, min(100, int(conf * 100)))

        evidence = e.get("evidence")
        if evidence:
            rel_obj["description"] = str(evidence)

        objects.append(rel_obj)

    # Build the report SDO that references all objects
    report_node = None
    for n in nodes:
        if n.get("type") == "report" and n.get("value") == "investigation_summary":
            report_node = n
            break

    report_md = report_node.get("metadata", {}) if report_node else {}
    threat_assessment = report_md.get("threat_assessment", "unknown")
    summary = report_md.get("summary", "")

    all_obj_ids = [o["id"] for o in objects if o["id"] != identity_id]
    if all_obj_ids:
        report_stix_id = _stix_id("report", inv_id, "report", "stix_bundle")
        report_obj = {
            "type": "report",
            "spec_version": "2.1",
            "id": report_stix_id,
            "name": f"Bounce-CTI Investigation: {inv.get('seed_value', inv_id)}",
            "description": summary or f"Investigation of {inv.get('seed_type', 'unknown')} "
                           f"seed: {inv.get('seed_value', inv_id)}",
            "report_types": ["threat-report"],
            "published": created,
            "created": created,
            "modified": created,
            "created_by_ref": identity_id,
            "object_refs": all_obj_ids,
            "labels": [f"threat-assessment:{threat_assessment}"],
            "object_marking_refs": [marking_id],
        }

        # IOC list + observables we couldn't model as valid SCOs (custom props).
        iocs = report_md.get("ioc_list", [])
        if iocs:
            report_obj["x_bounce_ioc_list"] = [str(i) for i in iocs]
        if unmodelled:
            report_obj["x_bounce_unmodelled_observables"] = unmodelled

        objects.append(report_obj)

    # The TLP marking-definition must be present for its refs to resolve.
    objects.insert(1, dict(marking))

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid5(_NAMESPACE, inv_id)}",
        "objects": objects,
    }

    return bundle


# ── CSV export (OpenCTI workbench-ready) ─────────────────────────────────────

# Maps Bounce-CTI node.type to (stix_type, opencti_entity_type) tuples. The
# opencti_entity_type column matches the display names OpenCTI's CSV mapper
# expects (e.g. "StixFile" for files, "Url" capitalised) so an analyst can
# point a workbench CSV mapper at this output without renaming columns.
_CSV_TYPE_MAP = {
    "domain":    ("domain-name",       "Domain-Name"),
    "ip":        ("ipv4-addr",         "IPv4-Addr"),
    "url":       ("url",               "Url"),
    "hash":      ("file",              "StixFile"),
    "email":     ("email-addr",        "Email-Addr"),
    "asn":       ("autonomous-system", "Autonomous-System"),
    "cert":      ("x509-certificate",  "X509-Certificate"),
    "country":   ("location",          "Location"),
    "registrar": ("identity",          "Identity"),
    "ns":        ("domain-name",       "Domain-Name"),
    "malware":   ("malware",           "Malware"),
    "campaign":  ("campaign",          "Campaign"),
    "apt":       ("threat-actor",      "Threat-Actor"),
}

_CSV_COLUMNS = [
    "stix_type",
    "entity_type",
    "value",
    "hash_algorithm",
    "hash_md5",
    "hash_sha1",
    "hash_sha256",
    "labels",
    "confidence",
    "sources",
    "description",
    "first_seen",
    "last_seen",
    "investigation_id",
    "investigation_seed",
]


def _csv_iso(epoch) -> str:
    if not epoch:
        return ""
    try:
        return datetime.fromtimestamp(float(epoch), tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    except (TypeError, ValueError):
        return ""


def _csv_description(node: dict) -> str:
    """Build a short description string from node metadata. Truncated so the
    CSV stays readable in spreadsheet apps."""
    md = node.get("metadata") or {}
    parts = []
    for k in ("summary", "description", "evidence", "as_owner", "country",
              "registrar", "signature", "subject", "issuer"):
        v = md.get(k)
        if v:
            parts.append(f"{k}={v}")
            if len(parts) >= 4:
                break
    text = " | ".join(str(p) for p in parts)
    return text[:500]


def generate_csv(inv_id: str) -> str:
    """Export the investigation's observables as a STIX-flavoured CSV.

    One row per observable / domain object. Hashes get split across
    hash_md5/hash_sha1/hash_sha256 columns based on digest length so an
    OpenCTI CSV mapper can wire each column to the matching StixFile
    attribute. `sources` is the union of `metadata.sources_seen` across
    the node, semicolon-separated.
    """
    graph = gs.get_graph(inv_id)
    nodes = graph.get("nodes", [])

    with gs.conn() as c:
        row = c.execute("SELECT * FROM investigations WHERE id=?", (inv_id,)).fetchone()
    inv = dict(row) if row else {}
    seed_label = f"{inv.get('seed_type', '')}:{inv.get('seed_value', '')}".strip(":")

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_CSV_COLUMNS, extrasaction="ignore")
    writer.writeheader()

    # Stable ordering: by type then value so successive exports of the same
    # investigation diff cleanly in source control.
    for n in sorted(nodes, key=lambda x: (x.get("type", ""), str(x.get("value", "")))):
        ntype = n.get("type", "")
        nvalue = n.get("value", "")
        mapping = _CSV_TYPE_MAP.get(ntype)
        if not mapping:
            continue  # skip report/jarm/favicon/js_hash/etc.

        stix_type, entity_type = mapping
        if ntype == "ip" and ":" in str(nvalue):
            stix_type = "ipv6-addr"
            entity_type = "IPv6-Addr"

        md = n.get("metadata") or {}
        sources = md.get("sources_seen") or []
        tags = n.get("tags") or []
        conf = n.get("confidence")

        # Hash splitting for the StixFile rows.
        hash_md5 = hash_sha1 = hash_sha256 = ""
        hash_algo = ""
        if ntype == "hash":
            h_len = len(str(nvalue))
            if h_len == 32:
                hash_md5, hash_algo = nvalue, "MD5"
            elif h_len == 40:
                hash_sha1, hash_algo = nvalue, "SHA-1"
            elif h_len == 64:
                hash_sha256, hash_algo = nvalue, "SHA-256"

        writer.writerow({
            "stix_type": stix_type,
            "entity_type": entity_type,
            "value": nvalue,
            "hash_algorithm": hash_algo,
            "hash_md5": hash_md5,
            "hash_sha1": hash_sha1,
            "hash_sha256": hash_sha256,
            "labels": ";".join(str(t) for t in tags),
            "confidence": "" if conf is None else str(max(0, min(100, int(float(conf) * 100)))),
            "sources": ";".join(str(s) for s in sources),
            "description": _csv_description(n),
            "first_seen": _csv_iso(n.get("created_at")),
            "last_seen": _csv_iso(n.get("created_at")),
            "investigation_id": inv_id,
            "investigation_seed": seed_label,
        })

    return buf.getvalue()
