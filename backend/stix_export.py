"""Export an investigation graph as a STIX 2.1 bundle."""
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


# ── Node type → STIX object builder ──────────────────────────────────────────

def _make_domain(stix_id: str, node: dict, created: str) -> dict:
    return {
        "type": "domain-name",
        "spec_version": "2.1",
        "id": stix_id,
        "value": node["value"],
        "object_marking_refs": [],
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


def _make_email(stix_id: str, node: dict, created: str) -> dict:
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
_SKIP_TYPES = {"report", "jarm", "favicon", "js_hash"}


def generate_stix_bundle(inv_id: str) -> dict:
    """Generate a STIX 2.1 bundle from the investigation graph."""
    graph = gs.get_graph(inv_id)
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])

    # Investigation metadata for the Bounce-CTI identity
    with gs.conn() as c:
        inv_row = c.execute("SELECT * FROM investigations WHERE id=?", (inv_id,)).fetchone()
    inv = dict(inv_row) if inv_row else {}

    created = _ts(inv.get("created_at"))

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
    }

    objects = [identity_obj]
    node_id_map = {}  # bounce node id → stix id
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
        if ntype == "ip" and ":" in nvalue:
            stix_prefix = "ipv6-addr"
        stix_id = _stix_id(stix_prefix, inv_id, ntype, nvalue)
        node_id_map[n.get("id")] = stix_id

        ts_created = _ts(n.get("created_at"))
        obj = builder_fn(stix_id, n, ts_created)

        # Add created_by_ref for SDOs (they support it)
        if obj["type"] in ("malware", "campaign", "threat-actor", "identity",
                           "location", "report"):
            obj["created_by_ref"] = identity_id

        # Add confidence from bounce node (STIX 2.1 supports 0-100 integer)
        conf = n.get("confidence")
        if conf is not None and obj["type"] not in ("domain-name", "ipv4-addr",
                                                     "ipv6-addr", "url", "file",
                                                     "email-addr"):
            obj["confidence"] = max(0, min(100, int(conf * 100)))

        # Add tags as labels (STIX supports labels on SDOs)
        tags = n.get("tags", [])
        if tags and obj["type"] in ("malware", "campaign", "threat-actor",
                                     "identity", "location"):
            obj["labels"] = [str(t) for t in tags]

        # Add external references from metadata.sources_seen
        md = n.get("metadata", {})
        sources_seen = md.get("sources_seen", [])
        if sources_seen:
            obj["x_bounce_sources"] = [str(s) for s in sources_seen]

        objects.append(obj)

    # Convert edges to STIX relationships
    for e in edges:
        src_stix = node_id_map.get(e.get("src"))
        dst_stix = node_id_map.get(e.get("dst"))
        if not src_stix or not dst_stix:
            continue  # one end was skipped

        rel_type = _stix_relationship_type(e.get("relation", "related-to"))
        rel_seed = f"{inv_id}|{e.get('src')}|{e.get('dst')}|{e.get('relation')}"
        rel_id = f"relationship--{uuid.uuid5(_NAMESPACE, rel_seed)}"

        rel_obj = {
            "type": "relationship",
            "spec_version": "2.1",
            "id": rel_id,
            "relationship_type": rel_type,
            "source_ref": src_stix,
            "target_ref": dst_stix,
            "created": _ts(e.get("created_at")),
            "modified": _ts(e.get("created_at")),
            "created_by_ref": identity_id,
        }

        # Preserve the original Bounce-CTI relation as a custom property
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
            "published": created,
            "created": created,
            "modified": created,
            "created_by_ref": identity_id,
            "object_refs": all_obj_ids,
            "labels": [f"threat-assessment:{threat_assessment}"],
        }

        # IOC list as custom extension
        iocs = report_md.get("ioc_list", [])
        if iocs:
            report_obj["x_bounce_ioc_list"] = [str(i) for i in iocs]

        objects.append(report_obj)

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid5(_NAMESPACE, inv_id)}",
        "objects": objects,
    }

    return bundle
