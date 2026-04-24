"""MCP server exposing graph write/read tools to the agent.

Investigation id is read from env BOUNCE_INV_ID (set by backend when spawning claude).
"""
import os
from mcp.server.fastmcp import FastMCP
from .. import graph_store as gs
from ..defuse_lists import defuse_check

INV_ID = os.environ.get("BOUNCE_INV_ID", "default")
mcp = FastMCP("bounce-graph")


@mcp.tool()
def add_node(type: str, value: str, metadata: dict | None = None,
             confidence: float = 0.8, source: str = "agent",
             tags: list[str] | None = None) -> dict:
    """Add or merge a node in the investigation graph.

    type: one of domain, ip, hash, url, cert, asn, email, registrar, ns, favicon, jarm, ja3
    value: the node identifier (e.g. the domain string)
    metadata: free-form dict (whois, geo, ports, etc.)
    confidence: 0..1
    source: name of the source ("crtsh", "vt", "agent", ...)
    tags: list of semantic tags (e.g. ["cdn", "parking"])
    """
    return gs.add_node(INV_ID, type, value, metadata=metadata,
                       confidence=confidence, source=source, tags=tags)


@mcp.tool()
def add_edge(src_type: str, src_value: str, dst_type: str, dst_value: str,
             relation: str, evidence: str = "", source: str = "agent",
             confidence: float = 0.8) -> dict:
    """Add an edge between two nodes.

    relation examples: resolves_to, has_subdomain, shares_cert, same_registrant,
    same_ns, same_favicon, same_jarm, hosted_on_asn, communicates_with,
    historical_resolution
    """
    return gs.add_edge(INV_ID, src_type, src_value, dst_type, dst_value,
                       relation, evidence=evidence, source=source, confidence=confidence)


@mcp.tool()
def tag_node(type: str, value: str, tag: str | None = None,
             tags: list[str] | None = None) -> str:
    """Tag a node (cdn, parking, sinkhole, dyndns, shared_hosting, suspicious, benign, etc.).

    Pass either `tag` (single) or `tags` (list). Both are accepted for convenience.
    """
    items: list[str] = []
    if tag:
        items.append(tag)
    if tags:
        items.extend(tags)
    for t in items:
        gs.tag_node(INV_ID, type, value, t)
    return "ok"


@mcp.tool()
def get_graph(compact: bool = False) -> dict:
    """Return the current investigation graph (nodes + edges).

    For large graphs (50+ nodes), use compact=True to get a summary that fits
    within tool output limits. Compact mode returns:
      - nodes: list of {id, type, value, tags, confidence} (no metadata)
      - edges: list of {src, dst, relation} (no evidence/confidence)
      - stats: {node_count, edge_count, type_counts}
    Report metadata is NOT included in compact mode — call get_report()
    separately to get the report.

    Full mode (compact=False) returns all nodes and edges with full metadata.
    If the graph is very large, full mode may exceed output limits and fail;
    in that case, retry with compact=True and use get_node() for specific nodes.
    """
    graph = gs.get_graph(INV_ID)
    if not compact:
        return graph
    # Compact mode: strip metadata from non-report nodes, simplify edges
    nodes_compact = []
    for n in graph.get("nodes", []):
        if n.get("type") == "report":
            continue  # report data accessed via get_report()
        nodes_compact.append({
            "id": n.get("id"),
            "type": n.get("type"),
            "value": n.get("value"),
            "tags": n.get("tags", []),
            "confidence": n.get("confidence"),
        })
    edges_compact = [
        {"src": e.get("src"), "dst": e.get("dst"), "relation": e.get("relation")}
        for e in graph.get("edges", [])
    ]
    from collections import Counter
    type_counts = dict(Counter(n["type"] for n in nodes_compact))
    return {
        "nodes": nodes_compact,
        "edges": edges_compact,
        "stats": {
            "node_count": len(nodes_compact),
            "edge_count": len(edges_compact),
            "type_counts": type_counts,
        },
    }


@mcp.tool()
def get_node(type: str, value: str) -> dict | None:
    """Return a single node with full metadata. Use this to inspect specific
    nodes when the full graph is too large to retrieve at once."""
    graph = gs.get_graph(INV_ID)
    for n in graph.get("nodes", []):
        if n.get("type") == type and n.get("value") == value:
            return n
    return None


@mcp.tool()
def get_report() -> dict:
    """Return just the report node metadata (summary, threat_assessment,
    key_findings, prompt_history, etc.). Faster and smaller than get_graph
    when you only need the report."""
    graph = gs.get_graph(INV_ID)
    for n in graph.get("nodes", []):
        if n.get("type") == "report" and n.get("value") == "investigation_summary":
            return n.get("metadata", {})
    return {}


@mcp.tool()
def defuse(kind: str, value: str) -> dict:
    """Check if an indicator is a CDN/parking/sinkhole/dyndns. ALWAYS call before pivoting on an IP or NS.

    kind: ip | domain | ns
    Returns {tags, reasons, should_stop_pivot}.
    """
    return defuse_check(kind, value)


if __name__ == "__main__":
    mcp.run()
