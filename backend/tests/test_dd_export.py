"""Unit tests for the KYB / Due-Diligence dossier renderer (pure, no DB)."""
from backend import dd_export as dx

_GRAPH = {
    "nodes": [
        {"id": "c1", "type": "company", "value": "Acme Holdings Ltd", "tags": ["seed"],
         "metadata": {"lei": "529900T8BM49AURSDO55", "jurisdiction": "GB",
                      "status": "active", "incorporated": "2010-01-01", "source": "gleif"}},
        {"id": "c2", "type": "company", "value": "Acme Sub SARL", "tags": [],
         "metadata": {"jurisdiction": "FR", "source": "gleif"}},
        {"id": "c3", "type": "company", "value": "BadCo OOO", "tags": ["sanctioned"],
         "metadata": {"list": "OFAC", "programs": ["UKRAINE-EO13662"], "source": "sanctions"}},
        {"id": "p1", "type": "person", "value": "Jane Doe", "tags": [],
         "metadata": {"role": "director", "nationality": "British", "dob": "1980-04",
                      "source": "companies_house"}},
        {"id": "p2", "type": "person", "value": "John Smith", "tags": ["sanctioned"],
         "metadata": {"natures_of_control": ["ownership-of-shares-75-to-100-percent"],
                      "list": "UK"}},
        {"id": "rep", "type": "report", "value": "investigation_summary",
         "metadata": {"summary": "Acme group, one sanctioned subsidiary."}},
    ],
    "edges": [
        {"source": "c2", "target": "c1", "relation": "subsidiary_of"},
        {"source": "p1", "target": "c1", "relation": "officer_of"},
        {"source": "p2", "target": "c1", "relation": "significant_control_of"},
    ],
}
_INV = {"id": "inv1", "seed_type": "company", "seed_value": "Acme Holdings Ltd", "title": "Acme"}


def test_header_and_summary():
    md = dx.render_kyb_dossier(_GRAPH, _INV)
    assert md.startswith("# KYB Dossier — Acme Holdings Ltd")
    assert "3 companies · 2 people · 3 relations" in md
    assert "Acme group, one sanctioned subsidiary." in md


def test_sanctions_headline_first_and_lists_flagged():
    md = dx.render_kyb_dossier(_GRAPH, _INV)
    # sanctions section appears before companies (headline)
    assert md.index("## ⚠️ Sanctions exposure") < md.index("## Companies")
    assert "2 flagged node(s)" in md
    assert "BadCo OOO" in md and "OFAC" in md and "UKRAINE-EO13662" in md
    assert "John Smith" in md and "UK" in md


def test_company_and_hierarchy_and_people():
    md = dx.render_kyb_dossier(_GRAPH, _INV)
    assert "LEI 529900T8BM49AURSDO55" in md
    assert "## Corporate hierarchy (estimated)" in md
    assert "`Acme Sub SARL` —[subsidiary_of]→ `Acme Holdings Ltd`" in md
    assert "## Officers & significant control (2)" in md
    assert "director" in md and "ownership-of-shares-75-to-100-percent" in md
    # sanctioned company/person are marked
    assert md.count("**SANCTIONED**") >= 2


def test_disclaimers_always_present():
    md = dx.render_kyb_dossier(_GRAPH, _INV)
    assert "ESTIMATED" in md and "UBO/RBE" in md
    assert "candidates for human review" in md.lower()
    assert "not legal advice" in md.lower()


def test_empty_graph_no_sanctions():
    md = dx.render_kyb_dossier({"nodes": [], "edges": []}, {"id": "x", "seed_value": "Foo"})
    assert "# KYB Dossier — Foo" in md
    assert "No sanctions match was recorded" in md
    assert "0 companies · 0 people · 0 relations" in md
