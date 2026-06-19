"""Unit tests for sanctions screening parsers + matcher (no network)."""
import asyncio

from backend.sources import sanctions as s


# ── normalisation + scoring ────────────────────────────────────────────────
def test_normalize_strips_suffix_punct_diacritics():
    assert s._normalize("Acme, Ltd.") == "acme"
    assert s._normalize("Société Générale") == "societe generale"  # diacritics
    assert s._normalize("ACME  CORP") == "acme"                    # suffix + ws


def test_score_exact_subset_jaccard():
    assert s._score("acme", {"acme"}, "ACME Ltd") == 100
    # token subset (>=2 tokens)
    assert s._score("john smith", {"john", "smith"}, "John Q Smith") == 95
    # single common token must NOT trigger subset rule
    assert s._score("john", {"john"}, "John Q Smith") < 95
    # disjoint
    assert s._score("acme", {"acme"}, "Globex") == 0


# ── OFAC SDN.CSV (positional, no header) ───────────────────────────────────
_OFAC = (
    '1,"BADCO LIMITED","-0-","UKRAINE-EO13662","-0-"\n'
    '2,"SMITH, John","individual","SDGT","-0-"\n'
    '3,"-0-","-0-","-0-"\n'
)


def test_parse_ofac():
    out = s._parse_ofac(_OFAC)
    names = {e["name"]: e for e in out}
    assert "BADCO LIMITED" in names and names["BADCO LIMITED"]["type"] == "entity"
    assert names["BADCO LIMITED"]["programs"] == ["UKRAINE-EO13662"]
    assert names["SMITH, John"]["type"] == "person"
    assert all(e["name"] != "-0-" for e in out)  # placeholder rows dropped


# ── EU FSF CSV (semicolon, header, grouped by ref) ─────────────────────────
_EU = (
    "Entity_EU_ReferenceNumber;NameAlias_WholeName;Entity_SubjectType;regulation\n"
    "EU.1;Evil Corp;enterprise;2014/512\n"
    "EU.1;Evil Corporation;enterprise;2014/512\n"
    "EU.2;Jane Roe;person;2022/263\n"
)


def test_parse_eu_groups_aliases():
    out = {e["ref"]: e for e in s._parse_eu(_EU)}
    assert out["EU.1"]["name"] == "Evil Corp"
    assert "Evil Corporation" in out["EU.1"]["aliases"]
    assert out["EU.1"]["type"] == "entity"
    assert out["EU.2"]["type"] == "person"
    assert out["EU.2"]["programs"] == ["2022/263"]


# ── UK UKSL CSV (title line + Name 1..6 + Group ID) ────────────────────────
_UK = (
    "UK Sanctions List - generated 2026-06-16\n"
    "Name 6,Name 1,Name 2,Group ID,Group Type,Regime\n"
    ",Bad,Holdings,100,Entity,Russia\n"
    ",Bad,Holding,100,Entity,Russia\n"
    ",John,Doe,200,Individual,Russia\n"
)


def test_parse_uk_concatenates_names_and_groups():
    out = {e["ref"]: e for e in s._parse_uk(_UK)}
    assert out["100"]["name"] == "Bad Holdings"
    assert "Bad Holding" in out["100"]["aliases"]
    assert out["100"]["type"] == "entity"
    assert out["200"]["name"] == "John Doe" and out["200"]["type"] == "person"


# ── screen() end to end (parsed lists injected) ────────────────────────────
def test_screen_matches_and_flags(monkeypatch):
    async def fake_entries(list_name):
        return {
            "OFAC": s._parse_ofac(_OFAC),
            "EU": s._parse_eu(_EU),
            "UK": s._parse_uk(_UK),
        }[list_name]

    monkeypatch.setattr(s, "_entries", fake_entries)
    out = asyncio.run(s.screen("Evil Corp"))
    assert out["sanctioned"] is True
    assert any(h["list"] == "EU" and h["name"] == "Evil Corp" for h in out["hits"])
    assert out["lists_checked"] == ["OFAC", "EU", "UK"]


def test_screen_alias_hit(monkeypatch):
    # An alias that does NOT collapse to the primary after normalisation.
    eu = "Entity_EU_ReferenceNumber;NameAlias_WholeName;Entity_SubjectType;regulation\n" \
         "EU.9;Northwind Trading;enterprise;2014/512\n" \
         "EU.9;Boreas Shipping;enterprise;2014/512\n"

    async def fake_entries(list_name):
        return s._parse_eu(eu) if list_name == "EU" else []
    monkeypatch.setattr(s, "_entries", fake_entries)
    out = asyncio.run(s.screen("Boreas Shipping", lists=["EU"]))
    assert out["sanctioned"] is True
    assert out["hits"][0]["matched_on"] == "Boreas Shipping"  # matched the alias
    assert out["hits"][0]["name"] == "Northwind Trading"      # primary reported


def test_screen_no_hit(monkeypatch):
    async def fake_entries(list_name):
        return s._parse_ofac(_OFAC) if list_name == "OFAC" else []
    monkeypatch.setattr(s, "_entries", fake_entries)
    out = asyncio.run(s.screen("Totally Clean Inc", lists=["OFAC"]))
    assert out["sanctioned"] is False and out["hit_count"] == 0


def test_screen_empty_query():
    out = asyncio.run(s.screen("  "))
    assert out["hits"] == [] and "error" in out
