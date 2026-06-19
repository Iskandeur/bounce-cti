"""Unit tests for the French Recherche d'entreprises (DD) parsers (no network)."""
import asyncio

from backend.sources import recherche_entreprises as re_src


_RESULT = {
    "siren": "552032534", "nom_complet": "DANONE", "nom_raison_sociale": "DANONE",
    "etat_administratif": "A", "nature_juridique": "5710", "activite_principale": "70.10Z",
    "date_creation": "1900-01-01", "tranche_effectif_salarie": "52",
    "statut_diffusion": "O",
    "siege": {"geo_adresse": "17 Boulevard Haussmann 75009 Paris"},
    "dirigeants": [
        {"nom": "FABER", "prenoms": "Emmanuel", "qualite": "Président",
         "type_dirigeant": "personne physique", "nationalite": "Française",
         "date_de_naissance": "1964-02"},
        {"denomination": "HOLDING SA", "qualite": "Administrateur",
         "type_dirigeant": "personne morale"},
    ],
}


def test_parse_company():
    out = re_src._parse_company(_RESULT)
    assert out["siren"] == "552032534" and out["name"] == "DANONE"
    assert out["status"] == "A"
    assert "Paris" in out["address"]
    assert len(out["dirigeants"]) == 2


def test_parse_dirigeant_person_vs_company():
    person = re_src._parse_dirigeant(_RESULT["dirigeants"][0])
    assert person["kind"] == "person"
    assert person["name"] == "Emmanuel FABER"
    assert person["role"] == "Président" and person["dob"] == "1964-02"
    company = re_src._parse_dirigeant(_RESULT["dirigeants"][1])
    assert company["kind"] == "company" and company["name"] == "HOLDING SA"


def test_lookup_empty():
    out = asyncio.run(re_src.lookup("  "))
    assert out["found"] is False and "error" in out


def test_lookup_by_name(monkeypatch):
    async def fake_get_json(url, params=None, ttl=0, cache_key=None, **kw):
        assert params["q"] == "Danone"
        return {"results": [_RESULT], "total_results": 1}
    monkeypatch.setattr(re_src, "get_json", fake_get_json)
    out = asyncio.run(re_src.lookup("Danone"))
    assert out["found"] is True and out["matches"][0]["name"] == "DANONE"
    assert out["matches"][0]["dirigeants"][0]["name"] == "Emmanuel FABER"


def test_lookup_by_siren_strips_spaces(monkeypatch):
    seen = {}

    async def fake_get_json(url, params=None, ttl=0, cache_key=None, **kw):
        seen["q"] = params["q"]
        return {"results": [_RESULT], "total_results": 1}
    monkeypatch.setattr(re_src, "get_json", fake_get_json)
    asyncio.run(re_src.lookup("552 032 534"))
    assert seen["q"] == "552032534"  # SIREN whitespace stripped
