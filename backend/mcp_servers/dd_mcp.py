"""MCP server exposing Due-Diligence (KYB) source lookups to the agent.

This is the **DD source pool** (`mcp__dd__*`), mounted for investigations whose
vertical is ``dd`` (see ``backend/verticals.py``). It is kept separate from the
CTI pool: the domain is different (company registries, sanctions, ownership),
and the DD vertical is the product's monetisation boundary.

Sources exposed here are **factual** company / sanctions / ownership data under
commercial-OK licences (GLEIF CC0, OFAC public-domain, EU/UK open licences — see
THIRD_PARTY_LICENSES). Two hard product rules, enforced in the DD system prompt:

  * ownership is **estimated / inferred**, never "authoritative beneficial owner
    (UBO/RBE)" — the RBE is access-gated post-CJUE C-37/20;
  * **no adverse-media / criminal-offence inference** here (GDPR art. 10 /
    French art. 46 loi I&L) — that requires a processor-for-obligated-client
    structure, out of scope for this pool.
"""
from mcp.server.fastmcp import FastMCP
import importlib

mcp = FastMCP("bounce-dd")

_src_cache = {}


def _src(name: str):
    m = _src_cache.get(name)
    if m is None:
        m = importlib.import_module(f"backend.sources.{name}")
        _src_cache[name] = m
    return m


@mcp.tool()
async def gleif_lookup(query: str) -> dict:
    """Resolve a company by **name or LEI** via GLEIF (free, no key, CC0): legal
    name, jurisdiction, status, legal form, registered address, plus Level-2
    "who owns whom" relationships (direct/ultimate parent, direct children).
    Pass a 20-char LEI for an exact record (+ relationships) or a company name
    for the top matches. Graph each entity as a `company` node (set
    metadata.lei / jurisdiction / status) and each relationship as a `company`
    node linked with a `parent_of` / `subsidiary_of` edge. ⚠️ Level-2 is
    corporate ownership, NOT authoritative beneficial ownership — label any
    ownership as ESTIMATED/INFERRED, never as the official UBO/RBE."""
    return await _src("gleif").lookup(query)


@mcp.tool()
async def sanctions_screen(name: str, lists: list[str] | None = None) -> dict:
    """Screen a company or person **name** against the consolidated sanctions
    lists cleared for commercial use — **OFAC** (US SDN), **EU FSF**, **UK
    UKSL** (free, no key). Optionally restrict `lists` to a subset of
    ["OFAC","EU","UK"]. Returns scored candidate hits (name, matched alias,
    list, type, programmes, ref, score 0-100) plus `sanctioned: bool`. Screen
    every `company`/`person` node — a hit is a strong DD finding: tag the node
    `sanctioned`, add the programme(s), and cite the list + ref. ⚠️ Hits are
    CANDIDATES for human review (name collisions happen), NOT an automated
    determination — say so in the report."""
    return await _src("sanctions").screen(name, lists)


@mcp.tool()
async def companies_house_lookup(query: str) -> dict:
    """Resolve a **UK company** by name or company number via Companies House
    (free, needs COMPANIES_HOUSE_API_KEY; OGL v3.0). Returns the company
    profile + **officers** (directors/secretaries) + **persons with significant
    control (PSC)**. Pass a company number (e.g. `09876543`, `SC123456`) for the
    full record incl. officers/PSC, or a name for the top matches. Graph each
    officer / PSC as a `person` node (uses_role / significant_control edge to the
    company) — then sanctions_screen each person. PSC is registry-declared
    control (a public OGL register), still label ownership ESTIMATED, not an
    authoritative UBO/RBE determination. Returns `available: False` if no key."""
    return await _src("companies_house").lookup(query)


@mcp.tool()
async def edgar_lookup(query: str) -> dict:
    """Resolve a **US-listed company** by name, ticker, or CIK via SEC EDGAR
    (free, no key; public domain). Returns official name, CIK, tickers +
    exchanges, SIC industry, state of incorporation, business address, former
    names (aliases), and recent filing types. Use for US issuers (complements
    GLEIF/Companies House). Graph the issuer as a `company` node (metadata.cik /
    tickers / sic), add former names as aliases, and sanctions_screen it. US
    issuers only — returns found=false for private/non-US entities."""
    return await _src("edgar").lookup(query)


@mcp.tool()
async def recherche_entreprises_lookup(query: str) -> dict:
    """Resolve a **French company** by name or SIREN via the government
    Recherche d'entreprises API (free, no key; Licence Ouverte 2.0; aggregates
    INSEE Sirene + INPI RNE). Returns identity (SIREN, legal name, status, legal
    form, activity, creation date, registered address) and **dirigeants**
    (officers). Graph the company as a `company` node (metadata.siren) and each
    natural-person dirigeant as a `person` node (officer_of edge) — then
    sanctions_screen each person. (A dirigeant with kind=="company" is a
    corporate officer → graph as a company, not a person.) FR entities only.
    Officer data is GDPR-regulated: factual use only, ownership stays ESTIMATED."""
    return await _src("recherche_entreprises").lookup(query)
