"""Cryptocurrency wallet enrichment — on-chain activity for a wallet address.

Ported (concept + the ETH/Etherscan approach) from flowsint's ``crypto``
enrichers (``to_transactions`` / ``to_nfts``), Apache-2.0 — see
THIRD_PARTY_LICENSES. The ``wallet_address`` seed previously had **no** on-chain
enrichment (only abuse-feed cross-referencing via threatfox); this adds balance,
total received/sent, transaction count, an activity window, and a sample of
counterparties — the signals that tell a ransom/scam wallet apart from a dormant
or burner one, and that open counterparty pivots.

Backends:
- **BTC** (bech32 / legacy): blockstream.info Esplora API — **free, no key**.
- **ETH** (``0x``): Etherscan v2 — needs ``ETHERSCAN_API_KEY`` (via ``key_pool``);
  degrades gracefully to chain-only when no key is configured.
- **XMR** / unrecognised: returned as non-traceable (privacy chain / unknown
  format) so the agent records the chain and moves on.
"""
from __future__ import annotations

import re

from .. import key_pool
from .http_client import get_json

# Address-shape detection (mirrors the seed-prompt rules in backend/seeds.py).
_ETH_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_BTC_BECH32_RE = re.compile(r"^(bc1|tb1)[0-9ac-hj-np-z]{6,87}$")
_BTC_LEGACY_RE = re.compile(r"^[13][1-9A-HJ-NP-Za-km-z]{25,39}$")
_XMR_RE = re.compile(r"^[48][0-9A-Za-z]{94,105}$")

_BLOCKSTREAM = "https://blockstream.info/api"
_ETHERSCAN = "https://api.etherscan.io/v2/api"
_TTL = 3600  # chain state moves; keep enrichment reasonably fresh


def detect_chain(addr: str) -> str:
    """Best-effort chain detection from address shape. ETH also covers EVM
    chains (BSC/Polygon) — the caller should flag those separately."""
    a = (addr or "").strip()
    if _ETH_RE.match(a):
        return "eth"
    if _BTC_BECH32_RE.match(a.lower()) or _BTC_LEGACY_RE.match(a):
        return "btc"
    if _XMR_RE.match(a):
        return "xmr"
    return "unknown"


def _sats_to_btc(sats) -> float:
    return round((sats or 0) / 1e8, 8)


def _parse_btc(summary: dict, txs, addr: str) -> dict:
    """Shape blockstream address summary (+ recent txs) into a wallet profile.
    Pure — unit-tested."""
    cs = (summary or {}).get("chain_stats", {}) or {}
    ms = (summary or {}).get("mempool_stats", {}) or {}
    funded = (cs.get("funded_txo_sum", 0) or 0) + (ms.get("funded_txo_sum", 0) or 0)
    spent = (cs.get("spent_txo_sum", 0) or 0) + (ms.get("spent_txo_sum", 0) or 0)
    tx_count = (cs.get("tx_count", 0) or 0) + (ms.get("tx_count", 0) or 0)
    out = {
        "wallet_address": addr,
        "chain": "btc",
        "enriched": True,
        "balance_btc": _sats_to_btc(funded - spent),
        "total_received_btc": _sats_to_btc(funded),
        "total_sent_btc": _sats_to_btc(spent),
        "tx_count": tx_count,
        "source": "blockstream.info (Esplora, no key)",
    }
    if isinstance(txs, list) and txs:
        times = [t.get("status", {}).get("block_time") for t in txs
                 if (t.get("status") or {}).get("block_time")]
        if times:
            out["last_seen"] = max(times)
            out["first_seen_recent"] = min(times)  # within the fetched page only
        counter = set()
        for t in txs:
            for vin in t.get("vin", []) or []:
                a = ((vin.get("prevout") or {}).get("scriptpubkey_address"))
                if a and a != addr:
                    counter.add(a)
            for vout in t.get("vout", []) or []:
                a = vout.get("scriptpubkey_address")
                if a and a != addr:
                    counter.add(a)
        out["counterparty_count_recent"] = len(counter)
        out["counterparties_sample"] = sorted(counter)[:20]
    return out


def _parse_eth(balance_resp: dict, txlist_resp: dict, addr: str) -> dict:
    """Shape Etherscan balance + txlist into a wallet profile. Pure — unit-tested."""
    out = {"wallet_address": addr, "chain": "eth", "enriched": True,
           "source": "etherscan v2"}
    try:
        out["balance_eth"] = round(int((balance_resp or {}).get("result", 0)) / 1e18, 8)
    except (TypeError, ValueError):
        out["balance_eth"] = None
    txs = txlist_resp.get("result") if isinstance(txlist_resp, dict) else None
    if isinstance(txs, list):
        out["tx_count_recent"] = len(txs)
        times = [int(t["timeStamp"]) for t in txs if t.get("timeStamp")]
        if times:
            out["first_seen_recent"] = min(times)
            out["last_seen"] = max(times)
        counter = set()
        for t in txs:
            for fld in ("from", "to"):
                a = (t.get(fld) or "").lower()
                if a and a != addr.lower():
                    counter.add(a)
        out["counterparty_count_recent"] = len(counter)
        out["counterparties_sample"] = sorted(counter)[:20]
    return out


async def _enrich_btc(addr: str) -> dict:
    summary = await get_json(f"{_BLOCKSTREAM}/address/{addr}", ttl=_TTL,
                             cache_key=f"blockstream|addr|{addr}")
    status = summary.get("_status") if isinstance(summary, dict) else None
    if status and status != 200:
        return {"wallet_address": addr, "chain": "btc", "enriched": False,
                "reason": f"blockstream http {status}"}
    txs = await get_json(f"{_BLOCKSTREAM}/address/{addr}/txs", ttl=_TTL,
                         cache_key=f"blockstream|txs|{addr}")
    return _parse_btc(summary, txs, addr)


async def _enrich_eth(addr: str) -> dict:
    key = key_pool.acquire("etherscan")
    if not key:
        return {"wallet_address": addr, "chain": "eth", "enriched": False,
                "reason": "no ETHERSCAN_API_KEY configured (set ETHERSCAN_API_KEY[S])"}
    common = {"chainid": "1", "address": addr, "apikey": key}
    bal = await get_json(_ETHERSCAN, ttl=_TTL, cache_key=f"etherscan|bal|{addr}",
                         params={**common, "module": "account", "action": "balance",
                                 "tag": "latest"})
    txl = await get_json(_ETHERSCAN, ttl=_TTL, cache_key=f"etherscan|txlist|{addr}",
                         params={**common, "module": "account", "action": "txlist",
                                 "startblock": "0", "endblock": "99999999",
                                 "page": "1", "offset": "25", "sort": "desc"})
    return _parse_eth(bal, txl, addr)


async def lookup_wallet(address: str) -> dict:
    """Enrich a cryptocurrency wallet with on-chain activity."""
    addr = (address or "").strip()
    chain = detect_chain(addr)
    if chain == "btc":
        return await _enrich_btc(addr)
    if chain == "eth":
        return await _enrich_eth(addr)
    if chain == "xmr":
        return {"wallet_address": addr, "chain": "xmr", "enriched": False,
                "reason": "Monero is a privacy chain — on-chain tracing not available"}
    return {"wallet_address": addr, "chain": "unknown", "enriched": False,
            "reason": "unrecognised wallet address format"}
