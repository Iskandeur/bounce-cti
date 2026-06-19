"""Unit tests for the crypto wallet enricher parsers (no network)."""
import asyncio

from backend.sources import wallet_enrich as we


def test_detect_chain():
    assert we.detect_chain("0x" + "a" * 40) == "eth"
    assert we.detect_chain("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq") == "btc"
    assert we.detect_chain("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa") == "btc"
    assert we.detect_chain("4" + "A" * 94) == "xmr"
    assert we.detect_chain("not-a-wallet") == "unknown"
    assert we.detect_chain("") == "unknown"


def test_parse_btc_balance_and_counterparties():
    addr = "bc1self"
    summary = {
        "chain_stats": {"funded_txo_sum": 300000000, "spent_txo_sum": 100000000, "tx_count": 5},
        "mempool_stats": {"funded_txo_sum": 0, "spent_txo_sum": 0, "tx_count": 0},
    }
    txs = [
        {"status": {"block_time": 1700000000},
         "vin": [{"prevout": {"scriptpubkey_address": "bcCounterA"}}],
         "vout": [{"scriptpubkey_address": addr}, {"scriptpubkey_address": "bcCounterB"}]},
        {"status": {"block_time": 1700001000},
         "vin": [{"prevout": {"scriptpubkey_address": addr}}],
         "vout": [{"scriptpubkey_address": "bcCounterA"}]},
    ]
    out = we._parse_btc(summary, txs, addr)
    assert out["enriched"] is True and out["chain"] == "btc"
    assert out["total_received_btc"] == 3.0
    assert out["total_sent_btc"] == 1.0
    assert out["balance_btc"] == 2.0
    assert out["tx_count"] == 5
    assert out["last_seen"] == 1700001000
    assert set(out["counterparties_sample"]) == {"bcCounterA", "bcCounterB"}
    assert addr not in out["counterparties_sample"]
    assert out["counterparty_count_recent"] == 2


def test_parse_btc_handles_empty_txs():
    out = we._parse_btc({"chain_stats": {"funded_txo_sum": 0, "spent_txo_sum": 0, "tx_count": 0}}, [], "x")
    assert out["balance_btc"] == 0.0 and "counterparties_sample" not in out


def test_parse_eth_balance_and_txs():
    addr = "0x" + "a" * 40
    bal = {"status": "1", "result": "2500000000000000000"}  # 2.5 ETH
    txl = {"status": "1", "result": [
        {"from": addr, "to": "0x" + "b" * 40, "timeStamp": "1700000000"},
        {"from": "0x" + "c" * 40, "to": addr, "timeStamp": "1700009000"},
    ]}
    out = we._parse_eth(bal, txl, addr)
    assert out["balance_eth"] == 2.5
    assert out["tx_count_recent"] == 2
    assert out["last_seen"] == 1700009000
    assert out["first_seen_recent"] == 1700000000
    assert set(out["counterparties_sample"]) == {"0x" + "b" * 40, "0x" + "c" * 40}


def test_parse_eth_bad_balance_is_none():
    out = we._parse_eth({"result": "NOTOK"}, {"result": []}, "0xabc")
    assert out["balance_eth"] is None


def test_lookup_xmr_and_unknown_non_traceable():
    xmr = asyncio.run(we.lookup_wallet("4" + "A" * 94))
    assert xmr["chain"] == "xmr" and xmr["enriched"] is False
    unk = asyncio.run(we.lookup_wallet("garbage"))
    assert unk["chain"] == "unknown" and unk["enriched"] is False


def test_lookup_eth_without_key_degrades(monkeypatch):
    monkeypatch.setattr(we.key_pool, "acquire", lambda src: None)
    out = asyncio.run(we.lookup_wallet("0x" + "d" * 40))
    assert out["chain"] == "eth" and out["enriched"] is False
    assert "ETHERSCAN" in out["reason"]


def test_lookup_btc_end_to_end_mocked(monkeypatch):
    calls = []

    async def fake_get_json(url, headers=None, params=None, ttl=0, cache_key=None):
        calls.append(url)
        if url.endswith("/txs"):
            return [{"status": {"block_time": 1700000000}, "vin": [], "vout": []}]
        return {"chain_stats": {"funded_txo_sum": 100000000, "spent_txo_sum": 0, "tx_count": 1}}

    monkeypatch.setattr(we, "get_json", fake_get_json)
    out = asyncio.run(we.lookup_wallet("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"))
    assert out["enriched"] is True and out["total_received_btc"] == 1.0
    assert any(u.endswith("/txs") for u in calls)
