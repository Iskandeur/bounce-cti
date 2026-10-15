import asyncio
import dns.resolver
import dns.reversename

from .. import fixtures


async def _resolve(name: str, rtype: str) -> list[str]:
    def _q():
        try:
            ans = dns.resolver.resolve(name, rtype, lifetime=5)
            return [r.to_text().strip('"') for r in ans]
        except Exception as e:
            return []
    return await asyncio.get_event_loop().run_in_executor(None, _q)


async def resolve_all(domain: str) -> dict:
    async def _live():
        out = {}
        for rt in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"):
            out[rt] = await _resolve(domain, rt)
        return out
    # DNS keeps no cache entry, so it is the one source that needs its own
    # fixture hook (EVAL_PROTOCOL §4.C). Outside capture/replay this is _live().
    return await fixtures.through(f"dns|all|{domain}", _live)


async def reverse_dns(ip: str) -> list[str]:
    def _q():
        try:
            rev = dns.reversename.from_address(ip)
            ans = dns.resolver.resolve(rev, "PTR", lifetime=5)
            return [r.to_text().rstrip(".") for r in ans]
        except Exception:
            return []

    async def _live():
        return await asyncio.get_event_loop().run_in_executor(None, _q)
    return await fixtures.through(f"dns|ptr|{ip}", _live)
