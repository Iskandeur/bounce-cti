import asyncio
import dns.resolver
import dns.reversename


async def _resolve(name: str, rtype: str) -> list[str]:
    def _q():
        try:
            ans = dns.resolver.resolve(name, rtype, lifetime=5)
            return [r.to_text().strip('"') for r in ans]
        except Exception as e:
            return []
    return await asyncio.get_event_loop().run_in_executor(None, _q)


async def resolve_all(domain: str) -> dict:
    out = {}
    for rt in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"):
        out[rt] = await _resolve(domain, rt)
    return out


async def reverse_dns(ip: str) -> list[str]:
    def _q():
        try:
            rev = dns.reversename.from_address(ip)
            ans = dns.resolver.resolve(rev, "PTR", lifetime=5)
            return [r.to_text().rstrip(".") for r in ans]
        except Exception:
            return []
    return await asyncio.get_event_loop().run_in_executor(None, _q)
