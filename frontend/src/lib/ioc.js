// Agent-provided fields can occasionally be objects (e.g. {type, value}) instead
// of strings. Coerce to a display string so rendering never throws React #31.
export function iocString(v) {
  if (v == null) return ''
  if (typeof v === 'string') return v
  if (typeof v === 'object' && typeof v.value === 'string') return v.value
  return String(v)
}

// Refang defanged IOC notation — accepts `evil[.]com`, `hxxps://bad(.)site`,
// `user[at]evil[dot]com`, etc. Safe on already-live strings (no-op).
export function refang(s) {
  if (!s || typeof s !== 'string') return s
  let out = s.trim()
  // Strip surrounding angle brackets analysts sometimes add: `<evil[.]com>`.
  while (out.length > 1 && out.startsWith('<') && out.endsWith('>')) {
    out = out.slice(1, -1).trim()
  }
  out = out
    .replace(/\[\.\]/g, '.')
    .replace(/\(\.\)/g, '.')
    .replace(/\{\.\}/g, '.')
    .replace(/\[:\]/g, ':')
    .replace(/\[\/\]/g, '/')
    .replace(/\[@\]/g, '@')
    .replace(/\[\s*dot\s*\]/gi, '.')
    .replace(/\(\s*dot\s*\)/gi, '.')
    .replace(/\{\s*dot\s*\}/gi, '.')
    .replace(/\[\s*at\s*\]/gi, '@')
    .replace(/\(\s*at\s*\)/gi, '@')
    .replace(/\bhxxps\b/gi, 'https')
    .replace(/\bhxxp\b/gi, 'http')
    .replace(/\bfxp\b/gi, 'ftp')
  return out.trim()
}

// Auto-detect IOC type from a (refanged) value.
// Keep in sync with backend/main.py:detect_seed_type.
export const EXEC_EXTENSIONS_RE = /\.(exe|dll|sys|scr|bat|cmd|ps1|vbs|vbe|hta|pif|wsh|wsf|jse|msi|ocx|drv|lnk|dylib|elf)$/i
// D3 subdomain routing: the app is served on cti. / osint. / dd. deep-link
// subdomains (Cloudflare), each pre-selecting its vertical. The first DNS label
// (or a ?vertical= query param, handy for local dev / shareable links) wins over
// the persisted choice. Returns a known vertical name or null (bare bounce. /
// app. / localhost → fall back to localStorage/default).
export function verticalFromLocation() {
  try {
    const sub = (window.location.hostname || '').toLowerCase().split('.')[0]
    if (['cti', 'osint', 'dd'].includes(sub)) return sub
    const q = (new URLSearchParams(window.location.search).get('vertical') || '').toLowerCase()
    if (['cti', 'osint', 'dd'].includes(q)) return q
  } catch { /* ignore */ }
  return null
}


export function detectIOCType(raw, vertical = 'cti') {
  const v = refang(raw).trim()
  if (!v) return 'domain'
  // DD: seeds are legal entities — treat the input as a company name (or LEI).
  if (vertical === 'dd') return 'company'
  // OSINT: an @-prefixed handle is unambiguously an identity seed.
  if (vertical === 'osint' && /^@[A-Za-z0-9._-]{1,64}$/.test(v)) return 'username'
  if (/^(https?|ftp):\/\//i.test(v)) return 'url'
  // E.164 phone (a leading + then 7-15 digits, tolerating spaces/()-. seps).
  if (/^\+[1-9]\d{6,14}$/.test(v.replace(/[\s().\-]/g, ''))) return 'phone'
  if (/^(as|asn)\s*\d{1,10}$/i.test(v)) return 'asn'
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(v)) return 'ip'
  if (/^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/.test(v)) return 'ip'
  if (/^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/.test(v)) return 'email'
  if (/^0x[a-fA-F0-9]{40}$/.test(v)) return 'wallet_address'
  if (/^(bc1|tb1)[a-z0-9]{6,87}$/.test(v)) return 'wallet_address'
  if (/^[48][1-9A-HJ-NP-Za-km-z]{94}$/.test(v)) return 'wallet_address'
  if (/^[0-9a-fA-F]{62}$/.test(v)) return 'jarm'
  if (/^[0-9a-fA-F]{64}$/.test(v)) return 'hash'
  if (/^[0-9a-fA-F]{40}$/.test(v)) return 'hash'
  if (/^[0-9a-fA-F]{32}$/.test(v)) return 'hash'
  // Executable filename before domain: "malware.exe" matches the domain regex
  // too, but the filename interpretation is what the analyst wants.
  if (!/\s/.test(v) && EXEC_EXTENSIONS_RE.test(v)) return 'executable_name'
  if (/^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(v)) return 'domain'
  // Legacy BTC Base58 — checked LAST because the 1.../3... pattern collides
  // with arbitrary strings. Must be ≥25 chars and Base58 alphabet only.
  if (/^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/.test(v)) return 'wallet_address'
  // OSINT fallback: anything not matching a structured IOC above (a bare
  // handle like "darkcoder" or "john_doe") is treated as a username, not a
  // domain. CTI keeps the historical domain fallback.
  return vertical === 'osint' ? 'username' : 'domain'
}

// Parse the seed textarea into a deduped list of refanged IOCs (the
// "list" can be one entry — that's the single-IOC case). One IOC per
// line OR comma-separated. Whitespace-only lines dropped.
export function parseSeedInput(raw) {
  const seen = new Set()
  const out = []
  for (const piece of (raw || '').split(/[\n,]+/)) {
    const v = refang(piece).trim()
    if (!v || seen.has(v)) continue
    seen.add(v)
    out.push(v)
  }
  return out
}
