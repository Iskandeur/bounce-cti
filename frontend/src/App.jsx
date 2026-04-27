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
  country: '#ff7b72'
}
const NODE_SHAPES = {
  domain: 'ellipse', ip: 'rectangle', ns: 'diamond', registrar: 'hexagon',
  cert: 'round-rectangle', asn: 'barrel', hash: 'triangle', report: 'concave-hexagon',
  jarm: 'pentagon', url: 'cut-rectangle', country: 'tag'
}
const STATUS_COLOR = { running: '#e3b341', done: '#56d364', cleared: '#8b949e', error: '#f85149' }

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
  country:   () => 'maltego.Location.Country',
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

// Auto-detect IOC type from a (refanged) value
function detectIOCType(raw) {
  const v = refang(raw).trim()
  if (!v) return 'domain'
  if (/^(https?|ftp):\/\//i.test(v)) return 'url'
  if (/^(as|asn)\s*\d{1,10}$/i.test(v)) return 'asn'
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(v)) return 'ip'
  if (/^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/.test(v)) return 'ip'
  if (/^[0-9a-fA-F]{62}$/.test(v)) return 'jarm'
  if (/^[0-9a-fA-F]{64}$/.test(v)) return 'hash'
  if (/^[0-9a-fA-F]{40}$/.test(v)) return 'hash'
  if (/^[0-9a-fA-F]{32}$/.test(v)) return 'hash'
  if (/^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(v)) return 'domain'
  return 'domain'
}

const IOC_TYPE_LABEL = {
  domain: 'Domain', ip: 'IP', hash: 'Hash', url: 'URL', jarm: 'JARM', asn: 'ASN'
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

function MainApp({ onLogout, isAdmin, allowedModels, userId }) {
  const [seedType, setSeedType] = useState('auto')
  const [seedValue, setSeedValue] = useState('')
  const [batchMode, setBatchMode] = useState(false)
  const [batchText, setBatchText] = useState('')
  const [model, setModel] = useState('sonnet')
  const [adminOpen, setAdminOpen] = useState(false)
  const [shareOpen, setShareOpen] = useState(false)
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
  const [copied, setCopied] = useState(false)
  const [nodeValues, setNodeValues] = useState(new Map())
  const [filterTypes, setFilterTypes] = useState(new Set())
  const [showEdgeLabels, setShowEdgeLabels] = useState(true)
  const [rightTab, setRightTab] = useState('report')
  const [evidenceData, setEvidenceData] = useState(null)
  const [evidenceLoading, setEvidenceLoading] = useState(false)
  const [agentNotes, setAgentNotes] = useState([])
  const [customPrompt, setCustomPrompt] = useState('')
  const [promptBusy, setPromptBusy] = useState(false)
  // Optimistic pending prompt: shows the user's message in the chat immediately
  // while the agent is working. Cleared when prompt_history grows.
  const [pendingPrompt, setPendingPrompt] = useState(null)
  const [existingTypes, setExistingTypes] = useState(new Set())
  // Multi-selection for "copy / export" scope. Ctrl/Cmd/Shift + click toggles
  // a node into this set without touching the single-click details panel.
  // Empty set == "all nodes" (implicit select-all).
  const [pickedIds, setPickedIds] = useState(new Set())
  const [nodeCount, setNodeCount] = useState(0)
  const [graphSearch, setGraphSearch] = useState('')
  const [searchMatches, setSearchMatches] = useState(0)
  const [batchCombined, setBatchCombined] = useState(false)
  // Add-seed form: attach a new PEER IOC to the currently open investigation.
  const [addSeedType, setAddSeedType] = useState('auto')
  const [addSeedValue, setAddSeedValue] = useState('')
  // Service-restart banner + reconnect state. `serverDown=true` means the
  // backend sent us a `server_shutdown` frame (e.g. `systemctl restart`); we
  // display a banner and poll /api/auth/me until the service is back, then
  // reload so all stale state (WS, timers, in-flight fetches) is replaced.
  const [serverDown, setServerDown] = useState(false)
  const [leftWidth, setLeftWidth] = useState(260)
  const [rightWidth, setRightWidth] = useState(360)
  const isMobile = useIsMobile()
  const [mobileLeftOpen, setMobileLeftOpen] = useState(false)
  const [mobileRightOpen, setMobileRightOpen] = useState(false)

  const cyRef = useRef(null)
  const containerRef = useRef(null)
  const activeInvRef = useRef(null)
  const showEdgeLabelsRef = useRef(showEdgeLabels)
  const filterTypesRef = useRef(filterTypes)
  const leftWidthRef = useRef(260)
  const rightWidthRef = useRef(360)
  const dragStateRef = useRef(null)
  const chatEndRef = useRef(null)

  useEffect(() => { activeInvRef.current = activeInv }, [activeInv])
  useEffect(() => { showEdgeLabelsRef.current = showEdgeLabels }, [showEdgeLabels])
  useEffect(() => { filterTypesRef.current = filterTypes }, [filterTypes])
  useEffect(() => { leftWidthRef.current = leftWidth }, [leftWidth])
  useEffect(() => { rightWidthRef.current = rightWidth }, [rightWidth])

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
            'label': 'data(label)',
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
      // Honor a ?inv=<id> query param (used after importing a shared graph)
      // so the recipient lands directly on their freshly cloned investigation.
      try {
        const sp = new URLSearchParams(window.location.search)
        const wanted = sp.get('inv')
        if (wanted) {
          openInv(wanted)
          sp.delete('inv')
          const url = window.location.pathname + (sp.toString() ? '?' + sp.toString() : '')
          window.history.replaceState({}, '', url)
        }
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

  const addCyNode = useCallback((n) => {
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
    ;(n.tags || []).forEach(t => { d[t] = true })
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
  }, [])

  const handleEvent = useCallback((evt) => {
    if (evt.kind === 'snapshot') {
      evt.graph.nodes.forEach(n => addCyNode(n))
      evt.graph.edges.forEach(e => addCyEdge(e))
      // Auto-load report if present in snapshot
      const reportNode = evt.graph.nodes.find(n => n.type === 'report' && n.value === 'investigation_summary')
      if (reportNode?.metadata) setReport(reportNode.metadata)
      relayout()
    } else if (evt.kind === 'node_added' || evt.kind === 'node_updated') {
      addCyNode(evt.node)
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
    setEvents([])
    setAgentNotes([])
    setNodeValues(new Map())
    setExistingTypes(new Set())
    setFilterTypes(new Set())
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
          // Agent reasoning — summarize to keep timeline compact
          const full = textBlocks.join(' ')
          if (full.trim().length > 5) notes.push({ ts: evtTs, noteKind: 'reasoning', text: full.slice(0, 300) })
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

  // ── start ─────────────────────────────────────────────────────────────────
  const start = async () => {
    const cleaned = refang(seedValue)
    if (!cleaned) return
    const effectiveType = seedType === 'auto' ? detectIOCType(cleaned) : seedType
    const r = await fetch('/api/investigations', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ seed_type: effectiveType, seed_value: cleaned, model })
    })
    const { id } = await r.json()
    await refreshInvs()
    openInv(id)
  }

  // Launch a batch of investigations.
  // combined=false → one investigation per IOC (parallel).
  // combined=true  → single investigation graph with all IOCs as pivots (correlation mode).
  const startBatch = async () => {
    const items = batchText
      .split(/[\n,]+/)
      .map(s => refang(s))
      .filter(Boolean)
      .map(v => ({ seed_type: detectIOCType(v), seed_value: v }))
    if (items.length === 0) return
    const r = await fetch('/api/investigations/batch', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ items, model, combined: batchCombined })
    })
    const d = await r.json()
    await refreshInvs()
    const first = (d.started || [])[0]
    if (first) openInv(first.id)
    setBatchText('')
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
      setEvents([])
      setNodeValues(new Map())
      setExistingTypes(new Set())
    }
    await refreshInvs()
  }

  const stopInv = async (id, ev) => {
    ev.stopPropagation()
    await fetch(`/api/investigations/${id}/stop`, { method: 'POST' })
    await refreshInvs()
  }

  const rerunInv = async (id, ev) => {
    ev.stopPropagation()
    await fetch(`/api/investigations/${id}/rerun`, { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ model }) })
    await refreshInvs()
    openInv(id)
  }

  // Attach a new PEER seed to the currently open investigation. The agent runs
  // the full single-seed workflow for the new IOC on the existing graph and
  // updates the report with per-seed summaries + cross-seed findings.
  const submitAddSeed = async () => {
    if (!activeInv) return
    const v = refang(addSeedValue)
    if (!v) return
    const effectiveType = addSeedType === 'auto' ? detectIOCType(v) : addSeedType
    await fetch(`/api/investigations/${activeInv}/add_seed`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ seed_type: effectiveType, seed_value: v, model })
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
        selected_nodes: selectedNodes.length > 0 ? selectedNodes : null,
      })
    })
    const sel = selectedNodes.length > 0 ? ` [${selectedNodes.length} selected]` : ''
    setEvents(e => [`▶ custom prompt${sel}: ${text.slice(0, 60)}…`, ...e])
    // NOTE: promptBusy stays true — cleared when prompt_history grows or agent_exit fires
    refreshInvs()
  }

  const PIVOTABLE = ['domain', 'ip', 'hash', 'url', 'jarm', 'asn']
  const pivot = (n) => {
    if (!PIVOTABLE.includes(n.type)) return
    setBatchMode(false)
    setSeedType(n.type)
    setSeedValue(n.value)
  }

  // Pivot in-place: spawn another agent pass on the SAME investigation graph
  // (nodes/edges are merged via idempotent upserts).
  const pivotHere = async (n) => {
    if (!activeInv) return
    if (!PIVOTABLE.includes(n.type)) return
    await fetch(`/api/investigations/${activeInv}/enrich`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ seed_type: n.type, seed_value: n.value, model })
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
          <img className="logo-mark mobile-topbar-logo" src="/logo-256.png" alt="" />
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
        <div className="logo-row"><img className="logo-mark logo-mark-sidebar" src="/logo-256.png" alt="" /><div className="logo">BOUNCE<span>CTI</span></div>{isAdmin && <button className="admin-btn" title="Admin panel" onClick={() => setAdminOpen(true)}>⚙</button>}<button className="logout-btn" title="Log out" onClick={onLogout}>⎋</button></div>

        <div className="section-label">
          New investigation
          <button
            type="button"
            className={`batch-toggle${batchMode ? ' active' : ''}`}
            onClick={() => setBatchMode(v => !v)}
            title={batchMode ? 'Back to single IOC input' : 'Switch to batch mode (many IOCs at once)'}
          >
            {batchMode ? '↩ single' : '⧉ batch'}
          </button>
        </div>
        {!batchMode && (
          <>
            <div className="auto-detect-row">
              <input
                value={seedValue}
                onChange={e => { setSeedValue(e.target.value); if (seedType === 'auto') { /* auto stays */ } }}
                onKeyDown={e => e.key === 'Enter' && start()}
                placeholder="Paste any IOC: domain, IP, hash, URL, JARM, ASN (defanged ok)"
              />
              <span className="detected-type" title="Auto-detected type (click to override)">
                {seedType === 'auto'
                  ? (seedValue.trim() ? detectIOCType(seedValue) : '—').toUpperCase()
                  : seedType.toUpperCase()}
              </span>
            </div>
            <select value={seedType} onChange={e => setSeedType(e.target.value)} className="seed-type-override">
              <option value="auto">Auto-detect</option>
              <option value="domain">Domain</option>
              <option value="ip">IP address</option>
              <option value="hash">File hash</option>
              <option value="url">URL</option>
              <option value="jarm">JARM</option>
              <option value="asn">ASN</option>
            </select>
          </>
        )}
        {batchMode && (
          <>
            <textarea
              className="batch-textarea"
              value={batchText}
              onChange={e => setBatchText(e.target.value)}
              placeholder={`Paste any IOCs, one per line (type auto-detected):\nexample.com\n1.2.3.4\nhxxps://evil[.]com/path\ne3b0c44298fc1c149afbf4c8996fb924…`}
              rows={6}
            />
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
          </>
        )}
        <div className="section-label">Model</div>
        <select value={model} onChange={e => setModel(e.target.value)}>
          {(!allowedModels || allowedModels.includes('sonnet')) && <option value="sonnet">Sonnet 4.6 (recommended)</option>}
          {(!allowedModels || allowedModels.includes('opus')) && <option value="opus">Opus 4.6 (smarter, slower)</option>}
          {(!allowedModels || allowedModels.includes('opus-4.7')) && <option value="opus-4.7">Opus 4.7 (latest, smartest)</option>}
          {(!allowedModels || allowedModels.includes('haiku')) && <option value="haiku">Haiku 4.5 (faster, lighter)</option>}
        </select>
        <button onClick={batchMode ? startBatch : start}>
          {batchMode ? 'Launch batch →' : 'Investigate →'}
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
                  <span className="inv-seed">{i.seed_value}</span>
                  {extraSeeds > 0 && (
                    <span className="inv-seed-count" title={`${seedCount} seeds in this investigation`}>
                      +{extraSeeds}
                    </span>
                  )}
                  <span className="inv-type">{i.seed_type}</span>
                </div>
                <div className="inv-item-meta">
                  <span className="inv-status-dot" style={{ background: STATUS_COLOR[i.status] || '#8b949e' }} />
                  <span className="inv-status-text" style={{ color: STATUS_COLOR[i.status] || '#8b949e' }}>{i.status}</span>
                  {i.model && <span className="inv-model-badge">{i.model}</span>}
                  <span className="inv-actions">
                    {i.status === 'running' && (
                      <button className="icon-btn warning" title="Stop" onClick={e => stopInv(i.id, e)}>■</button>
                    )}
                    <button className="icon-btn" title="Rerun" onClick={e => rerunInv(i.id, e)}>↺</button>
                    <button className="icon-btn danger" title="Delete" onClick={e => deleteInv(i.id, e)}>✕</button>
                  </span>
                </div>
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
      <div className="graph">
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
              {!report && (
                <p className="hint">Click the ★ report node for the full investigation summary.</p>
              )}
              {report && (
                <>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span className={`threat-badge threat-${(report.threat_assessment || 'unknown').replace(/\s+/g, '_')}`}>
                      {(report.threat_assessment || 'UNKNOWN').toUpperCase()}
                    </span>
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
                        return (
                          <div key={`note-${i}`} className="timeline-entry timeline-note">
                            <div className="timeline-line">
                              <span className="timeline-dot timeline-dot-note" />
                              {i < merged.length - 1 && <span className="timeline-connector" />}
                            </div>
                            <div className="timeline-content">
                              <div className="timeline-note-text">{tn.text}</div>
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
      {adminOpen && <AdminPanel onClose={() => setAdminOpen(false)} selfId={userId} onImpersonate={() => window.location.reload()} />}
      {shareOpen && activeInv && (() => {
        const inv = invs.find(i => i.id === activeInv)
        return inv ? <ShareModal inv={inv} onClose={() => setShareOpen(false)} /> : null
      })()}
    </div>
    </div>
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
          <img className="logo-mark logo-mark-auth" src="/logo-512.png" alt="Bounce-CTI" />
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
