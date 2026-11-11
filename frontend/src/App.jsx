import React, { useEffect, useRef, useState, useCallback } from 'react'
import Login from './Login.jsx'
import AdminPanel from './AdminPanel.jsx'
import ShareModal from './ShareModal.jsx'
import SharedView from './SharedView.jsx'
import cytoscape from 'cytoscape'
import coseBilkent from 'cytoscape-cose-bilkent'
import { nextInvSearch } from './invUrl.js'
import { MALTEGO_TYPES, PIVOTABLE } from './lib/constants.js'
import { formatCountdown } from './lib/format.js'
import { iocString, refang, detectIOCType } from './lib/ioc.js'
import {
  buildCyStylesheet, INITIAL_LAYOUT, RELAYOUT_OPTIONS, HARD_RELAYOUT_OPTIONS,
  isAuxReportNode, toCyNodeData,
} from './lib/graph.js'
import { transcriptToNotes } from './lib/timeline.js'
import { reportToMarkdown } from './lib/reportMarkdown.js'
import useIsMobile from './hooks/useIsMobile.js'
import useTheme from './hooks/useTheme.js'
import usePanelResize from './hooks/usePanelResize.js'
import useQuota from './hooks/useQuota.js'
import useServerReconnect from './hooks/useServerReconnect.js'
import useRunSettings from './hooks/useRunSettings.js'
import useNewInvestigation from './hooks/useNewInvestigation.js'
import { useLeadStats, useCrossInvestigations, useNodeNote } from './hooks/useNodeData.js'
import Sidebar from './components/Sidebar.jsx'
import GraphPane from './components/GraphPane.jsx'
import ReportTab from './components/ReportTab.jsx'
import NodeTab from './components/NodeTab.jsx'
import TimelineTab from './components/TimelineTab.jsx'
import ActionsPanel from './components/ActionsPanel.jsx'
import ChatTab from './components/ChatTab.jsx'
import PromptBox from './components/PromptBox.jsx'

cytoscape.use(coseBilkent)

const wsMap = {}

function MainApp({ onLogout, isAdmin, allowedModels, userId }) {
  const settings = useRunSettings(allowedModels)
  const { model, effort } = settings
  const [adminOpen, setAdminOpen] = useState(false)
  const [shareOpen, setShareOpen] = useState(false)
  const [invs, setInvs] = useState([])
  const [activeInv, setActiveInv] = useState(null)
  // Active investigation's vertical (cti / osint / dd) — drives vertical-aware UI
  // (Actions tab is CTI-only; the report's indicator section is relabelled).
  const activeVertical = invs.find(i => i.id === activeInv)?.vertical || 'cti'
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
  // Which copy button just fired ('graph-json', 'maltego', 'report-md',
  // 'node-json', 'text'), so only that one shows "copied".
  const [copied, setCopied] = useState(null)
  const copiedTimer = useRef(null)
  const flashCopied = (key) => {
    setCopied(key)
    clearTimeout(copiedTimer.current)
    copiedTimer.current = setTimeout(() => setCopied(null), 1500)
  }
  const [nodeValues, setNodeValues] = useState(new Map())
  const [filterTypes, setFilterTypes] = useState(new Set())
  const [showEdgeLabels, setShowEdgeLabels] = useState(true)
  const [rightTab, setRightTab] = useState('report')
  const [evidenceData, setEvidenceData] = useState(null)
  const [evidenceLoading, setEvidenceLoading] = useState(false)
  const [agentNotes, setAgentNotes] = useState([])
  const [expandedReasoning, setExpandedReasoning] = useState(() => new Set())
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
  const leadStats = useLeadStats(activeInv, nodeCount)
  const crossInv = useCrossInvestigations(activeInv, selected)
  const [graphSearch, setGraphSearch] = useState('')
  const [searchMatches, setSearchMatches] = useState(0)
  const note = useNodeNote(activeInv, selected)
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
  // Service-restart banner + reconnect state. `serverDown=true` means the
  // backend sent us a `server_shutdown` frame (e.g. `systemctl restart`); we
  // display a banner and poll /api/auth/me until the service is back, then
  // reload so all stale state (WS, timers, in-flight fetches) is replaced.
  const [serverDown, setServerDown] = useState(false)
  const [quotaState, setQuotaState] = useQuota()
  const { leftWidth, rightWidth, startDrag } = usePanelResize()
  const isMobile = useIsMobile()
  const [mobileLeftOpen, setMobileLeftOpen] = useState(false)
  const [mobileRightOpen, setMobileRightOpen] = useState(false)
  const [theme, setTheme] = useTheme()

  const cyRef = useRef(null)
  const containerRef = useRef(null)
  const activeInvRef = useRef(null)
  const showEdgeLabelsRef = useRef(showEdgeLabels)
  const filterTypesRef = useRef(filterTypes)
  const chatEndRef = useRef(null)

  useEffect(() => { activeInvRef.current = activeInv }, [activeInv])
  const urlHydratedRef = useRef(false)

  // Sync activeInv ↔ URL (?inv=<id>) so that:
  //   - hard refresh keeps the investigation you were viewing,
  //   - browser back/forward navigates between recently-opened investigations,
  //   - the URL is shareable / pinnable.
  // Uses replaceState (not pushState) on natural switching so the back button
  // doesn't accumulate one entry per investigation click within a session.
  // Held back until the initial ?inv= deep link has been read (urlHydratedRef,
  // set after refreshInvs below): at mount activeInv is null and would erase it.
  useEffect(() => {
    try {
      const qs = nextInvSearch(window.location.search, activeInv, urlHydratedRef.current)
      if (qs === null) return
      window.history.replaceState({}, '', window.location.pathname + qs)
    } catch (_) { /* ignore */ }
  }, [activeInv])
  useEffect(() => { showEdgeLabelsRef.current = showEdgeLabels }, [showEdgeLabels])
  useEffect(() => { filterTypesRef.current = filterTypes }, [filterTypes])
  useEffect(() => { filterRelationsRef.current = filterRelations }, [filterRelations])
  useEffect(() => { showPinsRef.current = showPins }, [showPins])
  useEffect(() => { showNotesRef.current = showNotes }, [showNotes])

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
      style: buildCyStylesheet({ showPinsRef, showNotesRef, showEdgeLabelsRef, filterRelationsRef }),
      layout: INITIAL_LAYOUT,
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
      urlHydratedRef.current = true
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

  useServerReconnect(serverDown)

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
      cy.layout(RELAYOUT_OPTIONS).run()
    }, 250)
  }, [])

  // Hard relayout (used by toolbar): always randomize so a stuck "line" graph
  // breaks out of its bad local minimum.
  const hardRelayout = useCallback(() => {
    const cy = cyRef.current
    if (!cy || cy.nodes().length === 0) return
    if (relayoutTimer.current) clearTimeout(relayoutTimer.current)
    cy.layout(HARD_RELAYOUT_OPTIONS).run()
  }, [])

  const addCyNode = useCallback((n) => {
    if (isAuxReportNode(n)) return
    const cy = cyRef.current
    const d = toCyNodeData(n)
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
        const notes = transcriptToNotes(j.entries)
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

  const form = useNewInvestigation({
    model, effort, vertical: settings.vertical, activeInv, refreshInvs, openInv, setEvents,
  })

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
  // Returns true once the seed was sent, so the caller can clear its input.
  const submitAddSeed = async (raw) => {
    if (!activeInv) return false
    const v = refang(raw)
    if (!v) return false
    // Detect under the active investigation's vertical so a bare handle added
    // to an OSINT investigation seeds as a username, not a domain.
    const activeVertical = invs.find(i => i.id === activeInv)?.vertical || 'cti'
    const effectiveType = detectIOCType(v, activeVertical)
    await fetch(`/api/investigations/${activeInv}/add_seed`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ seed_type: effectiveType, seed_value: v, model, effort })
    })
    setEvents(e => [`▶ add seed: ${effectiveType} ${v}`, ...e])
    refreshInvs()
    return true
  }

  // ── copy helpers ─────────────────────────────────────────────────────────
  const copyNodeJson = (n) => {
    navigator.clipboard.writeText(JSON.stringify({
      type: n.type, value: n.value, tags: n.tags,
      source: n.source, confidence: n.confidence, metadata: n.metadata
    }, null, 2))
    flashCopied('node-json')
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
    flashCopied('graph-json')
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
    flashCopied('maltego')
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

  const pivot = (n) => {
    if (!PIVOTABLE.includes(n.type)) return
    form.setInputMode('ioc')
    form.setSeedText(n.value)
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

  const copyReportMarkdown = () => {
    if (!report) return
    navigator.clipboard.writeText(reportToMarkdown(report, activeVertical))
    flashCopied('report-md')
  }

  const copyText = (txt) => {
    if (!txt) return
    navigator.clipboard.writeText(String(txt))
    flashCopied('text')
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
      // cytoscape's indexOf throws when the element is outside the collection
      // (a selected edge, or a node that does not match the search).
      const idx = matches.toArray().findIndex(m => m.id() === current[0].id())
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
      <Sidebar
        mobileLeftOpen={mobileLeftOpen}
        theme={theme}
        setTheme={setTheme}
        isAdmin={isAdmin}
        setAdminOpen={setAdminOpen}
        onLogout={onLogout}
        settings={settings}
        allowedModels={allowedModels}
        form={form}
        invs={invs}
        activeInv={activeInv}
        quotaState={quotaState}
        invActions={{ openInv, stopInv, resumeInv, renameInv, rerunInv, mergeInv, deleteInv }}
        mergePickerSrc={mergePickerSrc}
        setMergePickerSrc={setMergePickerSrc}
        onAddSeed={submitAddSeed}
        setShareOpen={setShareOpen}
        events={events}
      />

      {/* ── LEFT RESIZE HANDLE ── */}
      <div className="resize-handle" onMouseDown={startDrag('left')} title="Drag to resize" />

      {/* ── GRAPH ── */}
      <GraphPane
        containerRef={containerRef}
        cyRef={cyRef}
        search={{ graphSearch, searchMatches, doGraphSearch, selectAllSearchMatches, focusNextSearchMatch }}
        display={{ showEdgeLabels, setShowEdgeLabels, showPins, setShowPins, showNotes, setShowNotes, hardRelayout }}
        exports={{ copied, copyGraphJson, copyToMaltego }}
        filters={{ existingTypeList, existingRelations, filterTypes, toggleFilterType, filterRelations, toggleFilterRelation }}
        nodeCount={nodeCount}
        pickedIds={pickedIds}
        setPickedIds={setPickedIds}
      />

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
          {activeVertical === 'cti' && (
            <button
              className={`panel-tab${rightTab === 'actions' ? ' active' : ''}`}
              onClick={() => setRightTab('actions')}
              title="Operational deliverables — blocklists, takedown templates, detection rules"
            >
              Actions
            </button>
          )}
          <button
            className={`panel-tab${rightTab === 'chat' ? ' active' : ''}`}
            onClick={() => setRightTab('chat')}
          >
            Chat
          </button>
        </div>

        <div className={`panel-content${rightTab === 'chat' ? ' chat-mode' : ''}`}>
          {rightTab === 'report' && (
            <ReportTab
              report={report}
              hypothesis={hypothesis}
              hypothesisStamp={hypothesisStamp}
              budgetLog={budgetLog}
              leadStats={leadStats}
              nodeCount={nodeCount}
              invs={invs}
              activeInv={activeInv}
              activeVertical={activeVertical}
              nodeValues={nodeValues}
              focusNode={focusNode}
              copied={copied}
              copyReportMarkdown={copyReportMarkdown}
              setShareOpen={setShareOpen}
              setRightTab={setRightTab}
            />
          )}
          {rightTab === 'node' && (
            <NodeTab
              selected={selected}
              activeInv={activeInv}
              note={note}
              evidence={{ evidenceData, setEvidenceData, evidenceLoading, setEvidenceLoading }}
              crossInv={crossInv}
              copied={copied}
              actions={{ togglePin, pivotHere, pivot, copyNodeJson, copyText, openInv }}
            />
          )}
          {rightTab === 'timeline' && (
            <TimelineTab
              cyRef={cyRef}
              agentNotes={agentNotes}
              selected={selected}
              focusNode={focusNode}
              expandedReasoning={expandedReasoning}
              setExpandedReasoning={setExpandedReasoning}
            />
          )}
          {/* ── Actions tab — operational deliverables (CTI only) ── */}
          {rightTab === 'actions' && activeVertical === 'cti' && (
            <ActionsPanel
              activeInv={activeInv}
              graphReady={!!cyRef.current && cyRef.current.nodes().length > 0}
            />
          )}
          {rightTab === 'chat' && (
            <ChatTab
              report={report}
              activeInv={activeInv}
              nodeValues={nodeValues}
              focusNode={focusNode}
              pendingPrompt={pendingPrompt}
              promptBusy={promptBusy}
              chatEndRef={chatEndRef}
              cyRef={cyRef}
              pickedIds={pickedIds}
              customPrompt={customPrompt}
              setCustomPrompt={setCustomPrompt}
              submitCustomPrompt={submitCustomPrompt}
            />
          )}
        </div>
        {/* Custom prompt — pinned at bottom of right panel (hidden when Chat tab active) */}
        {activeInv && rightTab !== 'chat' && (
          <PromptBox
            cyRef={cyRef}
            pickedIds={pickedIds}
            customPrompt={customPrompt}
            setCustomPrompt={setCustomPrompt}
            promptBusy={promptBusy}
            submitCustomPrompt={submitCustomPrompt}
          />
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
