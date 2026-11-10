import { useRef, useState } from 'react'
import { detectIOCType, parseSeedInput } from '../lib/ioc.js'

// State and submit handlers of the "New investigation" form (IOC / sample /
// PDF), plus the PDF import onto the open investigation, which shares the
// same busy / error state.
export default function useNewInvestigation({ model, effort, vertical, activeInv, refreshInvs, openInv, setEvents }) {
  // Unified IOC input — single textarea handles both single-IOC and multi-IOC
  // input. The submit handler detects the line count and routes to the
  // appropriate endpoint. Type is always auto-detected from the value.
  const [seedText, setSeedText] = useState('')
  // 'ioc' | 'pdf' — two ways to start an investigation. The IOC mode unifies
  // what used to be 'single' and 'batch' (paste one IOC or a list, same input).
  const [inputMode, setInputMode] = useState('ioc')
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
  const [batchCombined, setBatchCombined] = useState(true)

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
  return {
    seedText, setSeedText, inputMode, setInputMode, batchCombined, setBatchCombined,
    pdfFile, setPdfFile, pdfBusy, pdfError, setPdfError, pdfFileInputRef, pdfAddSeedInputRef,
    sampleFile, setSampleFile, sampleText, setSampleText, sampleBusy, sampleError, setSampleError,
    sampleFileInputRef, start, startFromPdf, startFromSample, addPdfToActiveInv,
  }
}
