import React, { useState } from 'react'
import Icon from './Icon.jsx'

// Add-IOC panel: appears only when an investigation is open. Lets the
// analyst attach a new peer seed (independent IOC) to the same graph.
// The agent compares its infrastructure against existing nodes and
// cross-links when concrete overlap is found.
export default function AddSeedPanel({ invs, activeInv, form, onAddSeed, setShareOpen }) {
  const { pdfBusy, pdfError, pdfAddSeedInputRef, addPdfToActiveInv } = form
  // Add-seed form: attach a new PEER IOC to the currently open investigation.
  // Type is always auto-detected — no override dropdown.
  const [addSeedValue, setAddSeedValue] = useState('')
  const submitAddSeed = async () => {
    if (await onAddSeed(addSeedValue)) setAddSeedValue('')
  }
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
          <Icon name="plus" />Add
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
        className="file-input"
        disabled={isRunning || pdfBusy}
      />
      <label
        htmlFor="pdf-add-seed-input"
        className={`btn-sm pdf-add-seed-btn${isRunning || pdfBusy ? ' disabled' : ''}`}
        title={isRunning
          ? 'Agent is running — wait for it to finish'
          : 'Upload a CTI report PDF — extracted IOCs are added as seeds'}
      >
        {pdfBusy ? 'Reading the PDF…' : <><Icon name="upload" />Import a PDF</>}
      </label>
      {pdfError && <div className="pdf-error">{pdfError}</div>}
      {/* Share entry-point: visible as soon as an investigation is open
          (don't make analysts hunt for it inside the report tab). */}
      <button
        className="btn-sm share-btn sidebar-share-btn"
        onClick={() => setShareOpen(true)}
        title="Generate a share link for this investigation"
      >
        Share this investigation
      </button>
    </>
  )
}
