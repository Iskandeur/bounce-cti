import React from 'react'
import PickedChips from './PickedChips.jsx'

// Custom prompt pinned at the bottom of the right panel (every tab but Chat).
export default function PromptBox({ cyRef, pickedIds, customPrompt, setCustomPrompt, promptBusy, submitCustomPrompt }) {
  return (
    <div className="custom-prompt-section">
      {pickedIds.size > 0 && (
        <div className="prompt-selected-nodes">
          <span className="prompt-selected-label">Selected ({pickedIds.size}):</span>
          <div className="prompt-selected-chips">
            <PickedChips cyRef={cyRef} pickedIds={pickedIds} />
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
        ? `Run on ${pickedIds.size} selected`
        : 'Run prompt')}
    </button>
  </div>
  )
}
