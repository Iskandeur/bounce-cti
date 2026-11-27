import React from 'react'
import HighlightedText from './HighlightedText.jsx'
import PickedChips from './PickedChips.jsx'
import BusyLabel from './BusyLabel.jsx'
import { busyProps } from '../lib/pressable.js'
import { iocString } from '../lib/ioc.js'

export default function ChatTab({
  report, activeInv, nodeValues, focusNode, pendingPrompt, promptBusy, chatEndRef,
  cyRef, pickedIds, customPrompt, setCustomPrompt, submitCustomPrompt,
}) {
  return (
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
                <PickedChips cyRef={cyRef} pickedIds={pickedIds} />
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
            className="auth-btn btn-primary"
            disabled={!promptBusy && !customPrompt.trim()}
            {...busyProps(promptBusy, submitCustomPrompt)}
            style={{ marginTop: 4, width: '100%' }}
          >
            <BusyLabel busy={promptBusy} label="Agent is thinking…">
              {pickedIds.size > 0 ? `Ask about ${pickedIds.size} selected` : 'Send'}
            </BusyLabel>
          </button>
        </div>
      )}
    </div>
  )
}
