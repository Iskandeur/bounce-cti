import React from 'react'

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

export default function AgentLog({ events }) {
  return (
    <>
      <div className="section-label" id="agent-log-label">Agent log</div>
      {/* Focusable: the log scrolls, and the keyboard must be able to scroll it. */}
      <div className="event-log" role="log" aria-labelledby="agent-log-label" tabIndex={0}>
        {events.length === 0 && <div className="event-line" style={{ color: 'var(--on-dim)' }}>No events yet</div>}
        {events.map((e, i) => (
          <div key={i} className={eventClass(e)}>{eventLabel(e)}</div>
        ))}
      </div>
    </>
  )
}
