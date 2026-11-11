import React from 'react'

// Working hypothesis — phase-1.5 commit, written within the
// first ~8 tool calls. Compact one-line summary by default;
// expand to see evidence + plan. Two schemas in the wild:
// organic (candidate_category / primary_evidence / plan_to_test)
// vs mechanical fallback (category / evidence /
// what_to_pursue_next) — read both.
//
// Freshness: a hypothesis pinned at 8 nodes is stale once the
// drain has added 40 more. Surface that delta + age so the
// analyst doesn't mistake the early guess for current consensus.
// Once the full investigation_summary report is rendered below,
// the hypothesis is mostly a historical artefact — collapse it
// hard and dim it.
export default function HypothesisCard({ hypothesis, hypothesisStamp, nodeCount, report }) {
  if (!hypothesis) return null
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
}
