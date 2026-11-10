import React from 'react'

// Budget-extension log (R4): collapsed by default, useful only
// when investigating why the agent kept pivoting past 60 calls.
export default function BudgetLog({ budgetLog }) {
  if (budgetLog.length === 0) return null
  return (
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
  )
}
