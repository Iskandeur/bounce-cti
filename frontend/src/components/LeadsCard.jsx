import React from 'react'
import { LEAD_STATES, LEAD_STATE_COLOR } from '../lib/constants.js'

// ── Context-pool leads ──────────────────────────────────
// Claims the agent brought from its own prior knowledge or
// from open-web text, kept visually and structurally apart
// from observed findings. The corroboration rate is the
// run's hallucination thermometer: how much of what the
// model proposed survived contact with a real source.
export default function LeadsCard({ leadStats }) {
  if (!leadStats || !(leadStats.total_leads > 0)) return null
  return (
    <details className="hypothesis-card lead-card">
      <summary>
        <span className="hypothesis-label">leads</span>
        <span className="hypothesis-cat">
          {leadStats.corroborated}/{leadStats.total_leads} corroborated
          {leadStats.corroboration_rate !== null
            && ` · ${Math.round(leadStats.corroboration_rate * 100)}%`}
        </span>
        {leadStats.unverified > 0 && (
          <span className="lead-pending-badge">
            {leadStats.unverified} untested
          </span>
        )}
      </summary>
      <div className="lead-body">
        <p className="lead-caveat">
          Not established facts — these came from the agent's prior
          knowledge or from open-web text, not from a source tool.
          They are excluded from blocklists, detection rules,
          takedown bundles and STIX.
        </p>
        {(leadStats.leads || []).map(l => {
          const state = LEAD_STATES.find(s => (l.tags || []).includes(s))
            || 'unverified'
          return (
            <div key={l.id} className="lead-item">
              <span
                className="lead-state"
                style={{ color: LEAD_STATE_COLOR[state] }}
              >
                {state}
              </span>
              <span className="lead-claim">{l.claim}</span>
              {l.evidence_tool && (
                <span className="lead-evidence">
                  via {l.evidence_tool}
                  {l.evidence_value ? ` → ${l.evidence_value}` : ''}
                </span>
              )}
              {state === 'unverified' && l.falsifier && (
                <span className="lead-evidence">
                  falsifier: {l.falsifier}
                </span>
              )}
            </div>
          )
        })}
      </div>
    </details>
  )
}
