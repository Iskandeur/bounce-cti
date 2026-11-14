import React, { useState } from 'react'
import { TIES_SHOWN, nodeOrigin, shortValue } from '../lib/provenance.js'

// Why a node is in the graph, written as text: where it came from, then the
// edges that tie it to the rest, each with the reason written on it when it
// carries one. The source
// names are the ones recorded with the node (the agent passes them to
// add_node), so the wording says "named" and "recorded". The cached answers of
// the sources themselves are the next level, under "Evidence (raw data)" in
// the Node tab.
//
// Presentational: `ties` comes from useNodeTies, `onOpenNode` is focusNode.
// Give it `key={node.id}` so the "show the others" state starts closed on
// every node.
export default function NodeProvenance({ node, ties, onOpenNode }) {
  const [showAll, setShowAll] = useState(false)
  const shown = showAll ? ties : ties.slice(0, TIES_SHOWN)
  const rest = ties.length - TIES_SHOWN
  const me = `this ${node.type || 'node'}`
  return (
    <section className="prov">
      <h2 className="prov-title">Provenance</h2>
      <Origin node={node} />
      <p>{tiesSentence(ties)}</p>
      {shown.length > 0 && (
        <ul className="prov-ties">
          {shown.map(t => (
            <li key={t.id}>
              {t.outgoing
                ? <span className="prov-self">{me}</span>
                : <Neighbour tie={t} onOpenNode={onOpenNode} />}
              {' '}<span className="prov-rel">{t.relation}</span>{' '}
              {t.outgoing && !t.self
                ? <Neighbour tie={t} onOpenNode={onOpenNode} />
                : <span className="prov-self">{me}</span>}
              {t.evidence && <span className="prov-reason">{t.evidence}</span>}
            </li>
          ))}
        </ul>
      )}
      {rest > 0 && (
        <button
          type="button"
          className="prov-link prov-more"
          aria-expanded={showAll}
          onClick={() => setShowAll(v => !v)}
        >
          {showAll
            ? `Show the first ${TIES_SHOWN} only`
            : `Show the ${rest} other edge${rest === 1 ? '' : 's'}`}
        </button>
      )}
    </section>
  )
}

function tiesSentence(ties) {
  const n = ties.length
  const withReason = ties.filter(t => t.evidence).length
  if (n === 0) return 'No edge ties this node to the graph yet.'
  const edges = `Tied to the graph by ${n} edge${n === 1 ? '' : 's'}`
  if (withReason === 0) return `${edges}; ${n === 1 ? 'it carries no written reason' : 'none carries a written reason'}.`
  if (withReason === n) return `${edges}, ${n === 1 ? 'with' : 'each with'} its reason below it.`
  return `${edges}, ${withReason} of them with a reason below.`
}

// The node at the other end of an edge: a real button, so the analyst walks
// the graph from the panel with the mouse or the keyboard.
function Neighbour({ tie, onOpenNode }) {
  const { id, type, value } = tie.neighbour
  return (
    <button
      type="button"
      className="prov-link"
      title={`${type} ${value}`}
      onClick={() => onOpenNode(id)}
    >
      <span className="prov-type">{type}</span> <span className="prov-value">{shortValue(value)}</span>
    </button>
  )
}

// Local date and time, with the UTC instant in the tooltip.
function When({ ts }) {
  const d = new Date(ts * 1000)
  return (
    <time dateTime={d.toISOString()} title={d.toISOString()}>
      {d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'medium' })}
    </time>
  )
}

// "a", "a and b", "a, b and c", each name in bold.
function Names({ names }) {
  return names.map((name, i) => (
    <React.Fragment key={i}>
      {i > 0 && (i === names.length - 1 ? ' and ' : ', ')}
      <b>{name}</b>
    </React.Fragment>
  ))
}

// A float as stored, without binary noise (0.30000000000000004 → 0.3).
const figure = x => String(Number(x.toFixed(4)))

function Origin({ node }) {
  const o = nodeOrigin(node)
  const on = o.createdAt ? <> on <When ts={o.createdAt} /></> : null
  const lead = o.lead
  return (
    <p>
      {o.kind === 'source' && (
        <>Added{on}, with <Names names={o.sources} /> named as its source{o.sources.length === 1 ? '' : 's'}. </>
      )}
      {o.kind === 'agent' && <>Added{on} by the agent, which named no source tool. </>}
      {o.kind === 'stub' && <>Created{on} as the end of an edge: nothing had been reported about this node itself. </>}
      {o.kind === 'tag' && <>Created{on} by tag promotion{o.tagEvidence ? ` (${o.tagEvidence})` : ''}. </>}
      {o.kind === 'none' && <>Added{on}. No source was recorded. </>}
      {o.kind === 'lead' && (
        <>
          A hypothesis
          {lead.basis === 'memory' && <> from the agent's own memory</>}
          {lead.basis === 'web' && <> drawn from open-web text (<b>{o.source}</b>)</>}
          {lead.basis === 'other' && <> from the context pool{o.source && <> (<b>{o.source}</b>)</>}</>}
          , recorded{on}.{' '}
          <LeadVerdict lead={lead} />
          A lead stays out of blocklists, detection rules, takedown bundles and STIX.{' '}
        </>
      )}
      {o.promotedFrom && (
        <>
          Promoted from a lead
          {o.promotedFrom.tool && <> once <b>{o.promotedFrom.tool}</b> confirmed it</>}
          {o.promotedFrom.value && ` (${o.promotedFrom.value})`}.{' '}
        </>
      )}
      {o.others.length > 0 && (
        <>
          Also recorded under <Names names={o.others} />
          {o.sourceCount > o.others.length ? `: ${o.sourceCount} source names in all` : ''}.{' '}
        </>
      )}
      {o.confidence !== null && (
        o.kind === 'lead'
          ? <>Confidence <b>{figure(o.confidence)}</b> on a scale of 0 to 1; the server caps the confidence of a lead.</>
          : <>Confidence given when it was added: <b>{figure(o.confidence)}</b> on a scale of 0 to 1.</>
      )}
    </p>
  )
}

// What a primary source said about a lead, in a sentence. The state is a word
// of that sentence; green and red keep the meaning they have on the graph
// (corroborated, refuted).
function LeadVerdict({ lead }) {
  const by = (
    <>
      {lead.tool && <> by <b>{lead.tool}</b></>}
      {lead.value && ` (${lead.value})`}
    </>
  )
  const note = lead.note ? `${String(lead.note).replace(/[.\s]+$/, '')}. ` : ''
  if (lead.state === 'corroborated') {
    return <><b className="prov-ok">Corroborated</b>{by}. {note}</>
  }
  if (lead.state === 'refuted') {
    return <><b className="prov-bad">Refuted</b>{by}. {note}</>
  }
  if (lead.state === 'unverifiable') {
    return <>Marked <b>unverifiable</b>: no primary source could test it. {note}</>
  }
  return (
    <>
      No primary source has tested it yet.{' '}
      {lead.verifiableBy.length > 0 && <>It can be tested with <Names names={lead.verifiableBy} />. </>}
      {lead.falsifier && <>What would refute it: {String(lead.falsifier).replace(/[.\s]+$/, '')}. </>}
    </>
  )
}
