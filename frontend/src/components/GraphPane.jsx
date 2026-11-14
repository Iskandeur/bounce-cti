import React, { useState } from 'react'
import { NODE_COLORS } from '../lib/constants.js'
import CopyLabel from './CopyLabel.jsx'
import GraphLegend from './GraphLegend.jsx'
import Icon from './Icon.jsx'

// Graph canvas with its toolbar (search, layout, display toggles, exports),
// the node-type / edge-relation filter chips and the legend.
export default function GraphPane({ containerRef, cyRef, search, display, exports, filters, summary, nodeCount, pickedIds, setPickedIds }) {
  const { graphSearch, searchMatches, doGraphSearch, selectAllSearchMatches, focusNextSearchMatch } = search
  const { showEdgeLabels, setShowEdgeLabels, showPins, setShowPins, showNotes, setShowNotes, showDefused, setShowDefused, hardRelayout } = display
  const { copied, copyGraphJson, copyToMaltego } = exports
  const { existingTypeList, existingRelations, filterTypes, toggleFilterType, filterRelations, toggleFilterRelation } = filters
  // On phones the node-type / edge-type filter chips used to occupy the lower
  // half of the graph permanently. They now collapse behind a toggle so the
  // canvas stays usable; desktop always shows them (CSS gates the toggle).
  const [mobileFiltersOpen, setMobileFiltersOpen] = useState(false)
  return (
    <main aria-label="Graph" className={`graph${mobileFiltersOpen ? ' mobile-filters-open' : ''}`}>
      <div id="cy" ref={containerRef} style={{ position: 'absolute', inset: 0 }} />

      {/* Graph toolbar (search integrated) */}
      <div className="graph-toolbar">
        <input
          className="graph-search-input"
          type="text"
          value={graphSearch}
          onChange={e => doGraphSearch(e.target.value)}
          onKeyDown={e => {
            if (e.key === 'Enter' && e.shiftKey) selectAllSearchMatches()
            else if (e.key === 'Enter') focusNextSearchMatch()
            else if (e.key === 'Escape') { doGraphSearch(''); e.target.blur() }
          }}
          placeholder="Search IOCs…"
          aria-label="Search the graph"
        />
        {graphSearch && (
          <span className="graph-search-info">
            {searchMatches} match{searchMatches !== 1 ? 'es' : ''}
            {searchMatches > 0 && (
              <>
                <button className="graph-search-action" onClick={focusNextSearchMatch} title="Focus next (Enter)" aria-label="Focus the next match"><Icon name="next" solo /></button>
                <button className="graph-search-action" onClick={selectAllSearchMatches} title="Select all matches (Shift+Enter)" aria-label="Select all matches"><Icon name="boxChecked" solo /></button>
              </>
            )}
            <button className="graph-search-action" onClick={() => doGraphSearch('')} title="Clear search" aria-label="Clear search"><Icon name="close" solo /></button>
          </span>
        )}
        <span className="toolbar-separator" />
        {/* One wrapper for the buttons: transparent on desktop, a single
            scrolling row under the search field on phones. */}
        <div className="toolbar-actions">
        <button className="toolbar-btn" onClick={() => cyRef.current?.fit(undefined, 80)} title="Fit graph">
          Fit
        </button>
        <button className="toolbar-btn" onClick={hardRelayout} title="Re-run layout (randomize)">
          Relayout
        </button>
        <button
          className={`toolbar-btn${showEdgeLabels ? ' active' : ''}`}
          aria-pressed={showEdgeLabels}
          onClick={() => setShowEdgeLabels(v => !v)}
          title={`${showEdgeLabels ? 'Hide' : 'Show'} the relation written on each edge`}
        >
          <Icon name={showEdgeLabels ? 'boxChecked' : 'box'} />Labels
        </button>
        <button
          className={`toolbar-btn${showPins ? ' active' : ''}`}
          aria-pressed={showPins}
          onClick={() => setShowPins(v => !v)}
          title={`${showPins ? 'Hide' : 'Show'} the pin markers on the graph`}
        >
          <Icon name={showPins ? 'boxChecked' : 'box'} />Pins
        </button>
        <button
          className={`toolbar-btn${showNotes ? ' active' : ''}`}
          aria-pressed={showNotes}
          onClick={() => setShowNotes(v => !v)}
          title={`${showNotes ? 'Hide' : 'Show'} analyst notes (e.g. 'VPN', 'C2') under each node`}
        >
          <Icon name={showNotes ? 'boxChecked' : 'box'} />Notes
        </button>
        {summary.defused > 0 && (
          <button
            className={`toolbar-btn${showDefused ? ' active' : ''}`}
            aria-pressed={showDefused}
            onClick={() => setShowDefused(v => !v)}
            title={`${showDefused ? 'Hide' : 'Show'} the ${summary.defused} defused node(s): CDN, parking, sinkhole, Tor exit, shared hosting and the like. Seeds and pinned nodes stay on the canvas, exports keep every node`}
          >
            <Icon name={showDefused ? 'boxChecked' : 'box'} />{`Defused (${summary.defused})`}
          </button>
        )}
        <button
          className="toolbar-btn"
          onClick={copyGraphJson}
          disabled={nodeCount === 0}
          title={pickedIds.size > 0
            ? `Copy ${pickedIds.size} selected node(s) as JSON`
            : `Copy all ${nodeCount} node(s) as JSON — ctrl+click nodes to narrow`}
        >
          <CopyLabel done={copied === 'graph-json'}><Icon name="copy" />{`JSON (${pickedIds.size > 0 ? pickedIds.size : nodeCount})`}</CopyLabel>
        </button>
        <button
          className="toolbar-btn hide-on-mobile"
          onClick={copyToMaltego}
          disabled={nodeCount === 0}
          title={pickedIds.size > 0
            ? `Copy ${pickedIds.size} selected node(s) in Maltego paste format`
            : `Copy all ${nodeCount} node(s) in Maltego paste format — ctrl+click nodes to narrow`}
        >
          <CopyLabel done={copied === 'maltego'}><Icon name="copy" />{`Maltego (${pickedIds.size > 0 ? pickedIds.size : nodeCount})`}</CopyLabel>
        </button>
        {pickedIds.size > 0 && (
          <button
            className="toolbar-btn"
            onClick={() => setPickedIds(new Set())}
            title="Clear selection (back to all-nodes default)"
          >
            <Icon name="close" />Clear selection
          </button>
        )}
        </div>{/* .toolbar-actions */}
      </div>

      {/* Mobile-only toggle for the filter chips. They overlay the lower
          graph, so on phones we keep them collapsed by default and let the
          analyst reveal them on demand. Hidden on desktop via CSS. */}
      {(existingTypeList.length > 0 || existingRelations.size >= 2) && (
        <button
          className="filter-toggle-btn mobile-only"
          onClick={() => setMobileFiltersOpen(v => !v)}
          aria-expanded={mobileFiltersOpen}
        >
          Filters
        </button>
      )}

      {/* Filter chips wrapper. `display: contents` on desktop so each bar
          keeps its own absolute position exactly as before; on mobile it
          becomes a collapsible bottom-sheet (see .filter-bars in styles). */}
      <div className="filter-bars">
      {/* Node type filter bar */}
      {existingTypeList.length > 0 && (
        <div className="filter-bar">
          {existingTypeList.map(type => {
            const active = !filterTypes.has(type)
            const color = NODE_COLORS[type] || '#8b949e'
            return (
              <button
                key={type}
                className={`filter-chip${active ? ' type-ink' : ' off'}`}
                aria-pressed={active}
                onClick={() => toggleFilterType(type)}
                style={active
                  ? { '--type': color, background: color + '33', borderColor: color }
                  : { background: 'transparent', borderColor: color + '66' }
                }
              >
                {type}
              </button>
            )
          })}
        </div>
      )}

      {/* Edge-relation filter row. Shows once we have ≥2 distinct relations
          on the graph. Click a chip to mute that relation type — useful for
          collapsing noisy historical / co_resolves links on dense graphs.
          Frontend-only (no data is lost). */}
      {existingRelations.size >= 2 && (
        <div className="filter-bar filter-bar-relations">
          <span className="filter-bar-label">edges</span>
          {[...existingRelations].sort().map(rel => {
            const active = !filterRelations.has(rel)
            return (
              <button
                key={rel}
                className={`filter-chip relation-chip${active ? '' : ' off'}`}
                aria-pressed={active}
                onClick={() => toggleFilterRelation(rel)}
                title={active ? `Hide ${rel} edges` : `Show ${rel} edges`}
              >
                {rel}
              </button>
            )
          })}
        </div>
      )}
      </div>{/* .filter-bars */}

      <GraphLegend summary={summary} />
    </main>
  )
}
