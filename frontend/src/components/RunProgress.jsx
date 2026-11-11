import React, { useEffect, useState } from 'react'
import { formatDuration } from '../lib/format.js'
import { activity, callFigures, endSentence, endTone, runElapsed, sinceEnd } from '../lib/runProgress.js'

// On phones the strip takes room from the graph: once the run is over, its
// last sentence stays this long, then the strip goes.
const TOPBAR_END_SECONDS = 60

// What the budget is, for the pointer and for assistive technology. The bar
// would mislead without it: the budget is spent by every phase and enforced
// by the pivot drain alone.
const BUDGET_NOTE = 'Calls to the source tools over the whole investigation, against the '
  + 'pivot-drain budget. The drain stops opening rounds when the budget is nearly used; '
  + 'the earlier phases are not capped by it, so the count can end above it.'

// The current time in seconds, refreshed every second while `live` so the
// elapsed time ticks. Kept inside this component: nothing else re-renders.
function useNowSeconds(live) {
  const [now, setNow] = useState(() => Date.now() / 1000)
  useEffect(() => {
    if (!live) return
    setNow(Date.now() / 1000)
    const id = setInterval(() => setNow(Date.now() / 1000), 1000)
    return () => clearInterval(id)
  }, [live])
  return now
}

// One sentence on the open investigation's run: the phase in plain words, the
// time since the run started and the source calls made. A full investigation
// adds a thin bar, calls ÷ pivot-drain budget, the only moving part. A run
// that is over leaves one quiet sentence: for good in the sidebar, for a
// minute in the phone strip. `placement`: 'sidebar' (above the agent log) or
// 'topbar' (under the top bar on phones).
export default function RunProgress({ progress, placement = 'sidebar' }) {
  const live = !!progress && !!progress.running
  const brief = placement === 'topbar'
  const ago = live ? null : sinceEnd(progress, Date.now() / 1000)
  // Keep re-rendering through that minute, so the strip leaves on time.
  const now = useNowSeconds(live || (brief && ago != null && ago < TOPBAR_END_SECONDS))
  if (!progress) return null
  const calls = callFigures(progress)
  const base = `run-progress run-progress-${placement}`

  if (!live) {
    const end = endSentence(progress)
    if (!end) return null
    if (brief && ago != null && ago >= TOPBAR_END_SECONDS) return null
    return (
      <div className={`${base} ended`} role="group" aria-label="Last run">
        <p className="run-progress-text">
          <span className={`run-progress-end ${endTone(progress)}`}>{end}.</span>
          {' '}<span title={calls.ceiling != null ? BUDGET_NOTE : undefined}>{calls.text}.</span>
        </p>
      </div>
    )
  }

  const elapsed = runElapsed(progress, now)
  const started = progress.run && !progress.run.ended_at
  const pct = calls.ceiling ? Math.min(100, (calls.used / calls.ceiling) * 100) : 0
  return (
    <div className={base} role="group" aria-label="Run progress">
      <p className="run-progress-text">
        <span className="run-progress-phase">{activity(progress)}</span>
        {started && elapsed != null && (
          <>, <span className="run-progress-time">{formatDuration(elapsed)}</span> into the run</>
        )}
        .{started && (
          <>
            {' '}
            <span
              className={`run-progress-calls${calls.over ? ' over' : ''}`}
              title={calls.ceiling != null ? BUDGET_NOTE : undefined}
            >{calls.text}</span>.
          </>
        )}
      </p>
      {started && calls.ceiling != null && (
        <div
          className={`run-progress-bar${calls.over ? ' over' : ''}`}
          role="progressbar"
          aria-label="Source calls against the pivot-drain budget"
          aria-valuemin={0}
          aria-valuemax={calls.ceiling}
          aria-valuenow={Math.min(calls.used, calls.ceiling)}
          aria-valuetext={calls.text}
          title={BUDGET_NOTE}
        >
          <div className="run-progress-fill" style={{ width: `${pct}%` }} />
        </div>
      )}
    </div>
  )
}

// The live region for run progress: a sentence when the phase changes and when
// the run ends, nothing per tool call or per tick. Mounted once and for good,
// so assistive technology is already listening when the first sentence lands.
export function RunProgressAnnouncer({ text }) {
  return (
    <div className="run-progress-live" role="status" aria-live="polite" aria-atomic="true">
      {text}
    </div>
  )
}
