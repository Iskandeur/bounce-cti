// Run progress, pure helpers: turn the document of
// GET /api/investigations/{id}/progress (backend/run_progress.py) into the
// words of the progress line and of its screen-reader announcements.
import { formatDuration } from './format.js'

// Phase names as agent_runner logs them (phase_<name>_starting).
const PHASE_LABELS = {
  main: 'Main investigation',
  hypothesis_write: 'Writing the working hypothesis',
  followup: 'Follow-up',
  corroborate_leads: 'Checking leads',
  report_write: 'Writing the report',
  lessons_learned: 'Retrospective',
  add_seed: 'Investigating the added seed',
  pivot: 'Pivoting on a node',
  custom_prompt: 'Running your prompt',
}

// Plain words for a phase. A drain round says its number and the most rounds
// the loop may run (it stops earlier when the graph stops growing or the call
// budget is nearly used). A phase this table does not know yet keeps its own
// name, made readable: "graph_audit" → "Graph audit".
export function phaseLabel(name, drain) {
  const raw = String(name || '')
  const round = raw.match(/^pivot_drain_(\d+)$/)
  if (round) {
    const max = drain && drain.max_rounds
    return `Pivot drain, round ${round[1]}${max ? ` of at most ${max}` : ''}`
  }
  if (PHASE_LABELS[raw]) return PHASE_LABELS[raw]
  const words = raw.replace(/_+/g, ' ').trim()
  return words ? words[0].toUpperCase() + words.slice(1) : 'Unnamed phase'
}

// WebSocket event kinds after which the progress document may have changed.
export function isProgressEvent(kind) {
  const k = String(kind || '')
  return k.startsWith('phase_') || k === 'agent_starting' || k === 'agent_exit'
    || k === 'agent_resume' || k === 'status_change'
}

// Seconds the run has lasted. A run that ended keeps its final length; a live
// one is measured on the server's clock (`now` at fetch time, plus the time
// since the answer arrived), so a wrong clock on the viewer's side does not
// bend the figure. Null when there is no run to measure.
export function runElapsed(progress, clientNowSec) {
  const run = progress && progress.run
  if (!run || !run.started_at) return null
  if (run.ended_at) return Math.max(0, run.ended_at - run.started_at)
  return Math.max(0, serverNow(progress, clientNowSec) - run.started_at)
}

function serverNow(progress, clientNowSec) {
  return (progress.now || clientNowSec)
    + Math.max(0, clientNowSec - (progress.received_at || clientNowSec))
}

// Seconds since the run ended, on the server's clock; null while it has not.
export function sinceEnd(progress, clientNowSec) {
  const run = progress && progress.run
  if (!run || !run.ended_at) return null
  return Math.max(0, serverNow(progress, clientNowSec) - run.ended_at)
}

// What the agent is doing, for an investigation whose status is `running`.
export function activity(progress) {
  const run = progress && progress.run
  // Status already `running`, run not logged yet (or the last one is over and
  // the next has not logged its start): the agent is being spawned.
  if (!run || run.ended_at) return 'Starting the agent'
  if (progress.phase) return phaseLabel(progress.phase.name, progress.drain)
  const done = progress.phases || []
  if (!done.length) return 'Starting the first phase'
  return `Between phases, after ${phaseLabel(done[done.length - 1].name, progress.drain)}`
}

const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`

// The call figures. With a ceiling (a full investigation, whose pivot drain
// spends the budget): calls of the whole investigation against it. Without
// one (added seed, manual pivot, custom prompt): the calls of this run.
export function callFigures(progress) {
  if (!progress) return null
  const ceiling = progress.ceiling
  if (ceiling == null) {
    const n = progress.source_calls_run || 0
    return { used: n, ceiling: null, over: false, text: `${plural(n, 'source call')} in this run` }
  }
  const used = progress.source_calls || 0
  const over = used > ceiling
  return {
    used, ceiling, over,
    text: over
      ? `${plural(used, 'source call')}, over the budget of ${ceiling}`
      : `${plural(used, 'source call')} of a budget of ${ceiling}`,
  }
}

// How a run that is no longer running ended, in one sentence. Null when the
// investigation never ran (an imported graph, a fresh row).
export function endSentence(progress) {
  const run = progress && progress.run
  if (!run) return null
  if (!run.ended_at) {
    // Marked terminal while a phase is still logged as in flight: a stop ends
    // the phase it interrupts, and the runner then goes on with the next one.
    if (progress.phase) {
      return `Marked ${progress.status}, and the agent is still in: ${phaseLabel(progress.phase.name, progress.drain)}`
    }
    return null
  }
  const took = formatDuration(run.ended_at - run.started_at)
  const end = String(run.end_status || progress.status || '')
  if (run.stopped_by_user) return `Run stopped after ${took}`
  if (end === 'done') return `Run finished in ${took}`
  if (end === 'quota_exceeded') return `Run paused by the Claude quota after ${took}`
  if (end.startsWith('error')) return `Run ended in error after ${took} (${end})`
  return `Run ended after ${took}${end ? ` (${end})` : ''}`
}

// How the end reads to the eye: 'error' and 'paused' get their colour, the
// rest stays quiet.
export function endTone(progress) {
  const run = progress && progress.run
  const end = String((run && run.end_status) || '')
  if (!run || !run.ended_at || run.stopped_by_user) return 'quiet'
  if (end.startsWith('error')) return 'error'
  if (end === 'quota_exceeded') return 'paused'
  return 'quiet'
}

// What a screen reader is told when the document goes from `prev` to `next`:
// the phase when it changes, and how the run ended. Null for everything else
// (a tick, a new call count, a gap between two phases).
export function announcementFor(prev, next) {
  if (!next) return null
  const sameInv = !!prev && prev.investigation_id === next.investigation_id
  const phase = next.phase ? next.phase.name : null
  if (next.running) {
    if (!phase) return null
    const before = sameInv && prev.phase ? prev.phase.name : null
    // Same phase name in a newer run (a second custom prompt) is a new phase.
    const sameRun = sameInv && prev.run && next.run
      && prev.run.started_at === next.run.started_at
    if (before === phase && sameRun) return null
    return `Phase: ${phaseLabel(phase, next.drain)}.`
  }
  // An investigation opened after its run ended says nothing.
  if (!sameInv || !prev.running) return null
  const end = endSentence(next)
  return end ? `${end}.` : null
}
