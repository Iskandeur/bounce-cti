import test from 'node:test'
import assert from 'node:assert/strict'
import { formatDuration } from './format.js'
import {
  phaseLabel, isProgressEvent, runElapsed, sinceEnd, activity, callFigures, endSentence,
  endTone, announcementFor,
} from './runProgress.js'

const T0 = 1_800_000_000

// A progress document as GET /api/investigations/{id}/progress returns it.
const doc = (over = {}) => ({
  investigation_id: 'inv1', status: 'running', running: true, vertical: 'cti',
  now: T0 + 100, received_at: 5000,
  run: { kind: 'investigation', started_at: T0, ended_at: null, end_status: null, stopped_by_user: false },
  phase: { name: 'main', started_at: T0 + 1 }, phases: [], drain: null,
  source_calls: 12, source_calls_run: 12, ceiling: 82,
  ...over,
})
const ended = (end_status, over = {}) => doc({
  status: end_status, running: false, phase: null,
  run: { kind: 'investigation', started_at: T0, ended_at: T0 + 842, end_status, stopped_by_user: false },
  ...over,
})

test('durations read like the countdown', () => {
  assert.equal(formatDuration(0), '0s')
  assert.equal(formatDuration(45.9), '45s')
  assert.equal(formatDuration(724), '12m 04s')
  assert.equal(formatDuration(3729), '1h 02m 09s')
  assert.equal(formatDuration(-3), '0s')
  assert.equal(formatDuration(undefined), '0s')
})

test('every phase the runner logs has plain words', () => {
  assert.equal(phaseLabel('main'), 'Main investigation')
  assert.equal(phaseLabel('hypothesis_write'), 'Writing the working hypothesis')
  assert.equal(phaseLabel('followup'), 'Follow-up')
  assert.equal(phaseLabel('corroborate_leads'), 'Checking leads')
  assert.equal(phaseLabel('report_write'), 'Writing the report')
  assert.equal(phaseLabel('lessons_learned'), 'Retrospective')
  assert.equal(phaseLabel('add_seed'), 'Investigating the added seed')
  assert.equal(phaseLabel('pivot'), 'Pivoting on a node')
  assert.equal(phaseLabel('custom_prompt'), 'Running your prompt')
})

test('a drain round says its number, and the most rounds when known', () => {
  assert.equal(phaseLabel('pivot_drain_2', { round: 2, max_rounds: 3 }), 'Pivot drain, round 2 of at most 3')
  assert.equal(phaseLabel('pivot_drain_2', null), 'Pivot drain, round 2')
  assert.equal(phaseLabel('pivot_drain_11', { max_rounds: null }), 'Pivot drain, round 11')
})

test('an unknown phase keeps its name, made readable', () => {
  assert.equal(phaseLabel('graph_audit'), 'Graph audit')
  assert.equal(phaseLabel('x'), 'X')
  assert.equal(phaseLabel(''), 'Unnamed phase')
  assert.equal(phaseLabel(undefined), 'Unnamed phase')
})

test('only run-level events ask for a refresh', () => {
  for (const k of ['phase_main_starting', 'phase_pivot_drain_2_exit', 'phase_new_thing_starting',
    'agent_starting', 'agent_exit', 'agent_resume', 'status_change']) {
    assert.equal(isProgressEvent(k), true, k)
  }
  for (const k of ['agent_assistant', 'agent_user', 'node_added', 'edge_added', 'snapshot',
    'phase2_needed', 'agent_stderr', undefined]) {
    assert.equal(isProgressEvent(k), false, String(k))
  }
})

test('elapsed time runs on the server clock', () => {
  // Fetched at client time 5000 when the server said T0+100; 30 s later.
  assert.equal(runElapsed(doc(), 5030), 130)
  // A viewer clock an hour off changes nothing: only the time since the fetch counts.
  assert.equal(runElapsed(doc({ received_at: 5000 + 3600 }), 5030 + 3600), 130)
  assert.equal(runElapsed(ended('done'), 99999), 842)
  assert.equal(runElapsed(doc({ run: null }), 5030), null)
  assert.equal(runElapsed(null, 5030), null)
})

test('time since the run ended, on the server clock too', () => {
  // Ended at T0+842; fetched at client time 5000 when the server said T0+850.
  const d = ended('done', { now: T0 + 850 })
  assert.equal(sinceEnd(d, 5000), 8)
  assert.equal(sinceEnd(d, 5052), 60)
  assert.equal(sinceEnd(doc(), 5052), null)
  assert.equal(sinceEnd(null, 5052), null)
})

test('what the agent is doing', () => {
  assert.equal(activity(doc()), 'Main investigation')
  assert.equal(activity(doc({ phase: null })), 'Starting the first phase')
  assert.equal(activity(doc({ phase: null, phases: [{ name: 'main' }, { name: 'followup' }] })),
    'Between phases, after Follow-up')
  assert.equal(activity(doc({ run: null, phase: null })), 'Starting the agent')
  // Status back to running, the new run has not logged its start yet.
  assert.equal(activity({ ...ended('done'), status: 'running', running: true }), 'Starting the agent')
  assert.equal(activity(doc({ phase: { name: 'pivot_drain_1' }, drain: { round: 1, max_rounds: 3 } })),
    'Pivot drain, round 1 of at most 3')
})

test('call figures against the budget, exact', () => {
  assert.deepEqual(callFigures(doc()),
    { used: 12, ceiling: 82, over: false, text: '12 source calls of a budget of 82' })
  assert.equal(callFigures(doc({ source_calls: 1 })).text, '1 source call of a budget of 82')
  assert.equal(callFigures(doc({ source_calls: 82 })).over, false)
  assert.deepEqual(callFigures(doc({ source_calls: 98 })),
    { used: 98, ceiling: 82, over: true, text: '98 source calls, over the budget of 82' })
})

test('a run with no drain loop shows its own calls and no budget', () => {
  assert.deepEqual(callFigures(doc({ ceiling: null, source_calls: 70, source_calls_run: 6 })),
    { used: 6, ceiling: null, over: false, text: '6 source calls in this run' })
  assert.equal(callFigures(null), null)
})

test('how a run ended', () => {
  assert.equal(endSentence(ended('done')), 'Run finished in 14m 02s')
  assert.equal(endSentence(ended('quota_exceeded')), 'Run paused by the Claude quota after 14m 02s')
  assert.equal(endSentence(ended('error: auth')), 'Run ended in error after 14m 02s (error: auth)')
  assert.equal(endSentence(ended('error rc=1')), 'Run ended in error after 14m 02s (error rc=1)')
  const stopped = ended('done')
  stopped.run.stopped_by_user = true
  assert.equal(endSentence(stopped), 'Run stopped after 14m 02s')
  assert.equal(endSentence(doc({ run: null })), null)
  assert.equal(endTone(ended('done')), 'quiet')
  assert.equal(endTone(ended('error: model')), 'error')
  assert.equal(endTone(ended('quota_exceeded')), 'paused')
  assert.equal(endTone(stopped), 'quiet')
})

test('a phase still in flight under a terminal status is said as it is', () => {
  const d = doc({ status: 'done', running: false, phase: { name: 'report_write' } })
  assert.equal(endSentence(d), 'Marked done, and the agent is still in: Writing the report')
})

test('announcements: the phase when it changes', () => {
  // Opening a running investigation says where it is.
  assert.equal(announcementFor(null, doc()), 'Phase: Main investigation.')
  // A poll with a new call count says nothing.
  assert.equal(announcementFor(doc(), doc({ source_calls: 13, now: T0 + 110 })), null)
  // Between two phases: nothing, then the next phase.
  const gap = doc({ phase: null, phases: [{ name: 'main' }] })
  assert.equal(announcementFor(doc(), gap), null)
  assert.equal(announcementFor(gap, doc({ phase: { name: 'followup' } })), 'Phase: Follow-up.')
  // Switching to another running investigation in the same phase.
  assert.equal(announcementFor(doc(), doc({ investigation_id: 'inv2' })), 'Phase: Main investigation.')
})

test('announcements: the same phase name in a newer run is announced again', () => {
  const first = doc({ phase: { name: 'custom_prompt' }, ceiling: null })
  const second = doc({
    phase: { name: 'custom_prompt' }, ceiling: null,
    run: { kind: 'custom_prompt', started_at: T0 + 900, ended_at: null, end_status: null },
  })
  assert.equal(announcementFor(first, second), 'Phase: Running your prompt.')
})

test('announcements: the end of a run that was seen running, once', () => {
  assert.equal(announcementFor(doc(), ended('done')), 'Run finished in 14m 02s.')
  assert.equal(announcementFor(doc(), ended('quota_exceeded')),
    'Run paused by the Claude quota after 14m 02s.')
  assert.equal(announcementFor(ended('done'), ended('done')), null)
  // Opening an investigation that finished earlier says nothing.
  assert.equal(announcementFor(null, ended('done')), null)
  assert.equal(announcementFor(doc({ investigation_id: 'inv2' }), ended('done')), null)
  assert.equal(announcementFor(doc(), null), null)
})
