// Persisted transcript entries → timeline notes (reasoning, tool calls, tool
// errors), so the timeline survives a page reload.
export function transcriptToNotes(entries) {
  const notes = []
  for (const e of (entries || [])) {
    if (e.kind === 'reasoning' && e.text) {
      notes.push({ ts: e.ts, noteKind: 'reasoning', text: e.text })
    } else if (e.kind === 'tool') {
      notes.push({
        ts: e.ts, noteKind: 'tool', text: e.name,
        detail: JSON.stringify(e.input || {}).slice(0, 200),
      })
    } else if (e.kind === 'tool_result' && e.is_error) {
      notes.push({
        ts: e.ts, noteKind: 'reasoning',
        text: `⚠ ${e.name} returned an error: ${(e.result_preview || '').slice(0, 200)}`,
      })
    }
  }
  return notes
}
