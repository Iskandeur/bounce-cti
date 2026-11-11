import { iocString } from './ioc.js'

// Build a markdown view of the current report for "Copy MD". Uses exact
// IOC values so analysts can paste into a ticket / chat without losing the
// auto-linking on the UI (IOCs will be rediscoverable via search there).
export function reportToMarkdown(r, activeVertical = 'cti') {
  if (!r) return ''
  const lines = []
  lines.push(`# Investigation summary`)
  lines.push('')
  if (r.threat_assessment) lines.push(`**Threat assessment:** \`${r.threat_assessment}\``)
  if (r.summary) { lines.push(''); lines.push(r.summary) }
  if (r.per_seed_summaries && Object.keys(r.per_seed_summaries).length) {
    lines.push(''); lines.push('## Per-seed summaries')
    Object.entries(r.per_seed_summaries).forEach(([sv, s]) => {
      lines.push(''); lines.push(`### \`${iocString(sv)}\` (${s?.type || '?'})`)
      if (s?.threat_assessment) lines.push(`**Threat assessment:** \`${s.threat_assessment}\``)
      if (s?.summary) { lines.push(''); lines.push(s.summary) }
      if (Array.isArray(s?.key_findings) && s.key_findings.length) {
        lines.push(''); lines.push('**Key findings:**')
        s.key_findings.forEach(f => {
          const text = typeof f === 'string' ? f : iocString(f.text)
          const srcs = (typeof f === 'object' && Array.isArray(f.sources)) ? f.sources : []
          const srcStr = srcs.length ? `  *(${srcs.map(iocString).join(', ')})*` : ''
          lines.push(`- ${text}${srcStr}`)
        })
      }
      if (Array.isArray(s?.sources_used) && s.sources_used.length) {
        lines.push(`**Sources used:** ${s.sources_used.map(x => `\`${iocString(x)}\``).join(', ')}`)
      }
    })
  }
  if (Array.isArray(r.cross_seed_findings) && r.cross_seed_findings.length) {
    lines.push(''); lines.push('## Cross-seed links')
    r.cross_seed_findings.forEach(c => {
      const text = typeof c === 'string' ? c : iocString(c.text)
      const seeds = (typeof c === 'object' && Array.isArray(c.seeds)) ? c.seeds : []
      const srcs = (typeof c === 'object' && Array.isArray(c.sources)) ? c.sources : []
      const seedStr = seeds.length ? `  _[seeds: ${seeds.map(iocString).join(', ')}]_` : ''
      const srcStr = srcs.length ? `  *(${srcs.map(iocString).join(', ')})*` : ''
      lines.push(`- ${text}${seedStr}${srcStr}`)
    })
  }
  if (r.key_findings?.length) {
    lines.push(''); lines.push('## Key findings')
    r.key_findings.forEach(f => {
      const text = typeof f === 'string' ? f : iocString(f.text)
      const srcs = (typeof f === 'object' && Array.isArray(f.sources)) ? f.sources : []
      const srcStr = srcs.length ? `  *(${srcs.map(iocString).join(', ')})*` : ''
      lines.push(`- ${text}${srcStr}`)
    })
  }
  if (r.discriminating_markers?.length) {
    lines.push(''); lines.push('## Discriminating markers')
    r.discriminating_markers.forEach(m => lines.push(`- \`${iocString(m)}\``))
  }
  if (r.pivot_suggestions?.length) {
    lines.push(''); lines.push('## Pivot suggestions')
    r.pivot_suggestions.forEach(p => lines.push(`- ${iocString(p)}`))
  }
  if (r.ioc_list?.length) {
    lines.push(''); lines.push('## ' + (activeVertical === 'dd' ? 'Entities & identifiers'
      : activeVertical === 'osint' ? 'Identifiers' : 'IOC list'))
    r.ioc_list.forEach(i => lines.push(`- \`${iocString(i)}\``))
  }
  if (r.sources_used?.length) {
    lines.push(''); lines.push(`**Sources used:** ${r.sources_used.map(s => `\`${iocString(s)}\``).join(', ')}`)
  }
  return lines.join('\n')
}
