import React from 'react'
import Icon from './Icon.jsx'
import CopyLabel from './CopyLabel.jsx'

// ── ActionsPanel ─────────────────────────────────────────────────────────
// Operational deliverables for a finished investigation. Three cards:
// Blocklist, Detection rules, Takedown. Each opens a formatted artifact
// the analyst can paste straight into a firewall / SIEM / abuse form.
export default function ActionsPanel({ activeInv, graphReady }) {
  const [mode, setMode] = React.useState(null)   // 'block' | 'detect' | 'takedown'
  const [format, setFormat] = React.useState('plain')
  const [includeDefused, setIncludeDefused] = React.useState(false)
  const [content, setContent] = React.useState('')
  const [takedown, setTakedown] = React.useState(null)
  const [loading, setLoading] = React.useState(false)
  const [copied, setCopied] = React.useState(false)
  const [err, setErr] = React.useState('')

  const blockFormats = [
    { id: 'plain',     label: 'Plain text',  ext: 'txt'   },
    { id: 'hosts',     label: 'hosts file',  ext: 'txt'   },
    { id: 'unbound',   label: 'Unbound',     ext: 'conf'  },
    { id: 'rpz',       label: 'BIND RPZ',    ext: 'zone'  },
    { id: 'palo_edl',  label: 'Palo EDL',    ext: 'txt'   },
    { id: 'cisco_acl', label: 'Cisco ACL',   ext: 'cfg'   },
    { id: 'csv',       label: 'CSV',         ext: 'csv'   },
  ]
  const detectFormats = [
    { id: 'sigma', label: 'Sigma', ext: 'yml'   },
    { id: 'snort', label: 'Snort', ext: 'rules' },
    { id: 'yara',  label: 'YARA',  ext: 'yar'   },
  ]

  React.useEffect(() => {
    setMode(null)
    setContent('')
    setTakedown(null)
    setErr('')
  }, [activeInv])

  const load = React.useCallback(async (which, fmt) => {
    if (!activeInv) return
    setLoading(true)
    setErr('')
    setContent('')
    setTakedown(null)
    try {
      if (which === 'block') {
        const params = new URLSearchParams({ fmt, include_defused: includeDefused ? '1' : '0' })
        const r = await fetch(`/api/investigations/${activeInv}/actions/blocklist?${params}`,
                              { credentials: 'same-origin' })
        if (!r.ok) throw new Error((await r.json()).detail || `HTTP ${r.status}`)
        const j = await r.json()
        setContent(j.content || '')
      } else if (which === 'detect') {
        const params = new URLSearchParams({ fmt, include_defused: includeDefused ? '1' : '0' })
        const r = await fetch(`/api/investigations/${activeInv}/actions/detection?${params}`,
                              { credentials: 'same-origin' })
        if (!r.ok) throw new Error((await r.json()).detail || `HTTP ${r.status}`)
        const j = await r.json()
        setContent(j.content || '')
      } else if (which === 'takedown') {
        const r = await fetch(`/api/investigations/${activeInv}/actions/takedown`,
                              { credentials: 'same-origin' })
        if (!r.ok) throw new Error((await r.json()).detail || `HTTP ${r.status}`)
        const j = await r.json()
        setTakedown(j)
      }
    } catch (e) {
      setErr(String(e.message || e))
    } finally {
      setLoading(false)
    }
  }, [activeInv, includeDefused])

  const open = (which) => {
    setMode(which)
    setCopied(false)
    if (which === 'block') { setFormat('plain'); load('block', 'plain') }
    else if (which === 'detect') { setFormat('sigma'); load('detect', 'sigma') }
    else if (which === 'takedown') { load('takedown') }
  }

  const switchFormat = (fmt) => {
    setFormat(fmt)
    setCopied(false)
    load(mode, fmt)
  }

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(content)
      setCopied(true)
      setTimeout(() => setCopied(false), 1400)
    } catch (_) {}
  }

  const download = () => {
    if (!content) return
    const formats = mode === 'block' ? blockFormats : detectFormats
    const meta = formats.find(f => f.id === format) || { ext: 'txt' }
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `bounce-cti-${activeInv}.${mode}.${format}.${meta.ext}`
    document.body.appendChild(a); a.click(); a.remove()
    URL.revokeObjectURL(url)
  }

  if (!activeInv) {
    return <p className="hint">Pick an investigation first.</p>
  }
  if (!graphReady) {
    return <p className="hint">Graph is still loading. Once nodes are in, come back here for blocklists / takedown emails / detection rules.</p>
  }

  return (
    <div className="actions-panel">
      <div className="actions-intro">
        Operational deliverables built from the graph. Defused noise (CDN /
        parking / sinkhole / Tor) is excluded by default — toggle the
        checkbox if you have audited a defused indicator and want it
        included.
      </div>

      <label className="actions-defuse-toggle">
        <input
          type="checkbox"
          checked={includeDefused}
          onChange={e => {
            setIncludeDefused(e.target.checked)
            if (mode === 'block' || mode === 'detect') load(mode, format)
          }}
        />
        Include defused indicators
      </label>

      <div className="actions-cards">
        <button
          className={`action-card${mode === 'block' ? ' active' : ''}`}
          aria-pressed={mode === 'block'}
          onClick={() => open('block')}
        >
          <div className="action-card-body">
            <div className="action-card-title">Blocklist</div>
            <div className="action-card-desc">Firewall / DNS / EDR drop-list in 7 formats</div>
          </div>
        </button>

        <button
          className={`action-card${mode === 'takedown' ? ' active' : ''}`}
          aria-pressed={mode === 'takedown'}
          onClick={() => open('takedown')}
        >
          <div className="action-card-body">
            <div className="action-card-title">Takedown</div>
            <div className="action-card-desc">Abuse-contact emails ready to send, one per host</div>
          </div>
        </button>

        <button
          className={`action-card${mode === 'detect' ? ' active' : ''}`}
          aria-pressed={mode === 'detect'}
          onClick={() => open('detect')}
        >
          <div className="action-card-body">
            <div className="action-card-title">Detection</div>
            <div className="action-card-desc">Sigma / Snort / YARA starter rule</div>
          </div>
        </button>
      </div>

      {err && <div className="actions-error">⚠ {err}</div>}

      {(mode === 'block' || mode === 'detect') && !err && (
        <div className="actions-output">
          <div className="actions-format-row">
            {(mode === 'block' ? blockFormats : detectFormats).map(f => (
              <button
                key={f.id}
                className={`format-pill${format === f.id ? ' active' : ''}`}
                aria-pressed={format === f.id}
                onClick={() => switchFormat(f.id)}
              >
                {f.label}
              </button>
            ))}
            <div style={{ flex: 1 }} />
            <button
              className="btn-sm secondary"
              onClick={copy}
              disabled={!content}
              title="Copy to clipboard"
            >
              <CopyLabel done={copied}><Icon name="copy" />Copy</CopyLabel>
            </button>
            <button
              className="btn-sm secondary"
              onClick={download}
              disabled={!content}
              title="Download file"
            >
              <Icon name="download" />File
            </button>
          </div>
          {loading && <div className="actions-loading">Rendering…</div>}
          {!loading && (
            <pre className="actions-output-pre">{content || '(no actionable IOCs in this graph)'}</pre>
          )}
        </div>
      )}

      {mode === 'takedown' && !err && (
        <div className="actions-takedown">
          {loading && <div className="actions-loading">Building takedown bundles…</div>}
          {!loading && takedown && takedown.count === 0 && (
            <div className="actions-empty">
              No host has a known abuse contact yet. Run the investigation
              long enough for RDAP / WHOIS to populate the registrar /
              abuse_email fields on the seed nodes.
            </div>
          )}
          {!loading && takedown && takedown.count > 0 && (
            <>
              <div className="takedown-summary">
                {takedown.count} target{takedown.count !== 1 ? 's' : ''} with known abuse contact
              </div>
              {takedown.items.map((t, i) => (
                <TakedownCard key={i} item={t} />
              ))}
            </>
          )}
        </div>
      )}
    </div>
  )
}

function TakedownCard({ item }) {
  const [copied, setCopied] = React.useState('')
  const copyText = async (text, label) => {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(label)
      setTimeout(() => setCopied(''), 1400)
    } catch (_) {}
  }
  return (
    <div className="takedown-card">
      <div className="takedown-card-header">
        <div className="takedown-card-target">
          <span className="takedown-target-type">{item.target.type}</span>
          <span className="takedown-target-value">{item.target.value}</span>
        </div>
        <div className="takedown-card-meta">
          {item.registrar && <span title="Registrar / Network operator">{item.registrar}</span>}
          {item.asn && <span className="takedown-asn">{item.asn}</span>}
        </div>
      </div>
      <div className="takedown-card-row">
        <span className="takedown-card-label">To:</span>
        <span className="takedown-card-email">{item.abuse_email}</span>
      </div>
      <div className="takedown-card-row">
        <span className="takedown-card-label">Subject:</span>
        <span className="takedown-card-subject">{item.subject}</span>
      </div>
      <details className="takedown-card-body">
        <summary>Preview email body</summary>
        <pre className="takedown-body-pre">{item.body}</pre>
      </details>
      <div className="takedown-card-actions">
        <a
          href={item.mailto}
          className="btn-sm"
          target="_blank"
          rel="noopener noreferrer"
          title="Open this in your default mail client"
        >
          <Icon name="external" />Open in mail client
        </a>
        <button className="btn-sm secondary" onClick={() => copyText(item.abuse_email, 'email')}>
          <CopyLabel done={copied === 'email'}><Icon name="copy" />Address</CopyLabel>
        </button>
        <button className="btn-sm secondary" onClick={() => copyText(item.subject, 'subject')}>
          <CopyLabel done={copied === 'subject'}><Icon name="copy" />Subject</CopyLabel>
        </button>
        <button className="btn-sm secondary" onClick={() => copyText(item.body, 'body')}>
          <CopyLabel done={copied === 'body'}><Icon name="copy" />Body</CopyLabel>
        </button>
      </div>
    </div>
  )
}
