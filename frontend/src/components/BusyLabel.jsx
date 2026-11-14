import React from 'react'

// The label of a button whose action takes time. Both labels stay in the DOM,
// stacked in one grid cell like a copy button's (CopyLabel.jsx): the button is
// as wide as the wider one, so it keeps its width while it is busy.
export default function BusyLabel({ busy, label, children }) {
  return (
    <span className="copy-label">
      <span className={busy ? 'copy-label-off' : undefined} aria-hidden={busy || undefined}>{children}</span>
      <span className={busy ? undefined : 'copy-label-off'} aria-hidden={!busy}>{label}</span>
    </span>
  )
}
