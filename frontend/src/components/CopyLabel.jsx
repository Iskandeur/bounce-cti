import React from 'react'
import Icon from './Icon.jsx'

// Both labels stay in the DOM, stacked in one grid cell: the button keeps the
// width of the wider one, so nothing next to it moves when the label flips.
// The check mark draws itself when the label flips to "copied" (.tick-draw).
export default function CopyLabel({ done, children }) {
  return (
    <span className="copy-label">
      <span className={done ? 'copy-label-off' : undefined}>{children}</span>
      <span className={done ? undefined : 'copy-label-off'} aria-hidden={!done}><Icon name="check" className={done ? 'tick-draw' : ''} />copied</span>
    </span>
  )
}
