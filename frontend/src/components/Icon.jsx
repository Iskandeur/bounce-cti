import React from 'react'
import { ICONS } from '../lib/icons.js'

// One icon of lib/icons.js (which also says which buttons take one). It is as
// tall as the text it sits in (1em), drawn in the text colour, and hidden from
// assistive technology: the button's label, or its aria-label, names it.
// `solo` is for a button that holds nothing else (no gap kept for a label).
export default function Icon({ name, solo = false, className = '' }) {
  const paths = ICONS[name]
  if (!paths) return null
  return (
    <svg
      className={`icon${solo ? ' icon-solo' : ''}${className ? ' ' + className : ''}`}
      viewBox="0 0 16 16"
      width="1em"
      height="1em"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {paths.map((d, i) => <path key={i} d={d} />)}
    </svg>
  )
}
