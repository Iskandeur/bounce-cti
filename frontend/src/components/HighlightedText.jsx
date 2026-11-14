import React from 'react'
import { iocString } from '../lib/ioc.js'
import { pressable } from '../lib/pressable.js'

export default function HighlightedText({ text, nodeValues, onNodeClick }) {
  const str = typeof text === 'string' ? text : iocString(text)
  if (!str) return null
  const tokens = str.split(/(\s+)/)
  return (
    <span>
      {tokens.map((token, i) => {
        const stripped = token.replace(/^[.,;:!?()"']+|[.,;:!?()"']+$/g, '')
        const id = nodeValues.get(token) || nodeValues.get(stripped)
        if (id) {
          return (
            <span
              key={i}
              className="ioc-link"
              {...pressable(() => onNodeClick(id))}
            >
              {token}
            </span>
          )
        }
        return <React.Fragment key={i}>{token}</React.Fragment>
      })}
    </span>
  )
}
