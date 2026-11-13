import { useCallback, useEffect, useRef, useState } from 'react'

// The width the graph keeps between the two panels when the window is too
// narrow for both at the width they were dragged to.
export const GRAPH_MIN = 340
const HANDLES = 10   // the two 5px resize handles
export const LEFT_MIN = 180
export const RIGHT_MIN = 220

// The grid columns of the desktop layout. In a window wide enough, each panel
// has the width it was dragged to. In a narrower one (769 to about 1100px with
// the default widths) the two panels share what the window leaves once the
// graph has GRAPH_MIN, in proportion to their widths, and neither goes under
// the minimum its handle allows. Fixed widths used to leave the graph a strip
// of a few dozen pixels there, its toolbar spilling over the sidebar.
export function panelColumns(left, right) {
  const share = side => `calc((100vw - ${GRAPH_MIN + HANDLES}px) * ${(side / (left + right)).toFixed(4)})`
  const col = (side, min) => `clamp(${min}px, ${share(side)}, ${side}px)`
  return `${col(left, LEFT_MIN)} 5px minmax(0, 1fr) 5px ${col(right, RIGHT_MIN)}`
}

// Widths of the two side panels, dragged by the resize handles.
export default function usePanelResize() {
  // Right panel default bumped to 460px so the "Partager" button + first lines
  // of the description/report aren't cropped at common laptop widths. Both
  // values persist to localStorage so a manual resize is remembered.
  const [leftWidth, setLeftWidth] = useState(() => {
    try {
      const v = parseInt(window.localStorage.getItem('bounce.leftWidth') || '', 10)
      if (Number.isFinite(v) && v >= LEFT_MIN && v <= 520) return v
    } catch (_) { /* ignore */ }
    return 260
  })
  const [rightWidth, setRightWidth] = useState(() => {
    try {
      const v = parseInt(window.localStorage.getItem('bounce.rightWidth') || '', 10)
      if (Number.isFinite(v) && v >= RIGHT_MIN && v <= 620) return v
    } catch (_) { /* ignore */ }
    return 460
  })
  const leftWidthRef = useRef(leftWidth)
  const rightWidthRef = useRef(rightWidth)
  const dragStateRef = useRef(null)
  useEffect(() => {
    leftWidthRef.current = leftWidth
    try { window.localStorage.setItem('bounce.leftWidth', String(leftWidth)) } catch (_) {}
  }, [leftWidth])
  useEffect(() => {
    rightWidthRef.current = rightWidth
    try { window.localStorage.setItem('bounce.rightWidth', String(rightWidth)) } catch (_) {}
  }, [rightWidth])

  // ── Panel resize drag handlers ───────────────────────────────────────────
  useEffect(() => {
    const onMouseMove = (e) => {
      if (!dragStateRef.current) return
      const { side, startX, startWidth } = dragStateRef.current
      const dx = e.clientX - startX
      if (side === 'left') {
        setLeftWidth(Math.max(LEFT_MIN, Math.min(520, startWidth + dx)))
      } else {
        setRightWidth(Math.max(RIGHT_MIN, Math.min(620, startWidth - dx)))
      }
    }
    const onMouseUp = () => {
      if (!dragStateRef.current) return
      dragStateRef.current = null
      document.body.style.cursor = ''
      document.body.style.userSelect = ''
    }
    document.addEventListener('mousemove', onMouseMove)
    document.addEventListener('mouseup', onMouseUp)
    return () => {
      document.removeEventListener('mousemove', onMouseMove)
      document.removeEventListener('mouseup', onMouseUp)
    }
  }, [])

  const startDrag = useCallback((side) => (e) => {
    e.preventDefault()
    dragStateRef.current = {
      side,
      startX: e.clientX,
      startWidth: side === 'left' ? leftWidthRef.current : rightWidthRef.current,
    }
    document.body.style.cursor = 'col-resize'
    document.body.style.userSelect = 'none'
  }, [])
  return { columns: panelColumns(leftWidth, rightWidth), startDrag }
}
