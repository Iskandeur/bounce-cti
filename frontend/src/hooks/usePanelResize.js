import { useCallback, useEffect, useRef, useState } from 'react'

// Widths of the two side panels, dragged by the resize handles.
export default function usePanelResize() {
  // Right panel default bumped to 460px so the "Partager" button + first lines
  // of the description/report aren't cropped at common laptop widths. Both
  // values persist to localStorage so a manual resize is remembered.
  const [leftWidth, setLeftWidth] = useState(() => {
    try {
      const v = parseInt(window.localStorage.getItem('bounce.leftWidth') || '', 10)
      if (Number.isFinite(v) && v >= 180 && v <= 520) return v
    } catch (_) { /* ignore */ }
    return 260
  })
  const [rightWidth, setRightWidth] = useState(() => {
    try {
      const v = parseInt(window.localStorage.getItem('bounce.rightWidth') || '', 10)
      if (Number.isFinite(v) && v >= 220 && v <= 620) return v
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
        setLeftWidth(Math.max(180, Math.min(520, startWidth + dx)))
      } else {
        setRightWidth(Math.max(220, Math.min(620, startWidth - dx)))
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
  return { leftWidth, rightWidth, startDrag }
}
