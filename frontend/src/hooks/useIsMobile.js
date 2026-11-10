import { useEffect, useState } from 'react'

// Tracks whether the viewport is in mobile width range. We expose drawer toggles
// and tweak interaction behavior (auto-open right panel on node tap, auto-close
// sidebar after starting an investigation, etc.) when this is true.
export default function useIsMobile(query = '(max-width: 768px)') {
  const [isMobile, setIsMobile] = useState(() => {
    if (typeof window === 'undefined' || !window.matchMedia) return false
    return window.matchMedia(query).matches
  })
  useEffect(() => {
    if (typeof window === 'undefined' || !window.matchMedia) return
    const mq = window.matchMedia(query)
    const handler = (e) => setIsMobile(e.matches)
    if (mq.addEventListener) mq.addEventListener('change', handler)
    else mq.addListener(handler)
    return () => {
      if (mq.removeEventListener) mq.removeEventListener('change', handler)
      else mq.removeListener(handler)
    }
  }, [query])
  return isMobile
}
