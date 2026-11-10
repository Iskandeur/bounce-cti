import { useEffect, useState } from 'react'

// Light/dark theme, mirrored on <html data-theme> and persisted (bounce-theme).
export default function useTheme() {
  const [theme, setTheme] = useState(() => {
    try { return document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark' }
    catch { return 'dark' }
  })

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    try { localStorage.setItem('bounce-theme', theme) } catch { /* ignore */ }
  }, [theme])
  return [theme, setTheme]
}
