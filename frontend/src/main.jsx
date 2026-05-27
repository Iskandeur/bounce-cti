import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.jsx'
import './styles.css'

// Apply the persisted theme before first paint to avoid a flash of dark UI.
try {
  const saved = localStorage.getItem('bounce-theme')
  if (saved === 'light' || saved === 'dark') {
    document.documentElement.setAttribute('data-theme', saved)
  }
} catch { /* localStorage unavailable (private mode) — default dark */ }

ReactDOM.createRoot(document.getElementById('root')).render(<App />)
