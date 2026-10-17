import React from 'react'
import ReactDOM from 'react-dom/client'
import SharedView from './SharedView.jsx'
import './styles.css'

// Entry of the static demo (vite.demo.config.js → dist-demo/). The snapshots
// are the files of eval/demo/, copied to data/ at build time; their names are
// injected as __DEMO_CASES__. `?case=<name>` picks one, otherwise the first.
const CASES = __DEMO_CASES__

function pick() {
  const asked = new URLSearchParams(window.location.search).get('case')
  return CASES.includes(asked) ? asked : CASES[0]
}

function NoSnapshot() {
  return (
    <div className="auth-screen">
      <div className="auth-card">
        <div className="logo">BOUNCE<span>CTI</span></div>
        <div className="auth-label">This build holds no demo snapshot (eval/demo/ was empty).</div>
      </div>
    </div>
  )
}

const name = pick()
ReactDOM.createRoot(document.getElementById('root')).render(
  name ? <SharedView demoSrc={`./data/${name}.json`} /> : <NoSnapshot />,
)
