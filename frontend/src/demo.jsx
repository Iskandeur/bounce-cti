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

const REPO_URL = 'https://github.com/Iskandeur/bounce-cti'

// A page published before any snapshot is committed still sends the reader
// somewhere useful: the recorded demo and the code.
function NoSnapshot() {
  const link = { textAlign: 'center', textDecoration: 'none' }
  return (
    <div className="auth-screen">
      <div className="auth-card">
        <div className="logo">BOUNCE<span>CTI</span></div>
        <div className="auth-label">No investigation is frozen in this build yet (eval/demo/ was empty).</div>
        <a className="auth-btn" href={`${REPO_URL}/blob/main/media/demo.mp4`} style={link}>
          ▶ Watch the 20-second demo
        </a>
        <a className="auth-btn secondary" href={REPO_URL} style={link}>Bounce-CTI on GitHub</a>
      </div>
    </div>
  )
}

const name = pick()
ReactDOM.createRoot(document.getElementById('root')).render(
  name
    ? <SharedView demoSrc={`./data/${name}.json`} demoCases={CASES} demoCase={name} />
    : <NoSnapshot />,
)
