import React from 'react'
import NewInvestigationForm from './NewInvestigationForm.jsx'
import InvestigationHistory from './InvestigationHistory.jsx'
import AddSeedPanel from './AddSeedPanel.jsx'
import AgentLog from './AgentLog.jsx'
import RunProgress from './RunProgress.jsx'

export default function Sidebar({
  mobileLeftOpen, theme, setTheme, isAdmin, setAdminOpen, onLogout, settings, allowedModels, form,
  invs, activeInv, quotaState, invActions, mergePickerSrc, setMergePickerSrc, onAddSeed, setShareOpen, events,
  runProgress,
}) {
  // The phone drawer gets no progress (the strip under the top bar shows it):
  // the status of the open investigation says a run is live there.
  const live = !!runProgress?.running || invs.find(i => i.id === activeInv)?.status === 'running'
  return (
    <aside aria-label="Investigations" className={`sidebar${mobileLeftOpen ? ' mobile-open' : ''}`}>
      {/* Everything that starts or picks an investigation scrolls as one column. */}
      <div className="sidebar-main">
        <div className="logo-row"><span className="logo-mark logo-mark-sidebar" aria-hidden="true" /><h1 className="logo" aria-label="Bounce-CTI">BOUNCE<span>CTI</span></h1><span className="logo-actions"><button className="theme-toggle-btn" title={theme === 'light' ? 'Switch to dark theme' : 'Switch to light theme'} aria-label="Toggle theme" onClick={() => setTheme(t => t === 'light' ? 'dark' : 'light')}>{theme === 'light' ? '☾' : '☀'}</button>{isAdmin && <button className="admin-btn" title="Admin panel" onClick={() => setAdminOpen(true)}>⚙</button>}<button className="logout-btn" title="Log out" onClick={onLogout}>⎋</button></span></div>

        <NewInvestigationForm form={form} settings={settings} allowedModels={allowedModels} />

        <InvestigationHistory
          invs={invs}
          activeInv={activeInv}
          quotaState={quotaState}
          actions={invActions}
          mergePickerSrc={mergePickerSrc}
          setMergePickerSrc={setMergePickerSrc}
        />

        {activeInv && (
          <AddSeedPanel
            invs={invs}
            activeInv={activeInv}
            form={form}
            onAddSeed={onAddSeed}
            setShareOpen={setShareOpen}
          />
        )}

      </div>

      {/* The run of the open investigation keeps the foot of the panel, out of
          the scrolling column: the summary of the run above the raw log it sums
          up. The log is taller while a run is live. */}
      {activeInv && (
        <div className={`sidebar-run${live ? ' live' : ''}`}>
          <RunProgress progress={runProgress} placement="sidebar" />
          <AgentLog events={events} />
        </div>
      )}
    </aside>
  )
}
