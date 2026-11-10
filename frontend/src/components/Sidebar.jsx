import React from 'react'
import NewInvestigationForm from './NewInvestigationForm.jsx'
import InvestigationHistory from './InvestigationHistory.jsx'
import AddSeedPanel from './AddSeedPanel.jsx'
import AgentLog from './AgentLog.jsx'

export default function Sidebar({
  mobileLeftOpen, theme, setTheme, isAdmin, setAdminOpen, onLogout, settings, allowedModels, form,
  invs, activeInv, quotaState, invActions, mergePickerSrc, setMergePickerSrc, onAddSeed, setShareOpen, events,
}) {
  return (
    <div className={`sidebar${mobileLeftOpen ? ' mobile-open' : ''}`}>
      <div className="logo-row"><span className="logo-mark logo-mark-sidebar" aria-hidden="true" /><div className="logo">BOUNCE<span>CTI</span></div><button className="theme-toggle-btn" title={theme === 'light' ? 'Switch to dark theme' : 'Switch to light theme'} aria-label="Toggle theme" onClick={() => setTheme(t => t === 'light' ? 'dark' : 'light')}>{theme === 'light' ? '☾' : '☀'}</button>{isAdmin && <button className="admin-btn" title="Admin panel" onClick={() => setAdminOpen(true)}>⚙</button>}<button className="logout-btn" title="Log out" onClick={onLogout}>⎋</button></div>

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

      <AgentLog events={events} />
    </div>
  )
}
