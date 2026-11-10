import React from 'react'

// Static analysis (uploaded samples only). Surfaces the
// in-process PE/ELF + strings + entropy pass run on
// upload. The agent reads the same payload via
// metadata.static_analysis.
export default function StaticAnalysis({ sa }) {
  if (!sa || sa.error) return null
  const pe = sa.pe || null
  const elf = sa.elf || null
  const packed = pe?.sections?.some(s => (s.entropy || 0) >= 7.5)
  return (
    <div className="static-analysis">
      <div className="section-label" style={{ margin: '6px 0', display: 'flex', alignItems: 'center', gap: 6 }}>
        Static analysis
        {packed && <span className="sa-warn" title="A section has entropy ≥7.5 — likely packed/encrypted">packed?</span>}
      </div>
      <div className="sa-row">
        <span className="sa-key">size</span>
        <span className="sa-val">{sa.size?.toLocaleString()} bytes</span>
      </div>
      <div className="sa-row">
        <span className="sa-key">entropy</span>
        <span className="sa-val">{sa.entropy}</span>
      </div>
      {pe && (
        <>
          <div className="sa-row">
            <span className="sa-key">arch</span>
            <span className="sa-val">PE / {pe.machine}{pe.is_pe32_plus ? ' (PE32+)' : ''}</span>
          </div>
          {pe.compile_timestamp ? (
            <div className="sa-row">
              <span className="sa-key">compiled</span>
              <span className="sa-val">
                {new Date(pe.compile_timestamp * 1000).toISOString().slice(0, 19).replace('T', ' ')}
              </span>
            </div>
          ) : null}
          {Array.isArray(pe.import_dlls) && pe.import_dlls.length > 0 && (
            <div className="sa-row sa-row-wrap">
              <span className="sa-key">imports</span>
              <span className="sa-val sa-chips">
                {pe.import_dlls.map(d => (
                  <span key={d} className="sa-chip">{d}</span>
                ))}
              </span>
            </div>
          )}
          {Array.isArray(pe.sections) && pe.sections.length > 0 && (
            <div className="sa-sections">
              <div className="sa-sections-header">sections</div>
              {pe.sections.map(s => (
                <div key={s.name} className={`sa-section${s.entropy >= 7.5 ? ' sa-section-hot' : ''}`}>
                  <span className="sa-section-name">{s.name || '<?>'}</span>
                  <span className="sa-section-meta">
                    {(s.virtual_size || 0).toLocaleString()}b · entropy {s.entropy}
                  </span>
                </div>
              ))}
            </div>
          )}
        </>
      )}
      {elf && (
        <div className="sa-row">
          <span className="sa-key">arch</span>
          <span className="sa-val">ELF{elf.ei_class} / {elf.machine}</span>
        </div>
      )}
      {sa.strings && (
        <div className="sa-row">
          <span className="sa-key">strings</span>
          <span className="sa-val">
            {sa.strings.ascii_total?.toLocaleString() || 0} ascii
            {sa.strings.utf16_total ? ` · ${sa.strings.utf16_total.toLocaleString()} utf16` : ''}
          </span>
        </div>
      )}
      {Array.isArray(sa.embedded_iocs) && sa.embedded_iocs.length > 0 && (
        <div className="sa-iocs">
          <div className="sa-iocs-header">{sa.embedded_iocs.length} IOCs embedded in strings</div>
          <div className="sa-chips">
            {sa.embedded_iocs.slice(0, 12).map((i, idx) => (
              <span key={idx} className="sa-chip" title={i.value}>
                <span className="sa-chip-type">{i.type}</span>{i.value.length > 28 ? i.value.slice(0, 26) + '…' : i.value}
              </span>
            ))}
            {sa.embedded_iocs.length > 12 && (
              <span className="sa-chip-more">+ {sa.embedded_iocs.length - 12}</span>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
