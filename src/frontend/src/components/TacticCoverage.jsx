import './TacticCoverage.css'

// MITRE ATT&CK kill-chain strip: one cell per tactic, in attack order.
// Cell intensity encodes how many alerts map to that tactic.  Mirrors
// TACTIC_ORDER in backend/services/mitre_mapper.py.

const SHORT = {
  'Reconnaissance':       'Recon',
  'Initial Access':       'Initial Access',
  'Execution':            'Execution',
  'Persistence':          'Persistence',
  'Privilege Escalation': 'Priv Esc',
  'Defense Evasion':      'Def Evasion',
  'Credential Access':    'Cred Access',
  'Discovery':            'Discovery',
  'Lateral Movement':     'Lateral Mvmt',
  'Collection':           'Collection',
  'Command & Control':    'C2',
  'Exfiltration':         'Exfil',
  'Impact':               'Impact',
}

export default function TacticCoverage({ tactics, highlight = [] }) {
  if (!tactics?.length) return <div className="tactic-empty">No MITRE coverage data</div>
  const max = Math.max(1, ...tactics.map(t => t.count))
  const hl = new Set(highlight)
  return (
    <div className="tactic-strip">
      {tactics.map(t => {
        const intensity = t.count ? 0.18 + 0.72 * (t.count / max) : 0
        const active = hl.has(t.tactic)
        return (
          <div
            key={t.tactic}
            className={`tactic-cell${t.count ? ' tactic-hit' : ''}${active ? ' tactic-active' : ''}`}
            style={t.count ? { '--intensity': intensity } : {}}
            title={`${t.tactic}: ${t.count} alert${t.count === 1 ? '' : 's'}`}
          >
            <div className="tactic-count mono">{t.count || '·'}</div>
            <div className="tactic-name">{SHORT[t.tactic] || t.tactic}</div>
          </div>
        )
      })}
    </div>
  )
}
