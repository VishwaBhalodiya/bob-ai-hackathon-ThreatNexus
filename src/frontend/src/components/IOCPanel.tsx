// IOCPanel — chip list for indicators of compromise
import type { IOCItem } from '../types'

const TYPE_COLOUR: Record<string, string> = {
  ip:     '#79c0ff',
  domain: '#d2a8ff',
  url:    '#ffa657',
  sha256: '#ff7b72',
  sha1:   '#ff7b72',
  md5:    '#ff7b72',
  email:  '#56d364',
}

interface Props {
  iocs: IOCItem[]
}

export function IOCPanel({ iocs }: Props) {
  if (!iocs.length) {
    return <span style={{ color: 'var(--muted)', fontSize: 12 }}>No IOCs identified</span>
  }
  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
      {iocs.map((ioc, i) => {
        const colour = TYPE_COLOUR[ioc.type] ?? '#8b949e'
        return (
          <span key={i} style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 4,
            background: '#21262d',
            border: `1px solid ${colour}55`,
            borderRadius: 4,
            padding: '2px 8px',
            fontSize: 11,
            fontFamily: 'monospace',
            color: colour,
            maxWidth: 280,
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
          }}>
            <span style={{ color: 'var(--muted)', fontSize: 10, textTransform: 'uppercase' }}>
              {ioc.type}
            </span>
            {ioc.value}
          </span>
        )
      })}
    </div>
  )
}
