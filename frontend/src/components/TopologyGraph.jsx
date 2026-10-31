import { COLOR, rname } from '../utils/format'

// Fixed layout of the reference topology (positions are presentation only).
const POS = {
  65100: [420, 55],
  65200: [170, 165],
  65300: [420, 165],
  65400: [680, 165],
  65500: [70, 300],
  65600: [270, 300],
  65700: [420, 300],
  65800: [560, 415],
}
const R = 27

function nodeLook(info, per) {
  if (info.role === 'victim') return { fill: COLOR.victim, stroke: COLOR.victim, text: '#fff' }
  if (info.role === 'attacker') return { fill: COLOR.attacker, stroke: COLOR.attacker, text: '#fff' }
  if (!per) return { fill: '#fff', stroke: COLOR.ink, text: COLOR.ink }
  if (per.diverted) return { fill: '#F9DAD6', stroke: COLOR.attacker, text: COLOR.ink }
  if (per.reached_victim) return { fill: '#D4EEE5', stroke: COLOR.victim, text: COLOR.ink }
  return { fill: '#E6E6E6', stroke: '#777', text: COLOR.ink, dash: '4 3' }
}

function offsetArrow(a, b, side = 6) {
  const dx = b[0] - a[0], dy = b[1] - a[1]
  const len = Math.hypot(dx, dy)
  const ux = dx / len, uy = dy / len
  const nx = -uy, ny = ux
  return [
    a[0] + ux * (R + 5) + nx * side, a[1] + uy * (R + 5) + ny * side,
    b[0] - ux * (R + 7) + nx * side, b[1] - uy * (R + 7) + ny * side,
  ]
}

export default function TopologyGraph({ topology, result, selected, onSelect, showRoutes = true }) {
  if (!topology) return <div className="muted">Loading topology…</div>
  const per = result?.per_as || {}
  const rows = {}
  topology.ases.forEach((a) => (rows[a.asn] = a))
  const providers = new Set(topology.attacker_providers)

  return (
    <div className="topo-wrap">
      <svg viewBox="0 0 760 492" role="img" aria-label="Eight-AS reference topology with selected routes">
        <defs>
          {[['v', COLOR.victim], ['a', COLOR.attacker], ['u', '#777']].map(([k, c]) => (
            <marker key={k} id={`ah-${k}`} viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M0,0 L10,5 L0,10 z" fill={c} />
            </marker>
          ))}
        </defs>

        {topology.links.map((l, i) => {
          const a = POS[l.provider], b = POS[l.customer]
          return <line key={i} x1={a[0]} y1={a[1]} x2={b[0]} y2={b[1]} stroke="#B8C0BA" strokeWidth="2" />
        })}

        {showRoutes &&
          Object.values(per).map((p) => {
            const path = p.probe.forwarding_path
            if (!path || path.length < 2) return null
            const [x1, y1, x2, y2] = offsetArrow(POS[path[0]], POS[path[1]])
            const k = p.diverted ? 'a' : p.reached_victim ? 'v' : 'u'
            const c = p.diverted ? COLOR.attacker : p.reached_victim ? COLOR.victim : '#777'
            return <line key={p.asn} x1={x1} y1={y1} x2={x2} y2={y2} stroke={c} strokeWidth="3.2" markerEnd={`url(#ah-${k})`} strokeLinecap="round" />
          })}

        {topology.ases.map((info) => {
          const [x, y] = POS[info.asn]
          const p = per[String(info.asn)]
          const look = nodeLook(info, p)
          const isSel = selected === info.asn
          return (
            <g key={info.asn} className="node" tabIndex={0} role="button"
               aria-label={`${rname(info.asn)} AS${info.asn} ${info.label}`}
               onClick={() => onSelect && onSelect(info.asn)}
               onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && onSelect && onSelect(info.asn)}>
              {p?.rov && <circle cx={x} cy={y} r={R + 6} fill="none" stroke={COLOR.rov} strokeWidth="3" />}
              {isSel && <circle cx={x} cy={y} r={R + 11} fill="none" stroke={COLOR.ink} strokeWidth="1.5" strokeDasharray="3 3" />}
              <circle cx={x} cy={y} r={R} fill={look.fill} stroke={look.stroke} strokeWidth="2.5" strokeDasharray={look.dash} />
              <text x={x} y={y + 5} textAnchor="middle" className="node-name" fill={look.text}>{rname(info.asn)}</text>
              <text x={x} y={y + R + 17} textAnchor="middle" className="node-sub">AS{info.asn}</text>
              {info.role === 'victim' && <text x={x} y={y + R + 30} textAnchor="middle" className="node-role">victim</text>}
              {info.role === 'attacker' && <text x={x} y={y + R + 30} textAnchor="middle" className="node-role">attacker</text>}
              {p?.path_end && (
                <g>
                  <rect x={x + R - 8} y={y - R - 6} width="17" height="17" rx="3" fill={COLOR.pe} />
                  <text x={x + R + 0.5} y={y - R + 7} textAnchor="middle" className="badge-t">P</text>
                </g>
              )}
              {providers.has(info.asn) && (
                <g>
                  <path d={`M${x - R - 5},${y - R + 12} l9,-16 l9,16 z`} fill={COLOR.attacker} />
                  <text x={x - R + 4} y={y - R + 9} textAnchor="middle" className="badge-t">!</text>
                </g>
              )}
            </g>
          )
        })}
      </svg>
      <ul className="legend" aria-label="Legend">
        <li><i className="sw" style={{ background: COLOR.victim }} /> victim (AS65700)</li>
        <li><i className="sw" style={{ background: COLOR.attacker }} /> attacker (AS65800)</li>
        <li><i className="sw ring" style={{ borderColor: COLOR.rov }} /> ROV enabled</li>
        <li><i className="sw sq" style={{ background: COLOR.pe }} /> path-end enabled (P)</li>
        <li><i className="sw tri" /> attacker's provider (!)</li>
        <li><i className="ln" style={{ background: COLOR.victim }} /> next hop, traffic reaches victim</li>
        <li><i className="ln" style={{ background: COLOR.attacker }} /> next hop, traffic diverted</li>
      </ul>
      <p className="muted small">Lines are provider→customer links (higher on the page = provider). Arrows show each AS's selected next hop.</p>
    </div>
  )
}
