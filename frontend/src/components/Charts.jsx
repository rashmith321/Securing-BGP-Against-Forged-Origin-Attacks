import { Area, Bar, BarChart, CartesianGrid, ComposedChart, Legend, Line, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis, Cell } from 'recharts'
import { COLOR, EXP_LABEL } from '../utils/format'

const pctTick = (v) => `${v}%`

// curves: { expKey: [{k, D_mean, D_min, D_max, ...}] }; every plotted value is a backend field.
export function CurveChart({ curves, xLabel = 'Number of adopting ASes, k (of 6 measured)', extraLines = [], height = 340 }) {
  const ks = new Set()
  Object.values(curves).forEach((c) => c.forEach((p) => ks.add(p.k)))
  const data = [...ks].sort((a, b) => a - b).map((k) => {
    const row = { k }
    Object.entries(curves).forEach(([exp, c]) => {
      const p = c.find((x) => x.k === k)
      if (p) {
        row[`${exp}_mean`] = +(100 * p.D_mean).toFixed(2)
        row[`${exp}_band`] = [+(100 * p.D_min).toFixed(2), +(100 * p.D_max).toFixed(2)]
        row[`${exp}_runs`] = p.runs
      }
    })
    extraLines.forEach((l) => (row[l.key] = l.value))
    return row
  })
  return (
    <div className="chart" role="img" aria-label="Diversion rate versus adoption">
      <ResponsiveContainer width="100%" height={height}>
        <ComposedChart data={data} margin={{ top: 10, right: 20, bottom: 28, left: 8 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#E1E6E2" />
          <XAxis dataKey="k" label={{ value: xLabel, position: 'insideBottom', offset: -16, fontSize: 12 }} />
          <YAxis domain={[0, 100]} tickFormatter={pctTick} label={{ value: 'Diversion rate D (% of measured ASes)', angle: -90, position: 'insideLeft', offset: 14, fontSize: 12, style: { textAnchor: 'middle' } }} />
          <Tooltip formatter={(v) => (Array.isArray(v) ? `${v[0]}% to ${v[1]}%` : `${v}%`)} labelFormatter={(k) => `k = ${k}`} />
          <Legend verticalAlign="top" height={30} />
          {Object.keys(curves).map((exp) => (
            <Area key={exp + 'b'} dataKey={`${exp}_band`} stroke="none" fill={COLOR[exp]} fillOpacity={0.12} legendType="none" name={`${EXP_LABEL[exp] || exp} (min-max over sets)`} isAnimationActive={false} />
          ))}
          {Object.keys(curves).map((exp) => (
            <Line key={exp} dataKey={`${exp}_mean`} name={`${EXP_LABEL[exp] || exp} (mean)`} stroke={COLOR[exp]} strokeWidth={2.5} dot={{ r: 4 }} isAnimationActive={false} />
          ))}
          {extraLines.map((l) => (
            <Line key={l.key} dataKey={l.key} name={l.name} stroke={l.color || COLOR.muted} strokeDasharray="6 4" dot={false} strokeWidth={2} isAnimationActive={false} />
          ))}
        </ComposedChart>
      </ResponsiveContainer>
    </div>
  )
}

export function ComparisonBars({ rows }) {
  const data = rows.map((r) => ({
    name: `${r.attack === 'none' ? 'No attack' : r.attack === 'type0' ? 'Type-0' : 'Type-1'} · ${r.rov_policy === 'ROV enabled' ? `ROV ${r.rov_adoption}` : 'no ROV'}`,
    D: +(100 * r.diversion_rate).toFixed(2),
    attack: r.attack,
    rov: r.rov_policy === 'ROV enabled',
  }))
  return (
    <div className="chart" role="img" aria-label="Diversion rate by attack and ROV policy">
      <ResponsiveContainer width="100%" height={320}>
        <BarChart data={data} margin={{ top: 10, right: 20, bottom: 50, left: 8 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#E1E6E2" />
          <XAxis dataKey="name" interval={0} angle={-20} textAnchor="end" height={70} tick={{ fontSize: 12 }} />
          <YAxis domain={[0, 100]} tickFormatter={pctTick} label={{ value: 'Diversion rate D (%)', angle: -90, position: 'insideLeft', fontSize: 12, style: { textAnchor: 'middle' } }} />
          <Tooltip formatter={(v) => `${v}%`} />
          <Bar dataKey="D" name="Diversion rate" isAnimationActive={false}>
            {data.map((d, i) => (
              <Cell key={i} fill={d.attack === 'type0' ? COLOR.type0_rov : d.attack === 'type1' ? COLOR.type1_rov : COLOR.victim} fillOpacity={d.rov ? 1 : 0.55} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}

export function SetBars({ sets, color }) {
  const data = sets.map((s) => ({
    name: s.adopters.length ? s.adopters.map((a) => `r${a - 65000}`).join(' ') : '(none)',
    D: +(100 * s.D).toFixed(2),
    p: s.p,
  }))
  const shade = ['#9AA7B2', '#E0A040', '#B42318']
  return (
    <div className="chart" role="img" aria-label="Diversion rate per adopter set">
      <ResponsiveContainer width="100%" height={Math.max(260, 26 * data.length + 70)}>
        <BarChart data={data} layout="vertical" margin={{ top: 10, right: 30, bottom: 28, left: 20 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#E1E6E2" />
          <XAxis type="number" domain={[0, 100]} tickFormatter={pctTick} label={{ value: 'Diversion rate D (%)', position: 'insideBottom', offset: -14, fontSize: 12 }} />
          <YAxis type="category" dataKey="name" width={150} tick={{ fontSize: 11 }} interval={0} />
          <Tooltip formatter={(v, _n, p) => [`${v}%`, `p = ${p.payload.p} attacker provider(s)`]} />
          <Bar dataKey="D" isAnimationActive={false}>
            {data.map((d, i) => <Cell key={i} fill={shade[d.p] || color} />)}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
      <ul className="legend inline">
        <li><i className="sw" style={{ background: shade[0] }} /> p = 0 (no attacker provider adopts)</li>
        <li><i className="sw" style={{ background: shade[1] }} /> p = 1</li>
        <li><i className="sw" style={{ background: shade[2] }} /> p = 2 (r400 and r600 both adopt)</li>
      </ul>
    </div>
  )
}
