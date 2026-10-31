import { COLOR, rname } from '../utils/format'

export function AsChips({ measured, value, onChange, color, label, attackerProviders = [] }) {
  const set = new Set(value)
  const toggle = (a) => {
    const n = new Set(set)
    n.has(a) ? n.delete(a) : n.add(a)
    onChange([...n].sort())
  }
  return (
    <fieldset className="chips">
      <legend>{label}</legend>
      <div className="chip-row">
        {measured.map((a) => (
          <label key={a} className={`chip ${set.has(a) ? 'on' : ''}`} style={set.has(a) ? { background: color, borderColor: color } : {}}>
            <input type="checkbox" checked={set.has(a)} onChange={() => toggle(a)} />
            {rname(a)}
            {attackerProviders.includes(a) && <b title="attacker's provider"> !</b>}
          </label>
        ))}
      </div>
      <div className="chip-actions">
        <button type="button" className="link" onClick={() => onChange([...measured])}>all</button>
        <button type="button" className="link" onClick={() => onChange([])}>none</button>
        <span className="muted small">{value.length}/{measured.length} ({Math.round((100 * value.length) / measured.length)}%)</span>
      </div>
    </fieldset>
  )
}

export function RovChips(props) {
  return <AsChips {...props} color={COLOR.rov} label="ROV adopters" />
}
export function PathEndChips(props) {
  return <AsChips {...props} color={COLOR.pe} label="Path-end adopters" />
}
