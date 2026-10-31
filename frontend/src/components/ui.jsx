import { ApiError } from '../services/api'

export function Page({ title, lead, children, actions }) {
  return (
    <section className="page">
      <header className="page-head">
        <div>
          <h1>{title}</h1>
          {lead && <p className="lead">{lead}</p>}
        </div>
        {actions && <div className="page-actions">{actions}</div>}
      </header>
      {children}
    </section>
  )
}

export function Card({ title, note, children, className = '' }) {
  return (
    <div className={`card ${className}`}>
      {(title || note) && (
        <div className="card-head">
          {title && <h2>{title}</h2>}
          {note && <span className="note">{note}</span>}
        </div>
      )}
      {children}
    </div>
  )
}

export function Button({ children, onClick, disabled, kind = 'primary', ...rest }) {
  return (
    <button className={`btn ${kind}`} onClick={onClick} disabled={disabled} {...rest}>
      {children}
    </button>
  )
}

export function Spinner({ label = 'Running simulation' }) {
  return (
    <span className="spinner" role="status">
      <i /> {label}
    </span>
  )
}

export function ErrorBox({ error }) {
  if (!error) return null
  const d = error instanceof ApiError ? error.detail : null
  if (d && d.error === 'baseline_unhealthy') {
    return (
      <div className="alert danger" role="alert">
        <strong>Baseline is unhealthy - the attack run was stopped.</strong>
        <p>Before any attack, all six measured ASes must reach the legitimate victim. These did not:</p>
        <ul>
          {(d.failing || []).map((f) => (
            <li key={f.asn}>
              AS{f.asn} reached <b>{f.endpoint}</b>: {f.likely_reason}
            </li>
          ))}
        </ul>
        <p>Fix the configuration (for example the ROA), or deliberately continue by turning off "Require a healthy baseline".</p>
      </div>
    )
  }
  return (
    <div className="alert danger" role="alert">
      <strong>{error.status ? `Request failed (${error.status})` : 'Request failed'}</strong>
      <p>{error.message}</p>
    </div>
  )
}

export function Tag({ children, tone = 'neutral' }) {
  return <span className={`tag ${tone}`}>{children}</span>
}

export function StateTag({ state }) {
  const tone = state === 'Valid' ? 'ok' : state === 'Invalid' ? 'bad' : 'neutral'
  return <Tag tone={tone}>RPKI {state}</Tag>
}

export function SimBadge() {
  return <span className="sim-badge" title="All results are produced by the simulation engine, not real routers">Simulated</span>
}

export function Table({ columns, rows, empty = 'No rows.', dense = false, rowClass }) {
  if (!rows || rows.length === 0) return <p className="muted">{empty}</p>
  return (
    <div className="table-wrap">
      <table className={dense ? 'dense' : ''}>
        <thead>
          <tr>
            {columns.map((c) => (
              <th key={c.key} className={c.num ? 'num' : ''}>{c.label}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i} className={rowClass ? rowClass(r) : ''}>
              {columns.map((c) => (
                <td key={c.key} className={c.num ? 'num' : ''}>{c.render ? c.render(r) : r[c.key]}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export function Stat({ label, value, sub, tone }) {
  return (
    <div className={`stat ${tone || ''}`}>
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      {sub && <div className="stat-sub">{sub}</div>}
    </div>
  )
}

export function Download({ href, children }) {
  return (
    <a className="btn ghost" href={href} download>
      {children}
    </a>
  )
}
