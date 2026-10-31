import { Card, StateTag, Table, Tag } from './ui'
import { ATTACK_LABEL, pathStr, rname } from '../utils/format'

export function MaliciousRoutePanel({ result }) {
  const m = result?.malicious_route
  if (!m) return <Card title="Route validation"><p className="muted">No attack is active, so there is no malicious advertisement to validate.</p></Card>
  const rows = Object.values(result.per_as).map((p) => ({
    asn: p.asn, rov: p.rov, pe: p.path_end, dec: p.malicious_route_decision, status: p.attack_route_status, detail: p.attack_route_detail,
  }))
  return (
    <Card title="Route validation panel" note={ATTACK_LABEL[m.attack]}>
      <dl className="kv">
        <dt>Advertised prefix</dt><dd><code>{m.prefix}</code></dd>
        <dt>Advertised AS path</dt><dd><code>{m.advertised_path_str}</code> (last AS = claimed origin)</dd>
        <dt>Claimed origin</dt><dd>AS{m.claimed_origin}</dd>
        <dt>Actual originator</dt><dd>AS{m.actual_originator} (attacker)</dd>
        <dt>Applicable ROA</dt>
        <dd>{m.applicable_roas.length ? m.applicable_roas.map((r, i) => <code key={i}>{r.prefix} max /{r.max_length} → AS{r.origin}</code>) : 'none'}</dd>
        <dt>RPKI state</dt><dd><StateTag state={m.rpki_state} /></dd>
        <dt>Why</dt><dd>{m.rpki_explanation}</dd>
        <dt>Path-end check</dt><dd>{m.path_end_ok ? <Tag tone="ok">passes</Tag> : <Tag tone="bad">fails</Tag>} {m.path_end_explanation}</dd>
      </dl>
      <div className={`callout ${m.rpki_state === 'Valid' ? 'warn' : ''}`}>
        {m.rpki_state === 'Valid'
          ? <><b>RPKI Valid does not mean the path is real.</b> ROV compares only the last AS in the path ({m.claimed_origin}) with the ROA. It never asks whether the AS before it ({m.advertised_as_path[0]}) is actually connected to {m.claimed_origin}, so the attacker can get through by writing the victim's number at the end.</>
          : <><b>Origin validation catches this one.</b> The claimed origin is not authorised by the ROA, so any AS running ROV can reject it.</>}
      </div>
      <h3>Decision at each measured AS</h3>
      <Table dense
        columns={[
          { key: 'asn', label: 'AS', render: (r) => `${rname(r.asn)} (AS${r.asn})` },
          { key: 'rov', label: 'ROV', render: (r) => (r.rov ? 'on' : 'off') },
          { key: 'pe', label: 'path-end', render: (r) => (r.pe ? 'on' : 'off') },
          { key: 'status', label: 'attack route', render: (r) => <Tag tone={r.status === 'accepted' ? 'bad' : r.status === 'rejected' ? 'ok' : 'neutral'}>{r.status.replace('_', ' ')}</Tag> },
          { key: 'why', label: 'explanation', render: (r) => {
            if (r.status === 'rejected') return r.detail.map((d) => `${d.reject_by}: ${d.reject_reason}`).join(' | ')
            if (r.status === 'accepted') return r.dec ? r.dec.rov_explanation : ''
            return 'Never received (an upstream filtered it or it was not exported here).'
          } },
        ]}
        rows={rows} />
    </Card>
  )
}

export function ProbeTable({ result }) {
  if (!result) return null
  const rows = Object.values(result.per_as)
  return (
    <Card title="Probes to 10.10.0.1:8080" note="one probe from each measured AS">
      <Table
        columns={[
          { key: 'asn', label: 'Source AS', render: (r) => `${rname(r.asn)} (AS${r.asn})` },
          { key: 'bl', label: 'Baseline', render: (r) => r.baseline_endpoint },
          { key: 'route', label: 'Selected AS path', render: (r) => <code>{r.best_route ? r.best_route.path : 'none'}</code> },
          { key: 'fwd', label: 'Forwarding path', render: (r) => <code>{pathStr(r.probe.forwarding_path)}</code> },
          { key: 'ep', label: 'Endpoint reached', render: (r) => <b>{r.endpoint}</b> },
          { key: 'out', label: 'Outcome', render: (r) => r.diverted ? <Tag tone="bad">diverted</Tag> : r.reached_victim ? <Tag tone="ok">victim</Tag> : <Tag>unreachable</Tag> },
          { key: 'choice', label: 'Why this route', render: (r) => r.route_choice || r.probe.failure_reason },
        ]}
        rows={rows}
        rowClass={(r) => (r.diverted ? 'row-bad' : '')}
      />
    </Card>
  )
}

export function RejectedTable({ rows, title = 'Rejected routes', showM = false }) {
  return (
    <Card title={title} note="filtered at import, by receiving AS">
      <Table dense empty="No route was rejected in this configuration."
        columns={[
          ...(showM ? [{ key: 'm', label: 'm', num: true }] : []),
          { key: 'receiver', label: 'Rejected at', render: (r) => `${rname(r.receiver)}` },
          { key: 'from', label: 'Received from', render: (r) => rname(r.from) },
          { key: 'path', label: 'AS path', render: (r) => <code>{r.path}</code> },
          { key: 'reject_by', label: 'By', render: (r) => <Tag tone={r.reject_by === 'ROV' ? 'info' : 'pe'}>{r.reject_by}</Tag> },
          { key: 'reject_reason', label: 'Reason' },
        ]}
        rows={rows} />
    </Card>
  )
}

export function BaselineCard({ baseline }) {
  if (!baseline) return null
  return (
    <Card title="Baseline health" note="before the attack">
      <p>
        {baseline.healthy
          ? <Tag tone="ok">healthy</Tag>
          : <Tag tone="bad">unhealthy</Tag>}{' '}
        {baseline.victims_reached}/6 measured ASes reach the legitimate victim.{baseline.converged ? '' : ' Routing did not converge.'}
      </p>
      {baseline.failing.length > 0 && (
        <ul className="small">{baseline.failing.map((f) => <li key={f.asn}>AS{f.asn}: {f.likely_reason}</li>)}</ul>
      )}
    </Card>
  )
}
