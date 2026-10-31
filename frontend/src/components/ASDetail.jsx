import { Card, StateTag, Table, Tag } from './ui'
import { pathStr, rname } from '../utils/format'

export default function ASDetail({ asn, topology, result }) {
  if (!asn || !topology) {
    return <Card title="Inspect an AS"><p className="muted">Select a node in the topology to see its role, links, selected route and probe outcome.</p></Card>
  }
  const info = topology.ases.find((a) => a.asn === asn)
  const nbrs = []
  topology.links.forEach((l) => {
    if (l.provider === asn) nbrs.push({ asn: l.customer, rel: 'customer' })
    if (l.customer === asn) nbrs.push({ asn: l.provider, rel: 'provider' })
  })
  const per = result?.per_as?.[String(asn)]
  return (
    <Card title={`${rname(asn)} · AS${asn}`} note={info.label}>
      <p className="small">
        Role: <Tag>{info.role}</Tag>{' '}
        {topology.attacker_providers.includes(asn) && <Tag tone="bad">attacker's provider</Tag>}
      </p>
      <p className="small">Neighbours: {nbrs.map((n) => `${rname(n.asn)} (${n.rel})`).join(', ') || 'none'}</p>
      {per ? (
        <>
          <p className="small">
            Defences: {per.rov ? <Tag tone="info">ROV</Tag> : <Tag>no ROV</Tag>} {per.path_end ? <Tag tone="pe">path-end</Tag> : <Tag>no path-end</Tag>}
          </p>
          <p className="small">
            Probe to {per.probe.destination_ip}:{per.probe.destination_port} reached <b>{per.endpoint}</b>
            {per.diverted ? ' (diverted to the attacker)' : per.reached_victim ? ' (legitimate victim)' : ` (${per.probe.failure_reason})`}.
          </p>
          <p className="small">Forwarding path: <code>{pathStr(per.probe.forwarding_path)}</code></p>
          <p className="small">Selected route: <code>{per.best_route ? per.best_route.path : 'none'}</code>{per.route_choice ? ` - ${per.route_choice}` : ''}</p>
          <p className="small">Attack route here: <b>{per.attack_route_status.replace('_', ' ')}</b></p>
          <Table dense empty="No accepted candidate routes."
            columns={[
              { key: 'path', label: 'AS path', render: (r) => <code>{r.path}</code> },
              { key: 'learned_from', label: 'from', render: (r) => rname(r.learned_from) },
              { key: 'relationship', label: 'rel.' },
              { key: 'local_pref', label: 'LP', num: true },
              { key: 'rpki_state', label: 'RPKI', render: (r) => <StateTag state={r.rpki_state} /> },
            ]}
            rows={per.candidate_routes} />
          {per.attack_route_status === 'rejected' && (
            <ul className="small">
              {per.attack_route_detail.map((r, i) => (
                <li key={i}>Rejected <code>{r.path}</code> from {rname(r.learned_from)} by <b>{r.reject_by}</b>: {r.reject_reason}</li>
              ))}
            </ul>
          )}
        </>
      ) : (
        <p className="muted small">Run a simulation to see routes for this AS{info.role !== 'measured' ? ' (not a measured AS)' : ''}.</p>
      )}
    </Card>
  )
}
