import { useCallback, useState } from 'react'
import { ComparisonBars } from '../components/Charts'
import { RovChips } from '../components/DefenseControls'
import { Button, Card, Download, ErrorBox, Page, SimBadge, Spinner, StateTag, Table, Tag } from '../components/ui'
import { useAsync } from '../hooks/useAsync'
import { api } from '../services/api'
import { ATTACK_LABEL, pct, setLabel } from '../utils/format'

export default function AttackComparison({ topology }) {
  const measured = topology?.measured ?? []
  const [rov, setRov] = useState(null)
  const cmp = useAsync(useCallback((body) => api.attackComparison(body), []))
  const sub = useAsync(useCallback(() => api.subprefix(), []))
  const res = cmp.data?.result
  const rovValue = rov ?? measured

  return (
    <Page title="Type-0 versus Type-1" lead="Runs the baseline and both attacks with ROV off and on, then compares them. The hypotheses below are checked against the computed values, not assumed."
      actions={<SimBadge />}>
      <Card title="ROV adoption used for the “ROV enabled” rows">
        <RovChips measured={measured} value={rovValue} onChange={setRov} attackerProviders={topology?.attacker_providers} />
        <div className="btn-row">
          <Button onClick={() => cmp.run({ rov_set: rovValue })} disabled={cmp.loading}>Run comparison</Button>
          {cmp.data?.run_id && <Download href={api.csvUrl(cmp.data.run_id, 'attack_comparison.csv')}>Download CSV</Download>}
          {cmp.loading && <Spinner />}
        </div>
      </Card>
      <ErrorBox error={cmp.error} />
      {res && (
        <>
          <Card title="Diversion by attack and ROV policy" note="simulated">
            <ComparisonBars rows={res.rows} />
          </Card>
          <Card title="Comparison table">
            <Table
              columns={[
                { key: 'attack', label: 'Attack', render: (r) => ATTACK_LABEL[r.attack] },
                { key: 'rov', label: 'ROV adoption', render: (r) => `${r.rov_adoption} (${r.rov_adoption_pct}%)` },
                { key: 'path', label: 'Advertised path', render: (r) => <code>{r.advertised_path}</code> },
                { key: 'st', label: 'RPKI state of attack route', render: (r) => (r.rpki_state === 'n/a' ? '-' : <StateTag state={r.rpki_state} />) },
                { key: 'acc', label: 'ASes accepting attack route', num: true, render: (r) => r.accepting_attack_route },
                { key: 'div', label: 'ASes diverted', num: true, render: (r) => r.diverted_count },
                { key: 'D', label: 'Diversion rate', num: true, render: (r) => `${r.diversion_fraction} = ${pct(r.diversion_rate)}` },
                { key: 'ok', label: 'Victim probes OK', num: true, render: (r) => r.victim_probe_successes },
              ]}
              rows={res.rows} />
          </Card>
          <Card title="Hypotheses checked against this run">
            <ul className="plain">
              {res.hypotheses.map((h, i) => (
                <li key={i}>
                  {h.supported === null ? <Tag>not testable</Tag> : h.supported ? <Tag tone="ok">supported</Tag> : <Tag tone="bad">not supported</Tag>} {h.hypothesis}{' '}
                  <span className="muted">({h.evidence})</span>
                </li>
              ))}
            </ul>
            <ul className="small">{res.findings.map((f, i) => <li key={i}>{f}</li>)}</ul>
          </Card>
        </>
      )}

      <Card title="Optional extension: sub-prefix hijack and ROA maximum length" note="separate from the core scenarios">
        <p className="small">The attacker announces <code>10.10.0.0/25</code> with the forged origin. The default ROA (max length 24) is never changed; the loose ROA (max length 25) exists only inside this experiment.</p>
        <div className="btn-row">
          <Button kind="ghost" onClick={() => sub.run()} disabled={sub.loading}>Run sub-prefix experiment</Button>
          {sub.loading && <Spinner />}
        </div>
        <ErrorBox error={sub.error} />
        {sub.data && (
          <Table
            columns={[
              { key: 'roa', label: 'ROA' },
              { key: 'defence', label: 'Defence' },
              { key: 'st', label: 'RPKI state of /25', render: (r) => <StateTag state={r.rpki_state} /> },
              { key: 'd', label: 'Diverted', render: (r) => `${r.diversion_fraction} = ${pct(r.diversion_rate)}` },
            ]}
            rows={sub.data.result.rows} />
        )}
      </Card>
    </Page>
  )
}
