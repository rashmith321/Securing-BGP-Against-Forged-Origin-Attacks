import { useCallback, useMemo, useState } from 'react'
import { CurveChart } from '../components/Charts'
import { AsChips } from '../components/DefenseControls'
import { Button, Card, Download, ErrorBox, Page, SimBadge, Spinner, Table } from '../components/ui'
import { useAsync } from '../hooks/useAsync'
import { api } from '../services/api'
import { COLOR, EXP_LABEL, pct, pp, setLabel } from '../utils/format'

const ORDERS = {
  providers_first: { label: 'Attacker providers first: r400, r600, r200, r500, r100, r300', order: [65400, 65600, 65200, 65500, 65100, 65300] },
  top_down: { label: 'Top-down: r100, r200, r300, r400, r500, r600', order: [65100, 65200, 65300, 65400, 65500, 65600] },
  providers_last: { label: 'Attacker providers last: r100, r200, r300, r500, r400, r600', order: [65100, 65200, 65300, 65500, 65400, 65600] },
}

export function PolicyPicker({ measured, policy, setPolicy, allowOrder = true, attackerProviders }) {
  return (
    <div className="policy">
      <fieldset className="radio-group">
        <legend>Which adopter sets are evaluated at each level k?</legend>
        <label className={policy.mode === 'all' ? 'on' : ''}><input type="radio" checked={policy.mode === 'all'} onChange={() => setPolicy({ ...policy, mode: 'all' })} />All combinations (exhaustive, recommended)</label>
        <label className={policy.mode === 'sample' ? 'on' : ''}><input type="radio" checked={policy.mode === 'sample'} onChange={() => setPolicy({ ...policy, mode: 'sample' })} />Seeded random sample</label>
        {allowOrder && <label className={policy.mode === 'order' ? 'on' : ''}><input type="radio" checked={policy.mode === 'order'} onChange={() => setPolicy({ ...policy, mode: 'order', order: policy.order || ORDERS.providers_first.order })} />Predefined adoption order</label>}
        {allowOrder && <label className={policy.mode === 'explicit' ? 'on' : ''}><input type="radio" checked={policy.mode === 'explicit'} onChange={() => setPolicy({ ...policy, mode: 'explicit' })} />One specific set</label>}
      </fieldset>
      {policy.mode === 'sample' && (
        <div className="row-controls">
          <label className="inline">Sets per level <input type="number" min="1" max="20" value={policy.max_sets} onChange={(e) => setPolicy({ ...policy, max_sets: Number(e.target.value) })} /></label>
          <label className="inline">Seed <input type="number" value={policy.seed} onChange={(e) => setPolicy({ ...policy, seed: Number(e.target.value) })} /></label>
        </div>
      )}
      {policy.mode === 'order' && (
        <label className="inline">Order{' '}
          <select value={JSON.stringify(policy.order)} onChange={(e) => setPolicy({ ...policy, order: JSON.parse(e.target.value) })}>
            {Object.entries(ORDERS).map(([k, o]) => <option key={k} value={JSON.stringify(o.order)}>{o.label}</option>)}
          </select>
        </label>
      )}
      {policy.mode === 'explicit' && (
        <AsChips measured={measured} value={policy.explicit || []} onChange={(v) => setPolicy({ ...policy, explicit: v })} color={COLOR.rov} label="Adopting ASes" attackerProviders={attackerProviders} />
      )}
    </div>
  )
}

export function policyBody(p) {
  const body = { mode: p.mode, seed: p.seed }
  if (p.mode === 'sample') body.max_sets = p.max_sets
  if (p.mode === 'order') body.order = p.order
  if (p.mode === 'explicit') body.explicit = p.explicit || []
  return body
}

export const DEFAULT_POLICY = { mode: 'all', max_sets: 3, seed: 1, order: ORDERS.providers_first.order, explicit: [] }

export default function RovAdoption({ topology }) {
  const measured = topology?.measured ?? []
  const [policy, setPolicy] = useState(DEFAULT_POLICY)
  const run = useAsync(useCallback((b) => api.rovAdoption(b), []))
  const res = run.data?.result
  const [exp, setExp] = useState('type0_rov')
  const [k, setK] = useState(2)
  const obs = useMemo(() => (res ? res.observations.filter((o) => o.exp === exp && o.k === k) : []), [res, exp, k])

  const cols = [
    { key: 'k', label: 'k', num: true },
    { key: 'a', label: 'Adoption', num: true, render: (r) => `${r.adoption_pct}%` },
    { key: 'runs', label: 'Sets', num: true },
    { key: 'D_mean', label: 'D mean', num: true, render: (r) => pct(r.D_mean) },
    { key: 'D_sd', label: 'D sd', num: true, render: (r) => pct(r.D_sd) },
    { key: 'D_min', label: 'min', num: true, render: (r) => pct(r.D_min) },
    { key: 'D_max', label: 'max', num: true, render: (r) => pct(r.D_max) },
    { key: 'pr', label: 'Protection', num: true, render: (r) => pp(r.protection_pp) },
    { key: 'rr', label: 'Relative reduction', num: true, render: (r) => (r.relative_reduction == null ? 'n/a' : pct(r.relative_reduction)) },
    { key: 'mg', label: 'Marginal gain', num: true, render: (r) => pp(r.marginal_gain_pp) },
    { key: 'U', label: 'Unreachable', num: true, render: (r) => pct(r.U_mean) },
  ]

  return (
    <Page title="ROV adoption experiment" lead="Turns ROV on at 0 to 6 of the measured ASes and re-runs both attacks each time. Every adopter set is evaluated unless you choose otherwise, so the curve is not tied to one lucky placement."
      actions={<SimBadge />}>
      <Card title="Setup">
        <PolicyPicker measured={measured} policy={policy} setPolicy={setPolicy} attackerProviders={topology?.attacker_providers} />
        <div className="btn-row">
          <Button onClick={() => run.run({ policy: policyBody(policy) })} disabled={run.loading}>Run adoption sweep</Button>
          {run.data?.run_id && <><Download href={api.csvUrl(run.data.run_id, 'summary.csv')}>summary.csv</Download><Download href={api.csvUrl(run.data.run_id, 'results.csv')}>results.csv</Download></>}
          {run.loading && <Spinner />}
        </div>
      </Card>
      <ErrorBox error={run.error} />
      {res && (
        <>
          <Card title="Diversion rate versus ROV adoption" note={`${res.set_mode} · simulated`}>
            <CurveChart curves={res.curves} />
            <p className="small muted">Line = mean D over the evaluated adopter sets; shaded band = min to max over those sets. {res.aggregation_text} With 6 measured ASes, D moves in steps of 16.7 percentage points.</p>
            <ul className="small">{res.findings.map((f, i) => <li key={i}>{f}</li>)}</ul>
          </Card>
          {Object.entries(res.curves).map(([e, c]) => (
            <Card key={e} title={EXP_LABEL[e]} note="measured values from the simulation">
              <Table dense columns={cols} rows={c} />
            </Card>
          ))}
          <Card title="Raw observations" note={`${res.observations.length} saved runs`}>
            <div className="row-controls">
              <label className="inline">Experiment <select value={exp} onChange={(e) => setExp(e.target.value)}>{Object.keys(res.curves).map((e) => <option key={e} value={e}>{EXP_LABEL[e]}</option>)}</select></label>
              <label className="inline">k <select value={k} onChange={(e) => setK(Number(e.target.value))}>{[0, 1, 2, 3, 4, 5, 6].map((x) => <option key={x}>{x}</option>)}</select></label>
            </div>
            <Table dense empty="No sets at this k under the chosen policy."
              columns={[
                { key: 's', label: 'ROV adopters', render: (o) => setLabel(o.rov_set) },
                { key: 'D', label: 'D', num: true, render: (o) => `${o.diverted_count}/6 = ${pct(o.D)}` },
                { key: 'dv', label: 'Diverted ASes', render: (o) => setLabel(o.diverted_asns) },
                { key: 'u', label: 'Unreachable', num: true, render: (o) => o.unreachable_count },
                { key: 'acc', label: 'Accepting attack route', num: true, render: (o) => o.accepting_attack_route },
              ]}
              rows={obs} />
          </Card>
        </>
      )}
    </Page>
  )
}
