import { useCallback, useMemo, useState } from 'react'
import { CurveChart } from '../components/Charts'
import { RejectedTable } from '../components/RoutePanels'
import { Button, Card, Download, ErrorBox, Page, SimBadge, Spinner, Table, Tag } from '../components/ui'
import { useAsync } from '../hooks/useAsync'
import { api } from '../services/api'
import { COLOR, pct, pp } from '../utils/format'
import { DEFAULT_POLICY, PolicyPicker, policyBody } from './RovAdoption'

export default function PathEnd({ topology }) {
  const measured = topology?.measured ?? []
  const [policy, setPolicy] = useState({ ...DEFAULT_POLICY })
  const run = useAsync(useCallback((b) => api.pathEnd(b), []))
  const res = run.data?.result
  const [m, setM] = useState(6)
  const rej = useMemo(() => (res ? res.rejected_routes.filter((r) => r.m === m) : []), [res, m])
  const reg = topology?.path_end_registry || {}

  return (
    <Page title="Path-end validation" lead="ROV is on at every measured AS. Path-end validation is then added at 0 to 6 of them. It rejects a route when the AS right before the claimed origin is not one the origin has authorised."
      actions={<SimBadge />}>
      <Card title="The rule in this model" note="simplified, ASPA-inspired">
        <p className="small">AS65700's registered upstream: {(reg['65700'] || []).map((a) => `AS${a}`).join(', ') || '…'}. A route ending in 65700 passes only if it comes straight from 65700 or the AS before 65700 is in that list. The attacker's providers r400 and r600 are <b>not</b> accepted as proof that AS65800 is an upstream of the victim.</p>
        <p className="small muted">This is an educational model, not a standards-compliant ASPA implementation.</p>
      </Card>
      <Card title="Setup">
        <PolicyPicker measured={measured} policy={policy} setPolicy={setPolicy} attackerProviders={topology?.attacker_providers} />
        <div className="btn-row">
          <Button onClick={() => run.run({ policy: policyBody(policy) })} disabled={run.loading}>Run path-end sweep</Button>
          {run.data?.run_id && <>
            <Download href={api.csvUrl(run.data.run_id, 'path_end_results.csv')}>path_end_results.csv</Download>
            <Download href={api.csvUrl(run.data.run_id, 'path_end_rejections.csv')}>rejections.csv</Download>
          </>}
          {run.loading && <Spinner />}
        </div>
      </Card>
      <ErrorBox error={run.error} />
      {res && (
        <>
          <Card title="ROV only versus ROV plus path-end" note="Type-1 attack · simulated">
            <CurveChart curves={{ type1_pathend: res.curve.map((c) => c) }}
              xLabel="Number of ASes also running path-end validation, m (ROV at all 6)"
              extraLines={[{ key: 'rovonly', name: `ROV only (m = 0): ${pct(res.rov_only?.D_mean)}`, value: +(100 * (res.rov_only?.D_mean ?? 0)).toFixed(2), color: COLOR.type1_rov }]} />
            <p className="small">
              Residual diversion at full adoption (m = 6): <b>{pct(res.full_adoption?.D_mean)}</b>. {res.hypothesis && <>{res.hypothesis.supported ? <Tag tone="ok">supported</Tag> : <Tag tone="bad">not supported</Tag>} {res.hypothesis.hypothesis} <span className="muted">({res.hypothesis.evidence})</span></>}
            </p>
            <ul className="small">{res.residual_notes.map((n, i) => <li key={i}>{n}</li>)}</ul>
          </Card>
          <Card title="Measured values">
            <Table dense
              columns={[
                { key: 'k', label: 'm', num: true },
                { key: 'runs', label: 'Sets', num: true },
                { key: 'D_mean', label: 'D mean', num: true, render: (r) => pct(r.D_mean) },
                { key: 'D_sd', label: 'D sd', num: true, render: (r) => pct(r.D_sd) },
                { key: 'D_min', label: 'min', num: true, render: (r) => pct(r.D_min) },
                { key: 'D_max', label: 'max', num: true, render: (r) => pct(r.D_max) },
                { key: 'pr', label: 'Protection vs ROV only', num: true, render: (r) => pp(r.protection_pp) },
                { key: 'mg', label: 'Marginal gain', num: true, render: (r) => pp(r.marginal_gain_pp) },
              ]}
              rows={res.curve} />
          </Card>
          <div className="row-controls">
            <label className="inline">Show rejected routes for m = <select value={m} onChange={(e) => setM(Number(e.target.value))}>{[0, 1, 2, 3, 4, 5, 6].map((x) => <option key={x}>{x}</option>)}</select></label>
            <span className="muted small">{rej.length} rejection rows across all evaluated adopter sets with m = {m}</span>
          </div>
          <RejectedTable rows={rej.slice(0, 200)} title={`Rejected routes at m = ${m}`} />
        </>
      )}
    </Page>
  )
}
