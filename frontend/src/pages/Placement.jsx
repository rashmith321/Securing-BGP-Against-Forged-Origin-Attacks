import { useCallback, useMemo, useState } from 'react'
import { SetBars } from '../components/Charts'
import { Button, Card, Download, ErrorBox, Page, SimBadge, Spinner, Table, Tag } from '../components/ui'
import { useAsync } from '../hooks/useAsync'
import { api } from '../services/api'
import { COLOR, EXP_LABEL, pct, pp, rname, setLabel } from '../utils/format'
import { DEFAULT_POLICY, PolicyPicker, policyBody } from './RovAdoption'

export default function Placement({ topology }) {
  const measured = topology?.measured ?? []
  const [policy, setPolicy] = useState({ ...DEFAULT_POLICY })
  const run = useAsync(useCallback((b) => api.placement(b), []))
  const res = run.data?.result
  const [exp, setExp] = useState('type0_rov')
  const [k, setK] = useState(2)
  const sets = useMemo(() => (res ? res.observations.filter((o) => o.exp === exp && o.k === k).map((o) => ({ adopters: o.adopters, D: o.D, p: o.p, diverted: o.diverted_asns })).sort((a, b) => a.D - b.D || a.p - b.p) : []), [res, exp, k])
  const pk = res?.results[exp]?.per_k.find((x) => x.k === k)

  return (
    <Page title="Placement analysis" lead="At the same number of adopters, does it matter who adopts? Every adopter set of size k is compared, with special attention to the attacker's two providers r400 and r600."
      actions={<SimBadge />}>
      <Card title="Setup">
        <PolicyPicker measured={measured} policy={policy} setPolicy={setPolicy} allowOrder={false} />
        <div className="btn-row">
          <Button onClick={() => run.run({ policy: policyBody(policy) })} disabled={run.loading}>Run placement study</Button>
          {run.data?.run_id && <>
            <Download href={api.csvUrl(run.data.run_id, 'placement.csv')}>placement.csv</Download>
            <Download href={api.csvUrl(run.data.run_id, 'placement_effect.csv')}>E(k) table</Download>
            <Download href={api.csvUrl(run.data.run_id, 'vulnerability.csv')}>vulnerability.csv</Download>
          </>}
          {run.loading && <Spinner />}
        </div>
      </Card>
      <ErrorBox error={run.error} />
      {res && (
        <>
          <Card title="How to read E(k)">
            <p className="small"><code>p</code> = how many of the attacker's providers ({res.attacker_providers.map(rname).join(', ')}) are among the k adopters. <code>D(k,p)</code> = mean diversion over the sets with that k and p.</p>
            <p className="small"><b>E(k) = 100 × (D(k, p_min) − D(k, p_max))</b>: the percentage points of protection gained by placing adopters at the attacker's providers. <b>Positive means the better placement reduces diversion.</b> We also report <b>E_set(k) = 100 × (D of worst set − D of best set)</b>, always ≥ 0, which answers the same question without grouping by p.</p>
          </Card>
          <Card title="Which sets, at which k">
            <div className="row-controls">
              <label className="inline">Experiment <select value={exp} onChange={(e) => setExp(e.target.value)}>{Object.keys(res.results).map((e) => <option key={e} value={e}>{EXP_LABEL[e]}</option>)}</select></label>
              <label className="inline">k <select value={k} onChange={(e) => setK(Number(e.target.value))}>{[1, 2, 3, 4, 5].map((x) => <option key={x}>{x}</option>)}</select></label>
            </div>
            {pk && (
              <p className="small">
                {pk.n_sets} sets evaluated. Best: <b>{setLabel(pk.best_set)}</b> (D = {pct(pk.best_D)}). Worst: <b>{setLabel(pk.worst_set)}</b> (D = {pct(pk.worst_D)}).{' '}
                E(k) = <b>{pk.E_provider_pp == null ? 'n/a' : pp(pk.E_provider_pp)}</b>, E_set(k) = <b>{pk.E_set_pp == null ? 'n/a' : pp(pk.E_set_pp)}</b>.
              </p>
            )}
            <SetBars sets={sets} color={COLOR[exp]} />
          </Card>
          <div className="grid two">
            <Card title="D(k, p) for the selected experiment">
              <Table dense
                columns={[
                  { key: 'p', label: 'p', num: true },
                  { key: 'runs', label: 'Sets', num: true },
                  { key: 'D_mean', label: 'D mean', num: true, render: (r) => pct(r.D_mean) },
                  { key: 'D_min', label: 'min', num: true, render: (r) => pct(r.D_min) },
                  { key: 'D_max', label: 'max', num: true, render: (r) => pct(r.D_max) },
                ]}
                rows={pk?.groups || []} />
            </Card>
            <Card title="E(k) by adoption count">
              <Table dense
                columns={[
                  { key: 'k', label: 'k', num: true },
                  { key: 'e', label: 'E(k)', num: true, render: (r) => (r.E_provider_pp == null ? 'n/a' : pp(r.E_provider_pp)) },
                  { key: 'es', label: 'E_set(k)', num: true, render: (r) => (r.E_set_pp == null ? 'n/a' : pp(r.E_set_pp)) },
                  { key: 'b', label: 'Best set', render: (r) => setLabel(r.best_set) },
                ]}
                rows={res.results[exp].per_k} />
            </Card>
          </div>
          <Card title="What the data says" note="generated from the results above">
            {res.notes.length ? <ul className="small">{res.notes.map((n, i) => <li key={i}>{n}</li>)}</ul> : <p className="muted">All placements at equal k gave the same diversion.</p>}
            <p className="small muted">Whether protecting attacker providers is best is measured, not assumed: compare the best set with the providers in the table above.</p>
          </Card>
          <Card title="Vulnerability report: ASes diverted with no defence at all">
            <Table
              columns={[
                { key: 'router', label: 'AS', render: (v) => <>{v.router} (AS{v.client}) {v.attacker_provider && <Tag tone="bad">attacker provider</Tag>}</> },
                { key: 't0', label: 'Type-0', render: (v) => (v.type0_rov ? <Tag tone="bad">diverted</Tag> : <Tag tone="ok">safe</Tag>) },
                { key: 't0p', label: 'Type-0 best path', render: (v) => <code>{v.type0_rov_best_path}</code> },
                { key: 't1', label: 'Type-1', render: (v) => (v.type1_rov ? <Tag tone="bad">diverted</Tag> : <Tag tone="ok">safe</Tag>) },
                { key: 't1p', label: 'Type-1 best path', render: (v) => <code>{v.type1_rov_best_path}</code> },
                { key: 'w', label: 'Why (Type-1)', render: (v) => v.type1_rov_why },
              ]}
              rows={res.vulnerability} />
          </Card>
        </>
      )}
    </Page>
  )
}
