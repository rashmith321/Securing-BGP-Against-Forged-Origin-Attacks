import { Fragment, useCallback, useEffect, useState } from 'react'
import { Button, Card, Download, ErrorBox, Page, SimBadge, Spinner, Table, Tag } from '../components/ui'
import { useAsync } from '../hooks/useAsync'
import { api } from '../services/api'
import { DEFAULT_POLICY, PolicyPicker, policyBody } from './RovAdoption'

const ASSUMPTIONS = [
  'Topology: the eight-AS reference topology from the implementation guide (8 provider→customer links); r400 and r600 are the attacker\'s providers.',
  'Routing policy: Gao-Rexford style. Customer routes are preferred (local-pref 200) over peer (150) and provider (100) routes; peer/provider routes are exported only to customers.',
  'Route ranking: local origin, then local-pref, then shortest AS path, then oldest route, then lowest neighbour router-id. Shortest path does not win automatically.',
  'The attack starts after the baseline has converged, so the legitimate route is older than the hijack route (this decides ties, e.g. at r100 for Type-0).',
  'ROV policy: reject RPKI Invalid, accept Valid and NotFound. Default ROA: 10.10.0.0/24, origin AS65700, max length 24.',
  'Path-end rule: the AS before the claimed origin must be in the origin\'s registry (AS65700 → AS65300).',
  'Probes: one per measured AS to 10.10.0.1:8080; the endpoint reached is the AS where hop-by-hop longest-prefix forwarding terminates.',
]
const LIMITS = [
  'This is a simulation, not a real Internet or production BGP testbed. FRR, Routinator, RTR sessions and real traffic were not used.',
  'The topology has eight ASes, six of them measured, so D changes in steps of 16.7 percentage points.',
  'Outcomes depend on the configured topology, policies, tie-breaking and defence adoption; do not generalise to the Internet without more experiments.',
  'The path-end defence is a simplified ASPA-inspired model, not a standards-compliant ASPA implementation.',
  'Real Mininet + FRR + Routinator validation is future integration work.',
]

export default function Results() {
  const [policy, setPolicy] = useState({ ...DEFAULT_POLICY })
  const list = useAsync(useCallback(() => api.listRuns(), []))
  const suite = useAsync(useCallback((b) => api.fullSuite(b), []))
  const detail = useAsync(useCallback((id) => api.getRun(id), []))
  const tables = useAsync(useCallback((id) => api.tables(id), []))
  const [selected, setSelected] = useState(null)

  useEffect(() => { list.run() }, [])           // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { if (suite.data) list.run() }, [suite.data])  // eslint-disable-line react-hooks/exhaustive-deps

  const choose = (id) => { setSelected(id); detail.run(id); tables.run(id) }
  const sres = suite.data
  const rec = detail.data

  return (
    <Page title="Results and export" lead="Every run is saved and never overwritten. Download CSV or JSON for any run, or run the whole suite to produce the full set of output files and figures."
      actions={<SimBadge />}>
      <Card title="Run everything" note="five experiments + output bundle">
        <PolicyPicker measured={[]} policy={policy} setPolicy={setPolicy} allowOrder={false} />
        <div className="btn-row">
          <Button onClick={() => suite.run({ policy: policyBody(policy) })} disabled={suite.loading}>Run full suite</Button>
          {suite.loading && <Spinner label="Running all experiments" />}
        </div>
        <ErrorBox error={suite.error} />
        {sres && (
          <>
            <h3>Output files</h3>
            <p className="small">Bundle <code>{sres.suite_run_id}</code></p>
            <ul className="files">
              {sres.files.map((f) => (
                <li key={f}><a href={api.fileUrl(sres.suite_run_id, f)} download>{f}</a></li>
              ))}
            </ul>
            <div className="figs">
              <figure><img src={api.fileUrl(sres.suite_run_id, 'gap1_adoption_curves.png')} alt="Adoption curves generated from saved results" /><figcaption>gap1_adoption_curves.png</figcaption></figure>
              <figure><img src={api.fileUrl(sres.suite_run_id, 'gap1_placement.png')} alt="Placement study generated from saved results" /><figcaption>gap1_placement.png</figcaption></figure>
            </div>
            <h3>Automatic summary</h3>
            <ul className="small">{sres.summary.bullets.map((b, i) => <li key={i}>{b}</li>)}</ul>
            <h3>Hypotheses</h3>
            <ul className="plain">
              {sres.summary.hypotheses.map((h, i) => (
                <li key={i}>{h.supported ? <Tag tone="ok">supported</Tag> : <Tag tone="bad">not supported</Tag>} {h.hypothesis} <span className="muted">({h.evidence})</span></li>
              ))}
            </ul>
            {sres.summary.flags.length > 0 && (
              <div className="alert warn"><strong>Flags</strong><ul>{sres.summary.flags.map((f, i) => <li key={i}>{f}</li>)}</ul></div>
            )}
          </>
        )}
      </Card>

      <div className="grid two">
        <Card title="Saved runs" note={list.data ? `${list.data.runs.length} runs` : undefined}>
          <ErrorBox error={list.error} />
          <Table dense empty="No runs saved yet. Run a simulation or experiment."
            columns={[
              { key: 'run_id', label: 'Run', render: (r) => <button className="link" onClick={() => choose(r.run_id)}>{r.run_id}</button> },
              { key: 'kind', label: 'Kind' },
              { key: 'created_at', label: 'Created (UTC)', render: (r) => r.created_at.replace('T', ' ').slice(0, 19) },
            ]}
            rows={list.data?.runs || []}
            rowClass={(r) => (r.run_id === selected ? 'row-sel' : '')} />
          <div className="btn-row"><Button kind="ghost" onClick={() => list.run()}>Refresh</Button></div>
        </Card>
        <Card title={selected ? `Run ${selected}` : 'Run details'}>
          {!selected && <p className="muted">Select a run to download its tables and see how it was produced.</p>}
          {selected && (
            <>
              <div className="btn-row">
                <Download href={api.jsonUrl(selected)}>JSON (config + results)</Download>
                {(tables.data?.tables || []).map((t) => <Download key={t} href={api.csvUrl(selected, t)}>{t}</Download>)}
              </div>
              {(tables.data?.files || []).length > 0 && (
                <ul className="files">{tables.data.files.map((f) => <li key={f}><a href={api.fileUrl(selected, f)} download>{f}</a></li>)}</ul>
              )}
              {rec && (
                <>
                  <h3>Reproducibility metadata</h3>
                  <dl className="kv">
                    {Object.entries(rec.metadata).map(([k, v]) => (<Fragment key={k}><dt>{k}</dt><dd>{String(v)}</dd></Fragment>))}
                  </dl>
                  <h3>Request</h3>
                  <pre className="code">{JSON.stringify(rec.request, null, 2)}</pre>
                </>
              )}
            </>
          )}
        </Card>
      </div>

      <div className="grid two">
        <Card title="Model assumptions"><ul className="small">{ASSUMPTIONS.map((a, i) => <li key={i}>{a}</li>)}</ul></Card>
        <Card title="Scope and limitations"><ul className="small">{LIMITS.map((a, i) => <li key={i}>{a}</li>)}</ul></Card>
      </div>
    </Page>
  )
}
