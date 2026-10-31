import { useState } from 'react'
import ASDetail from '../components/ASDetail'
import { PathEndChips, RovChips } from '../components/DefenseControls'
import { BaselineCard, MaliciousRoutePanel, ProbeTable, RejectedTable } from '../components/RoutePanels'
import TopologyGraph from '../components/TopologyGraph'
import { Button, Card, Download, ErrorBox, Page, SimBadge, Spinner, Stat } from '../components/ui'
import { ATTACK_LABEL, pct } from '../utils/format'

const ATTACKS = ['none', 'type0', 'type1', 'subprefix']

export default function Simulator({ topology, sim, cfg, setCfg, runSim, resetSim }) {
  const [sel, setSel] = useState(null)
  const measured = topology?.measured ?? []
  const result = sim.data?.result
  const m = result?.metrics
  const set = (patch) => setCfg({ ...cfg, ...patch })

  return (
    <Page title="Attack simulator" lead="Pick an attack and the defences each AS runs, then run it. Routes, validation states and probe outcomes are computed by the backend engine."
      actions={<SimBadge />}>
      <div className="grid two">
        <Card title="Scenario">
          <fieldset className="radio-group">
            <legend>Attack</legend>
            {ATTACKS.map((a) => (
              <label key={a} className={cfg.attack === a ? 'on' : ''}>
                <input type="radio" name="attack" checked={cfg.attack === a} onChange={() => set({ attack: a })} />
                {ATTACK_LABEL[a]}
              </label>
            ))}
          </fieldset>
          <RovChips measured={measured} value={cfg.rov} onChange={(v) => set({ rov: v })} attackerProviders={topology?.attacker_providers} />
          <PathEndChips measured={measured} value={cfg.pe} onChange={(v) => set({ pe: v })} attackerProviders={topology?.attacker_providers} />
          <div className="row-controls">
            <label className="inline">ROA maximum length{' '}
              <select value={cfg.roaMax} onChange={(e) => set({ roaMax: Number(e.target.value) })}>
                <option value={24}>/24 (default ROA)</option>
                <option value={25}>/25 (experimental loose ROA)</option>
              </select>
            </label>
            <label className="inline">
              <input type="checkbox" checked={cfg.requireHealthy} onChange={(e) => set({ requireHealthy: e.target.checked })} />
              Require a healthy baseline
            </label>
          </div>
          <div className="btn-row">
            <Button onClick={() => runSim(true)} disabled={sim.loading}>Run simulation</Button>
            <Button kind="ghost" onClick={resetSim}>Reset</Button>
            {sim.data?.run_id && <Download href={`/api/results/${sim.data.run_id}/csv`}>Download CSV</Download>}
            {sim.data?.run_id && <span className="muted small">saved as {sim.data.run_id}</span>}
          </div>
          {sim.loading && <Spinner />}
        </Card>
        <Card title="Topology and selected routes">
          <TopologyGraph topology={topology} result={result} selected={sel} onSelect={setSel} />
        </Card>
      </div>

      <ErrorBox error={sim.error} />

      {result && (
        <>
          <div className="stat-strip">
            <Stat label="Diversion rate D" value={pct(m.diversion_rate)} sub={m.diversion_fraction} tone={m.diverted_count ? 'attacker' : 'victim'} />
            <Stat label="Protected ASes" value={m.protected_count} sub="reach the victim" tone="victim" />
            <Stat label="Vulnerable ASes" value={m.vulnerable_count} sub="reach the attacker" tone={m.vulnerable_count ? 'attacker' : ''} />
            <Stat label="Victim probes OK" value={m.victim_probe_successes} sub="of 6" />
            <Stat label="Attacker-received" value={m.attacker_received_probes} sub="of 6" />
            <Stat label="Accept attack route" value={m.accepting_attack_route} sub="measured ASes, even if not best" />
          </div>
          <p className="muted small">{m.granularity_note} Results are simulated.</p>
          <div className="grid two">
            <MaliciousRoutePanel result={result} />
            <div className="stack">
              <ASDetail asn={sel} topology={topology} result={result} />
              <BaselineCard baseline={result.baseline} />
            </div>
          </div>
          <ProbeTable result={result} />
          <RejectedTable rows={result.rejected_routes} />
        </>
      )}
      {!result && !sim.loading && !sim.error && <Card><p className="muted">No result yet. Choose a scenario and press “Run simulation”.</p></Card>}
    </Page>
  )
}
