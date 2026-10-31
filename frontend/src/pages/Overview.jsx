import { useState } from 'react'
import ASDetail from '../components/ASDetail'
import TopologyGraph from '../components/TopologyGraph'
import { BaselineCard } from '../components/RoutePanels'
import { Card, ErrorBox, Page, SimBadge, Spinner, Stat } from '../components/ui'
import { ATTACK_LABEL, pct } from '../utils/format'

export default function Overview({ topology, sim, cfg, onGoto }) {
  const [sel, setSel] = useState(null)
  const result = sim.data?.result
  const m = result?.metrics
  const mr = result?.malicious_route
  const n = topology?.measured.length ?? 6

  let outcome = null
  if (result) {
    outcome = (
      <>
        <b>{ATTACK_LABEL[cfg.attack]}</b> with ROV at {cfg.rov.length}/{n} and path-end validation at {cfg.pe.length}/{n} measured ASes:{' '}
        <b>{m.diversion_fraction}</b> ({pct(m.diversion_rate)}) of probes end up at the attacker, and {m.victim_probe_successes} reach the legitimate victim.
        {mr && (
          <> The attacker's announcement <code>{mr.advertised_path_str}</code> is <b>RPKI {mr.rpki_state}</b>
            {mr.rpki_state === 'Valid' ? ' - origin validation cannot tell it apart from the real route.' : ' - ROV-enabled ASes reject it.'}</>
        )}
        {m.unreachable_count > 0 && <> {m.unreachable_count} AS(es) are left with no route at all.</>}
      </>
    )
  }

  return (
    <Page
      title="Securing BGP against forged-origin attacks"
      lead="ROV checks who a route says it comes from, not how it got there. This simulator measures how many ASes an attacker can still pull traffic from as ROV and path-end validation spread through an eight-AS network.">
      <div className="stat-strip">
        <Stat label="ASes" value="8" sub="6 measured" />
        <Stat label="Victim" value="AS65700" sub="r700 · 10.10.0.0/24" tone="victim" />
        <Stat label="Attacker" value="AS65800" sub="r800 · providers r400, r600" tone="attacker" />
        <Stat label="Scenario" value={cfg.attack === 'type1' ? 'Type-1' : cfg.attack === 'type0' ? 'Type-0' : cfg.attack === 'none' ? 'None' : 'Sub-prefix'} sub="set on Attack simulator" />
        <Stat label="ROV adoption" value={`${Math.round((100 * cfg.rov.length) / n)}%`} sub={`${cfg.rov.length} of ${n}`} />
        <Stat label="Path-end adoption" value={`${Math.round((100 * cfg.pe.length) / n)}%`} sub={`${cfg.pe.length} of ${n}`} />
        <Stat label="Diversion rate D" value={m ? pct(m.diversion_rate) : '-'} sub={m ? m.diversion_fraction : ''} tone={m && m.diverted_count ? 'attacker' : 'victim'} />
        <Stat label="Baseline" value={result ? (result.baseline.healthy ? 'healthy' : 'unhealthy') : '-'} sub={result ? `${result.baseline.victims_reached}/6 reach victim` : ''} tone={result && !result.baseline.healthy ? 'attacker' : ''} />
      </div>

      <ErrorBox error={sim.error} />
      <div className="grid two">
        <Card title="Reference topology" note={sim.loading ? undefined : 'current scenario'}>
          {sim.loading && <Spinner />}
          <TopologyGraph topology={topology} result={result} selected={sel} onSelect={setSel} />
        </Card>
        <div className="stack">
          <Card title="What is happening" note={<SimBadge />}>
            {outcome ? <p>{outcome}</p> : <p className="muted">Running the default scenario…</p>}
            <p className="small muted">Change the scenario on the <button className="link" onClick={() => onGoto('simulator')}>Attack simulator</button>; the numbers here always come from the backend engine.</p>
          </Card>
          <ASDetail asn={sel} topology={topology} result={result} />
        </div>
      </div>
      {result && <BaselineCard baseline={result.baseline} />}
    </Page>
  )
}
