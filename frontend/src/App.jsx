import { useCallback, useEffect, useState } from 'react'
import { SimBadge } from './components/ui'
import { useAsync } from './hooks/useAsync'
import AttackComparison from './pages/AttackComparison'
import Overview from './pages/Overview'
import PathEnd from './pages/PathEnd'
import Placement from './pages/Placement'
import Results from './pages/Results'
import RovAdoption from './pages/RovAdoption'
import Simulator from './pages/Simulator'
import { api } from './services/api'

const NAV = [
  ['overview', 'Overview'],
  ['simulator', 'Attack simulator'],
  ['comparison', 'Type-0 vs Type-1'],
  ['rov', 'ROV adoption'],
  ['placement', 'Placement'],
  ['pathend', 'Path-end validation'],
  ['results', 'Results and export'],
]

const INITIAL = { attack: 'type1', rov: [65100, 65200, 65300, 65400, 65500, 65600], pe: [], roaMax: 24, requireHealthy: true }

export default function App() {
  const [page, setPage] = useState('overview')
  const [topology, setTopology] = useState(null)
  const [backend, setBackend] = useState({ ok: null, error: null })
  const [cfg, setCfg] = useState(INITIAL)
  const sim = useAsync(useCallback((body) => api.simulate(body), []))

  const body = useCallback((c, save) => ({
    attack: c.attack,
    rov_set: c.rov,
    path_end_set: c.pe,
    roas: c.roaMax === 24 ? undefined : [{ prefix: '10.10.0.0/24', origin: 65700, max_length: c.roaMax }],
    require_healthy_baseline: c.requireHealthy,
    save,
  }), [])

  useEffect(() => {
    api.health().then(() => setBackend({ ok: true })).catch((e) => setBackend({ ok: false, error: e }))
    api.topology().then(setTopology).catch(() => {})
    sim.run(body(INITIAL, false))        // default scenario so the overview is never empty
  }, [])                                  // eslint-disable-line react-hooks/exhaustive-deps

  const runSim = (save) => sim.run(body(cfg, save))
  const resetSim = () => { setCfg(INITIAL); sim.run(body(INITIAL, false)) }

  const view = {
    overview: <Overview topology={topology} sim={sim} cfg={cfg} onGoto={setPage} />,
    simulator: <Simulator topology={topology} sim={sim} cfg={cfg} setCfg={setCfg} runSim={runSim} resetSim={resetSim} />,
    comparison: <AttackComparison topology={topology} />,
    rov: <RovAdoption topology={topology} />,
    placement: <Placement topology={topology} />,
    pathend: <PathEnd topology={topology} />,
    results: <Results />,
  }[page]

  return (
    <div className="shell">
      <aside className="side">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true">⬡</span>
          <div>
            <div className="brand-name">Forged-origin lab</div>
            <div className="brand-sub">BGP · RPKI · ROV</div>
          </div>
        </div>
        <nav aria-label="Pages">
          {NAV.map(([id, label]) => (
            <button key={id} className={page === id ? 'active' : ''} onClick={() => setPage(id)} aria-current={page === id ? 'page' : undefined}>
              {label}
            </button>
          ))}
        </nav>
        <div className="side-foot">
          <SimBadge />
          <p>Results come from a simulation engine, not from FRR, Routinator or real BGP sessions.</p>
          <p className={backend.ok === false ? 'bad' : 'ok'}>{backend.ok === null ? 'Checking backend…' : backend.ok ? 'Backend connected' : 'Backend not reachable'}</p>
        </div>
      </aside>
      <main>
        {backend.ok === false && (
          <div className="alert danger" role="alert">
            <strong>The backend is not running.</strong> From <code>backend/</code> run <code>uvicorn app.main:app --port 8000</code>, then reload.
          </div>
        )}
        {view}
      </main>
    </div>
  )
}
