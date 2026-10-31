// All numbers shown in the UI come from these backend responses. Nothing is recomputed in React.
const BASE = import.meta.env.VITE_API_BASE || ''

export class ApiError extends Error {
  constructor(status, detail) {
    super(typeof detail === 'string' ? detail : detail?.message || `Request failed (${status})`)
    this.status = status
    this.detail = detail
  }
}

async function request(path, options = {}) {
  let res
  try {
    res = await fetch(`${BASE}/api${path}`, {
      headers: { 'Content-Type': 'application/json' },
      ...options,
    })
  } catch {
    throw new ApiError(0, 'Cannot reach the backend. Start it with: uvicorn app.main:app --port 8000 (from backend/).')
  }
  const text = await res.text()
  let body
  try { body = text ? JSON.parse(text) : null } catch { body = text }
  if (!res.ok) {
    let detail = body?.detail ?? body
    if (Array.isArray(detail)) detail = detail.map((d) => `${(d.loc || []).slice(1).join('.')}: ${d.msg}`).join('; ')
    throw new ApiError(res.status, detail)
  }
  return body
}

const post = (path, body) => request(path, { method: 'POST', body: JSON.stringify(body ?? {}) })

export const api = {
  health: () => request('/health'),
  topology: () => request('/topology'),
  config: () => request('/config'),
  simulate: (body) => post('/simulate', body),
  baseline: (body) => post('/baseline', body),
  attackComparison: (body) => post('/experiments/attack-comparison', body),
  rovAdoption: (body) => post('/experiments/rov-adoption', body),
  placement: (body) => post('/experiments/placement', body),
  pathEnd: (body) => post('/experiments/path-end', body),
  subprefix: () => post('/experiments/subprefix', {}),
  fullSuite: (body) => post('/experiments/full-suite', body),
  listRuns: () => request('/results'),
  getRun: (id) => request(`/results/${encodeURIComponent(id)}`),
  tables: (id) => request(`/results/${encodeURIComponent(id)}/tables`),
  csvUrl: (id, table) => `${BASE}/api/results/${encodeURIComponent(id)}/csv${table ? `?table=${encodeURIComponent(table)}` : ''}`,
  jsonUrl: (id) => `${BASE}/api/results/${encodeURIComponent(id)}/json`,
  fileUrl: (id, name) => `${BASE}/api/results/${encodeURIComponent(id)}/files/${encodeURIComponent(name)}`,
}
