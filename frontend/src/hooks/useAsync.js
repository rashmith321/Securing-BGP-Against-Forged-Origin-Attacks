import { useCallback, useState } from 'react'

// Tiny request-state hook: idle | loading | success | error, keeps the last good data.
export function useAsync(fn) {
  const [state, setState] = useState({ status: 'idle', data: null, error: null })
  const run = useCallback(
    async (...args) => {
      setState((s) => ({ ...s, status: 'loading', error: null }))
      try {
        const data = await fn(...args)
        setState({ status: 'success', data, error: null })
        return data
      } catch (error) {
        setState((s) => ({ status: 'error', data: s.data, error }))
        return null
      }
    },
    [fn],
  )
  const reset = useCallback(() => setState({ status: 'idle', data: null, error: null }), [])
  return { ...state, loading: state.status === 'loading', run, reset }
}
