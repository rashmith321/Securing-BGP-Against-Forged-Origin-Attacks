export const rname = (asn) => `r${asn - 65000}`
export const asname = (asn) => `AS${asn}`
export const pct = (x, d = 1) => (x == null ? '-' : `${(x * 100).toFixed(d)}%`)
export const pp = (x, d = 1) => (x == null ? '-' : `${x.toFixed(d)} pp`)
export const setLabel = (xs) => (xs && xs.length ? xs.map(rname).join(' ') : 'none')
export const pathStr = (p) => (p && p.length ? p.join(' ') : '(local)')

export const ATTACK_LABEL = {
  none: 'No attack',
  type0: 'Type-0 origin hijack',
  type1: 'Type-1 forged-origin hijack',
  subprefix: 'Sub-prefix (forged origin, /25)',
}

export const EXP_LABEL = {
  type0_rov: 'Type-0 vs ROV adoption',
  type1_rov: 'Type-1 vs ROV adoption',
  type1_pathend: 'Type-1 vs path-end adoption (ROV everywhere)',
}

export const COLOR = {
  victim: '#0E7C66',
  attacker: '#B42318',
  rov: '#2457A6',
  pe: '#6E44B2',
  warn: '#A65F00',
  ink: '#17212B',
  muted: '#5B6773',
  type0_rov: '#2457A6',
  type1_rov: '#B42318',
  type1_pathend: '#6E44B2',
}
