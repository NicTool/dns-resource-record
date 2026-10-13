// Failures that are the other tool's limitation or bug, not ours. A known
// failure is reported but does not fail the run. `types` and `when` narrow an entry.
export const KNOWN = [
  {
    stages: ['knot-parse', 'knot-serve'],
    types: ['HIP', 'NXT', 'SIG', 'WKS'],
    reason: 'Knot does not implement this type',
  },
  {
    stages: ['coredns-parse', 'coredns-serve'],
    types: ['WKS', 'NSEC3', 'NSEC3PARAM'],
    reason: 'CoreDNS (miekg/dns) does not implement this type',
  },
  { stages: ['coredns-serve'], types: ['NXT'], reason: 'CoreDNS encodes the NXT bit map in the NSEC format' },
  { stages: ['ldns-parse'], types: ['NXT'], reason: 'ldns does not implement NXT' },
  {
    stages: ['ldns-parse', 'nsd-parse'],
    types: ['WKS'],
    when: (c) => !c.rr.get('bit map'),
    reason: 'ldns rejects, and NSD crashes on, a WKS record with no services',
  },
  { stages: ['nsd-serve'], types: ['APL'], reason: 'NSD mis-encodes APL prefixes' },
  {
    stages: ['bind-serve', 'knot-serve', 'nsd-serve', 'pdns-serve', 'maradns-serve'],
    types: ['NSEC3'],
    reason: 'NSEC3 is served only in denial-of-existence answers, or dig rejects a non-hash owner',
  },
  { stages: ['maradns-export'], types: ['DNAME'], reason: 'MaraDNS does not support DNAME' },
  {
    stages: ['pdns-parse', 'pdns-serve'],
    types: ['HIP', 'NXT', 'SIG', 'WKS'],
    reason: 'PowerDNS does not implement this type',
  },
  {
    stages: ['pdns-parse', 'pdns-serve'],
    types: ['CERT'],
    reason: 'PowerDNS rejects certificate type mnemonics (RFC 4398 §2.2)',
  },
  {
    stages: ['pdns-parse', 'pdns-serve'],
    types: ['IPSECKEY'],
    when: (c) => c.rr.get('gateway type') === 0,
    reason: 'PowerDNS rejects the "." gateway that RFC 4025 §3.3 requires for gateway type 0',
  },
  {
    stages: ['pdns-serve'],
    types: ['RRSIG'],
    reason: 'PowerDNS answers RRSIG queries only for presigned zones',
  },
  {
    stages: ['maradns-serve'],
    when: (c) => c.rr.get('ttl') > 63072000,
    reason: 'MaraDNS caps TTLs at two years (63072000)',
  },
  {
    stages: ['pdns-parse', 'pdns-serve'],
    types: ['CAA'],
    reason: 'PowerDNS splits CAA rdata on spaces only, so a tab joins the value to the tag',
  },
]

export function knownReason(stage, c) {
  return KNOWN.find(
    (k) =>
      k.stages.includes(stage) && (!k.types || k.types.includes(c?.type)) && (!k.when || (c && k.when(c))),
  )?.reason
}
