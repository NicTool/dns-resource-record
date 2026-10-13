import * as RR from '../index.js'
import { hex, sortedJSON } from './tools.js'

// Records that only make sense at a zone apex keep the apex as their owner.
const APEX_TYPES = new Set(['SOA', 'NS', 'DNSKEY', 'CDNSKEY', 'CDS', 'NSEC3PARAM', 'ZONEMD'])
const NS_NAME = 'ns.interop.invalid.'

// Each record gets its own zone, rN.interop.test., with its owner moved under it,
// so no two records can conflict and every tool sees one record per zone.
export function buildCases(records) {
  const cases = []
  const problems = []
  records.forEach(({ type, source, rec }, n) => {
    const id = `${type}#${n} (${source})`
    if ((rec.class ?? 'IN') !== 'IN')
      return problems.push({ id, type, stage: 'setup', status: 'skip', err: `class ${rec.class}` })
    const Type = RR[type]
    const apex = `r${n}.interop.test.`
    const owner = APEX_TYPES.has(type) ? apex : `${rec.owner === '.' ? '' : rec.owner}${apex}`
    try {
      const rr = new Type({ ...rec, owner, ttl: rec.ttl ?? 3600 })
      cases.push({
        id,
        n,
        type,
        Type,
        rr,
        apex,
        owner,
        typeId: Type.typeId ?? rr.getTypeId(),
        wire: hex(rr.getWireRdata()),
        json: sortedJSON(rr),
      })
    } catch (e) {
      problems.push({ id, type, stage: 'setup', status: 'fail', err: e.message.split('\n')[0] })
    }
  })
  return { cases, problems }
}

function apexRecords(c) {
  const soa = new RR.SOA({
    owner: c.apex,
    ttl: 3600,
    type: 'SOA',
    mname: NS_NAME,
    rname: 'hostmaster.interop.invalid.',
    serial: 1,
    refresh: 3600,
    retry: 600,
    expire: 86400,
    minimum: 300,
  })
  const ns = new RR.NS({ owner: c.apex, ttl: 3600, type: 'NS', dname: NS_NAME })
  return { soa: c.type === 'SOA' ? null : soa, ns: c.type === 'NS' ? null : ns }
}

export function bindZone(c) {
  const { soa, ns } = apexRecords(c)
  const lines = [soa?.toBind(), ns?.toBind()]
  // DS belongs to the parent side of a delegation.
  if (c.type === 'DS')
    lines.push(new RR.NS({ owner: c.owner, ttl: 3600, type: 'NS', dname: NS_NAME }).toBind())
  return [...lines, c.rr.toBind()].filter(Boolean).join('')
}

export function tinydnsData(c) {
  const { soa, ns } = apexRecords(c)
  return [soa?.toTinydns(), ns?.toTinydns(), c.rr.toTinydns()].filter(Boolean).join('')
}

// csv2(5) requires the SOA to be a zone's first record.
export function csv2Zone(c) {
  const { soa, ns } = apexRecords(c)
  const record = c.rr.toMaraDNS()
  return c.type === 'SOA' ? record + ns.toMaraDNS() : soa.toMaraDNS() + (ns?.toMaraDNS() ?? '') + record
}
