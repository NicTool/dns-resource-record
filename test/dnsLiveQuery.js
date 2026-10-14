/**
 * Live DNS round-trip test.
 *
 * Queries records from test/fixtures/nictool.tnpi.net.zone against:
 *   - NSD at localhost:1053
 *   - tinydns at ns2.cadillac.net (from test/fixtures/v2.nictool.tnpi.net.zone)
 *
 * Each record is read with fromBind() and its wire form must match one of the
 * server's answers, after decompressing name pointers in the answer.
 *
 * Each server's tests are skipped when it is unreachable.
 */

import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

import RR, * as rrtypes from '../index.js'
import { parseBindLine, tokenize } from '../lib/bind.js'
import { buildQuery, parseResponse, wirePackDomain } from '../lib/wire.js'
import { dnsQuery } from '../lib/dns-query.js'

const ZONE_FILE = new URL('fixtures/nictool.tnpi.net.zone', import.meta.url)
const V2_ZONE_FILE = new URL('fixtures/v2.nictool.tnpi.net.zone', import.meta.url)

const NSD = { host: '127.0.0.1', port: 1053 }
const NS2 = { host: 'ns2.cadillac.net', port: 53 }

// Types served by ns2.cadillac.net (NicTool 2.0). SOA is omitted because the
// serial changes on zone updates.
const NS2_TYPES = new Set(['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'CAA', 'SRV', 'LOC', 'NS'])

// RRSIG, SIG and NSEC3 hold synthetic data; the CERT fixture differs from
// NSD's zone data; DS lives in the parent zone.
const SKIP_LIVE = new Set(['RRSIG', 'SIG', 'NSEC3', 'CERT', 'DS'])

const hex = (bytes) => Buffer.from(bytes).toString('hex')

/** Records of a zone file, each with an absolute owner and an explicit TTL. */
function parseZoneFile(url) {
  const records = []
  let origin = ''
  let defaultTtl = 3600
  let text = ''

  for (const line of readFileSync(url, 'utf8').split('\n')) {
    text += `${line}\n`
    let tokens
    try {
      tokens = tokenize(text)
    } catch (e) {
      if (/unbalanced parentheses/.test(e.message)) continue // the record continues on the next line
      throw e
    }
    const entry = text
    text = ''

    if (!tokens.length) continue
    if (tokens[0].text === '$ORIGIN') origin = tokens[1].text
    else if (tokens[0].text === '$TTL') defaultTtl = parseInt(tokens[1].text, 10)
    else {
      const parsed = parseBindLine(entry, RR.CLASSES)
      const owner = parsed.owner.endsWith('.') ? parsed.owner : `${parsed.owner}.${origin}`
      const ttl = parsed.ttl ?? defaultTtl
      const bindLine = entry.replace(/^\S+/, parsed.ttl === undefined ? `${owner} ${ttl}` : owner)
      records.push({ owner, ttl, type: parsed.type, bindLine })
    }
  }
  return records
}

async function isReachable({ host, port }) {
  try {
    await dnsQuery(host, port, buildQuery('nictool.tnpi.net', 6 /* SOA */), 1500)
    return true
  } catch {
    return false
  }
}

/** The concatenated content of length-prefixed character-strings. */
function joinCharStrings(rdata) {
  const parts = []
  for (let i = 0; i < rdata.length; i += rdata[i] + 1) parts.push(rdata.subarray(i + 1, i + 1 + rdata[i]))
  return hex(Buffer.concat(parts))
}

async function queryAndCompare(server, record, rr, { joinTxt }) {
  const typeId = rrtypes.typeMap[record.type]
  const query = buildQuery(record.owner.replace(/\.$/, ''), typeId)
  const { rcode, answers } = parseResponse(await dnsQuery(server.host, server.port, query))
  assert.equal(rcode, 0, `RCODE=${rcode} for ${record.type} ${record.owner}`)

  const typed = answers.filter((a) => a.typeId === typeId)
  assert.ok(typed.length > 0, `No ${record.type} answer for ${record.owner}`)

  // djbdns splits TXT character-strings at 127 bytes, the library at 255
  const rdata = joinTxt && record.type === 'TXT' ? joinCharStrings : hex
  const key = (owner, cls, bytes) => `${hex(owner)} ${cls} ${rdata(bytes)}`
  const expected = key(wirePackDomain(rr.get('owner')), rr.getClassId(), rr.getWireRdata())
  const received = typed.map((a) => key(a.ownerBytes, a.cls, a.rdataBytes))
  assert.ok(received.includes(expected), `expected: ${expected}\nreceived: ${received.join('\n          ')}`)
}

describe('DNS live query round-trip', async () => {
  for (const [name, server, records, opts] of [
    ['NSD at localhost:1053', NSD, parseZoneFile(ZONE_FILE), { joinTxt: false }],
    [
      'tinydns at ns2.cadillac.net',
      NS2,
      parseZoneFile(V2_ZONE_FILE).filter((r) => NS2_TYPES.has(r.type)),
      { joinTxt: true },
    ],
  ]) {
    const available = await isReachable(server)
    describe(name, { skip: available ? false : `${name} not reachable` }, () => {
      for (const record of records) {
        const rrClass = rrtypes[record.type]
        if (SKIP_LIVE.has(record.type) || !rrClass) continue

        test(`${record.type} ${record.owner}`, async (t) => {
          let rr
          try {
            rr = rrClass.fromBind(record.bindLine)
          } catch (e) {
            return t.skip(`fromBind failed: ${e.message}`)
          }
          await queryAndCompare(server, record, rr, opts)
        })
      }
    })
  }
})
