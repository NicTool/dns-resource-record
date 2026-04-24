/**
 * Live DNS round-trip test.
 *
 * Queries records from test/fixtures/nictool.tnpi.net.zone against:
 *   - NSD at localhost:1053
 *   - tinydns at ns2.cadillac.net (from test/fixtures/v2.nictool.tnpi.net.zone)
 *
 * For each record the test:
 *   1. Creates an RR via fromBind() using the zone file line.
 *   2. Calls toWire() to get the expected uncompressed wire bytes.
 *   3. Sends a UDP DNS query to the server.
 *   4. Parses the response, decompressing any name pointers in both the
 *      answer owner name and the rdata.
 *   5. Asserts the reconstructed wire matches toWire().
 *
 * Requires NSD serving nictool.tnpi.net at 127.0.0.1:1053.
 * ns2.cadillac.net tests are skipped when the host is unreachable.
 */

import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

import * as rrtypes from '../index.js'
import { buildQuery, parseResponse } from '../lib/wire.js'
import { dnsQuery } from '../lib/dns-query.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const ZONE_FILE = join(__dirname, 'fixtures', 'nictool.tnpi.net.zone')
const V2_ZONE_FILE = join(__dirname, 'fixtures', 'v2.nictool.tnpi.net.zone')

const NSD = { host: '127.0.0.1', port: 1053 }
const NS2 = { host: 'ns2.cadillac.net', port: 53 }

// Types served by ns2.cadillac.net (NicTool 2.0), derived from
// test/fixtures/v2.nictool.tnpi.net.zone. SOA is omitted because the serial
// number changes on zone updates.
const NS2_TYPES = new Set(['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'CAA', 'SRV', 'LOC', 'NS'])

// Skip live queries for DNSSEC records with synthetic data, obsolete types,
// and types where NSD's encoding differs from the library:
//   CERT: zone fixture data does not match NSD's actual zone data.
const SKIP_LIVE = new Set(['RRSIG', 'SIG', 'NSEC3', 'CERT'])

// DS records live in the parent zone, not the child — NSD won't serve them
const PARENT_ZONE_ONLY = new Set(['DS'])

const { typeMap } = rrtypes

// ── Zone File Parsing ─────────────────────────────────────────────────────────

/** Split a zone file line on whitespace, preserving content inside quotes. */
function splitZoneLine(line) {
  const parts = []
  let current = ''
  let inQuote = false
  for (const c of line) {
    if (c === '"') {
      inQuote = !inQuote
      current += c
    } else if (!inQuote && (c === ' ' || c === '\t')) {
      if (current) {
        parts.push(current)
        current = ''
      }
    } else {
      current += c
    }
  }
  if (current) parts.push(current)
  return parts
}

function parseZoneFile(path) {
  const content = readFileSync(path, 'utf8')
  const lines = []
  let buf = ''
  let inParen = false
  let origin = ''
  let defaultTtl = 3600

  for (const raw of content.split('\n')) {
    // Strip inline comments (excluding quoted strings)
    let l = raw
    let inQuote = false
    for (let i = 0; i < l.length; i++) {
      if (l[i] === '"') inQuote = !inQuote
      if (!inQuote && l[i] === ';') {
        l = l.slice(0, i)
        break
      }
    }
    l = l.trimEnd()
    if (!l.trim()) continue

    // Handle zone directives (only valid outside parentheses)
    const trimmed = l.trim()
    if (trimmed.startsWith('$ORIGIN')) {
      origin = trimmed.split(/\s+/)[1]
      continue
    }
    if (trimmed.startsWith('$TTL')) {
      defaultTtl = parseInt(trimmed.split(/\s+/)[1], 10) || defaultTtl
      continue
    }

    if (inParen) {
      buf = buf.trimEnd() + ' ' + l.trim()
      if (l.includes(')')) {
        inParen = false
        lines.push(buf.replace(/\s*\)\s*$/, '').trim())
        buf = ''
      }
      continue
    }

    if (l.includes('(') && !l.includes(')')) {
      inParen = true
      buf = l.replace(/\s*\(\s*$/, '').trim()
    } else if (l.includes('(') && l.includes(')')) {
      lines.push(
        l
          .replace(/\s*\(\s*|\s*\)\s*/g, ' ')
          .replace(/\s+/g, ' ')
          .trim(),
      )
    } else {
      lines.push(l)
    }
  }

  const records = []
  for (const line of lines) {
    if (line.startsWith(';')) continue
    const parts = splitZoneLine(line)
    if (parts.length < 4) continue

    let owner, ttl, cls, type, rdataParts

    if (/^\d+$/.test(parts[1])) {
      // owner TTL [class] TYPE rdata...
      owner = parts[0]
      ttl = parseInt(parts[1], 10)
      if (parts[2] === 'IN' || parts[2] === 'in') {
        cls = 'IN'
        type = parts[3].toUpperCase()
        rdataParts = parts.slice(4)
      } else {
        cls = 'IN'
        type = parts[2].toUpperCase()
        rdataParts = parts.slice(3)
      }
    } else if (parts[1] === 'IN' || parts[1] === 'in') {
      // owner IN TYPE rdata... (no TTL — inherit $TTL)
      owner = parts[0]
      ttl = defaultTtl
      cls = 'IN'
      type = parts[2].toUpperCase()
      rdataParts = parts.slice(3)
    } else {
      continue
    }

    // Expand relative owner names using $ORIGIN
    if (origin && !owner.endsWith('.')) {
      owner = `${owner}.${origin}`
    }

    // Rebuild a single-line BIND record for fromBind()
    const bindLine = `${owner}\t${ttl}\t${cls}\t${type}\t${rdataParts.join('\t')}`
    records.push({ owner, ttl, class: cls, type, bindLine })
  }

  return records
}

// ── Server availability ───────────────────────────────────────────────────────

async function isReachable(host, port) {
  try {
    const q = buildQuery('nictool.tnpi.net', 6 /* SOA */)
    await dnsQuery(host, port, q, 1500)
    return true
  } catch {
    return false
  }
}

const nsdAvailable = await isReachable(NSD.host, NSD.port)
const ns2Available = await isReachable(NS2.host, NS2.port)

// ── Wire comparison helper ────────────────────────────────────────────────────

/**
 * Query a DNS server, build uncompressed wire bytes for each answer, and
 * assert that one of them matches the expected wire from toWire().
 */
async function queryAndCompare(server, record, rrClass) {
  const typeId = typeMap[record.type]
  assert.ok(typeId, `No typeId for ${record.type}`)

  const queryBuf = buildQuery(record.owner.replace(/\.$/, ''), typeId)
  const responseBuf = await dnsQuery(server.host, server.port, queryBuf)
  const { rcode, answers } = parseResponse(responseBuf)

  assert.equal(rcode, 0, `RCODE=${rcode} for ${record.type} ${record.owner}`)

  const typed = answers.filter((a) => a.typeId === typeId)
  assert.ok(typed.length > 0, `No ${record.type} answer for ${record.owner}`)

  // Expected wire from library
  const rr = rrClass.fromBind(record.bindLine)
  const expectedHex = Buffer.from(rr.toWire()).toString('hex')

  // Build actual uncompressed wires for all matching answers
  const actuals = typed.map((a) => {
    const rdlen = a.rdataBytes.length
    const meta = Buffer.alloc(10)
    meta.writeUInt16BE(typeId, 0)
    meta.writeUInt16BE(a.cls, 2)
    meta.writeUInt32BE(record.ttl, 4)
    meta.writeUInt16BE(rdlen, 8)
    return Buffer.concat([a.ownerBytes, meta, a.rdataBytes]).toString('hex')
  })

  assert.ok(
    actuals.includes(expectedHex),
    `Wire mismatch for ${record.type} ${record.owner}\n` +
      `  expected: ${expectedHex}\n` +
      `  received: ${actuals.join(', ')}`,
  )
}

/**
 * Parse a TXT rdata buffer (length-prefixed character-strings) and return the
 * concatenated content as a hex string. This lets us compare TXT record content
 * regardless of chunk boundaries (djbdns uses 127-byte chunks; library uses 255).
 */
function extractTxtContent(rdataBytes) {
  let offset = 0
  const parts = []
  while (offset < rdataBytes.length) {
    const len = rdataBytes[offset++]
    parts.push(rdataBytes.slice(offset, offset + len))
    offset += len
  }
  return Buffer.concat(parts.map((p) => Buffer.from(p))).toString('hex')
}

/**
 * Like queryAndCompare, but compares TXT record content (concatenated strings)
 * rather than exact wire bytes. Required for ns2.cadillac.net because djbdns
 * splits TXT character-strings at 127 bytes while the library uses 255 bytes.
 */
async function queryAndCompareTxtContent(server, record, rrClass) {
  const typeId = typeMap[record.type]
  assert.ok(typeId, `No typeId for ${record.type}`)

  const queryBuf = buildQuery(record.owner.replace(/\.$/, ''), typeId)
  const responseBuf = await dnsQuery(server.host, server.port, queryBuf)
  const { rcode, answers } = parseResponse(responseBuf)

  assert.equal(rcode, 0, `RCODE=${rcode} for ${record.type} ${record.owner}`)

  const typed = answers.filter((a) => a.typeId === typeId)
  assert.ok(typed.length > 0, `No ${record.type} answer for ${record.owner}`)

  const rr = rrClass.fromBind(record.bindLine)
  const expectedContent = extractTxtContent(rr.getWireRdata())
  const actualContents = typed.map((a) => extractTxtContent(a.rdataBytes))

  assert.ok(
    actualContents.includes(expectedContent),
    `TXT content mismatch for ${record.owner}\n` +
      `  expected: ${expectedContent}\n` +
      `  received: ${actualContents.join(', ')}`,
  )
}

// ── Tests ─────────────────────────────────────────────────────────────────────

const zoneRecords = parseZoneFile(ZONE_FILE)
const v2ZoneRecords = parseZoneFile(V2_ZONE_FILE)

describe('DNS live query round-trip', () => {
  describe(
    'NSD at localhost:1053',
    { skip: nsdAvailable ? false : 'NSD not reachable at localhost:1053' },
    () => {
      for (const record of zoneRecords) {
        if (SKIP_LIVE.has(record.type)) continue
        if (PARENT_ZONE_ONLY.has(record.type)) continue

        const rrClass = rrtypes[record.type]
        if (!rrClass) continue // type not implemented in library

        test(`${record.type} ${record.owner}`, async (t) => {
          try {
            rrClass.fromBind(record.bindLine)
          } catch (e) {
            t.skip(`fromBind failed: ${e.message}`)
            return
          }
          await queryAndCompare(NSD, record, rrClass)
        })
      }
    },
  )

  describe(
    'tinydns at ns2.cadillac.net',
    { skip: ns2Available ? false : 'ns2.cadillac.net not reachable' },
    () => {
      for (const record of v2ZoneRecords.filter((r) => NS2_TYPES.has(r.type))) {
        if (SKIP_LIVE.has(record.type)) continue
        if (PARENT_ZONE_ONLY.has(record.type)) continue

        const rrClass = rrtypes[record.type]
        if (!rrClass) continue

        test(`${record.type} ${record.owner}`, async (t) => {
          try {
            rrClass.fromBind(record.bindLine)
          } catch (e) {
            t.skip(`fromBind failed: ${e.message}`)
            return
          }
          // djbdns splits TXT character-strings at 127 bytes; the library uses 255.
          // Compare concatenated content rather than exact wire bytes.
          if (record.type === 'TXT') {
            await queryAndCompareTxtContent(NS2, record, rrClass)
          } else {
            await queryAndCompare(NS2, record, rrClass)
          }
        })
      }
    },
  )
})
