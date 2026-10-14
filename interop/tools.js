import { execFileSync, spawn, spawnSync } from 'node:child_process'
import fs from 'node:fs'

import { nameToLabels } from '../lib/name.js'

export const hex = (bytes) => Buffer.from(bytes).toString('hex')
export const sortedJSON = (rr) => JSON.stringify(Object.fromEntries(Object.entries(rr.toJSON()).sort()))
export const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

export function has(cmd) {
  return spawnSync('sh', ['-c', `command -v ${cmd}`]).status === 0
}

export function run(cmd, args, opts = {}) {
  try {
    return {
      ok: true,
      out: execFileSync(cmd, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], ...opts }),
    }
  } catch (e) {
    return { ok: false, out: `${e.stdout ?? ''}${e.stderr ?? ''}`.trim() || e.message }
  }
}

export function startDaemon(cmd, args, logFile, opts = {}) {
  const log = fs.openSync(logFile, 'a')
  return spawn(cmd, args, { stdio: ['ignore', log, log], ...opts })
}

export async function waitForAnswer(port, name, tries = 50) {
  for (let i = 0; i < tries; i++) {
    if (/status: \w+/.test(dig(port, name, 6).out)) return true
    await sleep(200)
  }
  return false
}

export function dig(port, name, typeId, extra = []) {
  return run('dig', [
    '@127.0.0.1',
    '-p',
    String(port),
    '+time=2',
    '+tries=1',
    '+norec',
    ...extra,
    name,
    `TYPE${typeId}`,
  ])
}

// Answer rdata as hex, from `dig +unknownformat` (RFC 3597 `\# len hex`).
export function servedRdata(port, c, udp = false) {
  const out = dig(port, c.owner, c.typeId, [
    udp ? '+notcp' : '+tcp',
    '+unknownformat',
    '+noall',
    '+answer',
    '+comments',
  ]).out
  const rdata = out
    .split('\n')
    .filter((l) => l && !l.startsWith(';'))
    .map((l) =>
      l
        .match(/\\# \d+\s*(.*)$/)?.[1]
        .replace(/\s/g, '')
        .toLowerCase(),
    )
    .filter((r) => r !== undefined)
  return { rdata, status: out.match(/status: (\w+)/)?.[1] ?? 'no reply', out }
}

function wireName(name) {
  try {
    return hex(Buffer.concat(nameToLabels(name).map((l) => Buffer.from(l)))).toLowerCase()
  } catch {
    return name.toLowerCase()
  }
}

// Lines in a tool's zone output that hold this case's record.
export function recordLines(c, text) {
  const owner = wireName(c.owner)
  return text.split('\n').filter((line) => {
    const words = line.trim().split(/\s+/)
    if (!words[0] || wireName(words[0].endsWith('.') ? words[0] : `${words[0]}.`) !== owner) return false
    return words.slice(1, 5).some((w) => w === c.type || w === `TYPE${c.typeId}`)
  })
}

// Import a tool's presentation of the record and compare it with ours: equal
// fields are ok, equal wire bytes are a formatting difference only.
export function reimport(c, text) {
  const lines = recordLines(c, text)
  if (lines.length !== 1)
    return { status: 'fail', err: `expected 1 ${c.type} line, got ${lines.length}`, detail: text.slice(-500) }
  let back
  try {
    back = c.Type.fromBind(lines[0])
  } catch (e) {
    return { status: 'fail', err: `fromBind: ${e.message.split('\n')[0]}`, detail: lines[0] }
  }
  if (sortedJSON(back) === c.json) return { status: 'ok' }
  let wire
  try {
    wire = hex(back.getWireRdata())
  } catch (e) {
    wire = e.message
  }
  if (wire === c.wire && back.get('ttl') === c.rr.get('ttl')) return { status: 'normalized' }
  return {
    status: 'fail',
    err: 'imports as different data',
    detail: `line: ${lines[0]}\nours: ${c.json}\nback: ${sortedJSON(back)}`,
  }
}
