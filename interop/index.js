// Interop check: every test record, exported by this library, parsed and
// served by the DNS software installed here, then compared with toWire().
//
//   npm run interop [-- stage ...]
//
// Stages whose tools are missing are skipped. INTEROP_PORT sets the first
// port (default 15353), INTEROP_KEEP=1 keeps the work directory and
// INTEROP_VERBOSE=1 lists known failures as well. Exits 1 on a new failure.
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

import { bindZone, buildCases } from './cases.js'
import { knownReason } from './known.js'
import { collectRecords } from './records.js'
import { STAGES, available, serve } from './stages.js'

const only = process.argv.slice(2)
const verbose = process.env.INTEROP_VERBOSE === '1'
// os.tmpdir() keeps control-socket paths within the sockaddr_un limit.
const work = fs.mkdtempSync(path.join(os.tmpdir(), 'rr-interop-'))
const basePort = Number(process.env.INTEROP_PORT ?? 15353)
const ctx = { work, zoneFile: (c) => path.join(work, 'zones', `${c.apex}zone`) }
fs.mkdirSync(path.join(work, 'zones'))

const { cases, problems } = buildCases(await collectRecords())
const byId = new Map(cases.map((c) => [c.id, c]))
for (const c of cases) fs.writeFileSync(ctx.zoneFile(c), bindZone(c))

const results = problems
const skippedStages = []
for (const [i, stage] of STAGES.entries()) {
  if (only.length && !only.includes(stage.name)) continue
  ctx.port = basePort + i
  const why = available(stage) ?? (await stage.setup?.(ctx))
  if (why) {
    skippedStages.push(`${stage.name}: ${why}`)
    continue
  }
  process.stderr.write(`${stage.name}…\n`)
  const stageResults = stage.start ? await serve(stage, cases, ctx, results) : await eachCase(stage)
  for (const r of stageResults) {
    r.stage = stage.name
    const reason = r.status === 'fail' && knownReason(stage.name, byId.get(r.id))
    if (reason) Object.assign(r, { status: 'known', reason })
    results.push(r)
  }
}

report()
if (process.env.INTEROP_KEEP === '1') console.log(`\nwork directory: ${work}`)
else fs.rmSync(work, { recursive: true, force: true })
process.exitCode = results.some((r) => r.status === 'fail') ? 1 : 0

async function eachCase(stage) {
  const out = []
  for (const c of cases) {
    try {
      out.push({ id: c.id, type: c.type, ...(await stage.each(c, ctx)) })
    } catch (e) {
      out.push({ id: c.id, type: c.type, status: 'fail', err: e.message.split('\n')[0] })
    }
  }
  return out
}

function report() {
  const table = {}
  for (const r of results) {
    table[r.stage] ??= { ok: 0, normalized: 0, known: 0, fail: 0, skip: 0 }
    table[r.stage][r.status]++
  }
  console.log(`${cases.length} records\n`)
  console.table(table)
  for (const s of skippedStages) console.log(`skipped ${s}`)

  for (const status of verbose ? ['fail', 'known'] : ['fail']) {
    const list = results.filter((r) => r.status === status)
    if (!list.length) continue
    console.log(`\n${status === 'fail' ? 'FAILURES' : 'KNOWN'} (${list.length})`)
    for (const r of list) {
      console.log(`\n[${r.stage}] ${r.id}: ${r.err}${r.reason ? ` — ${r.reason}` : ''}`)
      if (r.detail && status === 'fail')
        console.log(indent(r.detail.trim().split('\n').slice(0, 8).join('\n')))
    }
  }
  console.log(`\nnormalized: the tool writes the record differently; the wire bytes match.`)
}

function indent(text) {
  return text.replace(/^/gm, '    ')
}
