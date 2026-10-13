import fs from 'node:fs'
import path from 'node:path'

import { wirePackDomain } from '../lib/wire.js'
import { csv2Zone, tinydnsData } from './cases.js'
import { dig, has, hex, reimport, run, servedRdata, sleep, startDaemon, waitForAnswer } from './tools.js'

const PDNS_SCHEMAS = [
  process.env.INTEROP_PDNS_SCHEMA,
  '/opt/homebrew/share/doc/pdns/schema.sqlite3.sql',
  '/usr/local/share/doc/pdns/schema.sqlite3.sql',
  '/opt/local/share/doc/pdns/schema.sqlite3.sql',
  '/usr/share/doc/pdns-backend-sqlite3/schema.sqlite3.sql',
  '/usr/share/pdns-backend-sqlite3/schema/schema.sqlite3.sql',
].filter(Boolean)

// Each stage checks one tool. `needs` lists the commands it runs; a stage whose
// commands are not installed is skipped. Server stages serve only the zones
// their own checker accepted, since one bad zone can stop a server starting.
export const STAGES = [
  {
    name: 'bind-parse',
    needs: ['named-compilezone'],
    each: (c, ctx) => {
      const r = run('named-compilezone', [
        '-q',
        '-k',
        'ignore',
        '-i',
        'none',
        '-s',
        'full',
        '-o',
        '-',
        c.apex,
        ctx.zoneFile(c),
      ])
      if (!r.ok)
        return {
          status: 'fail',
          err: 'rejected',
          detail: run('named-compilezone', [
            '-k',
            'ignore',
            '-i',
            'none',
            '-o',
            '/dev/null',
            c.apex,
            ctx.zoneFile(c),
          ]).out,
        }
      return reimport(c, r.out)
    },
  },
  {
    name: 'ldns-parse',
    needs: ['ldns-read-zone'],
    each: (c, ctx) => {
      const r = run('ldns-read-zone', [ctx.zoneFile(c)])
      if (!r.ok || /error/i.test(r.out)) return { status: 'fail', err: 'rejected', detail: r.out }
      return reimport(c, r.out)
    },
  },
  {
    name: 'knot-parse',
    needs: ['kzonecheck'],
    each: (c, ctx) => checked(run('kzonecheck', ['-v', '-o', c.apex, '-d', 'off', ctx.zoneFile(c)])),
  },
  {
    name: 'nsd-parse',
    needs: ['nsd-checkzone'],
    each: (c, ctx) => checked(run('nsd-checkzone', [c.apex, ctx.zoneFile(c)])),
  },
  {
    name: 'coredns-parse',
    needs: ['coredns'],
    each: (c, ctx) => corednsLoads(c, ctx),
  },
  {
    name: 'pdns-parse',
    needs: ['pdnsutil', 'sqlite3'],
    setup: (ctx) => pdnsSetup(ctx),
    each: (c, ctx) => {
      const load = run('pdnsutil', [`--config-dir=${ctx.pdnsDir}`, 'zone', 'load', c.apex, ctx.zoneFile(c)])
      if (!load.ok || /error|not part of zone/i.test(load.out))
        return { status: 'fail', err: 'rejected', detail: load.out }
      return reimport(c, run('pdnsutil', [`--config-dir=${ctx.pdnsDir}`, 'zone', 'list', c.apex]).out)
    },
  },
  {
    name: 'tinydns',
    needs: ['tinydns-data', 'tinydns-get'],
    each: (c, ctx) => tinydnsCheck(c, ctx),
  },
  {
    // csv2 export, read back by dns-zone when it is installed alongside.
    name: 'maradns-export',
    needs: [],
    setup: async (ctx) => {
      fs.mkdirSync(path.join(ctx.work, 'maradns'), { recursive: true })
      try {
        ctx.dnsZone = (await import('@nictool/dns-zone')).maradns
      } catch {
        ctx.dnsZone = null
      }
    },
    each: async (c, ctx) => {
      let zone
      try {
        zone = csv2Zone(c)
      } catch (e) {
        return { status: 'fail', err: e.message.split('\n')[0] }
      }
      fs.writeFileSync(path.join(ctx.work, 'maradns', `${c.apex}csv2`), zone)
      if (!ctx.dnsZone) return { status: 'ok' }
      try {
        const back = (await ctx.dnsZone.parseZoneFile(c.rr.toMaraDNS())).at(-1)
        if (hex(back.getWireRdata()) !== c.wire)
          return { status: 'fail', err: 'dns-zone reads different data', detail: c.rr.toMaraDNS() }
        return { status: 'ok' }
      } catch (e) {
        return { status: 'fail', err: `dns-zone: ${e.message.split('\n')[0]}`, detail: c.rr.toMaraDNS() }
      }
    },
  },
  {
    name: 'bind-serve',
    needs: ['named', 'dig'],
    checker: 'bind-parse',
    start: (ctx, served) => {
      const conf = path.join(ctx.work, 'named.conf')
      fs.writeFileSync(
        conf,
        `options { directory "${ctx.work}"; listen-on port ${ctx.port} { 127.0.0.1; }; listen-on-v6 { none; };
  pid-file "${ctx.work}/named.pid"; recursion no; dnssec-validation no; check-names primary ignore; check-integrity no; };
${served.map((c) => `zone "${c.apex}" { type primary; file "${ctx.zoneFile(c)}"; };`).join('\n')}\n`,
      )
      return startDaemon('named', ['-g', '-c', conf], path.join(ctx.work, 'named.log'))
    },
  },
  {
    name: 'knot-serve',
    needs: ['knotd', 'dig'],
    checker: 'knot-parse',
    start: (ctx, served) => {
      const dir = path.join(ctx.work, 'knot')
      fs.mkdirSync(dir, { recursive: true })
      const conf = path.join(dir, 'knot.conf')
      fs.writeFileSync(
        conf,
        `server:\n  rundir: "${dir}"\n  listen: 127.0.0.1@${ctx.port}\ndatabase:\n  storage: "${dir}"\n` +
          `template:\n  - id: default\n    semantic-checks: off\n    journal-content: none\n    zonefile-sync: -1\n    zonefile-load: whole\n` +
          `zone:\n${served.map((c) => `  - domain: "${c.apex}"\n    file: "${ctx.zoneFile(c)}"`).join('\n')}\n`,
      )
      return startDaemon('knotd', ['-c', conf], path.join(ctx.work, 'knot.log'))
    },
  },
  {
    name: 'nsd-serve',
    needs: ['nsd', 'dig'],
    checker: 'nsd-parse',
    start: (ctx, served) => {
      const dir = path.join(ctx.work, 'nsd')
      fs.mkdirSync(dir, { recursive: true })
      const conf = path.join(dir, 'nsd.conf')
      fs.writeFileSync(
        conf,
        `server:\n  ip-address: 127.0.0.1@${ctx.port}\n  username: ""\n  chroot: ""\n  database: ""\n  zonelistfile: "${dir}/zone.list"\n` +
          `  xfrdfile: "${dir}/xfrd.state"\n  xfrdir: "${dir}"\n  pidfile: "${dir}/nsd.pid"\n  logfile: "${dir}/nsd.log"\n` +
          `remote-control:\n  control-enable: no\n` +
          served.map((c) => `zone:\n  name: "${c.apex}"\n  zonefile: "${ctx.zoneFile(c)}"\n`).join(''),
      )
      return startDaemon('nsd', ['-d', '-c', conf], path.join(ctx.work, 'nsd.log'))
    },
  },
  {
    name: 'coredns-serve',
    needs: ['coredns', 'dig'],
    checker: 'coredns-parse',
    start: (ctx, served) => {
      const conf = path.join(ctx.work, 'Corefile')
      fs.writeFileSync(conf, served.map((c) => corefileBlock(c, ctx, ctx.port)).join('\n'))
      return startDaemon('coredns', ['-conf', conf], path.join(ctx.work, 'coredns.log'), { cwd: ctx.work })
    },
  },
  {
    name: 'pdns-serve',
    needs: ['pdns_server', 'pdnsutil', 'sqlite3', 'dig'],
    checker: 'pdns-parse',
    start: (ctx) => {
      fs.appendFileSync(
        path.join(ctx.pdnsDir, 'pdns.conf'),
        `local-address=127.0.0.1\nlocal-port=${ctx.port}\n`,
      )
      return startDaemon('pdns_server', [`--config-dir=${ctx.pdnsDir}`], path.join(ctx.work, 'pdns.log'))
    },
  },
  {
    name: 'maradns-serve',
    needs: ['maradns', 'dig'],
    // TCP is MaraDNS's separate zoneserver.
    udp: true,
    checker: 'maradns-export',
    start: (ctx, served) => {
      const dir = path.join(ctx.work, 'maradns')
      fs.writeFileSync(
        path.join(dir, 'mararc'),
        `ipv4_bind_addresses = "127.0.0.1"\ndns_port = ${ctx.port}\nchroot_dir = "${dir}"\nhide_disclaimer = "YES"\ncsv2 = {}\n` +
          served.map((c) => `csv2["${c.apex}"] = "${c.apex}csv2"`).join('\n') +
          '\n',
      )
      return startDaemon('maradns', ['-f', path.join(dir, 'mararc')], path.join(ctx.work, 'maradns.log'), {
        cwd: dir,
      })
    },
  },
]

function checked(r) {
  return r.ok ? { status: 'ok' } : { status: 'fail', err: 'rejected', detail: r.out }
}

function corefileBlock(c, ctx, port) {
  return `${c.apex}:${port} {\n  bind 127.0.0.1\n  file ${ctx.zoneFile(c)}\n}\n`
}

// CoreDNS refuses to start if any zone fails to parse, so each zone is tried alone.
async function corednsLoads(c, ctx) {
  const conf = path.join(ctx.work, 'Corefile.check')
  fs.writeFileSync(conf, corefileBlock(c, ctx, ctx.port))
  const proc = startDaemon('coredns', ['-conf', conf], path.join(ctx.work, 'coredns-check.log'))
  const log = path.join(ctx.work, 'coredns-check.log')
  const before = fs.statSync(log).size
  for (let i = 0; i < 40; i++) {
    await sleep(50)
    const out = fs.readFileSync(log, 'utf8').slice(before)
    if (/CoreDNS-/.test(out) || proc.exitCode !== null) {
      proc.kill('SIGKILL')
      await sleep(50)
      return /CoreDNS-/.test(out)
        ? { status: 'ok' }
        : { status: 'fail', err: 'rejected', detail: out.replace(/^maxprocs.*\n/m, '').trim() }
    }
  }
  proc.kill('SIGKILL')
  return { status: 'fail', err: 'did not start' }
}

function pdnsSetup(ctx) {
  const schema = PDNS_SCHEMAS.find((f) => fs.existsSync(f))
  if (!schema) return 'no PowerDNS sqlite3 schema found; set INTEROP_PDNS_SCHEMA'
  ctx.pdnsDir = path.join(ctx.work, 'pdns')
  fs.mkdirSync(ctx.pdnsDir, { recursive: true })
  const db = path.join(ctx.pdnsDir, 'pdns.db')
  const r = run('sqlite3', [db], { input: fs.readFileSync(schema, 'utf8'), stdio: ['pipe', 'pipe', 'pipe'] })
  if (!r.ok) return `sqlite3: ${r.out}`
  fs.writeFileSync(
    path.join(ctx.pdnsDir, 'pdns.conf'),
    `launch=gsqlite3\ngsqlite3-database=${db}\nsocket-dir=${ctx.pdnsDir}\ndaemon=no\nguardian=no\n`,
  )
}

// tinydns itself binds port 53 and chroots, so tinydns-get, which runs the same
// lookup code against data.cdb, stands in for the server.
function tinydnsCheck(c, ctx) {
  const dir = path.join(ctx.work, 'tinydns', c.apex)
  fs.mkdirSync(dir, { recursive: true })
  try {
    fs.writeFileSync(path.join(dir, 'data'), tinydnsData(c))
  } catch (e) {
    return { status: 'fail', err: `toTinydns: ${e.message.split('\n')[0]}` }
  }
  const compile = run('tinydns-data', [], { cwd: dir })
  if (!compile.ok) return { status: 'fail', err: 'tinydns-data rejected', detail: compile.out }
  const out = run('tinydns-get', [String(c.typeId), tinydnsName(c.owner)], { cwd: dir }).out
  const answers = out.split('\n').filter((l) => l.startsWith('answer: '))
  if (answers.length !== 1)
    return { status: 'fail', err: `expected 1 answer, got ${answers.length}`, detail: out }
  let served
  try {
    served = tinydnsRdata(answers[0])
  } catch (e) {
    return { status: 'fail', err: `unparsed answer: ${e.message}`, detail: answers[0] }
  }
  return served === c.wire
    ? { status: 'ok' }
    : { status: 'fail', err: 'wire mismatch', detail: `ours:   ${c.wire}\nserved: ${served}` }
}

// djbdns names use octal escapes; presentation names use decimal.
function tinydnsName(name) {
  return (
    name.replace(/\\(\d{3})/g, (_, d) => `\\${Number(d).toString(8).padStart(3, '0')}`).replace(/\.$/, '') ||
    '.'
  )
}

function fromTinydnsName(name) {
  const decimal = name.replace(/\\([0-7]{3})/g, (_, o) => `\\${String(parseInt(o, 8)).padStart(3, '0')}`)
  return decimal.endsWith('.') ? decimal : `${decimal}.`
}

// tinydns-get prints A, NS, CNAME, PTR, MX and SOA as text and other types as
// their number and the rdata with octal escapes.
function tinydnsRdata(answer) {
  const [, , type, ...rest] = answer.slice('answer: '.length).split(' ')
  const u16 = (n) => [(n >> 8) & 0xff, n & 0xff]
  const u32 = (n) => [...u16(Math.floor(n / 65536)), ...u16(n % 65536)]
  const name = (n) => [...wirePackDomain(fromTinydnsName(n))]
  switch (type) {
    case 'A':
      return hex(rest[0].split('.').map(Number))
    case 'NS':
    case 'CNAME':
    case 'PTR':
      return hex(name(rest[0]))
    case 'MX':
      return hex([...u16(Number(rest[0])), ...name(rest[1])])
    case 'SOA':
      return hex([...name(rest[0]), ...name(rest[1]), ...rest.slice(2).flatMap((n) => u32(Number(n)))])
  }
  if (!/^\d+$/.test(type)) throw new Error(type)
  const text = rest.join(' ')
  const bytes = []
  for (let i = 0; i < text.length; i++) {
    const octal = text.slice(i).match(/^\\([0-7]{3})/)
    if (octal) {
      bytes.push(parseInt(octal[1], 8))
      i += 3
    } else bytes.push(text.charCodeAt(i))
  }
  return hex(bytes)
}

// Serve every zone the stage's checker accepted, then compare each answer with toWire.
export async function serve(stage, cases, ctx, results) {
  const rejected = new Set(
    results
      .filter((r) => r.stage === stage.checker && r.status !== 'ok' && r.status !== 'normalized')
      .map((r) => r.id),
  )
  const served = cases.filter((c) => !rejected.has(c.id))
  const proc = stage.start(ctx, served)
  try {
    if (!(await waitForAnswer(ctx.port, served[0].apex)))
      return [
        {
          id: stage.name,
          type: '-',
          status: 'fail',
          err: 'server did not answer',
          detail: proc.exitCode === null ? '' : `exited ${proc.exitCode}`,
        },
      ]
    return cases.map((c) => {
      if (rejected.has(c.id))
        return { id: c.id, type: c.type, status: 'skip', err: `${stage.checker} rejected it` }
      const { rdata, status, out } = servedRdata(ctx.port, c, stage.udp)
      if (rdata.length !== 1)
        return {
          id: c.id,
          type: c.type,
          status: 'fail',
          err: `${status}, ${rdata.length} answers`,
          detail: out,
        }
      if (rdata[0] !== c.wire)
        return {
          id: c.id,
          type: c.type,
          status: 'fail',
          err: 'wire mismatch',
          detail: `ours:   ${c.wire}\nserved: ${rdata[0]}`,
        }
      const text = dig(ctx.port, c.owner, c.typeId, [stage.udp ? '+notcp' : '+tcp', '+noall', '+answer']).out
      return { id: c.id, type: c.type, ...reimport(c, text) }
    })
  } finally {
    proc.kill()
    await sleep(300)
  }
}

export function available(stage) {
  const missing = stage.needs.filter((cmd) => !has(cmd))
  return missing.length ? `not installed: ${missing.join(', ')}` : null
}
