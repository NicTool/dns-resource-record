import { createSocket } from 'node:dgram'
import { createConnection } from 'node:net'

import { base64ToBytes, hexToBytes } from './binary.js'
import { expandIPv6 } from './tinydns.js'

// ── Name encoding/decoding ────────────────────────────────────────────────────

export function encodeName(name) {
  const labels = name.replace(/\.$/, '').split('.')
  const parts = labels.map((l) => {
    const b = Buffer.from(l)
    return Buffer.concat([Buffer.from([b.length]), b])
  })
  return Buffer.concat([...parts, Buffer.from([0])])
}

/**
 * Read a (possibly pointer-compressed) DNS name from a packet.
 * Returns { bytes: Buffer (uncompressed wire name), end: offset after name }.
 */
export function readWireName(packet, offset) {
  const labels = []
  let pos = offset
  let end = -1

  while (pos < packet.length) {
    const len = packet[pos]
    if (len === 0) {
      if (end === -1) end = pos + 1
      labels.push(Buffer.from([0]))
      break
    }
    if ((len & 0xc0) === 0xc0) {
      if (end === -1) end = pos + 2
      pos = ((len & 0x3f) << 8) | packet[pos + 1]
      continue
    }
    const label = packet.slice(pos, pos + 1 + len)
    labels.push(label)
    pos += 1 + len
  }

  return { bytes: Buffer.concat(labels), end }
}

/**
 * Decompress rdata for types that embed domain names (RFC 1035 §3.3).
 * For all other types, returns the raw rdata bytes unchanged.
 */
export function decompressRdata(packet, rdataOffset, rdlen, typeId) {
  const raw = packet.slice(rdataOffset, rdataOffset + rdlen)

  switch (typeId) {
    // Single name: NS, CNAME, PTR, DNAME
    case 2:
    case 5:
    case 12:
    case 39: {
      const { bytes } = readWireName(packet, rdataOffset)
      return bytes
    }

    // SOA: mname + rname + 5 × uint32
    case 6: {
      const { bytes: mname, end: e1 } = readWireName(packet, rdataOffset)
      const { bytes: rname, end: e2 } = readWireName(packet, e1)
      const tail = packet.slice(e2, rdataOffset + rdlen) // 20 bytes
      return Buffer.concat([mname, rname, tail])
    }

    // preference(2) + name: MX, KX
    case 15:
    case 36: {
      const pref = raw.slice(0, 2)
      const { bytes } = readWireName(packet, rdataOffset + 2)
      return Buffer.concat([pref, bytes])
    }

    // priority(2) + weight(2) + port(2) + name: SRV
    case 33: {
      const head = raw.slice(0, 6)
      const { bytes } = readWireName(packet, rdataOffset + 6)
      return Buffer.concat([head, bytes])
    }

    // mbox + txt (two names): RP
    case 17: {
      const { bytes: mbox, end: e1 } = readWireName(packet, rdataOffset)
      const { bytes: txt } = readWireName(packet, e1)
      return Buffer.concat([mbox, txt])
    }

    // order(2)+pref(2)+flags_str+svc_str+regexp_str+name: NAPTR
    case 35: {
      const head = raw.slice(0, 4)
      let pos = rdataOffset + 4
      const strings = []
      for (let i = 0; i < 3; i++) {
        const slen = packet[pos]
        strings.push(packet.slice(pos, pos + 1 + slen))
        pos += 1 + slen
      }
      const { bytes: name } = readWireName(packet, pos)
      return Buffer.concat([head, ...strings, name])
    }

    default:
      return raw
  }
}

// ── Query building and parsing ────────────────────────────────────────────────

export function buildQuery(name, typeId, classId = 1) {
  const nameBytes = encodeName(name)
  const header = Buffer.alloc(12)
  header.writeUInt16BE(Math.floor(Math.random() * 65536), 0)
  header.writeUInt16BE(0x0100, 2) // RD=1
  header.writeUInt16BE(1, 4) // QDCOUNT=1
  header.writeUInt16BE(1, 10) // ARCOUNT=1 (OPT record)
  const question = Buffer.alloc(nameBytes.length + 4)
  nameBytes.copy(question)
  question.writeUInt16BE(typeId, nameBytes.length)
  question.writeUInt16BE(classId, nameBytes.length + 2)
  // EDNS0 OPT record: root name, type=OPT(41), class=4096 (UDP payload), TTL=0, RDLEN=0
  const opt = Buffer.alloc(11)
  opt[0] = 0x00 // owner = root
  opt.writeUInt16BE(41, 1) // type = OPT
  opt.writeUInt16BE(4096, 3) // UDP payload size
  opt.writeUInt32BE(0, 5) // extended RCODE and flags
  opt.writeUInt16BE(0, 9) // RDLENGTH = 0
  return Buffer.concat([header, question, opt])
}

export function parseResponse(packet) {
  const rcode = packet.readUInt16BE(2) & 0xf
  const qdcount = packet.readUInt16BE(4)
  const ancount = packet.readUInt16BE(6)

  if (rcode !== 0) return { rcode, answers: [] }

  let offset = 12
  for (let i = 0; i < qdcount; i++) {
    const { end } = readWireName(packet, offset)
    offset = end + 4
  }

  const answers = []
  for (let i = 0; i < ancount; i++) {
    const { bytes: ownerBytes, end: nameEnd } = readWireName(packet, offset)
    offset = nameEnd
    const typeId = packet.readUInt16BE(offset)
    const cls = packet.readUInt16BE(offset + 2)
    const rdlen = packet.readUInt16BE(offset + 8)
    const rdataOffset = offset + 10
    const rdataBytes = decompressRdata(packet, rdataOffset, rdlen, typeId)
    offset += 10 + rdlen
    answers.push({ ownerBytes, typeId, cls, rdataBytes })
  }

  return { rcode: 0, answers }
}

// ── Network queries ───────────────────────────────────────────────────────────

export function dnsQueryUDP(host, port, queryBuf, timeout = 5000) {
  return new Promise((resolve, reject) => {
    const socket = createSocket('udp4')
    const timer = setTimeout(() => {
      socket.close()
      reject(new Error(`DNS query timed out (${host}:${port})`))
    }, timeout)
    socket.on('message', (msg) => {
      clearTimeout(timer)
      socket.close()
      resolve(msg)
    })
    socket.on('error', (err) => {
      clearTimeout(timer)
      socket.close()
      reject(err)
    })
    socket.send(queryBuf, port, host, (err) => {
      if (err) {
        clearTimeout(timer)
        socket.close()
        reject(err)
      }
    })
  })
}

export function dnsQueryTCP(host, port, queryBuf, timeout = 5000) {
  return new Promise((resolve, reject) => {
    const conn = createConnection({ host, port })
    const timer = setTimeout(() => {
      conn.destroy()
      reject(new Error(`DNS TCP query timed out (${host}:${port})`))
    }, timeout)
    let received = Buffer.alloc(0)
    conn.on('connect', () => {
      const len = Buffer.alloc(2)
      len.writeUInt16BE(queryBuf.length)
      conn.write(Buffer.concat([len, queryBuf]))
    })
    conn.on('data', (chunk) => {
      received = Buffer.concat([received, chunk])
      if (received.length >= 2) {
        const msgLen = received.readUInt16BE(0)
        if (received.length >= 2 + msgLen) {
          clearTimeout(timer)
          conn.destroy()
          resolve(received.slice(2, 2 + msgLen))
        }
      }
    })
    conn.on('error', (err) => {
      clearTimeout(timer)
      reject(err)
    })
  })
}

export async function dnsQuery(host, port, queryBuf, timeout = 5000) {
  const udpResult = await dnsQueryUDP(host, port, queryBuf, timeout)
  const tc = (udpResult.readUInt16BE(2) >> 9) & 1
  if (tc) return dnsQueryTCP(host, port, queryBuf, timeout)
  return udpResult
}

// ── SVCB/HTTPS parameter encoding (RFC 9460) ─────────────────────────────────

const SVCPARAM_KEYS = {
  mandatory: 0,
  alpn: 1,
  'no-default-alpn': 2,
  port: 3,
  ipv4hint: 4,
  ech: 5,
  ipv6hint: 6,
}

/**
 * Encode SVCB/HTTPS params string (e.g. 'alpn="h2,h3" port="8443"') to wire bytes.
 */
export function svcParamsToWire(paramsStr) {
  if (!paramsStr || !paramsStr.trim()) return new Uint8Array(0)

  const parts = []
  // Match: key, key=unquoted, or key="quoted" tokens
  const re = /([^\s=]+)(?:=(?:"([^"]*)"|(\S*)))?(?=\s|$)/g
  let m
  while ((m = re.exec(paramsStr.trim())) !== null) {
    const key = m[1].toLowerCase()
    const val = m[2] ?? m[3] ?? ''
    const keyId = SVCPARAM_KEYS[key]
    if (keyId === undefined) continue

    let valBytes
    if (keyId === 1) {
      // alpn: comma-separated list, each entry length-prefixed
      const enc = new TextEncoder()
      const entries = val.split(',').map((e) => enc.encode(e.trim()))
      const total = entries.reduce((s, e) => s + 1 + e.length, 0)
      valBytes = new Uint8Array(total)
      let p = 0
      for (const e of entries) {
        valBytes[p++] = e.length
        valBytes.set(e, p)
        p += e.length
      }
    } else if (keyId === 2) {
      // no-default-alpn: no value
      valBytes = new Uint8Array(0)
    } else if (keyId === 3) {
      // port: uint16
      valBytes = new Uint8Array(2)
      new DataView(valBytes.buffer).setUint16(0, parseInt(val, 10))
    } else if (keyId === 4) {
      // ipv4hint: one or more IPv4 addresses
      const addrs = val.split(',').map((a) => a.trim().split('.').map(Number))
      valBytes = new Uint8Array(addrs.length * 4)
      addrs.forEach((addr, i) => addr.forEach((b, j) => (valBytes[i * 4 + j] = b)))
    } else if (keyId === 5) {
      // ech: base64-encoded ECH config
      valBytes = base64ToBytes(val)
    } else if (keyId === 6) {
      // ipv6hint: one or more IPv6 addresses (expand compressed form before encoding)
      const addrs = val.split(',').map((a) => hexToBytes(expandIPv6(a.trim(), '')))
      valBytes = new Uint8Array(addrs.length * 16)
      addrs.forEach((addr, i) => valBytes.set(addr, i * 16))
    } else {
      valBytes = new TextEncoder().encode(val)
    }

    const param = new Uint8Array(4 + valBytes.length)
    new DataView(param.buffer).setUint16(0, keyId)
    new DataView(param.buffer).setUint16(2, valBytes.length)
    param.set(valBytes, 4)
    parts.push(param)
  }

  // Sort by key ID (SvcParams MUST be in ascending order per RFC 9460)
  parts.sort((a, b) => new DataView(a.buffer).getUint16(0) - new DataView(b.buffer).getUint16(0))

  const total = parts.reduce((s, p) => s + p.length, 0)
  const result = new Uint8Array(total)
  let pos = 0
  for (const p of parts) {
    result.set(p, pos)
    pos += p.length
  }
  return result
}
