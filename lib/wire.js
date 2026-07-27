import { base64ToBytes, bytesToBase64, bytesToHex, hexToBytes } from './binary.js'
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
 *
 * Bounded to defend against malicious or truncated packets:
 *   - rejects pointer cycles via a visited-offset set
 *   - caps total pointer dereferences at 128
 *   - caps the decoded name at 255 bytes (RFC 1035 §3.1)
 *   - rejects truncated pointers, pointer targets past the packet end,
 *     truncated labels, and unterminated names
 */
export function readWireName(packet, offset) {
  if (offset < 0 || offset >= packet.length) {
    throw new Error('readWireName: offset out of bounds')
  }

  const labels = []
  const visited = new Set()
  let pos = offset
  let end = -1
  let nameLen = 0
  let terminated = false

  while (pos < packet.length) {
    const len = packet[pos]
    if (len === 0) {
      if (end === -1) end = pos + 1
      labels.push(Buffer.from([0]))
      terminated = true
      break
    }
    if ((len & 0xc0) === 0xc0) {
      if (pos + 1 >= packet.length) throw new Error('readWireName: truncated pointer')
      if (end === -1) end = pos + 2
      if (visited.has(pos)) throw new Error('readWireName: pointer cycle detected')
      visited.add(pos)
      if (visited.size > 128) throw new Error('readWireName: pointer chain too long')
      const target = ((len & 0x3f) << 8) | packet[pos + 1]
      if (target >= packet.length) throw new Error('readWireName: pointer target out of bounds')
      pos = target
      continue
    }
    // Top two bits not 00 → reserved (RFC 1035 §4.1.4 / RFC 6891)
    if ((len & 0xc0) !== 0) throw new Error('readWireName: reserved label type')
    if (len > 63) throw new Error('readWireName: label exceeds 63 bytes')
    if (pos + 1 + len > packet.length) throw new Error('readWireName: truncated label')
    const label = packet.slice(pos, pos + 1 + len)
    labels.push(label)
    // RFC 1035 §3.1: octets of the full domain name (labels + length octets +
    // final zero) MUST NOT exceed 255 — count the root terminator too.
    nameLen += 1 + len
    if (nameLen + 1 > 255) throw new Error('readWireName: name exceeds 255 bytes')
    pos += 1 + len
  }

  if (!terminated) throw new Error('readWireName: unterminated name')
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

// ── Uncompressed domain name decoding ────────────────────────────────────────

/**
 * Decode a length-prefixed (uncompressed) DNS name from a Uint8Array.
 * Returns { fqdn: string, end: number } where end is the offset after the name.
 */
export function wireUnpackDomain(bytes, offset = 0) {
  const labels = []
  let pos = offset
  while (pos < bytes.length) {
    const len = bytes[pos]
    if (len === 0) {
      pos++
      break
    }
    labels.push(new TextDecoder().decode(bytes.subarray(pos + 1, pos + 1 + len)))
    pos += 1 + len
  }
  return { fqdn: labels.length ? labels.join('.') + '.' : '.', end: pos }
}

/**
 * Pack a fully qualified domain name into wire format (Uint8Array).
 * Domain labels are prefixed with their length; the name ends with a zero byte.
 */
export function wirePackDomain(fqdn) {
  if (fqdn === '.') return new Uint8Array([0])
  const enc = new TextEncoder()
  const labels = fqdn
    .split('.')
    .filter((p) => p.length > 0)
    .map((p) => {
      const b = enc.encode(p)
      if (b.length > 63) throw new Error(`DNS label exceeds 63 bytes: ${p}`)
      return b
    })

  const buf = new Uint8Array(labels.reduce((n, b) => n + b.length + 1, 1))
  let offset = 0
  for (const b of labels) {
    buf[offset++] = b.length
    buf.set(b, offset)
    offset += b.length
  }
  buf[offset] = 0
  return buf
}

/**
 * Pack a fully qualified domain name into wire format with RFC 1035 §4.1.4
 * name compression. `dict` is a `Map<suffix, offset>` shared across all names
 * emitted into a single outbound message; `currentOffset` is the absolute
 * offset at which the caller intends to place the returned bytes.
 *
 * Walks labels from longest suffix to shortest: when a suffix already has an
 * offset in `dict`, emits a 2-byte pointer and stops; otherwise emits the label
 * verbatim and records the new suffix offset for later reuse.
 */
export function wirePackDomainCompressed(fqdn, dict, currentOffset) {
  if (fqdn === '.') return new Uint8Array([0])
  const enc = new TextEncoder()
  const labels = fqdn
    .split('.')
    .filter((p) => p.length > 0)
    .map((p) => {
      const b = enc.encode(p)
      if (b.length > 63) throw new Error(`DNS label exceeds 63 bytes: ${p}`)
      return b
    })

  // Pre-compute the absolute write offset of each label and the suffix it begins.
  const suffixes = []
  let prefixBytes = 0
  for (let i = 0; i < labels.length; i++) {
    suffixes.push({
      key:
        labels
          .slice(i)
          .map((b) => new TextDecoder().decode(b))
          .join('.') + '.',
      writeOffset: currentOffset + prefixBytes,
    })
    prefixBytes += 1 + labels[i].length
  }

  // Find the longest existing suffix in the dict; everything to its right gets
  // replaced by a single pointer.
  let pointerAt = labels.length
  let pointerOffset = -1
  for (let i = 0; i < suffixes.length; i++) {
    const hit = dict.get(suffixes[i].key)
    if (hit !== undefined && hit < 0x4000) {
      pointerAt = i
      pointerOffset = hit
      break
    }
  }

  // Compute output size and allocate.
  let outSize = 0
  for (let i = 0; i < pointerAt; i++) outSize += 1 + labels[i].length
  outSize += pointerAt < labels.length ? 2 : 1 // pointer (2 bytes) or root terminator (1)
  const buf = new Uint8Array(outSize)

  let off = 0
  for (let i = 0; i < pointerAt; i++) {
    // Record this suffix for future reuse before writing past it.
    if (suffixes[i].writeOffset < 0x4000 && !dict.has(suffixes[i].key)) {
      dict.set(suffixes[i].key, suffixes[i].writeOffset)
    }
    buf[off++] = labels[i].length
    buf.set(labels[i], off)
    off += labels[i].length
  }
  if (pointerAt < labels.length) {
    buf[off++] = 0xc0 | ((pointerOffset >> 8) & 0x3f)
    buf[off] = pointerOffset & 0xff
  } else {
    buf[off] = 0
  }
  return buf
}

/**
 * Get wire format rdata for an RR instance.
 * Derived classes should override this with direct RFC 1035 wire encoding.
 * Fallback uses toTinydns() as an intermediate (less efficient but works for all types).
 */
export function getWireRdata(rrInstance) {
  const line = rrInstance.toTinydns()
  if (!line.startsWith(':')) {
    throw new Error(
      `${rrInstance.get('type')}: getWireRdata() not implemented. Override in rr/${rrInstance.get('type').toLowerCase()}.js`,
    )
  }
  // line: :fqdn:typeId:rdata:ttl:ts:loc\n
  // Extract octal-encoded rdata and decode
  const rdata = line.split(':')[3]
  return rrInstance.octalToUint8Array(rdata ?? '')
}

/**
 * Serialize an RR instance to DNS wire format (RFC 1035).
 * Combines owner name, type, class, TTL, and rdata.
 */
export function toWire(rrInstance) {
  const rdata = rrInstance.getWireRdata()
  const owner = wirePackDomain(rrInstance.get('owner'))
  const result = new Uint8Array(owner.length + 10 + rdata.length)
  result.set(owner, 0)
  const meta = new DataView(result.buffer, owner.length, 10)
  meta.setUint16(0, rrInstance.getTypeId())
  meta.setUint16(2, rrInstance.getClassId())
  meta.setUint32(4, rrInstance.get('ttl'))
  meta.setUint16(8, rdata.length)
  result.set(rdata, owner.length + 10)
  return result
}

/**
 * Deserialize wire format bytes into an RR instance.
 * Static method wrapper for RR.fromWire().
 */
export function fromWireBytes(RRConstructor, wireBytes, wireUnpackFn) {
  const instance = new RRConstructor(null)
  const bytes = wireBytes instanceof Uint8Array ? wireBytes : new Uint8Array(wireBytes)
  const { fqdn: owner, end } = wireUnpackFn(bytes, 0)
  if (end + 10 > bytes.length) throw new Error(`${RRConstructor.typeName}: truncated wire record`)
  const view = new DataView(bytes.buffer, bytes.byteOffset)
  const typeId = view.getUint16(end)
  if (RRConstructor.typeId !== undefined && typeId !== RRConstructor.typeId)
    throw new Error(
      `${RRConstructor.typeName}: wire type id ${typeId} does not match ${RRConstructor.typeId}`,
    )
  const classNum = view.getUint16(end + 2)
  const RRClasses = { IN: 1, CS: 2, CH: 3, HS: 4, NONE: 254, ANY: 255 }
  const cls = Object.keys(RRClasses).find((k) => RRClasses[k] === classNum) ?? `CLASS${classNum}` // RFC 3597 §5
  const ttl = view.getUint32(end + 4)
  const rdlen = view.getUint16(end + 8)
  if (end + 10 + rdlen !== bytes.length)
    throw new Error(
      `${RRConstructor.typeName}: RDLENGTH ${rdlen} does not match remaining ${bytes.length - end - 10} bytes`,
    )
  const rdata = bytes.slice(end + 10, end + 10 + rdlen)
  return instance.fromWire({ owner, cls, ttl, rdata, typeId })
}

/**
 * Generic fromWire decoder driven by rdataFields type annotations.
 * Supports u8, u16, u32, fqdn, hex, base64, str, qstr, charstr, qcharstr, charstrs, svcparams, ipv4, ipv6.
 * See rr/TEMPLATE.js for descriptions and example type usage.
 * Last typed field consumes all remaining bytes.
 */
export function fromWireGeneric(rrInstance, { owner, cls, ttl, rdata }) {
  const result = { owner, ttl, class: cls, type: rrInstance.constructor.typeName }
  const rdataFields = rrInstance.constructor.rdataFields ?? []
  const dv = new DataView(rdata.buffer, rdata.byteOffset)
  let pos = 0

  for (let i = 0; i < rdataFields.length; i++) {
    const entry = rdataFields[i]
    const fieldName = Array.isArray(entry) ? entry[0] : entry
    const fieldType = Array.isArray(entry) ? entry[1] : null

    switch (fieldType) {
      case 'u8':
        result[fieldName] = rdata[pos++]
        break
      case 'u16':
        result[fieldName] = dv.getUint16(pos)
        pos += 2
        break
      case 'certtype': {
        const certTypeNum = dv.getUint16(pos)
        const reverse = rrInstance.constructor.CERT_TYPES_REVERSE
        result[fieldName] = reverse?.[certTypeNum] ?? certTypeNum
        pos += 2
        break
      }
      case 'u32':
        result[fieldName] = dv.getUint32(pos)
        pos += 4
        break
      case 'fqdn': {
        const { fqdn, end } = wireUnpackDomain(rdata, pos)
        result[fieldName] = fqdn
        pos = end
        break
      }
      case 'hex':
        result[fieldName] = bytesToHex(rdata.subarray(pos)).toUpperCase()
        pos = rdata.length
        break
      case 'base64':
        result[fieldName] = bytesToBase64(rdata.subarray(pos))
        pos = rdata.length
        break
      case 'str':
        result[fieldName] = new TextDecoder().decode(rdata.subarray(pos))
        pos = rdata.length
        break
      case 'qstr':
        result[fieldName] = new TextDecoder().decode(rdata.subarray(pos))
        pos = rdata.length
        break
      case 'charstr': {
        const strLen = rdata[pos++]
        result[fieldName] = new TextDecoder().decode(rdata.subarray(pos, pos + strLen))
        pos += strLen
        break
      }
      case 'qcharstr': {
        const strLen = rdata[pos++]
        result[fieldName] = new TextDecoder().decode(rdata.subarray(pos, pos + strLen))
        pos += strLen
        break
      }
      case 'charstrs': {
        // RFC 1035 §3.3.14: each <character-string> on the wire is len-prefixed.
        // Preserve multi-string boundaries by returning an array when >1.
        const parts = []
        while (pos < rdata.length) {
          const strLen = rdata[pos++]
          if (pos + strLen > rdata.length) {
            throw new Error('fromWireGeneric: truncated character-string in rdata')
          }
          parts.push(new TextDecoder().decode(rdata.subarray(pos, pos + strLen)))
          pos += strLen
        }
        result[fieldName] = parts.length > 1 ? parts : (parts[0] ?? '')
        break
      }
      case 'svcparams':
        result[fieldName] = svcParamsFromWire(rdata.subarray(pos))
        pos = rdata.length
        break
      case 'ipv4':
        result[fieldName] = [...rdata.subarray(pos, pos + 4)].join('.')
        pos += 4
        break
      case 'ipv6': {
        const parts = []
        for (let j = 0; j < 16; j += 2) {
          parts.push(
            dv
              .getUint16(pos + j)
              .toString(16)
              .padStart(4, '0'),
          )
        }
        result[fieldName] = parts.join(':')
        pos += 16
        break
      }
      default:
        result[fieldName] = rdata[pos++]
        break
    }
  }

  return new rrInstance.constructor(result)
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

const SVCPARAM_KEY_NAMES = {
  0: 'mandatory',
  1: 'alpn',
  2: 'no-default-alpn',
  3: 'port',
  4: 'ipv4hint',
  5: 'ech',
  6: 'ipv6hint',
}

/**
 * Decode SVCB/HTTPS wire params bytes back to a human-readable params string.
 */
export function svcParamsFromWire(bytes) {
  if (!bytes || bytes.length === 0) return ''
  const parts = []
  let pos = 0
  while (pos + 4 <= bytes.length) {
    const dv = new DataView(bytes.buffer, bytes.byteOffset + pos)
    const keyId = dv.getUint16(0)
    const valLen = dv.getUint16(2)
    const val = bytes.subarray(pos + 4, pos + 4 + valLen)
    pos += 4 + valLen

    const keyName = SVCPARAM_KEY_NAMES[keyId] ?? `key${keyId}`
    if (keyId === 1) {
      // alpn: comma-separated length-prefixed entries
      const entries = []
      let p = 0
      while (p < val.length) {
        const len = val[p++]
        entries.push(new TextDecoder().decode(val.subarray(p, p + len)))
        p += len
      }
      parts.push(`alpn="${entries.join(',')}"`)
    } else if (keyId === 2) {
      parts.push('no-default-alpn')
    } else if (keyId === 3) {
      parts.push(`port=${new DataView(val.buffer, val.byteOffset).getUint16(0)}`)
    } else if (keyId === 4) {
      const addrs = []
      for (let i = 0; i < val.length; i += 4) addrs.push([...val.subarray(i, i + 4)].join('.'))
      parts.push(`ipv4hint=${addrs.join(',')}`)
    } else if (keyId === 5) {
      parts.push(`ech=${btoa([...val].map((b) => String.fromCharCode(b)).join(''))}`)
    } else if (keyId === 6) {
      const addrs = []
      for (let i = 0; i < val.length; i += 16) {
        const dv16 = new DataView(val.buffer, val.byteOffset + i)
        const groups = []
        for (let j = 0; j < 16; j += 2) groups.push(dv16.getUint16(j).toString(16).padStart(4, '0'))
        addrs.push(groups.join(':'))
      }
      parts.push(`ipv6hint=${addrs.join(',')}`)
    } else {
      parts.push(`${keyName}=${[...val].map((b) => b.toString(16).padStart(2, '0')).join('')}`)
    }
  }
  return parts.join(' ')
}
