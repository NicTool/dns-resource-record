export function hexToBytes(hex) {
  return Uint8Array.from({ length: hex.length / 2 }, (_, i) => parseInt(hex.slice(i * 2, i * 2 + 2), 16))
}

export function bytesToHex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('')
}

export function bytesToBase64(bytes) {
  return btoa([...bytes].map((b) => String.fromCharCode(b)).join(''))
}

export function base64ToBytes(b64) {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0))
}

// DNS type name → numeric type ID mapping (subset covering known RR types)
export const DNS_TYPE_IDS = {
  A: 1,
  NS: 2,
  MD: 3,
  MF: 4,
  CNAME: 5,
  SOA: 6,
  MB: 7,
  MG: 8,
  MR: 9,
  NULL: 10,
  WKS: 11,
  PTR: 12,
  HINFO: 13,
  MINFO: 14,
  MX: 15,
  TXT: 16,
  RP: 17,
  AFSDB: 18,
  X25: 19,
  ISDN: 20,
  RT: 21,
  NSAP: 22,
  NSAP_PTR: 23, // input-only alias; IANA registers the hyphenated form
  'NSAP-PTR': 23,
  SIG: 24,
  KEY: 25,
  PX: 26,
  GPOS: 27,
  AAAA: 28,
  LOC: 29,
  NXT: 30,
  EID: 31,
  NIMLOC: 32,
  SRV: 33,
  ATMA: 34,
  NAPTR: 35,
  KX: 36,
  CERT: 37,
  A6: 38,
  DNAME: 39,
  SINK: 40,
  OPT: 41,
  APL: 42,
  DS: 43,
  SSHFP: 44,
  IPSECKEY: 45,
  RRSIG: 46,
  NSEC: 47,
  DNSKEY: 48,
  DHCID: 49,
  NSEC3: 50,
  NSEC3PARAM: 51,
  TLSA: 52,
  SMIMEA: 53,
  HIP: 55,
  NINFO: 56,
  RKEY: 57,
  TALINK: 58,
  CDS: 59,
  CDNSKEY: 60,
  OPENPGPKEY: 61,
  CSYNC: 62,
  ZONEMD: 63,
  SVCB: 64,
  HTTPS: 65,
  SPF: 99,
  UINFO: 100,
  UID: 101,
  GID: 102,
  UNSPEC: 103,
  NID: 104,
  L32: 105,
  L64: 106,
  LP: 107,
  EUI48: 108,
  EUI64: 109,
  TKEY: 249,
  TSIG: 250,
  IXFR: 251,
  AXFR: 252,
  MAILB: 253,
  MAILA: 254,
  ANY: 255,
  URI: 256,
  CAA: 257,
  AVC: 258,
  DOA: 259,
  AMTRELAY: 260,
  TA: 32768,
  DLV: 32769,
}

const DNS_TYPE_NAMES = Object.fromEntries(Object.entries(DNS_TYPE_IDS).map(([k, v]) => [v, k]))

// 'MX' | 'TYPE123' (RFC 3597 §5) | '123' | 123  ->  numeric type id
export function typeNameToId(type) {
  let id
  if (typeof type === 'number') {
    id = type
  } else if (typeof type === 'string') {
    const t = type.toUpperCase()
    const typeNN = t.match(/^TYPE(\d+)$/)
    if (typeNN) id = parseInt(typeNN[1], 10)
    else if (/^\d+$/.test(t)) id = parseInt(t, 10)
    else id = DNS_TYPE_IDS[t]
  }
  if (!Number.isInteger(id) || id < 0 || id > 65535) throw new Error(`invalid DNS type: ${String(type)}`)
  return id
}

// 15 -> 'MX', 731 -> 'TYPE731' (RFC 3597 §5)
export function typeIdToName(id) {
  if (!Number.isInteger(id) || id < 0 || id > 65535) throw new Error(`invalid DNS type id: ${String(id)}`)
  return DNS_TYPE_NAMES[id] ?? `TYPE${id}`
}

// RFC 4034 §4.1.2 type bit maps, shared by NSEC and NSEC3.
export function typesToBitmap(typeNames) {
  const windows = new Map()
  for (const name of typeNames.trim().split(/\s+/).filter(Boolean)) {
    const id = typeNameToId(name)
    const w = Math.floor(id / 256)
    if (!windows.has(w)) windows.set(w, [])
    windows.get(w).push(id % 256)
  }

  const blocks = []
  for (const [wNum, bits] of [...windows.entries()].sort((a, b) => a[0] - b[0])) {
    const bitmapLen = Math.floor(Math.max(...bits) / 8) + 1
    const bitmap = new Uint8Array(bitmapLen)
    for (const b of bits) bitmap[Math.floor(b / 8)] |= 0x80 >> (b % 8)
    blocks.push(Uint8Array.from([wNum, bitmapLen, ...bitmap]))
  }

  const result = new Uint8Array(blocks.reduce((s, b) => s + b.length, 0))
  let pos = 0
  for (const b of blocks) {
    result.set(b, pos)
    pos += b.length
  }
  return result
}

export function bitmapToTypes(bitmap) {
  const types = []
  let pos = 0
  while (pos + 2 <= bitmap.length) {
    const windowNum = bitmap[pos]
    const bitmapLen = bitmap[pos + 1]
    pos += 2
    for (let i = 0; i < bitmapLen; i++) {
      for (let bit = 0; bit < 8; bit++) {
        if (bitmap[pos + i] & (0x80 >> bit)) types.push(typeIdToName(windowNum * 256 + i * 8 + bit))
      }
    }
    pos += bitmapLen
  }
  return types.join(' ')
}

// RFC 4648 §7 base32hex, unpadded, as NSEC3 presents hashed owner names.
const BASE32HEX = '0123456789abcdefghijklmnopqrstuv'

export function base32hexToBytes(str) {
  const bytes = []
  let value = 0
  let bits = 0
  for (const c of str.toLowerCase()) {
    const v = BASE32HEX.indexOf(c)
    if (v === -1) throw new Error(`invalid base32hex: ${str}`)
    value = (value << 5) | v
    bits += 5
    if (bits >= 8) {
      bits -= 8
      bytes.push((value >> bits) & 0xff)
      value &= (1 << bits) - 1
    }
  }
  return Uint8Array.from(bytes)
}

export function bytesToBase32hex(bytes) {
  let out = ''
  let value = 0
  let bits = 0
  for (const b of bytes) {
    value = (value << 8) | b
    bits += 8
    while (bits >= 5) {
      bits -= 5
      out += BASE32HEX[(value >> bits) & 31]
      value &= (1 << bits) - 1
    }
  }
  if (bits > 0) out += BASE32HEX[(value << (5 - bits)) & 31]
  return out
}
