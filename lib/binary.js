import { expandIPv6 } from './tinydns.js'

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
  NSAP_PTR: 23,
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

// SVCB/HTTPS SvcParamKey numeric codes (RFC 9460)
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
