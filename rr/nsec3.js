import RR from '../rr.js'

import * as BINARY from '../lib/binary.js'

export default class NSEC3 extends RR {
  static typeName = 'NSEC3'
  static typeId = 50
  static RFCs = [5155, 9077]
  static rdataFields = [
    'hash algorithm',
    'flags',
    'iterations',
    'salt',
    'next hashed owner name',
    ['type bit maps', 'list'],
  ]
  static tags = ['dnssec']

  constructor(opts) {
    super(opts)
    if (opts === null) return
  }

  /****** Resource record specific setters   *******/
  setHashAlgorithm(val) {
    if (val === undefined) this.throwHelp(`NSEC3: 'hash algorithm' is required`)
    this.is8bitInt('NSEC3', 'hash algorithm', val)
    this.set('hash algorithm', val)
  }

  setFlags(val) {
    if (val === undefined) this.throwHelp(`NSEC3: 'flags' is required`)
    this.is8bitInt('NSEC3', 'flags', val)
    this.set('flags', val)
  }

  setIterations(val) {
    if (val === undefined) this.throwHelp(`NSEC3: 'iterations' is required`)
    this.is16bitInt('NSEC3', 'iterations', val)
    this.set('iterations', val)
  }

  setSalt(val) {
    // RFC 5155 §3.3: case-insensitive hex, or "-" for an empty salt.
    if (val === undefined || val === '') this.throwHelp(`NSEC3: 'salt' is required, "-" when empty`)
    if (val !== '-' && !/^([0-9a-fA-F]{2}){1,255}$/.test(val))
      this.throwHelp(`NSEC3: 'salt' must be hex octets or "-"`)
    this.set('salt', val.toLowerCase())
  }

  setNextHashedOwnerName(val) {
    // RFC 5155 §3.3: unpadded, case-insensitive base32hex.
    if (!val) this.throwHelp(`NSEC3: 'next hashed owner name' is required`)
    if (!/^[0-9a-vA-V]+$/.test(val)) this.throwHelp(`NSEC3: 'next hashed owner name' must be base32hex`)
    const bytes = BINARY.base32hexToBytes(val).length
    // RFC 5155 §3.2: the Hash Length field is one octet
    if (bytes < 1 || bytes > 255)
      this.throwHelp(`NSEC3: 'next hashed owner name' must be 1-255 bytes, got ${bytes}`)
    // RFC 5155 §11: algorithm 1 is SHA-1, a 20-byte hash
    if (this.get('hash algorithm') === 1 && bytes !== 20)
      this.throwHelp(`NSEC3: a SHA-1 'next hashed owner name' is 20 bytes, got ${bytes}`)
    this.set('next hashed owner name', val.toLowerCase())
  }

  setTypeBitMaps(val) {
    // RFC 5155 §3.2: an empty non-terminal has no types.
    this.set('type bit maps', val ?? '')
  }

  getDescription() {
    return 'Next Secure'
  }

  getCanonical() {
    return {
      owner: 'test.example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'NSEC3',
      'hash algorithm': 1,
      flags: 1,
      iterations: 12,
      salt: 'aabbccdd',
      'next hashed owner name': '2vptu5timamqttgl4luu9kg21e0aor3s',
      'type bit maps': 'A RRSIG',
    }
  }

  /******  IMPORTERS   *******/

  fromWire({ owner, cls, ttl, rdata }) {
    return new NSEC3({ ...unpackRdata(rdata), owner, ttl, class: cls, type: 'NSEC3' })
  }

  /******  EXPORTERS   *******/

  // RFC 5155 §3.2: the salt and hash are length-prefixed binary.
  getWireRdata() {
    const salt = this.get('salt') === '-' ? new Uint8Array(0) : BINARY.hexToBytes(this.get('salt'))
    const hash = BINARY.base32hexToBytes(this.get('next hashed owner name'))
    const bitmap = BINARY.typesToBitmap(this.get('type bit maps'))

    const bytes = new Uint8Array(4 + 1 + salt.length + 1 + hash.length + bitmap.length)
    let pos = 0
    bytes[pos++] = this.get('hash algorithm')
    bytes[pos++] = this.get('flags')
    new DataView(bytes.buffer).setUint16(pos, this.get('iterations'))
    pos += 2
    bytes[pos++] = salt.length
    bytes.set(salt, pos)
    pos += salt.length
    bytes[pos++] = hash.length
    bytes.set(hash, pos)
    pos += hash.length
    bytes.set(bitmap, pos)
    return bytes
  }
}

function unpackRdata(bytes) {
  const saltLen = bytes[4]
  const hashLenAt = 5 + saltLen
  if (bytes.length < 5 || hashLenAt >= bytes.length)
    throw new Error('NSEC3: rdata is truncated before the hash')
  const hashLen = bytes[hashLenAt]
  const hashStart = hashLenAt + 1
  if (hashLen === 0 || hashStart + hashLen > bytes.length)
    throw new Error('NSEC3: hash length does not fit the rdata')
  return {
    'hash algorithm': bytes[0],
    flags: bytes[1],
    iterations: new DataView(bytes.buffer, bytes.byteOffset).getUint16(2),
    salt: saltLen ? BINARY.bytesToHex(bytes.subarray(5, hashLenAt)) : '-',
    'next hashed owner name': BINARY.bytesToBase32hex(bytes.subarray(hashStart, hashStart + hashLen)),
    'type bit maps': BINARY.bitmapToTypes(bytes.subarray(hashStart + hashLen)),
  }
}
