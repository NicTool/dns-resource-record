import RR from '../rr.js'

import * as TINYDNS from '../lib/tinydns.js'

export default class NSEC3 extends RR {
  static typeName = 'NSEC3'
  constructor(opts) {
    super(opts)
    if (opts === null) return
  }

  /****** Resource record specific setters   *******/
  setHashAlgorithm(val) {
    // Hash Algorithm is a single octet.
    // The Hash Algorithm field is represented as an unsigned decimal integer.
    if (!val) this.throwHelp(`NSEC3: 'hash algorithm' is required`)

    this.is8bitInt('NSEC3', 'hash algorithm', val)

    this.set('hash algorithm', val)
  }

  setFlags(val) {
    // The Flags field is represented as an unsigned decimal integer.
    if (!val) this.throwHelp(`NSEC3: 'flags' is required`)

    this.is8bitInt('NSEC3', 'flags', val)

    this.set('flags', val)
  }

  setIterations(val) {
    // The Iterations field is represented as an unsigned decimal integer. 0-65535
    if (!val) this.throwHelp(`NSEC3: 'iterations' is required`)

    this.is16bitInt('NSEC3', 'flags', val)

    this.set('iterations', val)
  }

  setSalt(val) {
    // The Salt field is represented as a sequence of case-insensitive
    // hexadecimal digits.  Whitespace is not allowed within the
    // sequence.  The Salt field is represented as "-" (without the
    // quotes) when the Salt Length field has a value of 0
    this.set('salt', val)
  }

  setNextHashedOwnerName(val) {
    // The Next Hashed Owner Name field is represented as an unpadded
    // sequence of case-insensitive base32 digits, without whitespace
    if (!val) this.throwHelp(`NSEC3: 'next hashed owner name' is required`)

    this.set('next hashed owner name', val)
  }

  setTypeBitMaps(val) {
    // The Type Bit Maps field is represented as a sequence of RR type mnemonics.
    if (!val) this.throwHelp(`NSEC3: 'type bit maps' is required`)

    this.set('type bit maps', val)
  }

  getDescription() {
    return 'Next Secure'
  }

  getTags() {
    return ['dnssec']
  }

  getRdataFields(arg) {
    return ['hash algorithm', 'flags', 'iterations', 'salt', 'next hashed owner name', 'type bit maps']
  }

  getRFCs() {
    return [5155, 9077]
  }

  getTypeId() {
    return 50
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

  fromBind({ bindline }) {
    // test.example.com. 3600 IN NSEC3 1 1 12 aabbccdd (2vptu5timamqttgl4luu9kg21e0aor3s A RRSIG)
    const [owner, ttl, c, type, ha, flags, iterations, salt] = bindline.split(/\s+/)
    // rdata may be parenthesized or inline
    const rdataStr = bindline.includes('(')
      ? bindline.split(/\(|\)/)[1]
      : bindline.split(/\s+/).slice(8).join(' ')

    return new NSEC3({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type: type,
      'hash algorithm': parseInt(ha, 10),
      flags: parseInt(flags, 10),
      iterations: parseInt(iterations, 10),
      salt,
      'next hashed owner name': rdataStr.trim().split(/\s+/)[0],
      'type bit maps': rdataStr.trim().split(/\s+/).slice(1).join('\t'),
    })
  }

  fromTinydns({ tinyline }) {
    const [fqdn, n, rdata, ttl, ts, loc] = tinyline.slice(1).split(':')
    if (n != 50) this.throwHelp('NSEC3 fromTinydns, invalid n')

    const bytes = Uint8Array.from(TINYDNS.octalToChar(rdata), (c) => c.charCodeAt(0))
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)

    const hashAlgorithm = bytes[0]
    const flags = bytes[1]
    const iterations = dv.getUint16(2)

    // The remaining bytes in the buffer contain:
    // Salt Length (1 octet)
    // Salt (variable length based on Salt Length)
    // Next Hashed Owner Name (variable length)
    // Type Bit Maps (variable length)
    const { salt, nextHashedOwnerName, typeBitMaps } = parseNSEC3Buffer(bytes)

    return new NSEC3({
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'NSEC3',
      'hash algorithm': hashAlgorithm,
      flags: flags,
      iterations: iterations,
      salt: salt,
      'next hashed owner name': nextHashedOwnerName,
      'type bit maps': typeBitMaps,
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  fromWire({ owner, cls, ttl, rdata }) {
    const dv = new DataView(rdata.buffer, rdata.byteOffset)
    const { salt, nextHashedOwnerName, typeBitMaps } = parseNSEC3Buffer(rdata)
    return new NSEC3({
      owner,
      ttl,
      class: cls,
      type: 'NSEC3',
      'hash algorithm': rdata[0],
      flags: rdata[1],
      iterations: dv.getUint16(2),
      salt,
      'next hashed owner name': nextHashedOwnerName,
      'type bit maps': typeBitMaps,
    })
  }

  /******  EXPORTERS   *******/

  toBind(zone_opts) {
    return `${this.getFQDN('owner', zone_opts)}	${this.get('ttl')}	${this.get('class')}	NSEC3${this.getRdataFields()
      .slice(0, 4)
      .map((f) => '	' + this.get(f))
      .join('')}	(${this.getRdataFields()
      .slice(4)
      .map((f) => this.get(f))
      .join('	')})
`
  }

  toTinydns() {
    const dataRe = new RegExp(/[\r\n\t:\\/]/, 'g')

    return this.getTinydnsGeneric(
      TINYDNS.UInt8toOctal(this.get('hash algorithm')) +
        TINYDNS.UInt8toOctal(this.get('flags')) +
        TINYDNS.UInt16toOctal(this.get('iterations')) +
        TINYDNS.escapeOctal(dataRe, this.get('salt')) +
        TINYDNS.escapeOctal(dataRe, this.get('next hashed owner name')) +
        TINYDNS.escapeOctal(dataRe, this.get('type bit maps')),
    )
  }

  getWireRdata() {
    const tail = `${this.get('salt')}${this.get('next hashed owner name')}${this.get('type bit maps')}`
    const tailBytes = new TextEncoder().encode(tail)

    const totalLen = 4 + tailBytes.length
    const bytes = new Uint8Array(totalLen)
    const dv = new DataView(bytes.buffer, bytes.byteOffset)

    let pos = 0
    bytes[pos++] = this.get('hash algorithm')
    bytes[pos++] = this.get('flags')
    dv.setUint16(pos, this.get('iterations'))
    pos += 2
    bytes.set(tailBytes, pos)

    return bytes
  }
}

function parseNSEC3Buffer(bytes) {
  // bytes is a Uint8Array containing the full RDATA binary (hash alg, flags, iterations, then ASCII salt + next-hashed + type bit maps)
  // Start after the first 4 bytes (hash alg, flags, iterations)
  const rest = new TextDecoder().decode(bytes.subarray(4))

  // determine expected next hashed owner name length from hash algorithm
  const hashAlgorithm = bytes[0]
  // common mapping: algorithm 1 => SHA-1 => 20 bytes => base32 length 32
  const expectedLen = hashAlgorithm === 1 ? 32 : hashAlgorithm === 2 ? 52 : 32

  // salt length is ambiguous in this representation; try to find a split where
  // the following segment matches expected base32 length
  let salt = ''
  let nextHashedOwnerName = ''
  let typeBitMaps = ''

  const maxSl = Math.min(64, rest.length)
  for (let sl = maxSl; sl >= 1; sl--) {
    const candNext = rest.slice(sl, sl + expectedLen)
    if (candNext.length !== expectedLen) continue
    if (!/^[0-9a-z]+$/.test(candNext)) continue
    // candidate looks like a base32 name; accept and treat remainder as type bit maps
    const saltCandidate = rest.slice(0, sl)
    if (!/^[0-9A-Fa-f]+$/.test(saltCandidate)) continue
    salt = saltCandidate
    nextHashedOwnerName = candNext
    typeBitMaps = rest.slice(sl + expectedLen)
    break
  }

  // fallback: if we couldn't find a split, treat everything up to first non-hex as salt
  if (!nextHashedOwnerName) {
    const saltMatch = rest.match(/^([0-9A-Fa-f]*)/)
    salt = saltMatch ? saltMatch[1] : ''
    nextHashedOwnerName = rest.slice(salt.length)
    typeBitMaps = ''
  }

  return {
    salt,
    nextHashedOwnerName,
    typeBitMaps,
  }
}
