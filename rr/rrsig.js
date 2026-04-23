import RR from '../rr.js'
import * as TINYDNS from '../lib/tinydns.js'
import * as WIRE from '../lib/binary.js'
import * as WIRELIB from '../lib/wire.js'

export default class RRSIG extends RR {
  static typeName = 'RRSIG'
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setTypeCovered(val) {
    // a 16-bit Type Covered field (RFC 4034 §3.1.1)
    if (!val && val !== 0) this.throwHelp(`RRSIG: 'type covered' is required`)
    if (typeof val === 'string') {
      const typeNN = val.match(/^TYPE(\d+)$/i)
      if (typeNN) {
        val = parseInt(typeNN[1], 10)
      } else {
        const id = WIRE.DNS_TYPE_IDS[val.toUpperCase()]
        if (id === undefined) this.throwHelp(`RRSIG: 'type covered' is not a recognized type name`)
        val = id
      }
    }
    this.is16bitInt('RRSIG', 'type covered', val)
    this.set('type covered', val)
  }

  setAlgorithm(val) {
    // a 1 octet Algorithm field
    if (!this.getAlgorithmOptions().has(val)) this.throwHelp(`RRSIG: algorithm invalid`)

    this.set('algorithm', val)
  }

  getAlgorithmOptions() {
    return new Map([
      [1, 'RSA/MD5'],
      [2, 'DH'],
      [3, 'RRSIGA/SHA-1'],
      [4, 'EC'],
      [5, 'RSA/SHA-1'],
      [253],
      [254],
    ])
  }

  setLabels(val) {
    // a 1 octet Labels field
    this.is8bitInt('RRSIG', 'labels', val)

    this.set('labels', val)
  }

  setOriginalTtl(val) {
    // a 4 octet Original TTL field
    this.is32bitInt('RRSIG', 'original ttl', val)

    this.set('original ttl', val)
  }

  setSignatureExpiration(val) {
    // a 4 octet Signature Expiration field
    this.set('signature expiration', val)
  }

  setSignatureInception(val) {
    // a 4 octet Signature Inception field
    this.set('signature inception', val)
  }

  setKeyTag(val) {
    // a 2 octet Key tag
    this.set('key tag', val)
  }

  setSignersName(val) {
    // the Signer's Name field
    this.set('signers name', val)
  }

  setSignature(val) {
    // the Signature field.

    this.set('signature', val)
  }

  getDescription() {
    return 'Resource Record Signature'
  }

  getTags() {
    return ['dnssec']
  }

  getRdataFields(arg) {
    return [
      'type covered',
      'algorithm',
      'labels',
      'original ttl',
      'signature expiration',
      'signature inception',
      'key tag',
      'signers name',
      'signature',
    ]
  }

  getRFCs() {
    return [4034]
  }

  getTypeId() {
    return 46
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'RRSIG',
      'type covered': 1,
      algorithm: 5,
      labels: 3,
      'original ttl': 3600,
      'signature expiration': 1045053120,
      'signature inception': 1042461120,
      'key tag': 12345,
      'signers name': 'example.com.',
      signature: 'ABCDEF...',
    }
  }

  /******  IMPORTERS   *******/

  fromBind({ bindline }) {
    // example.com. 3600 IN RRSIG typecovered algorithm labels origttl sigexp siginc keytag signersname ( signature )
    const parts = bindline.trim().split(/\s+/)
    const typeCoveredStr = parts[4]
    // type covered may be a type name ('A', 'MX'), TYPEnn (RFC 3597), or a numeric ID
    const typeNN = typeCoveredStr.match(/^TYPE(\d+)$/i)
    const typeCovered = /^\d+$/.test(typeCoveredStr)
      ? parseInt(typeCoveredStr, 10)
      : typeNN
        ? parseInt(typeNN[1], 10)
        : (WIRE.DNS_TYPE_IDS[typeCoveredStr.toUpperCase()] ?? parseInt(typeCoveredStr, 10))
    return new RRSIG({
      owner: parts[0],
      ttl: parseInt(parts[1], 10),
      class: parts[2],
      type: 'RRSIG',
      'type covered': typeCovered,
      algorithm: parseInt(parts[5], 10),
      labels: parseInt(parts[6], 10),
      'original ttl': parseInt(parts[7], 10),
      'signature expiration': parseInt(parts[8], 10),
      'signature inception': parseInt(parts[9], 10),
      'key tag': parseInt(parts[10], 10),
      'signers name': parts[11],
      signature: parts
        .slice(12)
        .filter((a) => a !== '(' && a !== ')')
        .join(' ')
        .trim(),
    })
  }

  fromTinydns({ tinyline }) {
    const [fqdn, n, rdata, ttl, ts, loc] = tinyline.slice(1).split(':')
    if (parseInt(n, 10) !== this.getTypeId()) this.throwHelp('RRSIG fromTinydns, invalid n')

    const bytes = Uint8Array.from(TINYDNS.octalToChar(rdata), (c) => c.charCodeAt(0))
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
    const typeCovered = dv.getUint16(0)
    const algorithm = bytes[2]
    const labels = bytes[3]
    const originalTtl = dv.getUint32(4)
    const signatureExpiration = dv.getUint32(8)
    const signatureInception = dv.getUint32(12)
    const keyTag = dv.getUint16(16)

    let pos = 18
    const labelArr = []
    while (pos < bytes.length) {
      const len = bytes[pos++]
      if (len === 0) break
      labelArr.push(new TextDecoder().decode(bytes.subarray(pos, pos + len)))
      pos += len
    }
    const signersName = `${labelArr.join('.')}.`
    const signature = new TextDecoder().decode(bytes.subarray(pos))

    return new RRSIG({
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'RRSIG',
      'type covered': typeCovered,
      algorithm,
      labels,
      'original ttl': originalTtl,
      'signature expiration': signatureExpiration,
      'signature inception': signatureInception,
      'key tag': keyTag,
      'signers name': signersName,
      signature,
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  fromWire({ owner, cls, ttl, rdata }) {
    const dv = new DataView(rdata.buffer, rdata.byteOffset)
    const typeCovered = dv.getUint16(0)
    const algorithm = rdata[2]
    const labels = rdata[3]
    const originalTtl = dv.getUint32(4)
    const signatureExpiration = dv.getUint32(8)
    const signatureInception = dv.getUint32(12)
    const keyTag = dv.getUint16(16)
    const { fqdn: signersName, end } = this.wireUnpackDomain(rdata, 18)
    const signature = new TextDecoder().decode(rdata.subarray(end))
    return new RRSIG({
      owner,
      ttl,
      class: cls,
      type: 'RRSIG',
      'type covered': typeCovered,
      algorithm,
      labels,
      'original ttl': originalTtl,
      'signature expiration': signatureExpiration,
      'signature inception': signatureInception,
      'key tag': keyTag,
      'signers name': signersName,
      signature,
    })
  }

  /******  EXPORTERS   *******/
  toBind(zone_opts) {
    return `${this.getPrefix(zone_opts)}\t${this.get('type covered')}\t${this.get('algorithm')}\t${this.get('labels')}\t${this.get('original ttl')}\t${this.get('signature expiration')}\t${this.get('signature inception')}\t${this.get('key tag')}\t${this.getFQDN('signers name', zone_opts)}\t${this.get('signature')}\n`
  }

  toTinydns() {
    const dataRe = new RegExp(/[\r\n\t:]/, 'g')
    return this.getTinydnsGeneric(
      TINYDNS.UInt16toOctal(this.get('type covered')) +
        TINYDNS.UInt8toOctal(this.get('algorithm')) +
        TINYDNS.UInt8toOctal(this.get('labels')) +
        TINYDNS.UInt32toOctal(this.get('original ttl')) +
        TINYDNS.UInt32toOctal(this.get('signature expiration')) +
        TINYDNS.UInt32toOctal(this.get('signature inception')) +
        TINYDNS.UInt16toOctal(this.get('key tag')) +
        TINYDNS.packDomainName(this.get('signers name')) +
        TINYDNS.escapeOctal(dataRe, this.get('signature')),
    )
  }

  getWireRdata() {
    const signerBytes = WIRELIB.wirePackDomain(this.get('signers name'))
    const sigBytes = new TextEncoder().encode(this.get('signature'))

    const totalLen = 2 + 1 + 1 + 4 + 4 + 4 + 2 + signerBytes.length + sigBytes.length
    const bytes = new Uint8Array(totalLen)
    const dv = new DataView(bytes.buffer, bytes.byteOffset)

    let pos = 0
    dv.setUint16(pos, this.get('type covered'))
    pos += 2
    bytes[pos++] = this.get('algorithm')
    bytes[pos++] = this.get('labels')
    dv.setUint32(pos, this.get('original ttl'))
    pos += 4
    dv.setUint32(pos, this.get('signature expiration'))
    pos += 4
    dv.setUint32(pos, this.get('signature inception'))
    pos += 4
    dv.setUint16(pos, this.get('key tag'))
    pos += 2
    bytes.set(signerBytes, pos)
    pos += signerBytes.length
    bytes.set(sigBytes, pos)

    return bytes
  }
}
