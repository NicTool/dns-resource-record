import RR from '../rr.js'
import * as TINYDNS from '../lib/tinydns.js'

export default class RRSIG extends RR {
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setTypeCovered(val) {
    // a 2 octet Type Covered field
    if (!val) this.throwHelp(`RRSIG: 'type covered' is required`)
    if (val.length > 2) this.throwHelp(`RRSIG: 'type covered' is too long`)

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
    return new RRSIG({
      owner: parts[0],
      ttl: parseInt(parts[1], 10),
      class: parts[2],
      type: 'RRSIG',
      'type covered': parseInt(parts[4], 10),
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

    const bytes = Buffer.from(TINYDNS.octalToChar(rdata), 'binary')
    const typeCovered = bytes.readUInt16BE(0)
    const algorithm = bytes.readUInt8(2)
    const labels = bytes.readUInt8(3)
    const originalTtl = bytes.readUInt32BE(4)
    const signatureExpiration = bytes.readUInt32BE(8)
    const signatureInception = bytes.readUInt32BE(12)
    const keyTag = bytes.readUInt16BE(16)

    let pos = 18
    const labelArr = []
    while (pos < bytes.length) {
      const len = bytes.readUInt8(pos++)
      if (len === 0) break
      labelArr.push(bytes.slice(pos, pos + len).toString())
      pos += len
    }
    const signersName = `${labelArr.join('.')}.`
    const signature = bytes.slice(pos).toString()

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
}
