import RR from '../rr.js'

import * as TINYDNS from '../lib/tinydns.js'
import * as WIRE from '../lib/binary.js'
import * as WIRELIB from '../lib/wire.js'

export default class SIG extends RR {
  static typeName = 'SIG'
  static rdataFields = [
    ['type covered', 'u16'],
    ['algorithm', 'u8'],
    ['labels', 'u8'],
    ['original ttl', 'u32'],
    ['signature expiration', 'u32'],
    ['signature inception', 'u32'],
    ['key tag', 'u16'],
    ['signers name', 'fqdn'],
    ['signature', 'str'],
  ]
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setTypeCovered(val) {
    // a 2 octet Type Covered field
    if (!val) this.throwHelp(`SIG: 'type covered' is required`)

    this.set('type covered', val)
  }

  setAlgorithm(val) {
    // a 1 octet Algorithm field
    this.is8bitInt('SIG', 'algorithm', val)

    this.set('algorithm', val)
  }

  setLabels(val) {
    // a 1 octet Labels field
    this.is8bitInt('SIG', 'labels', val)

    this.set('labels', val)
  }

  setOriginalTtl(val) {
    // a 4 octet Original TTL field
    this.is32bitInt('SIG', 'original ttl', val)

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
    // the domain name of the signer generating the SIG RR

    // RFC 4034: letters in the DNS names are lower cased
    this.set('signers name', val.toLowerCase())
  }

  setSignature(val) {
    // the Signature field.

    this.set('signature', val)
  }

  getDescription() {
    return 'Signature'
  }
  static tags = ['obsolete']
  static RFCs = [2535, 3755]
  static typeId = 24
  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'SIG',
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
    // example.com. 3600 IN SIG TypeCovered Algorithm Labels OrigTTL SigExpiration SigInception KeyTag SignersName ( Signature )
    const parts = bindline.trim().split(/\s+/)
    const typeCoveredStr = parts[4]
    const typeCovered = /^\d+$/.test(typeCoveredStr)
      ? parseInt(typeCoveredStr, 10)
      : (WIRE.DNS_TYPE_IDS[typeCoveredStr.toUpperCase()] ?? parseInt(typeCoveredStr, 10))

    return new SIG({
      owner: parts[0],
      ttl: parseInt(parts[1], 10),
      class: parts[2],
      type: 'SIG',
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

  /******  EXPORTERS   *******/
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

  fromTinydns({ tinyline }) {
    const [fqdn, n, rdata, ttl, ts, loc] = tinyline.substring(1).split(':')
    if (parseInt(n, 10) !== this.getTypeId()) this.throwHelp('SIG fromTinydns, invalid n')

    const bytes = Uint8Array.from(TINYDNS.octalToChar(rdata), (c) => c.charCodeAt(0))
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)

    const typeCovered = dv.getUint16(0)
    const algorithm = bytes[2]
    const labels = bytes[3]
    const originalTtl = dv.getUint32(4)
    const signatureExpiration = dv.getUint32(8)
    const signatureInception = dv.getUint32(12)
    const keyTag = dv.getUint16(16)

    // parse signers name from binary starting at offset 18
    let pos = 18
    const labelsArr = []
    while (pos < bytes.length) {
      const len = bytes[pos++]
      if (len === 0) break
      labelsArr.push(new TextDecoder().decode(bytes.subarray(pos, pos + len)))
      pos += len
    }
    const signersName = `${labelsArr.join('.')}.`

    const signature = new TextDecoder().decode(bytes.subarray(pos))

    return new SIG({
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'SIG',
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

  toBind(zone_opts) {
    return `${this.getFQDN('owner', zone_opts)}	${this.get('ttl')}	${this.get('class')}	SIG${this.getRdataFields()
      .slice(0, 4)
      .map((f) => '	' + this.get(f))
      .join('')}	${this.getRdataFields()
      .slice(4, 8)
      .map((f) => this.get(f))
      .join('	')}	( ${this.get('signature')} )`
  }
}
