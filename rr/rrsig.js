import RR from '../rr.js'
import * as TINYDNS from '../lib/tinydns.js'
import * as WIRE from '../lib/binary.js'
import * as WIRELIB from '../lib/wire.js'

export default class RRSIG extends RR {
  static typeName = 'RRSIG'
  static typeId = 46
  static RFCs = [4034]
  static rdataFields = [
    ['type covered', 'u16'],
    ['algorithm', 'u8'],
    ['labels', 'u8'],
    ['original ttl', 'u32'],
    ['signature expiration', 'u32'],
    ['signature inception', 'u32'],
    ['key tag', 'u16'],
    ['signers name', 'fqdn'],
    ['signature', 'base64'],
  ]
  static tags = ['dnssec']

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

  setLabels(val) {
    this.setTypedValue('u8', 'labels', val)
  }

  setOriginalTtl(val) {
    this.setTypedValue('u32', 'original ttl', val)
  }

  setSignatureExpiration(val) {
    this.setTypedValue('u32', 'signature expiration', val)
  }

  setSignatureInception(val) {
    this.setTypedValue('u32', 'signature inception', val)
  }

  setKeyTag(val) {
    this.setTypedValue('u16', 'key tag', val)
  }

  setSignersName(val) {
    this.setTypedValue('fqdn', 'signers name', val)
  }

  setSignature(val) {
    // RFC 4034 §3.2: presentation form is base64; wire form is decoded bytes.
    this.isBase64('RRSIG', 'signature', String(val).replace(/[\s()]/g, ''))
    this.set('signature', val)
  }

  getAlgorithmOptions() {
    // IANA DNSSEC Algorithm Numbers
    // https://www.iana.org/assignments/dns-sec-alg-numbers/
    return new Map([
      [1, 'RSA/MD5'],
      [2, 'DH'],
      [3, 'DSA/SHA-1'],
      [4, 'EC'],
      [5, 'RSA/SHA-1'],
      [6, 'DSA-NSEC3-SHA1'],
      [7, 'RSASHA1-NSEC3-SHA1'],
      [8, 'RSA/SHA-256'],
      [10, 'RSA/SHA-512'],
      [13, 'ECDSA P-256/SHA-256'],
      [14, 'ECDSA P-384/SHA-384'],
      [15, 'Ed25519'],
      [16, 'Ed448'],
      [253],
      [254],
    ])
  }

  getDescription() {
    return 'Resource Record Signature'
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
      signature:
        'oJB1W6WNGv+ldvQ3WDG0MQkg5IEhjRip8WTrPYGv07h108dUKGMeDPKijVCHX3DDKdfb' +
        '+v6oB9wfuh3DTJXUAfI/M0zmO/zz8bW0Rznl8O3tGNazPwQKkRN20XPXV6nwwfoXmJQb' +
        'sLNrLfkGJ5D6fwFm8nN+6pBzeDQfsS3Ap3o=',
    }
  }

  /******  IMPORTERS   *******/

  fromBind({ bindline }) {
    // example.com. 3600 IN RRSIG typecovered algorithm labels origttl sigexp siginc keytag signersname ( signature )
    const parts = bindline.trim().split(/\s+/)
    // type covered may be a type name ('A', 'MX'), TYPEnn (RFC 3597), or a numeric ID
    const typeCovered = WIRE.typeNameToId(parts[4])
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
    const signature = WIRE.bytesToBase64(bytes.subarray(pos))

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
        TINYDNS.base64toOctal(this.get('signature').replace(/[\s()]/g, '')),
    )
  }

  getWireRdata() {
    const signerBytes = WIRELIB.wirePackDomain(this.get('signers name'))
    const sigBytes = WIRE.base64ToBytes(this.get('signature').replace(/[\s()]/g, ''))

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
