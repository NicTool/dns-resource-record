import RR, { formatSignatureTime } from '../rr.js'

import * as TINYDNS from '../lib/tinydns.js'
import * as WIRE from '../lib/binary.js'
import * as WIRELIB from '../lib/wire.js'

export default class SIG extends RR {
  static typeName = 'SIG'
  static typeId = 24
  static RFCs = [2535, 3755]
  static rdataFields = [
    ['type covered', 'rrtype'],
    ['algorithm', 'u8'],
    ['labels', 'u8'],
    ['original ttl', 'u32'],
    ['signature expiration', 'u32'],
    ['signature inception', 'u32'],
    ['key tag', 'u16'],
    ['signers name', 'fqdn'],
    ['signature', 'base64'],
  ]
  static tags = ['obsolete']

  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setTypeCovered(val) {
    if (!val && val !== 0) this.throwHelp(`SIG: 'type covered' is required`)
    this.setTypedValue('rrtype', 'type covered', val)
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
    this.setSignatureTime('signature expiration', val)
  }

  setSignatureInception(val) {
    this.setSignatureTime('signature inception', val)
  }

  setKeyTag(val) {
    // a 2 octet Key tag
    this.set('key tag', val)
  }

  setSignersName(val) {
    // the domain name of the signer generating the SIG RR

    // RFC 4034: letters in the DNS names are lower cased
    this.set('signers name', this.lowercaseName(val))
  }

  setSignature(val) {
    this.isBase64('SIG', 'signature', val)
    this.set('signature', val)
  }

  getDescription() {
    return 'Signature'
  }

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
      signature: 'AQPSKmynfzW4kyBv015MUG2DeIQ3Cbl+BBZH4b/0PY1kxkmvHjcZc8no',
    }
  }

  /******  EXPORTERS   *******/
  toTinydns() {
    return this.getTinydnsGeneric(
      TINYDNS.UInt16toOctal(this.get('type covered')) +
        TINYDNS.UInt8toOctal(this.get('algorithm')) +
        TINYDNS.UInt8toOctal(this.get('labels')) +
        TINYDNS.UInt32toOctal(this.get('original ttl')) +
        TINYDNS.UInt32toOctal(this.get('signature expiration')) +
        TINYDNS.UInt32toOctal(this.get('signature inception')) +
        TINYDNS.UInt16toOctal(this.get('key tag')) +
        TINYDNS.packDomainName(this.get('signers name')) +
        TINYDNS.base64toOctal(this.get('signature')),
    )
  }

  getWireRdata() {
    const signerBytes = WIRELIB.wirePackDomain(this.get('signers name'))
    const sigBytes = WIRE.base64ToBytes(this.get('signature'))

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
    const { owner, typeId, rdata, ttl, timestamp, location } = this.parseTinydnsLine(tinyline)
    if (parseInt(typeId, 10) !== this.getTypeId()) this.throwHelp('SIG fromTinydns, invalid n')

    const bytes = TINYDNS.octalRdataToBytes(rdata)
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

    const signature = WIRE.bytesToBase64(bytes.subarray(pos))

    return new SIG({
      owner,
      ttl,
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
      timestamp,
      location,
    })
  }

  toBind(zone_opts) {
    // RFC 2535 §7.2 presents SIG times only as YYYYMMDDHHmmSS; BIND rejects integers.
    const rdata = this.getRdataFields().map((f) => {
      if (f === 'signature expiration' || f === 'signature inception') return formatSignatureTime(this.get(f))
      if (f === 'signers name') return this.getFQDN(f, zone_opts)
      if (f === 'type covered') return WIRE.typeIdToName(this.get(f))
      return this.get(f)
    })
    return `${this.getPrefix(zone_opts)}\t${rdata.join('\t')}\n`
  }
}
