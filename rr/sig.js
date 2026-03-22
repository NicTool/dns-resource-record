import RR from '../rr.js'

import * as TINYDNS from '../lib/tinydns.js'

export default class SIG extends RR {
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

    this.is8bitInt('SIG', 'labels', val)

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
    return [2535]
  }

  getTypeId() {
    return 24
  }

  /******  IMPORTERS   *******/

  fromBind({ bindline }) {
    // example.com. 3600 IN SIG TypeCovered Algorithm Labels OrigTTL SigExpiration SigInception KeyTag SignersName ( Signature )
    const parts = bindline.trim().split(/\s+/)

    return new SIG({
      owner: parts[0],
      ttl: parseInt(parts[1], 10),
      class: parts[2],
      type: 'SIG',
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

  fromTinydns({ tinyline }) {
    const [fqdn, n, rdata, ttl, ts, loc] = tinyline.substring(1).split(':')
    if (parseInt(n, 10) !== this.getTypeId()) this.throwHelp('SIG fromTinydns, invalid n')

    const bytes = Buffer.from(TINYDNS.octalToChar(rdata), 'binary')

    const typeCovered = bytes.readUInt16BE(0)
    const algorithm = bytes.readUInt8(2)
    const labels = bytes.readUInt8(3)
    const originalTtl = bytes.readUInt32BE(4)
    const signatureExpiration = bytes.readUInt32BE(8)
    const signatureInception = bytes.readUInt32BE(12)
    const keyTag = bytes.readUInt16BE(16)

    // parse signers name from binary buffer starting at offset 18
    let pos = 18
    const labelsArr = []
    while (pos < bytes.length) {
      const len = bytes.readUInt8(pos++)
      if (len === 0) break
      labelsArr.push(bytes.slice(pos, pos + len).toString())
      pos += len
    }
    const signersName = `${labelsArr.join('.')}.`

    const signature = bytes.slice(pos).toString()

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
