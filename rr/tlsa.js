import RR from '../rr.js'

import * as TINYDNS from '../lib/tinydns.js'

export default class TLSA extends RR {
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setCertificateUsage(val) {
    if (![0, 1, 2, 3].includes(val))
      throw new Error(`TLSA: certificate usage invalid, ${this.citeRFC()}`)

    this.set('certificate usage', val)
  }

  setSelector(val) {
    if (![0, 1].includes(val))
      throw new Error(`TLSA: selector invalid, ${this.citeRFC()}`)

    this.set('selector', val)
  }

  setMatchingType(val) {
    if (![0, 1, 2].includes(val))
      throw new Error(`TLSA: matching type, ${this.citeRFC()}`)

    this.set('matching type', val)
  }

  setCertificateAssociationData(val) {
    this.set('certificate association data', val)
  }

  getDescription() {
    return 'TLSA certificate association'
  }

  getRdataFields(arg) {
    return [
      'certificate usage',
      'selector',
      'matching type',
      'certificate association data',
    ]
  }

  getRFCs() {
    return [6698]
  }

  getTypeId() {
    return 52
  }

  getQuotedFields() {
    return []
  }

  /******  IMPORTERS   *******/

  fromBind(opts) {
    // test.example.com  3600  IN  TLSA, usage, selector, match, data
    const match = opts.bindline.split(
      /^([^\s]+)\s+([0-9]+)\s+(\w+)\s+(\w+)\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)\s+(.*?)\s*$/,
    )
    if (!match) throw new Error(`unable to parse TLSA: ${opts.bindline}`)
    const [owner, ttl, c, type, usage, selector, matchtype, cad] =
      match.slice(1)
    return new TLSA({
      owner: this.fullyQualify(owner),
      ttl: parseInt(ttl, 10),
      class: c,
      type,
      'certificate usage': parseInt(usage, 10),
      selector: parseInt(selector, 10),
      'matching type': parseInt(matchtype, 10),
      'certificate association data': cad,
    })
  }

  fromTinydns(opts) {
    const [fqdn, n, rdata, ttl, ts, loc] = opts.tinyline.substring(1).split(':')
    if (n != 52) throw new Error('TLSA fromTinydns, invalid n')

    const bytes = Buffer.from(TINYDNS.octalToChar(rdata), 'binary')

    return new TLSA({
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'TLSA',
      'certificate usage': bytes.readUInt8(0),
      selector: bytes.readUInt8(1),
      'matching type': bytes.readUInt8(2),
      'certificate association data': bytes.slice(3).toString(),
      timestamp: ts,
      location: loc !== '' && loc !== '\n' ? loc : '',
    })
  }

  /******  EXPORTERS   *******/
  toTinydns() {
    const dataRe = new RegExp(/[\r\n\t:\\/]/, 'g')

    return this.getTinydnsGeneric(
      TINYDNS.UInt8toOctal(this.get('certificate usage')) +
        TINYDNS.UInt8toOctal(this.get('selector')) +
        TINYDNS.UInt8toOctal(this.get('matching type')) +
        TINYDNS.escapeOctal(dataRe, this.get('certificate association data')),
    )
  }
}
