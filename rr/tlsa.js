import RR from '../rr.js'

import * as TINYDNS from '../lib/tinydns.js'

export default class TLSA extends RR {
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setCertificateUsage(val) {
    if (!this.getCertificateUsageOptions().has(val))
      this.throwHelp(`TLSA: certificate usage invalid`)

    this.set('certificate usage', val)
  }

  getCertificateUsageOptions() {
    return new Map([
      [0, 'CA certificate'],
      [1, 'an end entity certificate'],
      [2, 'the trust anchor'],
      [3, 'domain-issued certificate'],
    ])
  }

  setSelector(val) {
    if (!this.getSelectorOptions().has(val))
      this.throwHelp(`TLSA: selector invalid`)

    this.set('selector', val)
  }

  getSelectorOptions() {
    return new Map([
      [0, 'Full certificate'],
      [1, 'SubjectPublicKeyInfo'],
    ])
  }

  setMatchingType(val) {
    if (!this.getMatchingTypeOptions().has(val))
      this.throwHelp(`TLSA: matching type`)

    this.set('matching type', val)
  }

  getMatchingTypeOptions() {
    return new Map([
      [0, 'Exact match'],
      [1, 'SHA-256 hash'],
      [2, 'SHA-512 hash'],
    ])
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
    const match = opts.bindline
      .trim()
      .split(
        /^([^\s]+)\s+([0-9]{1,10})\s+(IN)\s+(TLSA)\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)\s+(.*?)$/,
      )
    if (!match) this.throwHelp(`unable to parse TLSA: ${opts.bindline}`)
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
    if (n != 52) this.throwHelp('TLSA fromTinydns, invalid n')

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
