import RR from '../rr.js'

import * as TINYDNS from '../lib/tinydns.js'

export default class SMIMEA extends RR {
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setCertificateUsage(val) {
    if (!this.getCertificateUsageOptions().has(val)) this.throwHelp(`SMIMEA: certificate usage invalid`)

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
    if (!this.getSelectorOptions().has(val)) this.throwHelp(`SMIMEA: selector invalid`)

    this.set('selector', val)
  }

  getSelectorOptions() {
    return new Map([
      [0, 'Full certificate'],
      [1, 'SubjectPublicKeyInfo'],
    ])
  }

  setMatchingType(val) {
    if (!this.getMatchingTypeOptions().has(val)) this.throwHelp(`SMIMEA: matching type`)

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
    return 'S/MIME cert association'
  }

  getRdataFields(arg) {
    return ['certificate usage', 'selector', 'matching type', 'certificate association data']
  }

  getRFCs() {
    return [8162]
  }

  getTypeId() {
    return 53
  }

  getQuotedFields() {
    return []
  }

  /******  IMPORTERS   *******/

  fromBind(opts) {
    // test.example.com  3600  IN  SMIMEA, usage, selector, match, data
    const [owner, ttl, c, type, usage, selector, match] = opts.bindline.split(/\s+/)
    return new SMIMEA({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type: type,
      'certificate usage': parseInt(usage, 10),
      selector: parseInt(selector, 10),
      'matching type': parseInt(match, 10),
      'certificate association data': opts.bindline.split(/\s+/).slice(7).join(' ').trim(),
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
