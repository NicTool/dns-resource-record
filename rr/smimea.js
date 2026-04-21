import RR from '../rr.js'

import * as TINYDNS from '../lib/tinydns.js'
import * as BINARY from '../lib/binary.js'

export default class SMIMEA extends RR {
  static typeName = 'SMIMEA'
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

  getTags() {
    return ['security']
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

  getCanonical() {
    return {
      owner: '_443._tcp.www.example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'SMIMEA',
      'certificate usage': 0,
      selector: 0,
      'matching type': 1,
      'certificate association data': 'ABCDEF...',
    }
  }

  getQuotedFields() {
    return []
  }

  /******  IMPORTERS   *******/

  fromBind({ bindline }) {
    // test.example.com  3600  IN  SMIMEA, usage, selector, match, data
    const [owner, ttl, c, type, usage, selector, match] = bindline.split(/\s+/)
    return new SMIMEA({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type: type,
      'certificate usage': parseInt(usage, 10),
      selector: parseInt(selector, 10),
      'matching type': parseInt(match, 10),
      'certificate association data': bindline.split(/\s+/).slice(7).join(' ').trim(),
    })
  }

  fromTinydns({ tinyline }) {
    const [owner, _typeId, rdata, ttl, ts, loc] = tinyline.slice(1).split(':')
    const binaryRdata = Uint8Array.from(TINYDNS.octalToChar(rdata), (c) => c.charCodeAt(0))

    return new SMIMEA({
      owner: this.fullyQualify(owner),
      ttl: parseInt(ttl, 10),
      type: 'SMIMEA',
      'certificate usage': binaryRdata[0],
      selector: binaryRdata[1],
      'matching type': binaryRdata[2],
      'certificate association data': BINARY.bytesToHex(binaryRdata.subarray(3)),
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  /******  EXPORTERS   *******/
  toTinydns() {
    return this.getTinydnsGeneric(
      TINYDNS.UInt8toOctal(this.get('certificate usage')) +
        TINYDNS.UInt8toOctal(this.get('selector')) +
        TINYDNS.UInt8toOctal(this.get('matching type')) +
        TINYDNS.packHex(this.get('certificate association data').replace(/[\s()]/g, '')),
    )
  }
}
