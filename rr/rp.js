import RR from '../rr.js'

import * as TINYDNS from '../lib/tinydns.js'

export default class RP extends RR {
  static typeName = 'RP'
  static rdataFields = [
    ['mbox', 'fqdn'],
    ['txt', 'fqdn'],
  ]

  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setMbox(val) {
    if (!val) this.throwHelp('RP: mbox is required')

    this.isFullyQualified('RP', 'mbox', val)

    this.set('mbox', val.toLowerCase())
  }

  setTxt(val) {
    if (!val) this.throwHelp('RP: txt is required')

    this.isFullyQualified('RP', 'txt', val)

    this.set('txt', val.toLowerCase())
  }

  getDescription() {
    return 'Responsible Person'
  }
  static tags = ['obsolete']
  static RFCs = [1183]
  static typeId = 17
  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'RP',
      mbox: 'admin.example.com.',
      txt: 'info.example.com.',
    }
  }

  /******  IMPORTERS   *******/
  fromTinydns({ tinyline }) {
    const [owner, _typeId, rdata, ttl, ts, loc] = tinyline.slice(1).split(':')

    const [mbox, consumed] = TINYDNS.unpackDomainName(rdata)
    const txt = TINYDNS.unpackDomainName(rdata.slice(consumed))[0]

    return new RP({
      owner: this.fullyQualify(owner),
      ttl: parseInt(ttl, 10),
      type: 'RP',
      mbox,
      txt,
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  /******  EXPORTERS   *******/

  getWireRdata() {
    const mbox = this.wirePackDomain(this.get('mbox'))
    const txt = this.wirePackDomain(this.get('txt'))
    const result = new Uint8Array(mbox.length + txt.length)
    result.set(mbox, 0)
    result.set(txt, mbox.length)
    return result
  }

  toTinydns() {
    return this.getTinydnsGeneric(
      TINYDNS.packDomainName(this.get('mbox')) + TINYDNS.packDomainName(this.get('txt')),
    )
  }
}
