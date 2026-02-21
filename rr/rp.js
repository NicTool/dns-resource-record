import RR from '../rr.js'

import * as TINYDNS from '../lib/tinydns.js'

export default class RP extends RR {
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

  getRdataFields(arg) {
    return ['mbox', 'txt']
  }

  getRFCs() {
    return [1183]
  }

  getTypeId() {
    return 17
  }

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
  fromBind(opts) {
    // test.example.com  3600  IN  RP  mbox txt
    const [owner, ttl, c, type, mbox, txt] = opts.bindline.split(/\s+/)
    return new RP({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type,
      mbox,
      txt,
    })
  }

  /******  EXPORTERS   *******/
  toBind(zone_opts) {
    return `${this.getPrefix(zone_opts)}\t${this.getFQDN('mbox', zone_opts)}\t${this.getFQDN('txt', zone_opts)}\n`
  }

  toTinydns() {
    return this.getTinydnsGeneric(
      TINYDNS.packDomainName(this.get('mbox')) + TINYDNS.packDomainName(this.get('txt')),
    )
  }
}
