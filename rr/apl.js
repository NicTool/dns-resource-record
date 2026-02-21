import RR from '../rr.js'

export default class APL extends RR {
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setAplRdata(val) {
    if (!val) this.throwHelp('APL: apl rdata is required')
    // apl rdata is a list of address prefix list items, e.g.:
    // 1:192.0.2.0/24 !1:192.0.2.64/28 2:2001:db8::/32
    this.set('apl rdata', val)
  }

  getDescription() {
    return 'Address Prefix List'
  }

  getRdataFields(arg) {
    return ['apl rdata']
  }

  getRFCs() {
    return [3123]
  }

  getTypeId() {
    return 42
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'APL',
      'apl rdata': '1:192.0.2.0/24 !1:192.0.2.64/28 2:2001:db8::/32',
    }
  }

  /******  IMPORTERS   *******/
  fromBind(opts) {
    // test.example.com  3600  IN  APL  {[!]afi:address/prefix}*
    const parts = opts.bindline.split(/\s+/)
    const [owner, ttl, c, type] = parts
    return new APL({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type,
      'apl rdata': parts.slice(4).join(' ').trim(),
    })
  }

  /******  EXPORTERS   *******/
}
