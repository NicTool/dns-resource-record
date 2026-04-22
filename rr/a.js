import RR from '../rr.js'

export default class A extends RR {
  static typeName = 'A'
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setAddress(val) {
    if (!val) this.throwHelp('A: address is required')
    if (!this.isIPv4(val)) this.throwHelp('A address must be IPv4')
    this.set('address', val)
  }

  getDescription() {
    return 'Address'
  }

  getTags() {
    return ['common']
  }

  getRdataFields(arg) {
    return ['address']
  }

  getRFCs() {
    return [1035]
  }

  getTypeId() {
    return 1
  }

  getCanonical() {
    return {
      owner: 'host.example.com.',
      class: 'IN',
      ttl: 3600,
      type: 'A',
      address: '192.0.2.127',
    }
  }

  /******  IMPORTERS   *******/
  fromTinydns({ tinyline }) {
    // +fqdn:ip:ttl:timestamp:lo
    const [owner, ip, ttl, ts, loc] = tinyline.slice(1).split(':')

    return new A({
      owner: this.fullyQualify(owner),
      type: 'A',
      address: ip,
      ttl: parseInt(ttl, 10),
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  fromBind(opts) {
    const { owner, ttl, cls, rdata } = opts
    return new A({
      owner,
      ttl,
      class: cls,
      type: 'A',
      address: rdata[0],
    })
  }

  /******  EXPORTERS   *******/
  getWireRdata() {
    return new Uint8Array(this.get('address').split('.').map(Number))
  }

  toTinydns() {
    return `+${this.getTinyFQDN('owner')}:${this.get('address')}:${this.getTinydnsPostamble()}\n`
  }
}
