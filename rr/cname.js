import RR from '../rr.js'

export default class CNAME extends RR {
  static typeName = 'CNAME'
  static tinydnsType = 'C'
  static rdataFields = ['cname']
  static fqdnFields = ['cname']

  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setCname(val) {
    this.setFqdnValue('CNAME', 'cname', val)
  }

  getDescription() {
    return 'Canonical Name'
  }

  getTags() {
    return ['common']
  }

  getRFCs() {
    return [1035, 2181]
  }

  getTypeId() {
    return 5
  }

  getCanonical() {
    return {
      owner: 'www.example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'CNAME',
      cname: 'web.example.com.',
    }
  }

  /******  IMPORTERS   *******/
  fromWire({ owner, cls, ttl, rdata }) {
    const { fqdn } = this.wireUnpackDomain(rdata, 0)
    return new CNAME({ owner, ttl, class: cls, type: 'CNAME', cname: fqdn })
  }

  /******  EXPORTERS   *******/
  getWireRdata() {
    return this.wirePackDomain(this.get('cname'))
  }
}
