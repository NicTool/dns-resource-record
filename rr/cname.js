import RR from '../rr.js'

export default class CNAME extends RR {
  static typeName = 'CNAME'
  static typeId = 5
  static RFCs = [1035, 2181]
  static tinydnsType = 'C'
  static rdataFields = [['cname', 'fqdn']]
  static tags = ['common']

  constructor(opts) {
    super(opts)
  }

  getDescription() {
    return 'Canonical Name'
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

  /******  EXPORTERS   *******/
  getWireRdata() {
    return this.wirePackDomain(this.get('cname'))
  }
}
