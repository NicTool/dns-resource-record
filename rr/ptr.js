import RR from '../rr.js'

export default class PTR extends RR {
  static typeName = 'PTR'
  static tinydnsType = '^'
  static rdataFields = [['dname', 'fqdn']]

  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setDname(val) {
    this.isFullyQualified('PTR', 'dname', val)
    this.isValidHostname('PTR', 'dname', val)

    // RFC 4034: letters in the DNS names are lower cased
    this.set('dname', val.toLowerCase())
  }

  getDescription() {
    return 'Pointer'
  }
  static tags = ['common']
  static RFCs = [1035]
  static typeId = 12
  getCanonical() {
    return {
      owner: '2.2.0.192.in-addr.arpa.',
      ttl: 3600,
      class: 'IN',
      type: 'PTR',
      dname: 'host.example.com.',
    }
  }

  /******  EXPORTERS   *******/
  getWireRdata() {
    return this.wirePackDomain(this.get('dname'))
  }
}
