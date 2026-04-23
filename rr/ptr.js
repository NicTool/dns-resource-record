import RR from '../rr.js'

export default class PTR extends RR {
  static typeName = 'PTR'
  static typeId = 12
  static RFCs = [1035]
  static tinydnsType = '^'
  static rdataFields = [['dname', 'fqdn']]
  static tags = ['common']

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
