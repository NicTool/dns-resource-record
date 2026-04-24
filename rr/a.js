import RR from '../rr.js'

export default class A extends RR {
  static typeName = 'A'
  static typeId = 1
  static RFCs = [1035]
  static tinydnsType = '+'
  static rdataFields = [['address', 'ipv4']]
  static tags = ['common']

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

  getCanonical() {
    return {
      owner: 'host.example.com.',
      class: 'IN',
      ttl: 3600,
      type: 'A',
      address: '192.0.2.127',
    }
  }

  /******  EXPORTERS   *******/
  getWireRdata() {
    return new Uint8Array(this.get('address').split('.').map(Number))
  }
}
