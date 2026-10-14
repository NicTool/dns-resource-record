import RR from '../rr.js'

export default class HINFO extends RR {
  static typeName = 'HINFO'
  static typeId = 13
  static RFCs = [1034, 1035, 8482]
  static rdataFields = [
    ['cpu', 'qcharstr'],
    ['os', 'qcharstr'],
  ]
  static tags = ['obsolete']

  constructor(opts) {
    super(opts)
  }

  getDescription() {
    return 'Host Info'
  }

  getCanonical() {
    return {
      owner: 'test.example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'HINFO',
      cpu: 'DEC-2060',
      os: 'TOPS20',
    }
  }

  /******  EXPORTERS   *******/
}
