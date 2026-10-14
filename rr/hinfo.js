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

  getWireRdata() {
    const cpu = new TextEncoder().encode(this.get('cpu'))
    const os = new TextEncoder().encode(this.get('os'))
    const result = new Uint8Array(2 + cpu.length + os.length)
    result[0] = cpu.length
    result.set(cpu, 1)
    result[1 + cpu.length] = os.length
    result.set(os, 2 + cpu.length)
    return result
  }
}
