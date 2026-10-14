import RR from '../rr.js'

export default class RP extends RR {
  static typeName = 'RP'
  static rdataFields = [
    ['mbox', 'fqdn'],
    ['txt', 'fqdn'],
  ]

  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setMbox(val) {
    this.setTypedValue('fqdn', 'mbox', val)
  }

  setTxt(val) {
    this.setTypedValue('fqdn', 'txt', val)
  }

  getDescription() {
    return 'Responsible Person'
  }
  static tags = ['obsolete']
  static RFCs = [1183]
  static typeId = 17
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

  /******  EXPORTERS   *******/
}
