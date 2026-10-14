import RR from '../rr.js'

export default class DNAME extends RR {
  static typeName = 'DNAME'
  static typeId = 39
  static RFCs = [2672, 6672]
  static rdataFields = [['target', 'fqdn']]

  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setTarget(val) {
    this.setTypedValue('fqdn', 'target', val)
  }

  getDescription() {
    return 'Delegation Name'
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'DNAME',
      target: 'example.net.',
    }
  }

  /******  IMPORTERS   *******/

  /******  EXPORTERS   *******/
}
