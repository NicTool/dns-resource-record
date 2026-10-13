// obsoleted by RFC 7208

import TXT from './txt.js'

export default class SPF extends TXT {
  static typeName = 'SPF'
  static typeId = 99
  // tinydns has no SPF line; it takes the generic `:` form.
  static tinydnsType = undefined
  static RFCs = [4408, 7208]
  static rdataFields = [['data', 'charstrs']]
  static tags = ['obsolete']

  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setData(val) {
    this.set('data', val)
  }

  getDescription() {
    return 'Sender Policy Framework'
  }
  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'SPF',
      data: 'v=spf1 mx -all',
    }
  }

  /******  EXPORTERS   *******/
  getWireRdata() {
    return super.getWireRdata()
  }
}
