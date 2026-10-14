import RR from '../rr.js'

export default class DHCID extends RR {
  static typeName = 'DHCID'
  static typeId = 49
  static RFCs = [4701]
  static rdataFields = [['data', 'base64']]

  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setData(val) {
    if (!val) this.throwHelp('DHCID: data is required')
    this.isBase64('DHCID', 'data', val)
    this.set('data', val)
  }

  getDescription() {
    return 'DHCP Identifier'
  }

  getCanonical() {
    return {
      owner: 'host.example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'DHCID',
      data: 'AAIBY2/AuCccgoJbsaxcQc9TUapptP69lOjxfNuVAA2kjEA=',
    }
  }

  /******  IMPORTERS   *******/

  /******  EXPORTERS   *******/
}
