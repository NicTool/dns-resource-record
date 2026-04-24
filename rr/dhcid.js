import RR from '../rr.js'

import * as TINYDNS from '../lib/tinydns.js'

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
  fromTinydns({ tinyline }) {
    // DHCID via generic, :fqdn:49:rdata:ttl:timestamp:lo
    const { owner, typeId, rdata, ttl, timestamp, location } = this.parseTinydnsLine(tinyline)
    if (typeId != this.getTypeId()) this.throwHelp('DHCID fromTinydns, invalid n')

    return new DHCID({
      owner,
      ttl,
      type: 'DHCID',
      data: TINYDNS.octalToBase64(rdata),
      timestamp,
      location,
    })
  }

  /******  EXPORTERS   *******/

  getWireRdata() {
    return new Uint8Array(
      atob(this.get('data'))
        .split('')
        .map((c) => c.charCodeAt(0)),
    )
  }

  toTinydns() {
    return this.getTinydnsGeneric(TINYDNS.base64toOctal(this.get('data')))
  }
}
