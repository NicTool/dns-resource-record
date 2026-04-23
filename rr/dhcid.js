import RR from '../rr.js'

import * as TINYDNS from '../lib/tinydns.js'

export default class DHCID extends RR {
  static typeName = 'DHCID'
  static rdataFields = ['data']

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

  getRFCs() {
    return [4701]
  }

  getTypeId() {
    return 49
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
    const [fqdn, n, rdata, ttl, ts, loc] = tinyline.slice(1).split(':')
    if (n != 49) this.throwHelp('DHCID fromTinydns, invalid n')

    return new DHCID({
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'DHCID',
      data: TINYDNS.octalToBase64(rdata),
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  fromWire({ owner, cls, ttl, rdata }) {
    return new DHCID({
      owner,
      ttl,
      class: cls,
      type: 'DHCID',
      data: btoa([...rdata].map((b) => String.fromCharCode(b)).join('')),
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
