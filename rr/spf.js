// obsoleted by RFC 7208

import TXT from './txt.js'

import * as TINYDNS from '../lib/tinydns.js'

export default class SPF extends TXT {
  static typeName = 'SPF'
  static typeId = 99
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

  /******  IMPORTERS   *******/
  fromTinydns({ tinyline }) {
    // SPF via generic, :fqdn:n:rdata:ttl:timestamp:lo
    const [fqdn, n, rdata, ttl, ts, loc] = tinyline.slice(1).split(':')
    if (n != 99) this.throwHelp('SPF fromTinydns, invalid n')

    return new SPF({
      type: 'SPF',
      owner: this.fullyQualify(fqdn),
      data: TINYDNS.octalToChar(rdata),
      ttl: parseInt(ttl, 10),
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  /******  EXPORTERS   *******/
  getWireRdata() {
    return super.getWireRdata()
  }

  toTinydns() {
    // `data` may be a string or an array of <character-string>s (RFC 1035 §3.3.14).
    // tinydns generic format stores rdata as a flat byte stream, so join here.
    let data = this.get('data')
    if (Array.isArray(data)) data = data.join('')
    const rdata = TINYDNS.escapeOctal(new RegExp(/[\r\n\t:\\/]/, 'g'), data)
    return this.getTinydnsGeneric(rdata)
  }
}
