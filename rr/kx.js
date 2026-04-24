import RR from '../rr.js'

import * as TINYDNS from '../lib/tinydns.js'

export default class KX extends RR {
  static typeName = 'KX'
  static typeId = 36
  static RFCs = [2230]
  static rdataFields = [
    ['preference', 'u16'],
    ['exchanger', 'fqdn'],
  ]

  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setPreference(val) {
    if (val === undefined) this.throwHelp('KX: preference is required')
    this.is16bitInt('KX', 'preference', val)
    this.set('preference', val)
  }

  setExchanger(val) {
    if (!val) this.throwHelp('KX: exchanger is required')

    this.isFullyQualified('KX', 'exchanger', val)
    this.isValidHostname('KX', 'exchanger', val)

    this.set('exchanger', val.toLowerCase())
  }

  getDescription() {
    return 'Key Exchanger'
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'KX',
      preference: 10,
      exchanger: 'kx.example.com.',
    }
  }

  /******  IMPORTERS   *******/
  fromTinydns({ tinyline }) {
    // KX via generic, :fqdn:36:rdata:ttl:timestamp:lo
    const [fqdn, n, rdata, ttl, ts, loc] = tinyline.slice(1).split(':')
    if (n != 36) this.throwHelp('KX fromTinydns, invalid n')

    return new KX({
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'KX',
      preference: TINYDNS.octalToUInt16(rdata.slice(0, 8)),
      exchanger: TINYDNS.unpackDomainName(rdata.slice(8))[0],
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  /******  EXPORTERS   *******/

  getWireRdata() {
    const exchanger = this.wirePackDomain(this.get('exchanger'))
    const result = new Uint8Array(2 + exchanger.length)
    const dv = new DataView(result.buffer)
    dv.setUint16(0, this.get('preference'))
    result.set(exchanger, 2)
    return result
  }

  toTinydns() {
    return this.getTinydnsGeneric(
      TINYDNS.UInt16toOctal(this.get('preference')) + TINYDNS.packDomainName(this.get('exchanger')),
    )
  }
}
