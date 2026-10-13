import RR from '../rr.js'

import * as BINARY from '../lib/binary.js'

export default class NSEC extends RR {
  static typeName = 'NSEC'
  static typeId = 47
  static RFCs = [4034]
  static rdataFields = ['next domain', ['type bit maps', 'list']]
  static tags = ['dnssec']

  constructor(opts) {
    super(opts)
    if (opts === null) return
  }

  /****** Resource record specific setters   *******/
  setNextDomain(val) {
    if (!val) this.throwHelp(`NSEC: 'next domain' is required:`)

    this.isFullyQualified('NSEC', 'next domain', val)
    this.isValidHostname('NSEC', 'next domain', val)

    // RFC 4034: letters in the DNS names are lower cased
    this.set('next domain', this.lowercaseName(val))
  }

  setTypeBitMaps(val) {
    if (!val) this.throwHelp(`NSEC: 'type bit maps' is required`)

    this.set('type bit maps', val)
  }

  getDescription() {
    return 'Next Secure'
  }

  getCanonical() {
    return {
      owner: 'alfa.example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'NSEC',
      'next domain': 'host.example.com.',
      'type bit maps': 'A MX RRSIG NSEC TYPE1234',
    }
  }

  /******  IMPORTERS   *******/

  fromWire({ owner, cls, ttl, rdata }) {
    const { fqdn: nextDomain, end } = this.wireUnpackDomain(rdata, 0)
    const typeBitMaps = BINARY.bitmapToTypes(rdata.subarray(end))
    return new NSEC({
      owner,
      ttl,
      class: cls,
      type: 'NSEC',
      'next domain': nextDomain,
      'type bit maps': typeBitMaps,
    })
  }

  /******  EXPORTERS   *******/

  getWireRdata() {
    const nameBytes = this.wirePackDomain(this.get('next domain'))
    const bitmapBytes = BINARY.typesToBitmap(this.get('type bit maps'))
    const result = new Uint8Array(nameBytes.length + bitmapBytes.length)
    result.set(nameBytes)
    result.set(bitmapBytes, nameBytes.length)
    return result
  }
}
