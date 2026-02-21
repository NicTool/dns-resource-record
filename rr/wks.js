import RR from '../rr.js'

import * as TINYDNS from '../lib/tinydns.js'

export default class WKS extends RR {
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setAddress(val) {
    if (!val) this.throwHelp('WKS: address is required')
    if (!this.isIPv4(val)) this.throwHelp('WKS address must be IPv4')
    this.set('address', val)
  }

  setProtocol(val) {
    if (!val) this.throwHelp('WKS: protocol is required')
    const upper = typeof val === 'string' ? val.toUpperCase() : val
    if (!['TCP', 'UDP', 6, 17].includes(upper)) this.throwHelp('WKS protocol must be TCP or UDP')
    this.set('protocol', upper)
  }

  setBitMap(val) {
    this.set('bit map', val ?? '')
  }

  getDescription() {
    return 'Well Known Service'
  }

  getRdataFields(arg) {
    return ['address', 'protocol', 'bit map']
  }

  getRFCs() {
    return [883, 1035]
  }

  getTypeId() {
    return 11
  }

  /******  IMPORTERS   *******/

  fromBind(opts) {
    // test.example.com  3600  IN  WKS 192.168.1.1 TCP ftp smtp
    const parts = opts.bindline.split(/\s+/)
    const [owner, ttl, c, type, address, protocol] = parts
    return new WKS({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type,
      address,
      protocol,
      'bit map': parts.slice(6).join(' ').trim(),
    })
  }

  /******  EXPORTERS   *******/

  toTinydns() {
    const dataRe = new RegExp(/[\r\n\t:\\/]/, 'g')
    const protoMap = { TCP: 6, UDP: 17, 6: 6, 17: 17 }
    const protoNum = protoMap[this.get('protocol')]

    return this.getTinydnsGeneric(
      TINYDNS.ipv4toOctal(this.get('address')) +
        TINYDNS.UInt8toOctal(protoNum) +
        TINYDNS.escapeOctal(dataRe, this.get('bit map')),
    )
  }
}
