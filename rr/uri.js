import RR from '../rr.js'

import * as TINYDNS from '../lib/tinydns.js'

export default class URI extends RR {
  static typeName = 'URI'
  static rdataFields = ['priority', 'weight', 'target']
  static quotedFields = ['target']
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setPriority(val) {
    this.is16bitInt('URI', 'priority', val)

    this.set('priority', val)
  }

  setWeight(val) {
    this.is16bitInt('URI', 'weight', val)

    this.set('weight', val)
  }

  setTarget(val) {
    if (!val) this.throwHelp(`URI: target is required`)

    this.set('target', val)
  }

  /******  IMPORTERS   *******/
  fromTinydns({ tinyline }) {
    // URI via generic, :fqdn:n:rdata:ttl:timestamp:lo
    const [fqdn, n, rdata, ttl, ts, loc] = tinyline.slice(1).split(':')
    if (n != 256) this.throwHelp('URI fromTinydns, invalid n')

    return new URI({
      type: 'URI',
      owner: this.fullyQualify(fqdn),
      priority: TINYDNS.octalToUInt16(rdata.slice(0, 8)),
      weight: TINYDNS.octalToUInt16(rdata.slice(8, 16)),
      target: TINYDNS.octalToChar(rdata.slice(16)),
      ttl: parseInt(ttl, 10),
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  /******  MISC   *******/
  getDescription() {
    return 'URI'
  }

  getRFCs() {
    return [7553]
  }

  getTypeId() {
    return 256
  }

  getCanonical() {
    return {
      owner: 'www.example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'URI',
      priority: 10,
      weight: 10,
      target: 'http://www.example.com/',
    }
  }

  fromWire({ owner, cls, ttl, rdata }) {
    const dv = new DataView(rdata.buffer, rdata.byteOffset)
    return new URI({
      owner,
      ttl,
      class: cls,
      type: 'URI',
      priority: dv.getUint16(0),
      weight: dv.getUint16(2),
      target: new TextDecoder().decode(rdata.subarray(4)),
    })
  }

  /******  EXPORTERS   *******/

  getWireRdata() {
    const target = new TextEncoder().encode(this.get('target'))
    const result = new Uint8Array(4 + target.length)
    const dv = new DataView(result.buffer)
    dv.setUint16(0, this.get('priority'))
    dv.setUint16(2, this.get('weight'))
    result.set(target, 4)
    return result
  }

  toTinydns() {
    const dataRe = new RegExp(/[\r\n\t:\\/]/, 'g')
    let rdata = ''

    for (const e of ['priority', 'weight']) {
      rdata += TINYDNS.UInt16toOctal(this.get(e))
    }

    rdata += TINYDNS.escapeOctal(dataRe, this.get('target'))
    return this.getTinydnsGeneric(rdata)
  }
}
