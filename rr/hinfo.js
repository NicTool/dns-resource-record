import RR from '../rr.js'

import * as TINYDNS from '../lib/tinydns.js'

export default class HINFO extends RR {
  static typeName = 'HINFO'
  static rdataFields = ['cpu', 'os']
  static quotedFields = ['cpu', 'os']

  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setCpu(val) {
    if (val.length > 255) this.throwHelp('HINFO cpu cannot exceed 255 chars')
    this.set('cpu', val.replace(/^["']|["']$/g, ''))
  }

  setOs(val) {
    if (val.length > 255) this.throwHelp('HINFO os cannot exceed 255 chars')
    this.set('os', val.replace(/^["']|["']$/g, ''))
  }

  getDescription() {
    return 'Host Info'
  }

  getTags() {
    return ['obsolete']
  }

  getRFCs() {
    return [1034, 1035, 8482]
  }

  getTypeId() {
    return 13
  }

  getCanonical() {
    return {
      owner: 'test.example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'HINFO',
      cpu: 'DEC-2060',
      os: 'TOPS20',
    }
  }

  /******  IMPORTERS   *******/
  fromTinydns({ tinyline }) {
    // HINFO via generic, :fqdn:n:rdata:ttl:timestamp:lo
    const [fqdn, , rdata, ttl, ts, loc] = tinyline.slice(1).split(':')
    const [cpu, os] = [...TINYDNS.unpackString(rdata)]

    return new this.constructor({
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'HINFO',
      cpu,
      os,
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  fromWire({ owner, cls, ttl, rdata }) {
    const cpuLen = rdata[0]
    const cpu = new TextDecoder().decode(rdata.subarray(1, 1 + cpuLen))
    const osLen = rdata[1 + cpuLen]
    const os = new TextDecoder().decode(rdata.subarray(2 + cpuLen, 2 + cpuLen + osLen))
    return new HINFO({ owner, ttl, class: cls, type: 'HINFO', cpu, os })
  }

  /******  EXPORTERS   *******/

  getWireRdata() {
    const cpu = new TextEncoder().encode(this.get('cpu'))
    const os = new TextEncoder().encode(this.get('os'))
    const result = new Uint8Array(2 + cpu.length + os.length)
    result[0] = cpu.length
    result.set(cpu, 1)
    result[1 + cpu.length] = os.length
    result.set(os, 2 + cpu.length)
    return result
  }

  toTinydns() {
    return this.getTinydnsGeneric(
      [TINYDNS.packString(this.get('cpu')), TINYDNS.packString(this.get('os'))].join(''),
    )
  }
}
