import RR from '../rr.js'
import * as TINYDNS from '../lib/tinydns.js'

export default class SRV extends RR {
  static typeName = 'SRV'
  static rdataFields = ['priority', 'weight', 'port', 'target']
  static fqdnFields = ['target']

  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setPriority(val) {
    this.is16bitInt('SRV', 'priority', val)
    this.set('priority', val)
  }

  setPort(val) {
    this.is16bitInt('SRV', 'port', val)
    this.set('port', val)
  }

  setWeight(val) {
    this.is16bitInt('SRV', 'weight', val)
    this.set('weight', val)
  }

  setTarget(val) {
    this.setFqdnValue('SRV', 'target', val)
  }

  getDescription() {
    return 'Service'
  }

  getTags() {
    return ['common']
  }

  getRFCs() {
    return [2782]
  }

  getTypeId() {
    return 33
  }

  getCanonical() {
    return {
      owner: '_imaps._tcp.example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'SRV',
      priority: 10,
      weight: 10,
      port: 993,
      target: 'mail.example.com.',
    }
  }

  /******  IMPORTERS   *******/
  fromTinydns({ tinyline }) {
    const str = tinyline
    let fqdn, addr, port, pri, weight, ttl, ts, loc, n, rdata

    if (str[0] === 'S') {
      // patched tinydns with S records
      ;[fqdn, addr, port, pri, weight, ttl, ts, loc] = str.slice(1).split(':')
    } else {
      // tinydns generic record format
      ;[fqdn, n, rdata, ttl, ts, loc] = str.slice(1).split(':')
      if (n != 33) this.throwHelp('SRV fromTinydns: invalid n')

      pri = TINYDNS.octalToUInt16(rdata.slice(0, 8))
      weight = TINYDNS.octalToUInt16(rdata.slice(8, 16))
      port = TINYDNS.octalToUInt16(rdata.slice(16, 24))
      addr = TINYDNS.unpackDomainName(rdata.slice(24))[0]
    }

    return new SRV({
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'SRV',
      priority: parseInt(pri, 10),
      weight: parseInt(weight, 10),
      port: parseInt(port, 10),
      target: this.fullyQualify(addr),
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  fromWire({ owner, cls, ttl, rdata }) {
    const dv = new DataView(rdata.buffer, rdata.byteOffset)
    const priority = dv.getUint16(0)
    const weight = dv.getUint16(2)
    const port = dv.getUint16(4)
    const { fqdn: target } = this.wireUnpackDomain(rdata, 6)
    return new SRV({ owner, ttl, class: cls, type: 'SRV', priority, weight, port, target })
  }

  /******  EXPORTERS   *******/

  getWireRdata() {
    const target = this.wirePackDomain(this.get('target'))
    const result = new Uint8Array(6 + target.length)
    const dv = new DataView(result.buffer)
    dv.setUint16(0, this.get('priority'))
    dv.setUint16(2, this.get('weight'))
    dv.setUint16(4, this.get('port'))
    result.set(target, 6)
    return result
  }

  toTinydns() {
    let rdata = ''

    for (const e of ['priority', 'weight', 'port']) {
      rdata += TINYDNS.UInt16toOctal(this.get(e))
    }

    rdata += TINYDNS.packDomainName(this.get('target'))

    return this.getTinydnsGeneric(rdata)
  }
}
