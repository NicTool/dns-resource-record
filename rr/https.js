import RR from '../rr.js'

import * as TINYDNS from '../lib/tinydns.js'
import * as WIRE from '../lib/wire.js'

export default class HTTPS extends RR {
  static typeName = 'HTTPS'
  static rdataFields = ['priority', 'target name', 'params']
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setPriority(val) {
    this.is16bitInt('HTTPS', 'priority', val)

    this.set('priority', val)
  }

  setTargetName(val) {
    // this.isFullyQualified('HTTPS', 'target name', val)
    // this.isValidHostname('HTTPS', 'target name', val)

    // RFC 4034: letters in the DNS names are lower cased
    this.set('target name', val.toLowerCase())
  }

  setParams(val) {
    // if (!val) this.throwHelp(`HTTPS: params is required`)

    this.set('params', val)
  }

  getDescription() {
    return 'HTTP Semantics'
  }

  getTags() {
    return ['common']
  }

  getRFCs() {
    return [9460]
  }

  getTypeId() {
    return 65
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'HTTPS',
      priority: 1,
      'target name': 'example.com.',
      params: 'alpn="h2,h3"',
    }
  }

  /******  IMPORTERS   *******/

  fromBind({ bindline }) {
    // test.example.com  3600  IN  HTTPS Priority TargetName Params
    const [owner, ttl, c, type, pri, fqdn] = bindline.split(/\s+/)
    return new HTTPS({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type,
      priority: parseInt(pri, 10),
      'target name': fqdn,
      params: bindline.split(/\s+/).slice(6).join(' ').trim(),
    })
  }

  fromTinydns({ tinyline }) {
    const [owner, _typeId, rd, ttl, ts, loc] = tinyline.slice(1).split(':')

    if (rd.length < 6) {
      this.throwHelp(`HTTPS: RDATA too short: ${rd}`)
    }

    const binary = Uint8Array.from(TINYDNS.octalToChar(rd), (c) => c.charCodeAt(0))
    const priority = (binary[0] << 8) | binary[1]

    let pos = 2
    const labels = []
    while (true) {
      const len = binary[pos]
      pos += 1
      if (len === 0) break
      labels.push(new TextDecoder().decode(binary.subarray(pos, pos + len)))
      pos += len
    }
    const targetName = `${labels.join('.')}.`
    const params = new TextDecoder().decode(binary.subarray(pos))

    return new HTTPS({
      owner: this.fullyQualify(owner),
      ttl: parseInt(ttl, 10),
      type: 'HTTPS',
      priority,
      'target name': targetName,
      params,
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  fromWire({ owner, cls, ttl, rdata }) {
    const dv = new DataView(rdata.buffer, rdata.byteOffset)
    const priority = dv.getUint16(0)
    const { fqdn: targetName, end } = this.wireUnpackDomain(rdata, 2)
    const params = WIRE.svcParamsFromWire(rdata.subarray(end))
    return new HTTPS({
      owner,
      ttl,
      class: cls,
      type: 'HTTPS',
      priority,
      'target name': targetName,
      params,
    })
  }

  /******  EXPORTERS   *******/

  toTinydns() {
    const dataRe = new RegExp(/[\r\n\t:\\/]/, 'g')

    return this.getTinydnsGeneric(
      TINYDNS.UInt16toOctal(this.get('priority')) +
        TINYDNS.packDomainName(this.get('target name')) +
        TINYDNS.escapeOctal(dataRe, this.get('params')),
    )
  }

  getWireRdata() {
    const targetBytes = this.wirePackDomain(this.get('target name'))
    const paramsBytes = WIRE.svcParamsToWire(this.get('params'))
    const result = new Uint8Array(2 + targetBytes.length + paramsBytes.length)
    new DataView(result.buffer).setUint16(0, this.get('priority'))
    result.set(targetBytes, 2)
    result.set(paramsBytes, 2 + targetBytes.length)
    return result
  }
}
