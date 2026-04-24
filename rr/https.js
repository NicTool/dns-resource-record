import RR from '../rr.js'

import * as TINYDNS from '../lib/tinydns.js'
import * as WIRE from '../lib/wire.js'

export default class HTTPS extends RR {
  static typeName = 'HTTPS'
  static typeId = 65
  static RFCs = [9460]
  static tags = ['common']
  static rdataFields = [
    ['priority', 'u16'],
    ['target name', 'fqdn'],
    ['params', 'svcparams'],
  ]

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
    const { owner, typeId, rdata, ttl, timestamp, location } = this.parseTinydnsLine(tinyline)
    if (typeId != this.getTypeId()) this.throwHelp('HTTPS fromTinydns, invalid n')
    const { priority, targetName, params } = TINYDNS.parseSvcbLikeRdata(rdata, 'HTTPS')

    return new HTTPS({
      owner,
      ttl,
      type: 'HTTPS',
      priority,
      'target name': targetName,
      params,
      timestamp,
      location,
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
