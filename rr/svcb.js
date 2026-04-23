import RR from '../rr.js'

import * as TINYDNS from '../lib/tinydns.js'
import * as WIRE from '../lib/wire.js'

export default class SVCB extends RR {
  static typeName = 'SVCB'
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setPriority(val) {
    this.is16bitInt('SVCB', 'priority', val)

    this.set('priority', val)
  }

  setTargetName(val) {
    // this.isFullyQualified('SVCB', 'target name', val)
    // this.isValidHostname('SVCB', 'target name', val)

    // RFC 4034: letters in the DNS names are lower cased
    this.set('target name', val.toLowerCase())
  }

  setParams(val) {
    // if (!val) throw new Error(`SVCB: params is required`)

    this.set('params', val)
  }

  getDescription() {
    return 'Service Binding'
  }

  getRdataFields(arg) {
    return ['priority', 'target name', 'params']
  }

  getRFCs() {
    return [9460]
  }

  getTypeId() {
    return 64
  }

  getCanonical() {
    return {
      owner: '_8443._foo.api.example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'SVCB',
      priority: 1,
      'target name': 'svc4.example.net.',
      params: 'alpn="h2,h3"',
    }
  }

  /******  IMPORTERS   *******/

  fromBind({ bindline }) {
    // test.example.com  3600  IN  SVCB Priority TargetName Params
    // _8443._foo.api.example.com. 7200 IN SVCB 0 svc4.example.net.
    // svc4.example.net.  7200  IN SVCB 3 svc4.example.net. ( alpn="bar" port="8004" )
    const [owner, ttl, c, type, pri, fqdn] = bindline.split(/\s+/)
    return new SVCB({
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
      this.throwHelp(`SVCB: RDATA too short: ${rd}`)
    }

    // Convert escaped octal RDATA into a binary buffer for reliable parsing
    const binary = Uint8Array.from(TINYDNS.octalToChar(rd), (c) => c.charCodeAt(0))

    const priority = (binary[0] << 8) | binary[1]

    // parse domain name from binary starting at offset 2
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
    // remaining params are ASCII text after the domain
    const params = new TextDecoder().decode(binary.subarray(pos))

    return new SVCB({
      owner: this.fullyQualify(owner),
      ttl: parseInt(ttl, 10),
      type: 'SVCB',
      priority: priority,
      'target name': targetName,
      params: params,
      timestamp: ts,
      location: loc?.trim() ?? '',
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
