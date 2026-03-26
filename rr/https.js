import RR from '../rr.js'

import * as TINYDNS from '../lib/tinydns.js'

export default class HTTPS extends RR {
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

  getRdataFields(arg) {
    return ['priority', 'target name', 'params']
  }

  getRFCs() {
    return [9460]
  }

  getTypeId() {
    return 65
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

    const binary = Buffer.from(TINYDNS.octalToChar(rd), 'binary')
    const priority = binary.readUInt16BE(0)

    let pos = 2
    const labels = []
    while (true) {
      const len = binary.readUInt8(pos)
      pos += 1
      if (len === 0) break
      labels.push(binary.slice(pos, pos + len).toString())
      pos += len
    }
    const targetName = `${labels.join('.')}.`
    const params = binary.slice(pos).toString()

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

  /******  EXPORTERS   *******/

  toTinydns() {
    const dataRe = new RegExp(/[\r\n\t:\\/]/, 'g')

    return this.getTinydnsGeneric(
      TINYDNS.UInt16toOctal(this.get('priority')) +
        TINYDNS.packDomainName(this.get('target name')) +
        TINYDNS.escapeOctal(dataRe, this.get('params')),
    )
  }
}
