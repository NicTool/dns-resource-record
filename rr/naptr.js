import RR from '../rr.js'
import * as TINYDNS from '../lib/tinydns.js'

const rdataRe = /[\r\n\t:\\/]/

export default class NAPTR extends RR {
  static typeName = 'NAPTR'
  constructor(opts) {
    super(opts)
  }

  getDescription() {
    return 'Naming Authority Pointer'
  }

  getQuotedFields() {
    return ['flags', 'service', 'regexp']
  }

  getRdataFields(arg) {
    return ['order', 'preference', 'flags', 'service', 'regexp', 'replacement']
  }

  getRFCs() {
    return [2915, 3403, 4848]
  }

  getTypeId() {
    return 35
  }

  getCanonical() {
    return {
      owner: 'cid.urn.arpa.',
      ttl: 3600,
      class: 'IN',
      type: 'NAPTR',
      order: 100,
      preference: 10,
      flags: 'S',
      service: 'z3950+N2L+N2R',
      regexp: '',
      replacement: 'gatekeeper.example.com.',
    }
  }

  /****** Resource record specific setters   *******/
  setOrder(val) {
    this.is16bitInt('NAPTR', 'order', val)
    this.set('order', val)
  }

  setPreference(val) {
    this.is16bitInt('NAPTR', 'preference', val)
    this.set('preference', val)
  }

  setFlags(val) {
    if (!this.getFlagsOptions().has(val.toUpperCase())) this.throwHelp(`NAPTR flags are invalid`)

    this.set('flags', val.toUpperCase())
  }

  getFlagsOptions() {
    return new Map([[''], ['S'], ['A'], ['U'], ['P']])
  }

  setService(val) {
    this.set('service', val)
  }

  setRegexp(val) {
    this.set('regexp', val)
  }

  setReplacement(val) {
    this.set('replacement', val)
  }

  /******  IMPORTERS   *******/
  fromTinydns({ tinyline }) {
    // NAPTR via generic, :fqdn:n:rdata:ttl:timestamp:lo
    const [fqdn, n, rdata, ttl, ts, loc] = tinyline.slice(1).split(':')
    if (n != 35) this.throwHelp('NAPTR fromTinydns, invalid n')

    const binRdata = Uint8Array.from(TINYDNS.octalToChar(rdata), (c) => c.charCodeAt(0))
    const dv = new DataView(binRdata.buffer, binRdata.byteOffset, binRdata.byteLength)

    const rec = {
      type: 'NAPTR',
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      timestamp: ts,
      location: loc?.trim() ?? '',
      order: dv.getUint16(0),
      preference: dv.getUint16(2),
    }

    let idx = 4
    const flagsLength = binRdata[idx]
    idx++
    rec.flags = new TextDecoder().decode(binRdata.subarray(idx, idx + flagsLength))
    idx += flagsLength

    const serviceLen = binRdata[idx]
    idx++
    rec.service = new TextDecoder().decode(binRdata.subarray(idx, idx + serviceLen))
    idx += serviceLen

    const regexpLen = binRdata[idx]
    idx++
    rec.regexp = new TextDecoder().decode(binRdata.subarray(idx, idx + regexpLen))
    idx += regexpLen

    const replaceLen = binRdata[idx]
    idx++
    rec.replacement = new TextDecoder().decode(binRdata.subarray(idx, idx + replaceLen))

    return new NAPTR(rec)
  }

  fromBind({ bindline }) {
    const regex =
      /^(?<owner>\S+)\s+(?<ttl>\d+)\s+(?<class>\S+)\s+(?<type>NAPTR)\s+(?<order>\d+)\s+(?<preference>\d+)\s+["'](?<flags>[^"']*)["']\s+["'](?<service>[^"']*)["']\s+["'](?<regexp>[^"']*)["']\s+(?<replacement>\S+)$/

    const match = bindline.trim().match(regex)

    if (!match) {
      throw new Error(`Invalid NAPTR BIND line: ${bindline}`)
    }

    const { owner, ttl, type, order, preference, flags, service, regexp, replacement } = match.groups

    return new NAPTR({
      owner: this.fullyQualify(owner),
      ttl: parseInt(ttl, 10),
      class: match.groups.class,
      type,
      order: parseInt(order, 10),
      preference: parseInt(preference, 10),
      flags,
      service,
      regexp,
      replacement,
    })
  }

  /******  EXPORTERS   *******/
  toTinydns() {
    let rdata =
      TINYDNS.UInt16toOctal(this.get('order')) +
      TINYDNS.UInt16toOctal(this.get('preference')) +
      TINYDNS.UInt8toOctal(this.get('flags').length) +
      this.get('flags') +
      TINYDNS.UInt8toOctal(this.get('service').length) +
      TINYDNS.escapeOctal(rdataRe, this.get('service')) +
      TINYDNS.UInt8toOctal(this.get('regexp').length) +
      TINYDNS.escapeOctal(rdataRe, this.get('regexp'))

    const replacement = this.get('replacement')
    if (replacement !== '') {
      rdata += TINYDNS.UInt8toOctal(replacement.length)
      rdata += TINYDNS.escapeOctal(rdataRe, replacement)
    }
    rdata += '\\000'

    return this.getTinydnsGeneric(rdata)
  }

  getWireRdata() {
    const enc = new TextEncoder()
    const flags = enc.encode(this.get('flags'))
    const service = enc.encode(this.get('service'))
    const regexp = enc.encode(this.get('regexp'))
    const replacementBytes = this.wirePackDomain(this.get('replacement'))

    const len = 4 + 1 + flags.length + 1 + service.length + 1 + regexp.length + replacementBytes.length
    const buf = new Uint8Array(len)
    const view = new DataView(buf.buffer)
    let pos = 0
    view.setUint16(pos, this.get('order'))
    pos += 2
    view.setUint16(pos, this.get('preference'))
    pos += 2
    buf[pos++] = flags.length
    buf.set(flags, pos)
    pos += flags.length
    buf[pos++] = service.length
    buf.set(service, pos)
    pos += service.length
    buf[pos++] = regexp.length
    buf.set(regexp, pos)
    pos += regexp.length
    buf.set(replacementBytes, pos)
    return buf
  }
}
