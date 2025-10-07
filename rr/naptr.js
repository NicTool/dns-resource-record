import RR from '../rr.js'
import * as TINYDNS from '../lib/tinydns.js'

const rdataRe = /[\r\n\t:\\/]/

export default class NAPTR extends RR {
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
    return [2915, 3403]
  }

  getTypeId() {
    return 35
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
    if (!this.getFlagsOptions().has(val.toUpperCase()))
      this.throwHelp(`NAPTR flags are invalid`)

    this.set('flags', val.toUpperCase())
  }

  getFlagsOptions () {
    return new Map([
      [ '' ],
      [ 'S' ],
      [ 'A' ],
      [ 'U' ],
      [ 'P' ],
    ])
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
  fromTinydns(opts) {
    // NAPTR via generic, :fqdn:n:rdata:ttl:timestamp:lo
    const [fqdn, n, rdata, ttl, ts, loc] = opts.tinyline.substring(1).split(':')
    if (n != 35) this.throwHelp('NAPTR fromTinydns, invalid n')

    const binRdata = Buffer.from(TINYDNS.octalToChar(rdata), 'binary')

    const rec = {
      type: 'NAPTR',
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      timestamp: ts,
      location: loc !== '' && loc !== '\n' ? loc : '',
      order: binRdata.readUInt16BE(0, 2),
      preference: binRdata.readUInt16BE(2, 4),
    }

    let idx = 4
    const flagsLength = binRdata.readUInt8(idx)
    idx++
    rec.flags = binRdata.slice(idx, flagsLength).toString()
    idx += flagsLength

    const serviceLen = binRdata.readUInt8(idx)
    idx++
    rec.service = binRdata.slice(idx, idx + serviceLen).toString()
    idx += serviceLen

    const regexpLen = binRdata.readUInt8(idx)
    idx++
    rec.regexp = binRdata.slice(idx, idx + regexpLen).toString()
    idx += regexpLen

    const replaceLen = binRdata.readUInt8(idx)
    idx++
    rec.replacement = binRdata.slice(idx, idx + replaceLen).toString()

    return new NAPTR(rec)
  }

  fromBind(opts) {
    const str = opts.bindline
    // test.example.com  3600  IN  NAPTR order, preference, "flags", "service", "regexp", replacement
    const [owner, ttl, c, type, order, preference] = str.split(/\s+/)
    const [flags, service, regexp] = str.match(/(?:").*?(?:"\s)/g)
    const replacement = str.trim().split(/\s+/).pop()

    const bits = {
      owner: owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type: type,
      order: parseInt(order, 10),
      preference: parseInt(preference, 10),
      flags: flags.trim().replace(/^['"]|['"]$/g, ''),
      service: service.trim().replace(/^['"]|['"]$/g, ''),
      regexp: regexp.trim().replace(/^['"]|['"]/g, ''),
      replacement: replacement,
    }
    return new NAPTR(bits)
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
}
