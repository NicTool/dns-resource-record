
const RR = require('./index').RR
const TINYDNS = require('../lib/tinydns')

const rdataRe = /[\r\n\t:\\/]/

class NAPTR extends RR {
  constructor (opts) {
    super(opts)
  }

  getDescription () {
    return 'Naming Authority Pointer'
  }

  getQuotedFields () {
    return [ 'flags', 'service', 'regexp' ]
  }

  getRdataFields (arg) {
    return [ 'order', 'preference', 'flags', 'service', 'regexp', 'replacement' ]
  }

  getRFCs () {
    return [ 2915, 3403 ]
  }

  getTypeId () {
    return 35
  }

  /****** Resource record specific setters   *******/
  setOrder (val) {
    this.is16bitInt('NAPTR', 'order', val)
    this.set('order', val)
  }

  setPreference (val) {
    this.is16bitInt('NAPTR', 'preference', val)
    this.set('preference', val)
  }

  setFlags (val) {
    if (![ '', 'S', 'A', 'U', 'P' ].includes(val))
      throw new Error (`NAPTR flags are invalid, ${this.citeRFC()}`)

    this.set('flags', val)
  }

  setService (val) {
    this.set('service', val)
  }

  setRegexp (val) {
    this.set('regexp', val)
  }

  setReplacement (val) {
    this.set('replacement', val)
  }

  /******  IMPORTERS   *******/
  fromTinydns (str) {
    // NAPTR via generic, :fqdn:n:rdata:ttl:timestamp:lo
    const [ fqdn, n, rdata, ttl, ts, loc ] = str.substring(1).split(':')
    if (n != 35) throw new Error('NAPTR fromTinydns, invalid n')

    const rec = {
      type      : 'NAPTR',
      owner     : this.fullyQualify(fqdn),
      ttl       : parseInt(ttl, 10),
      timestamp : ts,
      location  : loc !== '' && loc !== '\n' ? loc : '',
      order     : TINYDNS.octalToUInt16(rdata.substr(0, 8)),
      preference: TINYDNS.octalToUInt16(rdata.substr(8, 8)),
    }
    /*
    TODO: incomplete, need to remove octal escapes from regexp
    'cid.urn.arpa\t86400\tIN\tNAPTR\t100\t10\t""\t""\t"!^urn:cid:.+@([^\\.]+\\.)(.*)$!\x02!i"\t.\n',
    ':cid.urn.arpa:35:
    \000\144\000\012\000\000\040!^urn\072cid\072.+@([^\134.]+\134.)(.*)$!\x02!i\001.``000:86400::'
    */

    let idx = 16
    const flagsLength = TINYDNS.octalToUInt8(rdata.substr(idx, 4))
    rec.flags = rdata.substr(idx+4, flagsLength)
    idx += 4 + flagsLength

    const serviceLen = TINYDNS.octalToUInt8(rdata.substr(idx, 4))
    rec.service = TINYDNS.octalToChar(rdata.substr(idx+4, serviceLen))
    idx += 4 + serviceLen

    const regexpLen = TINYDNS.octalToUInt8(rdata.substr(idx, 4))
    rec.regexp = TINYDNS.octalToChar(rdata.substr(idx+4, regexpLen))
    idx += 4 + regexpLen

    const replaceLen = TINYDNS.octalToUInt8(rdata.substr(idx, 4))
    rec.replacement = TINYDNS.octalToChar(rdata.substr(idx+4, replaceLen))

    return new this.constructor(rec)
  }

  fromBind (str) {
    // test.example.com  3600  IN  NAPTR order, preference, "flags", "service", "regexp", replacement
    const [ owner, ttl, c, type, order, preference ] = str.split(/\s+/)
    const [ flags, service, regexp ] = str.match(/(?:").*?(?:"\s)/g)
    const replacement = str.trim().split(/\s+/).pop()

    const bits = {
      owner      : owner,
      ttl        : parseInt(ttl, 10),
      class      : c,
      type       : type,
      order      : parseInt(order, 10),
      preference : parseInt(preference, 10),
      flags      : flags.trim().replace(/^"|"$/g, ''),
      service    : service.trim().replace(/^"|"$/g, ''),
      regexp     : regexp.trim().replace(/^"|"$/g, ''),
      replacement: replacement,
    }
    return new this.constructor(bits)
  }

  /******  EXPORTERS   *******/
  toTinydns () {

    let rdata = ''
    rdata += TINYDNS.UInt16toOctal(this.get('order'))
    rdata += TINYDNS.UInt16toOctal(this.get('preference'))

    rdata += TINYDNS.UInt8toOctal(this.get('flags').length)
    rdata += this.get('flags')

    rdata += TINYDNS.UInt8toOctal(this.get('service').length)
    rdata += TINYDNS.escapeOctal(rdataRe, this.get('service'))

    rdata += TINYDNS.UInt8toOctal(this.get('regexp').length)
    rdata += TINYDNS.escapeOctal(rdataRe, this.get('regexp'))

    if (this.set('replacement' !== '')) {
      rdata += TINYDNS.UInt8toOctal(this.get('replacement').length)
      rdata += TINYDNS.escapeOctal(rdataRe, this.get('replacement'))
    }
    rdata += '``000'

    return this.getTinydnsGeneric(rdata)
  }
}

module.exports = NAPTR
