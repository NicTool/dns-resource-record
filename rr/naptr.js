
const RR = require('./index').RR
const TINYDNS = require('../lib/tinydns')

class NAPTR extends RR {
  constructor (obj) {
    super(obj)
    this.set('id', 35)

    this.setOrder(obj?.order)
    this.setPreference(obj?.preference)
    this.setFlags(obj?.flags)
    this.setService(obj?.service)
    this.setRegexp(obj?.regexp)
    this.setReplacement(obj?.replacement)
  }

  /****** Resource record specific setters   *******/
  setOrder (val) {
    if (!this.is16bitInt('NAPTR', 'order', val)) return

    this.set('order', val)
  }

  setPreference (val) {
    if (!this.is16bitInt('NAPTR', 'preference', val)) return
    this.set('preference', val)
  }

  setFlags (val) {
    if (![ '', 'S', 'A', 'U', 'P' ].includes(val))
      throw new Error (`NAPTR flags are invalid: RFC 2915`)

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
  fromTinydns () {
    //
  }

  fromBind () {
    //
  }

  getRFCs () {
    return [ 2915, 3403 ]
  }

  /******  EXPORTERS   *******/
  toBind () {
    // TODO: regexp =~ s/\\/\\\\/g;  # escape any \ characters

    // Domain TTL Class Type Order Preference Flags Service Regexp Replacement
    const fields = [ 'name', 'ttl', 'class', 'type', 'order', 'preference', 'flags', 'service', 'regexp', 'replacement' ]
    const quoted = [ 'flags', 'service', 'regexp' ]

    return `${fields.map(f => quoted.includes(f) ? this.getQuoted(f) : this.get(f)).join('\t')}\n`
  }

  toTinydns () {
    const rdataRe = /[\r\n\t:\\/]/

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

    return `:${this.get('name')}:35:${rdata}:${this.get('ttl')}::`
  }
}

module.exports = NAPTR
