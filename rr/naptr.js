
const RR = require('./index').RR

class NAPTR extends RR {
  constructor (obj) {
    super(obj)
    this.set('id', 35)

    this.setOrder(obj?.order)
    this.setPref(obj?.pref)
    this.setFlags(obj?.flags)
    this.setService(obj?.service)
    this.setRegexp(obj?.regexp)
    this.setReplacement(obj?.replacement)
  }

  setOrder (val) {
    if (!this.is16bitInt('NAPTR', 'order', val)) return

    this.set('order', val)
  }

  setPref (val) {
    if (!this.is16bitInt('NAPTR', 'pref', val)) return
    this.set('pref', val)
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

  getRFCs () {
    return [ 2915, 3403 ]
  }

  toBind () {
    // TODO: regexp =~ s/\\/\\\\/g;  # escape any \ characters

    // Domain TTL Class Type Order Preference Flags Service Regexp Replacement
    return `${this.get('name')}\t${this.get('ttl')}\t${this.get('class')}\tNAPTR\t${this.get('order')}\t${this.get('pref')}\t"${this.get('flags')}"\t"${this.get('service')}"\t"${this.get('regexp')}"\t${this.get('replacement')}\n`
  }
}

module.exports = NAPTR
