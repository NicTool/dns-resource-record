
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

  /****** Resource record specific setters   *******/
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
    const fields = [ 'name', 'ttl', 'class', 'type', 'order', 'pref' ]
    const quoted = [ 'flags', 'service', 'regexp' ]

    return `${fields.map(f => this.get(f)).join('\t')}\t`
      + `"${quoted.map(f => this.get(f)).join('"\t"')}"\t`
      + `${this.get('replacement')}\n`
  }
}

module.exports = NAPTR
