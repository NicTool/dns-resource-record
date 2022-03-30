
const RR = require('./index').RR
const TINYDNS = require('../lib/tinydns')

class CAA extends RR {
  constructor (opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setFlags (val) {
    this.is8bitInt('CAA', 'flags', val)

    if (![ 0, 128 ].includes(val)) {
      throw new Error(`CAA flags ${val} not recognized, RFC ${this.getRFCs()}`)
    }

    this.set('flags', val)
  }

  setTag (val) {
    if (typeof val !== 'string'
      || val.length < 1
      || /[^a-z0-9]/.test(val))
      throw new Error(`CAA tag must be a sequence of ASCII letters and numbers in lowercase, RFC ${this.getRFCs()}`)

    if (![ 'issue', 'issuewild', 'iodef' ].includes(val)) {
      throw new Error(`CAA tag ${val} not recognized: ${this.getRFCs()}`)
    }
    this.set('tag', val)
  }

  setValue (val) {
    // either (2) a quoted string or
    // (1) a contiguous set of characters without interior spaces
    if (this.isQuoted(val)) {
      val = val.replace(/^["']|["']$/g, '') // strip quotes
    }
    else {
      // if (/\s/.test(val)) throw new Error(`CAA value may not have spaces unless quoted: RFC 8659`)
    }

    // check if val starts with one of iodefSchemes
    const iodefSchemes = [ 'mailto:', 'http:', 'https:' ]
    if (!iodefSchemes.filter(s => val.startsWith(s)).length) {
      throw new Error(`CAA value must have valid iodefScheme prefix, RFC ${this.getRFCs()}`)
    }

    this.set('value', val)
  }

  getDescription () {
    return 'Certification Authority Authorization'
  }

  getQuotedFields () {
    return [ 'value' ]
  }

  getRdataFields (arg) {
    return [ 'flags', 'tag', 'value' ]
  }

  getRFCs () {
    return [ 6844, 8659 ]
  }

  getTypeId () {
    return 257
  }

  /******  IMPORTERS   *******/
  fromTinydns (str) {
    // CAA via generic, :fqdn:n:rdata:ttl:timestamp:lo
    const [ fqdn, n, rdata, ttl, ts, loc ] = str.substring(1).split(':')
    if (n != 257) throw new Error('CAA fromTinydns, invalid n')

    const flags  = TINYDNS.octalToUInt8(rdata.substring(0, 4))
    const taglen = TINYDNS.octalToUInt8(rdata.substring(4, 8))

    const unescaped   = TINYDNS.octalToChar(rdata.substring(8))
    const tag         = unescaped.substring(0, taglen)
    const fingerprint = unescaped.substring(taglen)

    return new this.constructor({
      owner    : this.fullyQualify(fqdn),
      ttl      : parseInt(ttl, 10),
      type     : 'CAA',
      flags,
      tag,
      value    : fingerprint,
      timestamp: ts,
      location : loc !== '' && loc !== '\n' ? loc : '',
    })
  }

  fromBind (str) {
    // test.example.com  3600  IN  CAA flags, tags, value
    const [ owner, ttl, c, type, flags, tag ] = str.split(/\s+/)
    return new this.constructor({
      owner,
      ttl  : parseInt(ttl, 10),
      class: c,
      type,
      flags: parseInt(flags, 10),
      tag,
      value: str.split(/\s+/).slice(6).join(' ').trim(),
    })
  }

  /******  EXPORTERS   *******/

  toTinydns () {
    let rdata = ''
    rdata += TINYDNS.UInt8toOctal(this.get('flags'))

    rdata += TINYDNS.UInt8toOctal(this.get('tag').length)
    rdata += TINYDNS.escapeOctal(/[\r\n\t:\\/]/, this.get('tag'))

    rdata += TINYDNS.escapeOctal(/[\r\n\t:\\/]/, this.getQuoted('value'))

    return this.getTinydnsGeneric(rdata)
  }
}

module.exports = CAA
