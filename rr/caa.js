
const RR = require('./index').RR
const TINYDNS = require('../lib/tinydns')

class CAA extends RR {
  constructor (opts) {
    super(opts)

    if (opts.tinyline) return this.fromTinydns(opts.tinyline)

    this.set('id', 257)
    this.setFlags(opts?.flags)
    this.setTag(opts?.tag)
    this.setValue(opts?.value)
  }

  /****** Resource record specific setters   *******/
  setFlags (val) {
    if (!this.is8bitInt('CAA', 'flags', val)) return

    if (![ 0, 128 ].includes(val)) {
      console.warn(`CAA flags ${val} not recognized: RFC 6844`)
    }

    this.set('flags', val)
  }

  setTag (val) {
    if (typeof val !== 'string'
      || val.length < 1
      || /[A-Z]/.test(val)
      || /[^a-z0-9]/.test(val))
      throw new Error('CAA flags must be a sequence of ASCII letters and numbers in lowercase: RFC 8659')

    if (![ 'issue', 'issuewild', 'iodef' ].includes(val)) {
      console.warn(`CAA tag ${val} not recognized: RFC 6844`)
    }
    this.set('tag', val)
  }

  setValue (val) {
    // either (2) a quoted string or
    // (1) a contiguous set of characters without interior spaces
    if (!/["']/.test(val) && /\s/.test(val)) {
      throw new Error(`CAA value may not have spaces unless quoted: RFC 8659`)
    }

    // const iodefSchemes = [ 'mailto:', 'http:', 'https:' ]
    // TODO: check if val starts with one of iodefSchemes, RFC 6844

    this.set('value', val)
  }

  getRFCs () {
    return [ 6844 ]
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
      type     : 'CAA',
      name     : fqdn,
      flags    : flags,
      tag      : tag,
      value    : fingerprint,
      ttl      : parseInt(ttl, 10),
      timestamp: ts,
      location : loc !== '' && loc !== '\n' ? loc : '',
    })
  }

  fromBind () {
    //
  }

  /******  EXPORTERS   *******/
  toBind () {
    let value = this.get('value')
    if (value[0] !== '"') value = `"${value}"` // add enclosing quotes

    const fields = [ 'name', 'ttl', 'class', 'type', 'flags', 'tag' ]
    return `${fields.map(f => this.get(f)).join('\t')}\t${value}\n`
  }

  toTinydns () {
    let rdata = ''
    rdata += TINYDNS.UInt8toOctal(this.get('flags'))

    rdata += TINYDNS.UInt8toOctal(this.get('tag').length)
    rdata += TINYDNS.escapeOctal(/[\r\n\t:\\/]/, this.get('tag'))

    rdata += TINYDNS.escapeOctal(/[\r\n\t:\\/]/, this.get('value'))

    return `:${this.get('name')}:257:${rdata}:${this.getEmpty('ttl')}:${this.getEmpty('timestamp')}:${this.getEmpty('location')}\n`
  }
}

module.exports = CAA
