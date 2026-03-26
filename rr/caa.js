import RR from '../rr.js'
import * as TINYDNS from '../lib/tinydns.js'

export default class CAA extends RR {
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setFlags(val) {
    this.is8bitInt('CAA', 'flags', val)

    if (!this.getFlagsOptions().has(val)) {
      this.throwHelp(`CAA flags ${val} not recognized`)
    }

    this.set('flags', val)
  }

  getFlagsOptions() {
    return new Map([
      [0, 'Non Critical'],
      [128, 'Critical'],
    ])
  }

  setTag(val) {
    if (typeof val !== 'string' || val.length < 1 || /[^a-z0-9]/.test(val))
      this.throwHelp(`CAA tag must be a sequence of ASCII letters and numbers in lowercase`)

    if (!this.getTagOptions().has(val)) {
      this.throwHelp(`CAA tag ${val} not recognized`)
    }
    this.set('tag', val)
  }

  getTagOptions() {
    return new Map([['issue'], ['issuewild'], ['iodef']])
  }

  setValue(val) {
    // either (2) a quoted string or
    // (1) a contiguous set of characters without interior spaces
    if (this.isQuoted(val)) {
      val = val.replace(/^["']|["']$/g, '') // strip quotes
    } else {
      // if (/\s/.test(val)) this.throwHelp(`CAA value may not have spaces unless quoted`)
    }

    // check if val starts with one of iodefSchemes
    if (this.get('tag') === 'iodef') {
      const iodefSchemes = ['mailto:', 'http:', 'https:']
      if (!iodefSchemes.filter((s) => val.startsWith(s)).length) {
        this.throwHelp(`CAA value must have valid iodefScheme prefix`)
      }
    }

    this.set('value', val)
  }

  getDescription() {
    return 'Certification Authority Authorization'
  }

  getTags() {
    return ['security']
  }

  getQuotedFields() {
    return ['value']
  }

  getRdataFields(arg) {
    return ['flags', 'tag', 'value']
  }

  getRFCs() {
    return [6844, 8659]
  }

  getTypeId() {
    return 257
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'CAA',
      flags: 0,
      tag: 'issue',
      value: 'http://letsencrypt.org',
    }
  }

  /******  IMPORTERS   *******/
  fromTinydns({ tinyline }) {
    // CAA via generic, :fqdn:n:rdata:ttl:timestamp:lo
    const [fqdn, n, rdata, ttl, ts, loc] = tinyline.slice(1).split(':')
    if (n != 257) this.throwHelp('CAA fromTinydns, invalid n')

    const flags = TINYDNS.octalToUInt8(rdata.slice(0, 4))
    const taglen = TINYDNS.octalToUInt8(rdata.slice(4, 8))

    const unescaped = TINYDNS.octalToChar(rdata.slice(8))
    const tag = unescaped.slice(0, taglen)
    const fingerprint = unescaped.slice(taglen)

    return new CAA({
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'CAA',
      flags,
      tag,
      value: fingerprint,
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  fromBind({ bindline }) {
    // test.example.com  3600  IN  CAA flags, tags, value
    const regex =
      /^(?<owner>\S+)\s+(?<ttl>\d{1,10})\s+(?<class>IN)\s+(?<type>CAA)\s+(?<flags>\d+)\s+(?<tag>\w+)\s+(?:"(?<quotedValue>[^"]+)"|(?<unquotedValue>\S+))$/i

    const match = bindline.trim().match(regex)

    if (!match) {
      this.throwHelp(`unable to parse CAA: ${bindline}`)
    }

    const { owner, ttl, class: c, type, flags, tag, quotedValue, unquotedValue } = match.groups

    return new CAA({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type,
      flags: parseInt(flags, 10),
      tag,
      value: quotedValue ?? unquotedValue,
    })
  }

  /******  EXPORTERS   *******/

  toTinydns() {
    return this.getTinydnsGeneric(
      TINYDNS.UInt8toOctal(this.get('flags')) +
        TINYDNS.UInt8toOctal(this.get('tag').length) +
        TINYDNS.escapeOctal(/[\r\n\t:\\/]/, this.get('tag')) +
        TINYDNS.escapeOctal(/[\r\n\t:\\/]/, this.getQuoted('value')),
    )
  }
}
