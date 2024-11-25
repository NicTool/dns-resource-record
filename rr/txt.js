import RR from '../rr.js'

import * as TINYDNS from '../lib/tinydns.js'

export default class TXT extends RR {
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setData(val) {
    this.set('data', val)
  }

  getDescription() {
    return 'Text'
  }

  getRdataFields(arg) {
    return ['data']
  }

  getRFCs() {
    return [1035]
  }

  getTypeId() {
    return 16
  }

  /******  IMPORTERS   *******/
  fromTinydns(opts) {
    const str = opts.tinyline
    let fqdn, rdata, s, ttl, ts, loc
    // 'fqdn:s:ttl:timestamp:lo
    if (str[0] === "'") {
      ;[fqdn, s, ttl, ts, loc] = str.substring(1).split(':')
      rdata = TINYDNS.octalToChar(s)
    } else {
      ;[fqdn, rdata, ttl, ts, loc] = this.fromTinydnsGeneric(str)
    }

    return new this.constructor({
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'TXT',
      data: rdata,
      timestamp: ts,
      location: loc !== '' && loc !== '\n' ? loc : '',
    })
  }

  fromTinydnsGeneric(str) {
    // generic: :fqdn:n:rdata:ttl:timestamp:location
    // eslint-disable-next-line prefer-const
    let [fqdn, n, rdata, ttl, ts, loc] = str.substring(1).split(':')
    if (n != 16) this.throwHelp('TXT fromTinydns, invalid n')

    rdata = TINYDNS.octalToChar(rdata)
    let s = ''
    let len = rdata[0].charCodeAt(0)
    let pos = 1
    while (pos < rdata.length) {
      s += rdata.substring(pos, +(len + pos))
      pos = len + pos
      len = rdata.charCodeAt(pos + 1)
    }
    return [fqdn, s, ttl, ts, loc]
  }

  fromBind(opts) {
    // test.example.com  3600  IN  TXT  "..."
    const match = opts.bindline
      .trim()
      .split(/^([\S]{1,255})\s+([0-9]{1,10})\s+(IN)\s+(\w{3})\s+?\s*(.*?)$/i)
    if (!match) this.throwHelp(`unable to parse TXT: ${opts.bindline}`)
    const [owner, ttl, c, type, rdata] = match.slice(1)

    return new this.constructor({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type,
      data: rdata
        .match(/"([^"]+?)"/g)
        .map((s) => s.replace(/^"|"$/g, ''))
        .join(''),
    })
  }

  /******  EXPORTERS   *******/
  toBind(zone_opts) {
    return `${this.getPrefix(zone_opts)}\t"${asQuotedStrings(this.get('data'))}"\n`
  }

  toMaraDNS() {
    const data = asQuotedStrings(this.get('data')).replace(/"/g, "'")
    return `${this.get('owner')}\t+${this.get('ttl')}\t${this.get('type')}\t'${data}' ~\n`
  }

  toTinydns() {
    let data = this.get('data')
    if (Array.isArray(data)) data = data.join('')
    const rdata = TINYDNS.escapeOctal(new RegExp(/[\r\n\t:\\/]/, 'g'), data)
    return `'${this.getTinyFQDN('owner')}:${rdata}:${this.getTinydnsPostamble()}\n`
  }
}

function asQuotedStrings(data) {
  // BIND croaks when any string in the TXT RR data is longer than 255
  if (Array.isArray(data)) {
    let hasTooLong = false
    for (const str of data) {
      if (str.length > 255) hasTooLong = true
    }
    return hasTooLong
      ? data
          .join('')
          .match(/(.{1,255})/g)
          .join('" "')
      : data.join('" "')
  }

  if (data.length > 255) {
    return data.match(/(.{1,255})/g).join('" "')
  }

  return data
}
