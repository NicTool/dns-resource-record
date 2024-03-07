import net from 'net'

import RR from '../rr.js'
import * as TINYDNS from '../lib/tinydns.js'

export default class AAAA extends RR {
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setAddress(val) {
    if (!val) throw new Error('AAAA: address is required')
    if (!net.isIPv6(val)) throw new Error(`AAAA: address must be IPv6 (${val})`)

    this.set('address', this.expand(val.toLowerCase())) // lower case: RFC 5952
  }

  getCompressed(val) {
    this.compress(val || this.get('address'))
  }

  getDescription() {
    return 'Address IPv6'
  }

  getRdataFields(arg) {
    return ['address']
  }

  getRFCs() {
    return [3596]
  }

  getTypeId() {
    return 28
  }

  /******  IMPORTERS   *******/
  fromTinydns(opts) {
    const str = opts.tinyline
    let fqdn, ip, n, rdata, ttl, ts, loc

    switch (str[0]) {
      case ':':
        // GENERIC  =>  :fqdn:28:rdata:ttl:timestamp:lo
        ;[fqdn, n, rdata, ttl, ts, loc] = str.substring(1).split(':')
        if (n != 28) throw new Error('AAAA fromTinydns, invalid n')
        ip = TINYDNS.octalToHex(rdata)
          .match(/([0-9a-fA-F]{4})/g)
          .join(':')
        break
      case '3':
      case '6':
        // AAAA     =>  3fqdn:ip:x:ttl:timestamp:lo
        // AAAA,PTR =>  6fqdn:ip:x:ttl:timestamp:lo
        ;[fqdn, rdata, ttl, ts, loc] = str.substring(1).split(':')
        ip = rdata.match(/(.{4})/g).join(':')
        break
    }

    return new AAAA({
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'AAAA',
      address: ip,
      timestamp: ts,
      location: loc !== '' && loc !== '\n' ? loc : '',
    })
  }

  fromBind(opts) {
    // test.example.com  3600  IN  AAAA  ...
    const [owner, ttl, c, type, ip] = opts.bindline.split(/\s+/)
    return new AAAA({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type,
      address: this.expand(ip),
    })
  }

  compress(val) {
    /*
     * RFC 5952
     * 4.1. Leading zeros MUST be suppressed...A single 16-bit 0000 field MUST be represented as 0.
     * 4.2.1 The use of the symbol "::" MUST be used to its maximum capability.
     * 4.2.2 The symbol "::" MUST NOT be used to shorten just one 16-bit 0 field.
     * 4.2.3 When choosing placement of a "::", the longest run...MUST be shortened
     * 4.3 The characters a-f in an IPv6 address MUST be represented in lowercase.
     */
    let r = val
      .replace(/0000/g, '0') // 4.1 0000 -> 0
      .replace(/:0+([1-9a-fA-F])/g, ':$1') // 4.1 remove leading zeros

    const mostConsecutiveZeros = [
      new RegExp(/0?(?::0){6,}:0?/),
      new RegExp(/0?(?::0){5,}:0?/),
      new RegExp(/0?(?::0){4,}:0?/),
      new RegExp(/0?(?::0){3,}:0?/),
      new RegExp(/0?(?::0){2,}:0?/),
    ]

    for (const re of mostConsecutiveZeros) {
      if (re.test(r)) {
        r = r.replace(re, '::')
        break
      }
    }

    return r
  }

  expand(val, delimiter) {
    if (delimiter === undefined) delimiter = ':'

    const colons = val.match(/:/g)
    if (colons && colons.length < 7) {
      // console.log(`AAAA: restoring compressed colons`)
      val = val.replace(/::/, ':'.repeat(9 - colons.length))
    }

    // restore compressed leading zeros
    return val
      .split(':')
      .map((s) => s.padStart(4, 0))
      .join(delimiter)
  }

  /******  EXPORTERS   *******/
  toBind(zone_opts) {
    return `${this.getPrefix(zone_opts)}\t${this.compress(this.get('address'))}\n`
  }

  toTinydns() {
    // from AAAA notation (8 groups of 4 hex digits) to 16 escaped octals
    const rdata = TINYDNS.packHex(this.expand(this.get('address'), ''))
    return this.getTinydnsGeneric(rdata)
  }
}
