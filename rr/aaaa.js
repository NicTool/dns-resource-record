import RR from '../rr.js'
import * as TINYDNS from '../lib/tinydns.js'

export default class AAAA extends RR {
  static typeName = 'AAAA'
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setAddress(val) {
    if (!val) this.throwHelp('AAAA: address is required')
    if (!this.isIPv6(val)) this.throwHelp(`AAAA: address must be IPv6 (${val})`)

    this.set('address', this.expand(val.toLowerCase())) // lower case: RFC 5952
  }

  getCompressed(val) {
    return this.compressIPv6(val ?? this.get('address'))
  }

  getDescription() {
    return 'Address IPv6'
  }

  getTags() {
    return ['common']
  }

  getRdataFields(arg) {
    return ['address']
  }

  getRFCs() {
    return [3596, 5952]
  }

  getTypeId() {
    return 28
  }

  getCanonical() {
    return {
      owner: 'host.example.com.',
      address: '2001:0db8:0020:000a:0000:0000:0000:0004',
      class: 'IN',
      ttl: 3600,
      type: 'AAAA',
    }
  }

  /******  IMPORTERS   *******/
  fromTinydns({ tinyline }) {
    const str = tinyline
    let fqdn, ip, n, rdata, ttl, ts, loc

    switch (str[0]) {
      case ':':
        // GENERIC  =>  :fqdn:28:rdata:ttl:timestamp:lo
        ;[fqdn, n, rdata, ttl, ts, loc] = str.slice(1).split(':')
        if (n != 28) this.throwHelp('AAAA fromTinydns, invalid n')
        ip = TINYDNS.octalToHex(rdata)
          .match(/([0-9a-fA-F]{4})/g)
          .join(':')
        break
      case '3':
      case '6':
        // AAAA     =>  3fqdn:ip:x:ttl:timestamp:lo
        // AAAA,PTR =>  6fqdn:ip:x:ttl:timestamp:lo
        ;[fqdn, rdata, ttl, ts, loc] = str.slice(1).split(':')
        ip = rdata.match(/(.{4})/g).join(':')
        break
    }

    return new AAAA({
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'AAAA',
      address: ip,
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  fromBind({ bindline }) {
    // test.example.com  3600  IN  AAAA  ...
    const [owner, ttl, c, type, ip] = bindline.split(/\s+/)
    return new AAAA({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type,
      address: this.expand(ip),
    })
  }

  expand(val, delimiter) {
    if (delimiter === undefined) delimiter = ':'

    const colons = val.match(/:/g)
    if (colons?.length < 7) {
      // console.log(`AAAA: restoring compressed colons`)
      val = val.replace(/::/, ':'.repeat(9 - colons.length))
    }

    // restore compressed leading zeros
    return val
      .split(':')
      .map((s) => s.padStart(4, 0))
      .join(delimiter)
      .toLowerCase()
  }

  /******  EXPORTERS   *******/
  getWireRdata() {
    const hex = this.expand(this.get('address'), '')
    const arr = new Uint8Array(hex.length / 2)
    for (let i = 0; i < arr.length; i++) arr[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
    return arr
  }

  toBind(zone_opts) {
    return `${this.getPrefix(zone_opts)}\t${this.getCompressed()}\n`
  }

  toTinydns() {
    // from AAAA notation (8 groups of 4 hex digits) to 16 escaped octals
    const rdata = TINYDNS.packHex(this.expand(this.get('address'), ''))
    return this.getTinydnsGeneric(rdata)
  }
}
