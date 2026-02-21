import RR from '../rr.js'

import * as TINYDNS from '../lib/tinydns.js'

export default class APL extends RR {
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setAplRdata(val) {
    if (!val) this.throwHelp('APL: apl rdata is required')
    // apl rdata is a list of address prefix list items, e.g.:
    // 1:192.0.2.0/24 !1:192.0.2.64/28 2:2001:db8::/32
    this.set('apl rdata', val)
  }

  getDescription() {
    return 'Address Prefix List'
  }

  getRdataFields(arg) {
    return ['apl rdata']
  }

  getRFCs() {
    return [3123]
  }

  getTypeId() {
    return 42
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'APL',
      'apl rdata': '1:192.0.2.0/24 !1:192.0.2.64/28 2:2001:db8::/32',
    }
  }

  /******  IMPORTERS   *******/
  fromBind(opts) {
    // test.example.com  3600  IN  APL  {[!]afi:address/prefix}*
    const parts = opts.bindline.split(/\s+/)
    const [owner, ttl, c, type] = parts
    return new APL({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type,
      'apl rdata': parts.slice(4).join(' ').trim(),
    })
  }

  /******  EXPORTERS   *******/
  toTinydns() {
    return this.getTinydnsGeneric(
      this.get('apl rdata')
        .split(/\s+/)
        .map((item) => {
          const neg = item.startsWith('!')
          const bare = neg ? item.slice(1) : item
          const colonIdx = bare.indexOf(':')
          const afi = parseInt(bare.slice(0, colonIdx), 10)
          const rest = bare.slice(colonIdx + 1)
          const slashIdx = rest.lastIndexOf('/')
          const addr = rest.slice(0, slashIdx)
          const prefix = parseInt(rest.slice(slashIdx + 1), 10)

          let addrBytes
          if (afi === 1) {
            addrBytes = Buffer.from(addr.split('.').map((n) => parseInt(n, 10)))
          } else {
            const dblIdx = addr.indexOf('::')
            let groups
            if (dblIdx !== -1) {
              const left = addr.slice(0, dblIdx).split(':').filter((s) => s !== '')
              const right = addr.slice(dblIdx + 2).split(':').filter((s) => s !== '')
              groups = [...left, ...Array(8 - left.length - right.length).fill('0000'), ...right]
            } else {
              groups = addr.split(':')
            }
            addrBytes = Buffer.from(groups.map((g) => g.padStart(4, '0')).join(''), 'hex')
          }

          let len = addrBytes.length
          while (len > 0 && addrBytes[len - 1] === 0) len--
          const afdPart = addrBytes.slice(0, len)

          let r = TINYDNS.UInt16toOctal(afi)
          r += TINYDNS.UInt8toOctal(prefix)
          r += TINYDNS.UInt8toOctal((neg ? 0x80 : 0) | afdPart.length)
          for (const b of afdPart) r += TINYDNS.UInt8toOctal(b)
          return r
        })
        .join(''),
    )
  }
}
