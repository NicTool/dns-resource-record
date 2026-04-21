import RR from '../rr.js'

import * as TINYDNS from '../lib/tinydns.js'

export default class APL extends RR {
  static typeName = 'APL'
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setAplRdata(val) {
    if (!val) this.throwHelp('APL: apl rdata is required')
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
      'apl rdata': '1:192.0.2.1/24 !1:192.0.2.64/28 2:2001:db8::1/128',
    }
  }

  /******  IMPORTERS   *******/
  fromTinydns({ tinyline }) {
    // APL via generic, :fqdn:42:rdata:ttl:timestamp:lo
    const [fqdn, n, rdata, ttl, ts, loc] = tinyline.slice(1).split(':')
    if (n != 42) this.throwHelp('APL fromTinydns, invalid n')

    const bytes = Uint8Array.from(TINYDNS.octalToChar(rdata), (c) => c.charCodeAt(0))
    const items = []
    let pos = 0

    while (pos < bytes.length) {
      const afi = (bytes[pos] << 8) | bytes[pos + 1]
      pos += 2
      const prefix = bytes[pos]
      pos++
      const adfLenByte = bytes[pos]
      pos++
      const neg = (adfLenByte & 0x80) !== 0
      const addrLen = adfLenByte & 0x7f
      const addrBytes = bytes.subarray(pos, pos + addrLen)
      pos += addrLen

      let addr
      if (afi === 1) {
        const padded = new Uint8Array(4)
        padded.set(addrBytes)
        addr = [...padded].join('.')
      } else {
        const padded = new Uint8Array(16)
        padded.set(addrBytes)
        const paddedDv = new DataView(padded.buffer)
        const groups = []
        for (let i = 0; i < 16; i += 2) groups.push(paddedDv.getUint16(i).toString(16).padStart(4, '0'))
        addr = this.compressIPv6(groups.join(':'))
      }

      items.push(`${neg ? '!' : ''}${afi}:${addr}/${prefix}`)
    }

    return new APL({
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'APL',
      'apl rdata': items.join(' '),
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  fromBind({ bindline }) {
    // test.example.com  3600  IN  APL  {[!]afi:address/prefix}*
    const parts = bindline.split(/\s+/)
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
            addrBytes = new Uint8Array(addr.split('.').map((n) => parseInt(n, 10)))
          } else {
            const dblIdx = addr.indexOf('::')
            let groups
            if (dblIdx !== -1) {
              const left = addr
                .slice(0, dblIdx)
                .split(':')
                .filter((s) => s !== '')
              const right = addr
                .slice(dblIdx + 2)
                .split(':')
                .filter((s) => s !== '')
              groups = [...left, ...Array(8 - left.length - right.length).fill('0000'), ...right]
            } else {
              groups = addr.split(':')
            }
            const hexStr = groups.map((g) => g.padStart(4, '0')).join('')
            addrBytes = Uint8Array.from({ length: hexStr.length / 2 }, (_, i) =>
              parseInt(hexStr.slice(i * 2, i * 2 + 2), 16),
            )
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
