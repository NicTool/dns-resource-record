import RR from '../rr.js'
import { ipv4Bytes, ipv6Bytes, ipv6ToPresentation } from '../lib/wire.js'

export default class APL extends RR {
  static typeName = 'APL'
  static typeId = 42
  static RFCs = [3123]
  static rdataFields = [['apl rdata', 'list']]

  /****** Resource record specific setters   *******/
  setAplRdata(val) {
    if (!val) this.throwHelp('APL: apl rdata is required')
    const items = val.trim().split(/\s+/)
    try {
      items.forEach(itemToWire)
    } catch (e) {
      this.throwHelp(e.message)
    }
    this.set('apl rdata', items.join(' '))
  }

  getDescription() {
    return 'Address Prefix List'
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'APL',
      'apl rdata': '1:192.0.2.0/24 !1:192.0.2.64/28 2:2001:db8::1/128',
    }
  }

  /******  IMPORTERS   *******/

  // RFC 3123 §4: ADDRESSFAMILY(2) PREFIX(1) N|AFDLENGTH(1) AFDPART
  fromWire({ owner, cls, ttl, rdata }) {
    const items = []
    for (let pos = 0; pos < rdata.length;) {
      if (pos + 4 > rdata.length) throw new Error('APL: rdata ends inside an item header')
      const afi = (rdata[pos] << 8) | rdata[pos + 1]
      const size = AFD_BYTES[afi]
      if (!size) throw new Error(`APL: unknown address family ${afi}`)
      const afdLength = rdata[pos + 3] & 0x7f
      if (afdLength > size || pos + 4 + afdLength > rdata.length)
        throw new Error('APL: address part overruns the item')
      const address = new Uint8Array(size)
      address.set(rdata.subarray(pos + 4, pos + 4 + afdLength))
      const text = afi === 1 ? address.join('.') : this.compressIPv6(ipv6ToPresentation(address))
      items.push(`${rdata[pos + 3] & 0x80 ? '!' : ''}${afi}:${text}/${rdata[pos + 2]}`)
      pos += 4 + afdLength
    }
    return new APL({ owner, ttl, class: cls, type: 'APL', 'apl rdata': items.join(' ') })
  }

  /******  EXPORTERS   *******/

  getWireRdata() {
    return Uint8Array.from(
      this.get('apl rdata')
        .split(' ')
        .flatMap((item) => [...itemToWire(item)]),
    )
  }
}

const AFD_BYTES = { 1: 4, 2: 16 }

// RFC 3123 §5: [!]afi:address/prefix, sent without its trailing zero octets
function itemToWire(item) {
  const m = item.match(/^(!?)([12]):([^/]+)\/(\d{1,3})$/)
  if (!m) throw new Error(`APL: item must be [!]1:IPv4/prefix or [!]2:IPv6/prefix: ${item}`)
  const [, negation, afi, address, prefix] = m
  const bytes = afi === '1' ? ipv4Bytes(address) : ipv6Bytes(address)
  if (Number(prefix) > bytes.length * 8) throw new Error(`APL: prefix /${prefix} is too long: ${item}`)
  let afdLength = bytes.length
  while (afdLength && bytes[afdLength - 1] === 0) afdLength--
  return Uint8Array.from([
    0,
    Number(afi),
    Number(prefix),
    (negation ? 0x80 : 0) | afdLength,
    ...bytes.subarray(0, afdLength),
  ])
}
