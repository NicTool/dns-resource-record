import RR from '../rr.js'

import { typeIdToName, typeNameToId } from '../lib/binary.js'

export default class NXT extends RR {
  static typeName = 'NXT'
  static typeId = 30
  static RFCs = [2065]
  static rdataFields = [
    ['next domain', 'fqdn'],
    ['type bit map', 'list'],
  ]
  static tags = ['obsolete']

  /****** Resource record specific setters   *******/

  setTypeBitMap(val) {
    if (!val) this.throwHelp(`NXT: 'type bit map' is required`)
    try {
      this.set('type bit map', nxtBitmapToTypes(typesToNxtBitmap(val)))
    } catch (e) {
      this.throwHelp(e.message)
    }
  }

  getDescription() {
    return 'Next Secure'
  }

  getCanonical() {
    return {
      owner: 'big.example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'NXT',
      'next domain': 'host.example.com.',
      'type bit map': 'A MX NXT',
    }
  }

  /******  IMPORTERS   *******/

  fromWire({ owner, cls, ttl, rdata }) {
    const { fqdn: nextDomain, end } = this.wireUnpackDomain(rdata, 0)
    const typeBitMap = nxtBitmapToTypes(rdata.subarray(end))
    return new NXT({
      owner,
      ttl,
      class: cls,
      type: 'NXT',
      'next domain': nextDomain,
      'type bit map': typeBitMap,
    })
  }

  /******  EXPORTERS   *******/

  getWireRdata() {
    const nameBytes = this.wirePackDomain(this.get('next domain'))
    const bitmapBytes = typesToNxtBitmap(this.get('type bit map'))
    const result = new Uint8Array(nameBytes.length + bitmapBytes.length)
    result.set(nameBytes)
    result.set(bitmapBytes, nameBytes.length)
    return result
  }
}

function nxtBitmapToTypes(bitmap) {
  const types = []
  for (let id = 0; id < bitmap.length * 8; id++) {
    if (bitmap[id >> 3] & (0x80 >> (id & 7))) types.push(typeIdToName(id))
  }
  return types.join(' ')
}

// RFC 2535 §5.2: one bit per type 1-127, trailing zero octets omitted. Bit 0
// would announce an extended format that was never defined.
function typesToNxtBitmap(typeNames) {
  const bitmap = new Uint8Array(16)
  let length = 0
  for (const name of typeNames.trim().split(/\s+/)) {
    const id = typeNameToId(name)
    if (id < 1 || id > 127) throw new Error(`NXT: type ${name} is outside 1-127 (RFC 2535 §5.2)`)
    bitmap[id >> 3] |= 0x80 >> (id & 7)
    length = Math.max(length, (id >> 3) + 1)
  }
  return bitmap.subarray(0, length)
}
