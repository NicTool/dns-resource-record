import RR from '../rr.js'

import * as BINARY from '../lib/binary.js'
import * as WIRE from '../lib/wire.js'

export default class HIP extends RR {
  static typeName = 'HIP'
  static typeId = 55
  static RFCs = [8005]
  static rdataFields = [['pk algorithm', 'u8'], 'hit', 'public key', ['rendezvous servers', 'list']]

  /****** Resource record specific setters   *******/
  // RFC 8005 §5: the HIT length is one octet, the public key length two.
  setHit(val) {
    if (!val) this.throwHelp('HIP: hit is required')
    this.isHexDigest('hit', val)
    if (val.length > 2 * 255) this.throwHelp('HIP: hit must be <=255 bytes')
    this.set('hit', val.toUpperCase())
  }

  setPublicKey(val) {
    if (!val) this.throwHelp('HIP: public key is required')
    this.isBase64('HIP', 'public key', val)
    if (BINARY.base64ToBytes(val).length > 65535) this.throwHelp('HIP: public key must be <=65535 bytes')
    this.set('public key', val)
  }

  setRendezvousServers(val) {
    if (val != null) this.isString('HIP', 'rendezvous servers', val)
    const names = (val ?? '').split(/\s+/).filter(Boolean)
    for (const name of names) {
      this.isFullyQualified('HIP', 'rendezvous servers', name)
      this.isValidName('HIP', 'rendezvous servers', name)
    }
    this.set('rendezvous servers', names.map((n) => this.lowercaseName(n)).join(' '))
  }

  getDescription() {
    return 'Host Identity Protocol'
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'HIP',
      'pk algorithm': 2,
      hit: '200100107B1A74DF365639CC39F1D578',
      'public key':
        'AwEAAbdxyhNuSutc5EMzxTs9LBPCIkOFH8cIvM4p9+LrV4e19WzK00+CI6zBCQTdtWsuxKbWIy87UOoJTwIXAqcOTiW7iHnQt5hwVAAAAA==',
      'rendezvous servers': '',
    }
  }

  /******  IMPORTERS   *******/

  fromWire({ owner, cls, ttl, rdata }) {
    const hitLen = rdata[0]
    const pkLen = (rdata[2] << 8) | rdata[3]
    const keyEnd = 4 + hitLen + pkLen
    if (rdata.length < 4 || keyEnd > rdata.length)
      throw new Error('HIP: HIT and public key lengths overrun the rdata')
    const rvsNames = []
    for (let pos = keyEnd; pos < rdata.length;) {
      const { fqdn, end } = this.wireUnpackDomain(rdata, pos)
      rvsNames.push(fqdn)
      pos = end
    }
    return new HIP({
      owner,
      ttl,
      class: cls,
      type: 'HIP',
      'pk algorithm': rdata[1],
      hit: BINARY.bytesToHex(rdata.subarray(4, 4 + hitLen)),
      'public key': BINARY.bytesToBase64(rdata.subarray(4 + hitLen, keyEnd)),
      'rendezvous servers': rvsNames.join(' '),
    })
  }

  /******  EXPORTERS   *******/

  getWireRdata() {
    const hitHex = this.get('hit')
    const hitBytes = BINARY.hexToBytes(hitHex)
    const pkBytes = BINARY.base64ToBytes(this.get('public key'))
    const rs = this.get('rendezvous servers')

    const rsNames = rs ? rs.split(/\s+/) : []
    const rsDomains = rsNames.map((name) => WIRE.wirePackDomain(name))
    const rsTotalLen = rsDomains.reduce((sum, b) => sum + b.length, 0)

    const totalLen = 1 + 1 + 2 + hitBytes.length + pkBytes.length + rsTotalLen
    const bytes = new Uint8Array(totalLen)
    const dv = new DataView(bytes.buffer, bytes.byteOffset)

    let pos = 0
    bytes[pos++] = hitBytes.length
    bytes[pos++] = this.get('pk algorithm')
    dv.setUint16(pos, pkBytes.length)
    pos += 2
    bytes.set(hitBytes, pos)
    pos += hitBytes.length
    bytes.set(pkBytes, pos)
    pos += pkBytes.length
    for (const rdomain of rsDomains) {
      bytes.set(rdomain, pos)
      pos += rdomain.length
    }

    return bytes
  }
}
