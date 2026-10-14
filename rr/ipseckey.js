import RR from '../rr.js'

import * as BINARY from '../lib/binary.js'
import * as WIRE from '../lib/wire.js'

export default class IPSECKEY extends RR {
  static typeName = 'IPSECKEY'
  static typeId = 45
  static RFCs = [4025]
  static rdataFields = [
    ['precedence', 'u8'],
    ['gateway type', 'u8'],
    ['algorithm', 'u8'],
    'gateway',
    ['publickey', 'base64'],
  ]
  static tags = ['security']

  /****** Resource record specific setters   *******/
  setPrecedence(val) {
    // an 8-bit precedence for this record.
    this.is8bitInt('IPSECKEY', 'precedence', val)

    this.set('precedence', val)
  }

  setGatewayType(val) {
    if (!this.getGatewayTypeOptions().has(val)) this.throwHelp(`IPSECKEY: Gateway Type is invalid`)

    this.set('gateway type', val)
  }

  getGatewayTypeOptions() {
    return new Map([
      [0, 'none'],
      [1, '4-byte IPv4'],
      [2, '16-byte IPv6'],
      [3, 'wire encoded domain name'],
    ])
  }

  setAlgorithm(val) {
    if (!this.getAlgorithmOptions().has(val)) this.throwHelp(`IPSECKEY: Algorithm invalid`)

    this.set('algorithm', val)
  }

  // IANA IPSECKEY Resource Record Parameters, Algorithm Type Field
  getAlgorithmOptions() {
    return new Map([
      [0, 'No key is present'],
      [1, 'DSA'], // RFC 4025
      [2, 'RSA'], // RFC 4025
      [3, 'ECDSA'], // RFC 8005
      [4, 'EdDSA'], // RFC 9373
    ])
  }

  setGateway(val) {
    const type = this.get('gateway type')
    const gwErr = new Error(`IPSECKEY: gateway invalid (${val}) for type ${type}`)
    switch (type) {
      case 0:
        if (val !== '.') throw gwErr
        break
      case 1:
        if (!this.isIPv4(val)) throw gwErr
        break
      case 2:
        if (!this.isIPv6(val)) throw gwErr
        val = this.expandIPv6(val.toLowerCase())
        break
      case 3:
        this.isFqdnValue('IPSECKEY', 'gateway', val)
        val = this.lowercaseName(val)
        break
    }

    this.set('gateway', val)
  }

  // RFC 4025 §2.4: algorithm 0 carries no key
  setPublickey(val) {
    if (val || this.get('algorithm') !== 0) this.isBase64('IPSECKEY', 'publickey', val)
    this.set('publickey', val ?? '')
  }

  getDescription() {
    return 'IPsec Keying'
  }

  getCanonical() {
    return {
      owner: '38.2.0.192.in-addr.arpa.',
      ttl: 7200,
      class: 'IN',
      type: 'IPSECKEY',
      precedence: 10,
      'gateway type': 1,
      algorithm: 2,
      gateway: '192.0.2.38',
      publickey: 'AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==',
    }
  }

  /******  IMPORTERS   *******/

  fromWire({ owner, cls, ttl, rdata }) {
    const precedence = rdata[0]
    const gwType = rdata[1]
    const algorithm = rdata[2]
    let gateway, keyStart
    switch (gwType) {
      case 0:
        gateway = '.'
        keyStart = 3
        break
      case 1:
        gateway = [...rdata.subarray(3, 7)].join('.')
        keyStart = 7
        break
      case 2:
        gateway = WIRE.ipv6ToPresentation(rdata.subarray(3, 19))
        keyStart = 19
        break
      case 3: {
        const { fqdn, end } = this.wireUnpackDomain(rdata, 3)
        gateway = fqdn
        keyStart = end
        break
      }
    }
    if (rdata.length < 3 || keyStart > rdata.length) throw new Error('IPSECKEY: rdata is truncated')
    const publickey = BINARY.bytesToBase64(rdata.subarray(keyStart))
    return new IPSECKEY({
      owner,
      ttl,
      class: cls,
      type: 'IPSECKEY',
      precedence,
      'gateway type': gwType,
      algorithm,
      gateway,
      publickey,
    })
  }

  /******  EXPORTERS   *******/

  getWireRdata() {
    const pubkeyBytes = BINARY.base64ToBytes(this.get('publickey'))
    const gwType = this.get('gateway type')

    let gwBytes
    switch (gwType) {
      case 0:
        gwBytes = new Uint8Array(0)
        break
      case 1:
        gwBytes = WIRE.ipv4Bytes(this.get('gateway'))
        break
      case 2:
        gwBytes = WIRE.ipv6Bytes(this.get('gateway'))
        break
      case 3:
        gwBytes = WIRE.wirePackDomain(this.get('gateway'))
        break
    }

    const bytes = new Uint8Array(3 + gwBytes.length + pubkeyBytes.length)
    bytes[0] = this.get('precedence')
    bytes[1] = gwType
    bytes[2] = this.get('algorithm')
    bytes.set(gwBytes, 3)
    bytes.set(pubkeyBytes, 3 + gwBytes.length)

    return bytes
  }
}
