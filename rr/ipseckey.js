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

  constructor(opts) {
    super(opts)
  }

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

  getAlgorithmOptions() {
    return new Map([
      [1, 'DSA'],
      [2, 'RSA'],
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
    }

    this.set('gateway', val)
  }

  setPublickey(val) {
    if (val) this.isBase64('IPSECKEY', 'publickey', val)
    this.set('publickey', val)
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
      case 2: {
        const dv = new DataView(rdata.buffer, rdata.byteOffset + 3)
        const groups = []
        for (let i = 0; i < 16; i += 2) groups.push(dv.getUint16(i).toString(16).padStart(4, '0'))
        gateway = groups.join(':')
        keyStart = 19
        break
      }
      case 3: {
        const { fqdn, end } = this.wireUnpackDomain(rdata, 3)
        gateway = fqdn
        keyStart = end
        break
      }
    }
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
        gwBytes = new Uint8Array(4)
        this.get('gateway')
          .split('.')
          .forEach((part, i) => {
            gwBytes[i] = parseInt(part, 10)
          })
        break
      case 2:
        gwBytes = new Uint8Array(16)
        {
          const parts = this.get('gateway').split(':')
          let pos = 0
          for (const part of parts) {
            if (part === '') continue
            const val = parseInt(part, 16)
            gwBytes[pos++] = (val >>> 8) & 0xff
            gwBytes[pos++] = val & 0xff
          }
        }
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
