import RR from '../rr.js'

import * as TINYDNS from '../lib/tinydns.js'

export default class IPSECKEY extends RR {
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
        break
    }

    this.set('gateway', val)
  }

  setPublickey(val) {
    // if (val) this.throwHelp(`IPSECKEY: publickey is optional`)

    this.set('publickey', val)
  }

  getDescription() {
    return 'IPsec Keying'
  }

  getRdataFields(arg) {
    return ['precedence', 'gateway type', 'algorithm', 'gateway', 'publickey']
  }

  getRFCs() {
    return [4025]
  }

  getTypeId() {
    return 45
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
  fromBind(opts) {
    // FQDN TTL CLASS IPSECKEY Precedence GatewayType Algorithm Gateway PublicKey
    const [owner, ttl, c, type, prec, gwt, algo, gateway, publickey] = opts.bindline.split(/\s+/)
    return new IPSECKEY({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type,
      precedence: parseInt(prec, 10),
      'gateway type': parseInt(gwt, 10),
      algorithm: parseInt(algo, 10),
      gateway,
      publickey,
    })
  }

  fromTinydns(opts) {
    const [fqdn, n, rdata, ttl, ts, loc] = opts.tinyline.substring(1).split(':')
    if (n != 45) this.throwHelp('IPSECKEY fromTinydns, invalid n')

    const precedence = TINYDNS.octalToUInt8(rdata.substring(0, 4))
    const gwType = TINYDNS.octalToUInt8(rdata.substring(4, 8))
    const algorithm = TINYDNS.octalToUInt8(rdata.substring(8, 12))

    let len, gateway, octalKey

    switch (gwType) {
      case 0: // no gateway
        gateway = rdata.substring(12, 13) // should always be: '.'
        octalKey = rdata.substring(13)
        break
      case 1: // 4-byte IPv4 address
        gateway = TINYDNS.octalToIPv4(rdata.substring(12, 28))
        octalKey = rdata.substring(28)
        break
      case 2: // 16-byte IPv6
        gateway = TINYDNS.octalToHex(rdata.substring(12, 76))
        octalKey = rdata.substring(76)
        break
      case 3: // wire encoded domain name
        ;[gateway, len] = TINYDNS.unpackDomainName(rdata.substring(12))
        octalKey = rdata.substring(12 + len)
        break
    }

    return new IPSECKEY({
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'IPSECKEY',
      precedence,
      'gateway type': gwType,
      algorithm,
      gateway,
      publickey: TINYDNS.octalToBase64(octalKey),
      timestamp: ts,
      location: loc !== '' && loc !== '\n' ? loc : '',
    })
  }

  /******  EXPORTERS   *******/

  toTinydns() {
    const rdataRe = new RegExp(/[\r\n\t:\\/]/, 'g')

    let rdata = ''
    rdata += TINYDNS.UInt8toOctal(this.get('precedence'))
    rdata += TINYDNS.UInt8toOctal(this.get('gateway type'))
    rdata += TINYDNS.UInt8toOctal(this.get('algorithm'))

    switch (this.get('gateway type')) {
      case 0:
        rdata += TINYDNS.escapeOctal(rdataRe, '.')
        break
      case 1:
        rdata += TINYDNS.ipv4toOctal(this.get('gateway'))
        break
      case 2:
        rdata += TINYDNS.ipv6toOctal(this.get('gateway'))
        break
      case 3:
        rdata += TINYDNS.packDomainName(this.get('gateway'))
        break
    }

    rdata += TINYDNS.base64toOctal(this.get('publickey'))

    return this.getTinydnsGeneric(rdata)
  }
}
