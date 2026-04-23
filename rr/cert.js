import RR from '../rr.js'

import * as TINYDNS from '../lib/tinydns.js'
import * as BINARY from '../lib/binary.js'

export default class CERT extends RR {
  static typeName = 'CERT'
  static rdataFields = ['cert type', 'key tag', 'algorithm', 'certificate']
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setCertType(val) {
    // The type field is the certificate type
    // the type field as an unsigned decimal integer or as a mnemonic symbol
    if (val === undefined || val === null || val === '') {
      this.throwHelp('cert type is required')
    }
    // Accept both mnemonic and numeric, but validate mnemonic
    if (typeof val === 'string') {
      const types = {
        PKIX: 1,
        SPKI: 2,
        PGP: 3,
        IPKIX: 4,
        ISPKI: 5,
        IPGP: 6,
        ACPKIX: 7,
        IACPKIX: 8,
        URI: 253,
        OID: 254,
      }
      if (!Object.hasOwn(types, val)) {
        this.throwHelp(`CERT: unknown cert type mnemonic: ${val}`)
      }
    } else {
      this.is16bitInt('CERT', 'cert type', val)
    }
    this.set('cert type', val)
  }

  getCertTypeValue(val) {
    if (typeof val === 'number') return val
    const types = {
      PKIX: 1,
      SPKI: 2,
      PGP: 3,
      IPKIX: 4,
      ISPKI: 5,
      IPGP: 6,
      ACPKIX: 7,
      IACPKIX: 8,
      URI: 253,
      OID: 254,
    }
    if (Object.hasOwn(types, val)) return types[val]
    this.throwHelp(`CERT: unknown cert type mnemonic: ${val}`)
  }

  setKeyTag(val) {
    // The key tag field is the 16-bit value
    // The key tag field is represented as an unsigned decimal integer.

    this.is16bitInt('CERT', 'key tag', val)

    this.set('key tag', val)
  }

  setAlgorithm(val) {
    // The algorithm field has the same meaning as the algorithm field in DNSKEY
    // The algorithm field is represented as an unsigned decimal integer
    this.is8bitInt('CERT', 'algorithm', val)

    this.set('algorithm', val)
  }

  setCertificate(val) {
    // certificate/CRL portion is represented in base 64 [16] and may be
    // divided into any number of white-space-separated substrings
    if (val === undefined || val === null || val === '') {
      this.throwHelp('certificate is required and cannot be empty')
    }
    this.isBase64('CERT', 'certificate', val.replace(/[\s()]/g, ''))
    this.set('certificate', val)
  }

  getDescription() {
    return 'Certificate'
  }

  getRFCs() {
    return [2538, 4398]
  }

  getTypeId() {
    return 37
  }

  getCanonical() {
    return {
      owner: 'mail.example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'CERT',
      'cert type': 'PGP',
      'key tag': 0,
      algorithm: 0,
      certificate: 'AQIDBA==',
    }
  }

  /******  IMPORTERS   *******/

  fromTinydns({ tinyline }) {
    const [owner, n, rdata, ttl, ts, loc] = tinyline.slice(1).split(':')
    if (n != 37) this.throwHelp('CERT fromTinydns, invalid n')

    const bytes = Uint8Array.from(TINYDNS.octalToChar(rdata), (c) => c.charCodeAt(0))
    const typeNum = (bytes[0] << 8) | bytes[1]
    let certType = typeNum

    const types = {
      1: 'PKIX',
      2: 'SPKI',
      3: 'PGP',
      4: 'IPKIX',
      5: 'ISPKI',
      6: 'IPGP',
      7: 'ACPKIX',
      8: 'IACPKIX',
      253: 'URI',
      254: 'OID',
    }
    if (types[typeNum]) certType = types[typeNum]

    return new CERT({
      owner: this.fullyQualify(owner),
      ttl: parseInt(ttl, 10),
      type: 'CERT',
      'cert type': certType,
      'key tag': (bytes[2] << 8) | bytes[3],
      algorithm: bytes[4],
      certificate: BINARY.bytesToBase64(bytes.subarray(5)),
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  fromBind({ bindline }) {
    // test.example.com  3600  IN  CERT  certtype, keytag, algo, cert
    const [owner, ttl, c, type, certtype, keytag, algo, certificate] = bindline.split(/\s+/)
    return new CERT({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type,
      'cert type': /^[0-9]+$/.test(certtype) ? parseInt(certtype, 10) : certtype,
      'key tag': parseInt(keytag, 10),
      algorithm: parseInt(algo, 10),
      certificate,
    })
  }

  fromWire({ owner, cls, ttl, rdata }) {
    const dv = new DataView(rdata.buffer, rdata.byteOffset)
    const typeNum = dv.getUint16(0)
    const types = {
      1: 'PKIX',
      2: 'SPKI',
      3: 'PGP',
      4: 'IPKIX',
      5: 'ISPKI',
      6: 'IPGP',
      7: 'ACPKIX',
      8: 'IACPKIX',
      253: 'URI',
      254: 'OID',
    }
    const certType = types[typeNum] ?? typeNum
    return new CERT({
      owner,
      ttl,
      class: cls,
      type: 'CERT',
      'cert type': certType,
      'key tag': dv.getUint16(2),
      algorithm: rdata[4],
      certificate: BINARY.bytesToBase64(rdata.subarray(5)),
    })
  }

  /******  EXPORTERS   *******/

  toTinydns() {
    return this.getTinydnsGeneric(
      TINYDNS.UInt16toOctal(this.getCertTypeValue(this.get('cert type'))) +
        TINYDNS.UInt16toOctal(this.get('key tag')) +
        TINYDNS.UInt8toOctal(this.get('algorithm')) +
        TINYDNS.base64toOctal(this.get('certificate').replace(/[\s()]/g, '')),
    )
  }

  getWireRdata() {
    const certBytes = BINARY.base64ToBytes(this.get('certificate').replace(/[\s()]/g, ''))
    const bytes = new Uint8Array(5 + certBytes.length)
    const dv = new DataView(bytes.buffer, bytes.byteOffset)
    dv.setUint16(0, this.getCertTypeValue(this.get('cert type')))
    dv.setUint16(2, this.get('key tag'))
    bytes[4] = this.get('algorithm')
    bytes.set(certBytes, 5)
    return bytes
  }
}
