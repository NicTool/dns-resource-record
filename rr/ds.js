import RR from '../rr.js'

import * as TINYDNS from '../lib/tinydns.js'
import * as BINARY from '../lib/binary.js'

export default class DS extends RR {
  static typeName = 'DS'
  static typeId = 43
  static RFCs = [4034, 4509, 9619]
  static rdataFields = [['key tag', 'u16'], 'algorithm', 'digest type', ['digest', 'str']]
  static tags = ['dnssec']

  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setAlgorithm(val) {
    if (!this.getAlgorithmOptions().has(val)) this.throwHelp(`DS: algorithm invalid`)

    this.set('algorithm', val)
  }

  getAlgorithmOptions() {
    return new Map([
      [1, 'RSA/MD5'],
      [2, 'DH'],
      [3, 'DSA/SHA-1'],
      [4, 'EC'],
      [5, 'RSA/SHA-1'],
      [253, ''],
      [254, ''],
    ])
  }

  setDigestType(val) {
    if (![1, 2].includes(val)) this.throwHelp(`DS: digest type invalid`)

    this.set('digest type', val)
  }

  getDescription() {
    return 'Delegation Signer'
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'DS',
      'key tag': 12345,
      algorithm: 5,
      'digest type': 1,
      digest: 'ABCDEF123...',
    }
  }

  /******  IMPORTERS   *******/

  fromTinydns(opts) {
    const { tinyline } = opts
    const { owner, typeId, rdata, ttl, timestamp, location } = this.parseTinydnsLine(tinyline)
    if (typeId != this.getTypeId()) this.throwHelp('DS fromTinydns, invalid n')

    const binRdata = TINYDNS.octalRdataToBytes(rdata)

    return new DS({
      owner,
      ttl,
      type: 'DS',
      'key tag': (binRdata[0] << 8) | binRdata[1],
      algorithm: binRdata[2],
      'digest type': binRdata[3],
      digest: BINARY.bytesToHex(binRdata.subarray(4)).toUpperCase(),
      timestamp,
      location,
    })
  }

  fromWire({ owner, cls, ttl, rdata }) {
    const dv = new DataView(rdata.buffer, rdata.byteOffset)
    return new DS({
      owner,
      ttl,
      class: cls,
      type: 'DS',
      'key tag': dv.getUint16(0),
      algorithm: rdata[2],
      'digest type': rdata[3],
      digest: BINARY.bytesToHex(rdata.subarray(4)).toUpperCase(),
    })
  }

  /******  EXPORTERS   *******/

  toTinydns() {
    return this.getTinydnsGeneric(
      TINYDNS.UInt16toOctal(this.get('key tag')) +
        TINYDNS.UInt8toOctal(this.get('algorithm')) +
        TINYDNS.UInt8toOctal(this.get('digest type')) +
        TINYDNS.packHex(this.get('digest').replace(/\s+/g, '')),
    )
  }

  getWireRdata() {
    const digestBytes = BINARY.hexToBytes(this.get('digest').replace(/\s+/g, ''))
    const bytes = new Uint8Array(4 + digestBytes.length)
    const dv = new DataView(bytes.buffer, bytes.byteOffset)
    dv.setUint16(0, this.get('key tag'))
    bytes[2] = this.get('algorithm')
    bytes[3] = this.get('digest type')
    bytes.set(digestBytes, 4)
    return bytes
  }
}
