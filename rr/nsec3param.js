import RR from '../rr.js'
import * as TINYDNS from '../lib/tinydns.js'
import * as BINARY from '../lib/binary.js'

export default class NSEC3PARAM extends RR {
  static typeName = 'NSEC3PARAM'
  static typeId = 51
  static RFCs = [5155]
  static rdataFields = ['hash algorithm', 'flags', 'iterations', 'salt']
  static tags = ['dnssec']

  constructor(opts) {
    super(opts)
    if (opts === null) return
  }

  /****** Resource record specific setters   *******/
  setHashAlgorithm(val) {
    // Hash Algorithm is a single octet.
    // The Hash Algorithm field is represented as an unsigned decimal integer.
    if (val === undefined || val === null) this.throwHelp(`NSEC3PARAM: 'hash algorithm' is required`)

    this.is8bitInt('NSEC3PARAM', 'hash algorithm', val)

    this.set('hash algorithm', val)
  }

  setFlags(val) {
    // The Flags field is represented as an unsigned decimal integer.
    if (val === undefined || val === null) this.throwHelp(`NSEC3PARAM: 'flags' is required`)

    this.is8bitInt('NSEC3PARAM', 'flags', val)

    this.set('flags', val)
  }

  setIterations(val) {
    // The Iterations field is represented as an unsigned decimal integer. 0-65535
    if (val === undefined || val === null) this.throwHelp(`NSEC3PARAM: 'iterations' is required`)

    this.is16bitInt('NSEC3PARAM', 'iterations', val)

    this.set('iterations', val)
  }

  setSalt(val) {
    // The Salt field is represented as a sequence of case-insensitive
    // hexadecimal digits.  Whitespace is not allowed within the
    // sequence.  The Salt field is represented as "-" (without the
    // quotes) when the Salt Length field has a value of 0
    if (val === '-') {
      this.set('salt', val)
      return
    }

    if (val !== undefined && val !== null && !/^[0-9A-Fa-f]*$/.test(val)) {
      this.throwHelp(`NSEC3PARAM: 'salt' must be hex or '-'`)
    }

    this.set('salt', val)
  }

  getDescription() {
    return 'Next Secure Parameters'
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'NSEC3PARAM',
      'hash algorithm': 1,
      flags: 1,
      iterations: 12,
      salt: 'aabbccdd',
    }
  }

  /******  IMPORTERS   *******/

  fromTinydns({ tinyline }) {
    // RDATA format: Hash Algorithm (3 octal chars) + Flags (3 octal chars) + Iterations (6 octal chars) + Salt (escaped hex string)
    const { owner, typeId, rdata, ttl, timestamp, location } = this.parseTinydnsLine(tinyline)
    if (typeId != this.getTypeId()) this.throwHelp('NSEC3PARAM fromTinydns, invalid n')
    if (rdata.length < 4) {
      this.throwHelp(`NSEC3PARAM: RDATA too short: ${rdata}`)
    }

    // rd may contain actual binary characters (from JS string '\\001' -> char 0x01),
    // so convert via octalToChar and read bytes from a Uint8Array for robust parsing.
    const bytes = TINYDNS.octalRdataToBytes(rdata)

    return new NSEC3PARAM({
      owner,
      ttl,
      type: 'NSEC3PARAM',
      'hash algorithm': bytes[0],
      flags: bytes[1],
      iterations: (bytes[2] << 8) | bytes[3],
      salt: bytes[4] === 0 ? '-' : BINARY.bytesToHex(bytes.subarray(5, 5 + bytes[4])),
      timestamp,
      location,
    })
  }

  fromWire({ owner, cls, ttl, rdata }) {
    const dv = new DataView(rdata.buffer, rdata.byteOffset)
    const saltLen = rdata[4]
    const salt = saltLen === 0 ? '-' : BINARY.bytesToHex(rdata.subarray(5, 5 + saltLen))
    return new NSEC3PARAM({
      owner,
      ttl,
      class: cls,
      type: 'NSEC3PARAM',
      'hash algorithm': rdata[0],
      flags: rdata[1],
      iterations: dv.getUint16(2),
      salt,
    })
  }

  /******  EXPORTERS   *******/

  toTinydns() {
    const salt = this.get('salt')
    const saltOctal =
      salt === '-' ? TINYDNS.UInt8toOctal(0) : TINYDNS.UInt8toOctal(salt.length / 2) + TINYDNS.packHex(salt)

    return this.getTinydnsGeneric(
      TINYDNS.UInt8toOctal(this.get('hash algorithm')) +
        TINYDNS.UInt8toOctal(this.get('flags')) +
        TINYDNS.UInt16toOctal(this.get('iterations')) +
        saltOctal,
    )
  }

  getWireRdata() {
    const salt = this.get('salt')
    const saltBytes = salt === '-' ? new Uint8Array(0) : BINARY.hexToBytes(salt)
    const bytes = new Uint8Array(4 + 1 + saltBytes.length)
    const dv = new DataView(bytes.buffer, bytes.byteOffset)

    bytes[0] = this.get('hash algorithm')
    bytes[1] = this.get('flags')
    dv.setUint16(2, this.get('iterations'))
    bytes[4] = saltBytes.length
    bytes.set(saltBytes, 5)

    return bytes
  }
}
