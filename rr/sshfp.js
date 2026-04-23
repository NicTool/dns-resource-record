import RR from '../rr.js'
import * as TINYDNS from '../lib/tinydns.js'
import * as BINARY from '../lib/binary.js'

export default class SSHFP extends RR {
  static typeName = 'SSHFP'
  static typeId = 44
  static RFCs = [4255, 7479, 8709]
  static rdataFields = [
    ['algorithm', 'u8'],
    ['fptype', 'u8'],
    ['fingerprint', 'hex'],
  ]
  static tags = ['security']

  constructor(opts) {
    super(opts)
  }

  getAlgorithmOptions() {
    return new Map([
      [0, 'reserved'],
      [1, 'RSA'],
      [2, 'DSA'],
      [3, 'ECDSA'],
      [4, 'Ed25519'],
      [6, 'Ed448'],
    ])
  }

  getFptypeOptions() {
    return new Map([
      [0, 'reserved'],
      [1, 'SHA-1'],
      [2, 'SHA-256'],
    ])
  }

  getDescription() {
    return 'Secure Shell Key Fingerprints'
  }

  getCanonical() {
    return {
      owner: 'mail.example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'SSHFP',
      algorithm: 2,
      fptype: 1,
      fingerprint: '123456789abcdef6789abcdf6789abdf6789abcd',
    }
  }

  /******  IMPORTERS   *******/
  fromTinydns({ tinyline }) {
    // SSHFP via generic, :fqdn:n:rdata:ttl:timestamp:lo
    const [fqdn, n, rdata, ttl, ts, loc] = tinyline.slice(1).split(':')
    if (n != 44) this.throwHelp('SSHFP fromTinydns, invalid n')

    return new SSHFP({
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'SSHFP',
      algorithm: TINYDNS.octalToUInt8(rdata.slice(0, 4)),
      fptype: TINYDNS.octalToUInt8(rdata.slice(4, 8)),
      fingerprint: TINYDNS.octalToHex(rdata.slice(8)),
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  /******  EXPORTERS   *******/

  toTinydns() {
    return this.getTinydnsGeneric(
      TINYDNS.UInt8toOctal(this.get('algorithm')) +
        TINYDNS.UInt8toOctal(this.get('fptype')) +
        TINYDNS.packHex(this.get('fingerprint')),
    )
  }

  getWireRdata() {
    const bytes = new Uint8Array(2 + BINARY.hexToBytes(this.get('fingerprint')).length)
    bytes[0] = this.get('algorithm')
    bytes[1] = this.get('fptype')
    bytes.set(BINARY.hexToBytes(this.get('fingerprint')), 2)
    return bytes
  }
}
