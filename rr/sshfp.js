import RR from '../rr.js'
import * as TINYDNS from '../lib/tinydns.js'

export default class SSHFP extends RR {
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setAlgorithm(val) {
    // 0: reserved  1: RSA  2: DSA  3: ECDSA  4: Ed25519  6: Ed448
    this.is8bitInt('SSHFP', 'algorithm', val)

    this.set('algorithm', val)
  }

  setFptype(val) {
    // 0: reserved, 1: SHA-1, 2: SHA-256
    this.is8bitInt('SSHFP', 'type', val)

    this.set('fptype', val)
  }

  setFingerprint(val) {
    this.set('fingerprint', val)
  }

  getDescription() {
    return 'Secure Shell Key Fingerprints'
  }

  getRdataFields() {
    return ['algorithm', 'fptype', 'fingerprint']
  }

  getRFCs() {
    return [4255, 7479, 8709]
  }

  getTypeId() {
    return 44
  }

  /******  IMPORTERS   *******/
  fromTinydns(opts) {
    // SSHFP via generic, :fqdn:n:rdata:ttl:timestamp:lo
    const [fqdn, n, rdata, ttl, ts, loc] = opts.tinyline.substring(1).split(':')
    if (n != 44) this.throwHelp('SSHFP fromTinydns, invalid n')

    return new SSHFP({
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'SSHFP',
      algorithm: TINYDNS.octalToUInt8(rdata.substring(0, 4)),
      fptype: TINYDNS.octalToUInt8(rdata.substring(4, 8)),
      fingerprint: TINYDNS.octalToHex(rdata.substring(8)),
      timestamp: ts,
      location: loc !== '' && loc !== '\n' ? loc : '',
    })
  }

  fromBind(opts) {
    // test.example.com  3600  IN  SSHFP  algo fptype fp
    const [owner, ttl, c, type, algo, fptype, fp] = opts.bindline.split(/\s+/)
    return new SSHFP({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type: type,
      algorithm: parseInt(algo, 10),
      fptype: parseInt(fptype, 10),
      fingerprint: fp,
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
}
