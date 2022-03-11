
const RR      = require('./index').RR
const TINYDNS = require('../lib/tinydns')

class SSHFP extends RR {
  constructor (opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setAlgorithm (val) {
    // 0: reserved; 1: RSA 2: DSA 3: ECDSA 4: Ed25519 6:Ed448
    if (!this.is8bitInt('SSHFP', 'algorithm', val)) return

    this.set('algorithm', val)
  }

  setFptype (val) {
    // 0: reserved, 1: SHA-1, 2: SHA-256
    if (!this.is8bitInt('SSHFP', 'type', val)) return

    this.set('fptype', val)
  }

  setFingerprint (val) {
    this.set('fingerprint', val)
  }

  getDescription () {
    return 'Secure Shell Key Fingerprints'
  }

  getRdataFields () {
    return [ 'algorithm', 'fptype', 'fingerprint' ]
  }

  getRFCs () {
    return [ 4255 ]
  }

  getTypeId () {
    return 44
  }

  /******  IMPORTERS   *******/
  fromTinydns (str) {
    // SSHFP via generic, :fqdn:n:rdata:ttl:timestamp:lo
    const [ fqdn, n, rdata, ttl, ts, loc ] = str.substring(1).split(':')
    if (n != 44) throw new Error('SSHFP fromTinydns, invalid n')

    const algo   = TINYDNS.octalToUInt16(rdata.substring(0, 8))
    const fptype = TINYDNS.octalToUInt16(rdata.substring(8, 16))

    const fingerprint = TINYDNS.octalToHex(rdata.substring(16))

    return new this.constructor({
      type       : 'SSHFP',
      name       : fqdn,
      algorithm  : algo,
      fptype     : fptype,
      fingerprint: fingerprint,
      ttl        : parseInt(ttl, 10),
      timestamp  : ts,
      location   : loc !== '' && loc !== '\n' ? loc : '',
    })
  }

  fromBind (str) {
    // test.example.com  3600  IN  SSHFP  algo fptype fp
    const [ fqdn, ttl, c, type, algo, fptype, fp ] = str.split(/\s+/)
    return new this.constructor({
      class      : c,
      type       : type,
      name       : fqdn,
      algorithm  : parseInt(algo, 10),
      fptype     : parseInt(fptype, 10),
      fingerprint: fp,
      ttl        : parseInt(ttl, 10),
    })
  }

  /******  EXPORTERS   *******/

  toTinydns () {
    let rdata = ''

    for (const e of [ 'algorithm', 'fptype' ]) {
      rdata += TINYDNS.UInt16toOctal(this.get(e))
    }

    rdata += TINYDNS.packHex(this.get('fingerprint'))
    return `:${this.get('name')}:44:${rdata}:${this.getEmpty('ttl')}:${this.getEmpty('timestamp')}:${this.getEmpty('location')}\n`
  }
}

module.exports = SSHFP
