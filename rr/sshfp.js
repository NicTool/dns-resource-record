
const RR      = require('./index').RR
const TINYDNS = require('../lib/tinydns')

class SSHFP extends RR {
  constructor (opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setAlgorithm (val) {
    // 0: reserved; 1: RSA 2: DSA 3: ECDSA 4: Ed25519 6:Ed448
    this.is8bitInt('SSHFP', 'algorithm', val)

    this.set('algorithm', val)
  }

  setFptype (val) {
    // 0: reserved, 1: SHA-1, 2: SHA-256
    this.is8bitInt('SSHFP', 'type', val)

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
      owner      : this.fullyQualify(fqdn),
      ttl        : parseInt(ttl, 10),
      type       : 'SSHFP',
      algorithm  : algo,
      fptype     : fptype,
      fingerprint: fingerprint,
      timestamp  : ts,
      location   : loc !== '' && loc !== '\n' ? loc : '',
    })
  }

  fromBind (str) {
    // test.example.com  3600  IN  SSHFP  algo fptype fp
    const [ owner, ttl, c, type, algo, fptype, fp ] = str.split(/\s+/)
    return new this.constructor({
      owner,
      ttl        : parseInt(ttl, 10),
      class      : c,
      type       : type,
      algorithm  : parseInt(algo, 10),
      fptype     : parseInt(fptype, 10),
      fingerprint: fp,
    })
  }

  /******  EXPORTERS   *******/

  toTinydns () {
    let rdata = ''

    for (const e of [ 'algorithm', 'fptype' ]) {
      rdata += TINYDNS.UInt16toOctal(this.get(e))
    }

    rdata += TINYDNS.packHex(this.get('fingerprint'))
    return this.getTinydnsGeneric(rdata)
  }
}

module.exports = SSHFP
