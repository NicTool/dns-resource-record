
const RR = require('./index').RR

class SSHFP extends RR {
  constructor (opts) {
    super(opts)
    this.set('id', 44)

    this.setAlgorithm(opts?.algorithm)
    this.setFpType(opts?.fptype)
    this.setFingerprint(opts?.fingerprint)
  }

  /****** Resource record specific setters   *******/
  setAlgorithm (val) {
    // 0: reserved; 1: RSA 2: DSA 3: ECDSA 4: Ed25519 6:Ed448
    if (!this.is8bitInt('SSHFP', 'algorithm', val)) return

    this.set('algorithm', val)
  }

  setFpType (val) {
    // 0: reserved, 1: SHA-1, 2: SHA-256
    if (!this.is8bitInt('SSHFP', 'type', val)) return

    this.set('fptype', val)
  }

  setFingerprint (val) {
    this.set('fingerprint', val)
  }

  getRFCs () {
    return [ 4255 ]
  }

  /******  IMPORTERS   *******/
  fromTinydns () {
    //
  }

  fromBind () {
    //
  }

  /******  EXPORTERS   *******/
  toBind () {
    const fields = [ 'name', 'ttl', 'algorithm', 'fptype', 'fingerprint' ]
    return `${fields.map(f => this.get(f)).join('\t')}\n`
  }
}

module.exports = SSHFP
