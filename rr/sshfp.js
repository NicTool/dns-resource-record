
const RR = require('./index')

class SSHFP extends RR {
  constructor (opts) {
    super(opts)

    this.setAlgorithm(opts?.algorithm)
    this.setFpType(opts?.fptype)
    this.setFingerprint(opts?.fingerprint)
  }

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

  toBind () {
    return `${this.get('name')}\t${this.get('ttl')}\t${this.get('algorithm')}\t${this.get('fptype')}\t${this.get('fingerprint')}\n`
  }
}

module.exports = SSHFP
