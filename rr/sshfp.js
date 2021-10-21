
const RR = require('./index')

class SSHFP extends RR {
  constructor (opts) {
    super(opts)

    this.setAlgorithm(opts?.algorithm)
    this.setType(opts?.type)
    this.setFingerprint(opts?.fingerprint)
  }

  setAlgorithm (val) {
    // (0: reserved; 1: RSA 2: DSA 3: ECDSA 4: Ed25519 6:Ed448
    if (!this.is8bitInt('SSHFP', 'algorithm', val)) return

    this.set('algorithm', val)
  }

  setType (val) {
    // 0: reserved, 1: SHA-1
    if (!this.is8bitInt('SSHFP', 'type', val)) return

    this.set('type', val)
  }

  setFingerprint (val) {
    this.set('fingerprint', val)
  }
}

module.exports = SSHFP
