
const RR = require('./index')

class SSHFP extends RR {
  constructor (opts) {
    super(opts)

    this.algorithm(opts?.algorithm)
    this.type(opts?.type)
    this.fingerprint(opts?.fingerprint)
  }

  algorithm (val) {
    // (0: reserved; 1: RSA 2: DSA 3: ECDSA 4: Ed25519 6:Ed448
    if (!this.is8bitInt('SSHFP', 'algorithm', val)) return

    this.set('algorithm', val)
  }

  type (val) {
    // 0: reserved, 1: SHA-1
    if (!this.is8bitInt('SSHFP', 'type', val)) return

    this.set('type', val)
  }

  fingerprint (val) {
    this.set('fingerprint', val)
  }
}

module.exports = SSHFP
