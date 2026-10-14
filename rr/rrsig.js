import RR from '../rr.js'
import { nameToLabels } from '../lib/name.js'

export default class RRSIG extends RR {
  static typeName = 'RRSIG'
  static typeId = 46
  static RFCs = [4034]
  static rdataFields = [
    ['type covered', 'rrtype'],
    ['algorithm', 'u8'],
    ['labels', 'u8'],
    ['original ttl', 'u32'],
    ['signature expiration', 'u32'],
    ['signature inception', 'u32'],
    ['key tag', 'u16'],
    ['signers name', 'fqdn'],
    ['signature', 'base64'],
  ]
  static tags = ['dnssec']

  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setTypeCovered(val) {
    if (!val && val !== 0) this.throwHelp(`RRSIG: 'type covered' is required`)
    this.setTypedValue('rrtype', 'type covered', val)
  }

  setAlgorithm(val) {
    // a 1 octet Algorithm field
    if (!this.getAlgorithmOptions().has(val)) this.throwHelp(`RRSIG: algorithm invalid`)

    this.set('algorithm', val)
  }

  setOwner(n) {
    if (this.get('labels') !== undefined) this.checkNames({ owner: n })
    super.setOwner(n)
  }

  setLabels(val) {
    this.is8bitInt('RRSIG', 'labels', val)
    this.checkNames({ labels: val })
    this.set('labels', val)
  }

  setOriginalTtl(val) {
    this.setTypedValue('u32', 'original ttl', val)
  }

  setSignatureExpiration(val) {
    this.setSignatureTime('signature expiration', val)
  }

  setSignatureInception(val) {
    this.setSignatureTime('signature inception', val)
  }

  setKeyTag(val) {
    this.setTypedValue('u16', 'key tag', val)
  }

  setSignersName(val) {
    this.isFqdnValue('RRSIG', 'signers name', val)
    this.checkNames({ signer: val })
    this.set('signers name', this.lowercaseName(val))
  }

  // RFC 4034 §3.1.3, §3.1.7: labels counts the owner's labels, less a leading
  // `*`, and is at least the signer's, which is the owner or an ancestor.
  checkNames({ owner = this.get('owner'), labels = this.get('labels'), signer = this.get('signers name') }) {
    if (owner === undefined) return
    const ownerLabels = nameToLabels(owner)
    const wildcard = ownerLabels[0]?.length === 1 && ownerLabels[0][0] === 0x2a
    const max = ownerLabels.length - (wildcard ? 1 : 0)
    if (labels > max) this.throwHelp(`RRSIG: labels (${labels}) exceeds the owner's ${max}`)
    if (signer === undefined) return

    const signerLabels = nameToLabels(signer)
    if (signerLabels.length > labels)
      this.throwHelp(`RRSIG: signers name has ${signerLabels.length} labels, more than labels (${labels})`)
    const fold = (label) => String.fromCharCode(...label).replace(/[A-Z]/g, (c) => c.toLowerCase())
    const offset = ownerLabels.length - signerLabels.length
    if (offset < 0 || signerLabels.some((label, i) => fold(label) !== fold(ownerLabels[offset + i])))
      this.throwHelp(`RRSIG: signers name ${signer} is not the owner or an ancestor of it`)
  }

  // RFC 4034 §3.2: base64, which a master file may split with whitespace
  setSignature(val) {
    const signature = String(val).replace(/[\s()]/g, '')
    this.isBase64('RRSIG', 'signature', signature)
    this.set('signature', signature)
  }

  getAlgorithmOptions() {
    // IANA DNSSEC Algorithm Numbers
    // https://www.iana.org/assignments/dns-sec-alg-numbers/
    return new Map([
      [1, 'RSA/MD5'],
      [2, 'DH'],
      [3, 'DSA/SHA-1'],
      [4, 'EC'],
      [5, 'RSA/SHA-1'],
      [6, 'DSA-NSEC3-SHA1'],
      [7, 'RSASHA1-NSEC3-SHA1'],
      [8, 'RSA/SHA-256'],
      [10, 'RSA/SHA-512'],
      [13, 'ECDSA P-256/SHA-256'],
      [14, 'ECDSA P-384/SHA-384'],
      [15, 'Ed25519'],
      [16, 'Ed448'],
      [253],
      [254],
    ])
  }

  getDescription() {
    return 'Resource Record Signature'
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'RRSIG',
      'type covered': 1,
      algorithm: 5,
      labels: 2,
      'original ttl': 3600,
      'signature expiration': 1045053120,
      'signature inception': 1042461120,
      'key tag': 12345,
      'signers name': 'example.com.',
      signature:
        'oJB1W6WNGv+ldvQ3WDG0MQkg5IEhjRip8WTrPYGv07h108dUKGMeDPKijVCHX3DDKdfb' +
        '+v6oB9wfuh3DTJXUAfI/M0zmO/zz8bW0Rznl8O3tGNazPwQKkRN20XPXV6nwwfoXmJQb' +
        'sLNrLfkGJ5D6fwFm8nN+6pBzeDQfsS3Ap3o=',
    }
  }

  /******  EXPORTERS   *******/
}
