import RR from '../rr.js'

import * as TINYDNS from '../lib/tinydns.js'

export default class DS extends RR {
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setKeyTag(val) {
    // a 2 octet Key Tag field...in network byte order
    if (!val) this.throwHelp(`DS: key tag is required`)
    if (val.length > 2) this.throwHelp(`DS: key tag is too long`)

    this.set('key tag', val)
  }

  setAlgorithm(val) {
    // 1=RSA/MD5, 2=DH, 3=DSA/SHA-1, 4=EC, 5=RSA/SHA-1
    if (![1, 2, 3, 4, 5, 253, 254].includes(val))
      this.throwHelp(`DS: algorithm invalid`)

    this.set('algorithm', val)
  }

  setDigestType(val) {
    if (![1, 2].includes(val)) this.throwHelp(`DS: digest type invalid`)

    this.set('digest type', val)
  }

  setDigest(val) {
    if (!val) this.throwHelp(`DS: digest is required`)

    this.set('digest', val)
  }

  getDescription() {
    return 'Delegation Signer'
  }

  getRdataFields(arg) {
    return ['key tag', 'algorithm', 'digest type', 'digest']
  }

  getRFCs() {
    return [4034, 4509]
  }

  getTypeId() {
    return 43
  }

  /******  IMPORTERS   *******/

  fromBind(opts) {
    // test.example.com  3600  IN  DS Key Tag Algorithm, Digest Type, Digest
    const [owner, ttl, c, type, keytag, algorithm, digesttype] =
      opts.bindline.split(/\s+/)
    return new DS({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type,
      'key tag': parseInt(keytag, 10),
      algorithm: parseInt(algorithm, 10),
      'digest type': parseInt(digesttype, 10),
      digest: opts.bindline.split(/\s+/).slice(7).join(' ').trim(),
    })
  }

  fromTinydns(opts) {
    const [fqdn, n, rdata, ttl, ts, loc] = opts.tinyline.substring(1).split(':')
    if (n != 43) this.throwHelp('DS fromTinydns, invalid n')

    const binRdata = Buffer.from(TINYDNS.octalToChar(rdata), 'binary')

    return new DS({
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'DS',
      'key tag': binRdata.readUInt16BE(0),
      algorithm: binRdata.readUInt8(2),
      'digest type': binRdata.readUInt8(3),
      digest: binRdata.slice(4).toString(),
      timestamp: ts,
      location: loc !== '' && loc !== '\n' ? loc : '',
    })
  }

  /******  EXPORTERS   *******/

  toTinydns() {
    const rdataRe = new RegExp(/[\r\n\t:\\/]/, 'g')

    return this.getTinydnsGeneric(
      TINYDNS.UInt16toOctal(this.get('key tag')) +
        TINYDNS.UInt8toOctal(this.get('algorithm')) +
        TINYDNS.UInt8toOctal(this.get('digest type')) +
        TINYDNS.escapeOctal(rdataRe, this.get('digest')),
    )
  }
}
