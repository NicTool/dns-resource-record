import RR, { formatSignatureTime } from '../rr.js'

import * as BINARY from '../lib/binary.js'

export default class SIG extends RR {
  static typeName = 'SIG'
  static typeId = 24
  static RFCs = [2535, 3755]
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
  static tags = ['obsolete']

  /****** Resource record specific setters   *******/
  setTypeCovered(val) {
    if (!val && val !== 0) this.throwHelp(`SIG: 'type covered' is required`)
    this.setTypedValue('rrtype', 'type covered', val)
  }

  setSignatureExpiration(val) {
    this.setSignatureTime('signature expiration', val)
  }

  setSignatureInception(val) {
    this.setSignatureTime('signature inception', val)
  }

  getDescription() {
    return 'Signature'
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'SIG',
      'type covered': 1,
      algorithm: 5,
      labels: 3,
      'original ttl': 3600,
      'signature expiration': 1045053120,
      'signature inception': 1042461120,
      'key tag': 12345,
      'signers name': 'example.com.',
      signature: 'AQPSKmynfzW4kyBv015MUG2DeIQ3Cbl+BBZH4b/0PY1kxkmvHjcZc8no',
    }
  }

  /******  EXPORTERS   *******/

  toBind(zone_opts) {
    // RFC 2535 §7.2 presents SIG times only as YYYYMMDDHHmmSS; BIND rejects integers.
    const rdata = this.getRdataFields().map((f) => {
      if (f === 'signature expiration' || f === 'signature inception') return formatSignatureTime(this.get(f))
      if (f === 'signers name') return this.getFQDN(f, zone_opts)
      if (f === 'type covered') return BINARY.typeIdToName(this.get(f))
      return this.get(f)
    })
    return `${this.getPrefix(zone_opts)}\t${rdata.join('\t')}\n`
  }
}
