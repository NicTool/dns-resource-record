import RR from '../rr.js'
import * as TINYDNS from '../lib/tinydns.js'

export default class TSIG extends RR {
  constructor(opts) {
    super(opts)
    if (opts === null) return
  }

  /****** Resource record specific setters   *******/

  getDescription() {
    return 'Transaction Signature'
  }

  getRdataFields(arg) {
    return ['algorithm name', 'time signed', 'fudge', 'mac', 'original id', 'error', 'other']
  }

  getRFCs() {
    return [2845, 8945]
  }

  getTypeId() {
    return 250
  }

  getCanonical() {
    return {
      owner: 'test.example.',
      ttl: 0,
      class: 'ANY',
      type: 'TSIG',
      'algorithm name': 'hmac-sha256.',
      'time signed': 1620650000,
      fudge: 300,
      mac: 'ABCDEF...',
      'original id': 12345,
      error: 0,
      other: '',
    }
  }

  setClass(t) {
    if (t !== 'ANY') this.throwHelp('TSIG: Class is required to be ANY')
    this.set('class', t)
  }

  setTtl(t) {
    if (t !== 0) this.throwHelp('TSIG: TTL is required to be 0')
    this.set('ttl', t)
  }

  setAlgorithmName(val) {
    if (!val) this.throwHelp(`TSIG: 'algorithm name' is required`)
    this.set('algorithm name', val)
  }

  setTimeSigned(val) {
    // a 48-bit unsigned integer, as seconds since the UNIX epoch
    if (val === undefined) this.throwHelp(`TSIG: 'time signed' is required`)
    this.set('time signed', val)
  }

  setFudge(val) {
    // 16-bit unsigned
    this.is16bitInt('TSIG', 'fudge', val)
    this.set('fudge', val)
  }

  setMac(val) {
    this.set('mac', val ?? '')
  }

  setOriginalId(val) {
    this.is16bitInt('TSIG', 'original id', val)
    this.set('original id', val)
  }

  setError(val) {
    this.is16bitInt('TSIG', 'error', val)
    this.set('error', val)
  }

  setOther(val) {
    this.set('other', val ?? '')
  }

  /******  IMPORTERS   *******/

  fromBind({ bindline }) {
    // owner ttl ANY TSIG alg time fudge mac_size mac original_id error other_len
    const parts = bindline.trimEnd().split('\t')
    const [owner, ttl, cls, type, alg, time, fudge, , mac, origId, error] = parts

    return new TSIG({
      owner,
      ttl: parseInt(ttl, 10),
      class: cls,
      type: type.toUpperCase(),
      'algorithm name': alg,
      'time signed': parseInt(time, 10),
      fudge: parseInt(fudge, 10),
      mac: mac || '',
      'original id': parseInt(origId, 10),
      error: parseInt(error, 10),
      other: '',
    })
  }

  fromTinydns({ tinyline }) {
    const [owner, _typeId, rdata, ttl, ts, loc] = tinyline.slice(1).split(':')

    const algUnpacked = TINYDNS.unpackDomainName(rdata)
    const algBinaryLen = algUnpacked[2]

    const bytes = Buffer.from(TINYDNS.octalToChar(rdata), 'binary')
    let bpos = algBinaryLen

    const timeSigned = bytes.readUInt32BE(bpos)
    bpos += 4
    const fudge = bytes.readUInt16BE(bpos)
    bpos += 2
    const macSize = bytes.readUInt16BE(bpos)
    bpos += 2
    const mac = macSize > 0 ? bytes.slice(bpos, bpos + macSize).toString('hex') : ''
    bpos += macSize
    const originalId = bytes.readUInt16BE(bpos)
    bpos += 2
    const error = bytes.readUInt16BE(bpos)
    bpos += 2
    const other = bpos < bytes.length ? bytes.slice(bpos).toString() : ''

    return new TSIG({
      owner: this.fullyQualify(owner),
      ttl: parseInt(ttl, 10),
      class: 'ANY',
      type: 'TSIG',
      'algorithm name': algUnpacked[0],
      'time signed': timeSigned,
      fudge,
      mac,
      'original id': originalId,
      error,
      other,
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  /******  EXPORTERS   *******/
  toBind(zone_opts) {
    const mac = this.get('mac') ?? ''
    const macSize = mac.length > 0 ? mac.length : ''
    const other = this.get('other') ?? ''
    const otherLen = other.length > 0 ? other.length : 0
    return (
      [
        this.getFQDN('owner', zone_opts),
        this.get('ttl'),
        this.get('class'),
        this.get('type'),
        this.get('algorithm name'),
        this.get('time signed'),
        this.get('fudge'),
        macSize,
        mac,
        this.get('original id'),
        this.get('error'),
        otherLen,
      ].join('\t') + '\n'
    )
  }

  toTinydns() {
    const dataRe = new RegExp(/[\r\n\t:\\/]/, 'g')
    const alg = this.get('algorithm name') || ''

    return this.getTinydnsGeneric(
      TINYDNS.packDomainName(alg) +
        TINYDNS.UInt32toOctal(this.get('time signed') ?? 0) +
        TINYDNS.UInt16toOctal(this.get('fudge')) +
        TINYDNS.UInt16toOctal(this.get('mac size') ?? 0) +
        (this.get('mac size') > 0 ? TINYDNS.escapeOctal(dataRe, this.get('mac')) : '') +
        TINYDNS.UInt16toOctal(this.get('original id') ?? 0) +
        TINYDNS.UInt16toOctal(this.get('error') ?? 0) +
        (this.get('other').length > 0 ? TINYDNS.escapeOctal(dataRe, this.get('other')) : ''),
    )
  }
}
