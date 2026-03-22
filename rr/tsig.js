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
    // test.example.com 0 ANY TSIG SAMPLE-ALG.EXAMPLE. 853804800 300 0 0 0
    const parts = bindline.trim().split(/\s+/)

    if (parts.length < 11) {
      // this.throwHelp(`unable to parse TSIG (insufficient fields): ${bindline}`)
    }

    const [owner, ttl, cls, type, alg, time, fudge, mac, origId, error] = parts

    let other = ''
    const errorIndex = bindline.indexOf(error)
    if (errorIndex !== -1) {
      const remainder = bindline.slice(errorIndex + error.length).trim()
      other = remainder
    }

    return new TSIG({
      owner,
      ttl: parseInt(ttl, 10),
      class: cls,
      type: type.toUpperCase(),
      'algorithm name': alg,
      'time signed': parseInt(time, 10),
      fudge: parseInt(fudge, 10),
      'mac size': mac.length,
      mac: mac === '-' ? '' : mac,
      'original id': parseInt(origId, 10),
      error: parseInt(error, 10),
      other: other,
    })
  }

  fromTinydns({ tinyline }) {
    const [owner, _typeId, rdata, ttl, ts, loc] = tinyline.slice(1).split(':')

    const algUnpacked = TINYDNS.unpackDomainName(rdata)
    let pos = algUnpacked[1]

    const consume = (len) => {
      if (len === 0) return ''
      const segment = rdata.substring(pos, pos + len)
      pos += len
      return segment
    }

    const timeSigned = TINYDNS.octalToUInt32(consume(12))
    const fudge = TINYDNS.octalToUInt16(consume(6))
    const macSize = TINYDNS.octalToUInt16(consume(6))
    const mac = TINYDNS.unescapeOctal(consume(macSize * 3))
    const originalId = TINYDNS.octalToUInt16(consume(6))
    const error = TINYDNS.octalToUInt16(consume(6))
    const otherLen = TINYDNS.octalToUInt16(consume(6))
    const other = TINYDNS.unescapeOctal(consume(otherLen * 3))

    return new TSIG({
      owner: this.fullyQualify(owner),
      ttl: parseInt(ttl, 10),
      type: 'TSIG',
      'algorithm name': algUnpacked[0],
      'time signed': timeSigned,
      fudge,
      'mac size': macSize,
      mac,
      'original id': originalId,
      error,
      other,
      ts,
      location: loc?.trim() ?? '',
    })
  }

  /******  EXPORTERS   *******/
  toBind(zone_opts) {
    const parts = [
      this.getFQDN('owner', zone_opts),
      this.get('ttl'),
      this.get('class'),
      this.get('type'),
      this.get('algorithm name'),
      this.get('time signed'),
      this.get('fudge'),
      this.get('mac') === 0 ? '0' : this.get('mac'),
      this.get('original id'),
      this.get('error'),
    ]
    const other = this.get('other') ?? ''
    return `${parts.join('\t')}${other ? '\t' + other : ''}\n`
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
