import RR from '../rr.js'

import * as TINYDNS from '../lib/tinydns.js'

export default class NSEC extends RR {
  constructor(opts) {
    super(opts)
    if (opts === null) return
  }

  /****** Resource record specific setters   *******/
  setNextDomain(val) {
    if (!val) this.throwHelp(`NSEC: 'next domain' is required:`)

    this.isFullyQualified('NSEC', 'next domain', val)
    this.isValidHostname('NSEC', 'next domain', val)

    // RFC 4034: letters in the DNS names are lower cased
    this.set('next domain', val.toLowerCase())
  }

  setTypeBitMaps(val) {
    if (!val) this.throwHelp(`NSEC: 'type bit maps' is required`)

    this.set('type bit maps', val)
  }

  getDescription() {
    return 'Next Secure'
  }

  getRdataFields(arg) {
    return ['next domain', 'type bit maps']
  }

  getRFCs() {
    return [4034]
  }

  getTypeId() {
    return 47
  }

  /******  IMPORTERS   *******/

  fromTinydns({ tinyline }) {
    const [owner, _typeId, rdata, ttl, ts, loc] = tinyline.slice(1).split(':')
    const binaryRdata = Buffer.from(TINYDNS.octalToChar(rdata), 'binary')
    const [nextDomain, _escapedLen, binaryLen] = TINYDNS.unpackDomainName(rdata)

    return new NSEC({
      owner: this.fullyQualify(owner),
      ttl: parseInt(ttl, 10),
      type: 'NSEC',
      'next domain': nextDomain,
      'type bit maps': binaryRdata.slice(binaryLen).toString(),
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  fromBind({ bindline }) {
    // test.example.com  3600  IN  NSEC NextDomain TypeBitMaps
    const [owner, ttl, c, type, next] = bindline.split(/\s+/)
    return new NSEC({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type: type,
      'next domain': next,
      'type bit maps': bindline.split(/\s+/).slice(5).filter(removeParens).join(' ').trim(),
    })
  }

  /******  EXPORTERS   *******/

  toTinydns() {
    const dataRe = new RegExp(/[\r\n\t:\\/]/, 'g')

    return this.getTinydnsGeneric(
      TINYDNS.packDomainName(this.get('next domain')) +
        TINYDNS.escapeOctal(dataRe, this.get('type bit maps')),
    )
  }
}

const removeParens = (a) => !['(', ')'].includes(a)
