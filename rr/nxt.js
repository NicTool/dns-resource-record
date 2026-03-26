import RR from '../rr.js'

import * as TINYDNS from '../lib/tinydns.js'

export default class NXT extends RR {
  constructor(opts) {
    super(opts)
    if (opts === null) return
  }

  /****** Resource record specific setters   *******/
  setNextDomain(val) {
    if (!val) this.throwHelp(`NXT: 'next domain' is required`)

    this.isFullyQualified('NXT', 'next domain', val)
    this.isValidHostname('NXT', 'next domain', val)

    // RFC 4034: letters in the DNS names are lower cased
    this.set('next domain', val.toLowerCase())
  }

  setTypeBitMap(val) {
    if (!val) this.throwHelp(`NXT: 'type bit map' is required`)

    this.set('type bit map', val)
  }

  getDescription() {
    return 'Next Secure'
  }

  getTags() {
    return ['deprecated']
  }

  getRdataFields(arg) {
    return ['next domain', 'type bit map']
  }

  getRFCs() {
    return [2065]
  }

  getTypeId() {
    return 30
  }

  getCanonical() {
    return {
      owner: 'big.example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'NXT',
      'next domain': 'host.example.com.',
      'type bit map': 'A MX NXT',
    }
  }

  /******  IMPORTERS   *******/

  fromTinydns({ tinyline }) {
    const [owner, n, rdata, ttl, ts, loc] = tinyline.slice(1).split(':')
    if (parseInt(n, 10) !== this.getTypeId()) this.throwHelp('NXT fromTinydns, invalid n')

    const binaryRdata = Buffer.from(TINYDNS.octalToChar(rdata), 'binary')
    const [nextDomain, _escapedLen, binaryLen] = TINYDNS.unpackDomainName(rdata)

    return new NXT({
      owner: this.fullyQualify(owner),
      ttl: parseInt(ttl, 10),
      type: 'NXT',
      'next domain': nextDomain,
      'type bit map': binaryRdata.slice(binaryLen).toString(),
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  fromBind({ bindline }) {
    // test.example.com  3600  IN  NXT NextDomain TypeBitMap
    const [owner, ttl, c, type, next] = bindline.split(/\s+/)
    return new NXT({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type: type,
      'next domain': next,
      'type bit map': bindline.split(/\s+/).slice(5).filter(removeParens).join(' ').trim(),
    })
  }

  /******  EXPORTERS   *******/

  toTinydns() {
    const dataRe = new RegExp(/[\r\n\t:\\/]/, 'g')

    return this.getTinydnsGeneric(
      TINYDNS.packDomainName(this.get('next domain')) + TINYDNS.escapeOctal(dataRe, this.get('type bit map')),
    )
  }
}

const removeParens = (a) => !['(', ')'].includes(a)
