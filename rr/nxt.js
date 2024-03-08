import RR from '../rr.js'

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

  getRdataFields(arg) {
    return ['next domain', 'type bit map']
  }

  getRFCs() {
    return [2065]
  }

  getTypeId() {
    return 30
  }

  /******  IMPORTERS   *******/

  fromBind(opts) {
    // test.example.com  3600  IN  NXT NextDomain TypeBitMap
    const [owner, ttl, c, type, next] = opts.bindline.split(/\s+/)
    return new NXT({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type: type,
      'next domain': next,
      'type bit map': opts.bindline
        .split(/\s+/)
        .slice(5)
        .filter(removeParens)
        .join(' ')
        .trim(),
    })
  }

  /******  EXPORTERS   *******/
}

const removeParens = (a) => !['(', ')'].includes(a)
