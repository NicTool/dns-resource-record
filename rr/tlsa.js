
import RR from '../rr.js'

export default class TLSA extends RR {
  constructor (opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setCertificateUsage (val) {
    if (![ 0,1,2,3 ].includes(val))
      throw new Error(`TLSA: certificate usage invalid, ${this.citeRFC()}`)

    this.set('certificate usage', val)
  }

  setSelector (val) {
    if (![ 0,1 ].includes(val))
      throw new Error(`TLSA: selector invalid, ${this.citeRFC()}`)

    this.set('selector', val)
  }

  setMatchingType (val) {
    if (![ 0,1,2 ].includes(val))
      throw new Error(`TLSA: matching type, ${this.citeRFC()}`)

    this.set('matching type', val)
  }

  setCertificateAssociationData (val) {
    this.set('certificate association data', val)
  }

  getDescription () {
    return 'TLSA certificate association'
  }

  getRdataFields (arg) {
    return [ 'certificate usage', 'selector', 'matching type', 'certificate association data' ]
  }

  getRFCs () {
    return [ 6698 ]
  }

  getTypeId () {
    return 52
  }

  getQuotedFields () {
    return [  ]
  }

  /******  IMPORTERS   *******/

  fromBind (str) {
    // test.example.com  3600  IN  TLSA, usage, selector, match, data
    const match = str.split(/^([^\s]+)\s+([0-9]+)\s+(\w+)\s+(\w+)\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)\s+(.*?)\s*$/)
    if (!match) throw new Error(`unable to parse TLSA: ${str}`)
    const [ owner, ttl, c, type, usage, selector, matchtype, cad ] = match.slice(1)
    return new this.constructor({
      owner                         : this.fullyQualify(owner),
      ttl                           : parseInt(ttl, 10),
      class                         : c,
      type,
      'certificate usage'           : parseInt(usage,     10),
      selector                      : parseInt(selector,  10),
      'matching type'               : parseInt(matchtype, 10),
      'certificate association data': cad,
    })
  }
}
