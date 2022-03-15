
const RR = require('./index').RR

class SMIMEA extends RR {
  constructor (opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setCertificateUsage (val) {
    if (![ 0,1,2,3 ].includes(val))
      throw new Error(`SMIMEA: certificate usage invalid, see ${this.getRFCs()}`)

    this.set('certificate usage', val)
  }

  setSelector (val) {
    if (![ 0,1 ].includes(val))
      throw new Error(`SMIMEA: selector invalid, see ${this.getRFCs()}`)

    this.set('selector', val)
  }

  setMatchingType (val) {
    if (![ 0,1,2 ].includes(val))
      throw new Error(`SMIMEA: matching type, see ${this.getRFCs()}`)

    this.set('matching type', val)
  }

  setCertificateAssociationData (val) {
    this.set('certificate association data', val)
  }


  getDescription () {
    return 'S/MIME cert association'
  }

  getRdataFields (arg) {
    return [ 'certificate usage', 'selector', 'matching type', 'certificate association data' ]
  }

  getRFCs () {
    return [ 8162 ]
  }

  getTypeId () {
    return 53
  }

  getQuotedFields () {
    return [  ]
  }

  /******  IMPORTERS   *******/
  // fromTinydns (str) {
  // }

  fromBind (str) {
    // test.example.com  3600  IN  SMIMEA, usage, selector, match, data
    const [ fqdn, ttl, c, type, usage, selector, match ] = str.split(/\s+/)
    return new this.constructor({
      name                          : fqdn,
      ttl                           : parseInt(ttl, 10),
      class                         : c,
      type                          : type,
      'certificate usage'           : parseInt(usage,    10),
      selector                      : parseInt(selector, 10),
      'matching type'               : parseInt(match   , 10),
      'certificate association data': str.split(/\s+/).slice(7).join(' ').trim(),
    })
  }

  /******  EXPORTERS   *******/
  // toTinydns () {
  // }
}

module.exports = SMIMEA