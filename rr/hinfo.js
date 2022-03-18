
const RR = require('./index').RR

class HINFO extends RR {
  constructor (opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setCpu (val) {
    if (val.length > 255) throw new Error('HINFO cpu cannot exceed 255 chars')
    this.set('cpu', val)
  }

  setOs (val) {
    if (val.length > 255) throw new Error('HINFO os cannot exceed 255 chars')
    this.set('os', val)
  }

  getDescription () {
    return 'Host Info'
  }

  getRdataFields (arg) {
    return [ 'cpu', 'os' ]
  }

  getRFCs () {
    return [ 8482 ]
  }

  getTypeId () {
    return 13
  }

  getQuotedFields () {
    return [ 'cpu', 'os' ]
  }

  /******  IMPORTERS   *******/
  fromTinydns (str) {
    // HINFO via generic, :fqdn:n:rdata:ttl:timestamp:lo
  }

  fromBind () {
  }

  /******  EXPORTERS   *******/
  // toTinydns () {
  //   const rdata = '' // TODO
  //   return this.getTinydnsGeneric(rdata)
  // }
}

module.exports = HINFO
