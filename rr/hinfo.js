
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
  // fromTinydns (str) {
  //   // HINFO via generic, :fqdn:n:rdata:ttl:timestamp:lo
  // }

  fromBind (str) {
    // test.example.com  3600  IN  HINFO   DEC-2060 TOPS20
    const [ owner, ttl, c, type, cpu, os ] = str.split(/\s+/)

    const bits = {
      owner,
      ttl  : parseInt(ttl, 10),
      class: c,
      type,
      cpu,
      os,
    }
    return new this.constructor(bits)
  }

  /******  EXPORTERS   *******/
  // toTinydns () {
  //   const rdata = '' // TODO
  //   return this.getTinydnsGeneric(rdata)
  // }
}

module.exports = HINFO
