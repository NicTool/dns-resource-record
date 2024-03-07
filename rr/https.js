
// import net from 'net'

import RR from '../rr.js'

export default class HTTPS extends RR {
  constructor (opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setPriority (val) {
    this.is16bitInt('HTTPS', 'priority', val)

    this.set('priority', val)
  }

  setTargetName (val) {

    // this.isFullyQualified('HTTPS', 'target name', val)
    // this.isValidHostname('HTTPS', 'target name', val)

    // RFC 4034: letters in the DNS names are lower cased
    this.set('target name', val.toLowerCase())
  }

  setParams (val) {
    // if (!val) throw new Error(`HTTPS: params is required, ${this.citeRFC()}`)

    this.set('params', val)
  }

  getDescription () {
    return 'HTTP Semantics'
  }

  getRdataFields (arg) {
    return [ 'priority', 'target name', 'params' ]
  }

  getRFCs () {
    return [9460]
  }

  getTypeId () {
    return 65
  }

  /******  IMPORTERS   *******/

  fromBind (opts) {
    // test.example.com  3600  IN  HTTPS Priority DomainName FieldValue
    const [ owner, ttl, c, type, pri, fqdn ] = opts.bindline.split(/\s+/)
    return new HTTPS({
      owner,
      ttl          : parseInt(ttl, 10),
      class        : c,
      type,
      priority     : parseInt(pri, 10),
      'target name': fqdn,
      params        : opts.bindline.split(/\s+/).slice(6).join(' ').trim(),
    })
  }

  /******  EXPORTERS   *******/
}
