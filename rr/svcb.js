
// import net from 'net'

import RR from '../rr.js'

export default class SVCB extends RR {
  constructor (opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setPriority (val) {
    this.is16bitInt('SVCB', 'priority', val)

    this.set('priority', val)
  }

  setDomainName (val) {

    // this.isFullyQualified('SVCB', 'domain name', val)
    // this.isValidHostname('SVCB', 'domain name', val)

    // RFC 4034: letters in the DNS names are lower cased
    this.set('domain name', val.toLowerCase())
  }

  setValue (val) {
    // if (!val) throw new Error(`SVCB: value is required, ${this.citeRFC()}`)

    this.set('value', val)
  }

  getDescription () {
    return 'Service'
  }

  getRdataFields (arg) {
    return [ 'priority', 'domain name', 'value' ]
  }

  getRFCs () {
    return [ ]
  }

  getTypeId () {
    return 64
  }

  /******  IMPORTERS   *******/

  fromBind (str) {
    // test.example.com  3600  IN  SVCB Priority DomainName FieldValue
    const [ owner, ttl, c, type, pri, fqdn ] = str.split(/\s+/)
    return new SVCB({
      owner,
      ttl          : parseInt(ttl, 10),
      class        : c,
      type,
      priority     : parseInt(pri, 10),
      'domain name': fqdn,
      value        : str.split(/\s+/).slice(6).join(' ').trim(),
    })
  }

  /******  EXPORTERS   *******/
}
