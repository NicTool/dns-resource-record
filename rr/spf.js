// obsoleted by RFC 7208

import TXT from './txt.js'

import * as TINYDNS from '../lib/tinydns.js'

export default class SPF extends TXT {
  constructor (opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setData (val) {
    this.set('data', val)
  }

  getDescription () {
    return 'Sender Policy Framework'
  }

  getRdataFields (arg) {
    return [ 'data' ]
  }

  getRFCs () {
    return [ 4408, 7208 ]
  }

  getTypeId () {
    return 99
  }

  /******  IMPORTERS   *******/
  fromTinydns (opts) {
    // SPF via generic, :fqdn:n:rdata:ttl:timestamp:lo
    const [ fqdn, n, rdata, ttl, ts, loc ] = opts.tinyline.substring(1).split(':')
    if (n != 99) throw new Error('SPF fromTinydns, invalid n')

    return new SPF({
      type     : 'SPF',
      owner    : this.fullyQualify(fqdn),
      data     : TINYDNS.octalToChar(rdata),
      ttl      : parseInt(ttl, 10),
      timestamp: ts,
      location : loc !== '' && loc !== '\n' ? loc : '',
    })
  }

  /******  EXPORTERS   *******/
  toTinydns () {
    const rdata = TINYDNS.escapeOctal(new RegExp(/[\r\n\t:\\/]/, 'g'), this.get('data'))
    return this.getTinydnsGeneric(rdata)
  }
}
