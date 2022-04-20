
import RR from '../rr.js'

export default class HINFO extends RR {
  constructor (opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setCpu (val) {
    if (val.length > 255) throw new Error('HINFO cpu cannot exceed 255 chars')
    this.set('cpu', val.replace(/^["']|["']$/g, ''))
  }

  setOs (val) {
    if (val.length > 255) throw new Error('HINFO os cannot exceed 255 chars')
    this.set('os', val.replace(/^["']|["']$/g, ''))
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
  fromBind (str) {
    // test.example.com  3600  IN  HINFO   DEC-2060 TOPS20
    const match = str.match(/([^\s]+)\s+([0-9]+)\s+(IN)\s+(HINFO)\s+("[^"]+"|[^\s]+)\s+("[^"]+"|[^\s]+)/i)
    if (!match) throw new Error(`unable to parse HINFO: ${str}`)
    const [ owner, ttl, c, type, cpu, os ] = match.slice(1)

    return new HINFO({
      owner,
      ttl  : parseInt(ttl, 10),
      class: c,
      type,
      cpu,
      os,
    })
  }

  // fromTinydns (str) {
  //   // HINFO via generic, :fqdn:n:rdata:ttl:timestamp:lo
  // }

  /******  EXPORTERS   *******/
}
