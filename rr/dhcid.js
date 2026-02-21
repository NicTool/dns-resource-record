import RR from '../rr.js'

export default class DHCID extends RR {
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setData(val) {
    if (!val) this.throwHelp('DHCID: data is required')
    this.set('data', val)
  }

  getDescription() {
    return 'DHCP Identifier'
  }

  getRdataFields(arg) {
    return ['data']
  }

  getRFCs() {
    return [4701]
  }

  getTypeId() {
    return 49
  }

  getCanonical() {
    return {
      owner: 'host.example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'DHCID',
      data: 'AAIBY2/AuCccgoJbsaxcQc9TUapptP69lOjxfNuVAA2kjEA=',
    }
  }

  /******  IMPORTERS   *******/
  fromBind(opts) {
    // host.example.com  3600  IN  DHCID  <base64data>
    const parts = opts.bindline.split(/\s+/)
    const [owner, ttl, c, type] = parts
    return new DHCID({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type,
      data: parts.slice(4).join(''),
    })
  }

  /******  EXPORTERS   *******/
}
