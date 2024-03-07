import RR from '../rr.js'

export default class WKS extends RR {
  constructor(opts) {
    super(opts)
    if (opts === null) return
  }

  /****** Resource record specific setters   *******/

  getDescription() {
    return 'Well Known Service'
  }

  getRdataFields(arg) {
    return ['bit map']
  }

  getRFCs() {
    return [883, 1035]
  }

  getTypeId() {
    return 11
  }

  /******  IMPORTERS   *******/

  fromBind(opts) {
    // test.example.com  3600  IN  WKS 192.168.1.1 TCP 25
    const [owner, ttl, c, type, address, protocol, bitmap] =
      opts.bindline.split(/\s+/)
    return new WKS({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type,
      address, // 32-bit int
      protocol, // 8-bit int, 6=TCP, 17=UDP
      bitmap, // var len bit map, must be multiple of 8
    })
  }

  /******  EXPORTERS   *******/
}
