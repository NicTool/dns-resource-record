import RR from '../rr.js'

export default class TSIG extends RR {
  constructor(opts) {
    super(opts)
    if (opts === null) return
  }

  /****** Resource record specific setters   *******/
  
  getDescription() {
    return 'Transaction Signature'
  }

  getRdataFields(arg) {
    return ['algorithm name', 'time signed', 'fudge', 'mac', 'original id', 'error', 'other']
  }

  getRFCs() {
    return [2845]
  }

  getTypeId() {
    return 250
  }

  /******  IMPORTERS   *******/

  fromBind(opts) {
    // test.example.com  3600  IN  TSIG SAMPLE-ALG.EXAMPLE. 853804800 300 0 0 0
    const [owner, ttl, c, type, algorithm] = opts.bindline.split(/\s+/)
    return new TSIG({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type: type,
      'algorithm': algorithm,
      // 'time signed': opts.bindline,
      // fudge
      // mac
      // original id
      // error
      // other
    })
  }

  /******  EXPORTERS   *******/
}
