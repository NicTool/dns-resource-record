import RR from '../rr.js'

export default class OPENPGPKEY extends RR {
  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setPublicKey(val) {
    this.set('public key', val)
  }

  getDescription() {
    return 'OpenPGP Public Key'
  }

  getRdataFields() {
    return ['public key']
  }

  getRFCs() {
    return [4880, 7929]
  }

  getTypeId() {
    return 61
  }

  /******  IMPORTERS   *******/
  fromBind(str) {
    // test.example.com  3600  IN  OPENPGPKEY  <base64 public key>
    const [owner, ttl, c, type, privatekey] = str.split(/\s+/)
    return new OPENPGPKEY({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type: type,
      'private key': privatekey,
    })
  }

  /******  EXPORTERS   *******/
}
