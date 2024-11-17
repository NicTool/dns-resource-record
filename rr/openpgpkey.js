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
  fromBind(obj) {
    // test.example.com  3600  IN  OPENPGPKEY  <base64 public key>
    // eslint-disable-next-line no-unused-vars
    const [ignore, owner, ttl, c, type, publickey] = obj.bindline
      .trim()
      .match(/^([\S]+)\s+(\d{1,10})\s+(IN)\s+(OPENPGPKEY)\s+([\W\w]*)$/)

    return new OPENPGPKEY({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type: type,
      'public key': publickey.trim(),
    })
  }

  /******  EXPORTERS   *******/
}
