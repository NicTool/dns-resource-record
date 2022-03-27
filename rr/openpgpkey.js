
const RR      = require('./index').RR

class OPENPGPKEY extends RR {
  constructor (opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setPublicKey (val) {
    this.set('public key', val)
  }

  getDescription () {
    return 'OpenPGP Public Key'
  }

  getRdataFields () {
    return [ 'public key' ]
  }

  getRFCs () {
    return [ 4880, 7929 ]
  }

  getTypeId () {
    return 61
  }

  /******  IMPORTERS   *******/
  fromBind (str) {
    // test.example.com  3600  IN  OPENPGPKEY  <base64 public key>
    const [ fqdn, ttl, c, type, privatekey ] = str.split(/\s+/)
    return new this.constructor({
      name         : fqdn,
      ttl          : parseInt(ttl, 10),
      class        : c,
      type         : type,
      'private key': privatekey,
    })
  }

  /******  EXPORTERS   *******/
}

module.exports = OPENPGPKEY
