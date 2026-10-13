import RR from '../rr.js'
import * as TINYDNS from '../lib/tinydns.js'
import * as BINARY from '../lib/binary.js'

export default class OPENPGPKEY extends RR {
  static typeName = 'OPENPGPKEY'
  static typeId = 61
  static RFCs = [4880, 7929]
  static rdataFields = [['public key', 'base64']]
  static tags = ['security']

  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setPublicKey(val) {
    this.isBase64('OPENPGPKEY', 'public key', val)
    this.set('public key', val)
  }

  getDescription() {
    return 'OpenPGP Public Key'
  }

  getCanonical() {
    return {
      owner: 'matt.example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'OPENPGPKEY',
      'public key':
        'AwEAAbdxyhNuSutc5EMzxTs9LBPCIkOFH8cIvM4p9+LrV4e19WzK00+CI6zBCQTdtWsuxKbWIy87UOoJTwIXAqcOTiW7iHnQt5hwVAAAAA==',
    }
  }

  /******  IMPORTERS   *******/

  fromTinydns({ tinyline }) {
    const { owner, typeId, rdata, ttl, timestamp, location } = this.parseTinydnsLine(tinyline)
    if (typeId != this.getTypeId()) this.throwHelp('OPENPGPKEY fromTinydns, invalid n')
    return new OPENPGPKEY({
      owner,
      ttl,
      type: 'OPENPGPKEY',
      'public key': TINYDNS.octalToBase64(rdata),
      timestamp,
      location,
    })
  }

  /******  EXPORTERS   *******/
  toTinydns() {
    return this.getTinydnsGeneric(TINYDNS.base64toOctal(this.get('public key')))
  }

  getWireRdata() {
    return BINARY.base64ToBytes(this.get('public key'))
  }
}
