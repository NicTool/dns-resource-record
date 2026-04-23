import RR from '../rr.js'
import * as TINYDNS from '../lib/tinydns.js'
import * as BINARY from '../lib/binary.js'

export default class OPENPGPKEY extends RR {
  static typeName = 'OPENPGPKEY'
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

  getTags() {
    return ['security']
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
  fromBind({ bindline: bindline }) {
    // test.example.com  3600  IN  OPENPGPKEY  <base64 public key>
    const regex =
      /^(?<owner>\S+)\s+(?<ttl>\d{1,10})\s+(?<class>IN)\s+(?<type>OPENPGPKEY)\s+(?<publickey>\S[\s\S]*)$/i
    const match = bindline.trim().match(regex)
    if (!match) this.throwHelp(`unable to parse OPENPGPKEY: ${bindline}`)

    const { owner, ttl, class: c, type, publickey } = match.groups
    const keyStr = publickey.trim().replace(/\s+/g, '')

    return new OPENPGPKEY({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type: type,
      'public key': keyStr,
    })
  }

  fromTinydns({ tinyline }) {
    const [owner, _typeId, rd, ttl, ts, loc] = tinyline.slice(1).split(':')
    return new OPENPGPKEY({
      owner: this.fullyQualify(owner),
      ttl: parseInt(ttl, 10),
      type: 'OPENPGPKEY',
      'public key': TINYDNS.octalToBase64(rd),
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  fromWire({ owner, cls, ttl, rdata }) {
    return new OPENPGPKEY({
      owner,
      ttl,
      class: cls,
      type: 'OPENPGPKEY',
      'public key': btoa([...rdata].map((b) => String.fromCharCode(b)).join('')),
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
