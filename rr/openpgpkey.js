import RR from '../rr.js'
import * as TINYDNS from '../lib/tinydns.js'

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
  fromBind({ bindline: bindline }) {
    // test.example.com  3600  IN  OPENPGPKEY  <base64 public key>
    const regex = /^([\S]+)\s+(\d{1,10})\s+(IN)\s+(OPENPGPKEY)\s+([\W\w]*)$/
    // eslint-disable-next-line no-unused-vars
    const [ignore, owner, ttl, c, type, publickey] = bindline.trim().match(regex)

    return new OPENPGPKEY({
      owner,
      ttl: parseInt(ttl, 10),
      class: c,
      type: type,
      'public key': publickey.trim(),
    })
  }

  fromTinydns({ tinyline }) {
    const [owner, _typeId, rd, ttl, ts, loc] = tinyline.slice(1).split(':')
    return new OPENPGPKEY({
      owner: this.fullyQualify(owner),
      ttl: parseInt(ttl, 10),
      type: 'OPENPGPKEY',
      'public key': Buffer.from(TINYDNS.unescapeOctal(rd), 'base64').toString('utf-8'),
      timestamp: ts,
      location: loc?.trim() || '',
    })
  }

  /******  EXPORTERS   *******/
  toTinydns() {
    const dataRe = new RegExp(/[\r\n\t:\\/]/, 'g')
    const escapedPublicKey = TINYDNS.escapeOctal(
      dataRe,
      Buffer.from(this.get('public key'), 'utf-8').toString('base64'),
    )
    return this.getTinydnsGeneric(escapedPublicKey)
  }
}
