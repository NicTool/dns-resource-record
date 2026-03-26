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
      'public key': 'mQINBFY...',
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
      location: loc?.trim() ?? '',
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
