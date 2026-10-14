import RR from '../rr.js'
import NSEC3, { saltFromBytes, saltToBytes } from './nsec3.js'

export default class NSEC3PARAM extends RR {
  static typeName = 'NSEC3PARAM'
  static typeId = 51
  static RFCs = [5155]
  static rdataFields = [['hash algorithm', 'u8'], ['flags', 'u8'], ['iterations', 'u16'], 'salt']
  static tags = ['dnssec']

  /****** Resource record specific setters   *******/
  setSalt(val) {
    NSEC3.prototype.setSalt.call(this, val)
  }

  getDescription() {
    return 'Next Secure Parameters'
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'NSEC3PARAM',
      'hash algorithm': 1,
      flags: 1,
      iterations: 12,
      salt: 'aabbccdd',
    }
  }

  /******  IMPORTERS   *******/

  // RFC 5155 §4.2: the salt fills the rest of the rdata.
  fromWire({ owner, cls, ttl, rdata }) {
    if (rdata.length < 5 || rdata.length !== 5 + rdata[4])
      throw new Error('NSEC3PARAM: salt length does not match the rdata')
    return new NSEC3PARAM({
      owner,
      ttl,
      class: cls,
      type: 'NSEC3PARAM',
      'hash algorithm': rdata[0],
      flags: rdata[1],
      iterations: (rdata[2] << 8) | rdata[3],
      salt: saltFromBytes(rdata.subarray(5)),
    })
  }

  /******  EXPORTERS   *******/

  getWireRdata() {
    const salt = saltToBytes(this.get('salt'))
    return Uint8Array.from([
      this.get('hash algorithm'),
      this.get('flags'),
      this.get('iterations') >> 8,
      this.get('iterations') & 0xff,
      salt.length,
      ...salt,
    ])
  }
}
