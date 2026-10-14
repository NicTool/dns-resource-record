import SVCB from './svcb.js'

// RFC 9460 §9: HTTPS is SVCB with the HTTP-specific defaults.
export default class HTTPS extends SVCB {
  static typeName = 'HTTPS'
  static typeId = 65
  static tags = ['common']

  getDescription() {
    return 'HTTP Semantics'
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'HTTPS',
      priority: 1,
      'target name': 'example.com.',
      params: 'alpn="h2,h3"',
    }
  }
}
