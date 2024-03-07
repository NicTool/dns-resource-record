import * as base from './base.js'

import CNAME from '../rr/cname.js'

const defaults = { class: 'IN', ttl: 3600, type: 'CNAME' }

const validRecords = [
  {
    ...defaults,
    owner: 'ns1.example.com.',
    cname: 'ns2.example.com.',
    testB: 'ns1.example.com.\t3600\tIN\tCNAME\tns2.example.com.\n',
    testT: 'Cns1.example.com:ns2.example.com.:3600::\n',
  },
]

const invalidRecords = [
  {
    ...defaults,
    owner: 'example.com.',
    cname: '192.0.2.4', // FQDN required
    msg: /cname must be a FQDN/,
  },
]

describe('CNAME record', function () {
  base.valid(CNAME, validRecords)
  base.invalid(CNAME, invalidRecords)

  base.getDescription(CNAME)
  base.getRFCs(CNAME, validRecords[0])
  base.getFields(CNAME, ['cname'])
  base.getTypeId(CNAME, 5)

  base.toBind(CNAME, validRecords)
  base.toTinydns(CNAME, validRecords)

  base.fromTinydns(CNAME, validRecords)
  base.fromBind(CNAME, validRecords)
})
