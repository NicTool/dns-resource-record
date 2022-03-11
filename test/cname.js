
// const assert = require('assert')

const base = require('./base')

const CNAME = require('../rr/cname')

const validRecords = [
  {
    class: 'IN',
    name : 'ns1.example.com',
    type : 'CNAME',
    cname: 'ns2.example.com.',
    ttl  : 3600,
    testB: 'ns1.example.com\t3600\tIN\tCNAME\tns2.example.com.\n',
    testT: 'Cns1.example.com:ns2.example.com.:3600::\n',
  },
]

const invalidRecords = [
  {
    class: 'IN',
    name : 'example.com',
    type : 'CNAME',
    cname: '192.0.2.4',  // FQDN required
    ttl  : 3600,
  },
]

describe('CNAME record', function () {
  base.valid(CNAME, validRecords)
  base.invalid(CNAME, invalidRecords)

  base.getDescription(CNAME)
  base.getRFCs(CNAME, validRecords[0])
  base.getFields(CNAME, [ 'cname' ])
  base.getTypeId(CNAME, 5)

  base.toBind(CNAME, validRecords)
  base.toTinydns(CNAME, validRecords)

  base.fromTinydns(CNAME, validRecords)
  base.fromBind(CNAME, validRecords)
})
