import { describe } from 'node:test'
import * as base from '../base.js'

import CNAME from '../../rr/cname.js'

const defaults = { class: 'IN', ttl: 3600, type: 'CNAME' }

const validRecords = [
  {
    ...defaults,
    owner: 'ns1.example.com.',
    cname: 'ns2.example.com.',
    testB: 'ns1.example.com.\t3600\tIN\tCNAME\tns2.example.com.\n',
    testT: 'Cns1.example.com:ns2.example.com:3600::\n',
    testW: '036e7331076578616d706c6503636f6d000005000100000e100011036e7332076578616d706c6503636f6d00',
  },
  {
    ...defaults,
    owner: '*.example.com.',
    cname: 'www.example.com.',
    testB: '*.example.com.\t3600\tIN\tCNAME\twww.example.com.\n',
    testT: 'C*.example.com:www.example.com:3600::\n',
    testW: '012a076578616d706c6503636f6d000005000100000e10001103777777076578616d706c6503636f6d00',
  },
  {
    owner: 'ftp.nictool.tnpi.net.',
    ttl: 3600,
    class: 'IN',
    type: 'CNAME',
    cname: 'www.nictool.tnpi.net.',
    testB: 'ftp.nictool.tnpi.net.\t3600\tIN\tCNAME\twww.nictool.tnpi.net.\n',
    testT: 'Cftp.nictool.tnpi.net:www.nictool.tnpi.net:3600::\n',
    testW:
      '03667470076e6963746f6f6c04746e7069036e6574000005000100000e10001603777777076e6963746f6f6c04746e7069036e657400',
  },
  {
    owner: 'webmail.nictool.tnpi.net.',
    ttl: 3600,
    class: 'IN',
    type: 'CNAME',
    cname: 'mail.nictool.tnpi.net.',
    testB: 'webmail.nictool.tnpi.net.\t3600\tIN\tCNAME\tmail.nictool.tnpi.net.\n',
    testT: 'Cwebmail.nictool.tnpi.net:mail.nictool.tnpi.net:3600::\n',
    testW:
      '077765626d61696c076e6963746f6f6c04746e7069036e6574000005000100000e100017046d61696c076e6963746f6f6c04746e7069036e657400',
  },
]

const invalidRecords = [
  {
    ...defaults,
    owner: 'example.com.',
    cname: '192.0.2.4', // FQDN required
    msg: /cname must be a domain name/,
  },
]

describe('CNAME record', function () {
  base.valid(CNAME, validRecords)
  base.invalid(CNAME, invalidRecords)

  base.getDescription(CNAME)
  base.getRFCs(CNAME, validRecords[0])
  base.getFields(CNAME, ['cname'])
  base.getCanonical(CNAME)
  base.getTypeId(CNAME, 5)
  base.getTags(CNAME)

  base.toBind(CNAME, validRecords)
  base.toWire(CNAME, validRecords)
  base.toTinydns(CNAME, validRecords)

  base.fromTinydns(CNAME, validRecords)
  base.fromBind(CNAME, validRecords)
  base.fromWire(CNAME, validRecords)
})
